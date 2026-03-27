// Package reporting provides vulnerability reporting tools with exploit-before-report validation.
package reporting

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/internal/tools"
)

// Valid verification methods — the agent must specify one when reporting.
var validVerificationMethods = map[string]bool{
	"exploited":         true, // Full exploitation with proof
	"time_based":        true, // Time-based blind confirmation (SQLi, command injection)
	"data_extracted":    true, // Actual data was extracted
	"callback_received": true, // SSRF/XXE/RCE callback received
	"error_based":       true, // Error-based confirmation (SQL error, stack trace)
	"blind_confirmed":   true, // Blind vulnerability confirmed via side-channel
	"reflected":         true, // Payload reflected in response (XSS)
	"authenticated":     true, // Auth bypass / IDOR with evidence
	"manual_verified":   true, // Manually verified via browser / curl
}

// Minimum evidence keywords per severity — used for auto-downgrade heuristics.
var evidenceKeywords = map[string][]string{
	"critical": {"rce", "remote code", "shell", "reverse shell", "command execution", "dump", "database", "full access", "admin takeover", "account takeover"},
	"high":     {"sqli", "sql injection", "data extract", "xss", "cross-site", "ssrf", "idor", "auth bypass", "token", "session hijack", "file inclusion"},
	"medium":   {"reflected", "csrf", "redirect", "disclosure", "injection", "traversal"},
}

// Vulnerability represents a found vulnerability.
type Vulnerability struct {
	ID                 string  `json:"id"`
	Title              string  `json:"title"`
	Severity           string  `json:"severity"`
	OriginalSeverity   string  `json:"original_severity,omitempty"` // if auto-downgraded
	Description        string  `json:"description"`
	Impact             string  `json:"impact"`
	Target             string  `json:"target"`
	Endpoint           string  `json:"endpoint"`
	Method             string  `json:"method"`
	CVE                string  `json:"cve"`
	CVSS               float64 `json:"cvss"`
	TechnicalAnalysis  string  `json:"technical_analysis"`
	PoCDescription     string  `json:"poc_description"`
	PoCScript          string  `json:"poc_script_code"`
	Remediation        string  `json:"remediation_steps"`
	ExploitationProof  string  `json:"exploitation_proof"`
	VerificationMethod string  `json:"verification_method"`
	Verified           bool    `json:"verified"`
	Timestamp          string  `json:"timestamp"`
	AgentName          string  `json:"agent_name"`
}

var vulnerabilities []Vulnerability

// Register adds reporting tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name: "report_vulnerability",
		Description: `Report a VERIFIED, EXPLOITABLE vulnerability with proof. CRITICAL RULES:
1. You MUST have already EXPLOITED this vulnerability before calling this tool.
2. You MUST provide exploitation_proof showing concrete evidence (extracted data, reflected payload, command output, callback, timing proof).
3. Reports without exploitation proof for severity >= medium will be REJECTED — exploit first, then report.
4. Do NOT report missing headers, version disclosure, or scanner-only findings as vulnerabilities — those are INFO at best.`,
		Parameters: []tools.Parameter{
			{Name: "title", Description: "Vulnerability title", Required: true},
			{Name: "severity", Description: "Severity: critical, high, medium, low, info", Required: true},
			{Name: "description", Description: "Detailed description of the vulnerability", Required: true},
			{Name: "exploitation_proof", Description: "REQUIRED for medium+. Concrete evidence of exploitation: extracted data, reflected payload text, command output, timing measurement, callback confirmation. Paste actual output here.", Required: true},
			{Name: "verification_method", Description: "How you verified: exploited, time_based, data_extracted, callback_received, error_based, blind_confirmed, reflected, authenticated, manual_verified", Required: true},
			{Name: "impact", Description: "Real-world impact assessment", Required: false},
			{Name: "target", Description: "Target URL/host", Required: false},
			{Name: "endpoint", Description: "Affected endpoint", Required: false},
			{Name: "method", Description: "HTTP method", Required: false},
			{Name: "cve", Description: "CVE identifier if known", Required: false},
			{Name: "cvss", Description: "CVSS score (0-10)", Required: false},
			{Name: "technical_analysis", Description: "Technical details of the vulnerability", Required: false},
			{Name: "poc_description", Description: "Step-by-step PoC description", Required: false},
			{Name: "poc_script_code", Description: "Reproducible PoC code (curl, python, etc.)", Required: false},
			{Name: "remediation_steps", Description: "Remediation recommendations", Required: false},
		},
		Execute: reportVuln,
	})
}

func reportVuln(args map[string]string) (tools.Result, error) {
	severity := strings.ToLower(strings.TrimSpace(args["severity"]))
	proof := strings.TrimSpace(args["exploitation_proof"])
	method := strings.ToLower(strings.TrimSpace(args["verification_method"]))
	title := strings.TrimSpace(args["title"])

	// ── Gate 1: Validate verification method ──
	if method == "" || !validVerificationMethods[method] {
		return tools.Result{
			Output: fmt.Sprintf("❌ REJECTED: Invalid verification_method '%s'. Must be one of: %s\n\nYou must EXPLOIT the vulnerability first, then report with the correct verification method.",
				method, formatValidMethods()),
		}, nil
	}

	// ── Gate 2: Require exploitation proof for medium+ severity ──
	isHighSeverity := severity == "critical" || severity == "high" || severity == "medium"
	if isHighSeverity && (proof == "" || len(proof) < 20) {
		return tools.Result{
			Output: fmt.Sprintf(`❌ REJECTED: '%s' reported as %s but has NO exploitation proof.

XALGORIX RULE: You MUST exploit the vulnerability BEFORE reporting it.

Required steps:
1. You found a potential %s → Good, but not enough to report.
2. Now EXPLOIT it safely — extract data, trigger the payload, confirm the behavior.
3. Paste the ACTUAL OUTPUT of exploitation into 'exploitation_proof'.
4. Then call report_vulnerability again with the proof.

If you cannot exploit it, downgrade severity to 'info' and report as informational.`,
				title, strings.ToUpper(severity), title),
		}, nil
	}

	// ── Gate 3: Check for common false positive patterns ──
	if rejection := checkFalsePositive(title, args["description"], severity, proof); rejection != "" {
		return tools.Result{Output: rejection}, nil
	}

	// ── Gate 4: Smart Deduplication — same vuln type on same endpoint = duplicate ──
	endpoint := strings.TrimSpace(args["endpoint"])
	vulnType := extractVulnType(title, args["description"])
	normalizedEndpoint := normalizeEndpoint(endpoint)
	
	for _, existing := range vulnerabilities {
		existingType := extractVulnType(existing.Title, existing.Description)
		existingNormEndpoint := normalizeEndpoint(existing.Endpoint)
		
		// Check 1: Exact title + endpoint match
		if strings.EqualFold(existing.Title, title) && existing.Endpoint == endpoint {
			return tools.Result{
				Output: fmt.Sprintf("⚠️ DUPLICATE: '%s' at endpoint '%s' already reported as %s. Skipping.", title, endpoint, existing.ID),
			}, nil
		}
		
		// Check 2: Same vulnerability TYPE on same normalized endpoint
		if vulnType != "" && vulnType == existingType && normalizedEndpoint == existingNormEndpoint && normalizedEndpoint != "" {
			return tools.Result{
				Output: fmt.Sprintf("⚠️ DUPLICATE: Same vulnerability type '%s' already reported on endpoint '%s' as %s ('%s'). Skipping.\nIf this is genuinely different, use a distinct endpoint or describe how it differs.",
					vulnType, endpoint, existing.ID, existing.Title),
			}, nil
		}
	}

	// ── Gate 5: Severity classification — enforce max severity per vuln type ──
	originalSeverity := ""
	if cappedSev, reason := classifySeverity(title, args["description"], severity, proof); cappedSev != severity {
		originalSeverity = severity
		severity = cappedSev
		_ = reason // will be included in output message below
	}

	// ── Auto-downgrade: weak proof for high severity ──
	if originalSeverity == "" && isHighSeverity && !hasStrongEvidence(severity, proof, args["description"]) {
		originalSeverity = severity
		severity = "info"
	}

	var cvss float64
	if c := args["cvss"]; c != "" {
		fmt.Sscanf(c, "%f", &cvss)
	}

	vuln := Vulnerability{
		ID:                 fmt.Sprintf("XALG-%d", len(vulnerabilities)+1),
		Title:              title,
		Severity:           severity,
		OriginalSeverity:   originalSeverity,
		Description:        args["description"],
		Impact:             args["impact"],
		Target:             args["target"],
		Endpoint:           endpoint,
		Method:             args["method"],
		CVE:                args["cve"],
		CVSS:               cvss,
		TechnicalAnalysis:  args["technical_analysis"],
		PoCDescription:     args["poc_description"],
		PoCScript:          args["poc_script_code"],
		ExploitationProof:  proof,
		VerificationMethod: method,
		Verified:           proof != "" && method != "",
		Remediation:        args["remediation_steps"],
		Timestamp:          time.Now().Format(time.RFC3339),
	}

	vulnerabilities = append(vulnerabilities, vuln)

	msg := fmt.Sprintf("✅ Vulnerability reported: [%s] %s (%s) — Verified: %v", vuln.ID, vuln.Title, strings.ToUpper(vuln.Severity), vuln.Verified)
	if originalSeverity != "" {
		msg += fmt.Sprintf("\n⚠️ AUTO-DOWNGRADED from %s → %s (insufficient exploitation evidence for higher severity)", strings.ToUpper(originalSeverity), strings.ToUpper(severity))
	}

	return tools.Result{
		Output:   msg,
		Metadata: map[string]any{"vuln_id": vuln.ID, "verified": vuln.Verified},
	}, nil
}

// checkFalsePositive detects common false positive patterns and rejects them.
func checkFalsePositive(title, description, severity, proof string) string {
	lower := strings.ToLower(title + " " + description)
	isHighSev := severity == "critical" || severity == "high" || severity == "medium"

	// Pattern 1: Missing security headers reported as vulnerability
	headerKeywords := []string{"missing header", "x-frame-options", "x-content-type", "content-security-policy",
		"strict-transport", "x-xss-protection", "referrer-policy", "permissions-policy", "hsts"}
	for _, kw := range headerKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return fmt.Sprintf("❌ REJECTED: Missing security headers are INFORMATIONAL, not %s. Re-report as severity 'info' if needed.", strings.ToUpper(severity))
		}
	}

	// Pattern 2: Version/technology disclosure
	disclosureKeywords := []string{"version disclosure", "server header", "x-powered-by", "technology disclosure",
		"software version", "banner grabbing"}
	for _, kw := range disclosureKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return "❌ REJECTED: Version/technology disclosure is INFORMATIONAL unless you can exploit a specific CVE. Provide CVE + exploitation proof, or re-report as 'info'."
		}
	}

	// Pattern 3: Scanner-only findings without manual verification
	scannerKeywords := []string{"nuclei detected", "nuclei found", "scanner reported", "automated scan found",
		"wpscan found", "nmap detected"}
	for _, kw := range scannerKeywords {
		if strings.Contains(lower, kw) && proof == "" {
			return "❌ REJECTED: Scanner-only findings require MANUAL VERIFICATION. Run the scanner, then manually exploit the finding to confirm it. Paste the exploitation output as proof."
		}
	}

	// Pattern 4: CORS without exploitation proof
	if strings.Contains(lower, "cors") && isHighSev {
		corsProofKeywords := []string{"cookie", "token", "session", "steal", "extract", "hijack", "javascript", "xmlhttprequest", "fetch("}
		hasExploitProof := false
		lowerProof := strings.ToLower(proof)
		for _, kw := range corsProofKeywords {
			if strings.Contains(lowerProof, kw) {
				hasExploitProof = true
				break
			}
		}
		if !hasExploitProof {
			return "❌ REJECTED: CORS misconfiguration alone is INFORMATIONAL. To report as medium+, you must demonstrate cookie/token theft via CORS (provide PoC JavaScript that exfiltrates data). Otherwise re-report as 'info'."
		}
	}

	// Pattern 5: Open redirect without chaining
	if strings.Contains(lower, "open redirect") && isHighSev {
		chainKeywords := []string{"oauth", "token", "ssrf", "phishing", "chain", "exfiltrate", "steal"}
		hasChain := false
		lowerProof := strings.ToLower(proof + " " + description)
		for _, kw := range chainKeywords {
			if strings.Contains(lowerProof, kw) {
				hasChain = true
				break
			}
		}
		if !hasChain {
			return "❌ REJECTED: Open redirect alone is INFORMATIONAL. To report as medium+, chain it with OAuth token theft, SSRF, or demonstrate real impact. Otherwise re-report as 'info'."
		}
	}

	// Pattern 6: SSL/TLS issues (weak ciphers, old TLS versions)
	sslKeywords := []string{"ssl", "tls", "cipher", "certificate", "sweet32", "poodle", "heartbleed", "beast", "crime"}
	for _, kw := range sslKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: SSL/TLS configuration issues (weak ciphers, old versions) are OUT OF SCOPE. Do not report them."
		}
	}

	// Pattern 7: DNS configuration issues (SPF, DMARC, TXT)
	dnsKeywords := []string{"spf", "dmarc", "dkim", "domain-based message authentication", "sender policy framework", "txt record", "email spoofing"}
	for _, kw := range dnsKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: DNS and email configuration issues (SPF, DMARC, TXT, DKIM) are OUT OF SCOPE. Do not report them."
		}
	}

	return ""
}

// hasStrongEvidence checks if the proof actually contains meaningful exploitation evidence.
func hasStrongEvidence(severity, proof, description string) bool {
	if proof == "" {
		return false
	}

	lowerProof := strings.ToLower(proof)
	keywords, ok := evidenceKeywords[severity]
	if !ok {
		return true // low/info don't need strong evidence
	}

	// Check if proof contains relevant keywords
	for _, kw := range keywords {
		if strings.Contains(lowerProof, kw) {
			return true
		}
	}

	// Also check for generic exploitation indicators
	genericIndicators := []string{"root:", "uid=", "admin", "password", "select ", "union ", "alert(", "<script",
		"etc/passwd", "internal", "metadata", "169.254", "127.0.0.1", "localhost",
		"response:", "output:", "extracted:", "confirmed:", "result:", "HTTP/"}
	for _, ind := range genericIndicators {
		if strings.Contains(lowerProof, ind) {
			return true
		}
	}

	// If proof is long enough (>100 chars), it probably has real content
	return len(proof) > 100
}

func formatValidMethods() string {
	methods := make([]string, 0, len(validVerificationMethods))
	for m := range validVerificationMethods {
		methods = append(methods, m)
	}
	return strings.Join(methods, ", ")
}

// GetVulnerabilities returns all reported vulnerabilities.
func GetVulnerabilities() []Vulnerability {
	return vulnerabilities
}

// ResetVulnerabilities clears the vulnerability list (called at scan start).
func ResetVulnerabilities() {
	vulnerabilities = nil
}

// GetVulnsJSON returns vulnerabilities as JSON.
func GetVulnsJSON() string {
	data, _ := json.MarshalIndent(vulnerabilities, "", "  ")
	return string(data)
}

// severityRank maps severity strings to numeric levels for comparison.
var severityRank = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// classifySeverity enforces maximum severity caps based on vulnerability type.
// Returns the (possibly capped) severity and a reason if it was changed.
func classifySeverity(title, description, severity, proof string) (string, string) {
	rank, ok := severityRank[severity]
	if !ok || rank <= 1 {
		return severity, "" // info/low — no need to cap further
	}

	lower := strings.ToLower(title + " " + description)
	lowerProof := strings.ToLower(proof)

	// ── INFO-only findings (max severity: info) ──
	infoOnlyPatterns := []struct {
		keywords []string
		reason   string
	}{
		{[]string{"missing header", "security header", "x-frame-options missing", "csp missing", 
			"hsts missing", "x-content-type missing", "referrer-policy missing", 
			"permissions-policy missing", "x-xss-protection missing"},
			"Missing security headers are informational — not directly exploitable"},
		{[]string{"version disclosure", "server version", "software version", "banner grabbing",
			"x-powered-by", "server header disclosure", "technology detected"},
			"Version/technology disclosure is informational unless tied to a specific exploited CVE"},
		{[]string{"directory listing", "directory index", "index of /"},
			"Directory listing is informational unless sensitive files are exposed and accessed"},
		{[]string{"self-xss", "self xss"},
			"Self-XSS only affects the user's own session — not exploitable against others"},
		{[]string{"debug mode", "debug enabled", "stack trace exposed", "verbose error"},
			"Debug/error disclosure is informational unless it leaks credentials or enables further exploitation"},
		{[]string{"robots.txt", "sitemap.xml", "crossdomain.xml"},
			"Configuration file disclosure is informational"},
		{[]string{"ssl weak", "tls weak", "weak cipher", "tls 1.0", "tls 1.1", "ssl certificate"},
			"SSL/TLS configuration issues are informational — not directly exploitable in practice"},
		{[]string{"email disclosure", "email address found", "email harvesting"},
			"Email disclosure is informational"},
		{[]string{"dns zone transfer", "zone transfer"},
			"DNS zone transfer is informational in most contexts"},
	}

	for _, p := range infoOnlyPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				return "info", p.reason
			}
		}
	}

	// ── LOW-cap findings (max severity: low) ──
	lowCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		{[]string{"cors", "cross-origin resource sharing"},
			func() bool {
				// Exception: CORS + cookie theft proof = allow higher severity
				theftKeywords := []string{"cookie", "token", "steal", "exfiltrate", "xmlhttprequest", "fetch(", "document.cookie"}
				for _, tk := range theftKeywords {
					if strings.Contains(lowerProof, tk) {
						return true
					}
				}
				return false
			},
			"CORS alone is low severity — needs proven cookie/token theft for higher"},
		{[]string{"clickjacking", "click jacking", "ui redressing"},
			nil,
			"Clickjacking is low severity — limited real-world impact"},
		{[]string{"cookie without httponly", "cookie missing httponly", "cookie flag", "cookie attribute", "missing secure flag"},
			nil,
			"Missing cookie flags alone are low severity"},
		{[]string{"path disclosure", "full path", "internal path"},
			nil,
			"Internal path disclosure is low severity"},
	}

	for _, p := range lowCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow higher severity
				}
				if rank > severityRank["low"] {
					return "low", p.reason
				}
			}
		}
	}

	// ── MEDIUM-cap findings (max severity: medium) ──
	medCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		{[]string{"open redirect", "url redirect", "unvalidated redirect"},
			func() bool {
				// Exception: redirect chained with OAuth/token theft
				chainKeywords := []string{"oauth", "token", "ssrf", "chain", "steal"}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) {
						return true
					}
				}
				return false
			},
			"Open redirect is medium max — needs OAuth/token chain for higher"},
		{[]string{"reflected xss", "cross-site scripting", "dom xss", "dom-based xss"},
			func() bool {
				// Exception: XSS → account takeover demonstrated
				for _, kw := range []string{"account takeover", "session hijack", "cookie stolen", "admin access"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"XSS is medium max — needs proven session hijack/account takeover for higher"},
		{[]string{"csrf", "cross-site request forgery"},
			func() bool {
				// Exception: CSRF on critical action (password change, admin)
				for _, kw := range []string{"password", "admin", "delete account", "transfer", "payment"} {
					if strings.Contains(lower, kw) || strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"CSRF is medium max — needs critical action impact for higher"},
		{[]string{"host header injection", "host header"},
			nil,
			"Host header injection is medium max in most contexts"},
		{[]string{"crlf injection", "http response splitting"},
			nil,
			"CRLF injection is medium max unless chained with cache poisoning or XSS"},
	}

	for _, p := range medCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow higher severity
				}
				if rank > severityRank["medium"] {
					return "medium", p.reason
				}
			}
		}
	}

	return severity, "" // no cap needed
}

// extractVulnType extracts a canonical vulnerability type from title/description
// for deduplication purposes. Returns empty string if type can't be determined.
func extractVulnType(title, description string) string {
	lower := strings.ToLower(title + " " + description)

	vulnTypes := []struct {
		typeName string
		keywords []string
	}{
		{"xss", []string{"xss", "cross-site scripting", "cross site scripting", "reflected xss", "stored xss", "dom xss", "script injection"}},
		{"sqli", []string{"sql injection", "sqli", "sql inject", "blind sql", "union select", "error-based sql"}},
		{"ssrf", []string{"ssrf", "server-side request forgery", "server side request forgery"}},
		{"idor", []string{"idor", "insecure direct object", "broken access control", "unauthorized access"}},
		{"lfi", []string{"local file inclusion", "lfi", "file inclusion", "path traversal", "directory traversal"}},
		{"rfi", []string{"remote file inclusion", "rfi"}},
		{"rce", []string{"remote code execution", "rce", "command injection", "os command", "code execution"}},
		{"csrf", []string{"csrf", "cross-site request forgery", "cross site request forgery"}},
		{"xxe", []string{"xxe", "xml external entity"}},
		{"open_redirect", []string{"open redirect", "url redirect", "unvalidated redirect"}},
		{"auth_bypass", []string{"authentication bypass", "auth bypass", "login bypass"}},
		{"info_disclosure", []string{"information disclosure", "info disclosure", "sensitive data exposure", "data leak"}},
		{"missing_header", []string{"missing header", "security header", "x-frame-options", "content-security-policy", "hsts"}},
		{"version_disclosure", []string{"version disclosure", "server header", "x-powered-by", "technology disclosure"}},
		{"subdomain_takeover", []string{"subdomain takeover", "dangling dns", "unclaimed subdomain"}},
		{"clickjacking", []string{"clickjacking", "ui redressing"}},
		{"cors", []string{"cors", "cross-origin resource sharing"}},
		{"crlf", []string{"crlf injection", "http response splitting"}},
		{"ssti", []string{"ssti", "server-side template injection", "template injection"}},
		{"deserialization", []string{"deserialization", "insecure deserialization"}},
	}

	for _, vt := range vulnTypes {
		for _, kw := range vt.keywords {
			if strings.Contains(lower, kw) {
				return vt.typeName
			}
		}
	}
	return ""
}

// normalizeEndpoint strips query params, fragments, and trailing slashes
// so "/api/search?q=test" and "/api/search?q=foo" match as the same endpoint.
func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}

	// Strip query parameters
	if idx := strings.Index(endpoint, "?"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	// Strip fragment
	if idx := strings.Index(endpoint, "#"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	// Strip trailing slashes
	endpoint = strings.TrimRight(endpoint, "/")
	// Lowercase for consistent comparison
	return strings.ToLower(endpoint)
}
