// Package terminal provides the terminal_execute tool.
package terminal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tools"
)

const maxOutputLen = 20000

// Common command → package mappings for auto-install.
var packageMap = map[string]string{
	// DNS & networking
	"nslookup":   "dnsutils",
	"dig":        "dnsutils",
	"host":       "dnsutils",
	"whois":      "whois",
	"traceroute": "traceroute",
	"ping":       "iputils-ping",
	"nmap":       "nmap",
	"netcat":     "ncat",
	"nc":         "ncat",
	"socat":      "socat",
	"tcpdump":    "tcpdump",
	"ss":         "iproute2",
	"ip":         "iproute2",
	"arp":        "net-tools",
	"ifconfig":   "net-tools",
	"netstat":    "net-tools",
	// Web / HTTP
	"curl":   "curl",
	"wget":   "wget",
	"httpie": "httpie",
	"http":   "httpie",
	// SSL/TLS
	"openssl": "openssl",
	// Recon / enumeration
	"nikto":      "nikto",
	"dirb":       "dirb",
	"gobuster":   "gobuster",
	"ffuf":       "ffuf",
	"subfinder":  "subfinder",
	"findomain":  "findomain",
	"assetfinder": "assetfinder",
	"masscan":    "masscan",
	"wfuzz":      "wfuzz",
	"httpx":      "httpx",
	"dnsx":        "dnsx",
	"nuclei":      "nuclei",
	// Text processing
	"jq":        "jq",
	"xmllint":   "libxml2-utils",
	"html2text": "html2text",
	// Git
	"git": "git",
	// Python
	"python3": "python3",
	"pip3":    "python3-pip",
	"pip":     "python3-pip",
	// General
	"tree":    "tree",
	"unzip":   "unzip",
	"zip":     "zip",
	"file":    "file",
	"strings": "binutils",
	"xxd":     "xxd",
	"base64":  "coreutils",
	"awk":     "gawk",
	"sed":     "sed",
	"grep":    "grep",
	"find":    "findutils",
	"xargs":   "findutils",
	"bc":      "bc",
	// SQL
	"sqlmap": "sqlmap",
}

// decode decodes a base64 string
func decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// decodeHex decodes a hex string
func decodeHex(s string) ([]byte, error) {
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}

// Register adds terminal tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "terminal_execute",
		Description: "Execute a shell command in the terminal. Returns stdout, stderr, and exit code. Automatically installs missing tools.",
		Parameters: []tools.Parameter{
			{Name: "command", Description: "The shell command to execute", Required: true},
			{Name: "timeout", Description: "Timeout in seconds (default: 120)", Required: false},
		},
		Execute: executeCommand,
	})
}

func executeCommand(args map[string]string) (tools.Result, error) {
	command := args["command"]
	if command == "" {
		return tools.Result{}, fmt.Errorf("command is required")
	}

	// Block destructive commands
	if reason := isBlockedCommand(command); reason != "" {
		return tools.Result{Output: fmt.Sprintf("[BLOCKED] Destructive command rejected: %s. Xalgorix is read-only — it tests for vulnerabilities without causing damage.", reason)}, nil
	}

	// Pre-check: extract and verify all required tools are available
	// This ensures tools are installed BEFORE command runs
	toolsToCheck := extractCommands(command)
	for _, tool := range toolsToCheck {
		if _, err := exec.LookPath(tool); err != nil {
			// Tool not found, try to install it
			pkg := resolvePackage(tool)
			if pkg != "" {
				installOutput := installPackage(pkg)
				// Add install info to output
				_ = installOutput // logged in installPackage
			}
		}
	}

	timeoutSec := 120
	if t, ok := args["timeout"]; ok {
		fmt.Sscanf(t, "%d", &timeoutSec)
	}

	// Run the command
	if t, ok := args["timeout"]; ok {
		fmt.Sscanf(t, "%d", &timeoutSec)
	}

	// Run the command
	output, exitCode := runShell(command, timeoutSec)

	// Check for "command not found" and auto-install
	if exitCode == 127 || isCommandNotFound(output) {
		missingCmd := extractMissingCommand(output)
		if missingCmd != "" {
			pkg := resolvePackage(missingCmd)
			if pkg != "" {
				installOutput := installPackage(pkg)
				// Retry the original command
				retryOutput, retryExit := runShell(command, timeoutSec)
				combined := fmt.Sprintf("[auto-installed %s (%s)]\n%s\n%s",
					missingCmd, pkg, installOutput, retryOutput)
				if retryExit != 0 {
					combined += fmt.Sprintf("\n[exit code: %d]", retryExit)
				}
				return tools.Result{Output: combined}, nil
			}
		}
	}

	return tools.Result{Output: output}, nil
}

func runShell(command string, timeoutSec int) (string, int) {
	cfg := config.Get()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// Set PATH to include common tool locations
	cmdEnv := append(os.Environ(), 
		"PATH=/root/go/bin:/root/.local/bin:"+os.Getenv("PATH"),
		"GOPATH=/root/go",
	)
	
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = cfg.Workspace
	cmd.Env = cmdEnv

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			return fmt.Sprintf("Command timed out after %d seconds.\nPartial stdout:\n%s\nPartial stderr:\n%s",
				timeoutSec, truncate(stdout.String()), truncate(stderr.String())), -1
		}
	}

	return formatOutput(stdout.String(), stderr.String(), exitCode), exitCode
}

func isCommandNotFound(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "command not found") ||
		strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "not found in") ||
		strings.Contains(lower, ": not found")
}

func extractMissingCommand(output string) string {
	// Patterns: "bash: line N: <cmd>: command not found"
	//           "<cmd>: command not found"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "command not found") || strings.Contains(lower, ": not found") {
			// Extract the command name — typically the word before ": command not found"
			parts := strings.Split(line, ":")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				// Skip "bash", "line N", "STDERR", etc.
				if p != "" && !strings.HasPrefix(p, "bash") &&
					!strings.HasPrefix(p, "line ") &&
					!strings.HasPrefix(p, "STDERR") &&
					!strings.Contains(p, "command not found") &&
					!strings.Contains(p, "not found") &&
					!strings.HasPrefix(p, "/") {
					// Clean up — take last word (handles paths)
					words := strings.Fields(p)
					if len(words) > 0 {
						cmd := words[len(words)-1]
						// Validate it looks like a command
						if len(cmd) > 0 && len(cmd) < 50 && !strings.ContainsAny(cmd, " \t(){}[]") {
							return cmd
						}
					}
				}
			}
		}
	}
	return ""
}

func resolvePackage(cmd string) string {
	// Check our built-in map first
	if pkg, ok := packageMap[cmd]; ok {
		return pkg
	}
	// Fallback: try the command name itself as the package name
	return cmd
}

func installPackage(pkg string) string {
	// Special handling for Go-installed tools
	goTools := map[string]string{
		"nuclei":      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		"httpx":       "github.com/projectdiscovery/httpx/cmd/httpx@latest",
		"dnsx":        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		"subfinder":   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		"findomain":   "github.com/findomain/findomain@latest",
		"assetfinder": "github.com/tomnomnom/assetfinder@latest",
	}
	
	if goPkg, ok := goTools[pkg]; ok {
		installCmd := fmt.Sprintf("go install -v %s 2>&1", goPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[install %s failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s successfully]", pkg)
	}
	
	// Detect package manager and build install command
	var installCmd string

	if _, err := exec.LookPath("apt-get"); err == nil {
		installCmd = fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("dnf"); err == nil {
		installCmd = fmt.Sprintf("dnf install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("yum"); err == nil {
		installCmd = fmt.Sprintf("yum install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("pacman"); err == nil {
		installCmd = fmt.Sprintf("pacman -S --noconfirm %s 2>&1", pkg)
	} else if _, err := exec.LookPath("apk"); err == nil {
		installCmd = fmt.Sprintf("apk add --no-cache %s 2>&1", pkg)
	} else {
		return fmt.Sprintf("[cannot auto-install: no supported package manager found for %s]", pkg)
	}

	// Prefix with sudo if not running as root
	if os.Getuid() != 0 {
		installCmd = "sudo " + installCmd
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("[install %s failed: %s]\n%s", pkg, err, truncate(string(out)))
	}

	return fmt.Sprintf("[installed %s successfully]", pkg)
}

func formatOutput(stdout, stderr string, exitCode int) string {
	var b strings.Builder

	if stdout != "" {
		b.WriteString(truncate(stdout))
	}

	if stderr != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("STDERR:\n")
		b.WriteString(truncate(stderr))
	}

	if exitCode != 0 {
		b.WriteString(fmt.Sprintf("\n[exit code: %d]", exitCode))
	}

	return b.String()
}

func truncate(s string) string {
	if len(s) > maxOutputLen {
		half := maxOutputLen / 2
		return s[:half] + "\n\n... [TRUNCATED] ...\n\n" + s[len(s)-half:]
	}
	return s
}

// blockedPatterns contains destructive commands that must never be executed.
var blockedPatterns = []struct {
	pattern string
	reason  string
}{
	{"rm -rf /", "recursive delete of root filesystem"},
	{"rm -rf /*", "recursive delete of root filesystem"},
	{"rm -rf ~", "recursive delete of home directory"},
	{"rm -rf .", "recursive delete of current directory"},
	{"> /dev/sd", "overwriting disk device"},
	{"dd if=/dev/zero", "overwriting with zeros"},
	{"dd if=/dev/random", "overwriting with random data"},
	{"mkfs", "formatting filesystem"},
	{"shutdown", "system shutdown"},
	{"reboot", "system reboot"},
	{"init 0", "system halt"},
	{"init 6", "system reboot"},
	{"halt", "system halt"},
	{"poweroff", "system poweroff"},
	{":(){ :|:&};:", "fork bomb"},
	{"chmod 777 /", "removing all file permissions on root"},
	{"chown -R", "recursive ownership change"},
	// SQL destructive statements
	{"drop table", "SQL DROP TABLE"},
	{"drop database", "SQL DROP DATABASE"},
	{"delete from", "SQL DELETE FROM"},
	{"truncate table", "SQL TRUNCATE TABLE"},
	{"update ", "SQL UPDATE (use SELECT to verify instead)"},
	// Python destructive
	{"shutil.rmtree", "recursive directory removal"},
	{"os.remove", "file deletion"},
}

// isBlockedCommand checks if a command matches any blocked pattern.
// It also detects encoding attempts (base64, hex, etc.) and checks decoded content.
func isBlockedCommand(cmd string) string {
	// First check the raw command
	if reason := checkBlocked(cmd); reason != "" {
		return reason
	}
	
	// Try to decode and check base64 encoded commands
	if decoded := tryBase64Decode(cmd); decoded != "" {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via base64 decoding)"
		}
	}
	
	// Try hex decoding
	if decoded := tryHexDecode(cmd); decoded != "" {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via hex decoding)"
		}
	}
	
	// Try URL decoding
	if decoded := tryURLDecode(cmd); decoded != "" && decoded != cmd {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via URL decoding)"
		}
	}
	
	// Check for common obfuscation patterns
	if reason := checkObfuscation(cmd); reason != "" {
		return reason
	}
	
	return ""
}

// checkBlocked is the core blocking logic
func checkBlocked(cmd string) string {
	lower := strings.ToLower(cmd)
	for _, bp := range blockedPatterns {
		if strings.Contains(lower, bp.pattern) {
			return bp.reason
		}
	}
	return ""
}

// tryBase64Decode attempts to decode a base64 string
func tryBase64Decode(cmd string) string {
	// Remove common prefixes
	cmd = strings.TrimSpace(cmd)
	cmd = strings.TrimPrefix(cmd, "echo ")
	cmd = strings.TrimPrefix(cmd, "echo ")
	cmd = strings.TrimSuffix(cmd, " | base64 -d")
	cmd = strings.TrimSuffix(cmd, " | base64 --decode")
	cmd = strings.TrimSuffix(cmd, "| base64 -d")
	cmd = strings.TrimSuffix(cmd, "| base64 --decode")
	cmd = strings.Trim(cmd, " \t\n")
	
	// Try standard base64
	if decoded, err := decodeBase64(cmd); err == nil && len(decoded) > 0 {
		return decoded
	}
	
	return ""
}

// decodeBase64 decodes a base64 string
func decodeBase64(cmd string) (string, error) {
	// Add padding if needed
	missing := 4 - (len(cmd) % 4)
	if missing != 4 {
		cmd += strings.Repeat("=", missing)
	}
	
	data, err := decode(cmd) // using the existing base64 decode
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// tryHexDecode attempts to decode a hex string
func tryHexDecode(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	
	// Check if it looks like hex (0x... or just hex chars)
	if !isHexString(cmd) {
		return ""
	}
	
	data, err := decodeHex(cmd)
	if err != nil {
		return ""
	}
	return string(data)
}

// isHexString checks if a string is valid hexadecimal
func isHexString(s string) bool {
	s = strings.ToLower(s)
	// Remove 0x prefix if present
	s = strings.TrimPrefix(s, "0x")
	if len(s) < 4 || len(s)%2 != 0 {
		return false
	}
	_, err := decodeHex(s)
	return err == nil
}

// tryURLDecode attempts to URL decode a string
func tryURLDecode(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	
	// Must contain URL-encoded characters
	if !strings.ContainsAny(cmd, "%") {
		return ""
	}
	
	// Use already imported net/url
	// Since we don't have net/url imported, we'll do simple decoding
	decoded := simpleURLDecode(cmd)
	return decoded
}

// simpleURLDecode does basic URL decoding
func simpleURLDecode(s string) string {
	result := s
	result = strings.ReplaceAll(result, "%20", " ")
	result = strings.ReplaceAll(result, "%2F", "/")
	result = strings.ReplaceAll(result, "%3A", ":")
	result = strings.ReplaceAll(result, "%3F", "?")
	result = strings.ReplaceAll(result, "%3D", "=")
	result = strings.ReplaceAll(result, "%26", "&")
	result = strings.ReplaceAll(result, "%27", "'")
	result = strings.ReplaceAll(result, "%22", "\"")
	result = strings.ReplaceAll(result, "%3C", "<")
	result = strings.ReplaceAll(result, "%3E", ">")
	result = strings.ReplaceAll(result, "%5C", "\\")
	result = strings.ReplaceAll(result, "%2D", "-")
	result = strings.ReplaceAll(result, "%5F", "_")
	result = strings.ReplaceAll(result, "%2E", ".")
	result = strings.ReplaceAll(result, "%2B", "+")
	result = strings.ReplaceAll(result, "%24", "$")
	result = strings.ReplaceAll(result, "%40", "@")
	result = strings.ReplaceAll(result, "%23", "#")
	// Handle %XX hex sequences
	for i := 0; i < len(result)-2; i++ {
		if result[i] == '%' {
			hex := result[i+1 : i+3]
			if data, err := decodeHex(hex); err == nil && len(data) == 1 {
				result = result[:i] + string(data[0]) + result[i+3:]
				i-- // recheck from the new position
			}
		}
	}
	return result
}

// extractCommands extracts all unique tool/command names from a shell command
func extractCommands(cmd string) []string {
	// Common security tools to look for
	tools := []string{
		"nmap", "nikto", "sqlmap", "gobuster", "ffuf", "dirb", "curl", "wget",
		"nuclei", "httpx", "dnsx", "subfinder", "findomain", "assetfinder",
		"masscan", "nc", "netcat", "socat", "openssl", "whatweb", "wafw00f",
		"gospider", "katana", "hakrawler", "gau", "waybackurls", "paramspider",
		"arjun", "x8", "jq", "xmllint", "hydra", "john",
		"git", "dirsearch", "feroxbuster", "testssl", "sslyze",
		"okenv", "ds_store", "gitdumper", "githacker",
	}
	
	found := make(map[string]bool)
	lowerCmd := strings.ToLower(cmd)
	
	for _, tool := range tools {
		// Check if tool appears as a standalone word in the command
		patterns := []string{
			" " + tool + " ",
			" " + tool + "\n",
			"|" + tool + " ",
			"&&" + tool + " ",
			tool + " -",
			tool + " --",
		}
		for _, p := range patterns {
			if strings.Contains(lowerCmd, p) {
				found[tool] = true
			}
		}
	}
	
	result := make([]string, 0, len(found))
	for t := range found {
		result = append(result, t)
	}
	return result
}

// checkObfuscation detects common obfuscation techniques
func checkObfuscation(cmd string) string {
	lower := strings.ToLower(cmd)
	
	// Check for character substitution obfuscation
	// e.g., c'h'o'p, r\m -rf, etc.
	obfuscationPatterns := []struct {
		pattern string
		reason  string
	}{
		{"chr\\s*\\(", "character code obfuscation"},
		{"\\\\x[0-9a-f]{2}", "hex escape obfuscation"},
		{"\\$\\s*\\{", "variable expansion obfuscation"},
	}
	
	for _, op := range obfuscationPatterns {
		if matched, _ := regexp.MatchString(op.pattern, lower); matched {
			// Check if the deobfuscated content would be dangerous
			// For now, just warn about the obfuscation attempt
			return "obfuscated command detected: " + op.reason
		}
	}
	
	return ""
}

