// Package terminal provides the terminal_execute tool.
package terminal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
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
	"nikto":     "nikto",
	"dirb":      "dirb",
	"gobuster":  "gobuster",
	"ffuf":      "ffuf",
	"subfinder": "subfinder",
	"amass":     "amass",
	"masscan":   "masscan",
	"wfuzz":     "wfuzz",
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

	timeoutSec := 120
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

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = cfg.Workspace

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
