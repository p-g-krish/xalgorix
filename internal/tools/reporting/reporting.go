// Package reporting provides vulnerability reporting tools.
package reporting

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/internal/tools"
)

// Vulnerability represents a found vulnerability.
type Vulnerability struct {
	ID                string  `json:"id"`
	Title             string  `json:"title"`
	Severity          string  `json:"severity"`
	Description       string  `json:"description"`
	Impact            string  `json:"impact"`
	Target            string  `json:"target"`
	Endpoint          string  `json:"endpoint"`
	Method            string  `json:"method"`
	CVE               string  `json:"cve"`
	CVSS              float64 `json:"cvss"`
	TechnicalAnalysis string  `json:"technical_analysis"`
	PoCDescription    string  `json:"poc_description"`
	PoCScript         string  `json:"poc_script_code"`
	Remediation       string  `json:"remediation_steps"`
	Timestamp         string  `json:"timestamp"`
	AgentName         string  `json:"agent_name"`
}

var vulnerabilities []Vulnerability

// Register adds reporting tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "report_vulnerability",
		Description: "Report a discovered vulnerability with full details.",
		Parameters: []tools.Parameter{
			{Name: "title", Description: "Vulnerability title", Required: true},
			{Name: "severity", Description: "Severity: critical, high, medium, low, info", Required: true},
			{Name: "description", Description: "Detailed description", Required: true},
			{Name: "impact", Description: "Impact assessment", Required: false},
			{Name: "target", Description: "Target URL/host", Required: false},
			{Name: "endpoint", Description: "Affected endpoint", Required: false},
			{Name: "method", Description: "HTTP method", Required: false},
			{Name: "cve", Description: "CVE identifier", Required: false},
			{Name: "cvss", Description: "CVSS score", Required: false},
			{Name: "technical_analysis", Description: "Technical details", Required: false},
			{Name: "poc_description", Description: "PoC description", Required: false},
			{Name: "poc_script_code", Description: "PoC code", Required: false},
			{Name: "remediation_steps", Description: "Remediation steps", Required: false},
		},
		Execute: reportVuln,
	})
}

func reportVuln(args map[string]string) (tools.Result, error) {
	var cvss float64
	if c := args["cvss"]; c != "" {
		fmt.Sscanf(c, "%f", &cvss)
	}

	vuln := Vulnerability{
		ID:                fmt.Sprintf("XALG-%d", len(vulnerabilities)+1),
		Title:             args["title"],
		Severity:          args["severity"],
		Description:       args["description"],
		Impact:            args["impact"],
		Target:            args["target"],
		Endpoint:          args["endpoint"],
		Method:            args["method"],
		CVE:               args["cve"],
		CVSS:              cvss,
		TechnicalAnalysis: args["technical_analysis"],
		PoCDescription:    args["poc_description"],
		PoCScript:         args["poc_script_code"],
		Remediation:       args["remediation_steps"],
		Timestamp:         time.Now().Format(time.RFC3339),
	}

	vulnerabilities = append(vulnerabilities, vuln)

	return tools.Result{
		Output:   fmt.Sprintf("✅ Vulnerability reported: [%s] %s (%s)", vuln.ID, vuln.Title, strings.ToUpper(vuln.Severity)),
		Metadata: map[string]any{"vuln_id": vuln.ID},
	}, nil
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
