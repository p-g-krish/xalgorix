// Package web provides the HTTP server and API handlers.
package web

// Build autonomous instruction that gives AI freedom to decide approach
func buildAutonomousInstruction(target string, customInstruction string) string {
	baseInstruction := `## AUTONOMOUS PENTESTING MODE

You are an expert penetration tester. YOUR GOAL: Find REAL exploitable vulnerabilities.

## YOUR TARGET: ` + target + `

## STRICT FALSE POSITIVE RULES - FOLLOW THESE!

### MARK AS INFO/LOW ONLY (NOT High/Critical):
- phpMyAdmin with authentication = INFO (not exploitable without auth bypass)
- CORS misconfiguration alone = INFO (needs proof of data theft to be higher)
- SSL/TLS issues alone = INFO (needs proof of MITM capability)
- Open redirect alone = INFO (needs chaining with XSS)
- Debug mode/enabled = INFO (needs actual exploitation)
- Missing security headers = INFO (not exploitable alone)
- Server version disclosure = INFO (only escalate if CVE exists)
- Information disclosure = INFO/LOW (non-sensitive data only)

### SEVERITY REQUIREMENTS:

**CRITICAL - ALL must be proven:**
- RCE with actual command execution and screenshot
- Full database dump with sensitive data screenshot
- Complete auth bypass without any credentials

**HIGH - ALL must be proven:**
- SQL Injection with ACTUAL data extraction (usernames, passwords, emails) - screenshot required
- Auth bypass giving FULL account access - screenshot required
- Stored XSS with session hijacking - must demonstrate cookie theft
- IDOR with proof of accessing OTHER users' data - screenshot required

**MEDIUM:**
- Reflected XSS with screenshot
- CSRF with proof of state change
- Stored XSS without session hijacking (lower impact)

**INFO:**
- phpMyAdmin with auth (not exploitable)
- CORS without exploitation (informational only)
- SSL issues without MITM proof
- Open redirect without chaining
- Debug mode without exploitation
- Missing headers alone

### PROOF REQUIREMENTS:
- CRITICAL/HIGH: Screenshot of actual data OR session hijacking
- MEDIUM: Screenshot of payload execution
- INFO: Screenshot of finding only

## AGENTMAIL FOR SIGN-UP TESTING
When testing registration/login:
1. action=create_inbox name=test123
2. Use the email for sign-up
3. action=wait_for_email inbox_id=XXX subject=verify timeout=120
4. Extract verification link

## YOUR APPROACH

1. Test each parameter manually
2. Exploit confirmed findings deeply
3. Report with PROOF
4. Only move on when fully tested

Target is NOT complete until ALL subdomains tested.
`

	if customInstruction != "" {
		return baseInstruction + "\n\n" + customInstruction
	}
	return baseInstruction
}

// Build autonomous DAST instruction for URL scanning
func buildDASTInstruction(target string) string {
	return `## AUTONOMOUS DAST MODE

YOUR TARGET: ` + target + `

## FALSE POSITIVES = INFO ONLY:
- phpMyAdmin with auth = INFO
- CORS alone = INFO  
- SSL issues = INFO
- Open redirect alone = INFO
- Debug mode = INFO

## PROOF REQUIRED FOR HIGH/CRITICAL:
- Screenshot of actual data extracted
- Session hijacking proof

## TESTING:
SQLi, XSS, IDOR, SSRF with ACTUAL exploitation proof.
`
}
