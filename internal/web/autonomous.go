// Package web provides the HTTP server and API handlers.
package web

// Build autonomous instruction that gives AI freedom to decide approach
func buildAutonomousInstruction(target string, customInstruction string) string {
	baseInstruction := `## AUTONOMOUS PENTESTING MODE

You are an expert penetration tester. YOUR GOAL: Find REAL exploitable vulnerabilities.

## YOUR TARGET: ` + target + `

## YOUR RESPONSIBILITY - ORGANIZE YOUR WORK

You are in a working directory. CREATE YOUR OWN directory structure:
- Create a folder for this target: mkdir -p ./TARGET
- Work inside that folder: cd ./TARGET
- Save all results there: ./TARGET/subdomains.txt, ./TARGET/nmap.txt, etc.

DO NOT scatter files everywhere. Be organized!

## STRICT FALSE POSITIVE RULES

### MARK AS INFO ONLY (NOT High/Critical):
- phpMyAdmin with authentication = INFO (not exploitable)
- CORS misconfiguration alone = INFO (needs proof of data theft)
- SSL/TLS issues alone = INFO (needs MITM proof)
- Open redirect alone = INFO (needs chaining)
- Debug mode = INFO (needs exploitation)
- Missing security headers alone = INFO
- Server version disclosure = INFO (only escalate if CVE exists)

### SEVERITY REQUIREMENTS:

**CRITICAL:** RCE with screenshot, full DB dump with data, complete auth bypass
**HIGH:** SQLi with ACTUAL data extraction screenshot, full account takeover screenshot
**MEDIUM:** Reflected XSS with screenshot, CSRF with proof
**INFO:** All the "not exploitable alone" findings

## AGENTMAIL FOR SIGN-UP TESTING
When testing registration/login:
1. action=create_inbox name=test123
2. Use the email for sign-up
3. action=wait_for_email inbox_id=XXX subject=verify timeout=120
4. Extract verification link

## YOUR APPROACH

1. CREATE TARGET FOLDER: mkdir -p ./TARGET && cd ./TARGET
2. Subdomain enumeration - ALL subdomains
3. Technology detection per subdomain
4. Crawl each subdomain
5. Test parameters deeply
6. Exploit with PROOF
7. Report with screenshots

Be organized. One target fully tested, then next.
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

## ORGANIZE YOUR WORK
Create folder: mkdir -p ./TARGET && cd ./TARGET

## FALSE POSITIVES = INFO ONLY:
phpMyAdmin with auth, CORS alone, SSL issues, Open redirect alone = INFO

## PROOF REQUIRED FOR HIGH/CRITICAL:
Screenshot of actual data or session hijacking

## TESTING:
SQLi, XSS, IDOR, SSRF with ACTUAL exploitation proof.
`
}
