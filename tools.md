# Xalgorix Tools

Complete list of tools included in Xalgorix - the most powerful open-source AI autonomous pentesting agent.

## 🔍 Recon & Subdomain Enumeration

| Tool | Purpose | Install |
|------|---------|---------|
| **subfinder** | Passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **findomain** | Subdomain discovery | `cargo install findomain` |
| **assetfinder** | Find related subdomains | `go install github.com/tomnomnom/assetfinder@latest` |
| **dnsx** | DNS resolution & bruteforce | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| **amass** | Subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@latest` |
| **gospider** | Web spidering | `go install github.com/jaeles-project/gospider@latest` |
| **katana** | Next-gen crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| **hakrawler** | Web crawling | `go install github.com/hakluke/hakrawler@latest` |
| **gau** | Get All URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **waybackurls** | Wayback Machine URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| **paramspider** | Parameter discovery | `pipx install paramspider` |

## 🌐 HTTP & Scanning

| Tool | Purpose | Install |
|------|---------|---------|
| **httpx** | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **nuclei** | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **gobuster** | Directory busting | `go install github.com/OJ/gobuster/v3@latest` |
| **ffuf** | Fuzzing | `go install github.com/ffuf/ffuf@latest` |
| **dirb** | Web scanning | `apt install dirb` |
| **nikto** | Web server scanning | `apt install nikto` |
| **wfuzz** | Web fuzzing | `pip install wfuzz` |

## 💉 Exploitation

| Tool | Purpose | Install |
|------|---------|---------|
| **sqlmap** | SQL injection | `git clone https://github.com/sqlmapproject/sqlmap` |
| **nmap** | Port & service scanning | `apt install nmap` |

## 🔧 Utilities

| Tool | Purpose | Install |
|------|---------|---------|
| **curl** | HTTP client | Built-in |
| **wget** | Downloader | Built-in |
| **jq** | JSON processing | `apt install jq` |
| **git** | Version control | Built-in |
| **python3** | Scripting | Built-in |
| **scrapling** | Anti-bot bypass scraping | `pipx install scrapling` |

## 🤖 Agent Tools (Built-in)

These tools come with Xalgorix:

| Tool | Description |
|------|-------------|
| **terminal_execute** | Run shell commands with auto-install |
| **browser** | Browser automation |
| **playwright** | Browser control for testing |
| **websearch** | Web search via Gemini/Brave/Google |
| **notes** | Track findings and endpoints |
| **reporting** | Generate PDF reports |
| **thinking** | AI reasoning and planning |
| **finish** | Complete and summarize scan |

## Auto-Install

Xalgorix automatically installs missing tools when needed. Just run a command and it'll handle the rest!

## Total Tools

**70+ tools** supported for comprehensive pentesting:
- DNS enumeration
- Subdomain discovery
- Web crawling
- Vulnerability scanning
- Fuzzing
- Exploitation
- Reporting
