<div align="center">

<img src="assets/banner.png" alt="Xalgorix" width="800"/>

<br/>

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Author](https://img.shields.io/badge/Author-@xalgord-00ff88?style=for-the-badge&logo=github&logoColor=white)](https://github.com/xalgord)
[![License](https://img.shields.io/badge/License-MIT-00ff88?style=for-the-badge)](LICENSE)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/xalgord)

<p><i>Point it at a target. It does the rest.</i></p>

</div>

---

Xalgorix is a fully autonomous AI pentesting agent that uses LLMs to drive comprehensive security assessments. Point it at a target, and it runs through a 20-phase penetration testing methodology — from reconnaissance to exploitation — using real tools, with zero human intervention.

## Features

- **Autonomous Agent Loop** — LLM-driven iterative scanning with tool calls parsed from XML
- **20 Critical Rules** — Persistence & bypass rules, parameter testing, hidden param discovery, vulnerability chaining
- **Auto-Install Missing Tools** — Detects `command not found`, resolves the package, installs it, and retries (70+ tool→package mappings)
- **Comprehensive Recon Toolset** — subfinder, findomain, assetfinder, gospider, gau, waymore, paramspider, arjun, and more
- **Liquid Glass Web UI** — Dark mode dashboard with frosted glass panels, real-time WebSocket feed, live clock, and token tracking
- **Persistent Scan Data** — Scans saved to `~/xalgorix-data/scans/` with 30-day retention, survives page refreshes and server restarts
- **Discord Webhook Notifications** — Real-time alerts for scan start, vulnerability found, and scan finished
- **Multi-LLM Provider Support** — Switch between OpenAI, Anthropic, DeepSeek, Google, Groq, Ollama, MiniMax, or custom providers
- **Scan Modes** — Single site or wildcard (subdomain enumeration) scanning
- **Multi-Target Queue** — Upload a targets file for sequential auto-scanning
- **Vulnerability Reporting** — Structured JSON reports with CVSS scores, PoC scripts, and remediation steps
- **Multi-Agent Support** — Spawn sub-agents for parallelized task delegation
- **Browser Automation** — Headless Chromium via go-rod for dynamic page testing
- **Real-Time Token Counter** — Tracks LLM token usage (K/M format) across iterations
- **11 Built-in Tools** — Terminal, Python, browser, file editor, web search, HTTP proxy, Notes, and more

## Architecture

```
cmd/xalgorix/           CLI entrypoint (flags, web/CLI mode)
internal/
├── agent/              Core agent loop (LLM → parse → execute → repeat)
│                       20 critical rules, 20-phase methodology
├── config/             Environment-based configuration
├── llm/
│   ├── client.go       OpenAI-compatible API client (streaming + token tracking)
│   └── parser.go       Multi-format XML tool call parser
├── tools/
│   ├── registry.go     Tool registry + parameter validation
│   ├── terminal/       Shell commands with auto-install
│   ├── python/         Python subprocess execution
│   ├── browser/        Headless Chromium automation (go-rod)
│   ├── fileedit/       File viewing, editing, listing, searching
│   ├── proxy/          Caido HTTP proxy integration
│   ├── websearch/      DuckDuckGo web search
│   ├── reporting/      Vulnerability reporting + JSON export
│   ├── notes/          Agent memory (persistent key-value notes)
│   ├── finish/         Scan completion signal
│   └── agentsgraph/    Multi-agent delegation
├── tui/                Terminal UI (CLI mode)
└── web/
    ├── server.go       HTTP + WebSocket server, scan persistence, Discord webhook
    └── static/         Embedded HTML/CSS/JS dashboard (liquid glass theme)
```

## Quick Start

### Prerequisites

- Go 1.25+
- An OpenAI-compatible LLM API (OpenAI, Anthropic, DeepSeek, Ollama, etc.)
- Security tools are auto-installed, but pre-installing recommended: `nmap`, `nuclei`, `subfinder`, `httpx`

### Install

```bash
go install github.com/xalgord/xalgorix/cmd/xalgorix@latest
```

> **💡 Recommended:** Install and run as `root` user to avoid permission issues when Xalgorix auto-installs missing security tools (nmap, nuclei, subfinder, etc.).

<details>
<summary>Or build from source</summary>

```bash
git clone https://github.com/xalgord/xalgorix.git
cd xalgorix
go build -ldflags "-s -w" -o xalgorix ./cmd/xalgorix/
sudo mv xalgorix /usr/local/bin/
```

</details>

### Configure

Create `~/.xalgorix.env` (recommended — works with `sudo`):

```bash
# ~/.xalgorix.env
XALGORIX_LLM=openai/gpt-5.4
XALGORIX_API_KEY=sk-your-key-here
XALGORIX_API_BASE=https://api.openai.com/v1

# Optional — Discord notifications
XALGORIX_DISCORD_WEBHOOK=https://discord.com/api/webhooks/your-webhook-url
```

<details>
<summary>Or use environment variables</summary>

```bash
export XALGORIX_LLM="openai/gpt-5.4"              # or anthropic/claude-sonnet-4.6, deepseek/deepseek-v4, etc.
export XALGORIX_API_KEY="sk-your-key-here"
export XALGORIX_API_BASE="https://api.openai.com/v1"  # provider API base
export XALGORIX_DISCORD_WEBHOOK="https://discord.com/api/webhooks/your-webhook-url"
```

</details>

### Run

```bash
# Web UI (recommended)
sudo xalgorix --web                    # http://localhost:1337
sudo xalgorix --web --port 8080        # custom port

# CLI mode
sudo xalgorix --target https://example.com
sudo xalgorix --target https://example.com --instruction "Focus on SQLi and XSS"
sudo xalgorix --target 192.168.1.0/24 --model openai/gpt-4o
```

> **Tip:** Run as `root` for full tool access (nmap SYN scan, package installation, etc.)

### Custom Instructions

Use the `--instruction` flag (CLI) or the instructions textarea (Web UI) to guide the agent. Here are some examples:

```text
# Authenticated Testing — provide credentials
Use these credentials for authenticated testing:
  Email: admin@example.com
  Password: P@ssw0rd123
Login at https://example.com/login and test all authenticated endpoints.

# Scope Restrictions
Only test *.example.com subdomains. Do NOT test third-party domains or CDNs.

# Focus on Specific Vulnerabilities
Focus on SQL Injection, IDOR, and authentication bypass. Skip XSS and CSRF.

# API Testing
The API docs are at https://example.com/api/docs. Test all API endpoints
for broken access control using these API keys:
  Admin:  Bearer eyJhbG...
  User:   Bearer eyJibW...

# Bug Bounty Program Rules
This is a HackerOne program. Out of scope: DoS, social engineering, phishing.
Only report P1-P3 severity bugs. Rate limiting is in place — keep requests slow.

# Internal Network
Scan the 10.0.0.0/24 subnet. Focus on exposed services, default credentials,
and unpatched CVEs. Check for SMB shares and open databases.
```

> **Tip:** The more context you give, the smarter the agent's testing strategy will be.

## Web UI

The liquid glass dark mode dashboard provides:

| Feature | Description |
|---------|-------------|
| **Live Feed** | Real-time WebSocket stream of agent actions |
| **Scan Modes** | Dropdown: Single Site / Wildcard scan |
| **Multi-Target** | Upload a file with one target per line |
| **Custom Instructions** | Textarea or file upload for extra directives |
| **LLM Provider Switching** | Dropdown to switch between providers at runtime |
| **Discord Notifications** | Paste a webhook URL for scan/vuln/completion alerts |
| **Vulnerability Cards** | Severity-colored cards with CVSS scores (real-time) |
| **Token Counter** | Real-time LLM token usage display (K/M format) |
| **Persistent Scans** | Scan data saved to disk, survives page refreshes |
| **Live Clock & Animations** | Real-time clock, breathing icons, scan pulse |

## Discord Webhook Notifications

Get real-time Discord alerts with rich embed messages:

| Event | Embed Color | Details |
|-------|-------------|---------|
| 🚀 **Scan Started** | Green | Target list, scan mode, total count |
| 🐛 **Vulnerability Found** | Red/Amber/Blue by severity | Title, endpoint, CVSS score |
| ✅ **Scan Finished** | Blue | Vuln count, completion time |

**Setup options:**
```bash
# Option 1: Environment variable (recommended)
export XALGORIX_DISCORD_WEBHOOK="https://discord.com/api/webhooks/1234/abcdef"

# Option 2: Web UI — paste the URL in 🔔 Discord Notifications section
```

## Persistent Scan Data

All scan data is stored in `~/xalgorix-data/scans/` with per-target directories:

```
~/xalgorix-data/scans/
├── example.com_a3f8b2/
│   └── scan.json          # Full scan record (events, vulns, stats, tokens)
├── target.io_c9d1e4/
│   └── scan.json
└── ...
```

- **Auto-cleanup:** Scans older than 30 days are automatically deleted on server startup
- **Page refresh safe:** Last scan is restored on page load via `/api/scans/latest`
- **Scan history API:** `GET /api/scans` returns all saved scans (newest first)

## Built-in Tools

| Tool | Description |
|------|-------------|
| `terminal_execute` | Run shell commands (auto-installs missing tools) |
| `python_action` | Execute Python scripts in subprocess |
| `browser_action` | Headless Chromium: navigate, click, type, screenshot, JS |
| `send_request` | HTTP requests through Caido proxy (fallback: direct) |
| `list_requests` | Query Caido's captured traffic via GraphQL |
| `str_replace_editor` | View, create, and edit files |
| `list_files` | List directory contents |
| `search_files` | Grep/ripgrep across files |
| `web_search` | DuckDuckGo search |
| `report_vulnerability` | Log findings with severity, CVSS, PoC, remediation |
| `add_note` / `read_notes` | Persistent key-value memory across iterations |
| `create_agent` | Spawn sub-agents for parallel tasks |
| `finish` | Complete the scan with summary |

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `XALGORIX_LLM` | *(required)* | Model name (e.g. `openai/gpt-5.4`) |
| `XALGORIX_API_KEY` | *(required)* | API key |
| `XALGORIX_API_BASE` | `https://api.openai.com/v1` | API base URL |
| `XALGORIX_DISCORD_WEBHOOK` | — | Discord webhook URL for notifications |
| `XALGORIX_MAX_ITERATIONS` | `0` (unlimited) | Max agent iterations |
| `XALGORIX_WORKSPACE` | `$PWD` | Working directory |
| `XALGORIX_REASONING_EFFORT` | `high` | LLM reasoning effort |
| `XALGORIX_LLM_MAX_RETRIES` | `5` | API retry count |
| `XALGORIX_DISABLE_BROWSER` | `false` | Disable headless browser |
| `CAIDO_PORT` | auto-detect | Caido proxy port |
| `CAIDO_API_TOKEN` | — | Caido GraphQL API token |

## Recon Toolset

The agent uses an extensive set of recon tools (auto-installed if missing):

| Category | Tools |
|----------|-------|
| **Subdomain Enumeration** | subfinder, findomain, assetfinder, amass |
| **URL Discovery** | gospider, katana, hakrawler, gau, waymore, waybackurls |
| **Parameter Discovery** | paramspider, arjun, x8, uro |
| **Live Host Probing** | httpx (Go), dnsx |
| **Port Scanning** | nmap (full TCP + top UDP) |
| **Vulnerability Scanning** | nuclei, nikto, sqlmap, dalfox |
| **Directory Fuzzing** | gobuster, ffuf |
| **Tech Fingerprinting** | whatweb, wappalyzer, wafw00f |

## Default Methodology (20 Phases)

1. **Reconnaissance** — Subdomain enum, port scanning, directory brute-force, tech fingerprinting, JS analysis, hidden param discovery
2. **Vulnerability Scanning** — Nuclei (full templates), nikto, nmap vuln scripts
3. **Content Discovery** — Directory fuzzing, backup files, admin panels, sensitive paths
4. **SSL/TLS & Headers** — Cipher enumeration, certificate validation, security header audit, CORS check
5. **Authentication Testing** — SQLi on login, brute-force, OAuth, 2FA bypass, default credentials
6. **Injection Testing** — XSS (reflected/stored/DOM), SQLi (error/blind/time), command injection, XXE, SSTI
7. **SSRF & Redirects** — Parameter fuzzing for SSRF, cloud metadata, open redirect chaining
8. **IDOR & Access Control** — Broken access control, horizontal/vertical privilege escalation
9. **API & GraphQL** — Introspection, broken object-level auth, rate limiting, mass assignment
10. **File Upload** — Extension bypass, content-type manipulation, webshell upload
11. **Deserialization & RCE** — Java/PHP/Python/Node.js/Log4j exploit chains
12. **Race Conditions** — TOCTOU, parallel request testing, business logic flaws
13. **Subdomain Takeover** — CNAME dangling, NS takeover, service fingerprinting
14. **Email Security** — SPF, DKIM, DMARC validation
15. **Cloud Misconfigs** — S3/Azure/GCP bucket enumeration, Kubernetes, Docker
16. **WebSocket Security** — Origin validation, message injection, auth bypass
17. **CMS Testing** — WordPress, Joomla, Drupal-specific scanning
18. **Broken Link Hijacking** — External link validation, content spoofing
19. **Supply Chain** — JavaScript library vulnerabilities, dependency confusion
20. **Comprehensive Reporting** — Structured JSON reports with CVSS, PoC, and remediation

## LLM Compatibility

Works with any OpenAI-compatible chat completions API:

| Provider | Model Example | Tested |
|----------|--------------|--------|
| OpenAI | `openai/gpt-5.4` | ✅ |
| Anthropic | `anthropic/claude-sonnet-4.6` | ✅ |
| DeepSeek | `deepseek/deepseek-v4` | ✅ |
| Google | `google/gemini-3.1-pro` | ✅ |
| Groq | `groq/llama-4-70b` | ✅ |
| MiniMax | `minimax/MiniMax-M2.5` | ✅ |
| Ollama | `ollama/llama4` | ✅ (local) |

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">
<sub>Built by <a href="https://github.com/xalgord">@xalgord</a> — for security researchers. Use responsibly.</sub>
</div>
