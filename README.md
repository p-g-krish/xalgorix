<div align="center">

<img src="assets/banner.png" alt="Xalgorix" width="800"/>

<br/>

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-00ff88?style=for-the-badge)](LICENSE)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/xalgorix)

<p><i>Point it at a target. It does the rest.</i></p>

</div>

---

## 📸 Screenshots

### Web UI Dashboard
![Web UI](assets/ui-screenshot-1.png)

### Live Feed & Vulnerabilities
![Live Feed](assets/ui-screenshot-2.png)

### Severity Filter & Settings
![Severity Filter](assets/ui-screenshot-3.png)

### Scan Results
![Results](assets/ui-screenshot-4.png)

---

## 🚀 What is Xalgorix?

Xalgorix is a fully autonomous AI-powered penetration testing agent. It uses LLMs to drive comprehensive security assessments — from reconnaissance to exploitation — using real security tools, with zero human intervention.

> **TL;DR:** Give it a target URL, and Xalgorix will find vulnerabilities, generate a professional PDF report, and send Discord alerts — all automatically.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🤖 **Autonomous Agent** | LLM-driven pentesting with 20-phase methodology |
| 🎯 **Severity Filter** | Filter by Critical/High/Medium/Low/Info |
| 🚫 **Out of Scope** | Define targets to exclude from testing |
| 🔒 **Safety First** | Blocks destructive commands, encoding bypass detection |
| 🔌 **Circuit Breaker** | Auto-blocks failing tools after 5 attempts |
| 🌐 **Web UI** | Dark mode dashboard with live feed & token tracking |
| 💬 **Chat During Scan** | Send messages to agent while scan is running |
| 🌐 **Browser + Caido** | Playwright/Chromium with Caido proxy integration |
| 📱 **Mobile Ready** | Works on phones & tablets |
| 💾 **Scan Persistence** | Resume interrupted scans after restart |
| 📊 **PDF Reports** | Professional pentest reports auto-generated |
| 🔔 **Discord Alerts** | Get notified on scan start/vuln/completion |
| 🔧 **Auto-Install** | 70+ tool→package mappings |
| 🧠 **Multi-LLM** | OpenAI, Anthropic, DeepSeek, MiniMax, Groq, Ollama, Google |
| 🔐 **Authentication** | Optional login protection for dashboard |
| 🔍 **CVE Search** | Query NIST NVD database for CVE details |
| 🐛 **Exploit Search** | Search Exploit-DB for public exploits |
| 🔎 **Web Search** | Google, Bing, Brave, DuckDuckGo integration |
| ✅ **Tool Pre-Check** | Auto-installs missing tools before running |

---

## 🆚 Why Xalgorix?

| Feature | Xalgorix | Shannon | Strix | PentestGPT | HexStrike |
|---------|:--------:|:-------:|:-----:|:----------:|:---------:|
| **Self-Hosted** | ✅ | ⚠️ SaaS | ✅ | ✅ | ✅ |
| **Blackbox Testing** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Whitebox Testing** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Web UI Dashboard** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Live Real-Time Feed** | ✅ | ❌ | ❌ | ⚠️ Terminal | ❌ |
| **PDF Reports** | ✅ Auto | ✅ | ✅ | ⚠️ Manual | ❌ |
| **Discord Alerts** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Browser Automation** | ✅ Playwright | ✅ | ✅ | ✅ | ✅ |
| **Auto-Install Tools** | ✅ 70+ | ❌ | ⚠️ Docker | ⚠️ Docker | ⚠️ MCP |
| **Rate Limiting** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Queue/Multi-Target** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Severity Filtering** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Circuit Breaker** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Research Publication** | ❌ | ❌ | ❌ | ✅ USENIX | ❌ |
| **Requires Source Code** | ❌ | ✅ | ❌ | ❌ | ❌ |

### Key Differences

- **Shannon** — Requires source code (white-box only), part of paid Keygraph platform
- **Strix** — Docker-based, requires Docker, good reports but no UI
- **PentestGPT** — Published at USENIX Security 2024, Docker-based, terminal-only
- **HexStrike** — MCP server integration, 150+ tools via MCP protocol

### Why Xalgorix?

- **100% Self-Hosted** — No SaaS subscription, runs entirely on your machine
- **True Blackbox** — Test any target without source code
- **Rich Web UI** — Dark mode dashboard with live feed, token tracking, vulnerability details
- **Automated Reports** — Professional PDF reports auto-generated and sent to Discord
- **Zero Setup** — Auto-installs 70+ security tools with package mapping
- **Production Ready** — Rate limiting, circuit breaker, queue scanning, authentication

---

## 🛠️ Quick Start

### 1️⃣ Install

```bash
# Quick install
go install github.com/xalgord/xalgorix/cmd/xalgorix@latest

# Or build from source
git clone https://github.com/xalgord/xalgorix.git
cd xalgorix
./build.sh --install
```

### 2️⃣ Configure

```bash
# Create ~/.xalgorix.env
nano ~/.xalgorix.env
```

```bash
# Required
XALGORIX_LLM=openai/gpt-4.5
XALGORIX_API_KEY=your_api_key
# OR use Anthropic:
# XALGORIX_LLM=anthropic/claude-sonnet-4.6
# XALGORIX_API_KEY=sk-ant-...

# Optional - for custom providers (MiniMax, Ollama, etc.)
# XALGORIX_API_BASE=https://api.minimax.io/

# Optional
XALGORIX_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```

> ⚠️ **Note:** Xalgorix will refuse to start if `~/.xalgorix.env` is missing or missing required variables (`XALGORIX_LLM` and `XALGORIX_API_KEY`).

### 3️⃣ Run

```bash
# Web UI (recommended)
xalgorix --web

# Or CLI
xalgorix --target https://example.com
```

---

## 📖 Command Reference

### CLI Flags

| Flag | Alias | Description |
|------|-------|-------------|
| `--web` | `-w` | Launch the Web UI dashboard |
| `--port` | `-p` | Web UI port (default: 1337) |
| `--target` | `-t` | Target URL, IP, or local path (repeatable) |
| `--instruction` | `-i` | Custom instructions for the agent |
| `--model` | `-m` | LLM model (overrides XALGORIX_LLM) |
| `--update` | `-up` | Update to latest version |
| `--version` | `-v` | Show version |
| `--start` | — | Install and start as systemd service |
| `--stop` | — | Stop the service |
| `--restart` | — | Restart the service |
| `--uninstall` | — | Remove from system |
| `--help` | `-h` | Show help |

### Environment Variables

#### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `XALGORIX_LLM` | Model name (with optional provider prefix) | `openai/gpt-5.4`, `anthropic/claude-opus-4.6`, `deepseek/deepseek-v4`, `minimax/M3`, `custom/my-model` |
| `XALGORIX_API_KEY` | API key | `sk-...` |

#### Optional - API Base (for custom providers)

| Variable | Description | Example |
|----------|-------------|---------|
| `XALGORIX_API_BASE` | API base URL (auto-detected from provider prefix if not set) | `https://api.openai.com/`, `https://api.anthropic.com`, `https://api.minimax.io/`, `https://your-custom-llm.com/v1` |

> **💡 Custom Providers:** To use any custom LLM provider, just set `XALGORIX_LLM=custom/modelname` and `XALGORIX_API_BASE=https://your-api-endpoint.com/v1`

#### Supported Provider Prefixes (auto-detected)

| Prefix | API Base |
|--------|----------|
| `openai/` | `https://api.openai.com/v1` |
| `anthropic/` | `https://api.anthropic.com` |
| `deepseek/` | `https://api.deepseek.com/v1` |
| `groq/` | `https://api.groq.com/openai/v1` |
| `google/` | `https://generativelanguage.googleapis.com/v1` |
| `gemini/` | `https://generativelanguage.googleapis.com/v1` |
| `ollama/` | `http://localhost:11434/v1` |
| `minimax/` | `https://api.minimax.io/v1` |

#### Optional - Model Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `XALGORIX_REASONING_EFFORT` | `high` | Reasoning effort: `low`, `medium`, `high` |
| `XALGORIX_LLM_MAX_RETRIES` | `5` | Max retries on API failure |
| `XALGORIX_MEMORY_COMPRESSOR_TIMEOUT` | `60` | Context compression timeout (seconds) |
| `XALGORIX_MAX_ITERATIONS` | `0` | Max iterations (0 = unlimited) |

#### Optional - Integrations

| Variable | Description | Example |
|----------|-------------|---------|
| `XALGORIX_DISCORD_WEBHOOK` | Discord webhook for alerts | `https://discord.com/api/webhooks/...` |
| `XALGORIX_USERNAME` | Dashboard username (enables auth) | `admin` |
| `XALGORIX_PASSWORD` | Dashboard password | `secret123` |

#### Optional - Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `XALGORIX_RATE_LIMIT_REQUESTS` | `60` | Requests per window |
| `XALGORIX_RATE_LIMIT_WINDOW` | `60` | Window in seconds |

#### Optional - Browser

| Variable | Default | Description |
|----------|---------|-------------|
| `XALGORIX_DISABLE_BROWSER` | `false` | Set to `true` to disable browser automation |

### Supported Models

Xalgorix supports multiple LLM providers:

- **OpenAI** — `openai/gpt-5.4`, `openai/gpt-5`, `openai/o1`, `openai/o3`
- **Anthropic** — `anthropic/claude-opus-4.6`, `anthropic/claude-sonnet-4.6`
- **DeepSeek** — `deepseek/deepseek-v4`, `deepseek/deepseek-v3`, `deepseek/deepseek-coder`
- **Google** — `google/gemini-3.1-pro`, `google/gemini-2.0-flash`
- **Groq** — hosts Llama 4, Qwen 3, Mixtral (use model name directly)
- **Ollama** — `ollama/llama4`, `ollama/qwen3` (local)
- **MiniMax** — `minimax/M3`, `minimax/Text-01`

---

## 📖 Usage Guide

### Web UI Features

| Feature | Usage |
|---------|-------|
| 🎯 **Single Scan** | Enter URL, click Start |
| 🌐 **Wildcard Scan** | Select "Wildcard" mode for subdomain enum |
| 📂 **Multi-Target** | Upload a `.txt` file with one target per line |
| 🎯 **Severity Filter** | Check only Critical/High to skip Low/Info |
| 🚫 **Out of Scope** | Exclude targets from testing |
| 💬 **Custom Instructions** | Tell Xalgorix what to focus on |
| ⚙️ **LLM Provider** | Switch providers in settings |
| 🔔 **Discord** | Add webhook for alerts |

### Example Instructions

```text
# Focus on specific vulns
"Focus on SQL Injection and IDOR. Skip XSS."

# Authenticated testing
"Login with: admin@email.com / Password123"

# Bug bounty rules
"This is a HackerOne program. Out of scope: DoS, social engineering."

# Internal network
"Scan 10.0.0.0/24. Focus on SMB and database services."
```

---

## 🏗️ Architecture

```
xalgorix/
├── cmd/xalgorix/          # CLI entry point
├── internal/
│   ├── agent/             # 🤖 Core agent loop
│   ├── config/            # ⚙️ Configuration
│   ├── llm/               # 🧠 LLM client & parser
│   ├── tools/             # 🔧 11 built-in tools
│   │   ├── terminal/      # 💻 Command execution
│   │   ├── browser/      # 🌐 Headless Chrome
│   │   ├── python/       # 🐍 Python scripts
│   │   ├── reporting/     # 📊 Vulnerability reports
│   │   └── ...
│   ├── web/
│   │   ├── server.go      # 🌎 HTTP + WebSocket
│   │   └── static/        # 🎨 Web UI (HTML/CSS/JS)
│   └── tui/               # 📟 Terminal UI
└── skills/                # 📚 Vulnerability knowledge
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `XALGORIX_LLM` | — | Model (e.g., `openai/gpt-4.5`, `anthropic/claude-sonnet-4.6`) |
| `XALGORIX_API_KEY` | — | Your API key |
| `XALGORIX_API_BASE` | Auto-detected | API endpoint (set for custom providers) |
| `XALGORIX_DISCORD_WEBHOOK` | — | Discord webhook URL |
| `XALGORIX_RATE_LIMIT_REQUESTS` | 100 | Requests per window |
| `XALGORIX_RATE_LIMIT_WINDOW` | 60 | Window in seconds |
| `XALGORIX_MAX_ITERATIONS` | 0 | 0 = unlimited |
| `XALGORIX_DISABLE_BROWSER` | false | Disable headless Chrome |
| `CAIDO_PORT` | 8080 | Caido proxy port for browser integration |
| `CAIDO_API_TOKEN` | — | Caido GraphQL API token |

### Supported LLM Providers

| Provider | Model Example |
|----------|--------------|
| 🟢 OpenAI | `openai/gpt-5.4`, `openai/gpt-5`, `openai/o1`, `openai/o3` |
| 🔴 Anthropic | `anthropic/claude-opus-4.6`, `anthropic/claude-sonnet-4.6` |
| 🟣 DeepSeek | `deepseek/deepseek-v4`, `deepseek/deepseek-v3` |
| 🟠 Google | `google/gemini-3.1-pro`, `google/gemini-2.0-flash` |
| 🟡 Groq | `llama-4`, `qwen3`, `mixtral` (uses model name directly) |
| ⚫ Ollama | `ollama/llama4`, `ollama/qwen3` (local) |
| 🔵 MiniMax | `minimax/M3`, `minimax/Text-01` |

---

## 🛡️ Safety Features

### Blocked Commands

```
❌ Filesystem:  rm -rf /, rm -rf ~, mkfs, dd
❌ SQL:         DROP TABLE, DELETE FROM, UPDATE
❌ System:      shutdown, reboot, halt, poweroff
❌ Code:        shutil.rmtree, os.remove
```

### Encoding Bypass Detection

Xalgorix detects obfuscated commands:

| Technique | Example |
|----------|--------|
| Base64 | `echo cm0gL3JmIC8= \| base64 -d` |
| Hex | `\x72\x6d\x20\x2d\x72\x66` |
| URL | `%72%6d%20%2d%72%66` |

### Circuit Breaker

After **5 consecutive failures**, a tool is temporarily blocked for **60 seconds** to prevent wasting time.

---

## 📊 API Endpoints

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start scan |
| `POST` | `/api/stop` | Stop scan |
| `GET` | `/api/status` | Get status |
| `GET` | `/api/scans` | List scans |
| `GET` | `/api/scans/:id` | Get scan details |
| `GET` | `/api/report/:id` | Download PDF |

### Queue

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/queue/status` | Check interrupted queue |
| `POST` | `/api/queue/resume` | Resume scan |
| `POST` | `/api/queue/clear` | Clear queue |

### Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/settings/rate-limit` | Get rate limit |
| `POST` | `/api/settings/rate-limit` | Update rate limit |

---

## 🔍 Recon Tools (Auto-Installed) (Auto-Installed)

| Category | Tools |
|----------|-------|
| 🌐 Subdomains | subfinder, findomain, assetfinder, amass |
| 🔎 URLs | gospider, katana, gau, waybackurls |
| 🔧 Parameters | paramspider, arjun |
| 🚀 Ports | nmap |
| 💥 Vulns | nuclei, nikto, sqlmap, dalfox |
| 📁 Fuzzing | gobuster, ffuf |
| 🖥️ Tech | whatweb, wappalyzer |

---

## 📋 20-Phase Methodology

1. 🔍 **Recon** — Subdomains, ports, directories
2. 🦠 **Vuln Scan** — Nuclei, nikto, nmap scripts
3. 📂 **Content** — Fuzzing, backups, admin panels
4. 🔐 **SSL/TLS** — Cipher, certificates, headers
5. 🔑 **Auth** — SQLi login, brute-force, OAuth
6. 💉 **Injection** — XSS, SQLi, Command, XXE, SSTI
7. 🔄 **SSRF** — Param fuzzing, cloud metadata
8. 🚪 **IDOR** — Access control, privilege escalation
9. 🌐 **API** — GraphQL, REST, rate limiting
10. 📤 **Upload** — Extension bypass, webshells
11. ⚙️ **RCE** — Deserialization, Log4j
12. ⏱️ **Race** — TOCTOU, business logic
13. 🌟 **Takeover** — Subdomain, CNAME
14. 📧 **Email** — SPF, DKIM, DMARC
15. ☁️ **Cloud** — S3, Azure, GCP, K8s
16. 🔌 **WebSocket** — Origin, injection
17. CMS | WordPress, Joomla, Drupal
18. 🔗 **Links** — Broken link hijacking
19. 📦 **Supply Chain** — JS libs, dependencies
20. 📝 **Report** — JSON + PDF

---

## 📄 PDF Report Contents

The auto-generated report includes:

- ✅ Cover page with target & date
- 📊 Executive summary with vuln counts
- 🐛 Vulnerability details (CVSS, PoC, remediation)
- 🔗 Tested endpoints
- 📋 Methodology applied
- ⚠️ Legal disclaimer

---

## 📁 Data Storage

```
~/xalgorix-data/scans/
├── example.com_abc123/
│   └── scan.json
├── target.io_def456/
│   └── scan.json
└── queue_state.json
```

- 📅 30-day auto-cleanup
- 💾 Survives page refresh
- 🔄 Queue resume after restart

---

## 🤝 Contributing

Pull requests welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

MIT License — see [LICENSE](LICENSE).

---

## 🔗 Links

| Resource | URL |
|----------|-----|
| 📖 Documentation | [docs.xalgorix.com](https://docs.xalgorix.com) |
| 🐛 Issues | [github.com/xalgord/xalgorix/issues](https://github.com/xalgord/xalgorix/issues) |
| ☕ Donate | [buymeacoffee.com/xalgord](https://buymeacoffee.com/xalgord) |

---

<div align="center">

**Built with ⚡ by [@xalgord](https://github.com/xalgord)**  
*Use responsibly.*

</div>
