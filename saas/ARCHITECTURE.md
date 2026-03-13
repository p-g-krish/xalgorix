# Xalgorix SaaS — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────┐
│                   FRONTEND                          │
│           Next.js App (Vercel/VPS)                  │
│   Landing Page │ Dashboard │ Reports │ Billing      │
└──────────────────────┬──────────────────────────────┘
                       │ HTTPS
┌──────────────────────▼──────────────────────────────┐
│                  API GATEWAY                         │
│              Go API Server (REST + WS)               │
│   Auth │ Rate Limiting │ Scan Queue │ Webhooks       │
└───┬──────────┬──────────┬──────────┬────────────────┘
    │          │          │          │
    ▼          ▼          ▼          ▼
┌───────┐ ┌───────┐ ┌────────┐ ┌──────────┐
│Postgres│ │ Redis │ │  S3    │ │ Stripe   │
│Users   │ │Queue  │ │Reports │ │Billing   │
│Scans   │ │Cache  │ │Logs    │ │Payments  │
│Vulns   │ │Events │ │Assets  │ │Webhooks  │
└───────┘ └───┬───┘ └────────┘ └──────────┘
              │
    ┌─────────▼──────────┐
    │   SCAN WORKERS     │
    │ Docker containers  │
    │ (1 per scan)       │
    │                    │
    │ ┌────────────────┐ │
    │ │ Xalgorix Agent │ │
    │ │ + All tools    │ │
    │ │ + LLM client   │ │
    │ └────────────────┘ │
    └────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Frontend** | Next.js + TypeScript | SSR, fast, great DX |
| **API** | Go (existing codebase) | Already built, performant |
| **Database** | PostgreSQL | Relational data, JSONB for scan results |
| **Cache/Queue** | Redis | Pub/sub for WebSocket events, scan queue |
| **Object Storage** | S3 / MinIO | PDF reports, scan logs, artifacts |
| **Container Runtime** | Docker | Scan isolation, tool pre-installation |
| **Auth** | JWT + OAuth2 (Google, GitHub) | Standard, stateless |
| **Payments** | Stripe | Subscriptions, usage-based billing |
| **Hosting** | VPS (Hetzner/DigitalOcean) | Cost-effective for compute-heavy scans |
| **CDN** | Cloudflare | DDoS protection, edge caching |

---

## Database Schema (Core)

```sql
-- Users
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT UNIQUE NOT NULL,
    name        TEXT,
    avatar_url  TEXT,
    plan        TEXT DEFAULT 'free',  -- free, pro, enterprise
    stripe_id   TEXT,
    api_key     TEXT UNIQUE,
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Scans
CREATE TABLE scans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id),
    target      TEXT NOT NULL,
    scan_mode   TEXT DEFAULT 'single',
    status      TEXT DEFAULT 'queued',  -- queued, running, finished, failed
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    total_tokens BIGINT DEFAULT 0,
    iterations  INT DEFAULT 0,
    report_url  TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID REFERENCES scans(id),
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,  -- critical, high, medium, low, info
    cvss        FLOAT,
    cve         TEXT,
    endpoint    TEXT,
    method      TEXT,
    description TEXT,
    impact      TEXT,
    poc_script  TEXT,
    remediation TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Scan Events (for replay / live feed)
CREATE TABLE scan_events (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     UUID REFERENCES scans(id),
    type        TEXT NOT NULL,
    content     TEXT,
    tool_name   TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);
```

---

## Scan Isolation

Each scan runs in an ephemeral Docker container:

```dockerfile
FROM golang:1.25-alpine
RUN apk add nmap python3 git curl
COPY xalgorix /usr/local/bin/
COPY skills/ /opt/xalgorix/skills/
# Pre-install common security tools
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
ENTRYPOINT ["xalgorix", "--headless"]
```

**Resource limits per container:**
- CPU: 2 cores
- RAM: 4GB
- Disk: 10GB
- Network: egress only (no cross-container)
- Timeout: 2 hours max

---

## API Endpoints

```
POST   /api/auth/register       Register new user
POST   /api/auth/login          Login (returns JWT)
GET    /api/auth/me             Current user profile

POST   /api/scans               Start a new scan
GET    /api/scans               List user's scans
GET    /api/scans/:id           Get scan details + events
GET    /api/scans/:id/ws        WebSocket for live events
DELETE /api/scans/:id           Cancel/delete a scan
GET    /api/scans/:id/report    Download PDF report

GET    /api/vulns               List all vulns across scans
GET    /api/vulns/:id           Get vulnerability details

GET    /api/usage               Current billing period usage
POST   /api/billing/checkout    Create Stripe checkout session
POST   /api/billing/portal      Open Stripe customer portal
POST   /api/webhooks/stripe     Stripe webhook handler
```

---

## Security Considerations

- Scan containers have NO access to internal network
- API keys hashed with bcrypt before storage
- Rate limiting: 10 scans/hour (free), 100/hour (pro)
- Input validation: target must be a valid domain the user owns
- Scope verification: optional DNS TXT record proof of ownership
- All scan data encrypted at rest (AES-256)
