# Xalgorix SaaS — Product Requirements Document

## Vision

Turn Xalgorix into a cloud-hosted, self-service pentesting platform where security teams can run autonomous AI-driven security assessments without installing anything.

**Tagline:** *"AI Pentesting in One Click"*

---

## Target Users

| Persona | Description | Pain Point |
|---------|-------------|------------|
| **Startup CTO** | Small team, no dedicated security staff | Can't afford $20K+ manual pentests |
| **Security Engineer** | In-house security at mid-size company | Manual testing is slow, repetitive |
| **Bug Bounty Hunter** | Freelance security researcher | Needs faster recon + vuln discovery |
| **DevSecOps Lead** | CI/CD pipeline security | Wants automated security gates |
| **Compliance Officer** | Needs regular security audits | Quarterly pentest reports for SOC2/ISO |

---

## Core Features (MVP)

### 1. Dashboard
- Start scans by entering a target domain
- Real-time WebSocket feed (same as current UI)
- Scan history with searchable/filterable list
- Vulnerability details with severity, PoC, remediation

### 2. Authentication & Multi-Tenancy
- Sign up / login (email + OAuth: Google, GitHub)
- Per-user scan isolation (each user sees only their scans)
- API key management for programmatic access

### 3. Scan Management
- Single target and wildcard (subdomain) scan modes
- Upload targets file for batch scanning
- Schedule recurring scans (weekly, monthly)
- Scan queue with priority management

### 4. Reporting
- Auto-generated PDF pentest reports
- Executive summary + technical details
- CVSS scoring, PoC scripts, remediation steps
- Export as PDF, JSON, CSV
- Shareable report links (with expiry)

### 5. Notifications
- Email alerts for scan start/complete/vuln found
- Discord webhook integration (existing)
- Slack webhook integration (new)
- In-app notification center

### 6. API Access
- REST API for all operations
- Webhook callbacks for scan events
- CI/CD integration (GitHub Actions, GitLab CI)

---

## Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| Scan concurrency | 10 concurrent scans per node |
| Scan isolation | Docker container per scan |
| Data retention | 90 days (free), 1 year (pro) |
| Uptime SLA | 99.5% |
| Response time | Dashboard < 200ms, API < 500ms |
| Security | SOC2 Type II compliance target |

---

## Out of Scope (MVP)

- Mobile app
- On-prem enterprise deployment
- Custom LLM fine-tuning
- Collaborative team features (v2)
- SSO/SAML (v2)

---

## Success Metrics

| Metric | Target (6 months) |
|--------|-------------------|
| Registered users | 1,000 |
| Monthly active users | 200 |
| Paid subscribers | 50 |
| MRR | $5,000 |
| Scans completed | 5,000 |
| Vulns reported | 500 |

---

## Timeline

| Phase | Duration | Deliverables |
|-------|----------|-------------|
| **Phase 1: Auth + Multi-tenancy** | 4 weeks | User auth, scan isolation, basic dashboard |
| **Phase 2: Cloud Infrastructure** | 3 weeks | Docker scan runners, queue system, scaling |
| **Phase 3: Reporting + Billing** | 3 weeks | PDF reports, Stripe integration, usage limits |
| **Phase 4: Polish + Launch** | 2 weeks | Landing page, docs, beta launch |

**Total: ~12 weeks to MVP**
