# Xalgorix SaaS — Roadmap

## Phase 1: Foundation (Weeks 1-4)

- [ ] Set up Next.js frontend with landing page
- [ ] User authentication (email + Google/GitHub OAuth)
- [ ] PostgreSQL database with user/scan/vuln tables
- [ ] Migrate current scan logic to use DB instead of filesystem
- [ ] Basic dashboard: start scan, view results, scan history
- [ ] JWT-based API authentication

## Phase 2: Cloud Infra (Weeks 5-7)

- [ ] Docker-based scan isolation (one container per scan)
- [ ] Redis-backed scan queue with concurrency control
- [ ] WebSocket proxy for live scan events through API gateway
- [ ] Scan timeout and resource limit enforcement
- [ ] Health monitoring and auto-restart for workers
- [ ] S3 integration for scan logs and artifacts

## Phase 3: Reporting + Billing (Weeks 8-10)

- [ ] Auto-generated PDF pentest reports (executive + technical)
- [ ] Stripe subscription integration (Free/Pro/Enterprise)
- [ ] Usage tracking and plan limit enforcement
- [ ] Scan scheduling (cron-based recurring scans)
- [ ] Email notifications (SendGrid/Resend)
- [ ] Slack webhook integration

## Phase 4: Launch (Weeks 11-12)

- [ ] Landing page with pricing, features, demo video
- [ ] Documentation site (how-to guides, API docs)
- [ ] Beta invites to security community
- [ ] ProductHunt launch
- [ ] Blog post: "How We Built an AI Pentester"

---

## Post-Launch (v2)

- [ ] Team workspaces with role-based access
- [ ] API key management + CI/CD integration
- [ ] Custom skill builder (drag-and-drop methodology)
- [ ] Vulnerability trend analytics and dashboards
- [ ] SSO/SAML for enterprise customers
- [ ] On-prem deployment option
- [ ] Mobile app (React Native)
- [ ] Compliance report templates (SOC2, ISO 27001, PCI-DSS)
- [ ] AI-powered remediation assistant
- [ ] Marketplace for community-built skills
