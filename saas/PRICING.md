# Xalgorix SaaS — Pricing Strategy

## Plans

| Feature | Free | Pro ($49/mo) | Enterprise ($199/mo) |
|---------|------|-------------|---------------------|
| Scans per month | 3 | 50 | Unlimited |
| Concurrent scans | 1 | 3 | 10 |
| Scan duration limit | 30 min | 2 hours | 4 hours |
| Targets file upload | ❌ | ✅ | ✅ |
| Scheduled scans | ❌ | ✅ | ✅ |
| PDF reports | ❌ | ✅ | ✅ |
| API access | ❌ | ✅ | ✅ |
| Discord/Slack alerts | ✅ | ✅ | ✅ |
| Data retention | 30 days | 1 year | 2 years |
| Support | Community | Email | Priority |
| Custom skills | ❌ | ❌ | ✅ |
| Team members | 1 | 5 | 25 |
| CI/CD integration | ❌ | ✅ | ✅ |
| BYOK (own LLM key) | ✅ | ✅ | ✅ |

## Revenue Projections

| Month | Free Users | Pro | Enterprise | MRR |
|-------|-----------|-----|-----------|-----|
| 1 | 100 | 5 | 0 | $245 |
| 3 | 500 | 25 | 2 | $1,623 |
| 6 | 1,000 | 50 | 5 | $3,445 |
| 12 | 3,000 | 150 | 15 | $10,335 |

## Cost Structure (Monthly)

| Item | Cost |
|------|------|
| VPS (scan workers) | $100-400 |
| Database (managed PG) | $25 |
| LLM API costs (if not BYOK) | Variable |
| S3 storage | $10 |
| Cloudflare | $0-20 |
| Stripe fees (2.9%) | ~3% of revenue |
| **Total fixed** | **~$200-500/mo** |

## Monetization Add-ons

- **Premium skill packs**: $29-99 one-time (API testing, cloud pentest, mobile)
- **Extra scan credits**: $1 per scan beyond plan limit
- **White-label reports**: $29/mo (custom branding on PDF reports)
- **Priority queue**: $19/mo (scans start immediately, skip queue)
