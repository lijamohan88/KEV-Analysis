# CISA KEV Catalog — Live Analysis Dashboard

Real-time analysis of CISA's [Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog.

## What This Does

Every time someone visits the dashboard, it pulls the latest data directly from CISA's official JSON feed and computes all analysis client-side — no backend, no database, always current.

## Key Findings (as of March 2026)

- **1,536 CVEs** across 253 vendors and 626 products
- **Microsoft owns 23.5%** of the entire catalog (361 CVEs)
- **20.3% linked to ransomware** — but edge devices hit 38%
- **QNAP at 82%** ransomware intensity — highest of any vendor
- **18-year-old CVEs** still being added and actively exploited
- **Memory safety issues** make up 24% of the catalog

## Live Dashboard

**[→ View the Live Dashboard](https://YOUR_USERNAME.github.io/cisa-kev-dashboard/)**

## Tech Stack

- React 18 + Vite
- Recharts for visualizations
- CISA KEV JSON feed (live fetch)
- GitHub Pages (auto-deploys daily)

## Run Locally

```bash
npm install
npm run dev
```

## Data Source

[CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — updated by CISA as new exploited vulnerabilities are confirmed.

---

Built by **Lija Mohan** · [LinkedIn](https://www.linkedin.com/in/YOUR_PROFILE/)
