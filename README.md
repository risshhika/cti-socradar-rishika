<p align="center"><img src="docs/brand/ctiops-logo-dark.svg" alt="CTI Ops" width="360"></p>

# CTI Ops Platform — P4 Phishing Campaign Clustering & P6 Sector Threat Landscape

An enterprise-style threat-intelligence platform built for the SOCRadar Senior CTI Ops Engineer project.
It runs two automated pipelines on **public, passive data only** and presents the results in a
sidebar-driven analyst UI with hand-check (analyst verdict) workflow, exports and a pipeline console.

The UI uses the Mintverse design system (tokens, ECharts theme, chart cards with a question, source line,
table view and PNG export, KPI tiles with deltas, ⌘K palette, presentation mode, light and dark themes).
Charts include world maps, calendar and matrix heatmaps, Sankey flows, a shared-infrastructure network
graph, actor rank-over-time, stream and share charts, treemaps, sunbursts, radars, box plots and funnels.

| Module | Project | What it delivers |
| --- | --- | --- |
| **Phishing Intelligence** | P4 | Collects live phishing pages for a sector/brand set from urlscan.io and OpenPhish, fetches them, extracts structural features, clusters them into **campaigns**, fingerprints the **kit** behind each, and emits **detections** (Sigma for web & mail gateways, YARA for kit HTML, URL regexes, IOC lists, STIX 2.1) plus Markdown **campaign cards** with takedown targets. |
| **Threat Landscape** | P6 | Ingests ransomware leak-site victims (ransomware.live, cross-checked against RansomLook and the ransomwatch archive), classifies victims by **sector, region and size**, tracks **actor** activity and trends, mines public reporting for **initial-access-broker** listings and prices, and generates a short **monthly CISO briefing**. |

## Quick start (clean machine)

Requirements: Python 3.12 (`uv` installs it if missing), Node 20+, `uv` (`brew install uv` / `pip install uv`), internet access.

```bash
make setup          # backend venv + frontend deps
make run-all        # P6 then P4, ~5-10 min, prints a summary per pipeline
make build          # production UI bundle
make serve          # http://127.0.0.1:8000
```

Or everything in one go: `./scripts/run_all.sh`.

For development with hot reload: `make dev` (API on :8000, Vite on :5173 proxying `/api`).

No API keys are needed. Optional keys in `.env` (see `.env.example`) unlock urlscan.io DOM downloads
(instead of visiting phishing pages directly) and Claude-assisted classification / briefing prose.
Every LLM prompt is logged to `data/artifacts/prompts.jsonl`.

Scope (sector, brands, region, window, IAB feeds) is in `config/scope.yaml` and editable in the UI
under **Scope & Settings**. Pipelines can be run from the UI (**Pipelines & Runs**) or the CLI:

```bash
cd backend && .venv/bin/python -m app.cli run phishing
cd backend && .venv/bin/python -m app.cli run landscape
```

`make clean-data` wipes the database, HTTP cache and captured artifacts for a true clean start.

## Architecture

```
config/scope.yaml            analyst scope (sector / brands / region / window / feeds)
backend/app
  main.py                    FastAPI app, serves API + built frontend
  cli.py                     run <pipeline> | serve
  config.py  db.py  models.py  schemas.py
  pipelines/runner.py        run tracking, streamed logs, one run per pipeline
  api/                       overview, scope, pipelines, reviews, phishing, landscape
  modules/common             cached HTTP client with rate limiting, optional Claude helper
  modules/phishing           collectors → fetch → features → cluster → fingerprint → detections
  modules/landscape          collectors → classify → cross-source → actors → IAB → trends → briefing
frontend/src                 React + TypeScript, Mintverse design tokens, TanStack Query, ECharts
data/                        SQLite DB, HTTP cache, captured HTML, exports (gitignored)
docs/                        know-how report, prompt log
```

### P4 pipeline

1. **Collect** — urlscan.io public search (brand title/URL queries + generic phishing tag sweep, rate-limited
   to the unauthenticated 30 req/min), OpenPhish community feed. Deduplicated by URL.
2. **Fetch** — direct visit of each page (allowed by the brief for P4): no JavaScript execution, no form
   submission, 10 s timeout, 2 MB cap, 3 redirects max. Status recorded as ok / offline / blocked / error.
   HTML stored under `data/artifacts/phishing/html/`.
3. **Features** — title, forms & input names, form action hosts (credential exfil endpoints), script hosts,
   obfuscation markers, favicon, text tokens, DOM tag-sequence simhash, cloaking/anti-bot markers, kit path
   markers, Telegram bot tokens / hard-coded emails, brand detection.
4. **Cluster** — exact structural grouping (simhash + brand) then DBSCAN on a combined simhash-Hamming +
   Jaccard distance. Each cluster becomes a campaign with cohesion score, infrastructure summary and
   ranked takedown targets.
5. **Fingerprint** — signature database `modules/phishing/kits.yaml` (public kit families with references);
   unmatched clusters with shared markers become *inferred* kits for analysts to name.
6. **Detections** — per campaign: Sigma (proxy / email), YARA (kit HTML), URL regex, IOC domain/IP/URL lists,
   STIX 2.1 bundle, Markdown campaign card.

### P6 pipeline

1. **Ingest** victims per month from ransomware.live (`/v2/victims/{Y}/{M}`), actors from `/v2/groups`,
   public breach reporting from `/v2/recentcyberattacks`; RansomLook (live) and ransomwatch `posts.json` (archive, frozen June 2025) as second aggregators.
2. **Classify** sector (source label → keyword map → optional LLM), region (ISO country → region /
   sub-region), size band (revenue / employee regexes on the leak-site description).
3. **Cross-source** match victims between aggregators (normalized name + group alias + ±7 days) to
   measure coverage.
4. **Actors** — monthly counts (total and in-scope), top sectors/countries, status, trend, TTPs/tools/DLS.
5. **IAB** — RSS feeds of public vendor/news reporting filtered by access-broker keywords; access types,
   prices, revenue claims, countries and sectors extracted by regex (optional LLM).
6. **Trends & briefing** — monthly stats and a Jinja2 Markdown briefing (template prose; LLM-rewritten
   executive summary optional).

## Hand check & evaluation support

Every campaign, sample, kit, victim, actor, IAB listing and briefing has an **analyst verdict** control
(agree / over-flagged / missed / unsure + note). The **Analyst Review** page aggregates them into a
precision proxy per entity type — this is the "hand check of a sample of output" the project guide asks for.

Objective checks built in:
- P6: cross-source agreement rate between ransomware.live and RansomLook/ransomwatch over their overlap window.
- P4: cluster cohesion, kit match confidence, fetch success rate; verdicts recorded per campaign/sample.

## Exports

| Endpoint | Content |
| --- | --- |
| `/api/phishing/export/campaign-cards` | Markdown campaign cards |
| `/api/phishing/export/stix` | STIX 2.1 bundle (indicators, campaigns) |
| `/api/phishing/export/sigma`, `/yara`, `/iocs`, `/csv` | Detection bundles |
| `/api/landscape/export/victims-csv`, `/actors-csv`, `/iab-csv` | Tracker data |
| `/api/landscape/export/briefing-md?id=` | Monthly briefing |
| `/api/phishing/viz`, `/api/phishing/campaigns/{id}/graph` | Chart data for the P4 pages |
| `/api/landscape/viz`, `/api/landscape/actors/{slug}/viz`, `/api/landscape/victims/summary` | Chart data for the P6 pages |

## Credits

Data: [urlscan.io](https://urlscan.io) public search & screenshots · [OpenPhish](https://openphish.com)
community feed · [ransomware.live](https://www.ransomware.live) (Julien Mousqueton) ·
[ransomwatch](https://github.com/joshhighet/ransomwatch) (joshhighet) · [RansomLook](https://www.ransomlook.io) · public RSS feeds of The Record,
Cyble, SOCRadar, Group-IB, KrebsOnSecurity, The Hacker News, Dark Reading, Intel 471.
Kit signatures are derived from public vendor reporting referenced in `kits.yaml`.
Libraries: FastAPI, SQLModel, scikit-learn, BeautifulSoup, feedparser, React, Apache ECharts, cmdk, Radix, Tailwind.
World outline: Natural Earth via the Apache ECharts 4 map pack (`frontend/public/geo/world.json`).
Design system ported from the author's Mintverse project.

## Tests

```bash
make test
```

## Know-how report

See `docs/KNOWHOW_REPORT.md` (milestones, methods, prompts, results & limitations) and `docs/PROMPTS.md`.
