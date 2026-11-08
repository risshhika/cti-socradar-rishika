# Know-how report — CTI Ops Platform (P4 + P6)

*Working notes, not a client report. Kept short on purpose. Numbers in "Results" are filled from the
latest clean-start run; everything else is written as the work happened.*

## 1. Milestones (in order)

| # | Step | Produced | Decisions / dead ends |
| --- | --- | --- | --- |
| 1 | Read the project guide, chose P4 **and** P6 and decided to ship them as one platform with a shared shell (sidebar, pipeline console, analyst review, exports) rather than two scripts. | Project scope | Two modules share ~40% of the plumbing (runs, reviews, HTTP cache, exports), so one platform was cheaper than two repos and mirrors how a CTI vendor sells modules. |
| 2 | Probed every candidate public source from the shell before writing code. | Source matrix | **Worked:** urlscan.io public search (30 req/min, no key), urlscan screenshots, OpenPhish feed (302 → GitHub raw), ransomware.live v2 (victims/month, groups, sectors, cyberattacks), ransomwatch posts.json, 8 vendor/news RSS feeds. **Dead ends:** PhishStats API unreachable, URLhaus now requires an auth key, urlscan `result/` and `dom/` endpoints return 403 without a key (→ fetch pages directly, which the brief allows for P4), BleepingComputer/KELA/Flare feeds block non-browser clients (403), ransomware.live has no IAB endpoint (→ mine public reporting via RSS). |
| 3 | Designed the data model and API contract first (SQLModel tables, Pydantic schemas, TypeScript mirror) so backend modules and the frontend could be built in parallel. | `models.py`, `schemas.py`, `types.ts`, `api.ts` | SQLModel 0.0.48 rejects naive datetimes → everything timezone-aware UTC. |
| 4 | Built the platform shell: FastAPI app, run tracker with streamed logs, analyst review API, scope config, cached/rate-limited HTTP client, optional Claude helper with prompt logging; React shell with collapsible sidebar, top bar (scope chips, run status, theme). | Running skeleton | Vite scaffold initially landed in the wrong folder because of a carried-over shell cwd; moved. |
| 5 | P4 module: collectors → fetch → features → clustering → kit fingerprinting → detections, API and exports. | 114 campaigns, 755 detections on the first full run | **Dead end:** unauthenticated urlscan rejects wildcard/regex queries → switched to title and URL term queries (wildcards only with a key). **Bug:** recursive DOM walk hit Python's recursion limit on a deeply nested page → iterative walk, per-page failures isolated. **Over-flag found by hand check:** 20/20 samples labelled "W3LL / OV6" were wrong (the 3-char marker matched inside base64 blobs) → kits now need ≥ 2 independent markers and short tokens must match on word boundaries. Most clusters now get an honest *inferred* kit instead of a wrong named one. |
| 6 | P6 module: ingestion → classification → cross-source → actors → IAB mining → trends → briefing, API and exports. | 5.6k victims, 417 actors, 36 IAB candidates, 3 briefings | **Dead end:** ransomwatch stopped updating in June 2025, so cross-source agreement was 0% → added RansomLook (maintained ransomwatch fork) as the live second aggregator and only measure agreement over the overlap window. **Bug:** ransomware.live returns actor `tools` as a category dict for some groups → flattened to "Tool (Category)". Non-Latin actor names (e.g. Cyrillic) slugify to empty → hash slug plus name lookup. IAB feeds paged back 12 pages to cover six months. |
| 7 | Frontend pages for both modules, pipelines console, review dashboard, settings. | 21 pages | Captured phishing HTML was briefly exposed as a static `text/html` mount on the app origin, which would execute in the analyst's browser → removed; HTML is only served as `text/plain`. |
| 9 | Redesign on the Mintverse design system and a much richer chart set. | ECharts layer, 20+ chart types, 5 chart-data endpoints | Shared chart builders first, then two parallel page rebuilds. Their reports surfaced builder defects (scroll-hijacking maps and graphs, unreadable funnel and heatmap labels in light theme, a Europe map coloured by the US scale), fixed once in the shared builders. |
| 8 | Clean-start run of both pipelines, browser verification, hand check of a sample. | §4 | SQLite "database is locked" when both pipelines run in parallel → 60 s busy timeout. A server restart marked a live CLI run as failed → runs record their PID and recovery only fails runs whose process is gone. |

## 2. Methods

### Inputs chosen and why
- **P4:** sector *Financial services & payments*, ten brands (PayPal, Chase, Wells Fargo, Bank of America, HSBC,
  Barclays, Santander, Revolut, Coinbase, Binance), last 14 days. Finance is the most-phished sector in public
  feeds so a 14-day window gives enough pages per brand for clustering without a paid urlscan plan.
- **P6:** sector *Healthcare*, region *Europe*, six months. Healthcare has clear sector labels on leak-site
  aggregators (good ground truth for the classifier) and European victims are numerous enough for monthly
  trends but small enough to hand-check.

### Sources and techniques

**P4 — phishing**

| Stage | Technique | Why |
| --- | --- | --- |
| Collect | urlscan.io public search: per-brand `page.title` and URL-term queries plus a generic `task.tags:phishing` sweep over the window, rate-limited to 28 req/min; OpenPhish community feed. Dedup by URL, cap 400. | urlscan gives scan metadata (IP, ASN, country, screenshot) for free; OpenPhish adds fresh URLs urlscan has not seen. |
| Fetch | Direct GET (permitted for P4): no JS, no form submission, 10 s timeout, 2 MB cap, ≤ 3 redirects, browser UA, 8 threads. | urlscan DOM/result endpoints need a key. |
| Features | BeautifulSoup/lxml: forms and input names, form-action hosts, script hosts, obfuscation (eval/atob/hex blobs), favicon, meta generator, visible-text tokens, 64-bit simhash of the DOM tag sequence, cloaking/anti-bot markers, Telegram bot tokens and hard-coded drop emails, path markers, brand detection with confidence. | Kits reuse templates: the DOM skeleton and form field names survive re-hosting even when domains and text change. |
| Cluster | Stage 1: identical simhash + brand. Stage 2: DBSCAN on a combined distance (normalized simhash Hamming + Jaccard over input names, script hosts, path tokens, favicon, top text tokens). Branded singletons kept as single-sample campaigns. | Exact grouping is cheap and certain; DBSCAN catches the same kit with minor edits without fixing a cluster count. |
| Fingerprint | `kits.yaml`: public kit families with URL/HTML/script/form/title markers and weights; a match needs score ≥ threshold **and** ≥ 2 distinct markers. Unmatched clusters of ≥ 3 become *inferred* kits listing their shared markers. | Named kits give analysts context; inferred kits stop the pipeline from forcing a wrong label. |
| Detect | Per campaign: Sigma (proxy and email log sources), YARA on kit HTML (≥ 2 shared strings), generalized URL regex, IOC domain/IP/URL lists, STIX 2.1 bundle, Markdown campaign card with ranked takedown targets (apex domains, hosting ASNs, exfil endpoints). | These are the artifacts a mail or web gateway and a takedown desk can consume directly. |

**P6 — landscape**

| Stage | Technique | Why |
| --- | --- | --- |
| Ingest | ransomware.live `/v2/victims/{Y}/{M}` for window + 1 month, `/v2/groups`, `/v2/recentcyberattacks`; RansomLook (live) and ransomwatch (archive) as second aggregators. | ransomware.live has the richest per-victim fields (sector, country, description). |
| Classify | Sector: source label → keyword map → optional LLM → unknown. Region: ISO2 → region and sub-region (DACH, Nordics, UK&I, Benelux). Size: revenue and employee regexes on the leak-site description. | Every label stays traceable to a method (`sector_method`, `size_basis`). |
| Cross-source | Normalized victim name (casefold, punctuation and legal suffixes stripped) + group alias + ± 7 days. | Objective coverage check on aggregator data that is otherwise unverifiable. |
| Actors | Monthly totals and in-scope counts, top sectors/countries, active if a victim in the last 60 days, trend from the last two full months (± 25%). | Answers the CISO question "who is targeting companies like us". |
| IAB | Eight public RSS feeds paged back ~6 months, keyword-filtered, article text fetched; regex extraction of access types, USD prices (ranges, "2k"), victim revenue (kept separate from price), countries, sectors, broker handles, ransomware groups (with a block list for common-word group names). | No public IAB dataset exists; vendors' weekly dark-web roundups are the best passive proxy. |
| Briefing | Jinja2 Markdown template fed by the same stats the dashboard uses; optional Claude rewrite of the executive summary and priorities only (tables stay template-generated). | Numbers in the briefing always trace back to the tracker. |

### How results were checked
- Analyst verdicts (agree / over-flag / miss / unsure) recorded in the UI per entity; aggregated as a precision proxy.
- P6 cross-source agreement between ransomware.live and ransomwatch.
- P4 cluster cohesion and kit confidence thresholds; manual inspection of captured HTML and screenshots.

## 3. Prompts
All prompts used with AI assistants are listed in `PROMPTS.md` (model, prompt, what was done with the output).
Runtime LLM prompts (optional, only when `CTIOPS_ANTHROPIC_API_KEY` is set) are logged by the platform to
`data/artifacts/prompts.jsonl`.

## 4. Results and limitations

Clean-start run on 2026-11-08 (`make clean-data && make run-all`, no API keys, no manual steps). Both pipelines succeeded.

| Pipeline | Runtime | Output |
| --- | --- | --- |
| P6 landscape | 62 s | 5,663 victims (May–Nov 2026), 418 actors, 81 in scope (Healthcare · Europe), 36 IAB candidates from 775 feed entries across 8 feeds, 100 public breach reports, briefings for Oct and Nov 2026 |
| P4 phishing | 401 s | 400 samples (269 urlscan, 131 OpenPhish), 250 fetched, 97 campaigns (31 with ≥ 2 samples), 30 kits (16 signature, 14 inferred), 644 detections (194 Sigma, 62 YARA, 97 each URL-regex / domain / IP / URL IOC sets) |

**P6 findings.** In-scope victims concentrate in Germany (18), the UK (12), Italy and Switzerland (8 each). The leading groups are *The Gentlemen* (17), Qilin (9), then SafePay, ShinyHunters, Space Bears and LockBit 5 (3–4 each). 76% of ransomware.live victims (4,230 of 5,558) are confirmed by RansomLook within ±7 days over the shared window, which is the objective coverage check for the tracker.

**P4 findings.** Ten-brand finance scope, 14 days. The most-targeted brands in fetched pages are Binance, HSBC, Coinbase and PayPal. The strongest campaigns are template-identical clusters on throwaway domains: a Banistmo loyalty-points lure on seven `.click` domains behind a "Verify you are human" gate, a multi-brand `.ph` redirect operation impersonating HSBC, Bank of America, Chase and Scotiabank, and a five-domain Coinbase cluster.

### Hand check (sample of output, by hand)

| Sample | Agreed | Over-flagged | Missed |
| --- | --- | --- | --- |
| 12 random in-scope victims | 9: sector and country correct (pharma distributor, rehab and eye clinics, nursing home, diagnostics lab…) | 2: *Andorra Life* is an insurer labelled Healthcare; *MIM Fertility* is described as US-based but carries GB. 1 borderline (a nutritional-supplement maker). Both errors come from the aggregator's own labels, which the classifier trusts first. | – |
| 12 largest phishing campaigns | 6 coherent, real campaigns (Banistmo `.click`, `.ph` multi-brand, Coinbase, two Roblox, numeric-domain dashboard) | 2 not phishing: a critical-news site about HSBC (`badhsbc.com`) and legitimate `google.com` pages that came in through the feeds. 3 over-merged or weak clusters (generic `pages.dev` / `edgeone.dev` hosting templates, a mixed HSBC cluster with cohesion 0.58). | 1 out-of-scope but real (bet365 betting spam); Banistmo is not in the brand list, so its campaign carries no brand. |
| Kit labels (earlier run) | – | 20/20 "W3LL / OV6" labels wrong: a three-character marker matched inside base64. Fixed by requiring two independent markers and word boundaries. | – |

### Limitations
- **P4 feeds.** Without an urlscan key, wildcard queries are rejected and DOMs cannot be downloaded, so pages are fetched directly; 37% were blocked by cloaking or already offline. JavaScript is not executed, so script-built pages yield weak features. 44% of samples carry no detected brand.
- **P4 precision.** Feed tags are trusted as "phishing", so legitimate pages (google.com) and critical sites slip in. Next step: drop samples on brand-owned / top-ranked domains and require a credential form or exfil endpoint before a sample can seed a campaign.
- **P4 clustering.** Free hosting platforms (`pages.dev`, `edgeone.dev`) share a DOM skeleton, which over-merges unrelated pages. A hosting-template blocklist for the simhash stage would fix most of it.
- **P6 labels.** Sector and country come from ransomware.live for 5,662 of 5,663 victims, so its mistakes pass through. Size band is unknown for 66 of 81 in-scope victims because leak posts rarely state revenue or headcount.
- **P6 IAB.** Public reporting rarely carries prices: 36 candidates, 6 with a price, 1 with high relevance. The market view is directional, not a price index.
- **Both.** SQLite single file; fine for a candidate project, not for concurrent analysts.
