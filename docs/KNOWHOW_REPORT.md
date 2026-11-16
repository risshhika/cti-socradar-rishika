# Know-how report — CTI Ops Platform (P4 + P6)

*Working notes, not a client report. Kept short on purpose. Phase 1 (to 8 Nov) built the platform; phase 2
(14–16 Nov) added the typosquat engine, the X access-broker monitor, victim identification, client reports,
the speed-up and the per-user key setup. Numbers in "Results" are from the live database on 16 Nov 2026.*

## 1. Milestones (in order)

### Phase 1 — platform (to 8 Nov)

| # | Step | Produced | Decisions / dead ends |
| --- | --- | --- | --- |
| 1 | Read the project guide, chose P4 **and** P6 and decided to ship them as one platform with a shared shell (sidebar, pipeline console, analyst review, exports) rather than two scripts. | Project scope | Two modules share ~40% of the plumbing (runs, reviews, HTTP cache, exports), so one platform was cheaper than two repos and mirrors how a CTI vendor sells modules. |
| 2 | Probed every candidate public source from the shell before writing code. | Source matrix | **Worked:** urlscan.io public search (30 req/min, no key), urlscan screenshots, OpenPhish feed (302 → GitHub raw), ransomware.live v2, ransomwatch posts.json, 8 vendor/news RSS feeds. **Dead ends:** PhishStats API unreachable, URLhaus now requires an auth key, urlscan `result/` and `dom/` need a key, BleepingComputer/KELA/Flare feeds block non-browser clients, ransomware.live has no IAB endpoint (→ mine public reporting via RSS). |
| 3 | Data model and API contract first (SQLModel tables, Pydantic schemas, TypeScript mirror). | `models.py`, `schemas.py`, `types.ts`, `api.ts` | SQLModel rejects naive datetimes → everything timezone-aware UTC. |
| 4 | Platform shell: FastAPI app, run tracker with streamed logs, analyst review API, scope config, cached/rate-limited HTTP client, optional Claude helper with prompt logging; React shell. | Running skeleton | Vite scaffold landed in the wrong folder (carried-over shell cwd); moved. |
| 5 | P4 module: collectors → fetch → features → clustering → kit fingerprinting → detections. | 114 campaigns, 755 detections on the first full run | Unauthenticated urlscan rejects wildcards → title and URL-term queries. Recursive DOM walk hit the recursion limit → iterative walk. **Hand check:** 20/20 "W3LL / OV6" kit labels were wrong (3-char marker inside base64) → kits need ≥ 2 independent markers on word boundaries. |
| 6 | P6 module: ingestion → classification → cross-source → actors → IAB mining → trends → briefing. | 5.6k victims, 417 actors, 36 IAB candidates, 3 briefings | ransomwatch stopped in June 2025 → added RansomLook as the live second aggregator. ransomware.live returns `tools` as a dict for some groups → flattened. Non-Latin actor names slugify to empty → hash slug. |
| 7 | Frontend pages for both modules, pipelines console, review dashboard, settings. | 21 pages | Captured phishing HTML was briefly served as `text/html` on the app origin (would execute in the analyst's browser) → only served as `text/plain`. |
| 8 | Clean-start run of both pipelines, browser verification, hand check. | §4 | SQLite "database is locked" with both pipelines → 60 s busy timeout. A server restart marked a live CLI run as failed → runs record their PID. |
| 9 | Redesign on the Mintverse design system and a richer chart set. | ECharts layer, 20+ chart types | Builder defects found by the page rebuilds (scroll-hijacking maps, unreadable labels in light theme) fixed once in the shared builders. |

### Phase 2 — this week (14–16 Nov)

| # | Step | Produced | Decisions / dead ends |
| --- | --- | --- | --- |
| 10 | Pulled the `ctiops` branch and ran it on Windows. | Running platform | Smart App Control blocked a compiled SQLAlchemy DLL → pure-Python reinstall. `os.kill(pid, 0)` *kills* a process on Windows → Windows-safe PID check. ransomware.live v2 returned 404 → bulk fallback, which then hit a UNIQUE constraint → dedupe on source id. |
| 11 | Wrote a plan from my idea sheet before coding (NRDs, fragment typosquats, two detection types, X IAB monitoring), then built step 1. | Typosquat engine, `DomainLead` table, explainable 0–100 threat rank | Brand **fragment chains** (`wel*far*go*`, `coin*base*`, `pay*pal*`) plus homoglyphs and typos. False positives found while testing: "purchase" matched Chase and "revolution" matched Revolut → exclusion lists; page brand detection switched to word boundaries. |
| 12 | One 7-day window for every source, and de-duplication. | Canonical URL/host dedup, merged sources per page, retention pruning each run | Plan said 14 days with a 7-day sweep; chose 7 days everywhere because pages live hours to days. One run: 1,459 reports → 1,413 unique pages (46 merged). |
| 13 | Added certificate transparency, then removed it. | — | **Dead end:** crt.sh's index was weeks behind and CertStream was down. Removed both rather than ship stale data. |
| 14 | Hardened collection. | Saved-copy fallback, circuit breaker, outage guard, process-pool feature extraction | PhishTank's keyless download is refused when rate-limited → keep a saved copy (24 h). urlscan blocked our IP → circuit breaker, then an API key (DOM download instead of visiting the page; wildcard queries). Laptop sleep made every fetch fail → if all fetches fail, assume our network and retry next run. One page hung feature extraction for ~2 h → worker process with a timeout. |
| 15 | Executive brand report, then a walkthrough deck of one page through the pipeline. | `/phishing/report`, P4 walkthrough deck | — |
| 16 | Found a bank campaign worth a client report. | Chase live-panel report (DuckDNS, one dedicated server, live relay of one-time codes) | **Ruled out on the way:** a `.ph` multi-brand cluster (decoded tenant "dotph-nxd": registry parking/monetisation, not phishing), an HSBC page on Akamai that is a mirror, formsubmit pages that were false positives. Found the live panel by pivoting on page title, then server IP. |
| 17 | Client report template from my edited draft. | `client_report.py` + Jinja template, CLI and UI button | My edit removed every mention of internal tools → the template now **refuses to render** text naming urlscan/OpenPhish/PhishTank/WhoisDS/verdict scores. A guard refuses campaigns whose pages collect nothing: the parking cluster would otherwise have been reported as Wells Fargo phishing. Blogspot/Google IPs had been called a "dedicated server" → stricter rule (known ASN, not a CDN, not a shared platform). |
| 18 | Every brand report in the same format, with that brand's statistics and seven charts. | Brand reports (matplotlib PNGs so they survive a Google Docs import) | The lead campaign picked first was a weak one-host case → ranked candidate campaigns by strong linkage evidence. |
| 19 | X access-broker monitor (five queries, financial only). | `x_iab` pipeline, X broker monitor page, evidence capture (record, images, post card, x.com screenshot, SHA-256) | **Decisions:** X API token for scheduled runs; ZoomInfo replaced by free registries (GLEIF, Wikidata, SEC EDGAR) because ZoomInfo needs an enterprise contract and forbids scraping. No token yet → captured posts through my own signed-in browser and imported them. I declined to wire a copied browser session token into the code (account risk, terms of service). |
| 20 | Victim identification for unnamed victims (my "top-3 by revenue, then Shodan" idea). | Identify button: country + revenue-band shortlist cross-checked with Shodan | **Dead ends, each fixed:** Wikidata and its query service return 403 without a contact User-Agent; Shodan's dev plan cannot OR filters and refuses `http.html`; Shodan's Cloudflare challenged the browser User-Agent; GLEIF first matched QNB's French branch, SBI's pension fund and a Swedish "CoinOne AB" for Korea's Coinone → head-office entities only, name-extension rule, and a country check. Worked example (Indian bank, Pulse Secure): 44 exposed hosts, 0 confident matches: an honest null result. |
| 21 | Watched accounts @DailyDarkWeb and @DarkWebInformer. | 28 financial posts with x.com screenshots | Read 639 posts over 7 days; the loose in-page filter kept 51; I kept 28 by hand. The 23 false positives drove a tighter filter (see §4). |
| 22 | Speed: P4 from 17 min to 70 s. | Incremental features, cached domain matches, one urlscan call per page, batched timeouts | Two real bugs found by timing runs: the domain-match cache key depended on Python set order (changed on every start), and hung pages were restarted from zero each time another one timed out. |
| 23 | Per-user API keys; private GitHub repo. | `cli setup`, start-up gate, fresh-clone test | No keys or personal names ship in git; `serve`/`run` refuse to start until a user has set up their own keys. |
| 24 | Panel deck. | 29-slide deck with coverage checklists | — |

## 2. Methods

### Inputs chosen and why
- **P4:** sector *Financial services & payments*, ten brands (PayPal, Chase, Wells Fargo, Bank of America, HSBC,
  Barclays, Santander, Revolut, Coinbase, Binance), **7 days** (phase 1 used 14). Finance is the most-phished
  sector in public feeds; 7 days matches how long phishing pages live and keeps runs short.
- **P6 landscape:** *Healthcare*, *Europe*, six months. Healthcare has clear sector labels on leak-site
  aggregators (good ground truth) and European volumes are small enough to hand-check.
- **P6 IAB monitor on X:** *financial services* only, my area. The two scopes are configurable; aligning the
  landscape on finance is a one-line change.

### Sources and techniques

**P4 — phishing**

| Stage | Technique | Why |
| --- | --- | --- |
| Collect | urlscan.io with an API key (100 req/min): per brand `page.title:"<brand>"` and `page.domain:*<brand>*`, plus a generic phishing sweep; OpenPhish community feed; PhishTank verified-online dump (saved copy when refused); WhoisDS newly registered domains (~70,000 a day). One 7-day window, pruned every run. | urlscan gives scan metadata and stored DOMs; feeds add URLs urlscan has not seen; new-domain lists find lookalikes before anyone reports them. |
| Typosquat leads | Every new domain matched per brand: embedded brand, fragment chain, homoglyph, typo; official brand domains never flagged; exclusion words. Matches cached per day. | Catches `wellsfarg.link`, `coinbasebank.vip` and padded spellings. |
| Dedup | Canonical URL and host; one page kept per URL, every reporting source recorded. | Stops one page counting three times. |
| Capture | Stored urlscan DOM first (no contact with the host). Otherwise one GET (allowed for P4): no JS, no form submission, 10 s timeout, 2 MB cap, 24 threads. | Passive where possible. |
| Features | Forms and input names, form-action hosts, script hosts, obfuscation, favicon hash, visible text, 64-bit DOM simhash, anti-bot markers, exfil (Telegram bots, drop mailboxes, webhooks), brand with confidence. Only new or changed pages re-analysed (version-stamped). | Kits reuse templates: structure and field names survive re-hosting. |
| Cluster | Stage 1: identical simhash + brand. Stage 2: DBSCAN (eps 0.42) on combined distance over simhash and shared artefacts. | Exact grouping is certain; DBSCAN catches the same kit with small edits. |
| Fingerprint | `kits.yaml` signatures (≥ 2 independent markers); unmatched clusters become *inferred* kits. | Named kits give context; inferred kits avoid wrong labels. |
| Rank | Points model, every factor shown: lookalike hostname (type A) above brand-on-page only (type B), live, harvesting, named kit, several sources. | Analysts see why a page is critical. |
| Detect | Per campaign: Sigma, YARA, URL regex, IOC lists, STIX 2.1, campaign card. | What a mail/web gateway and a takedown desk consume. |
| Report | Approved client template (no internal tool names, defanged IOCs, MITRE mapping, hunting queries); brand reports add seven charts. | One reproducible client format. |

**P6 — landscape and IAB**

| Stage | Technique | Why |
| --- | --- | --- |
| Ingest | ransomware.live v2 (with bulk fallback), RansomLook (live), ransomwatch (archive). | Richest per-victim fields, cross-checked. |
| Classify | Sector: source label → keywords → optional LLM. Region from ISO country. Size from revenue/employee text. | Every label traceable to its method. |
| Actors, IAB, briefing | As in phase 1: actor momentum, 8 RSS feeds for access-broker reporting, Jinja briefing. | Answers "who targets companies like us, and how". |
| X monitor | Five queries (`has:images`), narrowed to financial wording, retweets excluded; plus everything from watched accounts. Financial filter by sub-type (bank, credit union, payments, insurance, crypto exchange, brokerage, lending) with "data type" false friends removed ("payment details" leaked at a retailer). Evidence: record, original images, rendered post card, x.com screenshot, all SHA-256. | IAB and breach claims surface on X first; evidence must survive deletion. |
| Firmographics | GLEIF (legal name, country, head office only), Wikidata and SEC EDGAR (revenue, staff, industry; need a contact User-Agent); optional ZoomInfo connector. Same-name companies in another country rejected. | Free and keyless where possible; every value carries its source and date. |
| Identification | Unnamed victim: country + revenue band (from the post) → company shortlist → Shodan hosts running the named product in that country → cross-reference. Reads stored data only; never contacts a host; results are leads, never an automatic victim. | My "top 3 likely victims, then verify the tech stack" idea. |

### How results were checked
- Hand check of samples (below), done by reading each record; the findings are written up rather than
  silently applied.
- P6 cross-source agreement between aggregators (81% on the dashboard for Oct 2026).
- Timed runs for the speed-up (four runs on the same data); 90 automated tests; a fresh `git clone` run to
  prove the key gate and that nothing personal ships.

## 3. Prompts
I keep a separate log of every prompt given to the AI assistant (Claude in Claude Code: model, prompt, and what I
did with the output); it is available on request. Runtime LLM prompts are logged by the platform to
`data/artifacts/prompts.jsonl`; no Anthropic key was set this week, so none were sent.

## 4. Results and limitations

Live database, 16 Nov 2026.

| Pipeline | Runtime | Output |
| --- | --- | --- |
| P4 phishing | 70 s incremental (21 new pages); 9.5 min with ~350 new pages; 17 min before the speed-up. A full clean start was not re-timed this week. | 2,219 pages in 7 days (urlscan 1,243 · OpenPhish 783 · PhishTank 118 · new domains 91; a page can have several sources); 1,696 captured; 574 campaigns (148 multi-page); 81 kits seen (5 named, 76 inferred); 3,810 detections (1,148 Sigma, 370 YARA, 574 each URL regex / IOC domain / IOC URL, 570 IOC IP); 540 typosquat leads; threat tiers 150 critical · 316 high · 623 medium · 1,130 low |
| P6 landscape | 104 s (last run, 12 Nov) | 11,392 leak-site victims, 169 in scope (Healthcare · Europe), 421 actors, 38 IAB reports (median asking price $2,750), briefings for Oct and Nov 2026 |
| P6 X monitor | manual capture | 35 financial posts with full evidence (7 from the queries, 28 from watched accounts); 13 victims matched to a company record |

**P4 findings.** Crypto brands dominate (Binance 113 pages, Coinbase 109), then Chase and Bank of America.
The clearest operation is the Chase live panel: one dedicated server, hostnames rotated daily on DuckDNS, and
one-time codes relayed while the victim waits. Large template clusters (CAMP-2026-11-002, Bank of America,
70 pages on 70 domains) show kit reuse at scale.

**P6 findings.** On X this week, financial claims include Banco do Brasil (22.7M records), Robinhood
(14.5M), Octopus Hong Kong (38M), QNB, and Raymond James and Shenwan Hongyuan on INC Ransom's leak site,
plus an LPL Financial RDP access listing ($16B revenue claimed).

### Hand check (sample of output, by hand)

| Sample | Agreed | Over-flagged | Missed / unsure |
| --- | --- | --- | --- |
| 40 random typosquat leads (16 Nov) | 16 genuine lookalikes (`servicepaypal.app`, `wellsfargointl.com`, `binanceloginn.blogspot.com`, `en-browser-coinbase.pages.dev`…) | **21:** 15 multi-brand `.ph` names (`bancogalicia-barclays.ph`, `fedexsubdelive-hsbc.ph`) from registry parking, the same pattern ruled out in milestone 16; 3 brand-owned or legitimate (`wellsfargoauto.com`, `santanderconsumer.no`, a Binance event site); 3 false friends (`revoluterra.ru`, `casinorevolut.be`, `chaseschums.co.uk`) | 3 unsure (`coingainbase.com`, `wellsfargoprivatebanking.com`, `plansantander.com`). Missed lookalikes not measured. |
| 20 random critical-tier pages | 14 genuine (Cloudflare phishing interstitials, fake Binance download portals, Coinbase support scams, a wallet clone) | 4: a parked domain (`chasemygarage.com`), an offline page ranked on its name alone, two legitimate event sites (Chase, Binance Blockchain Week) | 2 unsure. None of the 20 had a detected password field (script-built forms, interstitials): credential detection under-reports. |
| X watched accounts, 7 days (639 posts read) | 28 of 51 filter hits were genuine financial victims | 23 were not financial victims: "Forex" in a shipping firm's name, "payment/bank data" leaked at a marketplace, retailer, rail operator, university or agency; tooling and news posts; a regulator | Posts outside the filter were not read, so misses are unmeasured. The filter was tightened on all 23 patterns. |
| Victim company matches | 13 head-office matches correct after fixes (Banco do Brasil, QNB Q.P.S.C., State Bank of India, Raymond James, Robinhood…) | Before fixes: QNB's French branch, SBI's pension fund, Swedish "CoinOne AB" for Korea's Coinone, Mirae Asset's UK subsidiary | Bangkok Bank and Mirae Asset (Korea) not found in GLEIF. |
| Phase 1 (8 Nov) | 9/12 victims and 6/12 campaigns correct | see phase 1 notes: aggregator label errors, `google.com` from feeds, platform-template over-merges, 20/20 wrong kit labels (fixed) | — |

### Limitations
- **Typosquat precision.** About half of new-domain leads are not phishing; the `.ph` registry-parking names are the
  largest group. Next: drop names that resolve to the registry's parking, and extend official brand domain lists
  (`wellsfargoauto.com`, `santanderconsumer.no`).
- **P4 credential surface.** No JavaScript is executed, so script-built forms show no password field; the rank still
  surfaces them through other factors, but "data requested" under-reports.
- **P4 kits.** Fingerprinting works on captured HTML; downloading the kit archive itself (sandboxed proxy, opendir
  tags) is not built. VirusTotal and GitHub phishing lists are not sources yet. Pivoting is a later stage.
- **X capture.** No X API token this week, so posts were captured through my own signed-in browser and imported:
  manual, and against X's terms for automation. The API path is built for scheduled runs.
- **Victim naming.** Most IAB posts name the victim only in the attached forum screenshot; OCR is not built, so
  unnamed victims depend on the shortlist + Shodan step, which needs ZoomInfo-grade revenue data (Wikidata has
  revenue for few Indian banks) and a Shodan plan with full filters.
- **Not built from my plan:** client watchlist matching, IAB ↔ ransomware victim linkage, supply-chain inference for
  non-financial victims (the data for the last two already sits in the same database).
- **P6 labels** still trust the aggregator first (phase 1 finding).
- **Both.** SQLite single file; fine for a candidate project, not for concurrent analysts.
