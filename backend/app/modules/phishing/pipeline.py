"""P4 pipeline: collect -> fetch -> features -> fingerprint -> cluster -> detections -> persist."""
from __future__ import annotations

import sys
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, as_completed, wait
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, col, delete, select

from ...config import get_settings
from ...models import AnalystReview, Detection, DomainLead, PhishCampaign, PhishKit, PhishSample
from ...pipelines.runner import RunContext
from . import fetch as fetchmod
from .cluster import Item, cluster_items
from .collectors import Candidate, OpenPhishCollector, PhishTankCollector, UrlscanCollector, split_host
from .dedupe import canonical_host, canonical_url, primary_rank
from .detections import build_detections
from .features import extract_features
from .fingerprint import fingerprint, infer_kit, kit_markers_for_sample, load_signatures
from .leads import Lead, NRDCollector
from .rank import threat_rank
from .typosquat import BrandSpec, build_specs, match_host

FETCH_THREADS = 8
REFETCH_AFTER = timedelta(hours=12)
ACTIVE_WINDOW = timedelta(days=3)
FEATURE_WORKERS = 4
FEATURE_TIMEOUT = 45.0  # seconds per page; one pathological page once stalled a run for ~2 hours
MAX_ALT_URLS = 25


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- collect / upsert

def _prioritise(cands: list[Candidate], limit: int) -> list[Candidate]:
    def key(c: Candidate):
        return (0 if c.brand_hint else 1, 0 if c.source == "urlscan" else 1, -(c.first_seen.timestamp() if c.first_seen else 0))
    return sorted(cands, key=key)[:limit]


def merge_candidates(cands: list[Candidate]) -> tuple[list[Candidate], int]:
    """Collapse candidates that are the same page (canonical URL) across and within sources.
    The urlscan report wins as primary (it carries the scan uuid and screenshot); every source is kept."""
    groups: dict[str, list[Candidate]] = {}
    for c in cands:
        groups.setdefault(canonical_url(c.url), []).append(c)
    out: list[Candidate] = []
    merged = 0
    for key, cs in groups.items():
        cs.sort(key=lambda c: (0 if c.source_id else 1, c.first_seen.timestamp() if c.first_seen else float("inf")))
        prim = cs[0]
        prim.meta = {**prim.meta, "_dedup_key": key, "_sources": sorted({c.source for c in cs}),
                     "_alt_urls": sorted({c.url for c in cs[1:] if c.url != prim.url})[:MAX_ALT_URLS]}
        prim.tags = sorted({t for c in cs for t in c.tags})
        prim.brand_hint = prim.brand_hint or next((c.brand_hint for c in cs if c.brand_hint), None)
        seen = [c.first_seen for c in cs if c.first_seen]
        prim.first_seen = min(seen) if seen else prim.first_seen
        merged += len(cs) - 1
        out.append(prim)
    return out, merged


def upsert_candidates(session: Session, cands: list[Candidate]) -> tuple[int, int]:
    keys = {c.meta.get("_dedup_key") or canonical_url(c.url) for c in cands}
    rows = session.exec(select(PhishSample).where(PhishSample.dedup_key.in_(list(keys)) |
                                                  PhishSample.url.in_([c.url for c in cands]))).all()
    by_key = {r.dedup_key or canonical_url(r.url): r for r in rows}
    new = updated = 0
    for c in cands:
        key = c.meta.get("_dedup_key") or canonical_url(c.url)
        srcs = set(c.meta.get("_sources") or [c.source])
        alts = set(c.meta.get("_alt_urls") or [])
        host, apex, tld = split_host(c.url)
        row = by_key.get(key)
        if row is None:
            row = PhishSample(url=c.url, source=c.source, source_id=c.source_id, source_tags=c.tags,
                              first_seen=c.first_seen, domain=c.domain or host, apex_domain=c.apex_domain or apex, tld=tld,
                              ip=c.ip, asn=c.asn, asn_name=c.asn_name, country=c.country, title=c.title,
                              screenshot_url=c.screenshot_url, brand=c.brand_hint, brand_confidence=0.3 if c.brand_hint else 0.0,
                              features={"_source": c.source, "_brand_hint": c.brand_hint, "_meta": c.meta},
                              dedup_key=key, sources=sorted(srcs), duplicate_urls=sorted(alts)[:MAX_ALT_URLS],
                              duplicate_count=len(alts) + len(srcs) - 1)
            session.add(row)
            by_key[key] = row
            new += 1
            continue
        before = (set(row.sources or [row.source]), set(row.duplicate_urls or []))
        if not row.source_id and c.source_id:
            row.source_id, row.screenshot_url = c.source_id, c.screenshot_url
        if not row.ip and c.ip:
            row.ip, row.asn, row.asn_name, row.country = c.ip, c.asn, c.asn_name, c.country
        row.source_tags = sorted(set(row.source_tags or []) | set(c.tags))
        row.sources = sorted(before[0] | srcs)
        row.duplicate_urls = sorted((before[1] | alts | ({c.url} if c.url != row.url else set())) - {row.url})[:MAX_ALT_URLS]
        row.duplicate_count = (row.duplicate_count or 0) + len(set(row.sources) - before[0]) + len(set(row.duplicate_urls) - before[1])
        row.dedup_key = key
        if c.first_seen and (row.first_seen is None or c.first_seen < _utc(row.first_seen)):
            row.first_seen = c.first_seen
        if c.brand_hint and not row.features.get("_brand_hint"):
            row.features = {**row.features, "_brand_hint": c.brand_hint}
        session.add(row)
        updated += 1
    session.commit()
    return new, updated


# --------------------------------------------------------------------------- retention + merge passes

def prune_old(ctx: RunContext, days: int) -> dict[str, int]:
    """Keep only the last `days` of ingested data. Samples with an analyst verdict are kept as hand-check
    evidence. Leads older than the window go too; captured HTML no longer referenced is deleted."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with ctx.session() as session:
        reviewed = {r.entity_id for r in session.exec(select(AnalystReview).where(AnalystReview.entity_type == "sample"))}
        old = [x for x in session.exec(select(PhishSample).where(PhishSample.first_seen < cutoff)) if x.id not in reviewed]
        old_ids = {x.id for x in old}
        leads_del = leads_kept = 0
        for ld in session.exec(select(DomainLead)):
            stale = ld.first_seen is not None and _utc(ld.first_seen) < cutoff
            if stale and (ld.sample_id is None or ld.sample_id in old_ids):
                session.delete(ld)
                leads_del += 1
            elif ld.sample_id in old_ids:
                ld.sample_id, ld.status = None, "new"
                session.add(ld)
                leads_kept += 1
        session.commit()
        paths = {x.html_path for x in old if x.html_path}
        for x in old:
            session.delete(x)
        session.commit()
        still = {r for r in session.exec(select(PhishSample.html_path).where(PhishSample.html_path.is_not(None)))}
    files = 0
    root = get_settings().artifacts_dir
    for rel in paths - still:
        f = root / rel
        if f.exists():
            f.unlink()
            files += 1
    ctx.log(f"retention {days}d: removed {len(old)} samples, {leads_del} leads and {files} captured pages older than "
            f"{cutoff:%Y-%m-%d %H:%M} UTC" + (f" ({len(reviewed)} reviewed samples kept)" if reviewed else ""))
    return {"samples": len(old), "leads": leads_del, "html_files": files}


def _merge_into(session: Session, prim: PhishSample, dups: list[PhishSample]) -> None:
    srcs = set(prim.sources or [prim.source])
    alts = set(prim.duplicate_urls or [])
    added = 0
    for d in dups:
        srcs |= set(d.sources or [d.source])
        alts |= set(d.duplicate_urls or []) | {d.url}
        added += 1 + (d.duplicate_count or 0)
        prim.source_tags = sorted(set(prim.source_tags or []) | set(d.source_tags or []))
        if d.first_seen and (prim.first_seen is None or _utc(d.first_seen) < _utc(prim.first_seen)):
            prim.first_seen = d.first_seen
        if not prim.source_id and d.source_id:
            prim.source_id, prim.screenshot_url = d.source_id, d.screenshot_url
        for ld in session.exec(select(DomainLead).where(DomainLead.sample_id == d.id)):
            ld.sample_id = prim.id
            session.add(ld)
        for rv in session.exec(select(AnalystReview).where(AnalystReview.entity_type == "sample", AnalystReview.entity_id == d.id)):
            rv.entity_id = prim.id
            session.add(rv)
    prim.sources = sorted(srcs)
    prim.duplicate_urls = sorted(alts - {prim.url})[:MAX_ALT_URLS]
    prim.duplicate_count = (prim.duplicate_count or 0) + added
    session.add(prim)
    session.flush()
    for d in dups:
        session.delete(d)


def dedupe_samples(ctx: RunContext, stage: str) -> int:
    """stage='url': same canonical URL. stage='content': same host + identical HTML, then same host + same
    DOM structure (pages that differ only by injected victim values)."""
    merged = 0
    with ctx.session() as session:
        rows = session.exec(select(PhishSample)).all()
        for r in rows:
            if not r.dedup_key:
                r.dedup_key = canonical_url(r.url)
                r.sources = r.sources or [r.source]
                session.add(r)
        session.commit()
        if stage == "url":
            keyfns = [("canonical URL", lambda r: r.dedup_key)]
        else:
            keyfns = [("identical HTML", lambda r: (canonical_host(r.domain), r.html_sha256) if r.fetch_status == "ok" and r.html_sha256 else None),
                      ("same DOM structure", lambda r: (canonical_host(r.domain), r.struct_hash) if r.fetch_status == "ok" and r.struct_hash else None)]
        for label, fn in keyfns:
            rows = session.exec(select(PhishSample)).all()
            groups: dict[Any, list[PhishSample]] = {}
            for r in rows:
                k = fn(r)
                if k is not None:
                    groups.setdefault(k, []).append(r)
            n = 0
            for members in groups.values():
                if len(members) < 2:
                    continue
                members.sort(key=primary_rank)
                _merge_into(session, members[0], members[1:])
                n += len(members) - 1
            session.commit()
            if n:
                ctx.log(f"dedup ({label}): merged {n} duplicate samples")
            merged += n
    return merged


# --------------------------------------------------------------------------- typosquat leads

def brand_specs(scope) -> list[BrandSpec]:
    return build_specs(scope.brands, scope.brand_fragments, scope.brand_domains, scope.brand_exclusions)


def upsert_leads(session: Session, leads: list[Lead]) -> tuple[int, int]:
    by_domain: dict[str, Lead] = {}
    sources: dict[str, set[str]] = {}
    for ld in leads:
        sources.setdefault(ld.domain, set()).add(ld.source)
        cur = by_domain.get(ld.domain)
        if cur is None or ld.match.score > cur.match.score:
            by_domain[ld.domain] = ld
    existing = {d.domain: d for d in session.exec(select(DomainLead).where(DomainLead.domain.in_(list(by_domain))))}
    new = updated = 0
    for dom, ld in by_domain.items():
        row = existing.get(dom)
        m = ld.match
        if row is None:
            row = DomainLead(domain=dom, brand=m.brand, match_kind=m.kind, match_score=m.score, evidence=m.evidence,
                             lure_words=m.lure_words, sources=sorted(sources[dom]), first_seen=ld.first_seen,
                             last_seen=ld.first_seen, meta=ld.meta)
            new += 1
        else:
            row.sources = sorted(set(row.sources or []) | sources[dom])
            row.first_seen = min(filter(None, [_utc(row.first_seen), ld.first_seen]))
            row.last_seen = max(filter(None, [_utc(row.last_seen), ld.first_seen]))
            row.meta = {**(row.meta or {}), **ld.meta}
            updated += 1
        session.add(row)
    session.commit()
    return new, updated


def promote_leads(session: Session, limit: int, known_urls: set[str]) -> list[Candidate]:
    """Strongest unfetched leads become candidates (https://<domain>/), pre-ranked on hostname evidence.
    A lead whose host already has a sample (from urlscan/OpenPhish) is linked to it, not fetched again."""
    hosts: dict[str, int] = {}
    for sid, dom in session.exec(select(PhishSample.id, PhishSample.domain)):
        hosts.setdefault(canonical_host(dom), sid)
    known_hosts = {canonical_host(split_host(u)[0]) for u in known_urls}
    rows = session.exec(select(DomainLead).where(DomainLead.sample_id.is_(None))).all()
    for r in rows:
        if r.domain in hosts:
            r.sample_id, r.status = hosts[r.domain], "promoted"
            session.add(r)
    rows = [r for r in rows if r.sample_id is None]
    scored = []
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    for r in rows:
        pre = threat_rank(host=r.domain, squat={"brand": r.brand, "kind": r.match_kind, "score": r.match_score,
                                                 "evidence": r.evidence, "lure_words": r.lure_words},
                          lead_sources=r.sources)
        r.threat_score, r.threat_tier, r.rank_factors = pre["score"], pre["tier"], pre["factors"]
        session.add(r)
        scored.append((pre["score"], _utc(r.first_seen) or epoch, r))
    session.commit()
    scored.sort(key=lambda x: (-x[0], -(x[1] - epoch).total_seconds()))
    out = []
    for _, _, r in scored:
        url = f"https://{r.domain}/"
        if url in known_urls or r.domain in known_hosts:
            continue
        out.append(Candidate(url=url, source=(r.sources or ["nrd"])[0], first_seen=_utc(r.first_seen),
                             tags=["typosquat-lead", *r.sources], domain=r.domain, brand_hint=r.brand,
                             meta={"lead_id": r.id, "lead_sources": r.sources, "match_kind": r.match_kind}))
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- fetch

def _needs_fetch(s: PhishSample, now: datetime) -> bool:
    if s.fetch_status in ("pending",):
        return True
    if s.fetch_status in ("offline", "error", "blocked"):
        return s.fetched_at is None or now - _utc(s.fetched_at) > REFETCH_AFTER
    return False


def fetch_samples(ctx: RunContext, urlscan: UrlscanCollector) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    with ctx.session() as session:
        rows = [s for s in session.exec(select(PhishSample)) if _needs_fetch(s, now)]
        todo = [(s.id, s.url, s.source_id) for s in rows]
    ctx.log(f"fetching {len(todo)} pages with {FETCH_THREADS} threads (10s timeout, 2MB cap, no JS)")
    counts: Counter[str] = Counter()
    use_api = bool(get_settings().urlscan_api_key)

    def work(item):
        sid, url, uuid = item
        if use_api and uuid:
            dom = urlscan.fetch_dom(uuid)
            res = urlscan.fetch_result(uuid) or {}
            if dom:
                sha, rel, size = fetchmod.store_html(dom)
                page = res.get("page", {})
                return sid, fetchmod.FetchResult(status="ok", http_status=int(page.get("status") or 200),
                                                 final_url=page.get("url") or url, html=dom, sha256=sha, size=size,
                                                 html_path=rel, ip=page.get("ip"), fetched_at=datetime.now(timezone.utc))
        return sid, fetchmod.fetch_page(url)

    results: dict[int, fetchmod.FetchResult] = {}
    with ThreadPoolExecutor(max_workers=FETCH_THREADS) as pool:
        futures = [pool.submit(work, t) for t in todo]
        for i, fut in enumerate(as_completed(futures), 1):
            sid, res = fut.result()
            results[sid] = res
            counts[res.status] += 1
            if i % 50 == 0:
                ctx.log(f"  fetched {i}/{len(todo)} ({dict(counts)})")
    if len(results) >= 20 and counts.get("offline", 0) == len(results):
        # every single page unreachable = our network (e.g. the machine just woke from sleep), not 100% takedowns
        ctx.log(f"fetch: all {len(results)} pages unreachable; network outage suspected, results discarded "
                f"(pages stay pending and are retried next run)")
        return {"network_outage_suspected": len(results)}
    with ctx.session() as session:
        for sid, res in results.items():
            s = session.get(PhishSample, sid)
            if not s:
                continue
            s.fetch_status, s.http_status, s.fetched_at = res.status, res.http_status, res.fetched_at
            s.final_url = res.final_url or s.final_url
            if res.ip and not s.ip:
                s.ip = res.ip
            if res.status == "ok" and res.sha256:
                s.html_sha256, s.html_size, s.html_path = res.sha256, res.size, res.html_path
            if res.error:
                s.features = {**s.features, "_fetch_error": res.error}
            session.add(s)
        session.commit()
    ctx.log(f"fetch done: {dict(counts)}")
    return dict(counts)


# --------------------------------------------------------------------------- features + fingerprint

def _read_html(rel: str | None) -> str:
    if not rel:
        return ""
    p = get_settings().artifacts_dir / rel
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def ensure_signature_kits(session: Session) -> dict[str, PhishKit]:
    kits = {k.slug: k for k in session.exec(select(PhishKit))}
    for sig in load_signatures():
        k = kits.get(sig.slug)
        if k is None:
            k = PhishKit(slug=sig.slug, name=sig.name, family=sig.family, description=sig.description, source="signature",
                         markers=sig.markers, references=sig.references)
            session.add(k)
            kits[sig.slug] = k
        else:
            k.name, k.family, k.description, k.markers, k.references = sig.name, sig.family, sig.description, sig.markers, sig.references
            session.add(k)
    session.commit()
    for k in kits.values():
        session.refresh(k)
    return kits


def _featurize(html: str, url: str, hint: str | None) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Runs in a worker process so a pathological page can be abandoned (module-level for pickling)."""
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))  # lxml/bs4 internals on pathological markup
    feats = extract_features(html, url, hint)
    feats["kit_markers"] = kit_markers_for_sample(html, url, feats)
    return feats, fingerprint(html, url, feats)


def _featurize_all(ctx: RunContext, jobs: list[tuple[int, str | None, str, str | None]]) -> dict[int, Any]:
    """{sample_id: (feats, kit) | Exception}. A page running longer than FEATURE_TIMEOUT is abandoned:
    the pool is torn down (killing the stuck worker) and rebuilt for the remaining pages."""
    results: dict[int, Any] = {}
    queue = list(jobs)
    by_id = {j[0]: j for j in jobs}
    done_n = 0
    while queue:
        pool = ProcessPoolExecutor(max_workers=FEATURE_WORKERS)
        inflight: dict[Any, int] = {}
        started: dict[Any, float] = {}
        stuck: int | None = None
        try:
            while (queue or inflight) and stuck is None:
                while queue and len(inflight) < FEATURE_WORKERS * 2:
                    sid, rel, url, hint = queue.pop(0)
                    html = _read_html(rel)
                    if not html.strip():
                        results[sid] = ValueError("empty body")
                        continue
                    inflight[pool.submit(_featurize, html, url, hint)] = sid
                if not inflight:
                    break
                finished, _ = wait(list(inflight), timeout=2.0, return_when=FIRST_COMPLETED)
                now = time.monotonic()
                for fut in finished:
                    sid = inflight.pop(fut)
                    started.pop(fut, None)
                    try:
                        results[sid] = fut.result()
                    except Exception as exc:  # noqa: BLE001 - one hostile page must not kill the run
                        results[sid] = exc
                    done_n += 1
                    if done_n % 100 == 0:
                        ctx.log(f"  features {done_n}/{len(jobs)}")
                for fut, sid in inflight.items():
                    if fut.running():
                        started.setdefault(fut, now)
                        if now - started[fut] > FEATURE_TIMEOUT:
                            stuck = sid
                            break
        finally:
            if stuck is not None:
                results[stuck] = TimeoutError(f"feature extraction exceeded {FEATURE_TIMEOUT:.0f}s")
                ctx.log(f"  sample {stuck}: feature extraction timed out, skipped")
                queue = [by_id[i] for i in inflight.values() if i != stuck] + queue
                for proc in list(getattr(pool, "_processes", {}).values()):
                    proc.terminate()
                pool.shutdown(wait=False, cancel_futures=True)
            else:
                pool.shutdown(wait=True)
    return results


def extract_all(ctx: RunContext) -> dict[str, Any]:
    with ctx.session() as session:
        kits = ensure_signature_kits(session)
        rows = session.exec(select(PhishSample).where(PhishSample.fetch_status == "ok")).all()
        ctx.log(f"extracting features for {len(rows)} captured pages "
                f"({FEATURE_WORKERS} workers, {FEATURE_TIMEOUT:.0f}s cap per page)")
        jobs = [(s.id, s.html_path, s.final_url or s.url, s.features.get("_brand_hint")) for s in rows]
        results = _featurize_all(ctx, jobs)
        brands: Counter[str] = Counter()
        kit_hits: Counter[str] = Counter()
        for s in rows:
            res = results.get(s.id)
            if res is None or isinstance(res, Exception):
                s.fetch_status = "error"
                if isinstance(res, ValueError) and str(res) == "empty body":
                    s.features = {**s.features, "_fetch_error": "empty body"}
                else:
                    err = f"{type(res).__name__}: {str(res)[:160]}" if res is not None else "not processed"
                    s.features = {**s.features, "_feature_error": err}
                session.add(s)
                continue
            feats, kit = res
            keep = {k: v for k, v in s.features.items() if k.startswith("_")}
            s.features = {**keep, **feats}
            s.title = feats["title"] or s.title
            s.struct_hash = feats["struct_hash"]
            s.brand, s.brand_confidence = feats["brand"], feats["brand_confidence"]
            if s.brand:
                brands[s.brand] += 1
            if kit:
                s.kit_id, s.kit_confidence = kits[kit["slug"]].id, kit["confidence"]
                s.features = {**s.features, "kit_hits": kit["hits"], "kit_score": kit["score"]}
                kit_hits[kit["name"]] += 1
            else:
                s.kit_id, s.kit_confidence = None, 0.0
            session.add(s)
        session.commit()
    timeouts = sum(1 for r in results.values() if isinstance(r, TimeoutError))
    ctx.log(f"brands detected: {dict(brands.most_common(10))}; kit matches: {dict(kit_hits)}; timeouts: {timeouts}")
    return {"pages": len(rows), "brands": dict(brands.most_common(20)), "kit_matches": dict(kit_hits), "timeouts": timeouts}


# --------------------------------------------------------------------------- cluster + detections

def _next_campaign_name(session: Session, now: datetime, n: int) -> str:
    return f"CAMP-{now.strftime('%Y-%m')}-{n:03d}"


def cluster_and_detect(ctx: RunContext, scope_sector: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    with ctx.session() as session:
        rows = session.exec(select(PhishSample).where(PhishSample.fetch_status == "ok", PhishSample.struct_hash.is_not(None))).all()
        items = [Item(sample_id=s.id, struct_hash=int(s.struct_hash, 16), brand=s.brand, fset=set(), features=s.features,
                      url=s.final_url or s.url, apex=s.apex_domain, ip=s.ip, asn=s.asn, asn_name=s.asn_name,
                      country=s.country, tld=s.tld, first_seen=_utc(s.first_seen) or _utc(s.fetched_at)) for s in rows]
        from .features import feature_set
        for it in items:
            it.fset = feature_set(it.features)
        ctx.log(f"clustering {len(items)} pages (stage 1 simhash+brand, stage 2 DBSCAN eps=0.42)")
        clusters = cluster_items(items)
        ctx.log(f"{len(clusters)} campaigns: " + ", ".join(f"{m}={sum(1 for c in clusters if c.method == m)}" for m in ("dbscan", "structural", "singleton")))

        # reset previous campaign state (re-cluster everything deterministically)
        session.exec(delete(Detection))
        for s in rows:
            s.campaign_id = None
        for s in session.exec(select(PhishSample).where(PhishSample.campaign_id.is_not(None))):
            s.campaign_id = None
            session.add(s)
        session.exec(delete(PhishCampaign))
        for k in session.exec(select(PhishKit).where(PhishKit.source == "inferred")):
            # inferred kits are re-derived every run; detach samples first
            for s in session.exec(select(PhishSample).where(PhishSample.kit_id == k.id)):
                s.kit_id, s.kit_confidence = None, 0.0
                session.add(s)
            session.delete(k)
        session.commit()

        kits = {k.id: k for k in session.exec(select(PhishKit))}
        sample_by_id = {s.id: s for s in rows}
        det_total = 0
        inferred = 0
        for n, cl in enumerate(clusters, 1):
            members = [sample_by_id[m.sample_id] for m in cl.members]
            first = min((_utc(m.first_seen) or now for m in members), default=now)
            last = max((_utc(m.first_seen) or _utc(m.fetched_at) or now for m in members), default=now)
            kit_votes = Counter(m.kit_id for m in members if m.kit_id)
            kit_id, kit_conf = None, 0.0
            if kit_votes:
                kit_id, votes = kit_votes.most_common(1)[0]
                kit_conf = round(sum(m.kit_confidence for m in members if m.kit_id == kit_id) / votes * (votes / len(members)) ** 0.5, 2)
            elif len(members) >= 3:
                spec = infer_kit(cl.brand, f"{cl.members[0].struct_hash:016x}", cl.summary["shared_marker_groups"])
                k = session.exec(select(PhishKit).where(PhishKit.slug == spec["slug"])).first()
                if k is None:
                    k = PhishKit(slug=spec["slug"], name=spec["name"], family=spec["family"], description=spec["description"],
                                 source="inferred", markers=spec["markers"], references=[], first_seen=first, last_seen=last)
                    session.add(k)
                    session.commit()
                    session.refresh(k)
                kits[k.id] = k
                kit_id, kit_conf = k.id, round(min(0.6, 0.3 + cl.cohesion * 0.3), 2)
                inferred += 1
                for m in members:
                    if not m.kit_id:
                        m.kit_id, m.kit_confidence = kit_id, kit_conf
            camp = PhishCampaign(name=_next_campaign_name(session, now, n), brand=cl.brand, sector=scope_sector,
                                 status="active" if now - last <= ACTIVE_WINDOW else "dormant", first_seen=first, last_seen=last,
                                 sample_count=len(members), domain_count=len({m.domain for m in members if m.domain}),
                                 ip_count=len({m.ip for m in members if m.ip}), cohesion=cl.cohesion, kit_id=kit_id,
                                 kit_confidence=kit_conf, cluster_method=cl.method, summary=cl.summary)
            session.add(camp)
            session.commit()
            session.refresh(camp)
            for m in members:
                m.campaign_id = camp.id
                session.add(m)
            kit_row = kits.get(kit_id) if kit_id else None
            camp_dict = {"name": camp.name, "brand": camp.brand, "sample_count": camp.sample_count, "cohesion": camp.cohesion,
                         "kit_name": kit_row.name if kit_row else None, "title_examples": cl.summary.get("title_examples", [])}
            dets = build_detections(camp_dict, [{"url": m.final_url or m.url, "domain": m.domain, "apex_domain": m.apex_domain,
                                                 "ip": m.ip, "features": m.features} for m in members],
                                    {"name": kit_row.name} if kit_row else None)
            for d in dets:
                session.add(Detection(campaign_id=camp.id, kit_id=kit_id, **d))
            det_total += len(dets)
            session.commit()

        # kit roll-ups
        for k in session.exec(select(PhishKit)):
            ks = session.exec(select(PhishSample).where(PhishSample.kit_id == k.id)).all()
            k.sample_count = len(ks)
            k.campaign_count = len({s.campaign_id for s in ks if s.campaign_id})
            times = [_utc(s.first_seen) or _utc(s.fetched_at) for s in ks if (s.first_seen or s.fetched_at)]
            k.first_seen, k.last_seen = (min(times), max(times)) if times else (k.first_seen, k.last_seen)
            session.add(k)
        session.commit()
        unclustered = sum(1 for s in rows if s.campaign_id is None)
    ctx.log(f"{det_total} detections generated; {inferred} inferred kits; {unclustered} brand-less singletons left unclustered")
    return {"campaigns": len(clusters), "detections": det_total, "inferred_kits": inferred, "unclustered": unclustered,
            "methods": dict(Counter(c.method for c in clusters))}


# --------------------------------------------------------------------------- threat rank

LEAD_STATUS = {"ok": "live", "offline": "offline", "blocked": "blocked"}


def rank_all(ctx: RunContext, specs: list[BrandSpec]) -> dict[str, Any]:
    """Score every sample (type A typosquat / type B content) and sync the result back to its lead.
    A feed-reported page whose hostname is a typosquat becomes a lead too (source = that feed)."""
    tiers: Counter[str] = Counter()
    types: Counter[str] = Counter()
    with ctx.session() as session:
        leads: dict[str, DomainLead] = {d.domain: d for d in session.exec(select(DomainLead))}
        for s in session.exec(select(PhishSample)):
            dom = (s.domain or "").lower()
            final_host = split_host(s.final_url)[0] if s.final_url else None
            m = match_host(dom, specs) if dom else None
            if m is None and final_host and final_host != dom:
                m = match_host(final_host, specs)
            squat = m.as_dict() if m else None
            lead = leads.get(canonical_host(dom))
            srcs = sorted(set(s.sources or [s.source]) | set(lead.sources if lead else []))
            r = threat_rank(host=dom, squat=squat, features=s.features, fetch_status=s.fetch_status,
                            kit_confidence=s.kit_confidence, source="openphish" if "openphish" in srcs else s.source,
                            source_tags=s.source_tags, lead_sources=srcs)
            s.squat, s.threat_score, s.threat_tier = squat, r["score"], r["tier"]
            s.detection_type, s.rank_factors = r["detection_type"], r["factors"]
            session.add(s)
            tiers[r["tier"]] += 1
            types[r["detection_type"]] += 1
            status = LEAD_STATUS.get(s.fetch_status, "promoted")
            if lead is not None:
                if lead.sample_id in (None, s.id):
                    lead.sample_id, lead.status = s.id, status
                    lead.threat_score, lead.threat_tier, lead.rank_factors = r["score"], r["tier"], r["factors"]
                    session.add(lead)
            elif m and dom:
                dom = canonical_host(dom)
                lead = DomainLead(domain=dom, brand=m.brand, match_kind=m.kind, match_score=m.score, evidence=m.evidence,
                                  lure_words=m.lure_words, sources=sorted(set(s.sources or [s.source])), first_seen=_utc(s.first_seen),
                                  last_seen=_utc(s.first_seen), status=status, sample_id=s.id, threat_score=r["score"],
                                  threat_tier=r["tier"], rank_factors=r["factors"])
                session.add(lead)
                leads[dom] = lead
        session.commit()
    ctx.log(f"threat rank: {dict(tiers)}; detection types: {dict(types)}")
    return {"tiers": dict(tiers), "detection_types": dict(types)}


# --------------------------------------------------------------------------- entry point

def run(ctx: RunContext) -> dict[str, Any]:
    scope = ctx.scope.phishing
    window = scope.window_days
    ctx.log(f"scope: sector='{scope.sector}' brands={scope.brands} window={window}d max_samples={scope.max_samples}")
    pruned = prune_old(ctx, window)
    urlscan = UrlscanCollector(scope, ctx.log)
    openphish = OpenPhishCollector(scope, ctx.log)
    phishtank = PhishTankCollector(scope, ctx.log)
    cands = urlscan.collect()
    cands += openphish.collect()
    cands += phishtank.collect()
    raw_n = len(cands)
    unique, merged_at_collect = merge_candidates(cands)
    seen = {c.url: c for c in unique}
    selected = _prioritise(unique, scope.max_samples)
    ctx.log(f"{raw_n} reports -> {len(unique)} unique pages after cross-source dedup ({merged_at_collect} merged); "
            f"{len(selected)} selected (brand-hinted + urlscan first)")

    # typosquat leads: WhoisDS newly-registered domains
    specs = brand_specs(scope)
    ctx.log("brand fragments: " + "; ".join(f"{sp.name}={'*'.join(sp.fragments)}*" for sp in specs))
    nrd = NRDCollector(specs, window, ctx.log)
    leads = nrd.collect()
    with ctx.session() as session:
        lead_new, lead_upd = upsert_leads(session, leads)
        promoted = promote_leads(session, scope.max_leads_promoted, {c.url for c in selected})
    ctx.log(f"typosquat leads: {len(leads)} matches ({lead_new} new, {lead_upd} seen before); "
            f"{len(promoted)} strongest promoted for capture")
    with ctx.session() as session:
        new, updated = upsert_candidates(session, selected + promoted)
        for c in promoted:
            lead = session.get(DomainLead, c.meta["lead_id"])
            sample = session.exec(select(PhishSample).where(PhishSample.url == c.url)).first()
            if lead and sample:
                lead.sample_id, lead.status = sample.id, "promoted"
                session.add(lead)
        session.commit()
    ctx.log(f"upserted samples: {new} new, {updated} existing")
    merged_url = dedupe_samples(ctx, "url")

    fetch_counts = fetch_samples(ctx, urlscan)
    feat = extract_all(ctx)
    merged_content = dedupe_samples(ctx, "content")
    clus = cluster_and_detect(ctx, scope.sector)
    ranked = rank_all(ctx, specs)

    with ctx.session() as session:
        total = len(session.exec(select(PhishSample.id)).all())
        ok = len(session.exec(select(PhishSample.id).where(PhishSample.fetch_status == "ok")).all())
        kits = len(session.exec(select(PhishKit.id).where(PhishKit.sample_count > 0)).all())
    return {
        "candidates": len(seen), "selected": len(selected), "new_samples": new, "updated_samples": updated,
        "samples_total": total, "samples_fetched_ok": ok, "fetch": fetch_counts,
        "pages_featurized": feat["pages"], "brands": feat["brands"], "kit_matches": feat["kit_matches"],
        "campaigns": clus["campaigns"], "cluster_methods": clus["methods"], "detections": clus["detections"],
        "inferred_kits": clus["inferred_kits"], "kits_with_samples": kits, "unclustered": clus["unclustered"],
        "feature_timeouts": feat.get("timeouts", 0), "window_days": window, "retention": pruned,
        "dedup": {"reports": raw_n, "merged_at_collect": merged_at_collect, "merged_url": merged_url,
                  "merged_content": merged_content},
        "leads": {"matches": len(leads), "new": lead_new, "promoted": len(promoted)},
        "threat_tiers": ranked["tiers"], "detection_types": ranked["detection_types"],
        "sources": {"urlscan": urlscan.status.as_dict(), "openphish": openphish.status.as_dict(),
                    "phishtank": phishtank.status.as_dict(), "nrd": nrd.status.as_dict()},
    }
