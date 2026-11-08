"""P4 pipeline: collect -> fetch -> features -> fingerprint -> cluster -> detections -> persist."""
from __future__ import annotations

import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, delete, select

from ...config import get_settings
from ...models import Detection, PhishCampaign, PhishKit, PhishSample
from ...pipelines.runner import RunContext
from . import fetch as fetchmod
from .cluster import Item, cluster_items
from .collectors import Candidate, OpenPhishCollector, UrlscanCollector, split_host
from .detections import build_detections
from .features import extract_features
from .fingerprint import fingerprint, infer_kit, kit_markers_for_sample, load_signatures

FETCH_THREADS = 8
REFETCH_AFTER = timedelta(hours=12)
ACTIVE_WINDOW = timedelta(days=3)


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- collect / upsert

def _prioritise(cands: list[Candidate], limit: int) -> list[Candidate]:
    def key(c: Candidate):
        return (0 if c.brand_hint else 1, 0 if c.source == "urlscan" else 1, -(c.first_seen.timestamp() if c.first_seen else 0))
    return sorted(cands, key=key)[:limit]


def upsert_candidates(session: Session, cands: list[Candidate]) -> tuple[int, int]:
    existing = {s.url: s for s in session.exec(select(PhishSample).where(PhishSample.url.in_([c.url for c in cands])))}
    new = updated = 0
    for c in cands:
        host, apex, tld = split_host(c.url)
        row = existing.get(c.url)
        if row is None:
            row = PhishSample(url=c.url, source=c.source, source_id=c.source_id, source_tags=c.tags,
                              first_seen=c.first_seen, domain=c.domain or host, apex_domain=c.apex_domain or apex, tld=tld,
                              ip=c.ip, asn=c.asn, asn_name=c.asn_name, country=c.country, title=c.title,
                              screenshot_url=c.screenshot_url, brand=c.brand_hint, brand_confidence=0.3 if c.brand_hint else 0.0,
                              features={"_source": c.source, "_brand_hint": c.brand_hint, "_meta": c.meta})
            session.add(row)
            new += 1
        else:
            if not row.source_id and c.source_id:
                row.source_id, row.screenshot_url = c.source_id, c.screenshot_url
            if not row.ip and c.ip:
                row.ip, row.asn, row.asn_name, row.country = c.ip, c.asn, c.asn_name, c.country
            row.source_tags = sorted(set(row.source_tags or []) | set(c.tags))
            if c.brand_hint and not row.features.get("_brand_hint"):
                row.features = {**row.features, "_brand_hint": c.brand_hint}
            session.add(row)
            updated += 1
    session.commit()
    return new, updated


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


def extract_all(ctx: RunContext) -> dict[str, Any]:
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))  # lxml/bs4 internals on pathological markup
    with ctx.session() as session:
        kits = ensure_signature_kits(session)
        rows = session.exec(select(PhishSample).where(PhishSample.fetch_status == "ok")).all()
        ctx.log(f"extracting features for {len(rows)} captured pages")
        brands: Counter[str] = Counter()
        kit_hits: Counter[str] = Counter()
        for i, s in enumerate(rows, 1):
            html = _read_html(s.html_path)
            if not html.strip():
                s.fetch_status = "error"
                s.features = {**s.features, "_fetch_error": "empty body"}
                session.add(s)
                continue
            url = s.final_url or s.url
            try:
                feats = extract_features(html, url, s.features.get("_brand_hint"))
                feats["kit_markers"] = kit_markers_for_sample(html, url, feats)
                kit = fingerprint(html, url, feats)
            except Exception as exc:  # noqa: BLE001 - one hostile page must not kill the run
                s.fetch_status = "error"
                s.features = {**s.features, "_feature_error": f"{type(exc).__name__}: {str(exc)[:160]}"}
                session.add(s)
                ctx.log(f"  feature extraction failed for sample {s.id}: {type(exc).__name__}")
                continue
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
            if i % 100 == 0:
                session.commit()
                ctx.log(f"  features {i}/{len(rows)}")
        session.commit()
    ctx.log(f"brands detected: {dict(brands.most_common(10))}; kit matches: {dict(kit_hits)}")
    return {"pages": len(rows), "brands": dict(brands.most_common(20)), "kit_matches": dict(kit_hits)}


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


# --------------------------------------------------------------------------- entry point

def run(ctx: RunContext) -> dict[str, Any]:
    scope = ctx.scope.phishing
    ctx.log(f"scope: sector='{scope.sector}' brands={scope.brands} days_back={scope.days_back} max_samples={scope.max_samples}")
    urlscan = UrlscanCollector(scope, ctx.log)
    openphish = OpenPhishCollector(scope, ctx.log)
    cands = urlscan.collect()
    cands += openphish.collect()
    seen: dict[str, Candidate] = {}
    for c in cands:
        if c.url not in seen:
            seen[c.url] = c
    selected = _prioritise(list(seen.values()), scope.max_samples)
    ctx.log(f"{len(seen)} unique candidates, {len(selected)} selected (brand-hinted + urlscan first)")
    with ctx.session() as session:
        new, updated = upsert_candidates(session, selected)
    ctx.log(f"upserted samples: {new} new, {updated} existing")

    fetch_counts = fetch_samples(ctx, urlscan)
    feat = extract_all(ctx)
    clus = cluster_and_detect(ctx, scope.sector)

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
        "sources": {"urlscan": urlscan.status.as_dict(), "openphish": openphish.status.as_dict()},
    }
