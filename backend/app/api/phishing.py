"""P4 API: campaigns, kits, samples, detections, stats and exports."""
from __future__ import annotations

import csv
import io
import json
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response
from sqlmodel import Session, col, func, or_, select

from ..config import get_settings
from ..db import get_session
from ..models import AnalystReview, Detection, DomainLead, PhishCampaign, PhishKit, PhishSample
from ..schemas import (CampaignDetail, CampaignOut, DetectionOut, KeyCount, KitDetail, KitOut, LeadList, LeadOut,
                       LeadStats, Page, PhishingStats, ReviewOut, SampleList, SampleOut, TimePoint)
from .common import key_counts, last_run, latest_verdicts

router = APIRouter(prefix="/api/phishing", tags=["phishing"])


# --------------------------------------------------------------------------- mappers

def _kit_names(session: Session, ids: set[int | None]) -> dict[int, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {k.id: k.name for k in session.exec(select(PhishKit).where(col(PhishKit.id).in_(ids)))}


def _campaign_out(c: PhishCampaign, kit_names: dict[int, str], det_counts: dict[int, int], verdicts: dict[int, str]) -> CampaignOut:
    return CampaignOut(id=c.id, name=c.name, brand=c.brand, sector=c.sector, status=c.status, first_seen=c.first_seen,
                       last_seen=c.last_seen, sample_count=c.sample_count, domain_count=c.domain_count, ip_count=c.ip_count,
                       cohesion=c.cohesion, kit_id=c.kit_id, kit_name=kit_names.get(c.kit_id) if c.kit_id else None,
                       kit_confidence=c.kit_confidence, cluster_method=c.cluster_method, summary=c.summary or {},
                       detection_count=det_counts.get(c.id, 0), review_verdict=verdicts.get(c.id))


def _sample_out(s: PhishSample, kit_names: dict[int, str], camp_names: dict[int, str], verdicts: dict[int, str]) -> SampleOut:
    return SampleOut(id=s.id, url=s.url, final_url=s.final_url, domain=s.domain, apex_domain=s.apex_domain, ip=s.ip, asn=s.asn,
                     asn_name=s.asn_name, country=s.country, tld=s.tld, source=s.source, source_id=s.source_id,
                     source_tags=s.source_tags or [], first_seen=s.first_seen, fetched_at=s.fetched_at, fetch_status=s.fetch_status,
                     http_status=s.http_status, title=s.title, brand=s.brand, brand_confidence=s.brand_confidence,
                     html_sha256=s.html_sha256, html_size=s.html_size, screenshot_url=s.screenshot_url, struct_hash=s.struct_hash,
                     features=s.features or {}, campaign_id=s.campaign_id,
                     campaign_name=camp_names.get(s.campaign_id) if s.campaign_id else None, kit_id=s.kit_id,
                     kit_name=kit_names.get(s.kit_id) if s.kit_id else None, kit_confidence=s.kit_confidence,
                     review_verdict=verdicts.get(s.id), detection_type=s.detection_type, threat_score=s.threat_score or 0,
                     threat_tier=s.threat_tier, squat=s.squat, rank_factors=s.rank_factors or [], dedup_key=s.dedup_key,
                     sources=s.sources or [s.source], duplicate_urls=s.duplicate_urls or [], duplicate_count=s.duplicate_count or 0)


def _kit_out(k: PhishKit) -> KitOut:
    return KitOut(id=k.id, slug=k.slug, name=k.name, family=k.family, description=k.description, source=k.source,
                  markers=k.markers or [], sample_count=k.sample_count, campaign_count=k.campaign_count,
                  first_seen=k.first_seen, last_seen=k.last_seen, references=k.references or [])


def _det_out(d: Detection) -> DetectionOut:
    return DetectionOut.model_validate(d, from_attributes=True)


def _det_counts(session: Session, campaign_ids: list[int]) -> dict[int, int]:
    if not campaign_ids:
        return {}
    rows = session.exec(select(Detection.campaign_id, func.count()).where(col(Detection.campaign_id).in_(campaign_ids))
                        .group_by(Detection.campaign_id)).all()
    return {cid: n for cid, n in rows}


def _campaign_names(session: Session, ids: set[int | None]) -> dict[int, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {c.id: c.name for c in session.exec(select(PhishCampaign).where(col(PhishCampaign.id).in_(ids)))}


def _samples_out(session: Session, rows: list[PhishSample]) -> list[SampleOut]:
    kit_names = _kit_names(session, {s.kit_id for s in rows})
    camp_names = _campaign_names(session, {s.campaign_id for s in rows})
    verdicts = latest_verdicts(session, "sample", [s.id for s in rows])
    return [_sample_out(s, kit_names, camp_names, verdicts) for s in rows]


def _campaigns_out(session: Session, rows: list[PhishCampaign]) -> list[CampaignOut]:
    kit_names = _kit_names(session, {c.kit_id for c in rows})
    det_counts = _det_counts(session, [c.id for c in rows])
    verdicts = latest_verdicts(session, "campaign", [c.id for c in rows])
    return [_campaign_out(c, kit_names, det_counts, verdicts) for c in rows]


# --------------------------------------------------------------------------- stats

@router.get("/stats", response_model=PhishingStats)
def stats(session: Session = Depends(get_session)):
    samples = session.exec(select(PhishSample)).all()
    campaigns = session.exec(select(PhishCampaign)).all()
    kits = session.exec(select(PhishKit).where(PhishKit.sample_count > 0)).all()
    kit_names = {k.id: k.name for k in kits}
    n_det = session.exec(select(func.count()).select_from(Detection)).one()
    by_day: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for s in samples:
        d = (s.first_seen or s.fetched_at or s.created_at)
        if d:
            key = d.strftime("%Y-%m-%d")
            by_day[key][0] += 1
            if s.campaign_id:
                by_day[key][1] += 1
    timeline = [TimePoint(period=k, value=v[0], secondary=v[1]) for k, v in sorted(by_day.items())]
    sizes = Counter()
    for c in campaigns:
        n = c.sample_count
        sizes["1" if n == 1 else "2-4" if n <= 4 else "5-9" if n <= 9 else "10+"] += 1
    size_order = ["1", "2-4", "5-9", "10+"]
    ok = [s for s in samples if s.fetch_status == "ok"]
    return PhishingStats(
        samples=len(samples), fetched_ok=len(ok), campaigns=len(campaigns),
        active_campaigns=sum(1 for c in campaigns if c.status == "active"), kits=len(kits), detections=n_det,
        brands=key_counts((s.brand for s in ok), top=12), tlds=key_counts((s.tld for s in samples), top=12),
        asns=key_counts((f"{s.asn} {s.asn_name or ''}".strip() for s in samples if s.asn), top=10),
        countries=key_counts((s.country for s in samples if s.country), top=10),
        sources=key_counts(src for s in samples for src in (s.sources or [s.source])),
        fetch_status=key_counts(s.fetch_status for s in samples),
        kit_distribution=key_counts((kit_names.get(s.kit_id) for s in ok if s.kit_id), top=12, label_none="unmatched"),
        timeline=timeline, campaign_sizes=[KeyCount(key=k, count=sizes.get(k, 0)) for k in size_order],
        last_run=last_run(session, "phishing"), duplicates_merged=sum(s.duplicate_count or 0 for s in samples),
    )


# --------------------------------------------------------------------------- campaigns

@router.get("/campaigns", response_model=list[CampaignOut])
def list_campaigns(brand: str | None = None, kit_id: int | None = None, status: str | None = None, q: str | None = None,
                   min_samples: int | None = None, session: Session = Depends(get_session)):
    stmt = select(PhishCampaign)
    if brand:
        stmt = stmt.where(PhishCampaign.brand == brand)
    if kit_id is not None:
        stmt = stmt.where(PhishCampaign.kit_id == kit_id)
    if status:
        stmt = stmt.where(PhishCampaign.status == status)
    if min_samples:
        stmt = stmt.where(PhishCampaign.sample_count >= min_samples)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(col(PhishCampaign.name).ilike(like), col(PhishCampaign.brand).ilike(like)))
    rows = session.exec(stmt.order_by(PhishCampaign.sample_count.desc(), PhishCampaign.id)).all()
    return _campaigns_out(session, rows)


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetail)
def get_campaign(campaign_id: int, session: Session = Depends(get_session)):
    c = session.get(PhishCampaign, campaign_id)
    if not c:
        raise HTTPException(404, "campaign not found")
    camp = _campaigns_out(session, [c])[0]
    kit = session.get(PhishKit, c.kit_id) if c.kit_id else None
    samples = session.exec(select(PhishSample).where(PhishSample.campaign_id == c.id).order_by(PhishSample.first_seen.desc())).all()
    dets = session.exec(select(Detection).where(Detection.campaign_id == c.id).order_by(Detection.type)).all()
    by_day: Counter[str] = Counter((s.first_seen or s.fetched_at or s.created_at).strftime("%Y-%m-%d") for s in samples)
    reviews = session.exec(select(AnalystReview).where(AnalystReview.entity_type == "campaign", AnalystReview.entity_id == c.id)
                           .order_by(AnalystReview.created_at.desc())).all()
    return CampaignDetail(campaign=camp, kit=_kit_out(kit) if kit else None, samples=_samples_out(session, samples),
                          detections=[_det_out(d) for d in dets],
                          timeline=[TimePoint(period=k, value=v) for k, v in sorted(by_day.items())],
                          reviews=[ReviewOut.model_validate(r, from_attributes=True) for r in reviews])


# --------------------------------------------------------------------------- kits

@router.get("/kits", response_model=list[KitOut])
def list_kits(with_samples: bool = False, session: Session = Depends(get_session)):
    stmt = select(PhishKit)
    if with_samples:
        stmt = stmt.where(PhishKit.sample_count > 0)
    rows = session.exec(stmt.order_by(PhishKit.sample_count.desc(), PhishKit.name)).all()
    return [_kit_out(k) for k in rows]


@router.get("/kits/{kit_id}", response_model=KitDetail)
def get_kit(kit_id: int, session: Session = Depends(get_session)):
    k = session.get(PhishKit, kit_id)
    if not k:
        raise HTTPException(404, "kit not found")
    camps = session.exec(select(PhishCampaign).where(PhishCampaign.kit_id == k.id).order_by(PhishCampaign.sample_count.desc())).all()
    samples = session.exec(select(PhishSample).where(PhishSample.kit_id == k.id).order_by(PhishSample.kit_confidence.desc()).limit(200)).all()
    dets = session.exec(select(Detection).where(Detection.kit_id == k.id).order_by(Detection.type)).all()
    return KitDetail(kit=_kit_out(k), campaigns=_campaigns_out(session, camps), samples=_samples_out(session, samples),
                     detections=[_det_out(d) for d in dets])


# --------------------------------------------------------------------------- typosquat leads

def _lead_out(d: DomainLead) -> LeadOut:
    return LeadOut(id=d.id, domain=d.domain, brand=d.brand, match_kind=d.match_kind, match_score=d.match_score,
                   evidence=d.evidence, lure_words=d.lure_words or [], sources=d.sources or [], first_seen=d.first_seen,
                   last_seen=d.last_seen, meta=d.meta or {}, status=d.status, sample_id=d.sample_id,
                   threat_score=d.threat_score or 0, threat_tier=d.threat_tier, rank_factors=d.rank_factors or [])


def _lead_stmt(brand, match_kind, source, threat_tier, status, q):
    stmt = select(DomainLead)
    if brand:
        stmt = stmt.where(DomainLead.brand == brand)
    if match_kind:
        stmt = stmt.where(DomainLead.match_kind == match_kind)
    if threat_tier:
        stmt = stmt.where(DomainLead.threat_tier == threat_tier)
    if status:
        stmt = stmt.where(DomainLead.status == status)
    if source:
        stmt = stmt.where(col(DomainLead.sources).contains(f'"{source}"'))
    if q:
        stmt = stmt.where(col(DomainLead.domain).ilike(f"%{q}%"))
    return stmt


@router.get("/reports/brands")
def report_brands(session: Session = Depends(get_session)):
    """Brands with samples in the window, most-targeted first (for the report picker)."""
    from ..modules.phishing.report import available_brands
    return available_brands(session)


@router.get("/reports/brand")
def brand_report(brand: str, session: Session = Depends(get_session)):
    from ..modules.phishing.report import build_brand_report
    rep = build_brand_report(session, brand)
    if rep.get("error"):
        raise HTTPException(404, rep["error"])
    return rep


@router.get("/reports/brand.html", response_class=Response)
def brand_report_html(brand: str, download: bool = False, reporter: str | None = None, classification: str = "TLP:CLEAR",
                      session: Session = Depends(get_session)):
    """Client report for one brand in the approved (Chase) template: brand statistics and charts, then the
    brand's leading campaign. Refuses (422) if any visible text names an internal source."""
    from ..config import load_scope
    from ..modules.phishing import client_report as cr
    from ..setup_wizard import reporter_name
    who = reporter_name(reporter)
    try:
        spec = cr.build_for_brand(session, brand, who, classification)
        body = cr.render(spec)
    except cr.NotReportable as e:
        raise HTTPException(404, str(e))
    except cr.ClientLeakError as e:
        raise HTTPException(422, {"error": str(e), "leaks": e.leaks})
    headers = {"Content-Security-Policy": "default-src 'none'; img-src data:; style-src 'unsafe-inline'"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{spec["report_id"]}.html"'
    return Response(content=body, media_type="text/html; charset=utf-8", headers=headers)


@router.get("/samples/{sample_id}/screenshot")
def sample_screenshot(sample_id: int, session: Session = Depends(get_session)):
    """urlscan's stored screenshot, cached locally (the phishing host itself is never contacted)."""
    from ..modules.phishing.report import screenshot_bytes
    s = session.get(PhishSample, sample_id)
    data = screenshot_bytes(s) if s else None
    if not data:
        raise HTTPException(404, "no screenshot for this sample")
    return Response(content=data, media_type="image/png", headers={"Cache-Control": "max-age=86400"})


def _client_spec(session: Session, campaign_id: int, reporter: str | None, classification: str, force: bool, screenshots: str):
    from ..config import load_scope
    from ..modules.phishing import client_report as cr
    from ..setup_wizard import reporter_name
    who = reporter_name(reporter)
    try:
        return cr.build_from_campaign(session, campaign_id, who, classification, screenshots=screenshots, force=force)
    except cr.NotReportable as e:
        raise HTTPException(409, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/campaigns/{campaign_id}/client-report")
def client_report_spec(campaign_id: int, reporter: str | None = None, classification: str = "TLP:CLEAR",
                       force: bool = False, session: Session = Depends(get_session)):
    """The auto-filled report spec plus any client-rule violations (for review before export)."""
    from ..modules.phishing import client_report as cr
    spec = _client_spec(session, campaign_id, reporter, classification, force, "link")
    return {"spec": spec, "leaks": cr.leak_check(spec)}


@router.get("/campaigns/{campaign_id}/client-report.html", response_class=Response)
def client_report_html(campaign_id: int, reporter: str | None = None, classification: str = "TLP:CLEAR",
                       force: bool = False, download: bool = False, session: Session = Depends(get_session)):
    """Client-facing report in the approved template. Refuses (422) if any visible text names an internal source."""
    from ..modules.phishing import client_report as cr
    spec = _client_spec(session, campaign_id, reporter, classification, force, "embed")
    try:
        body = cr.render(spec)
    except cr.ClientLeakError as e:
        raise HTTPException(422, {"error": str(e), "leaks": e.leaks})
    headers = {"Content-Security-Policy": "default-src 'none'; img-src data: https:; style-src 'unsafe-inline'"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{spec["report_id"]}.html"'
    return Response(content=body, media_type="text/html; charset=utf-8", headers=headers)


@router.get("/leads", response_model=LeadList)
def list_leads(brand: str | None = None, match_kind: str | None = None, source: str | None = None,
               threat_tier: str | None = None, status: str | None = None, q: str | None = None, sort: str = "threat",
               page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500), session: Session = Depends(get_session)):
    stmt = _lead_stmt(brand, match_kind, source, threat_tier, status, q)
    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    order = (DomainLead.first_seen.desc(),) if sort == "recent" else (DomainLead.threat_score.desc(), DomainLead.first_seen.desc())
    rows = session.exec(stmt.order_by(*order).offset((page - 1) * size).limit(size)).all()
    return LeadList(items=[_lead_out(d) for d in rows], page=Page(page=page, size=size, total=total))


@router.get("/leads/stats", response_model=LeadStats)
def lead_stats(session: Session = Depends(get_session)):
    leads = session.exec(select(DomainLead)).all()
    samples = session.exec(select(PhishSample.detection_type, PhishSample.threat_tier)).all()
    by_day: Counter[str] = Counter(d.first_seen.strftime("%Y-%m-%d") for d in leads if d.first_seen)
    tier_order = ["critical", "high", "medium", "low"]
    tiers = Counter(d.threat_tier for d in leads if d.threat_tier)
    stiers = Counter(t for _, t in samples if t)
    return LeadStats(
        leads=len(leads), by_brand=key_counts((d.brand for d in leads), top=20), by_kind=key_counts(d.match_kind for d in leads),
        by_source=key_counts(src for d in leads for src in (d.sources or [])),
        by_tier=[KeyCount(key=t, count=tiers.get(t, 0)) for t in tier_order],
        by_status=key_counts(d.status for d in leads),
        detection_types=key_counts((dt for dt, _ in samples), label_none="not ranked"),
        sample_tiers=[KeyCount(key=t, count=stiers.get(t, 0)) for t in tier_order],
        timeline=[TimePoint(period=k, value=v) for k, v in sorted(by_day.items())],
    )


# --------------------------------------------------------------------------- samples

@router.get("/samples", response_model=SampleList)
def list_samples(campaign_id: int | None = None, kit_id: int | None = None, brand: str | None = None,
                 fetch_status: str | None = None, source: str | None = None, q: str | None = None,
                 detection_type: str | None = None, threat_tier: str | None = None, sort: str = "recent",
                 page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500), session: Session = Depends(get_session)):
    stmt = select(PhishSample)
    if detection_type:
        stmt = stmt.where(PhishSample.detection_type == detection_type)
    if threat_tier:
        stmt = stmt.where(PhishSample.threat_tier == threat_tier)
    if campaign_id is not None:
        stmt = stmt.where(PhishSample.campaign_id == campaign_id)
    if kit_id is not None:
        stmt = stmt.where(PhishSample.kit_id == kit_id)
    if brand:
        stmt = stmt.where(PhishSample.brand == brand)
    if fetch_status:
        stmt = stmt.where(PhishSample.fetch_status == fetch_status)
    if source:
        stmt = stmt.where(PhishSample.source == source)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(col(PhishSample.url).ilike(like), col(PhishSample.domain).ilike(like),
                              col(PhishSample.title).ilike(like), col(PhishSample.ip).ilike(like)))
    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    order = (PhishSample.threat_score.desc(), PhishSample.first_seen.desc()) if sort == "threat" else         (PhishSample.first_seen.desc(), PhishSample.id.desc())
    rows = session.exec(stmt.order_by(*order).offset((page - 1) * size).limit(size)).all()
    return SampleList(items=_samples_out(session, rows), page=Page(page=page, size=size, total=total))


@router.get("/samples/{sample_id}", response_model=SampleOut)
def get_sample(sample_id: int, session: Session = Depends(get_session)):
    s = session.get(PhishSample, sample_id)
    if not s:
        raise HTTPException(404, "sample not found")
    return _samples_out(session, [s])[0]


@router.get("/samples/{sample_id}/html", response_class=PlainTextResponse)
def get_sample_html(sample_id: int, session: Session = Depends(get_session)):
    s = session.get(PhishSample, sample_id)
    if not s or not s.html_path:
        raise HTTPException(404, "no captured HTML for this sample")
    path = get_settings().artifacts_dir / s.html_path
    if not path.exists():
        raise HTTPException(404, "captured HTML missing on disk")
    # text/plain on purpose: the analyst UI must never render phishing HTML
    return PlainTextResponse(path.read_text(encoding="utf-8", errors="replace"), media_type="text/plain; charset=utf-8",
                             headers={"X-Content-Type-Options": "nosniff", "Content-Disposition": f"inline; filename={s.html_sha256}.txt"})


# --------------------------------------------------------------------------- detections

@router.get("/detections", response_model=list[DetectionOut])
def list_detections(campaign_id: int | None = None, kit_id: int | None = None, type: str | None = None,
                    target: str | None = None, session: Session = Depends(get_session)):
    stmt = select(Detection)
    if campaign_id is not None:
        stmt = stmt.where(Detection.campaign_id == campaign_id)
    if kit_id is not None:
        stmt = stmt.where(Detection.kit_id == kit_id)
    if type:
        stmt = stmt.where(Detection.type == type)
    if target:
        stmt = stmt.where(Detection.target == target)
    return [_det_out(d) for d in session.exec(stmt.order_by(Detection.campaign_id, Detection.type)).all()]


# --------------------------------------------------------------------------- exports

def _attachment(content: str | bytes, filename: str, media_type: str) -> Response:
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _scope_campaigns(session: Session, campaign_id: int | None) -> list[PhishCampaign]:
    stmt = select(PhishCampaign)
    if campaign_id is not None:
        stmt = stmt.where(PhishCampaign.id == campaign_id)
    rows = session.exec(stmt.order_by(PhishCampaign.sample_count.desc())).all()
    if campaign_id is not None and not rows:
        raise HTTPException(404, "campaign not found")
    return rows


@router.get("/export/{format}")
def export(format: str, campaign_id: int | None = None, session: Session = Depends(get_session)):
    camps = _scope_campaigns(session, campaign_id)
    camp_ids = [c.id for c in camps]
    suffix = f"-{camps[0].name}" if campaign_id is not None and camps else ""
    kit_names = _kit_names(session, {c.kit_id for c in camps})
    samples = session.exec(select(PhishSample).where(col(PhishSample.campaign_id).in_(camp_ids))).all() if camp_ids else []
    dets = session.exec(select(Detection).where(col(Detection.campaign_id).in_(camp_ids))).all() if camp_ids else []
    camp_by_id = {c.id: c for c in camps}

    if format == "leads-csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["domain", "brand", "match_kind", "evidence", "lure_words", "sources", "first_seen", "status",
                    "threat_score", "threat_tier"])
        for d in session.exec(select(DomainLead).order_by(DomainLead.threat_score.desc())):
            w.writerow([d.domain, d.brand, d.match_kind, d.evidence or "", " ".join(d.lure_words or []),
                        " ".join(d.sources or []), d.first_seen.isoformat() if d.first_seen else "", d.status,
                        d.threat_score, d.threat_tier or ""])
        return _attachment(buf.getvalue(), "typosquat-leads.csv", "text/csv")

    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["indicator", "type", "campaign", "brand", "kit", "first_seen", "source", "confidence", "screenshot"])
        for s in samples:
            c = camp_by_id.get(s.campaign_id)
            w.writerow([s.url, "url", c.name if c else "", s.brand or "", kit_names.get(c.kit_id, "") if c and c.kit_id else "",
                        s.first_seen.isoformat() if s.first_seen else "", s.source, round(s.brand_confidence, 2), s.screenshot_url or ""])
            if s.domain:
                w.writerow([s.domain, "domain", c.name if c else "", s.brand or "", kit_names.get(c.kit_id, "") if c and c.kit_id else "",
                            s.first_seen.isoformat() if s.first_seen else "", s.source, round(s.brand_confidence, 2), ""])
            if s.ip:
                w.writerow([s.ip, "ipv4", c.name if c else "", s.brand or "", "", s.first_seen.isoformat() if s.first_seen else "", s.source, "medium", ""])
        return _attachment(buf.getvalue(), f"phishing-iocs{suffix}.csv", "text/csv")

    if format == "iocs":
        lines = [f"# CTI Ops P4 IOCs generated {datetime.now(timezone.utc).isoformat()}"]
        for c in camps:
            lines.append(f"\n# {c.name} brand={c.brand} kit={kit_names.get(c.kit_id, '-') if c.kit_id else '-'} samples={c.sample_count}")
            for s in samples:
                if s.campaign_id == c.id:
                    lines.append(s.url)
            for d in sorted({s.domain for s in samples if s.campaign_id == c.id and s.domain}):
                lines.append(d)
            for ip in sorted({s.ip for s in samples if s.campaign_id == c.id and s.ip}):
                lines.append(ip)
        return _attachment("\n".join(lines) + "\n", f"phishing-iocs{suffix}.txt", "text/plain")

    if format in ("sigma", "yara"):
        parts = [d.content for d in dets if d.type == format]
        if not parts:
            raise HTTPException(404, f"no {format} rules for this selection")
        sep = "\n---\n" if format == "sigma" else "\n\n"
        ext = "yml" if format == "sigma" else "yar"
        return _attachment(sep.join(parts), f"phishing-{format}{suffix}.{ext}", "text/plain")

    if format == "stix":
        return _attachment(json.dumps(stix_bundle(camps, samples, kit_names), indent=2), f"phishing{suffix}.stix2.json", "application/json")

    if format == "campaign-cards":
        return _attachment(campaign_cards(camps, samples, dets, kit_names), f"campaign-cards{suffix}.md", "text/markdown")

    raise HTTPException(404, f"unknown export format {format!r}; use csv|leads-csv|stix|sigma|yara|iocs|campaign-cards")


def _stix_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, f'ctiops:{kind}:{key}')}"


def stix_bundle(camps: list[PhishCampaign], samples: list[PhishSample], kit_names: dict[int, str]) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = _stix_id("identity", "ctiops")
    objects: list[dict] = [{"type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
                            "name": "CTI Ops P4 pipeline", "identity_class": "system"}]
    for c in camps:
        cid = _stix_id("campaign", c.name)
        objects.append({"type": "campaign", "spec_version": "2.1", "id": cid, "created": now, "modified": now, "created_by_ref": identity_id,
                        "name": c.name, "description": f"Phishing campaign impersonating {c.brand or 'unknown brand'}; "
                        f"{c.sample_count} pages across {c.domain_count} hostnames; kit: {kit_names.get(c.kit_id, 'unknown') if c.kit_id else 'unknown'} "
                        f"(confidence {c.kit_confidence}). Cluster method {c.cluster_method}, cohesion {c.cohesion}.",
                        "first_seen": c.first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z") if c.first_seen else now,
                        "last_seen": c.last_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z") if c.last_seen else now,
                        "labels": [l for l in ["phishing", (c.brand or "").lower().replace(" ", "-")] if l]})
        if c.kit_id:
            tid = _stix_id("tool", kit_names.get(c.kit_id, str(c.kit_id)))
            objects.append({"type": "tool", "spec_version": "2.1", "id": tid, "created": now, "modified": now, "created_by_ref": identity_id,
                            "name": kit_names.get(c.kit_id, "unknown kit"), "tool_types": ["phishing-kit"]})
            objects.append({"type": "relationship", "spec_version": "2.1", "id": _stix_id("relationship", f"{c.name}:uses:{tid}"),
                            "created": now, "modified": now, "relationship_type": "uses", "source_ref": cid, "target_ref": tid})
        for s in samples:
            if s.campaign_id != c.id:
                continue
            patterns = [("url", f"[url:value = '{s.url.replace(chr(39), chr(92) + chr(39))}']")]
            if s.domain:
                patterns.append(("domain", f"[domain-name:value = '{s.domain}']"))
            if s.ip:
                patterns.append(("ip", f"[ipv4-addr:value = '{s.ip}']"))
            for kind, pat in patterns:
                iid = _stix_id("indicator", f"{kind}:{s.url if kind == 'url' else (s.domain if kind == 'domain' else s.ip)}")
                objects.append({"type": "indicator", "spec_version": "2.1", "id": iid, "created": now, "modified": now,
                                "created_by_ref": identity_id, "name": f"{c.name} {kind}", "pattern": pat, "pattern_type": "stix",
                                "indicator_types": ["malicious-activity"],
                                "valid_from": (s.first_seen or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                                "confidence": int(round((s.brand_confidence if kind != "ip" else 0.5) * 100)),
                                "labels": ["phishing"], "external_references": (
                                    [{"source_name": "urlscan.io", "url": f"https://urlscan.io/result/{s.source_id}/"}] if s.source_id else [])})
                objects.append({"type": "relationship", "spec_version": "2.1", "id": _stix_id("relationship", f"{iid}:indicates:{cid}"),
                                "created": now, "modified": now, "relationship_type": "indicates", "source_ref": iid, "target_ref": cid})
    # de-duplicate by id (same domain can appear under several samples)
    uniq = {o["id"]: o for o in objects}
    return {"type": "bundle", "id": _stix_id("bundle", now), "objects": list(uniq.values())}


def campaign_cards(camps: list[PhishCampaign], samples: list[PhishSample], dets: list[Detection], kit_names: dict[int, str]) -> str:
    out = [f"# Phishing campaign cards\n\nGenerated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by the CTI Ops P4 pipeline. "
           f"{len(camps)} campaigns.\n"]
    for c in camps:
        ss = [s for s in samples if s.campaign_id == c.id]
        dd = [d for d in dets if d.campaign_id == c.id]
        summ = c.summary or {}
        out.append(f"\n---\n\n## {c.name} — {c.brand or 'unknown brand'}\n")
        out.append(f"| | |\n|---|---|\n| Status | {c.status} |\n| Period | {c.first_seen:%Y-%m-%d} → {c.last_seen:%Y-%m-%d} |"
                   if c.first_seen and c.last_seen else "| | |\n|---|---|\n| Status | " + c.status + " |")
        out.append(f"| Pages / hosts / IPs | {c.sample_count} / {c.domain_count} / {c.ip_count} |\n| Kit | "
                   f"{kit_names.get(c.kit_id, 'unknown') if c.kit_id else 'unknown'} (confidence {c.kit_confidence}) |\n"
                   f"| Clustering | {c.cluster_method}, cohesion {c.cohesion} |\n| Sector | {c.sector or '-'} |\n")
        if summ.get("title_examples"):
            out.append("**Lure titles:** " + "; ".join(f"`{t}`" for t in summ["title_examples"][:4]) + "\n")
        infra = ", ".join(f"{d['key']} ({d['count']})" for d in summ.get("top_apex_domains", [])[:8])
        asns = ", ".join(f"{d['key']} ({d['count']})" for d in summ.get("top_asns", [])[:4])
        out.append(f"**Infrastructure:** {infra or '-'}  \n**Hosting ASNs:** {asns or '-'}  \n"
                   f"**TLDs:** {', '.join(d['key'] for d in summ.get('top_tlds', [])[:6]) or '-'}\n")
        shared = summ.get("shared_marker_groups", {})
        bits = []
        for k in ("input_names", "script_hosts", "path_markers", "antibot", "obfuscation", "exfil_types"):
            if shared.get(k):
                bits.append(f"- {k.replace('_', ' ')}: " + ", ".join(f"`{v}`" for v in shared[k][:8]))
        if bits:
            out.append("**Shared kit markers:**\n" + "\n".join(bits) + "\n")
        if summ.get("takedown_targets"):
            out.append("**Takedown targets:**\n" + "\n".join(f"- {t['type']}: `{t['value']}` ({t.get('count', t.get('samples', 0))} pages)" for t in summ["takedown_targets"][:10]) + "\n")
        out.append(f"**Detections ({len(dd)}):** " + ", ".join(sorted({f'{d.type} → {d.target}' for d in dd})) + "\n")
        out.append("**Sample URLs:**\n" + "\n".join(f"- `{s.url}`" + (f" ([screenshot]({s.screenshot_url}))" if s.screenshot_url else "") for s in ss[:8]) + "\n")
        sig = next((d for d in dd if d.type == "url_regex"), None)
        if sig:
            out.append(f"**URL pattern:** `{sig.content}`\n")
    return "\n".join(out)


# --------------------------------------------------------------------------- dashboard aggregates

@router.get("/viz")
def viz(session: Session = Depends(get_session)):
    """Everything the P4 dashboards chart, in one call (see modules/phishing/viz.py for shapes)."""
    from ..modules.phishing import viz as phviz

    return phviz.compute(session)


@router.get("/campaigns/{campaign_id}/graph")
def campaign_graph(campaign_id: int, session: Session = Depends(get_session)):
    """Infrastructure graph around one campaign, including campaigns that share a domain, IP or exfil endpoint."""
    from ..modules.phishing import viz as phviz

    if not session.get(PhishCampaign, campaign_id):
        raise HTTPException(404, "campaign not found")
    return phviz.campaign_graph(session, campaign_id)
