"""P6 API: sector threat landscape, victims, actors, IAB reporting, incidents, briefings, exports."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlmodel import Session, func, select

from ..config import load_scope
from ..db import get_session
from ..models import AnalystReview, Briefing, CyberIncident, IABListing, RansomVictim, ThreatActor
from ..modules.landscape import briefing as briefing_mod
from ..modules.landscape.classify import sector_matches
from ..modules.landscape.regions import countries_in
from ..modules.landscape.trends import actor_out, compute_stats, iab_stats
from ..modules.landscape.viz import actor_viz, landscape_viz
from ..modules.landscape.collectors import months_back
from ..modules.landscape.pipeline import _flatten_tools, slugify
from ..schemas import (ActorDetail, ActorOut, BriefingOut, BriefingSummary, GenerateBriefingRequest, IABOut, IABStats,
                       IncidentOut, LandscapeStats, Page, ReviewOut, VictimList, VictimOut)
from .common import latest_verdicts

router = APIRouter(prefix="/api/landscape", tags=["landscape"])


def _victim_out(v: RansomVictim, verdicts: dict[int, str] | None = None) -> VictimOut:
    d = VictimOut.model_validate(v, from_attributes=True)
    d.review_verdict = (verdicts or {}).get(v.id)
    return d


def _victims_out(session: Session, rows: list[RansomVictim]) -> list[VictimOut]:
    verdicts = latest_verdicts(session, "victim", [v.id for v in rows])
    return [_victim_out(v, verdicts) for v in rows]


# --------------------------------------------------------------------------- stats

@router.get("/stats", response_model=LandscapeStats)
def stats(months: int | None = None, sector: str | None = None, region: str | None = None,
          session: Session = Depends(get_session)):
    sc = load_scope().landscape
    return compute_stats(session, sector or sc.sector, region or sc.region, (months or sc.months) + 1)


@router.get("/viz")
def visuals(months: int | None = None, sector: str | None = None, region: str | None = None,
            session: Session = Depends(get_session)):
    """Every aggregate the P6 dashboards draw, in one call (see frontend/src/lib/landscapeViz.ts for the shape)."""
    sc = load_scope().landscape
    return landscape_viz(session, sector or sc.sector, region or sc.region, (months or sc.months) + 1)


# --------------------------------------------------------------------------- victims

def _victim_stmt(sector, region, country, group, month, size_band, q, in_scope, source, cols=None):
    stmt = select(*cols) if cols else select(RansomVictim)
    if sector:
        stmt = stmt.where(RansomVictim.sector == sector)
    if region:
        allowed = countries_in(region)
        if allowed is not None:
            stmt = stmt.where(RansomVictim.country.in_(sorted(allowed)))
    if country:
        stmt = stmt.where(RansomVictim.country == country.upper())
    if group:
        stmt = stmt.where(func.lower(RansomVictim.group) == group.lower())
    if month:
        stmt = stmt.where(RansomVictim.month == month)
    if size_band:
        stmt = stmt.where(RansomVictim.size_band == size_band)
    if source:
        stmt = stmt.where(RansomVictim.source == source)
    if in_scope is not None:
        stmt = stmt.where(RansomVictim.in_scope == in_scope)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(func.lower(RansomVictim.victim).like(like) | func.lower(RansomVictim.domain).like(like)
                          | func.lower(RansomVictim.description).like(like) | func.lower(RansomVictim.group).like(like))
    return stmt


@router.get("/victims", response_model=VictimList)
def victims(sector: str | None = None, region: str | None = None, country: str | None = None, group: str | None = None,
            month: str | None = None, size_band: str | None = None, q: str | None = None, in_scope: bool | None = None,
            source: str | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
            session: Session = Depends(get_session)):
    stmt = _victim_stmt(sector, region, country, group, month, size_band, q, in_scope, source)
    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    rows = session.exec(stmt.order_by(RansomVictim.discovered.desc(), RansomVictim.id.desc())
                        .offset((page - 1) * size).limit(size)).all()
    return VictimList(items=_victims_out(session, rows), page=Page(page=page, size=size, total=total))


@router.get("/victims/summary")
def victims_summary(sector: str | None = None, region: str | None = None, country: str | None = None,
                    group: str | None = None, month: str | None = None, size_band: str | None = None, q: str | None = None,
                    in_scope: bool | None = None, source: str | None = None, session: Session = Depends(get_session)):
    """Breakdowns of the whole filtered victim set (same filters as /victims) for the tracker's summary charts."""
    from collections import Counter
    cols = (RansomVictim.country, RansomVictim.group, RansomVictim.size_band, RansomVictim.sector, RansomVictim.month,
            RansomVictim.cross_source_match, RansomVictim.region)
    rows = session.exec(_victim_stmt(sector, region, country, group, month, size_band, q, in_scope, source, cols)).all()
    c = {k: Counter() for k in ("country", "group", "size", "sector", "month", "region")}
    cross = 0
    for cc, grp, size_, sec, mon, cm, reg in rows:
        c["country"][cc or "??"] += 1
        c["group"][grp] += 1
        c["size"][size_ or "unknown"] += 1
        c["sector"][sec or "Other"] += 1
        c["region"][reg or "Unknown"] += 1
        if mon:
            c["month"][mon] += 1
        cross += 1 if cm else 0
    top = lambda k, n=12: [{"key": key, "count": v} for key, v in c[k].most_common(n)]  # noqa: E731
    return {"total": len(rows), "cross_source": cross, "countries": top("country"), "groups": top("group"),
            "sizes": top("size", 6), "sectors": top("sector", 13), "regions": top("region"),
            "months": [{"key": m, "count": c["month"][m]} for m in sorted(c["month"])], "group_options": top("group", 80)}


@router.get("/victims/{victim_id}", response_model=VictimOut)
def victim(victim_id: int, session: Session = Depends(get_session)):
    v = session.get(RansomVictim, victim_id)
    if not v:
        raise HTTPException(404, "victim not found")
    return _victim_out(v, latest_verdicts(session, "victim", [v.id]))


# --------------------------------------------------------------------------- actors

@router.get("/actors", response_model=list[ActorOut])
def actors(scope_only: bool = False, q: str | None = None, status: str | None = None, limit: int = 300,
           session: Session = Depends(get_session)):
    sc = load_scope().landscape
    months = months_back(sc.months + 1)
    stmt = select(ThreatActor)
    if status:
        stmt = stmt.where(ThreatActor.status == status)
    if scope_only:
        stmt = stmt.where(ThreatActor.victim_count_scope > 0)
    if q:
        stmt = stmt.where(func.lower(ThreatActor.name).like(f"%{q.lower()}%"))
    rows = session.exec(stmt).all()
    rows.sort(key=lambda a: (-a.victim_count_window, -a.victim_count_total, a.name))
    return [actor_out(a, months) for a in rows[:limit]]


def _find_actor(session: Session, slug: str) -> ThreatActor:
    a = session.exec(select(ThreatActor).where(ThreatActor.slug == slug.lower())).first()
    if not a:  # exact name first: SQLite lower() only folds ASCII, so non-Latin names need this
        a = session.exec(select(ThreatActor).where(ThreatActor.name == slug)).first()
    if not a:
        a = session.exec(select(ThreatActor).where(func.lower(ThreatActor.name) == slug.lower())).first()
    if not a:  # tolerate any slug flavour: compare slugified names
        a = next((x for x in session.exec(select(ThreatActor)) if slugify(x.name) == slugify(slug)), None)
    if not a:
        raise HTTPException(404, "actor not found")
    return a


@router.get("/actors/{slug}/viz")
def actor_visuals(slug: str, months: int | None = None, session: Session = Depends(get_session)):
    """Chart data for one actor: monthly totals vs scope, sector mix vs landscape (radar), countries, calendar, TTPs."""
    sc = load_scope().landscape
    return actor_viz(session, _find_actor(session, slug), (months or sc.months) + 1)


@router.get("/actors/{slug}", response_model=ActorDetail)
def actor(slug: str, session: Session = Depends(get_session)):
    a = _find_actor(session, slug)
    sc = load_scope().landscape
    months = months_back(sc.months + 1)
    base = select(RansomVictim).where(func.lower(RansomVictim.group) == a.name.lower()).order_by(RansomVictim.discovered.desc())
    recent = session.exec(base.limit(25)).all()
    scope_rows = session.exec(base.where(RansomVictim.in_scope == True).limit(25)).all()  # noqa: E712
    return ActorDetail(actor=actor_out(a, months), description=a.description, ttps=a.ttps or [], tools=_flatten_tools(a.tools),
                       locations=[{k: v for k, v in loc.items() if k != "screen"} for loc in (a.locations or [])],
                       profile_url=a.profile_url, recent_victims=_victims_out(session, recent),
                       scope_victims=_victims_out(session, scope_rows))


# --------------------------------------------------------------------------- IAB

@router.get("/iab/stats", response_model=IABStats)
def iab_statistics(session: Session = Depends(get_session)):
    sc = load_scope().landscape
    return iab_stats(session, sc.sector, sc.region, months_back(sc.months + 1))


@router.get("/iab", response_model=list[IABOut])
def iab(region: str | None = None, sector: str | None = None, access_type: str | None = None, in_scope: bool | None = None,
        min_relevance: float = 0.0, q: str | None = None, limit: int = 500, session: Session = Depends(get_session)):
    stmt = select(IABListing).where(IABListing.relevance >= min_relevance)
    if in_scope is not None:
        stmt = stmt.where(IABListing.in_scope == in_scope)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(func.lower(IABListing.title).like(like) | func.lower(IABListing.summary).like(like)
                          | func.lower(IABListing.excerpt).like(like))
    rows = session.exec(stmt.order_by(IABListing.published.desc())).all()
    if region:
        allowed = countries_in(region)
        rows = [r for r in rows if (allowed is None) or (r.region == region) or any(c in allowed for c in (r.countries or []))]
    if sector:
        rows = [r for r in rows if any(sector_matches(s, sector) for s in (r.sectors or []))]
    if access_type:
        rows = [r for r in rows if access_type in (r.access_types or [])]
    return [IABOut.model_validate(r, from_attributes=True) for r in rows[:limit]]


@router.get("/iab/{listing_id}", response_model=IABOut)
def iab_one(listing_id: int, session: Session = Depends(get_session)):
    r = session.get(IABListing, listing_id)
    if not r:
        raise HTTPException(404, "listing not found")
    return IABOut.model_validate(r, from_attributes=True)


# --------------------------------------------------------------------------- incidents

@router.get("/incidents", response_model=list[IncidentOut])
def incidents(in_scope: bool | None = None, month: str | None = None, q: str | None = None, limit: int = 300,
              session: Session = Depends(get_session)):
    stmt = select(CyberIncident)
    if in_scope is not None:
        stmt = stmt.where(CyberIncident.in_scope == in_scope)
    if month:
        stmt = stmt.where(CyberIncident.month == month)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(func.lower(CyberIncident.title).like(like) | func.lower(CyberIncident.summary).like(like))
    rows = session.exec(stmt.order_by(CyberIncident.date.desc()).limit(limit)).all()
    return [IncidentOut.model_validate(r, from_attributes=True) for r in rows]


# --------------------------------------------------------------------------- briefings

@router.get("/briefings", response_model=list[BriefingSummary])
def briefings(session: Session = Depends(get_session)):
    rows = session.exec(select(Briefing).order_by(Briefing.period.desc(), Briefing.generated_at.desc())).all()
    return [BriefingSummary.model_validate(b, from_attributes=True) for b in rows]


@router.get("/briefings/{briefing_id}", response_model=BriefingOut)
def briefing(briefing_id: int, session: Session = Depends(get_session)):
    b = session.get(Briefing, briefing_id)
    if not b:
        raise HTTPException(404, "briefing not found")
    return BriefingOut.model_validate(b, from_attributes=True)


@router.post("/briefings/generate", response_model=BriefingOut)
def generate_briefing(body: GenerateBriefingRequest, session: Session = Depends(get_session)):
    try:
        datetime.strptime(body.period, "%Y-%m")
    except ValueError:
        raise HTTPException(422, "period must be YYYY-MM")
    sc = load_scope().landscape
    b = briefing_mod.generate(session, body.period, sc.sector, sc.region, use_llm=body.use_llm)
    return BriefingOut.model_validate(b, from_attributes=True)


@router.post("/briefings/{briefing_id}/finalize", response_model=BriefingOut)
def finalize_briefing(briefing_id: int, session: Session = Depends(get_session)):
    b = session.get(Briefing, briefing_id)
    if not b:
        raise HTTPException(404, "briefing not found")
    b.status = "final"
    session.add(b)
    session.commit()
    session.refresh(b)
    return BriefingOut.model_validate(b, from_attributes=True)


# --------------------------------------------------------------------------- exports

def _csv(rows: list[dict], filename: str) -> Response:
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow({k: (", ".join(map(str, v)) if isinstance(v, list) else v) for k, v in r.items()})
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/export/{fmt}")
def export(fmt: str, id: int | None = None, in_scope: bool | None = None, session: Session = Depends(get_session)):
    sc = load_scope().landscape
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    if fmt == "victims-csv":
        stmt = select(RansomVictim).order_by(RansomVictim.discovered.desc())
        if in_scope is not None:
            stmt = stmt.where(RansomVictim.in_scope == in_scope)
        rows = [{"victim": v.victim, "domain": v.domain, "group": v.group, "attack_date": v.attack_date, "discovered": v.discovered,
                 "month": v.month, "country": v.country, "region": v.region, "sector": v.sector, "sector_method": v.sector_method,
                 "size_band": v.size_band, "size_basis": v.size_basis, "in_scope": v.in_scope, "cross_source_match": v.cross_source_match,
                 "source": v.source, "url": v.url} for v in session.exec(stmt)]
        return _csv(rows, f"victims_{stamp}.csv")
    if fmt == "actors-csv":
        rows = [{"name": a.name, "status": a.status, "first_seen": a.first_seen, "last_seen": a.last_seen,
                 "victims_total": a.victim_count_total, "victims_window": a.victim_count_window, "victims_scope": a.victim_count_scope,
                 "monthly_counts": [f"{k}:{v}" for k, v in (a.monthly_counts or {}).items()],
                 "top_sectors": [f"{s['key']}:{s['count']}" for s in (a.top_sectors or [])],
                 "top_countries": [f"{s['key']}:{s['count']}" for s in (a.top_countries or [])],
                 "aliases": a.aliases, "profile_url": a.profile_url}
                for a in sorted(session.exec(select(ThreatActor)), key=lambda a: -a.victim_count_window)]
        return _csv(rows, f"actors_{stamp}.csv")
    if fmt == "iab-csv":
        rows = [{"published": r.published, "source": r.source, "title": r.title, "url": r.source_url, "relevance": r.relevance,
                 "access_types": r.access_types, "price_usd_min": r.price_usd_min, "price_usd_max": r.price_usd_max,
                 "revenue_usd": r.revenue_usd, "countries": r.countries, "region": r.region, "sectors": r.sectors,
                 "brokers": r.brokers, "actors": r.actors, "in_scope": r.in_scope, "extraction": r.extraction_method}
                for r in session.exec(select(IABListing).order_by(IABListing.published.desc()))]
        return _csv(rows, f"iab_reporting_{stamp}.csv")
    if fmt == "briefing-md":
        b = session.get(Briefing, id) if id else session.exec(select(Briefing).order_by(Briefing.period.desc())).first()
        if not b:
            raise HTTPException(404, "no briefing")
        name = f"briefing_{b.sector}_{b.region}_{b.period}.md".replace(" ", "_").replace("&", "and")
        return Response(b.markdown, media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})
    raise HTTPException(404, f"unknown export format {fmt!r}; use victims-csv | actors-csv | iab-csv | briefing-md")


@router.get("/reviews/{victim_id}", response_model=list[ReviewOut], include_in_schema=False)
def victim_reviews(victim_id: int, session: Session = Depends(get_session)):
    rows = session.exec(select(AnalystReview).where(AnalystReview.entity_type == "victim", AnalystReview.entity_id == victim_id)).all()
    return [ReviewOut.model_validate(r, from_attributes=True) for r in rows]
