"""P6 API: X (Twitter) IAB monitor posts, preserved evidence, victim company data and size filters."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlmodel import Session, select

from ..config import get_settings, load_scope
from ..db import get_session
from ..models import Organization, XPost
from ..modules.landscape import firmographics as fg
from ..modules.landscape.xmon import build_query

router = APIRouter(prefix="/api/landscape/x", tags=["x-monitor"])

ORG_FIELDS = ("id", "query_name", "legal_name", "website", "country", "industry", "fin_subtype", "revenue_usd", "revenue_year",
              "revenue_band", "employees", "employees_year", "employee_band", "identifiers", "sources", "match_score", "status")


def _org(o: Organization | None) -> dict[str, Any] | None:
    return {k: getattr(o, k) for k in ORG_FIELDS} if o else None


def _post(p: XPost, orgs: dict[int, Organization]) -> dict[str, Any]:
    org = orgs.get(p.org_id) if p.org_id else None
    claimed = fg.revenue_band(p.claimed_revenue_usd)
    return {
        **p.model_dump(exclude={"raw_path", "card_path", "shot_path"}),
        "card": f"/api/landscape/x/posts/{p.id}/card.png" if p.card_path else None,
        "shot": f"/api/landscape/x/posts/{p.id}/screenshot" if p.shot_path else None,
        "media": [{**m, "file": f"/api/landscape/x/posts/{p.id}/media/{i}" if m.get("path") else None} for i, m in enumerate(p.media)],
        "org": _org(org),
        # size used for narrowing: registry data when found, else what the post claims
        "revenue_band": (org.revenue_band if org and org.revenue_band else claimed),
        "revenue_basis": "registry" if org and org.revenue_band else ("claimed in post" if claimed else None),
        "employee_band": org.employee_band if org else None,
        "industry": (org.industry if org else None),
        "fin_subtype": (org.fin_subtype if org and org.fin_subtype else p.fin_subtype),
    }


@router.get("/status")
def status():
    s, sc = get_settings(), load_scope().landscape
    return {"x_api": bool(s.x_bearer_token), "registries": bool(s.registry_user_agent), "zoominfo": bool(s.zoominfo_username),
            "shodan": bool(s.shodan_api_key),
            "sectors": sc.x_sectors, "queries": [{**q, "sent_as": build_query(q["query"], sc.x_sectors)} for q in sc.x_queries],
            "revenue_bands": [b for _, b in fg.REVENUE_BANDS], "employee_bands": [b for _, b in fg.EMPLOYEE_BANDS]}


@router.post("/posts/{post_id}/identify")
def identify(post_id: int, session: Session = Depends(get_session)):
    """Shortlist companies by country + revenue band + sector, then cross-check which exposes the named tech on
    Shodan. Passive: public registries and Shodan's scan database only; no host is contacted. Leads, not proof."""
    from ..modules.landscape import identify as idmod
    r = session.get(XPost, post_id)
    if not r:
        raise HTTPException(404, "post not found")
    return idmod.identify_victim(session, r)


@router.get("/posts")
def posts(query: str | None = None, revenue_band: str | None = None, employee_band: str | None = None,
          fin_subtype: str | None = None, industry: str | None = None, status: str | None = None, q: str | None = None,
          min_relevance: float = 0.0, limit: int = 200, session: Session = Depends(get_session)):
    rows = session.exec(select(XPost).order_by(XPost.created_at.desc())).all()
    orgs = {o.id: o for o in session.exec(select(Organization))}
    out = []
    for r in rows:
        d = _post(r, orgs)
        if query and query not in r.queries:
            continue
        if revenue_band and d["revenue_band"] != revenue_band:
            continue
        if employee_band and d["employee_band"] != employee_band:
            continue
        if fin_subtype and d["fin_subtype"] != fin_subtype:
            continue
        if industry and industry.lower() not in (d["industry"] or "").lower():
            continue
        if status and r.status != status:
            continue
        if q and q.lower() not in (r.text + " " + (r.victim_name or "") + " " + (r.author_handle or "")).lower():
            continue
        if r.relevance < min_relevance:
            continue
        out.append(d)
    return out[:limit]


@router.get("/posts/{post_id}")
def post(post_id: int, session: Session = Depends(get_session)):
    r = session.get(XPost, post_id)
    if not r:
        raise HTTPException(404, "post not found")
    org = session.get(Organization, r.org_id) if r.org_id else None
    return _post(r, {org.id: org} if org else {})


def _file(rel: str | None, mime: str) -> Response:
    if not rel:
        raise HTTPException(404, "not captured")
    base = get_settings().artifacts_dir.resolve()
    f = (base / rel).resolve()
    if base not in f.parents or not f.exists():
        raise HTTPException(404, "not captured")
    return Response(f.read_bytes(), media_type=mime, headers={"Cache-Control": "max-age=86400"})


@router.get("/posts/{post_id}/card.png")
def card(post_id: int, session: Session = Depends(get_session)):
    r = session.get(XPost, post_id)
    return _file(r.card_path if r else None, "image/png")


@router.get("/posts/{post_id}/screenshot")
def screenshot(post_id: int, session: Session = Depends(get_session)):
    r = session.get(XPost, post_id)
    return _file(r.shot_path if r else None, "image/png" if str(r and r.shot_path).endswith(".png") else "image/jpeg")


@router.get("/posts/{post_id}/media/{idx}")
def media(post_id: int, idx: int, session: Session = Depends(get_session)):
    r = session.get(XPost, post_id)
    m = (r.media[idx] if r and 0 <= idx < len(r.media) else {}) or {}
    return _file(m.get("path"), "image/png" if str(m.get("path", "")).endswith(".png") else "image/jpeg")


@router.get("/posts/{post_id}/record.json")
def record(post_id: int, session: Session = Depends(get_session)):
    r = session.get(XPost, post_id)
    return _file(r.raw_path if r else None, "application/json")


@router.post("/import")
async def import_browser(request: Request, session: Session = Depends(get_session)):
    """Posts read from x.com search pages in the analyst's browser (JSON list; text/plain accepted)."""
    import json as _json

    from ..modules.landscape import x_pipeline as xp
    items = _json.loads((await request.body()).decode("utf-8"))
    return xp.import_browser_posts(session, items, load_scope().landscape.x_sectors)


class VictimIn(BaseModel):
    victim_name: str | None = None
    status: str | None = None  # new | relevant | noise
    refresh: bool = False


@router.patch("/posts/{post_id}")
def update_post(post_id: int, body: VictimIn, session: Session = Depends(get_session)):
    """Analyst confirms or corrects the victim (then company data is looked up) and triages the post."""
    r = session.get(XPost, post_id)
    if not r:
        raise HTTPException(404, "post not found")
    if body.status:
        if body.status not in ("new", "relevant", "noise"):
            raise HTTPException(422, "status must be new, relevant or noise")
        r.status = body.status
    if body.victim_name is not None:
        r.victim_name = body.victim_name.strip() or None
        r.victim_confirmed = bool(r.victim_name)
        r.org_id = None
    if r.victim_name and (body.victim_name is not None or body.refresh):
        org = fg.lookup(session, r.victim_name, refresh=body.refresh, country_hint=(r.countries or [None])[0])
        r.org_id = org.id if org.status == "ok" else None
    session.add(r)
    session.commit()
    return post(post_id, session)


@router.get("/companies")
def companies(revenue_band: str | None = None, employee_band: str | None = None, fin_subtype: str | None = None,
              session: Session = Depends(get_session)):
    rows = session.exec(select(Organization).where(Organization.status == "ok")).all()
    return [_org(o) for o in rows if (not revenue_band or o.revenue_band == revenue_band)
            and (not employee_band or o.employee_band == employee_band) and (not fin_subtype or o.fin_subtype == fin_subtype)]
