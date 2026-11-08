from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlmodel import Session, func, select

from ..config import load_scope
from ..db import get_session
from ..models import (Briefing, Detection, IABListing, PhishCampaign, PhishKit, PhishSample, PipelineRun,
                      RansomVictim, ThreatActor)
from ..schemas import OverviewOut, SourceHealth
from .common import last_run, run_out
from .reviews import summarize

router = APIRouter(prefix="/api/overview", tags=["overview"])


def _count(session: Session, model, *where) -> int:
    q = select(func.count()).select_from(model)
    for w in where:
        q = q.where(w)
    return session.exec(q).one()


def source_health(session: Session) -> list[SourceHealth]:
    """Derived from the last run summaries (each pipeline records per-source status)."""
    out: list[SourceHealth] = []
    for pipeline in ("phishing", "landscape"):
        run = session.exec(select(PipelineRun).where(PipelineRun.pipeline == pipeline,
                                                     PipelineRun.status == "succeeded")
                           .order_by(PipelineRun.created_at.desc())).first()
        sources = (run.summary or {}).get("sources", {}) if run else {}
        for name, info in sources.items():
            if isinstance(info, dict):
                out.append(SourceHealth(name=name, module=pipeline, status=info.get("status", "unknown"),
                                        detail=info.get("detail"), checked_at=run.finished_at))
            else:
                out.append(SourceHealth(name=name, module=pipeline, status=str(info), checked_at=run.finished_at))
    return out


@router.get("", response_model=OverviewOut)
def overview(session: Session = Depends(get_session)):
    scope = load_scope()
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    month_key = datetime.now(timezone.utc).strftime("%Y-%m")
    phishing = {
        "samples": _count(session, PhishSample),
        "samples_fetched": _count(session, PhishSample, PhishSample.fetch_status == "ok"),
        "campaigns": _count(session, PhishCampaign),
        "campaigns_active": _count(session, PhishCampaign, PhishCampaign.status == "active"),
        "kits": _count(session, PhishKit),
        "detections": _count(session, Detection),
        "samples_7d": _count(session, PhishSample, PhishSample.first_seen >= week_ago),
        "brands": [r[0] for r in session.exec(select(PhishSample.brand).where(PhishSample.brand.is_not(None))
                                              .group_by(PhishSample.brand)
                                              .order_by(func.count().desc()).limit(6))],
        "last_run": last_run(session, "phishing"),
    }
    landscape = {
        "victims_total": _count(session, RansomVictim),
        "victims_scope": _count(session, RansomVictim, RansomVictim.in_scope == True),  # noqa: E712
        "victims_month": _count(session, RansomVictim, RansomVictim.month == month_key),
        "victims_month_scope": _count(session, RansomVictim, RansomVictim.month == month_key,
                                      RansomVictim.in_scope == True),  # noqa: E712
        "actors_total": _count(session, ThreatActor),
        "actors_active": _count(session, ThreatActor, ThreatActor.status == "active"),
        "iab_listings": _count(session, IABListing),
        "iab_scope": _count(session, IABListing, IABListing.in_scope == True),  # noqa: E712
        "briefings": _count(session, Briefing),
        "last_run": last_run(session, "landscape"),
    }
    runs = [run_out(r) for r in session.exec(select(PipelineRun).order_by(PipelineRun.created_at.desc()).limit(8))]
    return OverviewOut(scope=scope, phishing=phishing, landscape=landscape, recent_runs=runs,
                       reviews=summarize(session), sources=source_health(session))
