from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from ..db import get_session
from ..models import AnalystReview
from ..schemas import ReviewIn, ReviewOut, ReviewSummary

router = APIRouter(prefix="/api/reviews", tags=["reviews"])
ENTITY_TYPES = ["campaign", "sample", "kit", "victim", "actor", "iab", "briefing"]


def summarize(session: Session) -> list[ReviewSummary]:
    out = []
    for et in ENTITY_TYPES:
        rows = session.exec(select(AnalystReview).where(AnalystReview.entity_type == et)
                            .order_by(AnalystReview.created_at.asc())).all()
        latest: dict[int, str] = {}
        for r in rows:
            latest[r.entity_id] = r.verdict
        if not latest:
            continue
        agree = sum(1 for v in latest.values() if v == "agree")
        miss = sum(1 for v in latest.values() if v == "miss")
        over = sum(1 for v in latest.values() if v == "over_flag")
        unsure = sum(1 for v in latest.values() if v == "unsure")
        prec = round(agree / (agree + over), 3) if (agree + over) else None
        out.append(ReviewSummary(entity_type=et, reviewed=len(latest), agree=agree, miss=miss,
                                 over_flag=over, unsure=unsure, precision_proxy=prec))
    return out


@router.get("", response_model=list[ReviewOut])
def list_reviews(entity_type: str | None = None, entity_id: int | None = None,
                 session: Session = Depends(get_session)):
    q = select(AnalystReview).order_by(AnalystReview.created_at.desc())
    if entity_type:
        q = q.where(AnalystReview.entity_type == entity_type)
    if entity_id is not None:
        q = q.where(AnalystReview.entity_id == entity_id)
    return [ReviewOut.model_validate(r, from_attributes=True) for r in session.exec(q.limit(500))]


@router.get("/summary", response_model=list[ReviewSummary])
def review_summary(session: Session = Depends(get_session)):
    return summarize(session)


@router.post("", response_model=ReviewOut, status_code=201)
def create_review(body: ReviewIn, session: Session = Depends(get_session)):
    rev = AnalystReview(**body.model_dump())
    session.add(rev)
    session.commit()
    session.refresh(rev)
    return ReviewOut.model_validate(rev, from_attributes=True)
