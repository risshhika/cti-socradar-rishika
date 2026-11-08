from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Any

from sqlmodel import Session, select

from ..models import AnalystReview, PipelineRun
from ..schemas import KeyCount, RunOut


def key_counts(values: Iterable[Any], top: int = 10, label_none: str = "unknown") -> list[KeyCount]:
    c = Counter((v if v not in (None, "") else label_none) for v in values)
    total = sum(c.values()) or 1
    return [KeyCount(key=str(k), count=n, share=round(n / total, 4)) for k, n in c.most_common(top)]


def run_out(run: PipelineRun) -> RunOut:
    dur = None
    if run.started_at and run.finished_at:
        dur = (run.finished_at - run.started_at).total_seconds()
    return RunOut(id=run.id, pipeline=run.pipeline, status=run.status, trigger=run.trigger, params=run.params or {},
                  summary=run.summary or {}, error=run.error, started_at=run.started_at, finished_at=run.finished_at,
                  created_at=run.created_at, duration_seconds=dur)


def last_run(session: Session, pipeline: str) -> RunOut | None:
    run = session.exec(select(PipelineRun).where(PipelineRun.pipeline == pipeline)
                       .order_by(PipelineRun.created_at.desc())).first()
    return run_out(run) if run else None


def latest_verdicts(session: Session, entity_type: str, ids: list[int]) -> dict[int, str]:
    if not ids:
        return {}
    rows = session.exec(select(AnalystReview).where(AnalystReview.entity_type == entity_type,
                                                    AnalystReview.entity_id.in_(ids))
                        .order_by(AnalystReview.created_at.asc())).all()
    out: dict[int, str] = {}
    for r in rows:
        out[r.entity_id] = r.verdict
    return out
