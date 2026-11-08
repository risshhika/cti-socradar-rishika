from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..db import get_session
from ..models import PipelineRun
from ..pipelines import runner
from ..schemas import RunDetail, RunOut, TriggerRunRequest
from .common import run_out

router = APIRouter(prefix="/api/pipelines", tags=["pipelines"])


@router.get("", response_model=list[dict])
def list_pipelines(session: Session = Depends(get_session)):
    out = []
    for name in runner.available():
        last = session.exec(select(PipelineRun).where(PipelineRun.pipeline == name)
                            .order_by(PipelineRun.created_at.desc())).first()
        out.append({"name": name, "running": runner.is_running(name),
                    "last_run": run_out(last).model_dump() if last else None})
    return out


@router.get("/runs", response_model=list[RunOut])
def list_runs(pipeline: str | None = None, limit: int = 50, session: Session = Depends(get_session)):
    q = select(PipelineRun).order_by(PipelineRun.created_at.desc()).limit(limit)
    if pipeline:
        q = q.where(PipelineRun.pipeline == pipeline)
    return [run_out(r) for r in session.exec(q)]


@router.get("/runs/{run_id}", response_model=RunDetail)
def get_run(run_id: int, session: Session = Depends(get_session)):
    run = session.get(PipelineRun, run_id)
    if not run:
        raise HTTPException(404, "run not found")
    base = run_out(run)
    return RunDetail(**base.model_dump(), log=run.log or "")


@router.post("/{name}/run", response_model=RunOut, status_code=202)
def trigger(name: str, body: TriggerRunRequest | None = None):
    try:
        run = runner.start_run(name, params=(body.params if body else {}), trigger="manual")
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    return run_out(run)
