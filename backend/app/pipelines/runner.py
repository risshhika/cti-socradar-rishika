"""Pipeline execution: each module exposes `run(ctx) -> dict`. Runs are tracked in pipeline_runs with a
streamed log so the UI can follow progress. One run per pipeline at a time."""
from __future__ import annotations

import logging
import os
import threading
import traceback
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, select

from ..config import Scope, load_scope
from ..db import get_engine
from ..models import PipelineRun

log = logging.getLogger(__name__)


class RunContext:
    def __init__(self, run_id: int, scope: Scope, params: dict[str, Any]) -> None:
        self.run_id = run_id
        self.scope = scope
        self.params = params
        self._buffer: list[str] = []
        self._lock = threading.Lock()

    def log(self, msg: str) -> None:
        line = f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}"
        log.info("run %s: %s", self.run_id, msg)
        with self._lock:
            self._buffer.append(line)
            lines = list(self._buffer)
        with Session(get_engine()) as s:
            run = s.get(PipelineRun, self.run_id)
            if run:
                run.log = "\n".join(lines)
                s.add(run)
                s.commit()

    def session(self) -> Session:
        return Session(get_engine())


PipelineFn = Callable[[RunContext], dict[str, Any]]
_REGISTRY: dict[str, PipelineFn] = {}
_ACTIVE: dict[str, threading.Thread] = {}
_ACTIVE_LOCK = threading.Lock()


def register(name: str, fn: PipelineFn) -> None:
    _REGISTRY[name] = fn


def available() -> list[str]:
    _load_modules()
    return sorted(_REGISTRY)


def _load_modules() -> None:
    if _REGISTRY:
        return
    from ..modules.landscape import pipeline as landscape  # noqa: F401
    from ..modules.landscape import x_pipeline  # noqa: F401
    from ..modules.phishing import pipeline as phishing  # noqa: F401

    register("phishing", phishing.run)
    register("landscape", landscape.run)
    register("x_iab", x_pipeline.run)


def is_running(name: str) -> bool:
    """True if a run is executing in this process or in another live process (e.g. `app.cli run`)."""
    with _ACTIVE_LOCK:
        t = _ACTIVE.get(name)
        if t and t.is_alive():
            return True
    with Session(get_engine()) as s:
        run = s.exec(select(PipelineRun).where(PipelineRun.pipeline == name, PipelineRun.status == "running")
                     .order_by(PipelineRun.created_at.desc())).first()
        return bool(run and _pid_alive((run.summary or {}).get("pid")))


def start_run(name: str, params: dict[str, Any] | None = None, trigger: str = "manual",
              blocking: bool = False) -> PipelineRun:
    _load_modules()
    if name not in _REGISTRY:
        raise KeyError(f"unknown pipeline {name!r}; available: {sorted(_REGISTRY)}")
    if is_running(name):
        raise RuntimeError(f"pipeline {name!r} is already running")
    with Session(get_engine()) as s:
        run = PipelineRun(pipeline=name, status="queued", trigger=trigger, params=params or {})
        s.add(run)
        s.commit()
        s.refresh(run)
        run_id = run.id
        snapshot = PipelineRun.model_validate(run)
    if blocking:
        _execute(name, run_id, params or {})
    else:
        t = threading.Thread(target=_execute, args=(name, run_id, params or {}), daemon=True, name=f"pipeline-{name}")
        with _ACTIVE_LOCK:
            _ACTIVE[name] = t
        t.start()
    return snapshot


def _execute(name: str, run_id: int, params: dict[str, Any]) -> None:
    scope = load_scope()
    ctx = RunContext(run_id, scope, params)
    with Session(get_engine()) as s:
        run = s.get(PipelineRun, run_id)
        run.status, run.started_at = "running", datetime.now(timezone.utc)
        run.summary = {"pid": os.getpid()}  # lets a restarted server tell live CLI runs from dead ones
        s.add(run)
        s.commit()
    try:
        ctx.log(f"starting pipeline '{name}' with params {params}")
        summary = _REGISTRY[name](ctx) or {}
        ctx.log("finished")
        status, error = "succeeded", None
    except Exception as exc:  # keep the run record even on failure
        summary = {}
        status, error = "failed", f"{exc}\n{traceback.format_exc()}"
        ctx.log(f"FAILED: {exc}")
    with Session(get_engine()) as s:
        run = s.get(PipelineRun, run_id)
        run.status, run.summary, run.error, run.finished_at = status, summary, error, datetime.now(timezone.utc)
        s.add(run)
        s.commit()
    with _ACTIVE_LOCK:
        _ACTIVE.pop(name, None)


def _pid_alive(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":
        # os.kill(pid, 0) on Windows calls TerminateProcess -- it would kill the run it is probing.
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return ctypes.get_last_error() == 5 or k32.GetLastError() == 5  # access denied -> exists
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # exists, owned by someone else
        return True
    return True


def recover_stale_runs() -> None:
    """Mark runs whose owning process is gone as failed. Runs still executing in another live process
    (e.g. `app.cli run` while the server restarts) are left alone."""
    with Session(get_engine()) as s:
        for run in s.exec(select(PipelineRun).where(PipelineRun.status.in_(["running", "queued"]))):
            pid = (run.summary or {}).get("pid")
            if pid != os.getpid() and _pid_alive(pid):
                continue
            run.status, run.error, run.finished_at = "failed", "owning process exited during run", datetime.now(timezone.utc)
            s.add(run)
        s.commit()
