"""CLI entry point.

  python -m app.cli run phishing          # run one pipeline, blocking, logs to stdout
  python -m app.cli run landscape
  python -m app.cli run all
  python -m app.cli serve [--port 8000]   # API + built frontend
  python -m app.cli export phishing csv   # see api/exports in each module
"""
from __future__ import annotations

import argparse
import sys

from .db import init_db
from .pipelines import runner


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ctiops")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a pipeline from a clean start")
    r.add_argument("pipeline", choices=["phishing", "landscape", "all"])
    r.add_argument("--param", action="append", default=[], help="key=value overrides")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")
    args = p.parse_args(argv)

    init_db()
    if args.cmd == "run":
        params = dict(kv.split("=", 1) for kv in args.param)
        names = ["phishing", "landscape"] if args.pipeline == "all" else [args.pipeline]
        rc = 0
        for name in names:
            run = runner.start_run(name, params=params, trigger="cli", blocking=True)
            from sqlmodel import Session, select

            from .db import get_engine
            from .models import PipelineRun

            with Session(get_engine()) as sess:
                final = sess.get(PipelineRun, run.id)
                print(f"\n== {name}: {final.status} ==")
                print(final.log)
                if final.status != "succeeded":
                    print(final.error, file=sys.stderr)
                    rc = 1
                else:
                    import json

                    print(json.dumps(final.summary, indent=2, default=str))
        return rc
    if args.cmd == "serve":
        import uvicorn

        uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
