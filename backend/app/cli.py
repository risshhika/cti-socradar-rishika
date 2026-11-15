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
    rp = sub.add_parser("report", help="render a client report (approved template, no internal source names)")
    src = rp.add_mutually_exclusive_group(required=True)
    src.add_argument("--spec", help="hand-written report spec (JSON), e.g. docs/reports/*.json")
    src.add_argument("--campaign", help="campaign id or name (CAMP-...) to auto-fill from")
    src.add_argument("--brand", help="brand report: brand statistics and charts, then its leading campaign")
    rp.add_argument("--reporter", default="", help="reporter name on the cover")
    rp.add_argument("--classification", default="TLP:CLEAR")
    rp.add_argument("--overrides", help="JSON file whose fields replace the auto-filled ones")
    rp.add_argument("--out", required=True, help="output .html (open in a browser, or upload to Google Docs)")
    xi = sub.add_parser("x-import", help="import X posts read in the browser (JSON list) through the IAB monitor filters")
    xi.add_argument("file")
    xs = sub.add_parser("x-shot", help="attach an x.com screenshot to an imported post")
    xs.add_argument("tweet_id")
    xs.add_argument("image")
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
    if args.cmd in ("x-import", "x-shot"):
        import json
        from pathlib import Path

        from sqlmodel import Session

        from .config import load_scope
        from .db import get_engine
        from .modules.landscape import x_pipeline as xp
        with Session(get_engine()) as sess:
            if args.cmd == "x-import":
                items = json.loads(Path(args.file).read_text(encoding="utf-8"))
                print(json.dumps(xp.import_browser_posts(sess, items, load_scope().landscape.x_sectors), indent=1))
            else:
                row = xp.attach_shot(sess, args.tweet_id, Path(args.image).read_bytes())
                print(f"attached to post {row.id}" if row else "no such post")
                return 0 if row else 1
        return 0
    if args.cmd == "report":
        import json
        from pathlib import Path

        from .modules.phishing import client_report as cr
        try:
            if args.spec:
                out = cr.render_spec_file(args.spec)
            else:
                from sqlmodel import Session, select

                from .db import get_engine
                from .models import PhishCampaign
                from .config import load_scope
                who = args.reporter or load_scope().phishing.report_reporter or "Analyst"
                with Session(get_engine()) as sess:
                    if args.brand:
                        spec = cr.build_for_brand(sess, args.brand, who, args.classification)
                    else:
                        spec = None
                    cid = None if spec else int(args.campaign) if str(args.campaign).isdigit() else sess.exec(
                        select(PhishCampaign.id).where(PhishCampaign.name == args.campaign)).first()
                    if spec is None and cid is None:
                        print(f"no campaign {args.campaign!r}", file=sys.stderr)
                        return 1
                    spec = spec or cr.build_from_campaign(sess, cid, who, args.classification)
                if args.overrides:
                    spec = cr.merge_overrides(spec, json.loads(Path(args.overrides).read_text(encoding="utf-8")))
                out = cr.render(spec)
        except cr.NotReportable as e:
            print(f"not reportable: {e}", file=sys.stderr)
            return 3
        except cr.ClientLeakError as e:
            print(f"refused: {e}", file=sys.stderr)
            for leak in e.leaks:
                print(f"  {leak['field']}: ...{leak['context']}...", file=sys.stderr)
            return 2
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"wrote {args.out} ({len(out):,} bytes)")
        return 0
    if args.cmd == "serve":
        import uvicorn

        uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
