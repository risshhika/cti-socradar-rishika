from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import landscape, overview, phishing, pipelines, reviews, scope
from .config import get_settings
from .db import init_db
from .pipelines import runner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    runner.recover_stale_runs()
    yield


app = FastAPI(title="CTI Ops Platform", version="0.1.0", lifespan=lifespan,
              description="P4 Phishing Campaign Clustering & Kit Fingerprinting · P6 Sector Threat Landscape & IAB/Ransomware Tracker")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

for r in (overview.router, scope.router, pipelines.router, reviews.router, phishing.router, landscape.router):
    app.include_router(r)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Captured phishing HTML is deliberately NOT mounted as static files: served from this origin as text/html it
# would execute in the analyst's browser. It is exposed only via /api/phishing/samples/{id}/html as text/plain.
settings = get_settings()
dist: Path = settings.frontend_dist
if dist.exists():
    app.mount("/assets", StaticFiles(directory=str(dist / "assets")), name="assets")
    dist_root = dist.resolve()

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(404, "not found")
        candidate = (dist / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(dist_root):
            return FileResponse(candidate)
        return FileResponse(dist_root / "index.html")
