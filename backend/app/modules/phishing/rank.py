"""Threat rank for phishing samples and domain leads (0-100, explainable).

Two detection types feed the same score:
  * typosquat  -- the hostname imitates the brand (pay-pal-ai.vercel.app). Ranked higher: the lure
                  works on sight, before the page even loads.
  * content    -- the hostname is meaningless (ehrjhefer.vercel.app) but the page impersonates the
                  brand. Only page evidence (brand, credential form, kit) can rank it.
Every point is recorded with its reason, so an analyst can see *why* something ranks where it does.
"""
from __future__ import annotations

from typing import Any

PLATFORMS = ("vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "github.io",
             "weebly.com", "wixsite.com", "webflow.io", "glitch.me", "onrender.com", "replit.app", "r2.dev",
             "edgeone.dev", "framer.app", "godaddysites.com", "square.site", "blogspot.com", "azurewebsites.net",
             "herokuapp.com", "surge.sh", "fly.dev", "ngrok-free.app", "ipfs.io", "dweb.link")

SQUAT_POINTS = {"homoglyph": 38, "embed": 35, "fragment": 30, "typo": 26}
TIERS = ((70, "critical"), (50, "high"), (30, "medium"), (0, "low"))


def tier_for(score: int) -> str:
    return next(name for floor, name in TIERS if score >= floor)


def platform_of(host: str | None) -> str | None:
    host = (host or "").lower()
    return next((p for p in PLATFORMS if host == p or host.endswith("." + p)), None)


def threat_rank(*, host: str | None, squat: dict[str, Any] | None, features: dict[str, Any] | None = None,
                fetch_status: str | None = None, kit_confidence: float = 0.0, source: str | None = None,
                source_tags: list[str] | None = None, lead_sources: list[str] | None = None) -> dict[str, Any]:
    f = features or {}
    meta = f.get("_meta") or {}
    factors: list[dict[str, Any]] = []

    def add(points: int, factor: str, detail: str) -> None:
        if points:
            factors.append({"factor": factor, "points": points, "detail": detail})

    # --- hostname evidence (type A)
    if squat:
        base = SQUAT_POINTS.get(squat["kind"], 25)
        pts = round(base * min(1.0, squat.get("score", 1.0) / (0.9 if squat["kind"] == "fragment" else 1.0)))
        add(pts, "typosquat", squat.get("evidence") or f"{squat['kind']} of {squat['brand']}")
        lures = squat.get("lure_words") or []
        add(min(8, 4 * len(lures)), "lure words", ", ".join(lures))

    # --- freshness
    age = meta.get("domainAgeDays") if meta.get("domainAgeDays") is not None else meta.get("apexDomainAgeDays")
    lead_sources = lead_sources or []
    if "nrd" in lead_sources or (isinstance(age, int | float) and age <= 30):
        add(12, "new domain", "registered in the last 30 days" if "nrd" not in lead_sources else "in newly-registered-domain feed")
    plat = platform_of(host)
    if plat:
        add(4, "free hosting", plat)

    # --- page evidence (type B, and confirmation for type A)
    brand, conf = f.get("brand"), float(f.get("brand_confidence") or 0.0)
    if brand and conf >= 0.5:
        add(round(18 * min(1.0, conf)), "brand on page", f"{brand} ({conf:.2f})")
        if squat and squat.get("brand") == brand:
            add(5, "host and page agree", brand)
    if f.get("has_password_field"):
        add(10, "credential form", "password field present")
    if any(fm.get("external_action") for fm in f.get("forms") or []):
        add(4, "off-site form post", "form submits to another host")
    if kit_confidence and kit_confidence > 0:
        add(8, "kit match", f"confidence {kit_confidence:.2f}")
    if f.get("antibot"):
        add(4, "cloaking", ", ".join(map(str, f["antibot"]))[:80] if isinstance(f["antibot"], list) else "anti-bot markers")

    # --- liveness and corroboration
    if fetch_status == "ok":
        add(4, "live", "page answered when fetched")
    elif fetch_status == "blocked":
        add(2, "cloaked", "blocked the fetch (anti-bot or geo-fencing)")
    elif fetch_status == "offline":
        add(-10, "offline", "not reachable when fetched")
    feeds = sorted({x for x in lead_sources if x in ("openphish", "phishtank")} | ({source} if source in ("openphish", "phishtank") else set()))
    if feeds:
        add(6, "reported", "listed by " + " + ".join(feeds) + (" (community-verified)" if "phishtank" in feeds else ""))
    elif "phishing" in (source_tags or []):
        add(6, "reported", "tagged phishing on urlscan")
    if len(set(lead_sources)) > 1:
        add(3, "multi-source", "+".join(sorted(set(lead_sources))))

    score = max(0, min(100, sum(x["points"] for x in factors)))
    if squat:
        dtype = "typosquat"
    elif brand and conf >= 0.5:
        dtype = "content"
    else:
        dtype = "unattributed"
    return {"score": score, "tier": tier_for(score), "detection_type": dtype,
            "factors": sorted(factors, key=lambda x: -abs(x["points"]))}
