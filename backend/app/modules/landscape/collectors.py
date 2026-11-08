"""Public-source collectors for P6.

Data credits:
  * ransomware.live (Julien Mousqueton) — https://www.ransomware.live  (API v2, CC BY-NC-SA)
  * ransomwatch (joshhighet) — https://github.com/joshhighet/ransomwatch (posts.json; archive stops mid-2025)
  * RansomLook — https://www.ransomlook.io (api/recent/N, actively maintained ransomwatch fork)
Passive collection only: aggregator APIs and public RSS feeds. No leak sites are contacted.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import date, datetime, timezone
from typing import Any

from dateutil import parser as dtparse

from ..common.http import CachedClient, RateLimiter

log = logging.getLogger(__name__)

RL_BASE = "https://api.ransomware.live/v2"
RANSOMWATCH_POSTS = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
RANSOMLOOK_RECENT = "https://www.ransomlook.io/api/recent/{n}"

_rl_rate = RateLimiter(rate=1, per=1.0)


def rl_client(ttl: int | None = None) -> CachedClient:
    return CachedClient("ransomware_live", ttl=ttl, rate=_rl_rate)


def parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = dtparse.parse(str(value))
        except (ValueError, OverflowError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def month_key(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m") if dt else None


def months_back(n: int, today: date | None = None) -> list[str]:
    """Return the last n months as YYYY-MM, oldest first, including the current month."""
    today = today or datetime.now(timezone.utc).date()
    y, m = today.year, today.month
    out = []
    for _ in range(n):
        out.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return list(reversed(out))


def stable_id(*parts: str) -> str:
    return hashlib.sha1("|".join(p or "" for p in parts).encode()).hexdigest()[:24]


class SourceStatus:
    def __init__(self) -> None:
        self.data: dict[str, dict[str, Any]] = {}

    def set(self, name: str, status: str, detail: str) -> None:
        self.data[name] = {"status": status, "detail": detail}


# --------------------------------------------------------------------------- ransomware.live

def fetch_victims_month(client: CachedClient, ym: str, fresh: bool = False) -> list[dict[str, Any]] | None:
    y, m = ym.split("-")
    # current month changes constantly -> short TTL
    ttl = 900 if fresh else None
    data = client.get_json(f"{RL_BASE}/victims/{y}/{int(m)}", ttl=ttl)
    if data is None:
        return None
    return data if isinstance(data, list) else []


def fetch_recent_victims(client: CachedClient) -> list[dict[str, Any]]:
    return client.get_json(f"{RL_BASE}/recentvictims", ttl=600) or []


def fetch_groups(client: CachedClient) -> list[dict[str, Any]] | None:
    data = client.get_json(f"{RL_BASE}/groups")
    return data if isinstance(data, list) else None


def fetch_sectors(client: CachedClient) -> dict[str, int]:
    data = client.get_json(f"{RL_BASE}/sectors")
    return data if isinstance(data, dict) else {}


def fetch_cyberattacks(client: CachedClient) -> list[dict[str, Any]]:
    data = client.get_json(f"{RL_BASE}/recentcyberattacks", ttl=1800)
    return data if isinstance(data, list) else []


def victim_source_id(v: dict[str, Any]) -> str:
    url = (v.get("url") or "").strip()
    if url:
        return url
    return "rl:" + stable_id(v.get("victim", ""), v.get("group", ""), str(v.get("attackdate") or v.get("discovered") or ""))


# --------------------------------------------------------------------------- ransomwatch

def fetch_ransomwatch_posts() -> list[dict[str, Any]] | None:
    client = CachedClient("ransomwatch")
    data = client.get_json(RANSOMWATCH_POSTS)
    return data if isinstance(data, list) else None


def fetch_ransomlook_posts(n: int = 6000) -> list[dict[str, Any]] | None:
    """RansomLook recent posts (post_title, group_name, discovered, description). Tries large N first."""
    client = CachedClient("ransomlook", ttl=1800)
    for size in (n, 2000, 500):
        data = client.get_json(RANSOMLOOK_RECENT.format(n=size))
        if isinstance(data, list) and data:
            return data
    return None
