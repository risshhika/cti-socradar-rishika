"""Shared HTTP client with on-disk caching, retries and polite rate limiting."""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from ...config import get_settings

log = logging.getLogger(__name__)


class RateLimiter:
    """Simple token bucket: at most `rate` calls per `per` seconds (thread-safe)."""

    def __init__(self, rate: int, per: float) -> None:
        self.rate, self.per = rate, per
        self._lock = threading.Lock()
        self._calls: list[float] = []

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._calls = [t for t in self._calls if now - t < self.per]
            if len(self._calls) >= self.rate:
                sleep_for = self.per - (now - self._calls[0]) + 0.05
                time.sleep(max(sleep_for, 0))
            self._calls.append(time.monotonic())


class CachedClient:
    """GET with disk cache keyed on URL+headers. `ttl=0` bypasses cache."""

    def __init__(self, namespace: str, ttl: int | None = None, rate: RateLimiter | None = None) -> None:
        s = get_settings()
        self.ttl = s.cache_ttl_seconds if ttl is None else ttl
        self.dir = s.cache_dir / namespace
        self.dir.mkdir(parents=True, exist_ok=True)
        self.rate = rate
        self.client = httpx.Client(
            timeout=s.http_timeout,
            follow_redirects=True,
            headers={"User-Agent": s.user_agent, "Accept": "*/*"},
        )

    def _key(self, url: str, headers: dict[str, str] | None) -> Path:
        h = hashlib.sha256((url + json.dumps(headers or {}, sort_keys=True)).encode()).hexdigest()[:32]
        return self.dir / f"{h}.json"

    def get(self, url: str, headers: dict[str, str] | None = None, retries: int = 3,
            ttl: int | None = None) -> httpx.Response | None:
        ttl = self.ttl if ttl is None else ttl
        path = self._key(url, headers)
        if ttl and path.exists() and time.time() - path.stat().st_mtime < ttl:
            try:
                cached = json.loads(path.read_text())
                return httpx.Response(cached["status"], content=cached["body"].encode("utf-8", "surrogatepass"),
                                      headers=cached.get("headers", {}), request=httpx.Request("GET", url))
            except Exception:  # corrupt cache -> refetch
                path.unlink(missing_ok=True)
        backoff = 1.5
        for attempt in range(retries):
            try:
                if self.rate:
                    self.rate.wait()
                resp = self.client.get(url, headers=headers)
                if resp.status_code == 429 or resp.status_code >= 500:
                    retry_after = float(resp.headers.get("retry-after", backoff))
                    log.warning("%s -> %s, retrying in %.1fs", url, resp.status_code, retry_after)
                    time.sleep(min(retry_after, 30))
                    backoff *= 2
                    continue
                if ttl and resp.status_code == 200:
                    path.write_text(json.dumps({"status": resp.status_code, "body": resp.text,
                                                "headers": {"content-type": resp.headers.get("content-type", "")}}))
                return resp
            except httpx.HTTPError as exc:
                log.warning("%s attempt %d failed: %s", url, attempt + 1, exc)
                time.sleep(backoff)
                backoff *= 2
        return None

    def get_json(self, url: str, **kw: Any) -> Any | None:
        resp = self.get(url, **kw)
        if resp is None or resp.status_code != 200:
            return None
        try:
            return resp.json()
        except ValueError:
            return None
