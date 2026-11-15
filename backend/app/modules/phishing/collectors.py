"""Candidate collectors for P4.

Sources (public, passive):
  * urlscan.io public search API (https://urlscan.io/docs/search/) - unauthenticated, 30 req/min per IP.
    With CTIOPS_URLSCAN_API_KEY the full result + DOM endpoints are used instead of visiting pages.
  * OpenPhish community feed (https://openphish.com/feed.txt -> GitHub raw mirror).
  * PhishTank verified-online dump (http://data.phishtank.com/data/online-valid.json), keyless.
Credit: urlscan.io GmbH, OpenPhish and PhishTank (Cisco Talos) for the data.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import tldextract

from ...config import PhishingScope, get_settings
from ..common.http import CachedClient, RateLimiter

log = logging.getLogger(__name__)

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
URLSCAN_DOM = "https://urlscan.io/dom/{uuid}/"
URLSCAN_SHOT = "https://urlscan.io/screenshots/{uuid}.png"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
PHISHTANK_FEED = "http://data.phishtank.com/data/online-valid.json"

# keyless: 30 req/min per IP; with a free API key: 120/min search and retrieve (we keep headroom)
_urlscan_rate = RateLimiter(100 if get_settings().urlscan_api_key else 28, 60.0)
_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


@dataclass
class Candidate:
    url: str
    source: str
    source_id: str | None = None
    first_seen: datetime | None = None
    tags: list[str] = field(default_factory=list)
    domain: str | None = None
    apex_domain: str | None = None
    ip: str | None = None
    asn: str | None = None
    asn_name: str | None = None
    country: str | None = None
    title: str | None = None
    screenshot_url: str | None = None
    brand_hint: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceStatus:
    status: str = "unknown"  # ok | degraded | down
    detail: str = ""
    fetched: int = 0
    requests: int = 0
    errors: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "detail": self.detail, "fetched": self.fetched,
                "requests": self.requests, "errors": self.errors}


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def split_host(url: str) -> tuple[str | None, str | None, str | None]:
    """(host, apex, tld) for a URL."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None, None, None
    if not host:
        return None, None, None
    ext = _extract(host)
    apex = ".".join(p for p in (ext.domain, ext.suffix) if p) or host
    return host.lower(), apex.lower(), (ext.suffix or "").lower() or None


def _brand_slug(brand: str) -> str:
    return re.sub(r"[^a-z0-9]", "", brand.lower())


def brand_queries(brand: str, days: int) -> list[str]:
    slug = _brand_slug(brand)
    # Leading wildcards / regexes need an account; anonymous search is limited to analysed-text queries.
    queries = [
        f'page.title:"{brand}" AND task.tags:phishing AND date:>now-{days}d',
        f"page.url:{slug} AND task.tags:phishing AND date:>now-{days}d",
        f'page.title:"{brand}" AND NOT page.domain:{slug}.com AND date:>now-{days}d',
    ]
    if get_settings().urlscan_api_key:
        queries.insert(1, f"page.domain:*{slug}* AND NOT page.domain:{slug}.com AND date:>now-{days}d")
    return queries


class UrlscanCollector:
    def __init__(self, scope: PhishingScope, log_fn=None) -> None:
        self.scope = scope
        self.settings = get_settings()
        self.client = CachedClient("urlscan", ttl=3600, rate=_urlscan_rate)
        self.status = SourceStatus()
        self._log = log_fn or (lambda m: log.info(m))
        self._consecutive_fail = 0
        self.tripped = False

    BREAKER = 3  # consecutive failed searches before we stop hitting urlscan for this run

    def _headers(self) -> dict[str, str] | None:
        return {"API-Key": self.settings.urlscan_api_key} if self.settings.urlscan_api_key else None

    def search(self, query: str, limit: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        search_after: str | None = None
        if self.tripped:
            return out
        while len(out) < limit:
            size = min(100, limit - len(out))
            url = f"{URLSCAN_SEARCH}?q={quote(query)}&size={size}"
            if search_after:
                url += f"&search_after={search_after}"
            self.status.requests += 1
            resp = self.client.get(url, headers=self._headers(), ttl=1800)
            if resp is None or resp.status_code != 200:
                self.status.errors += 1
                self._consecutive_fail += 1
                self._log(f"urlscan search failed ({resp.status_code if resp else 'no response'}): {query}")
                if self._consecutive_fail >= self.BREAKER:
                    # urlscan blocks IPs that exceed the keyless quota (connections are reset); hammering
                    # it only extends the block, so skip the remaining searches this run
                    self.tripped = True
                    self._log(f"urlscan: {self.BREAKER} failures in a row, skipping remaining searches this run "
                              "(likely keyless rate-limit block; a free CTIOPS_URLSCAN_API_KEY raises the quota)")
                break
            self._consecutive_fail = 0
            data = resp.json()
            results = data.get("results", [])
            out.extend(results)
            if not data.get("has_more") or not results:
                break
            sort = results[-1].get("sort")
            if not sort:
                break
            search_after = ",".join(str(s) for s in sort)
        return out

    @staticmethod
    def to_candidate(r: dict[str, Any], brand_hint: str | None) -> Candidate | None:
        task, page = r.get("task", {}), r.get("page", {})
        url = task.get("url") or page.get("url")
        if not url or not url.startswith("http"):
            return None
        uuid = task.get("uuid") or r.get("_id")
        host, apex, _ = split_host(url)
        return Candidate(
            url=url, source="urlscan", source_id=uuid, first_seen=parse_ts(task.get("time")),
            tags=list(task.get("tags") or []), domain=page.get("domain") or host,
            apex_domain=page.get("apexDomain") or apex, ip=page.get("ip"), asn=page.get("asn"),
            asn_name=page.get("asnname"), country=page.get("country"), title=page.get("title"),
            screenshot_url=URLSCAN_SHOT.format(uuid=uuid) if uuid else None, brand_hint=brand_hint,
            meta={"visibility": task.get("visibility"), "method": task.get("method"), "tlsIssuer": page.get("tlsIssuer"),
                  "server": page.get("server"), "domainAgeDays": page.get("domainAgeDays"),
                  "apexDomainAgeDays": page.get("apexDomainAgeDays")},
        )

    def collect(self) -> list[Candidate]:
        days = self.scope.window_days
        per_query = max(20, self.scope.max_samples // max(1, len(self.scope.brands) * 2))
        seen: dict[str, Candidate] = {}
        for brand in self.scope.brands:
            for q in brand_queries(brand, days)[: max(1, self.scope.urlscan_queries_per_brand)]:
                results = self.search(q, per_query)
                n = 0
                for r in results:
                    c = self.to_candidate(r, brand)
                    if c and c.url not in seen:
                        seen[c.url] = c
                        n += 1
                self._log(f"urlscan: {n} new candidates for '{brand}' via {q.split(' AND ')[0]}")
                if len(seen) >= self.scope.max_samples:
                    break
        # generic sweep to catch kits whose titles do not name the brand
        sweep_n = max(50, self.scope.max_samples // 4)
        for r in self.search(f"task.tags:phishing AND date:>now-{days}d", sweep_n):
            c = self.to_candidate(r, None)
            if c and c.url not in seen:
                seen[c.url] = c
        self._log(f"urlscan: {len(seen)} candidates total after generic sweep")
        self.status.fetched = len(seen)
        if self.status.requests and self.status.errors == 0:
            self.status.status = "ok"
        elif self.status.fetched:
            self.status.status = "degraded"
        else:
            self.status.status = "down"
        self.status.detail = f"{self.status.requests} search calls, {self.status.errors} errors, {len(seen)} candidates" + (" (stopped early: urlscan refusing connections)" if self.tripped else "")
        return list(seen.values())

    # ---- optional authenticated enrichment
    def fetch_result(self, uuid: str) -> dict[str, Any] | None:
        if not self.settings.urlscan_api_key:
            return None
        return self.client.get_json(URLSCAN_RESULT.format(uuid=uuid), headers=self._headers())

    def fetch_dom(self, uuid: str) -> str | None:
        if not self.settings.urlscan_api_key:
            return None
        resp = self.client.get(URLSCAN_DOM.format(uuid=uuid), headers=self._headers())
        return resp.text if resp is not None and resp.status_code == 200 else None


class OpenPhishCollector:
    def __init__(self, scope: PhishingScope, log_fn=None) -> None:
        self.scope = scope
        self.client = CachedClient("openphish", ttl=1800)
        self.status = SourceStatus()
        self._log = log_fn or (lambda m: log.info(m))

    def collect(self) -> list[Candidate]:
        self.status.requests = 1
        resp = self.client.get(OPENPHISH_FEED, ttl=1800)
        if resp is None or resp.status_code != 200:
            self.status.status, self.status.errors = "down", 1
            self.status.detail = f"feed unavailable ({resp.status_code if resp else 'no response'})"
            return []
        now = datetime.now(timezone.utc)
        brand_slugs = {_brand_slug(b): b for b in self.scope.brands}
        out: list[Candidate] = []
        for line in resp.text.splitlines():
            url = line.strip()
            if not url.startswith("http"):
                continue
            host, apex, _ = split_host(url)
            low = url.lower()
            hint = next((b for s, b in brand_slugs.items() if s in low), None)
            out.append(Candidate(url=url, source="openphish", first_seen=now, tags=["phishing"], domain=host,
                                 apex_domain=apex, brand_hint=hint))
        self.status.fetched = len(out)
        self.status.status = "ok" if out else "degraded"
        self.status.detail = f"{len(out)} URLs in current feed"
        self._log(f"openphish: {len(out)} URLs ({sum(1 for c in out if c.brand_hint)} match scope brands)")
        return out


class PhishTankCollector:
    """PhishTank verified-online dump (community-verified phish still online), keyless.

    Each entry carries the submission time (used for the window), the impersonated `target` brand and
    hosting details (IP, announcing network, country). PhishTank asks automated clients to identify
    themselves with a `phishtank/<name>` User-Agent and rate-limits keyless dump downloads: past the
    limit the dump URL redirects to a 404 error image. So the last good dump is kept on disk, refetched
    at most once per REFRESH, and reused (up to MAX_STALE old) whenever PhishTank refuses.
    """

    REFRESH = 3600          # seconds between download attempts
    MAX_STALE = 24 * 3600   # oldest saved dump still used when a download is refused

    def __init__(self, scope: PhishingScope, log_fn=None) -> None:
        self.scope = scope
        self.client = CachedClient("phishtank", ttl=0)  # own on-disk copy below, see class doc
        self.client.client.headers["User-Agent"] = "phishtank/ctiops-research"
        self.client.client.timeout = 120.0
        self.status = SourceStatus()
        self._log = log_fn or (lambda m: log.info(m))
        self.path = get_settings().cache_dir / "phishtank" / "online-valid.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> tuple[list | None, str]:
        """(entries, provenance). Download when the saved copy is older than REFRESH, else reuse it."""
        import json
        import time
        age = time.time() - self.path.stat().st_mtime if self.path.exists() else None
        if age is None or age >= self.REFRESH:
            self.status.requests = 1
            resp = self.client.get(PHISHTANK_FEED, retries=1, ttl=0)
            ok = resp is not None and resp.status_code == 200 and "json" in resp.headers.get("content-type", "")
            if ok:
                try:
                    data = resp.json()
                    tmp = self.path.with_suffix(".tmp")
                    tmp.write_bytes(resp.content)
                    tmp.replace(self.path)
                    return data, "downloaded now"
                except ValueError:
                    pass
            self.status.errors = 1
            reason = f"HTTP {resp.status_code} {resp.headers.get('content-type', '')}" if resp is not None else "no response"
            self._log(f"phishtank: download refused ({reason}; keyless rate limit)")
            if age is None or age > self.MAX_STALE:
                return None, reason
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return data, f"saved copy from {round((time.time() - self.path.stat().st_mtime) / 60)} min ago"

    @staticmethod
    def _brand(target: str | None, url: str, brand_slugs: dict[str, str]) -> str | None:
        t = _brand_slug(target or "")
        if t and t != "other":
            for slug, brand in brand_slugs.items():
                if slug in t or (len(t) >= 4 and t in slug):
                    return brand
        low = url.lower()
        return next((b for s, b in brand_slugs.items() if s in low), None)

    def collect(self) -> list[Candidate]:
        data, provenance = self._load()
        if not isinstance(data, list):
            self.status.status, self.status.errors = "down", 1
            self.status.detail = f"dump unavailable ({provenance}) and no saved copy from the last 24h"
            self._log("phishtank: dump unavailable, no recent saved copy")
            return []
        cutoff = datetime.now(timezone.utc).timestamp() - self.scope.window_days * 86400
        brand_slugs = {_brand_slug(b): b for b in self.scope.brands}
        out: list[Candidate] = []
        for r in data:
            url = (r.get("url") or "").strip()
            seen = parse_ts(r.get("submission_time"))
            if not url.startswith("http") or not seen or seen.timestamp() < cutoff:
                continue
            host, apex, _ = split_host(url)
            det = (r.get("details") or [{}])[0] or {}
            target = r.get("target")
            out.append(Candidate(
                url=url, source="phishtank", first_seen=seen, tags=["phishing", "phishtank-verified"], domain=host,
                apex_domain=apex, ip=det.get("ip_address") or None, asn=str(det["announcing_network"]) if det.get("announcing_network") else None,
                country=det.get("country") or None, brand_hint=self._brand(target, url, brand_slugs),
                meta={"phish_id": r.get("phish_id"), "phishtank_target": target, "phish_detail_url": r.get("phish_detail_url"),
                      "verified_at": r.get("verification_time")}))
        self.status.fetched = len(out)
        self.status.status = "ok" if provenance == "downloaded now" else "degraded"
        self.status.detail = f"{len(data):,} verified-online in dump ({provenance}), {len(out)} submitted in the last {self.scope.window_days}d"
        self._log(f"phishtank: {len(out)} verified phish in window ({sum(1 for c in out if c.brand_hint)} match scope brands)")
        return out
