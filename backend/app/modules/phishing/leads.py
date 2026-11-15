"""Domain leads for P4: brand typosquats found *before* anyone reports them as phishing.

Source (public, passive -- no connection to the suspicious domains is made here):
  * WhoisDS free daily newly-registered-domain (NRD) lists, ~70k domains/day, last N days.
    https://www.whoisds.com/newly-registered-domains
Every name is run through typosquat.match_host; only matches become leads. The pipeline then
promotes the strongest leads to phishing samples, where they are fetched like any other candidate.
Typosquat hostnames reported by urlscan / OpenPhish / PhishTank become leads too (see pipeline.rank_all).
Credit: WhoisDS.com.
"""
from __future__ import annotations

import base64
import io
import logging
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

import httpx

from ...config import get_settings
from .dedupe import canonical_host
from .typosquat import BrandSpec, SquatMatch, match_host

log = logging.getLogger(__name__)

WHOISDS_URL = "https://www.whoisds.com/whois-database/newly-registered-domains/{token}/nrd"


@dataclass
class Lead:
    domain: str
    source: str                 # nrd
    match: SquatMatch
    first_seen: datetime
    meta: dict = field(default_factory=dict)


@dataclass
class LeadStatus:
    status: str = "unknown"
    detail: str = ""
    scanned: int = 0
    matched: int = 0
    errors: int = 0

    def as_dict(self) -> dict:
        return {"status": self.status, "detail": self.detail, "fetched": self.matched, "scanned": self.scanned,
                "errors": self.errors}


def _client(timeout: float = 90.0) -> httpx.Client:
    s = get_settings()
    return httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": s.user_agent})


# --------------------------------------------------------------------------- NRD (WhoisDS)

class NRDCollector:
    """Daily newly-registered-domain lists. Past days never change, so each day is cached forever."""

    def __init__(self, specs: list[BrandSpec], days: int, log_fn=None) -> None:
        self.specs, self.days = specs, days
        self.status = LeadStatus()
        self._log = log_fn or (lambda m: log.info(m))
        self.dir = get_settings().cache_dir / "whoisds"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _day_domains(self, day: date, http: httpx.Client) -> list[str] | None:
        path = self.dir / f"{day.isoformat()}.txt"
        if path.exists() and path.stat().st_size > 0:
            return path.read_text(encoding="utf-8").split()
        token = base64.b64encode(f"{day.isoformat()}.zip".encode()).decode()
        try:
            resp = http.get(WHOISDS_URL.format(token=token))
        except httpx.HTTPError as exc:
            self._log(f"nrd {day}: download failed ({type(exc).__name__})")
            return None
        if resp.status_code != 200 or not resp.content.startswith(b"PK"):
            self._log(f"nrd {day}: not available (HTTP {resp.status_code})")
            return None
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            names = z.read(z.namelist()[0]).decode("utf-8", "replace").split()
        path.write_text("\n".join(names), encoding="utf-8")
        return names

    def collect(self) -> list[Lead]:
        today = datetime.now(timezone.utc).date()
        out: list[Lead] = []
        days_ok = 0
        with _client() as http:
            for back in range(1, self.days + 1):  # the list for day D is published on D+1
                day = today - timedelta(days=back)
                names = self._day_domains(day, http)
                if names is None:
                    self.status.errors += 1
                    continue
                days_ok += 1
                self.status.scanned += len(names)
                seen_at = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
                n = 0
                for d in names:
                    m = match_host(d, self.specs)
                    if m:
                        out.append(Lead(domain=canonical_host(d), source="nrd", match=m, first_seen=seen_at,
                                        meta={"registered": day.isoformat()}))
                        n += 1
                self._log(f"nrd {day}: {len(names):,} new domains, {n} brand matches")
        self.status.matched = len(out)
        self.status.status = "ok" if days_ok == self.days else "degraded" if days_ok else "down"
        self.status.detail = f"{days_ok}/{self.days} days, {self.status.scanned:,} domains scanned, {len(out)} matches"
        return out
