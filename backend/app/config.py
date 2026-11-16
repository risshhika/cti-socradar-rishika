from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Process-level settings (env / .env). Analyst scope lives in config/scope.yaml."""

    model_config = SettingsConfigDict(env_file=REPO_ROOT / ".env", env_prefix="CTIOPS_", extra="ignore")

    data_dir: Path = REPO_ROOT / "data"
    scope_file: Path = REPO_ROOT / "config" / "scope.yaml"
    frontend_dist: Path = REPO_ROOT / "frontend" / "dist"
    database_url: str | None = None
    urlscan_api_key: str | None = None
    anthropic_api_key: str | None = None
    x_bearer_token: str | None = None  # X API v2 app bearer token (recent search), CTIOPS_X_BEARER_TOKEN
    # Wikidata and SEC EDGAR refuse automated clients without a contact User-Agent, e.g.
    # "ctiops-research/0.1 (you@example.org)". Those two lookups are skipped until it is set; GLEIF needs nothing.
    registry_user_agent: str | None = None
    zoominfo_username: str | None = None  # optional ZoomInfo Enrich + Search API (enterprise); free registries otherwise
    zoominfo_password: str | None = None
    # Shodan API key (CTIOPS_SHODAN_API_KEY): passive read of Shodan's host database to see which exposed
    # endpoint runs a named product (e.g. Pulse Secure) for victim identification. We never connect to a host.
    shodan_api_key: str | None = None
    report_reporter: str = ""  # CTIOPS_REPORT_REPORTER: author name on client reports (set by `cli setup`)
    anthropic_model: str = "claude-sonnet-5-5"
    http_timeout: float = 20.0
    cache_ttl_seconds: int = 6 * 3600
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{self.data_dir / 'ctiops.db'}"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    s.cache_dir.mkdir(parents=True, exist_ok=True)
    s.artifacts_dir.mkdir(parents=True, exist_ok=True)
    return s


class PhishingScope(BaseModel):
    sector: str = "Financial services & payments"
    brands: list[str] = Field(default_factory=lambda: ["PayPal", "Chase", "HSBC"])
    # One ingestion window for every source (WhoisDS NRD, urlscan, OpenPhish, PhishTank) and the retention
    # limit: data older than this is pruned at the start of each run.
    days_back: int = 7
    max_samples: int = 400
    urlscan_queries_per_brand: int = 2
    report_reporter: str = ""  # name on the cover of client reports
    # typosquat leads from WhoisDS newly-registered domains, see modules/phishing/typosquat.py
    max_leads_promoted: int = 80  # strongest leads fetched as samples, on top of max_samples
    brand_fragments: dict[str, list[str]] = Field(default_factory=dict)   # PayPal: [pay, pal] -> pay*pal*
    brand_domains: dict[str, list[str]] = Field(default_factory=dict)     # official domains, never flagged
    brand_exclusions: dict[str, list[str]] = Field(default_factory=dict)  # ordinary words containing the brand

    @property
    def window_days(self) -> int:
        return max(1, self.days_back)


class LandscapeScope(BaseModel):
    sector: str = "Healthcare"
    region: str = "Europe"
    months: int = 6
    iab_feeds: list[str] = Field(default_factory=list)
    # X (Twitter) IAB monitor: recent-search queries (7-day window on the X API), run for these sectors only
    x_queries: list[dict[str, str]] = Field(default_factory=list)  # {label, query}
    x_accounts: list[str] = Field(default_factory=list)  # watched handles: everything they post, sector-filtered
    x_sectors: list[str] = Field(default_factory=lambda: ["Financial Services"])
    x_max_pages: int = 2  # 100 posts per page, per query, per run (X API read quota)


class Scope(BaseModel):
    phishing: PhishingScope = Field(default_factory=PhishingScope)
    landscape: LandscapeScope = Field(default_factory=LandscapeScope)


def load_scope() -> Scope:
    path = get_settings().scope_file
    if not path.exists():
        return Scope()
    with path.open() as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}
    return Scope.model_validate(raw)


def save_scope(scope: Scope) -> None:
    path = get_settings().scope_file
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        yaml.safe_dump(scope.model_dump(), fh, sort_keys=False, allow_unicode=True)
