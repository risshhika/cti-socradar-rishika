"""SQLModel tables shared by both modules. JSON columns hold flexible analyst-facing payloads."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Column, Text
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- platform


class PipelineRun(SQLModel, table=True):
    __tablename__ = "pipeline_runs"

    id: int | None = Field(default=None, primary_key=True)
    pipeline: str = Field(index=True)  # phishing | landscape
    status: str = Field(default="queued", index=True)  # queued | running | succeeded | failed
    trigger: str = Field(default="manual")  # manual | cli | schedule
    params: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    summary: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    log: str = Field(default="", sa_column=Column(Text))
    error: str | None = Field(default=None, sa_column=Column(Text))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)


class AnalystReview(SQLModel, table=True):
    """Hand-check verdicts: did the automation agree, miss, or over-flag?"""

    __tablename__ = "analyst_reviews"

    id: int | None = Field(default=None, primary_key=True)
    entity_type: str = Field(index=True)  # campaign | sample | kit | victim | actor | iab | briefing
    entity_id: int = Field(index=True)
    verdict: str  # agree | miss | over_flag | unsure
    note: str | None = Field(default=None, sa_column=Column(Text))
    reviewer: str = "analyst"
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- P4 phishing


class PhishKit(SQLModel, table=True):
    __tablename__ = "phish_kits"

    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(index=True, unique=True)
    name: str
    family: str | None = None
    description: str | None = Field(default=None, sa_column=Column(Text))
    source: str = "signature"  # signature | inferred
    markers: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    sample_count: int = 0
    campaign_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    references: list[str] = Field(default_factory=list, sa_column=Column(JSON))


class PhishCampaign(SQLModel, table=True):
    __tablename__ = "phish_campaigns"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)  # CAMP-2026-11-001
    brand: str | None = Field(default=None, index=True)
    sector: str | None = None
    status: str = Field(default="active", index=True)  # active | dormant
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sample_count: int = 0
    domain_count: int = 0
    ip_count: int = 0
    cohesion: float = 0.0  # 0..1 mean intra-cluster similarity
    kit_id: int | None = Field(default=None, foreign_key="phish_kits.id", index=True)
    kit_confidence: float = 0.0
    cluster_method: str = "structural"  # structural | dbscan | singleton
    summary: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    # summary keys: top_tlds, top_asns, top_countries, top_paths, shared_markers, title_examples,
    #               form_actions, exfil_endpoints, takedown_targets
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class PhishSample(SQLModel, table=True):
    __tablename__ = "phish_samples"

    id: int | None = Field(default=None, primary_key=True)
    url: str = Field(index=True)
    final_url: str | None = None
    domain: str | None = Field(default=None, index=True)
    apex_domain: str | None = Field(default=None, index=True)
    ip: str | None = Field(default=None, index=True)
    asn: str | None = None
    asn_name: str | None = None
    country: str | None = None
    tld: str | None = None
    source: str = Field(index=True)  # urlscan | openphish
    source_id: str | None = Field(default=None, index=True)  # urlscan uuid
    source_tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    first_seen: datetime | None = Field(default=None, index=True)
    fetched_at: datetime | None = None
    fetch_status: str = "pending"  # pending | ok | offline | blocked | error | skipped
    http_status: int | None = None
    title: str | None = None
    brand: str | None = Field(default=None, index=True)
    brand_confidence: float = 0.0
    html_sha256: str | None = Field(default=None, index=True)
    html_size: int | None = None
    html_path: str | None = None  # relative path under data/artifacts
    screenshot_url: str | None = None
    struct_hash: str | None = Field(default=None, index=True)  # simhash of DOM tag sequence
    features: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    # features keys: forms, inputs, form_actions, scripts, script_hosts, favicon_hash, text_tokens,
    #                kit_markers, obfuscation, redirects, meta, dom_depth, tag_count
    campaign_id: int | None = Field(default=None, foreign_key="phish_campaigns.id", index=True)
    kit_id: int | None = Field(default=None, foreign_key="phish_kits.id", index=True)
    kit_confidence: float = 0.0
    created_at: datetime = Field(default_factory=utcnow)


class Detection(SQLModel, table=True):
    __tablename__ = "detections"

    id: int | None = Field(default=None, primary_key=True)
    campaign_id: int | None = Field(default=None, foreign_key="phish_campaigns.id", index=True)
    kit_id: int | None = Field(default=None, foreign_key="phish_kits.id", index=True)
    type: str = Field(index=True)  # sigma | yara | url_regex | ioc_domain | ioc_ip | ioc_url | snort
    target: str = "web_gateway"  # mail_gateway | web_gateway | siem | edr
    title: str
    content: str = Field(sa_column=Column(Text))
    confidence: str = "medium"  # low | medium | high
    false_positive_notes: str | None = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- P6 landscape


class RansomVictim(SQLModel, table=True):
    __tablename__ = "ransom_victims"

    id: int | None = Field(default=None, primary_key=True)
    source: str = Field(index=True)  # ransomware_live | ransomwatch
    source_id: str = Field(index=True, unique=True)
    victim: str = Field(index=True)
    domain: str | None = Field(default=None, index=True)
    group: str = Field(index=True)
    attack_date: datetime | None = Field(default=None, index=True)
    discovered: datetime | None = Field(default=None, index=True)
    month: str | None = Field(default=None, index=True)  # YYYY-MM (attack_date or discovered)
    country: str | None = Field(default=None, index=True)
    region: str | None = Field(default=None, index=True)
    sector_raw: str | None = None
    sector: str | None = Field(default=None, index=True)
    sector_method: str = "source"  # source | keyword | llm | unknown
    size_band: str = Field(default="unknown", index=True)  # small | mid | large | enterprise | unknown
    size_basis: str | None = None
    description: str | None = Field(default=None, sa_column=Column(Text))
    data_size: str | None = None
    ransom_demand: str | None = None
    press: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    url: str | None = None
    in_scope: bool = Field(default=False, index=True)  # matches configured sector AND region
    cross_source_match: bool = False  # found in both aggregators
    created_at: datetime = Field(default_factory=utcnow)


class ThreatActor(SQLModel, table=True):
    __tablename__ = "threat_actors"

    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(index=True, unique=True)
    name: str
    aliases: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    description: str | None = Field(default=None, sa_column=Column(Text))
    status: str = Field(default="active", index=True)  # active | dormant | unknown
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    victim_count_total: int = 0
    victim_count_scope: int = 0
    victim_count_window: int = 0  # within configured months
    monthly_counts: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    monthly_counts_scope: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    top_sectors: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    top_countries: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    ttps: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    tools: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    locations: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    profile_url: str | None = None
    updated_at: datetime = Field(default_factory=utcnow)


class IABListing(SQLModel, table=True):
    """Initial-access-broker activity extracted from public reporting."""

    __tablename__ = "iab_listings"

    id: int | None = Field(default=None, primary_key=True)
    source: str = Field(index=True)  # feed/site name
    source_url: str = Field(index=True, unique=True)
    published: datetime | None = Field(default=None, index=True)
    month: str | None = Field(default=None, index=True)
    title: str
    summary: str | None = Field(default=None, sa_column=Column(Text))
    excerpt: str | None = Field(default=None, sa_column=Column(Text))
    access_types: list[str] = Field(default_factory=list, sa_column=Column(JSON))  # RDP, VPN, Citrix, ...
    price_usd_min: float | None = None
    price_usd_max: float | None = None
    revenue_usd: float | None = None
    countries: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    region: str | None = Field(default=None, index=True)
    sectors: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    brokers: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    actors: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    relevance: float = 0.0  # 0..1 how strongly the article is about IAB activity
    extraction_method: str = "regex"  # regex | llm
    in_scope: bool = Field(default=False, index=True)
    created_at: datetime = Field(default_factory=utcnow)


class CyberIncident(SQLModel, table=True):
    """Public breach / cyberattack reporting (ransomware.live cyberattacks feed)."""

    __tablename__ = "cyber_incidents"

    id: int | None = Field(default=None, primary_key=True)
    source_id: str = Field(index=True, unique=True)
    date: datetime | None = Field(default=None, index=True)
    month: str | None = Field(default=None, index=True)
    title: str
    summary: str | None = Field(default=None, sa_column=Column(Text))
    domain: str | None = None
    country: str | None = Field(default=None, index=True)
    region: str | None = Field(default=None, index=True)
    sector: str | None = Field(default=None, index=True)
    actor: str | None = None
    link: str | None = None
    in_scope: bool = Field(default=False, index=True)


class Briefing(SQLModel, table=True):
    __tablename__ = "briefings"

    id: int | None = Field(default=None, primary_key=True)
    period: str = Field(index=True)  # YYYY-MM
    sector: str
    region: str
    title: str
    markdown: str = Field(sa_column=Column(Text))
    stats: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    generator: str = "template"  # template | llm
    status: str = "draft"  # draft | final
    generated_at: datetime = Field(default_factory=utcnow)
