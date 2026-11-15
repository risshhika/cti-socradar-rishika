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
    # threat rank (modules/phishing/rank.py): typosquat (type A) | content (type B) | unattributed
    detection_type: str | None = Field(default=None, index=True)
    threat_score: int = Field(default=0, index=True)
    threat_tier: str | None = Field(default=None, index=True)  # critical | high | medium | low
    squat: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))  # hostname match evidence
    rank_factors: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    # de-duplication (modules/phishing/dedupe.py): one sample per page, every reporting source kept
    dedup_key: str | None = Field(default=None, index=True)  # canonical URL
    sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))  # urlscan | openphish | nrd | ct
    duplicate_urls: list[str] = Field(default_factory=list, sa_column=Column(JSON))  # merged alternate URLs
    duplicate_count: int = 0  # how many other reports were merged into this sample
    created_at: datetime = Field(default_factory=utcnow)


class DomainLead(SQLModel, table=True):
    """A brand-typosquat hostname seen in newly-registered-domain lists or CT logs, before (or without)
    any phishing report. Strong leads are promoted to PhishSample and fetched."""
    __tablename__ = "domain_leads"

    id: int | None = Field(default=None, primary_key=True)
    domain: str = Field(index=True, unique=True)
    brand: str = Field(index=True)
    match_kind: str = Field(index=True)  # embed | homoglyph | fragment | typo
    match_score: float = 0.0
    evidence: str | None = None
    lure_words: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))  # nrd | ct | urlscan | openphish
    first_seen: datetime | None = Field(default=None, index=True)
    last_seen: datetime | None = None
    meta: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))  # registered date, cert issuer/id
    status: str = Field(default="new", index=True)  # new | promoted | live | offline | blocked
    sample_id: int | None = Field(default=None, foreign_key="phish_samples.id", index=True)
    threat_score: int = Field(default=0, index=True)
    threat_tier: str | None = Field(default=None, index=True)
    rank_factors: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
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


# --------------------------------------------------------------------------- P6: X (Twitter) IAB monitor

class XPost(SQLModel, table=True):
    """A public X post matched by one of the IAB monitor queries, with preserved evidence."""

    __tablename__ = "x_posts"

    id: int | None = Field(default=None, primary_key=True)
    tweet_id: str = Field(index=True, unique=True)
    url: str
    author_id: str | None = None
    author_handle: str | None = Field(default=None, index=True)
    author_name: str | None = None
    created_at: datetime | None = Field(default=None, index=True)
    lang: str | None = None
    text: str = Field(sa_column=Column(Text))
    queries: list[str] = Field(default_factory=list, sa_column=Column(JSON))  # labels of every query that matched
    links: list[str] = Field(default_factory=list, sa_column=Column(JSON))  # expanded URLs in the post
    media: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))  # key, type, url, path, sha256, alt
    metrics: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    # evidence: raw API record + rendered post card, both hashed at capture time
    raw_path: str | None = None
    raw_sha256: str | None = None
    card_path: str | None = None
    card_sha256: str | None = None
    shot_path: str | None = None  # screenshot of the post as shown on x.com (browser capture)
    shot_sha256: str | None = None
    capture_method: str = "api"  # api | browser
    captured_at: datetime = Field(default_factory=utcnow)
    # extraction
    financial_terms: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    fin_subtype: str | None = Field(default=None, index=True)  # Bank | Credit union | Insurance | Payments | ...
    access_types: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    price_usd_min: float | None = None
    price_usd_max: float | None = None
    claimed_revenue_usd: float | None = None
    countries: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    forums: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    tech: list[str] = Field(default_factory=list, sa_column=Column(JSON))  # named products (Pulse Secure, Citrix, ...)
    host_count: int | None = None  # "~10,000+ hosts" claimed in the listing
    victim_candidates: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    relevance: float = 0.0
    # victim: auto-picked candidate or analyst-confirmed name, linked to company data
    victim_name: str | None = Field(default=None, index=True)
    victim_confirmed: bool = False
    org_id: int | None = Field(default=None, foreign_key="organizations.id", index=True)
    status: str = Field(default="new", index=True)  # new | relevant | noise


class Organization(SQLModel, table=True):
    """Company firmographics (revenue, employees, industry) from public registries, cached per name."""

    __tablename__ = "organizations"

    id: int | None = Field(default=None, primary_key=True)
    name_key: str = Field(index=True, unique=True)  # classify.normalize_name of the queried name
    query_name: str
    legal_name: str | None = None
    website: str | None = None
    country: str | None = None
    industry: str | None = None
    industry_codes: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    fin_subtype: str | None = Field(default=None, index=True)
    revenue_usd: float | None = None
    revenue_year: int | None = None
    revenue_band: str | None = Field(default=None, index=True)
    employees: int | None = None
    employees_year: int | None = None
    employee_band: str | None = Field(default=None, index=True)
    identifiers: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))  # wikidata, cik, lei, ticker
    sources: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))  # {source, url, fields, fetched}
    match_score: float = 0.0
    status: str = "ok"  # ok | not_found | ambiguous
    fetched_at: datetime = Field(default_factory=utcnow)
