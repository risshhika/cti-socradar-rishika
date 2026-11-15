"""API response/request schemas. The frontend's src/lib/types.ts mirrors these 1:1."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .config import Scope


class Page(BaseModel):
    page: int = 1
    size: int = 50
    total: int = 0


class KeyCount(BaseModel):
    key: str
    count: int
    share: float | None = None


class TimePoint(BaseModel):
    period: str  # ISO date or YYYY-MM
    value: int
    secondary: int | None = None  # e.g. in-scope count


# --------------------------------------------------------------------------- platform

class RunOut(BaseModel):
    id: int
    pipeline: str
    status: str
    trigger: str
    params: dict[str, Any]
    summary: dict[str, Any]
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    duration_seconds: float | None = None


class RunDetail(RunOut):
    log: str


class TriggerRunRequest(BaseModel):
    params: dict[str, Any] = Field(default_factory=dict)


class ReviewIn(BaseModel):
    entity_type: str
    entity_id: int
    verdict: str
    note: str | None = None
    reviewer: str = "analyst"


class ReviewOut(ReviewIn):
    id: int
    created_at: datetime


class ReviewSummary(BaseModel):
    entity_type: str
    reviewed: int
    agree: int
    miss: int
    over_flag: int
    unsure: int
    precision_proxy: float | None  # agree / (agree + over_flag)


class SourceHealth(BaseModel):
    name: str
    module: str
    status: str  # ok | degraded | down | unknown
    detail: str | None = None
    checked_at: datetime | None = None


class OverviewOut(BaseModel):
    scope: Scope
    phishing: dict[str, Any]  # kpis: samples, campaigns, kits, detections, brands, last_run
    landscape: dict[str, Any]  # kpis: victims_total, victims_scope, actors_active, iab_listings, briefings
    recent_runs: list[RunOut]
    reviews: list[ReviewSummary]
    sources: list[SourceHealth]


# --------------------------------------------------------------------------- P4

class KitOut(BaseModel):
    id: int
    slug: str
    name: str
    family: str | None
    description: str | None
    source: str
    markers: list[dict[str, Any]]
    sample_count: int
    campaign_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    references: list[str]


class CampaignOut(BaseModel):
    id: int
    name: str
    brand: str | None
    sector: str | None
    status: str
    first_seen: datetime | None
    last_seen: datetime | None
    sample_count: int
    domain_count: int
    ip_count: int
    cohesion: float
    kit_id: int | None
    kit_name: str | None = None
    kit_confidence: float
    cluster_method: str
    summary: dict[str, Any]
    detection_count: int = 0
    review_verdict: str | None = None


class SampleOut(BaseModel):
    id: int
    url: str
    final_url: str | None
    domain: str | None
    apex_domain: str | None
    ip: str | None
    asn: str | None
    asn_name: str | None
    country: str | None
    tld: str | None
    source: str
    source_id: str | None
    source_tags: list[str]
    first_seen: datetime | None
    fetched_at: datetime | None
    fetch_status: str
    http_status: int | None
    title: str | None
    brand: str | None
    brand_confidence: float
    html_sha256: str | None
    html_size: int | None
    screenshot_url: str | None
    struct_hash: str | None
    features: dict[str, Any]
    campaign_id: int | None
    campaign_name: str | None = None
    kit_id: int | None
    kit_name: str | None = None
    kit_confidence: float
    review_verdict: str | None = None
    detection_type: str | None = None
    threat_score: int = 0
    threat_tier: str | None = None
    squat: dict[str, Any] | None = None
    rank_factors: list[dict[str, Any]] = Field(default_factory=list)
    dedup_key: str | None = None
    sources: list[str] = Field(default_factory=list)
    duplicate_urls: list[str] = Field(default_factory=list)
    duplicate_count: int = 0


class LeadOut(BaseModel):
    id: int
    domain: str
    brand: str
    match_kind: str
    match_score: float
    evidence: str | None
    lure_words: list[str]
    sources: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    meta: dict[str, Any]
    status: str
    sample_id: int | None
    threat_score: int
    threat_tier: str | None
    rank_factors: list[dict[str, Any]]


class LeadList(BaseModel):
    items: list[LeadOut]
    page: Page


class LeadStats(BaseModel):
    leads: int
    by_brand: list[KeyCount]
    by_kind: list[KeyCount]
    by_source: list[KeyCount]
    by_tier: list[KeyCount]
    by_status: list[KeyCount]
    detection_types: list[KeyCount]  # across all samples: typosquat | content | unattributed
    sample_tiers: list[KeyCount]
    timeline: list[TimePoint]


class DetectionOut(BaseModel):
    id: int
    campaign_id: int | None
    kit_id: int | None
    type: str
    target: str
    title: str
    content: str
    confidence: str
    false_positive_notes: str | None
    created_at: datetime


class CampaignDetail(BaseModel):
    campaign: CampaignOut
    kit: KitOut | None
    samples: list[SampleOut]
    detections: list[DetectionOut]
    timeline: list[TimePoint]
    reviews: list[ReviewOut]


class KitDetail(BaseModel):
    kit: KitOut
    campaigns: list[CampaignOut]
    samples: list[SampleOut]
    detections: list[DetectionOut]


class SampleList(BaseModel):
    items: list[SampleOut]
    page: Page


class PhishingStats(BaseModel):
    samples: int
    fetched_ok: int
    campaigns: int
    active_campaigns: int
    kits: int
    detections: int
    brands: list[KeyCount]
    tlds: list[KeyCount]
    asns: list[KeyCount]
    countries: list[KeyCount]
    sources: list[KeyCount]
    fetch_status: list[KeyCount]
    kit_distribution: list[KeyCount]
    timeline: list[TimePoint]  # samples per day (secondary = clustered)
    campaign_sizes: list[KeyCount]  # buckets: 1, 2-4, 5-9, 10+
    last_run: RunOut | None
    duplicates_merged: int = 0  # reports folded into existing samples (cross-source, URL variants, same page)


# --------------------------------------------------------------------------- P6

class VictimOut(BaseModel):
    id: int
    source: str
    victim: str
    domain: str | None
    group: str
    attack_date: datetime | None
    discovered: datetime | None
    month: str | None
    country: str | None
    region: str | None
    sector_raw: str | None
    sector: str | None
    sector_method: str
    size_band: str
    size_basis: str | None
    description: str | None
    data_size: str | None
    ransom_demand: str | None
    press: list[dict[str, Any]]
    url: str | None
    in_scope: bool
    cross_source_match: bool
    review_verdict: str | None = None


class VictimList(BaseModel):
    items: list[VictimOut]
    page: Page


class ActorOut(BaseModel):
    id: int
    slug: str
    name: str
    aliases: list[str]
    status: str
    first_seen: datetime | None
    last_seen: datetime | None
    victim_count_total: int
    victim_count_scope: int
    victim_count_window: int
    monthly_counts: dict[str, int]
    monthly_counts_scope: dict[str, int]
    top_sectors: list[dict[str, Any]]
    top_countries: list[dict[str, Any]]
    trend: str = "flat"  # rising | falling | flat | new
    mom_change: float | None = None


class ActorDetail(BaseModel):
    actor: ActorOut
    description: str | None
    ttps: list[dict[str, Any]]
    tools: list[str]
    locations: list[dict[str, Any]]
    profile_url: str | None
    recent_victims: list[VictimOut]
    scope_victims: list[VictimOut]


class IABOut(BaseModel):
    id: int
    source: str
    source_url: str
    published: datetime | None
    month: str | None
    title: str
    summary: str | None
    excerpt: str | None
    access_types: list[str]
    price_usd_min: float | None
    price_usd_max: float | None
    revenue_usd: float | None
    countries: list[str]
    region: str | None
    sectors: list[str]
    brokers: list[str]
    actors: list[str]
    relevance: float
    extraction_method: str
    in_scope: bool


class IABStats(BaseModel):
    listings: int
    in_scope: int
    with_price: int
    price_median: float | None
    price_min: float | None
    price_max: float | None
    access_types: list[KeyCount]
    regions: list[KeyCount]
    sectors: list[KeyCount]
    sources: list[KeyCount]
    timeline: list[TimePoint]
    price_points: list[dict[str, Any]]  # {month, price, access_type, title}


class IncidentOut(BaseModel):
    id: int
    date: datetime | None
    month: str | None
    title: str
    summary: str | None
    domain: str | None
    country: str | None
    region: str | None
    sector: str | None
    actor: str | None
    link: str | None
    in_scope: bool


class BriefingOut(BaseModel):
    id: int
    period: str
    sector: str
    region: str
    title: str
    markdown: str
    stats: dict[str, Any]
    generator: str
    status: str
    generated_at: datetime


class BriefingSummary(BaseModel):
    id: int
    period: str
    sector: str
    region: str
    title: str
    generator: str
    status: str
    generated_at: datetime


class GenerateBriefingRequest(BaseModel):
    period: str  # YYYY-MM
    use_llm: bool = False


class LandscapeStats(BaseModel):
    sector: str
    region: str
    months: list[str]
    victims_total: int
    victims_scope: int
    victims_sector: int
    victims_region: int
    actors_active_window: int
    actors_active_scope: int
    cross_source_rate: float | None
    timeline: list[TimePoint]  # per month: value=total, secondary=in scope
    by_sector: list[KeyCount]
    by_region: list[KeyCount]
    by_country_scope: list[KeyCount]
    by_size_scope: list[KeyCount]
    top_actors_window: list[KeyCount]
    top_actors_scope: list[KeyCount]
    sector_share_by_month: list[dict[str, Any]]  # {period, sector:count...}
    actor_trends: list[ActorOut]  # top movers
    iab: IABStats
    incidents_scope: int
    mom_scope_change: float | None
    last_run: RunOut | None
