// Mirrors backend/app/schemas.py. Keep in sync.
export interface Page { page: number; size: number; total: number }
export interface KeyCount { key: string; count: number; share?: number | null }
export interface TimePoint { period: string; value: number; secondary?: number | null }

export interface PhishingScope { sector: string; brands: string[]; days_back: number; max_samples: number; urlscan_queries_per_brand: number; [k: string]: unknown }
export interface LandscapeScope { sector: string; region: string; months: number; iab_feeds: string[] }
export interface Scope { phishing: PhishingScope; landscape: LandscapeScope }

export type RunStatus = 'queued' | 'running' | 'succeeded' | 'failed'
export interface RunOut {
  id: number; pipeline: string; status: RunStatus; trigger: string
  params: Record<string, unknown>; summary: Record<string, unknown>; error: string | null
  started_at: string | null; finished_at: string | null; created_at: string; duration_seconds: number | null
}
export interface RunDetail extends RunOut { log: string }
export interface PipelineInfo { name: string; running: boolean; last_run: RunOut | null }

export type Verdict = 'agree' | 'miss' | 'over_flag' | 'unsure'
export type EntityType = 'campaign' | 'sample' | 'kit' | 'victim' | 'actor' | 'iab' | 'briefing'
export interface ReviewIn { entity_type: EntityType; entity_id: number; verdict: Verdict; note?: string | null; reviewer?: string }
export interface ReviewOut extends ReviewIn { id: number; created_at: string }
export interface ReviewSummary { entity_type: EntityType; reviewed: number; agree: number; miss: number; over_flag: number; unsure: number; precision_proxy: number | null }
export interface SourceHealth { name: string; module: string; status: 'ok' | 'degraded' | 'down' | 'unknown' | string; detail: string | null; checked_at: string | null }

export interface OverviewOut {
  scope: Scope
  phishing: { samples: number; samples_fetched: number; campaigns: number; campaigns_active: number; kits: number; detections: number; samples_7d: number; brands: string[]; last_run: RunOut | null }
  landscape: { victims_total: number; victims_scope: number; victims_month: number; victims_month_scope: number; actors_total: number; actors_active: number; iab_listings: number; iab_scope: number; briefings: number; last_run: RunOut | null }
  recent_runs: RunOut[]
  reviews: ReviewSummary[]
  sources: SourceHealth[]
}

// ---- P4
export interface KitOut {
  id: number; slug: string; name: string; family: string | null; description: string | null; source: string
  markers: Record<string, unknown>[]; sample_count: number; campaign_count: number
  first_seen: string | null; last_seen: string | null; references: string[]
}
export interface CampaignOut {
  id: number; name: string; brand: string | null; sector: string | null; status: string
  first_seen: string | null; last_seen: string | null; sample_count: number; domain_count: number; ip_count: number
  cohesion: number; kit_id: number | null; kit_name: string | null; kit_confidence: number; cluster_method: string
  summary: Record<string, any>; detection_count: number; review_verdict: Verdict | null
}
export interface SampleOut {
  id: number; url: string; final_url: string | null; domain: string | null; apex_domain: string | null
  ip: string | null; asn: string | null; asn_name: string | null; country: string | null; tld: string | null
  source: string; source_id: string | null; source_tags: string[]; first_seen: string | null; fetched_at: string | null
  fetch_status: string; http_status: number | null; title: string | null; brand: string | null; brand_confidence: number
  html_sha256: string | null; html_size: number | null; screenshot_url: string | null; struct_hash: string | null
  features: Record<string, any>; campaign_id: number | null; campaign_name: string | null
  kit_id: number | null; kit_name: string | null; kit_confidence: number; review_verdict: Verdict | null
  detection_type: 'typosquat' | 'content' | 'unattributed' | null; threat_score: number; threat_tier: ThreatTier | null
  squat: SquatMatch | null; rank_factors: RankFactor[]
  dedup_key: string | null; sources: string[]; duplicate_urls: string[]; duplicate_count: number
}
export type ThreatTier = 'critical' | 'high' | 'medium' | 'low'
export interface SquatMatch { brand: string; kind: 'embed' | 'homoglyph' | 'fragment' | 'typo'; score: number; label: string; evidence: string; lure_words: string[] }
export interface RankFactor { factor: string; points: number; detail: string }
export interface LeadOut {
  id: number; domain: string; brand: string; match_kind: SquatMatch['kind']; match_score: number; evidence: string | null
  lure_words: string[]; sources: string[]; first_seen: string | null; last_seen: string | null; meta: Record<string, any>
  status: 'new' | 'promoted' | 'live' | 'offline' | 'blocked' | string; sample_id: number | null
  threat_score: number; threat_tier: ThreatTier | null; rank_factors: RankFactor[]
}
export interface LeadList { items: LeadOut[]; page: Page }
export interface ReportBrand { brand: string; samples: number; live: number; in_scope: boolean }
export interface BrandReport {
  brand: string; generated_at: string; window_days: number; sector: string
  executive_summary: string; impact_one_line: string; method_note: string
  numbers: {
    window_days: number; pages: number; share_of_all: number; live: number; blocked: number; offline: number
    critical: number; high: number; medium: number; low: number; typosquat_hosts: number; content_only: number
    campaigns: number; active_campaigns: number; multi_page_campaigns: number; kits: number; named_kits: number
    typosquat_leads: number; new_domain_leads: number; detections: number; duplicates_merged: number
    sources: Record<string, number>; daily: { day: string; pages: number }[]
  }
  targeting: {
    rank_among_brands: number | null; detection_types: Record<string, number>; squat_kinds: Record<string, number>
    lure_words: { word: string; count: number }[]; hosting_platforms: { platform: string; pages: number }[]; dedicated_domains: number
    title_themes: string[]; credential_surface: { key: string; asset: string; impact: string; pages: number; share: number }[]
    kits: { name: string; source: string; pages: number }[]
  }
  use_case: null | {
    sample_id: number; screenshot: string; caption: string; threat_score: number; threat_tier: ThreatTier | null
    verified_live_at: string | null; live_within_48h: boolean; first_seen: string | null; country: string | null
    hosting: string | null; platform: string | null; assets_requested: string[]
  }
  fingerprint: null | {
    kit: null | { name: string; family: string | null; source: string; confidence: number; description: string; references: string[]; pages: number; campaigns: number }
    matched_markers: string[]
    campaign: null | { name: string; pages: number; domains: number; ips: number; cohesion: number; method: string; status: string; shared_markers: string[]; exfil_endpoints: string[] }
    page: { dom_simhash: string | null; favicon_hash: string | null; html_sha256: string | null; input_names: string[]; script_hosts: string[]; obfuscation: string[]; antibot: string[]; exfil: string[]; image_names: string[] }
  }
  urlscan_queries: { label: string; query: string; why: string; link: string; results_now?: number | null; error?: string }[]
  geography: { countries: { country: string; pages: number; new_recently: boolean }[]; new_countries: string[]; asns: { asn: string; pages: number }[]; tlds: { tld: string; pages: number }[] }
  user_impact: { asset: string; consequence: string; evidence: string }[]
  defense: { organisation: string[]; customers: string[] }
}
export interface LeadStats {
  leads: number; by_brand: KeyCount[]; by_kind: KeyCount[]; by_source: KeyCount[]; by_tier: KeyCount[]; by_status: KeyCount[]
  detection_types: KeyCount[]; sample_tiers: KeyCount[]; timeline: TimePoint[]
}
export interface DetectionOut {
  id: number; campaign_id: number | null; kit_id: number | null; type: string; target: string; title: string
  content: string; confidence: string; false_positive_notes: string | null; created_at: string
}
export interface CampaignDetail { campaign: CampaignOut; kit: KitOut | null; samples: SampleOut[]; detections: DetectionOut[]; timeline: TimePoint[]; reviews: ReviewOut[] }
export interface KitDetail { kit: KitOut; campaigns: CampaignOut[]; samples: SampleOut[]; detections: DetectionOut[] }
export interface SampleList { items: SampleOut[]; page: Page }
export interface PhishingStats {
  samples: number; fetched_ok: number; campaigns: number; active_campaigns: number; kits: number; detections: number
  brands: KeyCount[]; tlds: KeyCount[]; asns: KeyCount[]; countries: KeyCount[]; sources: KeyCount[]; fetch_status: KeyCount[]
  kit_distribution: KeyCount[]; timeline: TimePoint[]; campaign_sizes: KeyCount[]; last_run: RunOut | null
  duplicates_merged: number
}

// ---- P6
export interface VictimOut {
  id: number; source: string; victim: string; domain: string | null; group: string
  attack_date: string | null; discovered: string | null; month: string | null; country: string | null; region: string | null
  sector_raw: string | null; sector: string | null; sector_method: string; size_band: string; size_basis: string | null
  description: string | null; data_size: string | null; ransom_demand: string | null; press: Record<string, any>[]
  url: string | null; in_scope: boolean; cross_source_match: boolean; review_verdict: Verdict | null
}
export interface VictimList { items: VictimOut[]; page: Page }
export interface ActorOut {
  id: number; slug: string; name: string; aliases: string[]; status: string; first_seen: string | null; last_seen: string | null
  victim_count_total: number; victim_count_scope: number; victim_count_window: number
  monthly_counts: Record<string, number>; monthly_counts_scope: Record<string, number>
  top_sectors: { key: string; count: number }[]; top_countries: { key: string; count: number }[]
  trend: 'rising' | 'falling' | 'flat' | 'new' | string; mom_change: number | null
}
export interface ActorDetail {
  actor: ActorOut; description: string | null; ttps: Record<string, any>[]; tools: string[]
  locations: Record<string, any>[]; profile_url: string | null; recent_victims: VictimOut[]; scope_victims: VictimOut[]
}
export interface IABOut {
  id: number; source: string; source_url: string; published: string | null; month: string | null; title: string
  summary: string | null; excerpt: string | null; access_types: string[]; price_usd_min: number | null; price_usd_max: number | null
  revenue_usd: number | null; countries: string[]; region: string | null; sectors: string[]; brokers: string[]; actors: string[]
  relevance: number; extraction_method: string; in_scope: boolean
}
export interface IABStats {
  listings: number; in_scope: number; with_price: number; price_median: number | null; price_min: number | null; price_max: number | null
  access_types: KeyCount[]; regions: KeyCount[]; sectors: KeyCount[]; sources: KeyCount[]; timeline: TimePoint[]
  price_points: { month: string; price: number; access_type: string; title: string }[]
}
export interface IncidentOut {
  id: number; date: string | null; month: string | null; title: string; summary: string | null; domain: string | null
  country: string | null; region: string | null; sector: string | null; actor: string | null; link: string | null; in_scope: boolean
}
export interface BriefingOut {
  id: number; period: string; sector: string; region: string; title: string; markdown: string
  stats: Record<string, any>; generator: string; status: string; generated_at: string
}
export interface BriefingSummary { id: number; period: string; sector: string; region: string; title: string; generator: string; status: string; generated_at: string }
export interface LandscapeStats {
  sector: string; region: string; months: string[]
  victims_total: number; victims_scope: number; victims_sector: number; victims_region: number
  actors_active_window: number; actors_active_scope: number; cross_source_rate: number | null
  timeline: TimePoint[]; by_sector: KeyCount[]; by_region: KeyCount[]; by_country_scope: KeyCount[]; by_size_scope: KeyCount[]
  top_actors_window: KeyCount[]; top_actors_scope: KeyCount[]; sector_share_by_month: Record<string, any>[]
  actor_trends: ActorOut[]; iab: IABStats; incidents_scope: number; mom_scope_change: number | null; last_run: RunOut | null
}
