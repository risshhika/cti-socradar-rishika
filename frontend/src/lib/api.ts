import type * as T from './types'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status = status }
}

async function request<R>(path: string, init?: RequestInit): Promise<R> {
  const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...init })
  if (!res.ok) {
    let detail = res.statusText
    try { const j = await res.json(); detail = j.detail ?? JSON.stringify(j) } catch { /* ignore */ }
    throw new ApiError(res.status, detail)
  }
  if (res.status === 204) return undefined as R
  return res.json() as Promise<R>
}

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const p = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, String(v)) })
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const api = {
  overview: () => request<T.OverviewOut>('/api/overview'),
  scope: { get: () => request<T.Scope>('/api/scope'), put: (s: T.Scope) => request<T.Scope>('/api/scope', { method: 'PUT', body: JSON.stringify(s) }) },
  pipelines: {
    list: () => request<T.PipelineInfo[]>('/api/pipelines'),
    runs: (pipeline?: string, limit = 50) => request<T.RunOut[]>(`/api/pipelines/runs${qs({ pipeline, limit })}`),
    run: (id: number) => request<T.RunDetail>(`/api/pipelines/runs/${id}`),
    trigger: (name: string, params: Record<string, unknown> = {}) => request<T.RunOut>(`/api/pipelines/${name}/run`, { method: 'POST', body: JSON.stringify({ params }) }),
  },
  reviews: {
    list: (entity_type?: T.EntityType, entity_id?: number) => request<T.ReviewOut[]>(`/api/reviews${qs({ entity_type, entity_id })}`),
    summary: () => request<T.ReviewSummary[]>('/api/reviews/summary'),
    create: (r: T.ReviewIn) => request<T.ReviewOut>('/api/reviews', { method: 'POST', body: JSON.stringify(r) }),
  },
  phishing: {
    stats: () => request<T.PhishingStats>('/api/phishing/stats'),
    campaigns: (p: { brand?: string; kit_id?: number; status?: string; q?: string; min_samples?: number } = {}) => request<T.CampaignOut[]>(`/api/phishing/campaigns${qs(p)}`),
    campaign: (id: number) => request<T.CampaignDetail>(`/api/phishing/campaigns/${id}`),
    kits: () => request<T.KitOut[]>('/api/phishing/kits'),
    kit: (id: number) => request<T.KitDetail>(`/api/phishing/kits/${id}`),
    samples: (p: { campaign_id?: number; kit_id?: number; brand?: string; fetch_status?: string; source?: string; q?: string; detection_type?: string; threat_tier?: string; sort?: 'recent' | 'threat'; page?: number; size?: number } = {}) => request<T.SampleList>(`/api/phishing/samples${qs(p)}`),
    leads: (p: { brand?: string; match_kind?: string; source?: string; threat_tier?: string; status?: string; q?: string; sort?: 'threat' | 'recent'; page?: number; size?: number } = {}) => request<T.LeadList>(`/api/phishing/leads${qs(p)}`),
    leadStats: () => request<T.LeadStats>('/api/phishing/leads/stats'),
    clientReportUrl: (id: number, p: { reporter?: string; force?: boolean; download?: boolean } = {}) =>
      `/api/phishing/campaigns/${id}/client-report.html${qs({ reporter: p.reporter || undefined, force: p.force || undefined, download: p.download || undefined })}`,
    reportBrands: () => request<T.ReportBrand[]>('/api/phishing/reports/brands'),
    brandReport: (brand: string) => request<T.BrandReport>(`/api/phishing/reports/brand${qs({ brand })}`),
    brandReportHtml: (brand: string, download: boolean) => `/api/phishing/reports/brand.html${qs({ brand, download: download || undefined })}`,
    sample: (id: number) => request<T.SampleOut>(`/api/phishing/samples/${id}`),
    detections: (p: { campaign_id?: number; kit_id?: number; type?: string; target?: string } = {}) => request<T.DetectionOut[]>(`/api/phishing/detections${qs(p)}`),
    exportUrl: (format: 'csv' | 'leads-csv' | 'stix' | 'sigma' | 'yara' | 'iocs' | 'campaign-cards', campaign_id?: number) => `/api/phishing/export/${format}${qs({ campaign_id })}`,
  },
  landscape: {
    stats: (p: { months?: number; sector?: string; region?: string } = {}) => request<T.LandscapeStats>(`/api/landscape/stats${qs(p)}`),
    victims: (p: { sector?: string; region?: string; country?: string; group?: string; month?: string; size_band?: string; q?: string; in_scope?: boolean; page?: number; size?: number } = {}) => request<T.VictimList>(`/api/landscape/victims${qs(p)}`),
    victim: (id: number) => request<T.VictimOut>(`/api/landscape/victims/${id}`),
    actors: (p: { scope_only?: boolean; q?: string; status?: string } = {}) => request<T.ActorOut[]>(`/api/landscape/actors${qs(p)}`),
    actor: (slug: string) => request<T.ActorDetail>(`/api/landscape/actors/${encodeURIComponent(slug)}`),
    iab: (p: { region?: string; sector?: string; access_type?: string; in_scope?: boolean; min_relevance?: number; q?: string } = {}) => request<T.IABOut[]>(`/api/landscape/iab${qs(p)}`),
    iabStats: () => request<T.IABStats>('/api/landscape/iab/stats'),
    incidents: (p: { in_scope?: boolean; month?: string; q?: string } = {}) => request<T.IncidentOut[]>(`/api/landscape/incidents${qs(p)}`),
    briefings: () => request<T.BriefingSummary[]>('/api/landscape/briefings'),
    briefing: (id: number) => request<T.BriefingOut>(`/api/landscape/briefings/${id}`),
    generateBriefing: (period: string, use_llm = false) => request<T.BriefingOut>('/api/landscape/briefings/generate', { method: 'POST', body: JSON.stringify({ period, use_llm }) }),
    exportUrl: (format: 'victims-csv' | 'actors-csv' | 'iab-csv' | 'briefing-md', id?: number) => `/api/landscape/export/${format}${qs({ id })}`,
  },
  x: {
    status: () => request<XStatus>('/api/landscape/x/status'),
    posts: (p: Record<string, string> = {}) => request<XPost[]>(`/api/landscape/x/posts${qs(p)}`),
    update: (id: number, b: { victim_name?: string; status?: string; refresh?: boolean }) => request<XPost>(`/api/landscape/x/posts/${id}`, { method: 'PATCH', body: JSON.stringify(b) }),
    identify: (id: number) => request<XIdentify>(`/api/landscape/x/posts/${id}/identify`, { method: 'POST' }),
  },
}

export type XOrg = { id: number; query_name: string; legal_name: string | null; website: string | null; country: string | null; industry: string | null; fin_subtype: string | null; revenue_usd: number | null; revenue_year: number | null; revenue_band: string | null; employees: number | null; employees_year: number | null; employee_band: string | null; identifiers: Record<string, string>; sources: { source: string; url: string; fields: string[]; fetched: string }[]; match_score: number; status: string }
export type XPost = { id: number; tweet_id: string; url: string; author_handle: string | null; author_name: string | null; created_at: string | null; text: string; queries: string[]; links: string[]; media: { key: string; type: string; url: string; alt: string | null; sha256: string | null; file: string | null }[]; raw_sha256: string | null; card_sha256: string | null; card: string | null; shot: string | null; shot_sha256: string | null; capture_method: string; financial_terms: string[]; fin_subtype: string | null; access_types: string[]; price_usd_min: number | null; price_usd_max: number | null; claimed_revenue_usd: number | null; countries: string[]; forums: string[]; tech: string[]; host_count: number | null; victim_candidates: string[]; relevance: number; victim_name: string | null; victim_confirmed: boolean; status: string; org: XOrg | null; revenue_band: string | null; revenue_basis: string | null; employee_band: string | null; industry: string | null }
export type XCandidate = { name: string; website: string | null; revenue_usd: number | null; revenue_band: string | null; employees: number | null; country: string | null; shodan_host: string | null; shodan_hostnames: string[]; confidence: string; why: string[]; source: string }
export type XIdentify = { post_id: number; country: string | null; revenue_band: [number, number]; tech: string[]; host_count: number | null; firmographic_source: string; firmographic_count: number; shodan_count: number; candidates: XCandidate[]; shodan_leads: { ip: string; org: string | null; hostnames: string[]; product: string | null; ssl_cn: string | null }[]; shodan_error: string | null; notes: string[]; missing_keys: string[]; disclaimer: string }
export type XStatus = { x_api: boolean; registries: boolean; shodan?: boolean; zoominfo: boolean; sectors: string[]; queries: { label: string; query: string; sent_as: string }[]; revenue_bands: string[]; employee_bands: string[] }

