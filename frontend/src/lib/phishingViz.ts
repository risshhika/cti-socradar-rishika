/** Types + fetchers for the P4 dashboard aggregates (backend/app/modules/phishing/viz.py). */
import { useQuery } from '@tanstack/react-query'
import type { KeyCount } from './types'

export interface GraphNodeOut { id: string; name: string; category: number; value: number; campaign_id?: number; kit_id?: number }
export interface GraphOut { nodes: GraphNodeOut[]; links: { source: string; target: string; value: number }[]; categories: string[]; campaigns: number; shared_infra: number }
export interface KitProfile { id: number; name: string; source: string; family: string | null; samples: number; campaigns: number; profile: number[]; brands: KeyCount[]; daily: number[]; first_seen: string | null; last_seen: string | null }
export interface CampaignBubble { id: number; name: string; brand: string; kit: string | null; first_seen: string; last_seen: string | null; samples: number; domains: number; ips: number; cohesion: number; method: string }
export interface Window { cur: number; prev: number }

export interface PhishingViz {
  days: string[]
  /** [hour 0-23, weekday 0=Mon, count] */
  hour_dow: [number, number, number][]
  daily_total: number[]
  daily_clustered: number[]
  daily_new_campaigns: number[]
  /** rules generated for campaigns first seen that day */
  daily_detections: number[]
  daily_by_source: Record<string, number[]>
  brands: KeyCount[]
  brand_day: { brands: string[]; cells: [number, number, number][] }
  kpis: { samples: Window; campaigns_new: Window; brands: Window; detections: Window; window_end: string }
  funnel: { name: string; value: number }[]
  kit_split: { named: number; inferred: number; none: number }
  sankey: { nodes: { name: string; depth: number }[]; links: { source: string; target: string; value: number }[] }
  graph: GraphOut
  hosting_tree: { name: string; value: number; children?: { name: string; value: number }[] }[]
  countries: { iso2: string; value: number }[]
  bubbles: CampaignBubble[]
  cohesion_hist: { bucket: string; count: number }[]
  detections_matrix: { types: string[]; targets: string[]; cells: [number, number, number][] }
  detections_by_type: KeyCount[]
  brand_kit: { brands: string[]; kits: string[]; cells: [number, number, number][] }
  kit_profiles: KitProfile[]
  radar_dims: string[]
  tlds: KeyCount[]
  fetch_status: KeyCount[]
  campaign_daily: Record<string, number[]>
  graph_categories: string[]
}

export interface CampaignGraph extends GraphOut {
  days: string[]
  daily: number[]
  related_campaigns: { id: number; name: string; samples: number }[]
  profile: number[]
  radar_dims: string[]
}

async function get<T>(path: string): Promise<T> {
  const r = await fetch(path)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<T>
}

export const fetchPhishingViz = () => get<PhishingViz>('/api/phishing/viz')
export const fetchCampaignGraph = (id: number) => get<CampaignGraph>(`/api/phishing/campaigns/${id}/graph`)

export function usePhishingViz() {
  return useQuery({ queryKey: ['phishing', 'viz'], queryFn: fetchPhishingViz, staleTime: 60_000 })
}

/** Query-state shape ChartCard expects. */
export const qstate = (q: { isLoading: boolean; isError: boolean; error: unknown; isFetching?: boolean; refetch?: () => unknown }) =>
  ({ isLoading: q.isLoading, isError: q.isError, error: q.error, isFetching: q.isFetching, refetch: q.refetch })

/** Sankey node names carry trailing spaces to keep the brand/kit/hosting columns apart; trim for display. */
export const cleanName = (s: string) => s.trimEnd()

export const SOURCE_LABEL: Record<string, string> = { urlscan: 'urlscan.io', openphish: 'OpenPhish', phishtank: 'PhishTank', nrd: 'New domains (WhoisDS)' }
