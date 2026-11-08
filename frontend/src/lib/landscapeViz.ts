/** Types + fetchers for the P6 chart endpoints (backend/app/modules/landscape/viz.py). */
import { qs } from './api'
import type { ActorOut } from './types'

export type Cell = [number, number, number]
export interface Matrix { actors: string[]; cells: Cell[] }
export interface CountryValue { iso2: string; value: number }
export interface TreeNode { name: string; value?: number; children?: TreeNode[] }

export interface LandscapeViz {
  sector: string
  region: string
  months: string[]
  partial_month: string
  series: {
    total: number[]; scope: number[]; sector: number[]; region: number[]; scope_actors: number[]
    cross_rate: (number | null)[]; iab: number[]; incidents_scope: number[]; incidents: number[]
  }
  calendar: { scope: [string, number][]; region: [string, number][]; sector: [string, number][] }
  world: { sector: CountryValue[]; all: CountryValue[]; region_all: CountryValue[]; region_countries: string[] }
  sector_month: { months: string[]; series: Record<string, number[]> }
  actor_month: { region: Matrix; scope: Matrix }
  bump: { actors: string[]; ranks: Record<string, (number | null)[]>; max_rank: number }
  sankey: { nodes: { name: string; depth: number }[]; links: { source: string; target: string; value: number }[] }
  sector_region: { regions: string[]; sectors: string[]; cells: Cell[] }
  sunburst: TreeNode[]
  size_tree: TreeNode[]
  size_coverage: number | null
  size_sector: { sizes: string[]; sectors: string[]; cells: Cell[] }
  cross_source: {
    by_month: { period: string; n: number; matched: number; rate: number | null }[]
    by_actor: { actor: string; n: number; matched: number; rate: number }[]
  }
  iab: {
    price_by_access: Record<string, number[]>
    bubbles: { id: number; title: string; revenue: number; price: number; access_type: string; region: string | null; month: string | null }[]
    access_month: { months: string[]; types: string[]; cells: Cell[] }
    price_median: number | null
    with_price: number
    listings: number
  }
  actors: {
    name: string; slug: string | null; status: string; window: number; scope: number; region: number; countries: number
    top_sector: string | null; monthly: number[]
  }[]
}

export interface ActorViz {
  months: string[]
  monthly: { total: number[]; scope: number[] }
  calendar: [string, number][]
  countries: CountryValue[]
  sectors: { key: string; count: number }[]
  regions: { key: string; count: number }[]
  sizes: { key: string; count: number }[]
  radar: { sectors: string[]; actor: number[]; landscape: number[] }
  ttps: { tactic_id: string | null; tactic: string | null; count: number; techniques: { id: string | null; name: string | null; details: string | null }[] }[]
  window_total: number
}

export interface KC { key: string; count: number }
export interface VictimSummary {
  total: number; cross_source: number; countries: KC[]; groups: KC[]; sizes: KC[]; sectors: KC[]; regions: KC[]; months: KC[]; group_options: KC[]
}
export type VictimFilter = { sector?: string; region?: string; country?: string; group?: string; month?: string; size_band?: string; q?: string; in_scope?: boolean }

async function get<T>(path: string): Promise<T> {
  const r = await fetch(path)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json() as Promise<T>
}

export const landscapeViz = {
  get: (p: { months?: number; sector?: string; region?: string } = {}) => get<LandscapeViz>(`/api/landscape/viz${qs(p)}`),
  victimSummary: (p: VictimFilter) => get<VictimSummary>(`/api/landscape/victims/summary${qs(p)}`),
  /** all actors (the typed client stops at the API's default limit of 300) */
  actors: (p: { scope_only?: boolean; status?: string }) => get<ActorOut[]>(`/api/landscape/actors${qs({ ...p, limit: 2000 })}`),
  finalizeBriefing: async (id: number) => {
    const r = await fetch(`/api/landscape/briefings/${id}/finalize`, { method: 'POST' })
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
    return r.json()
  },
  actor: (slug: string, months?: number) => get<ActorViz>(`/api/landscape/actors/${encodeURIComponent(slug)}/viz${qs({ months })}`),
}

/** Index of the last complete month (the newest month is usually partial). */
export const lastFullIdx = (months: string[]) => Math.max(0, months.length - 2)
