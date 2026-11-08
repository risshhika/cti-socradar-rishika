import { useMemo, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import { TrendingUp, TrendingDown, Minus, Sparkles } from 'lucide-react'
import { Badge, KV, Ext, SeverityPill } from '../../components/ui'
import { ReviewPanel } from '../../components/ui/ReviewPanel'
import { ChartCard, type TableTwin } from '../../components/ui/ChartCard'
import { EChart } from '../../charts/EChart'
import { sparkline } from '../../charts/options'
import { countryName, flag } from '../../charts/countries'
import { useTheme } from '../../theme/ThemeProvider'
import type { Tokens } from '../../theme/echartsTheme'
import { landscapeViz } from '../../lib/landscapeViz'
import { useFilters } from '../../components/ui/useParams'
import { fmtDate, fmtPct } from '../../lib/format'
import type { ActorOut, VictimOut } from '../../lib/types'

export const slugify = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
/** Link to an actor profile. Non-Latin names slugify to '' so fall back to the raw name, which the API resolves. */
export const actorHref = (name: string) => `/landscape/actors/${encodeURIComponent(slugify(name) || name)}`

export const SRC = {
  rl: 'ransomware.live',
  rlx: 'ransomware.live × RansomLook',
  iab: 'vendor & news RSS (IAB extraction)',
  groups: 'ransomware.live /groups',
  incidents: 'ransomware.live cyberattacks',
}

/** Analysis window (months) shared across P6 pages through the URL (?w=3|6|12). */
export function useWindow(): [number, (n: number) => void] {
  const f = useFilters<'w'>()
  const w = Number(f.get('w') || 6)
  return [[3, 6, 12].includes(w) ? w : 6, (n: number) => f.set('w', n === 6 ? '' : n, false)]
}

export function useViz(months: number) {
  return useQuery({ queryKey: ['landscape', 'viz', months], queryFn: () => landscapeViz.get({ months }), retry: false })
}

type Q = Pick<UseQueryResult, 'isLoading' | 'isError' | 'error' | 'isFetching' | 'refetch'>

/** ChartCard + EChart in one: every P6 chart states its question, cites its source and exports as PNG. */
export function Viz({ title, question, source, query, height, option, empty, emptyText, table, caveat, actions, needsWorld, onEvents, asOf, style }: {
  title: string; question: string; source: string; query: Q; height: number; option: Record<string, unknown> | null
  empty?: boolean; emptyText?: string; table?: TableTwin; caveat?: ReactNode; actions?: ReactNode; needsWorld?: boolean
  onEvents?: Record<string, (p: any) => void>; asOf?: string | null; style?: React.CSSProperties
}) {
  return (
    <ChartCard title={title} question={question} source={source} query={query} height={height} empty={empty || !option} emptyText={emptyText}
      table={table} caveat={caveat} actions={actions} asOf={asOf} style={style}
      render={(h) => option ? <EChart option={option} height={height} ariaLabel={title} handle={h} needsWorld={needsWorld} onEvents={onEvents} /> : null} />
  )
}

export const useTokens = (): Tokens => useTheme().tokens

/** Month label for page copy ("Oct 2026"): chart axes keep the compact form. */
export const monthLabel = (ym: string | null | undefined) => {
  if (!ym) return '—'
  const d = new Date(`${ym}-01T00:00:00Z`)
  return Number.isNaN(d.getTime()) ? ym : d.toLocaleDateString('en-US', { timeZone: 'UTC', month: 'short', year: 'numeric' })
}

/** Heatmap value labels: white on the darker half of the ramp so numbers stay readable in both themes. */
export function contrastLabels(option: any) {
  const ser = option?.series?.[0]
  const max = option?.visualMap?.max ?? 1
  if (ser?.data) ser.data = ser.data.map((d: any) => (d?.value?.[2] > max * 0.5 ? { ...d, label: { color: '#fff' } } : d))
  return option
}

/** Sunburst with outer labels kept inside the ring and only on slices wide enough to read. */
export function tuneSunburst(option: any) {
  const lv = option?.series?.[0]?.levels
  if (lv?.[1]) lv[1].label = { fontSize: 11, color: '#fff', rotate: 'tangential', minAngle: 16 }
  if (lv?.[2]) lv[2].label = { position: 'inside', color: '#fff', fontSize: 10, rotate: 'radial', minAngle: 9 }
  return option
}

/**
 * Choropleth tuned for dashboards: no scroll-zoom (it hijacks page scrolling) and, when zoomed to a region, a colour
 * scale fitted to that region's countries so they don't all collapse to one tone next to the US.
 */
export function tuneMap(option: any, values: { iso2: string; value: number }[], regionCountries: string[], zoomed: boolean) {
  const ser = option?.series?.[0]
  if (ser) { ser.roam = false; ser.zoom = zoomed ? 4.2 : 1.15 }
  if (zoomed && regionCountries.length && option?.visualMap) {
    const inRegion = new Set(regionCountries.map((c) => c.toUpperCase()))
    const max = Math.max(1, ...values.filter((v) => inRegion.has(v.iso2.toUpperCase())).map((v) => v.value))
    option.visualMap.max = max
    option.visualMap.text = [`${max}+`, '0']
    option.visualMap.outOfRange = { color: option.visualMap.inRange.color[option.visualMap.inRange.color.length - 1] }
  }
  return option
}

export function TrendBadge({ trend, mom }: { trend: string; mom?: number | null }) {
  const map: Record<string, { tone: 'danger' | 'ok' | 'neutral' | 'info'; Icon: typeof TrendingUp }> = { rising: { tone: 'danger', Icon: TrendingUp }, falling: { tone: 'ok', Icon: TrendingDown }, flat: { tone: 'neutral', Icon: Minus }, new: { tone: 'info', Icon: Sparkles } }
  const m = map[trend] ?? map.flat
  return <Badge tone={m.tone}><m.Icon size={11} style={{ marginRight: 3 }} />{trend}{mom != null && trend !== 'new' && <span className="num">&nbsp;{mom > 0 ? '+' : ''}{fmtPct(mom)}</span>}</Badge>
}

export function MiniSpark({ values, labels, width = 110, height = 30, color }: { values: number[]; labels?: string[]; width?: number; height?: number; color?: string }) {
  const t = useTokens()
  const option = useMemo(() => sparkline(values, t, { color, labels }), [values, t, color, labels])
  return <div style={{ width }}><EChart option={option} height={height} renderer="svg" ariaLabel="trend" /></div>
}

export function ActorSpark({ actor, months, scope }: { actor: ActorOut; months: string[]; scope?: boolean }) {
  const t = useTokens()
  const src = scope ? actor.monthly_counts_scope : actor.monthly_counts
  const keys = months.length ? months : Object.keys(src).sort()
  return <MiniSpark values={keys.map((m) => src[m] ?? 0)} labels={keys} color={actor.trend === 'rising' ? t.series[1] : t.accent} />
}

const SIZE_SEV: Record<string, string> = { enterprise: 'CRITICAL', large: 'HIGH', mid: 'MEDIUM', small: 'LOW', unknown: 'UNKNOWN' }
/** Organisation size as a labelled pill (larger orgs = higher impact). */
export function SizeBadge({ band }: { band: string }) {
  return <SeverityPill severity={SIZE_SEV[band] ?? 'UNKNOWN'} label={band === 'unknown' ? 'Size n/a' : band[0].toUpperCase() + band.slice(1)} />
}

export function Country({ cc, region }: { cc: string | null | undefined; region?: string | null }) {
  if (!cc) return <span className="muted">—</span>
  return <span title={region ?? undefined} style={{ whiteSpace: 'nowrap' }}><span style={{ marginRight: 5 }}>{flag(cc)}</span>{countryName(cc)}</span>
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return <div style={{ fontSize: 10.5, fontWeight: 600, letterSpacing: '.08em', textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: 6 }}>{children}</div>
}

export function VictimDetail({ v }: { v: VictimOut }) {
  return (
    <div style={{ display: 'grid', gap: 18 }}>
      <KV items={[
        { k: 'Domain', v: v.domain ? <span className="mono">{v.domain}</span> : '—' },
        { k: 'Actor', v: <Link to={actorHref(v.group)}>{v.group}</Link> },
        { k: 'Sector', v: <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>{v.sector ?? <span className="muted">unknown</span>}<Badge>{v.sector_method}</Badge>{v.sector_raw && v.sector_raw !== v.sector && <span className="muted" style={{ fontSize: 11 }}>raw: {v.sector_raw}</span>}</span> },
        { k: 'Location', v: <span><Country cc={v.country} />{v.region && <span className="muted"> · {v.region}</span>}</span> },
        { k: 'Size', v: <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}><SizeBadge band={v.size_band} />{v.size_basis && <span className="muted" style={{ fontSize: 11 }}>{v.size_basis}</span>}</span> },
        { k: 'Attack date', v: fmtDate(v.attack_date) },
        { k: 'Posted', v: fmtDate(v.discovered) },
        { k: 'Data claimed', v: v.data_size ?? '—' },
        { k: 'Ransom', v: v.ransom_demand ?? '—' },
        { k: 'Source', v: <span>{v.source}{v.url && <> · <Ext href={v.url}>record</Ext></>}</span> },
      ]} />
      {v.description && <div><SectionTitle>Leak-site description</SectionTitle><p style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 12.5, color: 'var(--text-2)', background: 'var(--page)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, maxHeight: 230, overflow: 'auto' }}>{v.description}</p></div>}
      {v.press?.length > 0 && <div><SectionTitle>Press coverage</SectionTitle><ul style={{ margin: 0, paddingLeft: 16, fontSize: 12.5, display: 'grid', gap: 4 }}>{v.press.map((p, i) => <li key={i}>{p.url || p.link ? <Ext href={String(p.url ?? p.link)}>{String(p.title ?? p.source ?? p.url ?? p.link)}</Ext> : String(p.title ?? JSON.stringify(p))}{p.date && <span className="muted"> · {fmtDate(String(p.date))}</span>}</li>)}</ul></div>}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}><SectionTitle>Analyst review · sector, region and size classification</SectionTitle><ReviewPanel entityType="victim" entityId={v.id} /></div>
    </div>
  )
}

export function VictimBadges({ v }: { v: VictimOut }) {
  return <>
    <Badge tone={v.in_scope ? 'accent' : 'neutral'}>{v.in_scope ? 'In scope' : 'Out of scope'}</Badge>
    <Badge tone={v.cross_source_match ? 'ok' : 'warn'}>{v.cross_source_match ? 'Confirmed by 2 sources' : 'Single source'}</Badge>
    <SizeBadge band={v.size_band} />
  </>
}

/** Turn {key,count}[] into chart bar items. */
export const bars = (rows: { key: string; count: number }[], n = 10, map?: (k: string) => string) => rows.slice(0, n).map((r) => ({ label: map ? map(r.key) : r.key, value: r.count }))
