import { type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Download } from 'lucide-react'
import { ChartCard, type TableTwin } from '../../components/ui/ChartCard'
import { EChart } from '../../charts/EChart'
import type { EChartsCoreOption } from '../../charts/echarts'
import { Badge, ConfidenceBadge, Code, DataTable, EmptyState, StatusBadge, VerdictBadge } from '../../components/ui'
import { CopyButton } from '../../components/ui/CopyButton'
import { ScreenshotThumb } from '../../components/ui/Screenshot'
import { api } from '../../lib/api'
import { fmtDate, truncate } from '../../lib/format'
import { countryName, flag } from '../../charts/countries'
import type { DetectionOut, SampleOut } from '../../lib/types'

export const KICKER = 'P4 · Phishing intelligence'

interface QState { isLoading: boolean; isError: boolean; error: unknown; isFetching?: boolean; refetch?: () => unknown }

/** ChartCard + EChart in one: every chart states its question and source, has a table twin and PNG export. */
export function Viz({ title, question, source, query, option, height, empty, emptyText, table, caveat, onEvents, needsWorld, actions, renderer, asOf, png }: {
  title: string; question: string; source: string; query: QState; option: object | undefined; height: number; empty?: boolean; emptyText?: string
  table?: TableTwin; caveat?: ReactNode; onEvents?: Record<string, (p: any) => void>; needsWorld?: boolean; actions?: ReactNode; renderer?: 'canvas' | 'svg'; asOf?: string | null; png?: boolean
}) {
  return (
    <ChartCard title={title} question={question} source={source} query={query} height={height} empty={empty || !option} emptyText={emptyText} table={table} caveat={caveat} actions={actions} asOf={asOf} png={png}
      style={{ height: '100%' }}
      render={(h) => option ? <EChart option={option as EChartsCoreOption} height={height} ariaLabel={title} handle={h} onEvents={onEvents} needsWorld={needsWorld} renderer={renderer} /> : null} />
  )
}

export function Chips({ items, tone, mono = true, max = 60, empty = 'none' }: { items: string[]; tone?: 'accent' | 'info' | 'warn' | 'neutral' | 'danger'; mono?: boolean; max?: number; empty?: string }) {
  if (!items.length) return <span className="muted" style={{ fontSize: 'var(--fs-sm)' }}>{empty}</span>
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
      {items.slice(0, max).map((s, i) => <Badge key={i} tone={tone}>{mono ? <span className="mono" style={{ fontSize: 11 }}>{s}</span> : s}</Badge>)}
      {items.length > max && <span className="muted" style={{ fontSize: 11 }}>+{items.length - max}</span>}
    </div>
  )
}

export function ExportButtons({ campaignId, formats = ['campaign-cards', 'stix', 'sigma', 'yara', 'iocs', 'csv'] }: { campaignId?: number; formats?: ('csv' | 'stix' | 'sigma' | 'yara' | 'iocs' | 'campaign-cards')[] }) {
  const label: Record<string, string> = { 'campaign-cards': 'Cards', stix: 'STIX', sigma: 'Sigma', yara: 'YARA', iocs: 'IOCs', csv: 'CSV' }
  return <>{formats.map((f) => <a key={f} className="btn btn-ghost" href={api.phishing.exportUrl(f, campaignId)} title={`Download ${label[f]}`}><Download size={14} />{label[f]}</a>)}</>
}

export const Geo = ({ cc }: { cc: string | null | undefined }) => cc ? <span title={countryName(cc)}>{flag(cc)} <span className="mono">{cc}</span></span> : <span className="muted">—</span>

export function SampleTable({ rows, hideCampaign, hideKit, maxHeight = '65vh', empty }: { rows: SampleOut[]; hideCampaign?: boolean; hideKit?: boolean; maxHeight?: string; empty?: ReactNode }) {
  const nav = useNavigate()
  return (
    <DataTable<SampleOut> rows={rows} rowKey={(r) => r.id} dense maxHeight={maxHeight} onRowClick={(r) => nav(`/phishing/samples/${r.id}`)}
      empty={empty ?? <EmptyState title="No samples" />}
      columns={[
        { key: 'shot', header: '', width: '52px', render: (r) => <span onClick={(e) => e.stopPropagation()}><ScreenshotThumb src={r.screenshot_url} size={40} /></span> },
        { key: 'url', header: 'URL', sort: (r) => r.url, render: (r) => <div style={{ maxWidth: 360 }}><div className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text)' }} title={r.url}>{r.url}</div><div className="muted" style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.title ?? ''}>{r.title ? truncate(r.title, 70) : 'no title'}</div></div> },
        { key: 'brand', header: 'Brand', sort: (r) => r.brand, render: (r) => r.brand ? <Badge tone="accent">{r.brand}</Badge> : <span className="muted">—</span> },
        { key: 'st', header: 'Capture', sort: (r) => r.fetch_status, render: (r) => <span style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }}><StatusBadge status={r.fetch_status} />{r.http_status && <span className="mono muted">{r.http_status}</span>}</span> },
        { key: 'geo', header: 'Hosting', sort: (r) => r.asn_name, render: (r) => <div style={{ fontSize: 12 }}><Geo cc={r.country} /> <span className="muted" style={{ display: 'inline-block', maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis', verticalAlign: 'bottom', whiteSpace: 'nowrap' }} title={r.asn_name ?? ''}>{r.asn_name ?? r.asn ?? ''}</span></div> },
        ...(hideCampaign ? [] : [{ key: 'camp', header: 'Campaign', sort: (r: SampleOut) => r.campaign_name, render: (r: SampleOut) => r.campaign_id ? <Link onClick={(e) => e.stopPropagation()} to={`/phishing/campaigns/${r.campaign_id}`} className="mono" style={{ whiteSpace: 'nowrap' }}>{r.campaign_name ?? `#${r.campaign_id}`}</Link> : <span className="muted">unclustered</span> }]),
        ...(hideKit ? [] : [{ key: 'kit', header: 'Kit', sort: (r: SampleOut) => r.kit_name, render: (r: SampleOut) => r.kit_name ? <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}><span style={{ maxWidth: 170, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.kit_name}>{r.kit_name}</span><ConfidenceBadge value={r.kit_confidence} /></span> : <span className="muted">—</span> }]),
        { key: 'src', header: 'Source', sort: (r) => r.source, render: (r) => <span className="muted">{r.source}</span> },
        { key: 'seen', header: 'First seen', sort: (r) => r.first_seen, render: (r) => <span className="muted num" style={{ whiteSpace: 'nowrap' }}>{fmtDate(r.first_seen)}</span> },
        { key: 'v', header: 'Verdict', render: (r) => <VerdictBadge verdict={r.review_verdict} /> },
      ]} />
  )
}

const TYPE_TONE: Record<string, 'info' | 'accent' | 'warn' | 'neutral'> = { sigma: 'accent', yara: 'accent', url_regex: 'warn' }
export const TARGET_LABEL: Record<string, string> = { web_gateway: 'Web gateway', mail_gateway: 'Mail gateway', siem: 'SIEM', edr: 'EDR / file scan' }
export const TYPE_LABEL: Record<string, string> = { sigma: 'Sigma', yara: 'YARA', url_regex: 'URL regex', ioc_domain: 'IOC · domains', ioc_ip: 'IOC · IPs', ioc_url: 'IOC · URLs', snort: 'Snort' }

export function DetectionList({ items, showCampaign }: { items: DetectionOut[]; showCampaign?: boolean }) {
  if (!items.length) return <EmptyState title="No detections" hint="Detections are generated per campaign once a cluster has at least one captured page." />
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {items.map((d) => (
        <section key={d.id} style={{ border: '1px solid var(--border)', borderRadius: 'var(--r-md)', overflow: 'hidden', background: 'var(--surface-1)' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--border)', background: 'var(--surface-2)' }}>
            <Badge tone={TYPE_TONE[d.type] ?? 'neutral'}>{TYPE_LABEL[d.type] ?? d.type}</Badge>
            <Badge>{TARGET_LABEL[d.target] ?? d.target}</Badge>
            <ConfidenceBadge value={d.confidence} />
            <span style={{ fontWeight: 600, fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>{d.title}</span>
            {showCampaign && d.campaign_id && <Link to={`/phishing/campaigns/${d.campaign_id}`} style={{ fontSize: 12 }}>campaign #{d.campaign_id}</Link>}
            <span style={{ flex: 1 }} />
            <CopyButton text={d.content} />
          </div>
          <Code className="" >{d.content}</Code>
          {d.false_positive_notes && <div style={{ padding: '8px 12px', fontSize: 12, color: 'var(--text-3)', borderTop: '1px solid var(--border)' }}><b style={{ color: 'var(--sev-medium)' }}>False-positive notes</b> · {d.false_positive_notes}</div>}
        </section>
      ))}
    </div>
  )
}

/**
 * Page-level overrides for graph / map options: pan-only roam (a wheel over the chart must scroll the page, not zoom it)
 * and a tighter force layout so nodes stay inside the card.
 */
export function tame<T extends { series?: unknown }>(opt: T, force?: { repulsion?: number; gravity?: number; edgeLength?: number | number[] }): T {
  const series = (opt.series as Record<string, unknown>[] | undefined)?.map((s) => ({
    ...s,
    roam: 'move',
    ...(s.type === 'graph' ? { force: { ...(s.force as object), repulsion: 70, gravity: 0.22, edgeLength: [18, 55], friction: 0.2, ...(force ?? {}) } } : {}),
  }))
  return { ...opt, series }
}

/** Inline SVG sparkline for table cells: hundreds of rows, so no chart instance per row. */
export function MiniSpark({ values, width = 84, height = 22, color = 'var(--accent)' }: { values: number[]; width?: number; height?: number; color?: string }) {
  if (!values.length || values.every((x) => !x)) return <span className="muted">—</span>
  const max = Math.max(1, ...values)
  const step = values.length > 1 ? width / (values.length - 1) : width
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(height - 2 - (v / max) * (height - 4)).toFixed(1)}`).join(' ')
  return (
    <svg width={width} height={height} aria-hidden style={{ display: 'block' }}>
      <polyline points={`0,${height - 1} ${pts} ${width},${height - 1}`} fill={`color-mix(in srgb, ${color} 18%, transparent)`} stroke="none" />
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.6} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  )
}

/** Shrink a radar so long axis names stay inside narrow cards. */
export function fitRadar<T>(opt: T, radius = '56%'): T {
  const o = opt as Record<string, any>
  return { ...o, radar: { ...o.radar, radius, axisName: { ...(o.radar?.axisName ?? {}), fontSize: 10 } } } as T
}

/** Move a ratio gauge's caption below the ring (the shared default overlaps the arc ends in short cards). */
export function fitGauge<T>(opt: T): T {
  const o = opt as Record<string, any>
  return { ...o, series: o.series.map((s: Record<string, any>) => ({ ...s, center: ['50%', '56%'], radius: '88%', title: { ...s.title, offsetCenter: [0, '62%'] }, detail: { ...s.detail, offsetCenter: [0, '0%'] } })) } as T
}

const luminance = (hex: string) => {
  const h = hex.replace('#', '')
  if (h.length < 6) return 0.5
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255)
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}
/** Funnel labels in white or ink depending on each stage's fill, so pale stages stay legible in both themes. */
export function fitFunnel<T>(opt: T, ink: string): T {
  const o = opt as Record<string, any>
  return { ...o, series: o.series.map((s: Record<string, any>) => ({ ...s, data: s.data.map((d: Record<string, any>) => ({ ...d, label: { color: luminance(String(d.itemStyle?.color ?? '#000')) > 0.55 ? ink : '#fff' } })) })) } as T
}
