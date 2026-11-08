import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { CheckCircle2, Circle, Download } from 'lucide-react'
import { api } from '../../lib/api'
import { PageHeader, Card, DataTable, Badge, VerdictBadge, Pagination, Loading, ErrorState, LinkButton } from '../../components/ui'
import { Drawer } from '../../components/ui/Drawer'
import { FilterBar, FilterChips, SearchInput, Select, Toggle, type ActiveFilter } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ModuleEmpty, RunPipelineButton, isNoData } from '../../components/ui/RunPipelineButton'
import { useFilters } from '../../components/ui/useParams'
import { columns, donut, horizontalBars } from '../../charts/options'
import { countryName } from '../../charts/countries'
import { fmtDate, fmtInt } from '../../lib/format'
import { fmtYm } from '../../lib/viz'
import { landscapeViz, type VictimFilter } from '../../lib/landscapeViz'
import { Country, SRC, SizeBadge, VictimBadges, VictimDetail, Viz, actorHref, monthLabel, useTokens } from './shared'
import type { VictimOut } from '../../lib/types'

const SIZE = 50
const SECTORS = ['Healthcare', 'Manufacturing', 'Professional Services', 'Technology', 'Retail & E-Commerce', 'Financial Services', 'Transportation', 'Education', 'Government & Defense', 'Agriculture and Food Production', 'Energy & Utilities', 'Hospitality', 'Other']
const REGIONS = ['Europe', 'North America', 'LATAM', 'MENA', 'East Asia', 'Southeast Asia', 'South Asia', 'Oceania', 'Sub-Saharan Africa', 'CIS', 'DACH', 'Nordics', 'UK&I', 'Benelux', 'Iberia', 'CEE']
const SIZES = ['enterprise', 'large', 'mid', 'small', 'unknown']
type K = 'sector' | 'region' | 'country' | 'group' | 'month' | 'size_band' | 'q' | 'in_scope' | 'page' | 'id'

export default function Victims() {
  const nav = useNavigate()
  const t = useTokens()
  const f = useFilters<K>()
  const scopeRaw = f.get('in_scope')
  const inScope = !(scopeRaw === '0' || scopeRaw === 'all' || scopeRaw === 'false')
  const filter: VictimFilter = {
    sector: f.get('sector') || undefined, region: f.get('region') || undefined, country: f.get('country') || undefined, group: f.get('group') || undefined,
    month: f.get('month') || undefined, size_band: f.get('size_band') || undefined, q: f.get('q') || undefined, in_scope: inScope ? true : undefined,
  }
  const params = { ...filter, page: f.page, size: SIZE }
  const q = useQuery({ queryKey: ['landscape', 'victims', params], queryFn: () => api.landscape.victims(params), retry: false, placeholderData: (prev) => prev })
  const sum = useQuery({ queryKey: ['landscape', 'victims-summary', filter], queryFn: () => landscapeViz.victimSummary(filter), retry: false, placeholderData: (prev) => prev })
  const scope = useQuery({ queryKey: ['scope'], queryFn: api.scope.get })
  const [sel, setSel] = useState<VictimOut | null>(null)
  const [qText, setQText] = useState(f.get('q'))
  useEffect(() => { const id = setTimeout(() => { if (qText !== f.get('q')) f.set('q', qText) }, 300); return () => clearTimeout(id) }, [qText]) // eslint-disable-line react-hooks/exhaustive-deps
  const deepId = f.get('id')
  const deep = useQuery({ queryKey: ['landscape', 'victim', deepId], enabled: !!deepId, queryFn: () => api.landscape.victim(Number(deepId)) })
  useEffect(() => { if (deep.data) setSel(deep.data) }, [deep.data])

  const s = sum.data
  const sq = { isLoading: sum.isLoading, isError: sum.isError, error: sum.error, isFetching: sum.isFetching, refetch: sum.refetch }
  const charts = useMemo(() => s && {
    months: columns(s.months.map((m) => ({ label: fmtYm(m.key), value: m.count, title: monthLabel(m.key) })), t, { unit: 'victims', showValues: true }),
    countries: horizontalBars(s.countries.slice(0, 8).map((c) => ({ label: c.key === '??' ? 'Unknown' : countryName(c.key), value: c.count })), t, { unit: 'victims', labelWidth: 96 }),
    groups: horizontalBars(s.groups.slice(0, 8).map((c) => ({ label: c.key, value: c.count })), t, { unit: 'victims', labelWidth: 96, color: t.series[1] }),
    sizes: donut(s.sizes.map((c) => ({ name: c.key, value: c.count, color: c.key === 'unknown' ? t.other : undefined })), t, { centerLabel: 'victims', legend: 'bottom' }),
  }, [s, t])

  const chips: ActiveFilter[] = [
    ...(inScope && scope.data ? [{ key: 'in_scope', label: `In scope: ${scope.data.landscape.sector} · ${scope.data.landscape.region}`, onRemove: () => f.set('in_scope', '0') }] : []),
    ...(['sector', 'region', 'country', 'group', 'month', 'size_band', 'q'] as K[]).filter((k) => f.get(k)).map((k) => ({
      key: k, label: `${k === 'size_band' ? 'size' : k}: ${k === 'country' ? countryName(f.get(k)) : k === 'month' ? monthLabel(f.get(k)) : f.get(k)}`, onRemove: () => { f.set(k, ''); if (k === 'q') setQText('') },
    })),
  ]

  const header = (
    <PageHeader kicker="P6 · Threat landscape" title="Victim tracker"
      subtitle={<>Leak-site victims from ransomware.live (cross-checked against RansomLook), classified by sector, region and size.</>}
      actions={<><LinkButton href={api.landscape.exportUrl('victims-csv')}><Download size={14} /> Victims CSV</LinkButton><RunPipelineButton name="landscape" label="Run pipeline" variant="secondary" size="sm" /></>} />
  )
  if (q.isLoading) return <>{header}<Loading rows={8} /></>
  if (q.error && !isNoData(q.error)) return <>{header}<ErrorState error={q.error} /></>
  if (!q.data) return <>{header}<Card><ModuleEmpty pipeline="landscape" title="No victims ingested yet" /></Card></>

  return (
    <>
      {header}
      <FilterBar>
        <Toggle pressed={inScope} onChange={(v) => f.set('in_scope', v ? '' : '0')}>{inScope ? <CheckCircle2 size={14} /> : <Circle size={14} />} In scope only</Toggle>
        <SearchInput value={qText} onChange={setQText} placeholder="Search victim, domain, description, actor…" />
        <Select value={f.get('sector')} onChange={(v) => f.set('sector', v)} label="Sector" options={[{ value: '', label: 'All sectors' }, ...SECTORS.map((x) => ({ value: x, label: x }))]} />
        <Select value={f.get('region')} onChange={(v) => f.set('region', v)} label="Region" options={[{ value: '', label: 'All regions' }, ...REGIONS.map((x) => ({ value: x, label: x }))]} />
        <Select value={f.get('country')} onChange={(v) => f.set('country', v)} label="Country" options={[{ value: '', label: 'All countries' }, ...(s?.countries ?? []).filter((c) => c.key !== '??').map((c) => ({ value: c.key, label: `${countryName(c.key)} (${c.count})` })), ...(f.get('country') && !s?.countries.some((c) => c.key === f.get('country')) ? [{ value: f.get('country'), label: countryName(f.get('country')) }] : [])]} />
        <Select value={f.get('group')} onChange={(v) => f.set('group', v)} label="Actor" options={[{ value: '', label: 'All actors' }, ...(s?.group_options ?? []).map((c) => ({ value: c.key, label: `${c.key} (${c.count})` })), ...(f.get('group') && !s?.group_options.some((c) => c.key === f.get('group')) ? [{ value: f.get('group'), label: f.get('group') }] : [])]} />
        <Select value={f.get('month')} onChange={(v) => f.set('month', v)} label="Month" options={[{ value: '', label: 'All months' }, ...(s?.months ?? []).slice().reverse().map((m) => ({ value: m.key, label: `${monthLabel(m.key)} (${m.count})` }))]} />
        <Select value={f.get('size_band')} onChange={(v) => f.set('size_band', v)} label="Size" options={[{ value: '', label: 'All sizes' }, ...SIZES.map((x) => ({ value: x, label: x }))]} />
      </FilterBar>
      <FilterChips filters={chips} onClear={() => { f.clear(); setQText('') }} count={<span><b style={{ color: 'var(--text)' }}>{fmtInt(q.data.page.total)}</b> victims{s ? <> · {Math.round((s.cross_source / Math.max(1, s.total)) * 100)}% confirmed by a second source</> : null}</span>} />

      <Grid>
        <Span n={3}><Viz title="Postings by month" question="When were these victims posted?" source={SRC.rl} query={sq} height={190} option={charts?.months ?? null} empty={!s?.months.length}
          table={{ columns: ['month', 'victims'], rows: (s?.months ?? []).map((m) => [monthLabel(m.key), m.count]) }}
          onEvents={{ click: (p) => { const m = s?.months[p.dataIndex]?.key; if (m) f.set('month', m) } }} /></Span>
        <Span n={3}><Viz title="Countries" question="Where are they?" source={SRC.rl} query={sq} height={190} option={charts?.countries ?? null} empty={!s?.countries.length}
          table={{ columns: ['country', 'victims'], rows: (s?.countries ?? []).map((c) => [countryName(c.key), c.count]) }}
          onEvents={{ click: (p) => { const c = s?.countries[p.dataIndex]?.key; if (c && c !== '??') f.set('country', c) } }} /></Span>
        <Span n={3}><Viz title="Actors" question="Who posted them?" source={SRC.rl} query={sq} height={190} option={charts?.groups ?? null} empty={!s?.groups.length}
          table={{ columns: ['actor', 'victims'], rows: (s?.groups ?? []).map((c) => [c.key, c.count]) }}
          onEvents={{ click: (p) => { const g = s?.groups[p.dataIndex]?.key; if (g) f.set('group', g) } }} /></Span>
        <Span n={3}><Viz title="Organisation size" question="How big are the victims?" source={SRC.rl} query={sq} height={190} option={charts?.sizes ?? null} empty={!s?.sizes.length}
          caveat="from revenue / headcount in the leak post" table={{ columns: ['size', 'victims'], rows: (s?.sizes ?? []).map((c) => [c.key, c.count]) }}
          onEvents={{ click: (p) => p.name && f.set('size_band', p.name) }} /></Span>
      </Grid>

      <DataTable<VictimOut> rows={q.data.items} rowKey={(v) => v.id} onRowClick={(v) => { setSel(v); f.set('id', v.id, false) }}
        empty={<Card><ModuleEmpty pipeline="landscape" title="No victims match these filters" hint="Clear a filter or widen the scope." /></Card>}
        columns={[
          { key: 'v', header: 'Victim', sort: (v) => v.victim.toLowerCase(), render: (v) => <div style={{ minWidth: 0, maxWidth: 300 }}><div style={{ color: 'var(--text)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v.victim}>{v.victim}</div>{v.domain && <div className="mono muted" style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.domain}</div>}</div> },
          { key: 'g', header: 'Actor', sort: (v) => v.group.toLowerCase(), render: (v) => <Link onClick={(e) => e.stopPropagation()} to={actorHref(v.group)}>{v.group}</Link> },
          { key: 's', header: 'Sector', sort: (v) => v.sector ?? '', render: (v) => <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{v.sector ?? <span className="muted">unknown</span>}{v.sector_method !== 'source' && <Badge tone="info">{v.sector_method}</Badge>}</span> },
          { key: 'c', header: 'Country', sort: (v) => v.country ?? '', render: (v) => <Country cc={v.country} region={v.region} /> },
          { key: 'z', header: 'Size', sort: (v) => SIZES.indexOf(v.size_band), render: (v) => <SizeBadge band={v.size_band} /> },
          { key: 'd', header: 'Posted', align: 'right', sort: (v) => v.discovered ?? '', render: (v) => <span className="num">{fmtDate(v.discovered)}</span> },
          { key: 'x', header: '2 sources', render: (v) => (v.cross_source_match ? <CheckCircle2 size={15} style={{ color: 'var(--good)' }} aria-label="confirmed" /> : <Circle size={15} style={{ color: 'var(--text-3)' }} aria-label="single source" />) },
          { key: 'r', header: 'Review', render: (v) => <VerdictBadge verdict={v.review_verdict} /> },
        ]} />
      <Pagination page={q.data.page.page} size={q.data.page.size} total={q.data.page.total} onPage={f.setPage} />

      <Drawer open={!!sel} onClose={() => { setSel(null); f.set('id', '', false) }} kind="Victim" title={sel?.victim} subtitle={sel ? <>{sel.group} · {sel.sector ?? 'unknown sector'} · {countryName(sel.country)} · posted {fmtDate(sel.discovered)}</> : undefined}
        badges={sel ? <VictimBadges v={sel} /> : undefined}>
        {sel && <>
          <VictimDetail v={sel} />
          <div style={{ marginTop: 16, display: 'flex', gap: 8 }}><button className="btn" onClick={() => nav(actorHref(sel.group))}>Open {sel.group} profile</button></div>
        </>}
      </Drawer>
    </>
  )
}
