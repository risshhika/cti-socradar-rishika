import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Download, Users } from 'lucide-react'
import { api } from '../../lib/api'
import { PageHeader, Card, DataTable, StatusBadge, Loading, ErrorState, LinkButton } from '../../components/ui'
import { FilterBar, SearchInput, Select, StatStrip, Toggle } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ModuleEmpty, isNoData } from '../../components/ui/RunPipelineButton'
import { useFilters } from '../../components/ui/useParams'
import { bubbles, donut, horizontalBars } from '../../charts/options'
import { fmtDate, fmtInt } from '../../lib/format'
import type { ActorOut } from '../../lib/types'
import { landscapeViz } from '../../lib/landscapeViz'
import { ActorSpark, SRC, TrendBadge, Viz, monthLabel, useTokens, useViz } from './shared'

const TRENDS = ['rising', 'new', 'flat', 'falling']
/** Keep trend colours identical across the bubble chart and the momentum donut. */
const recolor = (o: any, colors: string[]) => { (o.series ?? []).forEach((s: any, i: number) => { s.itemStyle = { ...s.itemStyle, color: `${colors[i]}bb`, borderColor: colors[i] } }); o.color = colors; return o }

export default function Actors() {
  const nav = useNavigate()
  const t = useTokens()
  const f = useFilters<'scope_only' | 'q' | 'status' | 'trend'>()
  const scopeOnly = f.get('scope_only') === '1'
  const [qText, setQText] = useState(f.get('q'))
  const q = useQuery({ queryKey: ['landscape', 'actors', scopeOnly, f.get('status')], queryFn: () => landscapeViz.actors({ scope_only: scopeOnly || undefined, status: f.get('status') || undefined }), retry: false })
  const viz = useViz(6)
  const scope = useQuery({ queryKey: ['scope'], queryFn: api.scope.get })
  const months = viz.data?.months ?? []
  const vq = { isLoading: viz.isLoading || q.isLoading, isError: viz.isError, error: viz.error, isFetching: viz.isFetching, refetch: viz.refetch }

  const rows = useMemo(() => {
    const needle = qText.trim().toLowerCase()
    return (q.data ?? []).filter((a) => (!needle || a.name.toLowerCase().includes(needle) || a.aliases.some((x) => x.toLowerCase().includes(needle)))
      && (!f.get('trend') || a.trend === f.get('trend')))
  }, [q.data, qText, f])
  const countries = useMemo(() => new Map((viz.data?.actors ?? []).map((a) => [a.name.toLowerCase(), a.countries])), [viz.data])

  const charts = useMemo(() => {
    const active = rows.filter((a) => a.victim_count_window > 0)
    const top = [...active].sort((a, b) => b.victim_count_window - a.victim_count_window).slice(0, 60)
    const trendColors = [t.series[1], t.series[6], t.other, t.series[2]]
    const trendCount = TRENDS.map((tr) => ({ name: tr, value: active.filter((a) => a.trend === tr).length }))
    return {
      bubbles: recolor(bubbles(top.map((a) => ({ name: a.name, x: a.victim_count_window, y: a.victim_count_scope, size: countries.get(a.name.toLowerCase()) ?? 1, category: Math.max(0, TRENDS.indexOf(a.trend)) })), t,
        { xName: 'victims in window (log)', yName: 'in-scope victims', xLog: true, categories: TRENDS }), trendColors),
      scope: horizontalBars([...active].filter((a) => a.victim_count_scope > 0).sort((a, b) => b.victim_count_scope - a.victim_count_scope).slice(0, 10).map((a) => ({ label: a.name, value: a.victim_count_scope })), t, { unit: 'in-scope victims', labelWidth: 100, color: t.series[1] }),
      trends: donut(trendCount.map((x, i) => ({ ...x, color: trendColors[i] })), t, { centerLabel: 'active actors', legend: 'bottom' }),
      top: top.length,
    }
  }, [rows, t, countries])

  const header = (
    <PageHeader kicker="P6 · Threat landscape" title="Ransomware actors"
      subtitle={<>Every group tracked on public leak-site aggregators, ranked by activity in the window{scope.data ? <> and against {scope.data.landscape.sector} · {scope.data.landscape.region}</> : null}.</>}
      actions={<LinkButton href={api.landscape.exportUrl('actors-csv')}><Download size={14} /> Actors CSV</LinkButton>} />
  )
  if (q.isLoading) return <>{header}<Loading rows={8} /></>
  if (q.error && !isNoData(q.error)) return <>{header}<ErrorState error={q.error} /></>
  if (!q.data?.length && !scopeOnly) return <>{header}<Card><ModuleEmpty pipeline="landscape" title="No actors ingested yet" icon={<Users size={24} />} /></Card></>
  const all = q.data ?? []
  const active = all.filter((a) => a.victim_count_window > 0)

  return (
    <>
      {header}
      <StatStrip items={[
        { label: 'Actors listed', value: fmtInt(all.length), sub: scopeOnly ? 'hitting the scope' : 'on ransomware.live' },
        { label: 'Posting in window', value: fmtInt(active.length), sub: months.length ? `${monthLabel(months[0])} – ${monthLabel(months[months.length - 1])}` : undefined },
        { label: 'Hitting our scope', value: fmtInt(all.filter((a) => a.victim_count_scope > 0).length), sub: scope.data ? `${scope.data.landscape.sector} · ${scope.data.landscape.region}` : undefined },
        { label: 'Rising', value: fmtInt(active.filter((a) => a.trend === 'rising').length), sub: '≥ +25% month on month' },
        { label: 'New', value: fmtInt(active.filter((a) => a.trend === 'new').length), sub: 'nothing the month before' },
        { label: 'Dormant', value: fmtInt(all.filter((a) => a.status === 'dormant').length), sub: 'no post in 60 days' },
      ]} />
      <Grid>
        <Span n={6}>
          <Viz title="Volume vs relevance" question="Which groups are big overall, and which of them actually hit companies like us?" source={SRC.rl} query={vq} height={340} option={charts.bubbles} empty={!charts.top}
            caveat="bubble size: countries hit · colour: trend" onEvents={{ click: (p) => p.data?.name && nav(`/landscape/actors/${encodeURIComponent(rows.find((a) => a.name === p.data.name)?.slug ?? p.data.name)}`) }} />
        </Span>
        <Span n={3}>
          <Viz title="Top actors in scope" question="Who posts our sector in our region most?" source={SRC.rl} query={vq} height={340} option={charts.scope}
            onEvents={{ click: (p) => { const a = rows.find((x) => x.name === p.name); if (a) nav(`/landscape/actors/${encodeURIComponent(a.slug)}`) } }} />
        </Span>
        <Span n={3}>
          <Viz title="Momentum" question="How many active groups are accelerating?" source={SRC.rl} query={vq} height={340} option={charts.trends}
            onEvents={{ click: (p) => p.name && f.set('trend', f.get('trend') === p.name ? '' : p.name) }} caveat="click to filter" />
        </Span>
      </Grid>
      <FilterBar>
        <Toggle pressed={scopeOnly} onChange={(v) => f.set('scope_only', v ? '1' : '')}>Hitting scope only</Toggle>
        <SearchInput value={qText} onChange={setQText} placeholder="Search actor or alias…" />
        <Select value={f.get('status')} onChange={(v) => f.set('status', v)} label="Status" options={[{ value: '', label: 'Any status' }, { value: 'active', label: 'Active' }, { value: 'dormant', label: 'Dormant' }]} />
        <Select value={f.get('trend')} onChange={(v) => f.set('trend', v)} label="Trend" options={[{ value: '', label: 'Any trend' }, ...TRENDS.map((x) => ({ value: x, label: x }))]} />
        <span className="muted" style={{ fontSize: 12.5, marginLeft: 'auto' }}>{fmtInt(rows.length)} actors</span>
      </FilterBar>
      <DataTable<ActorOut> rows={rows} rowKey={(a) => a.id} onRowClick={(a) => nav(`/landscape/actors/${encodeURIComponent(a.slug)}`)} maxHeight="70vh"
        empty={<Card><ModuleEmpty pipeline="landscape" title="No actors match" hint="Clear the search or toggle off the scope filter." /></Card>}
        columns={[
          { key: 'n', header: 'Actor', sort: (a) => a.name.toLowerCase(), render: (a) => <div><b style={{ color: 'var(--text)' }}>{a.name}</b>{a.aliases.length > 0 && <div className="muted" style={{ fontSize: 11 }}>aka {a.aliases.slice(0, 2).join(', ')}</div>}</div> },
          { key: 's', header: 'Status', sort: (a) => a.status, render: (a) => <StatusBadge status={a.status} /> },
          { key: 'w', header: 'Window', align: 'right', sort: (a) => a.victim_count_window, render: (a) => fmtInt(a.victim_count_window) },
          { key: 'sc', header: 'In scope', align: 'right', sort: (a) => a.victim_count_scope, render: (a) => (a.victim_count_scope ? <b style={{ color: 'var(--text)' }}>{a.victim_count_scope}</b> : <span className="muted">0</span>) },
          { key: 'tot', header: 'All time', align: 'right', sort: (a) => a.victim_count_total, render: (a) => fmtInt(a.victim_count_total) },
          { key: 'c', header: 'Countries', align: 'right', sort: (a) => countries.get(a.name.toLowerCase()) ?? 0, render: (a) => countries.get(a.name.toLowerCase()) ?? <span className="muted">—</span> },
          { key: 'sp', header: 'Monthly', render: (a) => <ActorSpark actor={a} months={months} /> },
          { key: 't', header: 'Trend', sort: (a) => a.mom_change ?? -99, render: (a) => <TrendBadge trend={a.trend} mom={a.mom_change} /> },
          { key: 'ts', header: 'Top sectors', render: (a) => <span className="muted">{a.top_sectors.slice(0, 2).map((x) => x.key).join(', ') || '—'}</span> },
          { key: 'l', header: 'Last post', align: 'right', sort: (a) => a.last_seen ?? '', render: (a) => <span className="num">{fmtDate(a.last_seen)}</span> },
        ]} />
    </>
  )
}
