import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Download, FileText, Radar } from 'lucide-react'
import { api } from '../../lib/api'
import { PageHeader, Card, DataTable, Badge, StatusBadge, Loading, ErrorState, LinkButton } from '../../components/ui'
import { KpiTile } from '../../components/ui/KpiTile'
import { Grid, Span, KpiRow, SectionLabel } from '../../components/ui/Grid'
import { Segmented } from '../../components/ui/controls'
import { RunPipelineButton, ModuleEmpty, isNoData } from '../../components/ui/RunPipelineButton'
import {
  bumpChart, calendarHeatmap, horizontalBars, matrixHeatmap, ratioGauge, sankey, shareColumns, streamGraph, sunburst, timeSeries,
  treemap, worldChoropleth, boxplot,
} from '../../charts/options'
import { countryName } from '../../charts/countries'
import { fmtYm, fmtNum } from '../../lib/viz'
import { fmtAgo, fmtUsd } from '../../lib/format'
import { lastFullIdx } from '../../lib/landscapeViz'
import type { ActorOut } from '../../lib/types'
import { ActorSpark, SRC, TrendBadge, Viz, actorHref, contrastLabels, monthLabel, tuneMap, tuneSunburst, useTokens, useViz, useWindow } from './shared'

/** Room for a two-line legend above the plot. */
const withTop = (o: any, top: number) => { if (o?.grid) o.grid.top = top; return o }
const withRiverTop = (o: any, top: number) => { if (o?.singleAxis) o.singleAxis.top = top; return o }
const usd = (v: number) => (v >= 1000 ? `$${Math.round(v / 100) / 10}k` : `$${v}`)

export default function LandscapeDashboard() {
  const nav = useNavigate()
  const t = useTokens()
  const [w, setW] = useWindow()
  const [mapScope, setMapScope] = useState<'world' | 'europe'>('europe')
  const [mapData, setMapData] = useState<'sector' | 'all'>('sector')
  const [amMode, setAmMode] = useState<'scope' | 'region'>('region')
  const viz = useViz(w)
  const stats = useQuery({ queryKey: ['landscape', 'stats', w], queryFn: () => api.landscape.stats({ months: w }), retry: false })
  const briefs = useQuery({ queryKey: ['landscape', 'briefings'], queryFn: api.landscape.briefings, retry: false })
  const d = viz.data
  const s = stats.data
  const q = { isLoading: viz.isLoading, isError: viz.isError, error: viz.error, isFetching: viz.isFetching, refetch: viz.refetch }

  const months = d?.months ?? []
  const li = lastFullIdx(months)
  const labels = months
  const partial = d?.partial_month
  const sector = d?.sector ?? s?.sector ?? ''
  const region = d?.region ?? s?.region ?? ''

  const opts = useMemo(() => {
    if (!d) return null
    const x = d.months
    const calRange: [string, string] = [`${x[0]}-01`, new Date().toISOString().slice(0, 10)]
    const am = d.actor_month[amMode]
    const secNames = Object.keys(d.sector_month.series)
    const riverRows: [string, number, string][] = secNames.flatMap((n) => d.sector_month.series[n].map((v, i) => [`${x[i]}-01`, v, n] as [string, number, string]))
    const iabTypes = Object.keys(d.iab.price_by_access)
    return {
      world: tuneMap(worldChoropleth(mapData === 'sector' ? d.world.sector : d.world.all, t, { unit: 'victims', highlight: d.world.region_countries, zoomTo: mapScope }), mapData === 'sector' ? d.world.sector : d.world.all, d.world.region_countries, mapScope === 'europe'),
      sunburst: tuneSunburst(sunburst(d.sunburst.map((r) => ({ name: r.name, children: (r.children ?? []).map((c) => ({ name: c.name === 'Other' || c.name === '??' ? c.name : countryName(c.name), value: c.value })) })), t, { unit: 'victims' })),
      tempo: timeSeries(x, [
        { name: `In scope · ${sector} · ${region}`, data: d.series.scope, type: 'bar', color: t.series[0] },
        { name: `${sector} · worldwide`, data: d.series.sector, yAxisIndex: 1, color: t.series[1] },
        { name: `${region} · all sectors`, data: d.series.region, yAxisIndex: 1, color: t.series[2], dashed: true },
      ], t, { rightAxisName: 'context', markX: partial, markText: 'partial' }),
      calendar: calendarHeatmap(d.calendar.scope, calRange, t, 'in-scope postings', 24),
      actorMonth: contrastLabels(matrixHeatmap(x, am.actors, am.cells, t, { unit: 'victims', xFormat: fmtYm, showValues: true, yWidth: 100 })),
      bump: bumpChart(x, d.bump.actors.map((a) => ({ name: a, ranks: d.bump.ranks[a].map((r) => (r != null && r <= 20 ? r : null)) })), t, { maxRank: Math.min(d.bump.max_rank, 20) }),
      sankey: sankey(d.sankey.nodes, d.sankey.links, t, { unit: 'victims' }),
      share: withTop(shareColumns(x, secNames.map((n) => ({ name: n, data: d.sector_month.series[n] })), t), 64),
      river: withRiverTop(streamGraph(riverRows, secNames, t, { unit: 'victims' }), 64),
      sectorRegion: contrastLabels(matrixHeatmap(d.sector_region.regions, d.sector_region.sectors, d.sector_region.cells, t, { unit: 'victims', showValues: true, yWidth: 150 })),
      sizeTree: treemap(d.size_tree, t, { unit: 'victims' }),
      crossGauge: ratioGauge(d.series.cross_rate[li] ?? null, t, { label: `confirmed · ${fmtYm(x[li])}` }),
      crossMonth: timeSeries(x, [{ name: 'Agreement', data: d.cross_source.by_month.map((c) => (c.rate == null ? null : Math.round(c.rate * 1000) / 10)), area: true }], t, { percent: true, legend: false }),
      crossActor: horizontalBars([...d.cross_source.by_actor].sort((a, b) => a.rate - b.rate).slice(0, 8).map((c) => ({ label: c.actor, value: Math.round(c.rate * 100) })), t, { unit: '% confirmed', labelWidth: 100 }),
      price: iabTypes.length ? boxplot(iabTypes, iabTypes.map((k) => d.iab.price_by_access[k]), t, { log: true, yFormat: usd, yName: 'USD' }) : null,
    }
  }, [d, t, mapData, mapScope, amMode, li, partial, sector, region])

  const header = (
    <PageHeader kicker="P6 · Threat landscape" title="Sector dashboard"
      subtitle={d ? <>{sector} · {region} · {monthLabel(months[0])} – {monthLabel(months[months.length - 1])} <span className="muted">({monthLabel(partial)} is partial; KPIs compare the last full month)</span>{s?.last_run && <> · data {fmtAgo(s.last_run.finished_at)}</>}</> : 'Who is targeting companies like us, and how?'}
      actions={<>
        <Segmented value={String(w)} onChange={(v) => setW(Number(v))} options={[{ value: '3', label: '3 mo' }, { value: '6', label: '6 mo' }, { value: '12', label: '12 mo' }]} label="Window" />
        <LinkButton href={api.landscape.exportUrl('victims-csv')}><Download size={14} /> Victims CSV</LinkButton>
        <Link to="/landscape/briefings" className="btn btn-ghost" style={{ textDecoration: 'none' }}><FileText size={14} /> Briefings</Link>
        <RunPipelineButton name="landscape" label="Run pipeline" size="sm" />
      </>} />
  )
  if (viz.isLoading) return <>{header}<Loading rows={8} /></>
  if (viz.error && !isNoData(viz.error)) return <>{header}<ErrorState error={viz.error} onRetry={() => viz.refetch()} /></>
  if (!d || !d.series.total.some(Boolean)) return <>{header}<Card><ModuleEmpty pipeline="landscape" title="No leak-site data ingested yet" icon={<Radar size={24} />} /></Card></>

  const sum = (a: number[]) => a.reduce((x, y) => x + y, 0)
  const mLabel = monthLabel(months[li])
  const latestBrief = briefs.data?.[0]
  const topCountries = [...(mapData === 'sector' ? d.world.sector : d.world.all)].sort((a, b) => b.value - a.value)
  const crossNow = d.series.cross_rate[li]
  const crossPrev = d.series.cross_rate[li - 1]

  return (
    <>
      {header}
      <KpiRow>
        <KpiTile kpi={{ label: 'Victims in scope', value: d.series.scope[li], prev: d.series.scope[li - 1], window: mLabel, spark: d.series.scope, sparkLabels: labels, source: SRC.rl, note: `${fmtNum(sum(d.series.scope))} in window`, to: '/landscape/victims' }} />
        <KpiTile kpi={{ label: `${sector} worldwide`, value: d.series.sector[li], prev: d.series.sector[li - 1], window: mLabel, spark: d.series.sector, sparkLabels: labels, source: SRC.rl, note: 'all regions', to: `/landscape/victims?in_scope=all&sector=${encodeURIComponent(sector)}` }} />
        <KpiTile kpi={{ label: `${region} · all sectors`, value: d.series.region[li], prev: d.series.region[li - 1], window: mLabel, spark: d.series.region, sparkLabels: labels, source: SRC.rl, note: 'regional pressure', to: `/landscape/victims?in_scope=all&region=${encodeURIComponent(region)}` }} />
        <KpiTile kpi={{ label: 'Actors hitting scope', value: d.series.scope_actors[li], prev: d.series.scope_actors[li - 1], window: mLabel, spark: d.series.scope_actors, sparkLabels: labels, source: SRC.rl, note: 'distinct groups', to: '/landscape/actors?scope_only=1' }} />
      </KpiRow>
      <KpiRow>
        <KpiTile kpi={{ label: 'Cross-source agreement', value: crossNow == null ? null : Math.round(crossNow * 100), prev: crossPrev == null ? null : Math.round(crossPrev * 100), suffix: '%', upIsBad: false, window: mLabel, spark: d.series.cross_rate.map((r) => (r == null ? 0 : Math.round(r * 100))), sparkLabels: labels, source: SRC.rlx, note: 'victims seen on both' }} />
        <KpiTile kpi={{ label: 'Access-broker reports', value: d.series.iab[li], prev: d.series.iab[li - 1], upIsBad: null, window: mLabel, spark: d.series.iab, sparkLabels: labels, source: SRC.iab, note: `${d.iab.listings} relevant in window`, to: '/landscape/iab' }} />
        <KpiTile kpi={{ label: 'Median access price', value: d.iab.price_median, format: (n) => fmtUsd(n), window: 'window', source: SRC.iab, note: `${d.iab.with_price} priced listing${d.iab.with_price === 1 ? '' : 's'}`, to: '/landscape/iab' }} />
        <KpiTile kpi={{ label: 'Public breach reports', value: d.series.incidents[li], prev: d.series.incidents[li - 1], upIsBad: null, window: mLabel, spark: d.series.incidents, sparkLabels: labels, source: SRC.incidents, note: `${sum(d.series.incidents_scope)} in scope` }} />
      </KpiRow>

      <SectionLabel>Where and when</SectionLabel>
      <div className="analyst-only" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}>
        <span className="muted" style={{ fontSize: 12 }}>Map</span>
        <Segmented value={mapData} onChange={setMapData} options={[{ value: 'sector', label: sector || 'Sector' }, { value: 'all', label: 'All sectors' }]} label="Map dataset" />
        <Segmented value={mapScope} onChange={setMapScope} options={[{ value: 'europe', label: 'Europe' }, { value: 'world', label: 'World' }]} label="Map zoom" />
      </div>
      <Grid>
        <Span n={8}>
          <Viz title={mapData === 'sector' ? `${sector} victims by country` : 'All victims by country'} question={`Where are ${mapData === 'sector' ? sector.toLowerCase() : 'all'} organisations being posted? ${region} countries are outlined.`}
            source={SRC.rl} query={q} height={380} option={opts?.world ?? null} needsWorld empty={!topCountries.length}
            table={{ columns: ['country', 'victims'], rows: topCountries.slice(0, 30).map((c) => [countryName(c.iso2), c.value]) }}
            onEvents={{ click: (p) => { const cc = p.data?.iso?.[0]; if (cc) nav(`/landscape/victims?in_scope=all&country=${cc}${mapData === 'sector' ? `&sector=${encodeURIComponent(sector)}` : ''}`) } }}
            caveat="click a country to open its victims" />
        </Span>
        <Span n={4}>
          <Viz title="Region › country" question={`How is ${sector.toLowerCase()} exposure split across regions?`} source={SRC.rl} query={q} height={380} option={opts?.sunburst ?? null} empty={!d.sunburst.length}
            table={{ columns: ['region', 'country', 'victims'], rows: d.sunburst.flatMap((r) => (r.children ?? []).map((c) => [r.name, countryName(c.name), c.value ?? 0])) }} caveat="click a ring to drill in" />
        </Span>
        <Span n={6}>
          <Viz title="Posting tempo" question="Is pressure on our sector and region rising, and does it track the wider landscape?" source={SRC.rl} query={q} height={260} option={opts?.tempo ?? null}
            table={{ columns: ['month', 'in scope', `${sector} worldwide`, `${region} all sectors`], rows: months.map((m, i) => [fmtYm(m), d.series.scope[i], d.series.sector[i], d.series.region[i]]) }}
            caveat="bars: in scope (left axis) · lines: context (right axis)" />
        </Span>
        <Span n={6}>
          <Viz title="In-scope postings by day" question="Do leak-site postings against us come in bursts?" source={SRC.rl} query={q} height={260} option={opts?.calendar ?? null} empty={!d.calendar.scope.length}
            table={{ columns: ['day', 'postings'], rows: d.calendar.scope.map(([day, n]) => [day, n]) }} caveat="posting date" />
        </Span>
      </Grid>

      <SectionLabel>Who is doing it</SectionLabel>
      <Grid>
        <Span n={6}>
          <Viz title="Actor activity by month" question={amMode === 'scope' ? 'Which groups post our sector in our region, month by month?' : `Which groups are most active in ${region}, month by month?`} source={SRC.rl} query={q} height={420}
            option={opts?.actorMonth ?? null} empty={!d.actor_month[amMode].actors.length}
            actions={<Segmented value={amMode} onChange={setAmMode} options={[{ value: 'region', label: `${region}` }, { value: 'scope', label: 'In scope' }]} label="Population" />}
            table={{ columns: ['actor', ...months.map(fmtYm)], rows: d.actor_month[amMode].actors.map((a, yi) => [a, ...months.map((_, xi) => d.actor_month[amMode].cells.find((c) => c[0] === xi && c[1] === yi)?.[2] ?? 0)]) }}
            onEvents={{ click: (p) => { const a = d.actor_month[amMode].actors[p.value?.[1]]; if (a) nav(actorHref(a)) } }} />
        </Span>
        <Span n={6}>
          <Viz title="Leaderboard over time" question="Which of the biggest groups overtook whom, worldwide?" source={SRC.rl} query={q} height={420} option={opts?.bump ?? null}
            table={{ columns: ['actor', ...months.map(fmtYm)], rows: d.bump.actors.map((a) => [a, ...d.bump.ranks[a].map((r) => (r == null ? '—' : `#${r}`))]) }}
            onEvents={{ click: (p) => p.seriesName && nav(actorHref(p.seriesName)) }} caveat="rank among all groups posting that month · off the chart below #20" />
        </Span>
        <Span n={12}>
          <Viz title="Targeting flow" question="Where do the ten busiest groups aim: which sectors, which regions?" source={SRC.rl} query={q} height={480} option={opts?.sankey ?? null}
            table={{ columns: ['from', 'to', 'victims'], rows: d.sankey.links.map((l) => [l.source.trim(), l.target.trim(), l.value]) }}
            onEvents={{ click: (p) => { if (p.dataType === 'node' && d.bump.actors.concat(d.sankey.nodes.filter((n) => n.depth === 0).map((n) => n.name)).includes(p.name)) nav(actorHref(p.name)) } }}
            caveat="actor → sector → region · sector→region widths scaled to the shown actors" />
        </Span>
        <Span n={12}>
          <Card title="Actor movers" subtitle="Biggest groups by the last two months, with their in-window trend (last two full months, ±25%)" actions={<Link to="/landscape/actors" className="secondary">All actors →</Link>}>
            <DataTable<ActorOut> rows={s?.actor_trends ?? []} rowKey={(a) => a.id} dense onRowClick={(a) => nav(`/landscape/actors/${encodeURIComponent(a.slug)}`)} columns={[
              { key: 'n', header: 'Actor', render: (a) => <b style={{ color: 'var(--text)' }}>{a.name}</b>, sort: (a) => a.name },
              { key: 's', header: 'Status', render: (a) => <StatusBadge status={a.status} /> },
              { key: 'w', header: 'Window', align: 'right', render: (a) => fmtNum(a.victim_count_window), sort: (a) => a.victim_count_window },
              { key: 'sc', header: 'In scope', align: 'right', render: (a) => (a.victim_count_scope ? <b style={{ color: 'var(--text)' }}>{a.victim_count_scope}</b> : <span className="muted">0</span>), sort: (a) => a.victim_count_scope },
              { key: 'sp', header: 'Monthly', render: (a) => <ActorSpark actor={a} months={s?.months ?? months} /> },
              { key: 't', header: 'Trend', render: (a) => <TrendBadge trend={a.trend} mom={a.mom_change} />, sort: (a) => a.mom_change ?? 0 },
              { key: 'ts', header: 'Top sectors', render: (a) => <span className="muted">{a.top_sectors.slice(0, 2).map((x) => x.key).join(', ')}</span> },
            ]} />
          </Card>
        </Span>
      </Grid>

      <SectionLabel>Sector mix</SectionLabel>
      <Grid>
        <Span n={6}>
          <Viz title={`Sector volume in ${region}`} question="Which sectors carry the load, and who rose or faded?" source={SRC.rl} query={q} height={300} option={opts?.river ?? null}
            table={{ columns: ['sector', ...months.map(fmtYm)], rows: Object.entries(d.sector_month.series).map(([k, v]) => [k, ...v]) }} />
        </Span>
        <Span n={6}>
          <Viz title={`Sector share in ${region}`} question="Is our sector's share of postings growing relative to others?" source={SRC.rl} query={q} height={300} option={opts?.share ?? null} />
        </Span>
        <Span n={6}>
          <Viz title="Sector × region" question="Which region–sector pairs are hottest worldwide?" source={SRC.rl} query={q} height={440} option={opts?.sectorRegion ?? null}
            table={{ columns: ['sector', ...d.sector_region.regions], rows: d.sector_region.sectors.map((sec, yi) => [sec, ...d.sector_region.regions.map((_, xi) => d.sector_region.cells.find((c) => c[0] === xi && c[1] === yi)?.[2] ?? 0)]) }}
            onEvents={{ click: (p) => { const r = d.sector_region.regions[p.value?.[0]]; const sec = d.sector_region.sectors[p.value?.[1]]; if (r && sec) nav(`/landscape/victims?in_scope=all&sector=${encodeURIComponent(sec)}${r !== 'Unknown' ? `&region=${encodeURIComponent(r)}` : ''}`) } }} />
        </Span>
        <Span n={6}>
          <Viz title={`Victim size by sector · ${region}`} question="Are attackers going after large organisations or the long tail?" source={SRC.rl} query={q} height={440} option={opts?.sizeTree ?? null} empty={!d.size_tree.length}
            caveat={`size known for ${d.size_coverage == null ? '—' : Math.round(d.size_coverage * 100)}% of victims (revenue / headcount in the leak post)`}
            table={{ columns: ['sector', 'size', 'victims'], rows: d.size_tree.flatMap((n) => (n.children ?? []).map((c) => [n.name, c.name, c.value ?? 0])) }} />
        </Span>
      </Grid>

      <SectionLabel>Access market and data quality</SectionLabel>
      <Grid>
        <Span n={4}>
          <Viz title="Access prices" question="What does initial access cost, by access type?" source={SRC.iab} query={q} height={240} option={opts?.price ?? null} empty={!opts?.price} emptyText="No prices extracted in this window"
            table={{ columns: ['access type', 'prices (USD)'], rows: Object.entries(d.iab.price_by_access).map(([k, v]) => [k, v.map((p) => fmtUsd(p)).join(', ')]) }}
            caveat={`${d.iab.with_price} of ${d.iab.listings} reports carry a price`} actions={<Link to="/landscape/iab" className="secondary">Brokers →</Link>} />
        </Span>
        <Span n={4}>
          <Viz title="Cross-source agreement" question="How much of the leak-site data is confirmed by a second aggregator?" source={SRC.rlx} query={q} height={240} option={opts?.crossMonth ?? null}
            table={{ columns: ['month', 'victims', 'confirmed', 'rate'], rows: d.cross_source.by_month.map((c) => [fmtYm(c.period), c.n, c.matched, c.rate == null ? '—' : `${Math.round(c.rate * 100)}%`]) }} />
        </Span>
        <Span n={4}>
          <Viz title="Agreement by actor" question="Whose claims are least corroborated (possible re-posts or fakes)? Busiest 12 groups, lowest first." source={SRC.rlx} query={q} height={240} option={opts?.crossActor ?? null}
            table={{ columns: ['actor', 'victims', 'confirmed', 'rate'], rows: d.cross_source.by_actor.map((c) => [c.actor, c.n, c.matched, `${Math.round(c.rate * 100)}%`]) }} />
        </Span>
      </Grid>

      {latestBrief && (
        <Card title="Latest briefing" subtitle={`${latestBrief.sector} · ${latestBrief.region}`} actions={<Link to="/landscape/briefings" className="secondary">All briefings →</Link>}>
          <Link to={`/landscape/briefings/${latestBrief.id}`} style={{ display: 'flex', alignItems: 'center', gap: 14, textDecoration: 'none', color: 'inherit' }}>
            <div style={{ display: 'grid', placeItems: 'center', width: 44, height: 44, borderRadius: 10, background: 'var(--accent-soft)', color: 'var(--accent)' }}><FileText size={20} /></div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, color: 'var(--text)' }}>{latestBrief.title}</div>
              <div className="muted" style={{ fontSize: 12.5 }}>{monthLabel(latestBrief.period)} · generated {fmtAgo(latestBrief.generated_at)}</div>
            </div>
            <StatusBadge status={latestBrief.status} /><Badge tone={latestBrief.generator === 'llm' ? 'accent' : 'neutral'}>{latestBrief.generator}</Badge>
          </Link>
        </Card>
      )}
    </>
  )
}
