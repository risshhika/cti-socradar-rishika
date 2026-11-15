import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileBarChart } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../lib/api'
import { usePhishingViz, qstate, cleanName, SOURCE_LABEL } from '../../lib/phishingViz'
import { PageHeader } from '../../components/ui'
import { KpiTile } from '../../components/ui/KpiTile'
import { Grid, KpiRow, Span, SectionLabel } from '../../components/ui/Grid'
import { RunPipelineButton, ModuleEmpty } from '../../components/ui/RunPipelineButton'
import { useTheme } from '../../theme/ThemeProvider'
import {
  bubbles, columns, donut, funnel, horizontalBars, matrixHeatmap, networkGraph, sankey, slot, timeSeries,
  treemap, worldChoropleth,
} from '../../charts/options'
import { countryName } from '../../charts/countries'
import { fmtAgo } from '../../lib/format'
import { fmtDay } from '../../lib/viz'
import { ExportButtons, KICKER, Viz, fitFunnel, tame } from './shared'

const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

export default function PhishingOverview() {
  const nav = useNavigate()
  const { tokens: t } = useTheme()
  const q = usePhishingViz()
  const stats = useQuery({ queryKey: ['phishing', 'stats'], queryFn: api.phishing.stats })
  const scope = useQuery({ queryKey: ['scope'], queryFn: api.scope.get })
  const v = q.data
  const qs = qstate(q)

  const o = useMemo(() => {
    if (!v) return null
    const days = v.days
    const short = (d: string) => fmtDay(d, { month: 'short', day: 'numeric' })
    const sources = Object.keys(v.daily_by_source)
    const topBrands = v.bubbles.reduce<string[]>((acc, b) => (acc.includes(b.brand) || acc.length >= 6 ? acc : [...acc, b.brand]), [])
    return {
      tempo: timeSeries(days, [
        ...sources.map((s, i) => ({ name: SOURCE_LABEL[s] ?? s, data: v.daily_by_source[s], type: 'bar' as const, stack: 'src', color: slot(t, i) })),
        { name: 'Clustered into a campaign', data: v.daily_clustered, color: t.series[3] },
      ], t, { xFormat: short }),
      funnel: fitFunnel(funnel(v.funnel, t), t.text),
      graph: tame(networkGraph(v.graph.nodes, v.graph.links, v.graph.categories, t, { labelMin: 6 })),
      sankey: sankey(v.sankey.nodes.map((n) => ({ ...n })), v.sankey.links, t, { unit: 'samples' }),
      world: tame(worldChoropleth(v.countries, t, { unit: 'samples hosted' })),
      brandDay: (() => {
        // Unbranded pages would flatten the colour scale for every real brand, so they are left out here.
        const keep = v.brand_day.brands.map((b, i) => [b, i] as const).filter(([b]) => b !== 'Unbranded')
        const remap = new Map(keep.map(([, i], j) => [i, j]))
        return matrixHeatmap(days, keep.map(([b]) => b), v.brand_day.cells.filter((c) => remap.has(c[1])).map((c) => [c[0], remap.get(c[1])!, c[2]] as [number, number, number]), t, { unit: 'pages', xFormat: short, yWidth: 100 })
      })(),
      brands: horizontalBars(v.brands.slice(0, 12).map((b) => ({ label: b.key, value: b.count, color: b.key === 'Unbranded' ? t.other : undefined })), t, { unit: 'samples', labelWidth: 110 }),
      hours: matrixHeatmap(Array.from({ length: 24 }, (_, h) => String(h).padStart(2, '0')), WEEKDAYS, v.hour_dow ?? [], t, { unit: 'pages first seen', yWidth: 34 }),
      fetch: donut(v.fetch_status.map((f) => ({ name: f.key, value: f.count, color: f.key === 'ok' ? t.series[2] : f.key === 'blocked' ? t.series[3] : f.key === 'offline' ? t.other : t.series[7] })), t, { centerLabel: 'collected' }),
      kits: donut([
        { name: 'Named kit (signature)', value: v.kit_split.named, color: t.series[0] },
        { name: 'Inferred kit (unnamed)', value: v.kit_split.inferred, color: t.series[6] },
        { name: 'Clustered, no kit', value: v.kit_split.none, color: t.other },
      ], t, { centerLabel: 'clustered', legend: 'bottom' }),
      bubbles: bubbles(v.bubbles.map((b) => ({ x: b.domains, y: b.samples, size: b.ips + 1, name: `${b.name} · ${b.brand}${b.kit ? ` · ${b.kit}` : ''}`, category: Math.max(0, topBrands.indexOf(b.brand)) })), t, {
        xName: 'Distinct domains', yName: 'Pages', categories: topBrands.length ? topBrands : ['campaigns'],
      }),
      cohesion: columns(v.cohesion_hist.map((h) => ({ label: h.bucket, value: h.count })), t, { unit: 'campaigns', showValues: true, color: t.series[6] }),
      tree: treemap(v.hosting_tree, t, { unit: 'samples' }),
      tlds: horizontalBars(v.tlds.slice(0, 10).map((x) => ({ label: x.key, value: x.count })), t, { unit: 'samples', labelWidth: 70, color: t.series[3] }),
    }
  }, [v, t])

  if (q.isSuccess && v && !v.funnel[0]?.value) {
    return <><PageHeader kicker={KICKER} title="Campaign overview" /><ModuleEmpty pipeline="phishing" title="No phishing samples yet" /></>
  }

  const k = v?.kpis
  const lastRun = stats.data?.last_run
  const asOf = lastRun?.finished_at ?? undefined
  const graphEvents = { click: (p: { dataType: string; data: { campaign_id?: number; kit_id?: number } }) => {
    if (p.dataType !== 'node') return
    if (p.data.campaign_id) nav(`/phishing/campaigns/${p.data.campaign_id}`)
    else if (p.data.kit_id) nav(`/phishing/kits/${p.data.kit_id}`)
  } }

  return (
    <>
      <PageHeader kicker={KICKER} title="Campaign overview"
        subtitle={<>{scope.data ? `${scope.data.phishing.sector} · ${scope.data.phishing.brands.length} watched brands · ${scope.data.phishing.days_back}-day window` : 'Phishing pages grouped into campaigns and kits'}{lastRun && <> · last run {fmtAgo(lastRun.finished_at)}</>}</>}
        actions={<><ExportButtons formats={['campaign-cards', 'stix', 'sigma', 'yara']} /><button className="btn" onClick={() => nav('/phishing/report')}><FileBarChart size={14} /> Generate executive report</button><RunPipelineButton name="phishing" label="Run pipeline" /></>} />

      <KpiRow>
        <KpiTile loading={!v} kpi={k && v ? { label: 'Phishing pages', value: k.samples.cur, prev: k.samples.prev, window: 'last 7 days', spark: v.daily_total, sparkLabels: v.days, source: 'urlscan.io · OpenPhish · PhishTank · WhoisDS', note: `${stats.data?.samples ?? '…'} in window`, to: '/phishing/samples' } : undefined} />
        <KpiTile loading={!v} kpi={k && v ? { label: 'New campaigns', value: k.campaigns_new.cur, prev: k.campaigns_new.prev, window: 'last 7 days', spark: v.daily_new_campaigns, sparkLabels: v.days, source: 'clustering', note: `${stats.data?.active_campaigns ?? '…'} active`, to: '/phishing/campaigns' } : undefined} />
        <KpiTile loading={!v} kpi={k && v ? { label: 'Brands impersonated', value: k.brands.cur, prev: k.brands.prev, window: 'last 7 days', spark: v.daily_clustered, sparkLabels: v.days, source: 'brand detection', note: `top: ${v.brands.filter((b) => b.key !== 'Unbranded').slice(0, 2).map((b) => b.key).join(', ')}` } : undefined} />
        <KpiTile loading={!v} kpi={k && v ? { label: 'Detections shipped', value: k.detections.cur, prev: k.detections.prev, window: 'last 7 days', spark: v.daily_detections ?? [], sparkLabels: v.days, source: 'Sigma · YARA · IOC', note: `${stats.data?.detections ?? '…'} total`, to: '/phishing/detections', upIsBad: null } : undefined} />
      </KpiRow>

      <Grid>
        <Span n={8}><Viz title="Collection tempo" question="How many phishing pages arrived per day, from which feed, and how many joined a campaign?" source="urlscan.io · OpenPhish · PhishTank · WhoisDS" asOf={asOf} query={qs} height={250} option={o?.tempo}
          table={v ? { columns: ['day', ...Object.keys(v.daily_by_source), 'clustered'], rows: v.days.map((d, i) => [d, ...Object.values(v.daily_by_source).map((s) => s[i]), v.daily_clustered[i]]) } : undefined} /></Span>
        <Span n={4}><Viz title="Pipeline funnel" question="How much of what we collect survives to a clustered, attributed campaign?" source="pipeline run" query={qs} height={250} option={o?.funnel}
          table={v ? { columns: ['stage', 'samples'], rows: v.funnel.map((f) => [f.name, f.value]) } : undefined} /></Span>
      </Grid>

      <SectionLabel>Infrastructure</SectionLabel>
      <Grid>
        <Span n={12}><Viz title="Shared infrastructure graph" question="Which campaigns reuse the same domains, IPs, hosting or exfil endpoints? Those are the takedown targets that hit several campaigns at once."
          source="captured pages · urlscan.io metadata" query={qs} height={540} option={o?.graph} onEvents={graphEvents}
          caveat={v ? `${v.graph.campaigns} campaigns · ${v.graph.shared_infra} infrastructure values shared by 2+ campaigns · click a campaign or kit to open it · drag to pan` : undefined}
          table={v ? { columns: ['node', 'type', 'samples'], rows: v.graph.nodes.slice().sort((a, b) => b.value - a.value).slice(0, 80).map((n) => [n.name, v.graph.categories[n.category], n.value]) } : undefined} /></Span>
      </Grid>
      <Grid>
        <Span n={6}><Viz title="Brand → kit → hosting" question="Which kits are used against which brands, and where are they hosted?" source="clustered samples" query={qs} height={440} option={o?.sankey}
          table={v ? { columns: ['from', 'to', 'samples'], rows: v.sankey.links.map((l) => [cleanName(l.source), cleanName(l.target), l.value]) } : undefined} /></Span>
        <Span n={6}><Viz title="Hosting countries" question="Where are the phishing pages hosted? (urlscan-observed IP geolocation)" source="urlscan.io page.country" query={qs} height={440} option={o?.world} needsWorld empty={!!v && !v.countries.length}
          caveat="OpenPhish and WhoisDS records carry no hosting data until captured"
          table={v ? { columns: ['country', 'samples'], rows: v.countries.map((c) => [countryName(c.iso2), c.value]) } : undefined} /></Span>
      </Grid>
      <Grid>
        <Span n={8}><Viz title="Hosting providers" question="Which networks host the most pages, and on which TLDs? Click a block to drill in." source="urlscan.io ASN · URL TLD" query={qs} height={340} option={o?.tree}
          table={v ? { columns: ['hosting', 'samples'], rows: v.hosting_tree.map((h) => [h.name, h.value]) } : undefined} /></Span>
        <Span n={4}><Viz title="TLDs" question="Which top-level domains do phishing pages sit on?" source="sample URLs" query={qs} height={340} option={o?.tlds}
          table={v ? { columns: ['tld', 'samples'], rows: v.tlds.map((x) => [x.key, x.count]) } : undefined} /></Span>
      </Grid>

      <SectionLabel>Targets & campaigns</SectionLabel>
      <Grid>
        <Span n={8}><Viz title="Brand activity by day" question="Which brands are being hit, and on which days did campaigns burst? (unbranded pages excluded)" source="brand detection on captured pages" query={qs} height={330} option={o?.brandDay}
          table={v ? { columns: ['brand', ...v.days], rows: v.brand_day.brands.map((b, bi) => [b, ...v.days.map((_, di) => v.brand_day.cells.find((c) => c[0] === di && c[1] === bi)?.[2] ?? 0)]) } : undefined} /></Span>
        <Span n={4}><Viz title="Most impersonated brands" question="Which brands account for the most pages? Click to filter campaigns." source="brand detection" query={qs} height={330} option={o?.brands}
          onEvents={{ click: (p: { name: string }) => p.name !== 'Unbranded' && nav(`/phishing/campaigns?brand=${encodeURIComponent(p.name)}`) }}
          table={v ? { columns: ['brand', 'samples'], rows: v.brands.map((b) => [b.key, b.count]) } : undefined} /></Span>
      </Grid>
      <Grid>
        <Span n={8}><Viz title="Campaign landscape" question="How big is each multi-page campaign and how widely is it spread? Many domains for few pages means throwaway domains. (bubble = IPs)" source="clustering" query={qs} height={330} option={o?.bubbles}
          onEvents={{ click: (p: { data: { name: string } }) => { const b = v?.bubbles.find((x) => p.data.name.startsWith(x.name)); if (b) nav(`/phishing/campaigns/${b.id}`) } }}
          table={v ? { columns: ['campaign', 'brand', 'first seen', 'samples', 'domains', 'IPs'], rows: v.bubbles.map((b) => [b.name, b.brand, b.first_seen.slice(0, 10), b.samples, b.domains, b.ips]) } : undefined} /></Span>
        <Span n={4}><Viz title="Cluster cohesion" question="How tight are the multi-page clusters? Low cohesion means a cluster may be over-merged." source="mean pairwise similarity" query={qs} height={330} option={o?.cohesion}
          table={v ? { columns: ['cohesion', 'campaigns'], rows: v.cohesion_hist.map((h) => [h.bucket, h.count]) } : undefined} /></Span>
      </Grid>
      <Grid>
        <Span n={4}><Viz title="When pages appear" question="At what hour (UTC) and weekday are new phishing pages first seen?" source="first-seen timestamps" query={qs} height={200} option={o?.hours}
          table={v ? { columns: ['weekday', 'hour', 'pages'], rows: (v.hour_dow ?? []).map(([h, d, n]) => [WEEKDAYS[d], h, n]) } : undefined} /></Span>
        <Span n={4}><Viz title="Capture outcome" question="How many pages were still live when we visited?" source="direct fetch (no JS, no form submission)" query={qs} height={200} option={o?.fetch}
          table={v ? { columns: ['outcome', 'samples'], rows: v.fetch_status.map((f) => [f.key, f.count]) } : undefined} /></Span>
        <Span n={4}><Viz title="Kit attribution" question="How many clustered pages map to a known kit, an inferred one, or none?" source="kits.yaml signatures" query={qs} height={200} option={o?.kits}
          table={v ? { columns: ['attribution', 'samples'], rows: [['named', v.kit_split.named], ['inferred', v.kit_split.inferred], ['none', v.kit_split.none]] } : undefined} /></Span>
      </Grid>
    </>
  )
}
