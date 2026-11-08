import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { DollarSign, Download } from 'lucide-react'
import { api } from '../../lib/api'
import { PageHeader, Card, DataTable, Badge, Loading, ErrorState, LinkButton, Ext, KV, Meter } from '../../components/ui'
import { Drawer } from '../../components/ui/Drawer'
import { ReviewPanel } from '../../components/ui/ReviewPanel'
import { FilterBar, SearchInput, Segmented, Select, StatStrip, Toggle } from '../../components/ui/controls'
import { Grid, Span, SectionLabel } from '../../components/ui/Grid'
import { ModuleEmpty, isNoData } from '../../components/ui/RunPipelineButton'
import { useFilters } from '../../components/ui/useParams'
import { boxplot, bubbles, donut, horizontalBars, matrixHeatmap } from '../../charts/options'
import { countryName } from '../../charts/countries'
import { fmtDate, fmtInt, fmtUsd } from '../../lib/format'
import { fmtYm } from '../../lib/viz'
import type { IABOut } from '../../lib/types'
import { SRC, SectionTitle, Viz, contrastLabels, useTokens, useViz, useWindow } from './shared'

const usdShort = (v: number) => (v >= 1e9 ? `$${Math.round(v / 1e8) / 10}B` : v >= 1e6 ? `$${Math.round(v / 1e5) / 10}M` : v >= 1e3 ? `$${Math.round(v / 100) / 10}k` : `$${Math.round(v)}`)
const padTop = (o: any, top: number) => { if (o?.grid) o.grid.top = top; return o }
const price = (r: IABOut) => (r.price_usd_min == null ? null : r.price_usd_max && r.price_usd_max !== r.price_usd_min ? `${fmtUsd(r.price_usd_min)} – ${fmtUsd(r.price_usd_max)}` : fmtUsd(r.price_usd_min))

export default function IAB() {
  const t = useTokens()
  const [w] = useWindow()
  const f = useFilters<'in_scope' | 'rel' | 'region' | 'access' | 'q'>()
  const rel = f.get('rel') || '0.2'
  const [qText, setQText] = useState(f.get('q'))
  const [sel, setSel] = useState<IABOut | null>(null)
  const params = { in_scope: f.get('in_scope') === '1' ? true : undefined, min_relevance: Number(rel), region: f.get('region') || undefined, access_type: f.get('access') || undefined }
  const list = useQuery({ queryKey: ['landscape', 'iab', params], queryFn: () => api.landscape.iab(params), retry: false, placeholderData: (p) => p })
  const stats = useQuery({ queryKey: ['landscape', 'iab-stats'], queryFn: api.landscape.iabStats, retry: false })
  const viz = useViz(w)
  const vq = { isLoading: viz.isLoading, isError: viz.isError, error: viz.error, isFetching: viz.isFetching, refetch: viz.refetch }
  const sq = { isLoading: stats.isLoading, isError: stats.isError, error: stats.error, isFetching: stats.isFetching, refetch: stats.refetch }
  const s = stats.data
  const iv = viz.data?.iab

  const rows = useMemo(() => {
    const n = qText.trim().toLowerCase()
    return (list.data ?? []).filter((r) => !n || `${r.title} ${r.summary ?? ''} ${r.brokers.join(' ')} ${r.actors.join(' ')}`.toLowerCase().includes(n))
  }, [list.data, qText])

  const charts = useMemo(() => {
    if (!iv || !s) return null
    const types = Object.keys(iv.price_by_access)
    const cats = Array.from(new Set(iv.bubbles.map((b) => b.access_type)))
    return {
      box: types.length ? boxplot(types, types.map((k) => iv.price_by_access[k]), t, { log: true, yFormat: usdShort, yName: 'asking price' }) : null,
      bubbles: iv.bubbles.length ? padTop(bubbles(iv.bubbles.map((b) => ({ name: b.title, x: b.revenue, y: b.price, size: 1, category: cats.indexOf(b.access_type) })), t, { xName: 'claimed victim revenue', yName: 'asking price', xLog: true, yLog: true, xFormat: usdShort, yFormat: usdShort, categories: cats }), 48) : null,
      heat: iv.access_month.types.length ? contrastLabels(matrixHeatmap(iv.access_month.months, iv.access_month.types, iv.access_month.cells, t, { unit: 'reports', xFormat: fmtYm, showValues: true, yWidth: 120 })) : null,
      access: horizontalBars(s.access_types.map((a) => ({ label: a.key, value: a.count })), t, { unit: 'reports', labelWidth: 120 }),
      sources: donut(s.sources.map((x) => ({ name: x.key, value: x.count })), t, { centerLabel: 'reports', legend: 'bottom' }),
      regions: horizontalBars(s.regions.filter((x) => x.key !== 'unknown').map((x) => ({ label: x.key, value: x.count })), t, { unit: 'reports', labelWidth: 120, color: t.series[2] }),
      sectors: horizontalBars(s.sectors.map((x) => ({ label: x.key, value: x.count })), t, { unit: 'reports', labelWidth: 140, color: t.series[3] }),
    }
  }, [iv, s, t])

  const header = (
    <PageHeader kicker="P6 · Threat landscape" title="Access brokers"
      subtitle="Initial-access-broker activity mined from public vendor and news reporting: what access is sold, for how much, against whom."
      actions={<LinkButton href={api.landscape.exportUrl('iab-csv')}><Download size={14} /> IAB CSV</LinkButton>} />
  )
  if (list.isLoading || stats.isLoading) return <>{header}<Loading rows={8} /></>
  if (list.error && !isNoData(list.error)) return <>{header}<ErrorState error={list.error} /></>
  if (!s || !s.listings) return <>{header}<Card><ModuleEmpty pipeline="landscape" title="No access-broker reporting mined yet" icon={<DollarSign size={24} />} /></Card></>
  const accessOptions = s.access_types.map((a) => ({ value: a.key, label: `${a.key} (${a.count})` }))

  return (
    <>
      {header}
      <StatStrip items={[
        { label: 'Relevant reports', value: fmtInt(s.listings), sub: 'relevance ≥ 0.2, in window' },
        { label: 'In our scope', value: fmtInt(s.in_scope), sub: 'region or sector match' },
        { label: 'Carry a price', value: fmtInt(s.with_price), sub: s.listings ? `${Math.round((s.with_price / s.listings) * 100)}% of reports` : undefined },
        { label: 'Median asking price', value: fmtUsd(s.price_median), sub: s.price_min != null ? `${fmtUsd(s.price_min)} – ${fmtUsd(s.price_max)}` : 'no prices' },
        { label: 'Access types seen', value: fmtInt(s.access_types.length), sub: s.access_types[0] ? `most: ${s.access_types[0].key}` : undefined },
        { label: 'Sources', value: fmtInt(s.sources.length), sub: s.sources[0] ? `most: ${s.sources[0].key}` : undefined },
      ]} />

      <SectionLabel>Pricing</SectionLabel>
      <Grid>
        <Span n={6}><Viz title="Asking price by access type" question="What does a foothold cost, and does the access type change the price?" source={SRC.iab} query={vq} height={280} option={charts?.box ?? null}
          empty={!charts?.box} emptyText="No prices extracted in this window" caveat="log scale · each dot is a quoted price"
          table={iv && { columns: ['access type', 'prices'], rows: Object.entries(iv.price_by_access).map(([k, v]) => [k, v.map((p) => fmtUsd(p)).join(', ')]) }} /></Span>
        <Span n={6}><Viz title="Victim revenue vs asking price" question="Do brokers price access by the size of the victim?" source={SRC.iab} query={vq} height={280} option={charts?.bubbles ?? null}
          empty={!charts?.bubbles} emptyText="No report gives both a price and a revenue figure" caveat="log–log · colour: access type"
          table={iv && { columns: ['report', 'revenue', 'price', 'access'], rows: iv.bubbles.map((b) => [b.title, fmtUsd(b.revenue), fmtUsd(b.price), b.access_type]) }} /></Span>
      </Grid>
      <SectionLabel>What is on offer</SectionLabel>
      <Grid>
        <Span n={6}><Viz title="Access type by month" question="Which kinds of access are being reported, and when?" source={SRC.iab} query={vq} height={300} option={charts?.heat ?? null} empty={!charts?.heat}
          onEvents={{ click: (p) => { const ty = iv?.access_month.types[p.value?.[1]]; if (ty) f.set('access', ty) } }} caveat="click a cell to filter the reports" /></Span>
        <Span n={3}><Viz title="Access types" question="Most common footholds" source={SRC.iab} query={sq} height={300} option={charts?.access ?? null}
          onEvents={{ click: (p) => p.name && f.set('access', p.name) }} table={{ columns: ['access', 'reports'], rows: s.access_types.map((a) => [a.key, a.count]) }} /></Span>
        <Span n={3}><Viz title="Reporting sources" question="Whose reporting feeds this view?" source={SRC.iab} query={sq} height={300} option={charts?.sources ?? null}
          table={{ columns: ['source', 'reports'], rows: s.sources.map((a) => [a.key, a.count]) }} /></Span>
        <Span n={6}><Viz title="Victim regions" question="Where are the access victims?" source={SRC.iab} query={sq} height={240} option={charts?.regions ?? null} empty={!s.regions.some((r) => r.key !== 'unknown')}
          onEvents={{ click: (p) => p.name && f.set('region', p.name) }} /></Span>
        <Span n={6}><Viz title="Victim sectors" question="Which industries are brokers selling into?" source={SRC.iab} query={sq} height={240} option={charts?.sectors ?? null} empty={!s.sectors.length} caveat="keyword-tagged, up to 3 per report" /></Span>
      </Grid>

      <SectionLabel>Reports</SectionLabel>
      <FilterBar>
        <Toggle pressed={f.get('in_scope') === '1'} onChange={(v) => f.set('in_scope', v ? '1' : '')}>In scope only</Toggle>
        <SearchInput value={qText} onChange={setQText} placeholder="Search title, broker, actor…" />
        <Segmented value={rel} onChange={(v) => f.set('rel', v === '0.2' ? '' : v)} label="Minimum relevance" options={[{ value: '0', label: 'All' }, { value: '0.2', label: '≥ 0.2' }, { value: '0.4', label: '≥ 0.4' }]} />
        <Select value={f.get('region')} onChange={(v) => f.set('region', v)} label="Region" options={[{ value: '', label: 'All regions' }, ...s.regions.filter((r) => r.key !== 'unknown').map((r) => ({ value: r.key, label: r.key }))]} />
        <Select value={f.get('access')} onChange={(v) => f.set('access', v)} label="Access type" options={[{ value: '', label: 'All access types' }, ...accessOptions]} />
        <span className="muted" style={{ marginLeft: 'auto', fontSize: 12.5 }}>{fmtInt(rows.length)} reports</span>
      </FilterBar>
      <DataTable<IABOut> rows={rows} rowKey={(r) => r.id} onRowClick={setSel} maxHeight="70vh"
        empty={<Card><ModuleEmpty pipeline="landscape" title="No reports match" hint="Lower the relevance threshold or clear a filter." /></Card>}
        columns={[
          { key: 'p', header: 'Published', sort: (r) => r.published ?? '', render: (r) => <span className="num" style={{ whiteSpace: 'nowrap' }}>{fmtDate(r.published)}</span> },
          { key: 's', header: 'Source', sort: (r) => r.source, render: (r) => <span className="muted">{r.source}</span> },
          { key: 't', header: 'Report', render: (r) => <div style={{ maxWidth: 380, whiteSpace: 'normal' }}><span style={{ color: 'var(--text)', fontWeight: 600 }}>{r.title}</span>{r.in_scope && <Badge tone="accent" className="ml-1">in scope</Badge>}</div> },
          { key: 'a', header: 'Access', render: (r) => <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, maxWidth: 220 }}>{r.access_types.slice(0, 4).map((x) => <Badge key={x}>{x}</Badge>)}{r.access_types.length > 4 && <span className="muted" style={{ fontSize: 11 }}>+{r.access_types.length - 4}</span>}</div> },
          { key: 'pr', header: 'Price', align: 'right', sort: (r) => r.price_usd_min, render: (r) => <span style={{ whiteSpace: 'nowrap' }}>{price(r) ?? <span className="muted">—</span>}</span> },
          { key: 'rv', header: 'Revenue', align: 'right', sort: (r) => r.revenue_usd, render: (r) => (r.revenue_usd ? usdShort(r.revenue_usd) : <span className="muted">—</span>) },
          { key: 'g', header: 'Region', sort: (r) => r.region ?? '', render: (r) => r.region ?? <span className="muted">—</span> },
          { key: 'rl', header: 'Relevance', sort: (r) => r.relevance, render: (r) => <Meter value={r.relevance} width={52} /> },
          { key: 'm', header: 'Method', render: (r) => <Badge tone={r.extraction_method === 'llm' ? 'accent' : 'neutral'}>{r.extraction_method}</Badge> },
        ]} />

      <Drawer open={!!sel} onClose={() => setSel(null)} kind="Access-broker report" title={sel?.title} subtitle={sel ? <>{sel.source} · {fmtDate(sel.published)}</> : undefined}
        badges={sel ? <>{sel.in_scope && <Badge tone="accent">In scope</Badge>}<Badge tone={sel.extraction_method === 'llm' ? 'accent' : 'neutral'}>{sel.extraction_method} extraction</Badge><Badge>relevance {Math.round(sel.relevance * 100)}%</Badge></> : undefined}>
        {sel && (
          <div style={{ display: 'grid', gap: 18 }}>
            <KV items={[
              { k: 'Article', v: <Ext href={sel.source_url}>{sel.source_url.replace(/^https?:\/\//, '').slice(0, 70)}</Ext> },
              { k: 'Access types', v: sel.access_types.length ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{sel.access_types.map((x) => <Badge key={x}>{x}</Badge>)}</div> : '—' },
              { k: 'Asking price', v: price(sel) ?? '—' },
              { k: 'Victim revenue', v: sel.revenue_usd ? fmtUsd(sel.revenue_usd) : '—' },
              { k: 'Countries', v: sel.countries.length ? sel.countries.map((c) => countryName(c)).join(', ') : '—' },
              { k: 'Region', v: sel.region ?? '—' },
              { k: 'Sectors', v: sel.sectors.join(', ') || '—' },
              { k: 'Brokers named', v: sel.brokers.join(', ') || '—' },
              { k: 'Ransomware groups', v: sel.actors.join(', ') || '—' },
            ]} />
            {sel.summary && <div><SectionTitle>Feed summary</SectionTitle><p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-2)' }}>{sel.summary}</p></div>}
            {sel.excerpt && <div><SectionTitle>Extracted excerpt</SectionTitle><p style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 12.5, color: 'var(--text-2)', background: 'var(--page)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, maxHeight: 260, overflow: 'auto' }}>{sel.excerpt}</p></div>}
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}><SectionTitle>Analyst review · is this really IAB activity, and is the extraction right?</SectionTitle><ReviewPanel entityType="iab" entityId={sel.id} /></div>
          </div>
        )}
      </Drawer>
    </>
  )
}
