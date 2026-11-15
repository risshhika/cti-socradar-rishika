import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ScanSearch } from 'lucide-react'
import { api } from '../../lib/api'
import { usePhishingViz, qstate, SOURCE_LABEL } from '../../lib/phishingViz'
import { PageHeader, Card, Pagination, Loading, ErrorState } from '../../components/ui'
import { FilterBar, FilterChips, SearchInput, Select, StatStrip } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ModuleEmpty, RunPipelineButton, isNoData } from '../../components/ui/RunPipelineButton'
import { useFilters } from '../../components/ui/useParams'
import { useTheme } from '../../theme/ThemeProvider'
import { donut, slot, timeSeries } from '../../charts/options'
import { fmtInt } from '../../lib/format'
import { fmtDay } from '../../lib/viz'
import { DETECTION_TYPE_LABEL, ExportButtons, KICKER, SampleTable, TIER_ORDER, Viz } from './shared'

const SIZE = 50
type K = 'campaign_id' | 'kit_id' | 'brand' | 'fetch_status' | 'source' | 'q' | 'detection_type' | 'threat_tier' | 'sort' | 'page'

export default function Samples() {
  const { tokens: t } = useTheme()
  const f = useFilters<K>()
  const params = { campaign_id: f.get('campaign_id') ? Number(f.get('campaign_id')) : undefined, kit_id: f.get('kit_id') ? Number(f.get('kit_id')) : undefined, brand: f.get('brand') || undefined, fetch_status: f.get('fetch_status') || undefined, source: f.get('source') || undefined, q: f.get('q') || undefined, detection_type: f.get('detection_type') || undefined, threat_tier: f.get('threat_tier') || undefined, sort: (f.get('sort') || 'threat') as 'threat' | 'recent', page: f.page, size: SIZE }
  const q = useQuery({ queryKey: ['phishing', 'samples', params], queryFn: () => api.phishing.samples(params), retry: false, placeholderData: (prev) => prev })
  const stats = useQuery({ queryKey: ['phishing', 'stats'], queryFn: api.phishing.stats, retry: false })
  const kits = useQuery({ queryKey: ['phishing', 'kits'], queryFn: api.phishing.kits, retry: false })
  const v = usePhishingViz()
  const st = stats.data
  const o = useMemo(() => {
    if (!v.data) return null
    const srcs = Object.keys(v.data.daily_by_source)
    return {
      bySource: timeSeries(v.data.days, srcs.map((s, i) => ({ name: SOURCE_LABEL[s] ?? s, data: v.data!.daily_by_source[s], area: true, color: slot(t, i) })), t, { xFormat: (x) => fmtDay(x, { month: 'short', day: 'numeric' }) }),
      outcome: donut(v.data.fetch_status.map((x) => ({ name: x.key, value: x.count, color: x.key === 'ok' ? t.series[2] : x.key === 'blocked' ? t.series[3] : x.key === 'offline' ? t.other : t.series[7] })), t, { centerLabel: 'pages' }),
    }
  }, [v.data, t])
  const opt = (arr: { key: string; count: number }[] | undefined, all: string, fmt = (k: string) => k) => [{ value: '', label: all }, ...(arr ?? []).map((b) => ({ value: b.key, label: `${fmt(b.key)} (${b.count})` }))]
  const chips = ([
    f.get('q') && { key: 'q', label: `“${f.get('q')}”` }, f.get('brand') && { key: 'brand', label: `Brand: ${f.get('brand')}` },
    f.get('fetch_status') && { key: 'fetch_status', label: `Capture: ${f.get('fetch_status')}` }, f.get('source') && { key: 'source', label: `Source: ${f.get('source')}` },
    f.get('kit_id') && { key: 'kit_id', label: `Kit: ${kits.data?.find((k) => String(k.id) === f.get('kit_id'))?.name ?? f.get('kit_id')}` },
    f.get('campaign_id') && { key: 'campaign_id', label: `Campaign #${f.get('campaign_id')}` },
    f.get('detection_type') && { key: 'detection_type', label: `Detection: ${DETECTION_TYPE_LABEL[f.get('detection_type')] ?? f.get('detection_type')}` },
    f.get('threat_tier') && { key: 'threat_tier', label: `Threat: ${f.get('threat_tier')}` },
  ].filter(Boolean) as { key: K; label: string }[]).map((c) => ({ ...c, onRemove: () => f.set(c.key, '') }))
  const fs = (k: string) => st?.fetch_status.find((x) => x.key === k)?.count ?? 0

  return (
    <>
      <PageHeader kicker={KICKER} title="Samples" subtitle="Every candidate phishing page from urlscan.io, OpenPhish, PhishTank and promoted WhoisDS typosquat leads, ranked by threat. Typosquat hosts imitate the brand in the hostname; content-only pages imitate it on the page."
        actions={<><ExportButtons formats={['csv', 'iocs']} /><RunPipelineButton name="phishing" label="Run pipeline" variant="secondary" /></>} />
      {st && <StatStrip items={[
        { label: 'Unique pages', value: fmtInt(st.samples), sub: st.sources.map((x) => `${SOURCE_LABEL[x.key] ?? x.key} ${x.count}`).join(' · ') },
        { label: 'Duplicates merged', value: fmtInt(st.duplicates_merged), sub: 'same page reported again' },
        { label: 'Captured live', value: fmtInt(fs('ok')), sub: `${Math.round((fs('ok') / Math.max(1, st.samples)) * 100)}% of collected` },
        { label: 'Blocked / cloaked', value: fmtInt(fs('blocked')), sub: 'anti-bot or 4xx' },
        { label: 'Offline', value: fmtInt(fs('offline')), sub: 'already taken down' },
        { label: 'Brands detected', value: fmtInt(st.brands.length) },
      ]} />}
      <Grid>
        <Span n={8}><Viz title="Pages per day by feed" question="Which feed is supplying pages, and when?" source="urlscan.io · OpenPhish · PhishTank · WhoisDS" query={qstate(v)} height={200} option={o?.bySource} /></Span>
        <Span n={4}><Viz title="Capture outcome" question="Were pages still live when visited?" source="direct fetch" query={qstate(v)} height={200} option={o?.outcome} /></Span>
      </Grid>
      <FilterBar>
        <SearchInput value={f.get('q')} onChange={(x) => f.set('q', x)} placeholder="Search URL, domain, title, IP…" />
        <Select value={f.get('brand')} onChange={(x) => f.set('brand', x)} options={opt(st?.brands, 'All brands')} label="Brand" />
        <Select value={f.get('fetch_status')} onChange={(x) => f.set('fetch_status', x)} options={opt(st?.fetch_status, 'Any capture')} label="Capture" />
        <Select value={f.get('source')} onChange={(x) => f.set('source', x)} options={opt(st?.sources, 'Any source', (k) => SOURCE_LABEL[k] ?? k)} label="Source" />
        <Select value={f.get('detection_type')} onChange={(x) => f.set('detection_type', x)} options={[{ value: '', label: 'Any detection' }, ...Object.entries(DETECTION_TYPE_LABEL).map(([value, label]) => ({ value, label }))]} label="Detection" />
        <Select value={f.get('threat_tier')} onChange={(x) => f.set('threat_tier', x)} options={[{ value: '', label: 'Any threat' }, ...TIER_ORDER.map((t) => ({ value: t, label: t[0].toUpperCase() + t.slice(1) }))]} label="Threat" />
        <Select value={f.get('sort') || 'threat'} onChange={(x) => f.set('sort', x === 'threat' ? '' : x)} options={[{ value: 'threat', label: 'Highest threat first' }, { value: 'recent', label: 'Most recent first' }]} label="Sort" />
        <Select value={f.get('kit_id')} onChange={(x) => f.set('kit_id', x)} options={[{ value: '', label: 'All kits' }, ...(kits.data ?? []).filter((k) => k.sample_count).map((k) => ({ value: String(k.id), label: k.name }))]} label="Kit" />
      </FilterBar>
      <FilterChips filters={chips} onClear={f.clear} count={q.data ? <span><b className="num" style={{ color: 'var(--text)' }}>{fmtInt(q.data.page.total)}</b> pages</span> : undefined} />
      <Card padded={false}>
        <div style={{ padding: 12 }}>
          {q.isLoading ? <Loading rows={10} /> : q.error && !isNoData(q.error) ? <ErrorState error={q.error} /> : (
            <>
              <SampleTable rows={q.data?.items ?? []} empty={<ModuleEmpty pipeline="phishing" title="No samples" icon={<ScanSearch size={24} />} hint={chips.length ? 'No sample matches these filters.' : undefined} />} />
              {q.data && q.data.page.total > SIZE && <Pagination page={f.page} size={SIZE} total={q.data.page.total} onPage={f.setPage} />}
            </>
          )}
        </div>
      </Card>
    </>
  )
}
