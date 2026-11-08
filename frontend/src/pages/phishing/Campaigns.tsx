import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Boxes } from 'lucide-react'
import { api } from '../../lib/api'
import { usePhishingViz, qstate } from '../../lib/phishingViz'
import { PageHeader, Card, DataTable, Badge, StatusBadge, ConfidenceBadge, VerdictBadge, Loading, ErrorState, Meter } from '../../components/ui'
import { FilterBar, FilterChips, SearchInput, Select, Segmented } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ModuleEmpty, RunPipelineButton, isNoData } from '../../components/ui/RunPipelineButton'
import { useFilters } from '../../components/ui/useParams'
import { useTheme } from '../../theme/ThemeProvider'
import { bubbles, horizontalBars } from '../../charts/options'
import { fmtDate, fmtInt } from '../../lib/format'
import type { CampaignOut } from '../../lib/types'
import { ExportButtons, KICKER, MiniSpark, Viz } from './shared'

type K = 'brand' | 'kit_id' | 'status' | 'min_samples' | 'q'

export default function Campaigns() {
  const nav = useNavigate()
  const { tokens: t } = useTheme()
  const f = useFilters<K>()
  const params = { brand: f.get('brand') || undefined, kit_id: f.get('kit_id') ? Number(f.get('kit_id')) : undefined, status: f.get('status') || undefined, min_samples: f.get('min_samples') ? Number(f.get('min_samples')) : undefined, q: f.get('q') || undefined }
  const q = useQuery({ queryKey: ['phishing', 'campaigns', params], queryFn: () => api.phishing.campaigns(params), retry: false, placeholderData: (p) => p })
  const kits = useQuery({ queryKey: ['phishing', 'kits'], queryFn: api.phishing.kits, retry: false })
  const stats = useQuery({ queryKey: ['phishing', 'stats'], queryFn: api.phishing.stats, retry: false })
  const viz = usePhishingViz()
  const rows = q.data ?? []
  const brands = useMemo(() => [{ value: '', label: 'All brands' }, ...(stats.data?.brands ?? []).map((b) => ({ value: b.key, label: `${b.key} (${b.count})` }))], [stats.data])
  const kitOpts = useMemo(() => [{ value: '', label: 'All kits' }, ...(kits.data ?? []).filter((k) => k.sample_count > 0).map((k) => ({ value: String(k.id), label: k.name }))], [kits.data])

  const charts = useMemo(() => {
    if (!rows.length) return null
    const multi = rows.filter((r) => r.sample_count >= 2)
    const brandsTop = Array.from(new Set(multi.map((r) => r.brand ?? 'Unbranded'))).slice(0, 6)
    const byBrand = new Map<string, number>()
    rows.forEach((r) => byBrand.set(r.brand ?? 'Unbranded', (byBrand.get(r.brand ?? 'Unbranded') ?? 0) + r.sample_count))
    return {
      scatter: bubbles(multi.map((r) => ({ x: Math.round(r.cohesion * 100), y: r.sample_count, size: r.domain_count, name: `${r.name} · ${r.brand ?? 'unbranded'}`, category: Math.max(0, brandsTop.indexOf(r.brand ?? 'Unbranded')) })), t, {
        xName: 'Cohesion %', yName: 'Pages', categories: brandsTop.length ? brandsTop : ['campaigns'],
      }),
      brands: horizontalBars([...byBrand.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([label, value]) => ({ label, value, color: label === 'Unbranded' ? t.other : undefined })), t, { unit: 'pages', labelWidth: 110 }),
    }
  }, [rows, t])

  const chips = ([
    f.get('q') && { key: 'q', label: `“${f.get('q')}”` },
    f.get('brand') && { key: 'brand', label: `Brand: ${f.get('brand')}` },
    f.get('kit_id') && { key: 'kit_id', label: `Kit: ${kits.data?.find((k) => String(k.id) === f.get('kit_id'))?.name ?? f.get('kit_id')}` },
    f.get('status') && { key: 'status', label: `Status: ${f.get('status')}` },
    f.get('min_samples') && { key: 'min_samples', label: `≥ ${f.get('min_samples')} pages` },
  ].filter(Boolean) as { key: K; label: string }[]).map((c) => ({ ...c, onRemove: () => f.set(c.key, '') }))
  const qs = qstate(q)

  return (
    <>
      <PageHeader kicker={KICKER} title="Campaigns" subtitle="Phishing pages grouped by shared DOM structure, kit markers and infrastructure. Each campaign is one takedown and detection unit."
        actions={<><ExportButtons formats={['campaign-cards', 'csv', 'stix']} /><RunPipelineButton name="phishing" label="Run pipeline" variant="secondary" /></>} />

      <FilterBar>
        <SearchInput value={f.get('q')} onChange={(v) => f.set('q', v)} placeholder="Search campaign, brand, domain…" />
        <Select value={f.get('brand')} onChange={(v) => f.set('brand', v)} options={brands} label="Brand" />
        <Select value={f.get('kit_id')} onChange={(v) => f.set('kit_id', v)} options={kitOpts} label="Kit" />
        <Segmented value={(f.get('status') || 'all') as string} onChange={(v) => f.set('status', v === 'all' ? '' : v)} label="Status" options={[{ value: 'all', label: 'All' }, { value: 'active', label: 'Active' }, { value: 'dormant', label: 'Dormant' }]} />
        <Segmented value={(f.get('min_samples') || '1') as string} onChange={(v) => f.set('min_samples', v === '1' ? '' : v)} label="Minimum size" options={[{ value: '1', label: 'Any size' }, { value: '2', label: '2+' }, { value: '5', label: '5+' }, { value: '10', label: '10+' }]} />
      </FilterBar>
      <FilterChips filters={chips} onClear={f.clear} count={<span><b className="num" style={{ color: 'var(--text)' }}>{fmtInt(rows.length)}</b> campaigns · {fmtInt(rows.reduce((a, r) => a + r.sample_count, 0))} pages</span>} />

      {charts && (
        <Grid>
          <Span n={8}><Viz title="Size vs cohesion" question="Which campaigns are big and tight (strong takedown targets), and which are loose clusters worth a hand check? (bubble = domains)" source="clustering" query={qs} height={260} option={charts.scatter}
            onEvents={{ click: (p: { data: { name: string } }) => { const r = rows.find((x) => p.data.name.startsWith(x.name)); if (r) nav(`/phishing/campaigns/${r.id}`) } }}
            table={{ columns: ['campaign', 'brand', 'pages', 'domains', 'cohesion'], rows: rows.filter((r) => r.sample_count >= 2).map((r) => [r.name, r.brand ?? '', r.sample_count, r.domain_count, Math.round(r.cohesion * 100)]) }} /></Span>
          <Span n={4}><Viz title="Pages by brand" question="Which brands do the filtered campaigns target? Click to filter." source="brand detection" query={qs} height={260} option={charts.brands}
            onEvents={{ click: (p: { name: string }) => p.name !== 'Unbranded' && f.set('brand', p.name) }} /></Span>
        </Grid>
      )}

      <Card padded={false}>
        <div style={{ padding: 12 }}>
          {q.isLoading ? <Loading rows={8} /> : q.error && !isNoData(q.error) ? <ErrorState error={q.error} /> : (
            <DataTable<CampaignOut> rows={rows} rowKey={(r) => r.id} onRowClick={(r) => nav(`/phishing/campaigns/${r.id}`)} maxHeight="72vh"
              empty={<ModuleEmpty pipeline="phishing" title="No campaigns" icon={<Boxes size={24} />} hint={chips.length ? 'No campaign matches these filters.' : undefined} />}
              columns={[
                { key: 'name', header: 'Campaign', sort: (r) => r.name, render: (r) => <div style={{ whiteSpace: 'nowrap' }}><div className="mono" style={{ fontWeight: 600, color: 'var(--text)' }}>{r.name}</div><div className="muted" style={{ fontSize: 11 }}>{r.cluster_method}</div></div> },
                { key: 'brand', header: 'Brand', sort: (r) => r.brand, render: (r) => r.brand ? <Badge tone="accent">{r.brand}</Badge> : <span className="muted">unbranded</span> },
                { key: 'kit', header: 'Kit', sort: (r) => r.kit_name, render: (r) => r.kit_name ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><span style={{ maxWidth: 170, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.kit_name}>{r.kit_name}</span><ConfidenceBadge value={r.kit_confidence} /></span> : <span className="muted">—</span> },
                { key: 'trend', header: 'Pages / day', render: (r) => <MiniSpark values={viz.data?.campaign_daily[String(r.id)] ?? []} /> },
                { key: 'n', header: 'Pages', align: 'right', sort: (r) => r.sample_count, render: (r) => <b className="num" style={{ color: 'var(--text)' }}>{fmtInt(r.sample_count)}</b> },
                { key: 'dom', header: 'Domains', align: 'right', sort: (r) => r.domain_count, render: (r) => <span className="num">{fmtInt(r.domain_count)}</span> },
                                { key: 'coh', header: 'Cohesion', sort: (r) => r.cohesion, render: (r) => r.sample_count > 1 ? <Meter value={r.cohesion} color="var(--series-7)" /> : <span className="muted">single page</span> },
                { key: 'first', header: 'First seen', sort: (r) => r.first_seen, render: (r) => <span className="num muted" style={{ whiteSpace: 'nowrap' }}>{fmtDate(r.first_seen)}</span> },
                { key: 'det', header: 'Rules', align: 'right', sort: (r) => r.detection_count, render: (r) => <span className="num">{fmtInt(r.detection_count)}</span> },
                { key: 'st', header: 'Status', sort: (r) => r.status, render: (r) => <StatusBadge status={r.status} /> },
                { key: 'v', header: 'Verdict', render: (r) => <VerdictBadge verdict={r.review_verdict} /> },
              ]} />
          )}
        </div>
      </Card>
    </>
  )
}
