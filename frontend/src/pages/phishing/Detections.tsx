import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, ShieldCheck } from 'lucide-react'
import { api } from '../../lib/api'
import { usePhishingViz, qstate } from '../../lib/phishingViz'
import { PageHeader, Loading, ErrorState } from '../../components/ui'
import { FilterBar, FilterChips, Select, StatStrip } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ModuleEmpty, RunPipelineButton, isNoData } from '../../components/ui/RunPipelineButton'
import { useFilters } from '../../components/ui/useParams'
import { useTheme } from '../../theme/ThemeProvider'
import { donut, matrixHeatmap } from '../../charts/options'
import { fmtInt } from '../../lib/format'
import { DetectionList, KICKER, TARGET_LABEL, TYPE_LABEL, Viz } from './shared'

type K = 'type' | 'target' | 'campaign_id'

export default function Detections() {
  const { tokens: t } = useTheme()
  const f = useFilters<K>()
  const params = { type: f.get('type') || undefined, target: f.get('target') || undefined, campaign_id: f.get('campaign_id') ? Number(f.get('campaign_id')) : undefined }
  const q = useQuery({ queryKey: ['phishing', 'detections', params], queryFn: () => api.phishing.detections(params), retry: false, placeholderData: (p) => p })
  const campaigns = useQuery({ queryKey: ['phishing', 'campaigns', {}], queryFn: () => api.phishing.campaigns(), retry: false })
  const v = usePhishingViz()
  const m = v.data?.detections_matrix
  const o = useMemo(() => {
    if (!v.data || !m) return null
    return {
      matrix: matrixHeatmap(m.targets.map((x) => TARGET_LABEL[x] ?? x), m.types.map((x) => TYPE_LABEL[x] ?? x), m.cells.map(([ty, tg, n]) => [tg, ty, n] as [number, number, number]), t, { unit: 'rules', showValues: true, yWidth: 100 }),
      types: donut(v.data.detections_by_type.map((x) => ({ name: TYPE_LABEL[x.key] ?? x.key, value: x.count })), t, { centerLabel: 'rules' }),
    }
  }, [v.data, m, t])
  const total = v.data?.detections_by_type.reduce((a, x) => a + x.count, 0) ?? 0
  const count = (k: string) => v.data?.detections_by_type.find((x) => x.key === k)?.count ?? 0
  const chips = ([
    f.get('type') && { key: 'type', label: `Type: ${TYPE_LABEL[f.get('type')] ?? f.get('type')}` },
    f.get('target') && { key: 'target', label: `Target: ${TARGET_LABEL[f.get('target')] ?? f.get('target')}` },
    f.get('campaign_id') && { key: 'campaign_id', label: `Campaign: ${campaigns.data?.find((c) => String(c.id) === f.get('campaign_id'))?.name ?? f.get('campaign_id')}` },
  ].filter(Boolean) as { key: K; label: string }[]).map((c) => ({ ...c, onRemove: () => f.set(c.key, '') }))

  return (
    <>
      <PageHeader kicker={KICKER} title="Detections" subtitle="Campaign-level rules a mail or web gateway can load: Sigma for proxy and mail logs, YARA for page content, URL regexes and IOC blocklists."
        actions={<>{(['sigma', 'yara', 'iocs', 'stix'] as const).map((x) => <a key={x} className="btn btn-ghost" href={api.phishing.exportUrl(x)}><Download size={14} />{x === 'iocs' ? 'IOCs' : x.toUpperCase()}</a>)}<RunPipelineButton name="phishing" label="Run pipeline" variant="secondary" /></>} />
      {v.data && <StatStrip items={[
        { label: 'Rules', value: fmtInt(total), sub: `${fmtInt(v.data.bubbles.length)} multi-page campaigns covered` },
        { label: 'Sigma', value: fmtInt(count('sigma')), sub: 'proxy + email logs' },
        { label: 'YARA', value: fmtInt(count('yara')), sub: 'kit HTML content' },
        { label: 'URL regex', value: fmtInt(count('url_regex')), sub: 'web gateway' },
        { label: 'IOC lists', value: fmtInt(count('ioc_domain') + count('ioc_ip') + count('ioc_url')), sub: 'domains · IPs · URLs' },
      ]} />}
      <Grid>
        <Span n={8}><Viz title="Coverage by control" question="Which security control gets which kind of rule?" source="detection generator" query={qstate(v)} height={240} option={o?.matrix}
          onEvents={{ click: (p: { componentType: string; value: [number, number, number] }) => { if (p.componentType === 'series' && m) { f.set('target', m.targets[p.value[0]]); f.set('type', m.types[p.value[1]]) } } }}
          table={m ? { columns: ['type', ...m.targets], rows: m.types.map((ty, i) => [TYPE_LABEL[ty] ?? ty, ...m.targets.map((_, j) => m.cells.find((c) => c[0] === i && c[1] === j)?.[2] ?? 0)]) } : undefined} /></Span>
        <Span n={4}><Viz title="Rule mix" question="What kinds of rules were produced?" source="detection generator" query={qstate(v)} height={240} option={o?.types} /></Span>
      </Grid>
      <FilterBar>
        <Select value={f.get('type')} onChange={(x) => f.set('type', x)} label="Type" options={[{ value: '', label: 'All types' }, ...(m?.types ?? []).map((x) => ({ value: x, label: TYPE_LABEL[x] ?? x }))]} />
        <Select value={f.get('target')} onChange={(x) => f.set('target', x)} label="Target" options={[{ value: '', label: 'All controls' }, ...(m?.targets ?? []).map((x) => ({ value: x, label: TARGET_LABEL[x] ?? x }))]} />
        <Select value={f.get('campaign_id')} onChange={(x) => f.set('campaign_id', x)} label="Campaign" options={[{ value: '', label: 'All campaigns' }, ...(campaigns.data ?? []).filter((c) => c.detection_count).map((c) => ({ value: String(c.id), label: `${c.name}${c.brand ? ` · ${c.brand}` : ''}` }))]} />
      </FilterBar>
      <FilterChips filters={chips} onClear={f.clear} count={q.data ? <span><b className="num" style={{ color: 'var(--text)' }}>{fmtInt(q.data.length)}</b> rules</span> : undefined} />
      {q.isLoading ? <Loading rows={6} /> : q.error && !isNoData(q.error) ? <ErrorState error={q.error} /> : (q.data?.length ? <DetectionList items={q.data.slice(0, 150)} showCampaign /> : <ModuleEmpty pipeline="phishing" title="No detections" icon={<ShieldCheck size={24} />} hint={chips.length ? 'No rule matches these filters.' : undefined} />)}
      {q.data && q.data.length > 150 && <p className="muted" style={{ fontSize: 12, marginTop: 10 }}>Showing the first 150 of {fmtInt(q.data.length)} rules. Narrow the filters, or download the full bundles above.</p>}
    </>
  )
}
