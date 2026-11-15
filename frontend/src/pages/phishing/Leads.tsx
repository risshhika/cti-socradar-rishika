import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { SpellCheck } from 'lucide-react'
import { api } from '../../lib/api'
import { SOURCE_LABEL } from '../../lib/phishingViz'
import type { LeadOut } from '../../lib/types'
import { Badge, Card, DataTable, ErrorState, KeyCountBars, Loading, PageHeader, Pagination, StatusBadge } from '../../components/ui'
import { FilterBar, FilterChips, SearchInput, Select, StatStrip } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ModuleEmpty, RunPipelineButton, isNoData } from '../../components/ui/RunPipelineButton'
import { useFilters } from '../../components/ui/useParams'
import { useTheme } from '../../theme/ThemeProvider'
import { timeSeries } from '../../charts/options'
import { fmtDate, fmtInt } from '../../lib/format'
import { fmtDay } from '../../lib/viz'
import { KICKER, MATCH_KIND_LABEL, RankFactors, ThreatPill, TIER_ORDER, Viz } from './shared'

const SIZE = 50
type K = 'brand' | 'match_kind' | 'source' | 'threat_tier' | 'status' | 'q' | 'sort' | 'page'

const STATUS_HINT: Record<string, string> = {
  new: 'matched, not fetched yet', promoted: 'queued for capture', live: 'page answered', offline: 'nothing served', blocked: 'refused the fetch',
}

/** Highlight the brand-imitating label inside the domain. */
function DomainCell({ d }: { d: LeadOut }) {
  return (
    <div style={{ maxWidth: 340 }}>
      <div className="mono" style={{ color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={d.domain}>{d.domain}</div>
      <div className="muted" style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={d.evidence ?? ''}>{d.evidence}</div>
    </div>
  )
}

export default function Leads() {
  const { tokens: t } = useTheme()
  const f = useFilters<K>()
  const params = {
    brand: f.get('brand') || undefined, match_kind: f.get('match_kind') || undefined, source: f.get('source') || undefined,
    threat_tier: f.get('threat_tier') || undefined, status: f.get('status') || undefined, q: f.get('q') || undefined,
    sort: (f.get('sort') || 'threat') as 'threat' | 'recent', page: f.page, size: SIZE,
  }
  const q = useQuery({ queryKey: ['phishing', 'leads', params], queryFn: () => api.phishing.leads(params), retry: false, placeholderData: (prev) => prev })
  const st = useQuery({ queryKey: ['phishing', 'leads', 'stats'], queryFn: api.phishing.leadStats, retry: false })
  const s = st.data
  const timeline = useMemo(() => {
    if (!s?.timeline.length) return undefined
    return timeSeries(s.timeline.map((p) => p.period), [{ name: 'New typosquat leads', data: s.timeline.map((p) => p.value), area: true, color: t.series[0] }], t,
      { xFormat: (x) => fmtDay(x, { month: 'short', day: 'numeric' }) })
  }, [s, t])
  const tier = (k: string) => s?.by_tier.find((x) => x.key === k)?.count ?? 0
  const dtype = (k: string) => s?.detection_types.find((x) => x.key === k)?.count ?? 0
  const opt = (arr: { key: string; count: number }[] | undefined, all: string, fmt = (k: string) => k) =>
    [{ value: '', label: all }, ...(arr ?? []).map((b) => ({ value: b.key, label: `${fmt(b.key)} (${b.count})` }))]
  const chips = ([
    f.get('q') && { key: 'q', label: `“${f.get('q')}”` }, f.get('brand') && { key: 'brand', label: `Brand: ${f.get('brand')}` },
    f.get('match_kind') && { key: 'match_kind', label: `Match: ${MATCH_KIND_LABEL[f.get('match_kind')] ?? f.get('match_kind')}` },
    f.get('source') && { key: 'source', label: `Source: ${SOURCE_LABEL[f.get('source')] ?? f.get('source')}` },
    f.get('threat_tier') && { key: 'threat_tier', label: `Threat: ${f.get('threat_tier')}` }, f.get('status') && { key: 'status', label: `Status: ${f.get('status')}` },
  ].filter(Boolean) as { key: K; label: string }[]).map((c) => ({ ...c, onRemove: () => f.set(c.key, '') }))

  return (
    <>
      <PageHeader kicker={KICKER} title="Typosquat leads"
        subtitle={<>Hostnames that imitate a scope brand: newly-registered domains from WhoisDS (often before any feed reports them) plus typosquat hosts reported by urlscan.io, OpenPhish and PhishTank. Brands match as fragment chains (<span className="mono">pay*pal*</span>, <span className="mono">wel*far*go</span>) after homoglyph normalisation, plus one- or two-letter typos. Pages that never name the brand in the host are covered under Samples as <i>content only</i>.</>}
        actions={<><a className="btn btn-ghost" href={api.phishing.exportUrl('leads-csv')}>Leads CSV</a><RunPipelineButton name="phishing" label="Run pipeline" variant="secondary" /></>} />
      {s && <StatStrip items={[
        { label: 'Typosquat leads', value: fmtInt(s.leads), sub: s.by_source.map((x) => `${SOURCE_LABEL[x.key] ?? x.key} ${x.count}`).join(' · ') },
        { label: 'Critical + high', value: fmtInt(tier('critical') + tier('high')), sub: `${tier('critical')} critical` },
        { label: 'Live when fetched', value: fmtInt(s.by_status.find((x) => x.key === 'live')?.count ?? 0), sub: `${s.by_status.find((x) => x.key === 'new')?.count ?? 0} not fetched yet` },
        { label: 'Samples by detection', value: `${fmtInt(dtype('typosquat'))} / ${fmtInt(dtype('content'))}`, sub: 'typosquat host / content only' },
      ]} />}
      <Grid>
        <Span n={6}><Viz title="New leads per day" question="How many brand-imitating hostnames appear each day?" source="WhoisDS NRD · urlscan.io · OpenPhish · PhishTank" query={st} height={200} option={timeline} /></Span>
        <Span n={3}>
          <Card title="By brand" subtitle="which brands are imitated">
            {s ? <KeyCountBars data={s.by_brand.slice(0, 10)} labelWidth={110} onClick={(k) => f.set('brand', k)} /> : <Loading rows={5} />}
          </Card>
        </Span>
        <Span n={3}>
          <Card title="By match type" subtitle="how the hostname imitates">
            {s ? <KeyCountBars data={s.by_kind.map((x) => ({ ...x, key: MATCH_KIND_LABEL[x.key] ?? x.key }))} labelWidth={110} onClick={(k) => f.set('match_kind', Object.entries(MATCH_KIND_LABEL).find(([, v]) => v === k)?.[0] ?? k)} /> : <Loading rows={4} />}
          </Card>
        </Span>
      </Grid>
      <FilterBar>
        <SearchInput value={f.get('q')} onChange={(x) => f.set('q', x)} placeholder="Search domain…" />
        <Select value={f.get('brand')} onChange={(x) => f.set('brand', x)} options={opt(s?.by_brand, 'All brands')} label="Brand" />
        <Select value={f.get('match_kind')} onChange={(x) => f.set('match_kind', x)} options={opt(s?.by_kind, 'Any match', (k) => MATCH_KIND_LABEL[k] ?? k)} label="Match" />
        <Select value={f.get('source')} onChange={(x) => f.set('source', x)} options={opt(s?.by_source, 'Any source', (k) => SOURCE_LABEL[k] ?? k)} label="Source" />
        <Select value={f.get('threat_tier')} onChange={(x) => f.set('threat_tier', x)} options={[{ value: '', label: 'Any threat' }, ...TIER_ORDER.map((x) => ({ value: x, label: `${x[0].toUpperCase()}${x.slice(1)} (${tier(x)})` }))]} label="Threat" />
        <Select value={f.get('status')} onChange={(x) => f.set('status', x)} options={opt(s?.by_status, 'Any status')} label="Status" />
        <Select value={f.get('sort') || 'threat'} onChange={(x) => f.set('sort', x === 'threat' ? '' : x)} options={[{ value: 'threat', label: 'Highest threat first' }, { value: 'recent', label: 'Newest first' }]} label="Sort" />
      </FilterBar>
      <FilterChips filters={chips} onClear={f.clear} count={q.data ? <span><b className="num" style={{ color: 'var(--text)' }}>{fmtInt(q.data.page.total)}</b> leads</span> : undefined} />
      <Card padded={false}>
        <div style={{ padding: 12 }}>
          {q.isLoading ? <Loading rows={10} /> : q.error && !isNoData(q.error) ? <ErrorState error={q.error} /> : (
            <>
              <DataTable<LeadOut> rows={q.data?.items ?? []} rowKey={(r) => r.id} dense maxHeight="65vh"
                empty={<ModuleEmpty pipeline="phishing" title="No typosquat leads" icon={<SpellCheck size={24} />} hint={chips.length ? 'No lead matches these filters.' : 'Run the phishing pipeline to scan newly-registered domains.'} />}
                columns={[
                  { key: 'threat', header: 'Threat', sort: (r) => r.threat_score, render: (r) => <span title={r.rank_factors.map((x) => `${x.factor} ${x.points > 0 ? '+' : ''}${x.points}`).join('\n')}><ThreatPill tier={r.threat_tier} score={r.threat_score} /></span> },
                  { key: 'domain', header: 'Domain', sort: (r) => r.domain, render: (r) => <DomainCell d={r} /> },
                  { key: 'brand', header: 'Brand', sort: (r) => r.brand, render: (r) => <Badge tone="accent">{r.brand}</Badge> },
                  { key: 'kind', header: 'Match', sort: (r) => r.match_kind, render: (r) => <Badge tone={r.match_kind === 'homoglyph' || r.match_kind === 'embed' ? 'danger' : 'warn'}>{MATCH_KIND_LABEL[r.match_kind] ?? r.match_kind}</Badge> },
                  { key: 'lure', header: 'Lure words', render: (r) => r.lure_words.length ? <span className="mono" style={{ fontSize: 11 }}>{r.lure_words.join(' ')}</span> : <span className="muted">—</span> },
                  { key: 'src', header: 'Seen in', sort: (r) => r.sources.join(','), render: (r) => <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>{r.sources.map((x) => <Badge key={x}>{x}</Badge>)}</span> },
                  { key: 'status', header: 'Status', sort: (r) => r.status, render: (r) => <span title={STATUS_HINT[r.status] ?? ''}><StatusBadge status={r.status} /></span> },
                  { key: 'sample', header: 'Sample', render: (r) => r.sample_id ? <Link to={`/phishing/samples/${r.sample_id}`} className="mono">#{r.sample_id}</Link> : <span className="muted">—</span> },
                  { key: 'seen', header: 'First seen', sort: (r) => r.first_seen, render: (r) => <span className="muted num" style={{ whiteSpace: 'nowrap' }}>{fmtDate(r.first_seen)}</span> },
                ]} />
              {q.data && q.data.page.total > SIZE && <Pagination page={f.page} size={SIZE} total={q.data.page.total} onPage={f.setPage} />}
            </>
          )}
        </div>
      </Card>
      {q.data?.items[0] && q.data.items[0].rank_factors.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <Card title={`Why ${q.data.items[0].domain} ranks highest`} subtitle="every point and its reason">
            <RankFactors factors={q.data.items[0].rank_factors} />
          </Card>
        </div>
      )}
    </>
  )
}
