import { useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { ArrowLeft, CheckCircle2, Download, Printer } from 'lucide-react'
import { api } from '../../lib/api'
import { PageHeader, Card, Badge, StatusBadge, KV, Loading, ErrorState, LinkButton } from '../../components/ui'
import { ReviewPanel } from '../../components/ui/ReviewPanel'
import { CopyButton } from '../../components/ui/CopyButton'
import { KpiTile } from '../../components/ui/KpiTile'
import { EChart } from '../../charts/EChart'
import { donut, horizontalBars } from '../../charts/options'
import { countryName } from '../../charts/countries'
import { fmtDateTime } from '../../lib/format'
import { landscapeViz } from '../../lib/landscapeViz'
import { SRC, SectionTitle, monthLabel, useTokens, useViz } from './shared'

type Pair = [string, number]

function Mini({ title, children }: { title: string; children: React.ReactNode }) {
  return <div><SectionTitle>{title}</SectionTitle>{children}</div>
}

export default function BriefingDetail() {
  const { id } = useParams()
  const bid = Number(id)
  const t = useTokens()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['landscape', 'briefing', bid], queryFn: () => api.landscape.briefing(bid) })
  const viz = useViz(12)
  const fin = useMutation({ mutationFn: () => landscapeViz.finalizeBriefing(bid), onSuccess: () => { qc.invalidateQueries({ queryKey: ['landscape', 'briefing', bid] }); qc.invalidateQueries({ queryKey: ['landscape', 'briefings'] }) } })
  const b = q.data
  const st = (b?.stats ?? {}) as Record<string, any>
  const charts = useMemo(() => ({
    groups: horizontalBars(((st.top_groups_scope ?? []) as Pair[]).map(([k, v]) => ({ label: k, value: v })), t, { unit: 'victims', labelWidth: 90 }),
    region: horizontalBars(((st.top_groups_region ?? []) as Pair[]).map(([k, v]) => ({ label: k, value: v })), t, { unit: 'victims', labelWidth: 90, color: t.series[2] }),
    countries: horizontalBars(((st.countries ?? []) as Pair[]).map(([k, v]) => ({ label: countryName(k), value: v })), t, { unit: 'victims', labelWidth: 90, color: t.series[1] }),
    sizes: donut(((st.sizes ?? []) as Pair[]).map(([k, v]) => ({ name: k, value: v, color: k === 'unknown' ? t.other : undefined })), t, { centerLabel: 'victims', legend: 'bottom' }),
  }), [st, t])

  const back = <Link to="/landscape/briefings" className="btn btn-ghost" style={{ textDecoration: 'none' }}><ArrowLeft size={14} /> Briefings</Link>
  if (q.isLoading) return <><PageHeader kicker="P6 · Monthly briefing" title="Loading…" actions={back} /><Loading rows={10} /></>
  if (q.error || !b) return <><PageHeader kicker="P6 · Monthly briefing" title="Briefing not found" actions={back} /><ErrorState error={q.error ?? 'Not found'} /></>

  const months = viz.data?.months ?? []
  const idx = months.indexOf(b.period)
  const trend = idx >= 0 ? viz.data!.series.scope.slice(0, idx + 1) : []
  const dq = (st.data_quality ?? {}) as Record<string, any>
  const h = (n: number) => Math.max(90, n * 26 + 16)

  return (
    <>
      <PageHeader kicker="P6 · Monthly briefing" title={`${monthLabel(b.period)} briefing`}
        subtitle={<>{b.sector} · {b.region} · {monthLabel(b.period)} · generated {fmtDateTime(b.generated_at)}</>}
        actions={<>
          {back}
          <CopyButton text={b.markdown} label="Copy Markdown" />
          <LinkButton href={api.landscape.exportUrl('briefing-md', b.id)}><Download size={14} /> .md</LinkButton>
          <button className="btn btn-ghost" onClick={() => window.print()}><Printer size={14} /> Print</button>
          {b.status !== 'final' && <button className="btn btn-primary" disabled={fin.isPending} onClick={() => fin.mutate()}><CheckCircle2 size={14} /> Mark final</button>}
        </>} />
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 360px', gap: 16, alignItems: 'start' }} className="briefing-layout">
        <Card>
          <div style={{ display: 'flex', gap: 6, marginBottom: 14 }}><StatusBadge status={b.status} /><Badge tone={b.generator === 'llm' ? 'accent' : 'neutral'}>{b.generator === 'llm' ? 'LLM-assisted narrative' : 'Template narrative'}</Badge></div>
          <article className="prose-brief" style={{ maxWidth: 860, overflowX: 'auto', width: 0, minWidth: '100%' }}><ReactMarkdown remarkPlugins={[remarkGfm]}>{b.markdown}</ReactMarkdown></article>
        </Card>
        <aside style={{ position: 'sticky', top: 0, display: 'grid', gap: 16 }}>
          <KpiTile kpi={{ label: 'In-scope victims', value: st.scope_victims ?? null, prev: st.prev_scope_victims ?? null, window: monthLabel(b.period), spark: trend.length > 1 ? trend : undefined, sparkLabels: months.slice(0, idx + 1), source: SRC.rl, note: st.sector_share_pct != null ? `${st.sector_share_pct}% of ${b.region} victims` : undefined }} />
          <Card title="At a glance" subtitle="The numbers behind this briefing">
            <div style={{ display: 'grid', gap: 16 }}>
              {(st.top_groups_scope ?? []).length > 0 && <Mini title="Most active against scope"><EChart option={charts.groups} height={h((st.top_groups_scope ?? []).length)} ariaLabel="Top groups in scope" /></Mini>}
              {(st.countries ?? []).length > 0 && <Mini title="Countries"><EChart option={charts.countries} height={h((st.countries ?? []).length)} ariaLabel="Countries" /></Mini>}
              {(st.top_groups_region ?? []).length > 0 && <Mini title={`Most active in ${b.region} (all sectors)`}><EChart option={charts.region} height={h((st.top_groups_region ?? []).length)} ariaLabel="Top groups in region" /></Mini>}
              {(st.sizes ?? []).length > 0 && <Mini title="Victim size"><EChart option={charts.sizes} height={190} ariaLabel="Victim size" /></Mini>}
            </div>
          </Card>
          <Card title="Data quality">
            <KV items={[
              { k: 'Cross-source', v: dq.cross_rate ?? '—' },
              { k: 'Sector from source', v: dq.sector_source != null ? `${dq.sector_source}%` : '—' },
              { k: 'Sector by keyword / LLM', v: dq.sector_keyword != null ? `${dq.sector_keyword}% / ${dq.sector_llm ?? 0}%` : '—' },
              { k: 'Size known', v: dq.size_known != null ? `${dq.size_known}%` : '—' },
              { k: 'IAB reports', v: st.iab_reports ?? '—' },
            ]} />
          </Card>
          <Card title="Analyst review" subtitle="Would you send this to the CISO as is?"><ReviewPanel entityType="briefing" entityId={b.id} /></Card>
        </aside>
      </div>
      <style>{`@media (max-width: 1100px) { .briefing-layout { grid-template-columns: 1fr !important; } .briefing-layout aside { position: static !important; } }`}</style>
    </>
  )
}
