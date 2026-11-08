import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ClipboardCheck } from 'lucide-react'
import { api } from '../lib/api'
import { PageHeader, Card, DataTable, VerdictBadge, EmptyState, Loading, ErrorState, Badge } from '../components/ui'
import { StatStrip } from '../components/ui/controls'
import { Grid, Span } from '../components/ui/Grid'
import { ChartCard } from '../components/ui/ChartCard'
import { EChart } from '../charts/EChart'
import { useTheme } from '../theme/ThemeProvider'
import { ratioGauge, timeSeries } from '../charts/options'
import { fmtDateTime, fmtInt } from '../lib/format'
import type { ReviewOut } from '../lib/types'
import { fitGauge } from './phishing/shared'

const LABEL: Record<string, string> = { campaign: 'Campaigns', sample: 'Samples', kit: 'Kits', victim: 'Victims', actor: 'Actors', iab: 'IAB listings', briefing: 'Briefings' }
const LINK: Record<string, (id: number) => string> = {
  campaign: (id) => `/phishing/campaigns/${id}`, sample: (id) => `/phishing/samples/${id}`, kit: (id) => `/phishing/kits/${id}`,
  briefing: (id) => `/landscape/briefings/${id}`, victim: () => '/landscape/victims', actor: () => '/landscape/actors', iab: () => '/landscape/iab',
}
const WHAT: Record<string, string> = {
  campaign: 'Are these pages really one campaign?', sample: 'Is this a phishing page for the detected brand?', kit: 'Is the kit attribution right?',
  victim: 'Are sector, region and size right?', actor: 'Is the actor profile and trend right?', iab: 'Is this really an access listing, with the right price?', briefing: 'Is the briefing accurate and useful?',
}

export default function Review() {
  const { tokens: t } = useTheme()
  const summary = useQuery({ queryKey: ['reviews', 'summary'], queryFn: api.reviews.summary })
  const recent = useQuery({ queryKey: ['reviews', 'recent'], queryFn: () => api.reviews.list() })
  const s = summary.data ?? []
  const totals = s.reduce((a, r) => ({ reviewed: a.reviewed + r.reviewed, agree: a.agree + r.agree, over: a.over + r.over_flag, miss: a.miss + r.miss }), { reviewed: 0, agree: 0, over: 0, miss: 0 })
  const stacked = useMemo(() => timeSeries(s.map((r) => LABEL[r.entity_type] ?? r.entity_type), [
    { name: 'Agree', data: s.map((r) => r.agree), type: 'bar', stack: 'v', color: t.good },
    { name: 'Over-flagged', data: s.map((r) => r.over_flag), type: 'bar', stack: 'v', color: t.sev.CRITICAL },
    { name: 'Missed', data: s.map((r) => r.miss), type: 'bar', stack: 'v', color: t.sev.MEDIUM },
    { name: 'Unsure', data: s.map((r) => r.unsure), type: 'bar', stack: 'v', color: t.other },
  ], t, { xFormat: (x) => x }), [s, t])
  const q = { isLoading: summary.isLoading, isError: summary.isError, error: summary.error, refetch: summary.refetch }

  return (
    <>
      <PageHeader kicker="System" title="Analyst review" subtitle="The hand check the evaluation asks for: an analyst marks a sample of outputs as agree, over-flagged, missed or unsure, and this page turns those verdicts into precision figures for the know-how report." />
      <StatStrip items={[
        { label: 'Outputs checked', value: fmtInt(totals.reviewed), sub: 'latest verdict per item' },
        { label: 'Agree', value: fmtInt(totals.agree), sub: totals.reviewed ? `${Math.round((totals.agree / totals.reviewed) * 100)}% of checked` : undefined },
        { label: 'Over-flagged', value: fmtInt(totals.over), sub: 'false positives' },
        { label: 'Missed', value: fmtInt(totals.miss), sub: 'false negatives found by hand' },
        { label: 'Overall precision', value: totals.agree + totals.over ? `${Math.round((totals.agree / (totals.agree + totals.over)) * 100)}%` : '—', sub: 'agree ÷ (agree + over-flagged)' },
      ]} />
      {summary.isLoading ? <Loading /> : summary.error ? <ErrorState error={summary.error} /> : !s.length ? (
        <Card><EmptyState icon={<ClipboardCheck size={22} />} title="No verdicts yet" hint="Open any campaign, sample, kit, victim, actor, IAB listing or briefing and use the Hand check panel. Aim for 20 to 30 items per module, picked at random." /></Card>
      ) : (
        <>
          <Grid>
            <Span n={12}>
              <ChartCard title="Precision by output type" question="Of the items checked, how often was the automation right?" source="analyst verdicts" query={q} height={170} png={false}
                table={{ columns: ['type', 'checked', 'agree', 'over-flagged', 'missed', 'unsure', 'precision'], rows: s.map((r) => [LABEL[r.entity_type] ?? r.entity_type, r.reviewed, r.agree, r.over_flag, r.miss, r.unsure, r.precision_proxy == null ? '—' : `${Math.round(r.precision_proxy * 100)}%`]) }}
                render={() => (
                  <div style={{ display: 'grid', gridTemplateColumns: `repeat(${s.length}, minmax(130px, 1fr))`, gap: 12 }}>
                    {s.map((r) => <EChart key={r.entity_type} option={fitGauge(ratioGauge(r.precision_proxy, t, { label: `${LABEL[r.entity_type] ?? r.entity_type} · ${r.reviewed} checked` }))} height={170} renderer="svg" ariaLabel={`${r.entity_type} precision`} />)}
                  </div>
                )} />
            </Span>
          </Grid>
          <Grid>
            <Span n={8}><ChartCard title="Verdict mix" question="Where does the automation over-flag or miss?" source="analyst verdicts" query={q} height={260} render={(h) => <EChart option={stacked} height={260} ariaLabel="Verdicts by type" handle={h} />} /></Span>
            <Span n={4}>
              <Card title="What each check asks">
                <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
                  {Object.entries(WHAT).map(([k, v]) => <div key={k} style={{ display: 'grid', gridTemplateColumns: '96px 1fr', gap: 8 }}><Badge>{LABEL[k]}</Badge><span className="secondary">{v}</span></div>)}
                </div>
              </Card>
            </Span>
          </Grid>
        </>
      )}
      <Card title="Recent verdicts" padded={false}>
        <div style={{ padding: '0 12px 12px' }}>
          <DataTable<ReviewOut> rows={recent.data ?? []} rowKey={(r) => r.id} maxHeight="55vh" empty={<EmptyState title="No verdicts recorded" />}
            columns={[
              { key: 'when', header: 'When', sort: (r) => r.created_at, render: (r) => <span className="num muted">{fmtDateTime(r.created_at)}</span> },
              { key: 'type', header: 'Type', sort: (r) => r.entity_type, render: (r) => <Badge>{LABEL[r.entity_type] ?? r.entity_type}</Badge> },
              { key: 'id', header: 'Item', render: (r) => <Link to={(LINK[r.entity_type] ?? (() => '#'))(r.entity_id)} className="mono">#{r.entity_id}</Link> },
              { key: 'v', header: 'Verdict', sort: (r) => r.verdict, render: (r) => <VerdictBadge verdict={r.verdict} /> },
              { key: 'n', header: 'Note', render: (r) => <span className="secondary" style={{ whiteSpace: 'normal' }}>{r.note ?? '—'}</span> },
              { key: 'who', header: 'Reviewer', render: (r) => <span className="muted">{r.reviewer}</span> },
            ]} />
        </div>
      </Card>
    </>
  )
}
