import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { FileText, Sparkles, Loader2 } from 'lucide-react'
import { api } from '../../lib/api'
import { PageHeader, Card, Badge, StatusBadge, Button, Input, Loading, ErrorState, EmptyState } from '../../components/ui'
import { Grid, Span } from '../../components/ui/Grid'
import { RunPipelineButton, isNoData } from '../../components/ui/RunPipelineButton'
import { columns } from '../../charts/options'
import { fmtAgo } from '../../lib/format'
import { fmtYm } from '../../lib/viz'
import { MiniSpark, SRC, Viz, monthLabel, useTokens, useViz } from './shared'

function lastFullMonth() { const d = new Date(); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() - 1); return d.toISOString().slice(0, 7) }

export default function Briefings() {
  const qc = useQueryClient()
  const nav = useNavigate()
  const t = useTokens()
  const q = useQuery({ queryKey: ['landscape', 'briefings'], queryFn: api.landscape.briefings, retry: false })
  const scope = useQuery({ queryKey: ['scope'], queryFn: api.scope.get })
  const viz = useViz(12)
  const [period, setPeriod] = useState(lastFullMonth())
  const [useLlm, setUseLlm] = useState(false)
  const gen = useMutation({
    mutationFn: () => api.landscape.generateBriefing(period, useLlm),
    onSuccess: (b) => { qc.invalidateQueries({ queryKey: ['landscape', 'briefings'] }); qc.invalidateQueries({ queryKey: ['overview'] }); nav(`/landscape/briefings/${b.id}`) },
  })
  const months = viz.data?.months ?? []
  const scopeSeries = viz.data?.series.scope ?? []
  const briefed = new Set((q.data ?? []).map((b) => b.period))
  const cadence = useMemo(() => columns(months.map((m, i) => ({ label: fmtYm(m), value: scopeSeries[i] ?? 0, title: `${monthLabel(m)}${briefed.has(m) ? ' · briefing published' : ''}`, color: briefed.has(m) ? t.accent : t.seq[2] })), t, { unit: 'in-scope victims', showValues: true }), [months, scopeSeries, briefed, t]) // eslint-disable-line react-hooks/exhaustive-deps

  const header = (
    <PageHeader kicker="P6 · Threat landscape" title="Monthly briefings"
      subtitle={scope.data ? <>Short CISO briefings for {scope.data.landscape.sector} in {scope.data.landscape.region}: who targeted companies like us, how, and what it means for priorities and budget.</> : undefined}
      actions={<RunPipelineButton name="landscape" label="Refresh data" variant="secondary" size="sm" />} />
  )
  return (
    <>
      {header}
      <Grid>
        <Span n={8}>
          <Viz title="Briefing coverage" question="How many in-scope victims did each month's briefing have to explain?" source={SRC.rl} height={200}
            query={{ isLoading: viz.isLoading, isError: viz.isError, error: viz.error, isFetching: viz.isFetching, refetch: viz.refetch }} option={months.length ? cadence : null}
            caveat="highlighted months have a briefing · click a month to prefill the generator"
            onEvents={{ click: (p) => { const m = months[p.dataIndex]; if (m) { const b = q.data?.find((x) => x.period === m); if (b) nav(`/landscape/briefings/${b.id}`); else setPeriod(m) } } }} />
        </Span>
        <Span n={4}>
          <Card title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><Sparkles size={14} style={{ color: 'var(--accent)' }} /> Generate briefing</span>} subtitle="Built from the victims, actors, access-broker reports and incidents already ingested for the period.">
            <div style={{ display: 'grid', gap: 12 }}>
              <label><div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>Period</div><Input type="month" value={period} onChange={setPeriod} className="w-full" /></label>
              <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12.5, color: 'var(--text-2)' }}><input type="checkbox" checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} style={{ marginTop: 3 }} /><span>Rewrite the narrative with Claude <span className="muted">(needs CTIOPS_ANTHROPIC_API_KEY; tables stay template-generated, falls back silently)</span></span></label>
              <div><Button variant="primary" disabled={gen.isPending || !period} onClick={() => gen.mutate()}>{gen.isPending ? <Loader2 size={14} className="spin" /> : <FileText size={14} />} Generate {monthLabel(period)}</Button></div>
              {gen.error && <ErrorState error={gen.error} />}
            </div>
          </Card>
        </Span>
      </Grid>
      {q.isLoading ? <Loading rows={4} /> : q.error && !isNoData(q.error) ? <ErrorState error={q.error} /> : q.data?.length ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
          {q.data.map((b) => {
            const idx = months.indexOf(b.period)
            const n = idx >= 0 ? scopeSeries[idx] : null
            const prev = idx > 0 ? scopeSeries[idx - 1] : null
            const delta = n != null && prev ? Math.round(((n - prev) / prev) * 100) : null
            return (
              <Link key={b.id} to={`/landscape/briefings/${b.id}`} className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 10, textDecoration: 'none', color: 'inherit' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <span style={{ fontSize: 10.5, fontWeight: 600, letterSpacing: '.08em', textTransform: 'uppercase', color: 'var(--accent)' }}>{monthLabel(b.period)}</span>
                  <span style={{ display: 'flex', gap: 4 }}><StatusBadge status={b.status} /><Badge tone={b.generator === 'llm' ? 'accent' : 'neutral'}>{b.generator}</Badge></span>
                </div>
                <div style={{ fontWeight: 600, fontSize: 14, lineHeight: 1.35, color: 'var(--text)' }}>{b.title}</div>
                <div style={{ display: 'flex', alignItems: 'flex-end', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 24, fontWeight: 650, letterSpacing: '-0.02em', lineHeight: 1 }}>{n ?? '—'}</div>
                    <div className="muted" style={{ fontSize: 11 }}>in-scope victims{delta != null && <span style={{ color: delta > 0 ? 'var(--bad-text)' : 'var(--good-text)', marginLeft: 4 }}>{delta > 0 ? '+' : ''}{delta}%</span>}</div>
                  </div>
                  {idx > 0 && <div style={{ marginLeft: 'auto' }}><MiniSpark values={scopeSeries.slice(0, idx + 1)} labels={months.slice(0, idx + 1)} width={120} height={36} /></div>}
                </div>
                <div className="muted" style={{ fontSize: 11.5, marginTop: 'auto' }}>{b.sector} · {b.region} · generated {fmtAgo(b.generated_at)}</div>
              </Link>
            )
          })}
        </div>
      ) : <Card><EmptyState icon={<FileText size={24} />} title="No briefings yet" hint="Generate one for the latest full month. The landscape pipeline must have ingested data for that period first." /></Card>}
    </>
  )
}
