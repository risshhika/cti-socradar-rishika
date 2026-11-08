import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Fish, Radar } from 'lucide-react'
import { api } from '../lib/api'
import { PageHeader, Card, DataTable, StatusBadge, Badge, Loading, ErrorState, KV } from '../components/ui'
import { Grid, Span } from '../components/ui/Grid'
import { RunPipelineButton } from '../components/ui/RunPipelineButton'
import { ChartCard } from '../components/ui/ChartCard'
import { EChart } from '../charts/EChart'
import { useTheme } from '../theme/ThemeProvider'
import { fmtAgo, fmtDateTime, fmtDuration, fmtInt } from '../lib/format'
import type { PipelineInfo, RunOut } from '../lib/types'

const META: Record<string, { title: string; tag: string; icon: typeof Fish; desc: string }> = {
  phishing: { title: 'Phishing campaign clustering', tag: 'P4', icon: Fish, desc: 'urlscan.io search + OpenPhish → direct page capture → DOM and marker features → structural + DBSCAN clustering → kit fingerprinting → Sigma / YARA / IOC detections.' },
  landscape: { title: 'Sector threat landscape', tag: 'P6', icon: Radar, desc: 'ransomware.live victims + RansomLook cross-check → sector, region and size classification → actor trends → IAB mining from public reporting → monthly CISO briefing.' },
}

/** Headline numbers per pipeline, pulled from the run summary. */
function stageFacts(name: string, s: Record<string, any>): { k: string; v: string }[] {
  if (!s || !Object.keys(s).length) return []
  if (name === 'phishing') return [
    { k: 'Candidates', v: fmtInt(s.candidates) }, { k: 'Selected', v: fmtInt(s.selected) },
    { k: 'Captured live', v: fmtInt(s.samples_fetched_ok ?? s.fetch?.ok) }, { k: 'Campaigns', v: fmtInt(s.campaigns) },
    { k: 'Inferred kits', v: fmtInt(s.inferred_kits) }, { k: 'Detections', v: fmtInt(s.detections) },
  ]
  return [
    { k: 'Victim records', v: fmtInt(s.victims?.records_seen) }, { k: 'In scope', v: fmtInt(s.in_scope_victims) },
    { k: 'Cross-source rate', v: s.cross_source?.rate != null ? `${Math.round(s.cross_source.rate * 100)}%` : '—' }, { k: 'Actors', v: fmtInt(s.actors?.actors) },
    { k: 'IAB candidates', v: fmtInt(s.iab?.candidates) }, { k: 'Briefings', v: fmtInt(s.briefings?.length) },
  ]
}

function PipelineCard({ p, runs }: { p: PipelineInfo; runs: RunOut[] }) {
  const { tokens: t } = useTheme()
  const nav = useNavigate()
  const m = META[p.name] ?? { title: p.name, tag: '', icon: Fish, desc: '' }
  const mine = runs.filter((r) => r.pipeline === p.name).slice(0, 20).reverse()
  const done = mine.filter((r) => r.status === 'succeeded' || r.status === 'failed')
  const ok = done.filter((r) => r.status === 'succeeded').length
  const option = useMemo(() => ({
    animation: false,
    grid: { left: 4, right: 4, top: 14, bottom: 4, containLabel: true },
    tooltip: { trigger: 'item', formatter: (x: { dataIndex: number }) => { const r = mine[x.dataIndex]; return `Run #${r.id} · ${r.status}<br/>${fmtDateTime(r.started_at)}<br/><b>${fmtDuration(r.duration_seconds)}</b>` } },
    xAxis: { type: 'category', data: mine.map((r) => `#${r.id}`), axisLabel: { color: t.text3, fontSize: 10 } },
    yAxis: { type: 'value', min: 0, axisLabel: { color: t.text3, fontSize: 10, formatter: (v: number) => (v >= 60 ? `${Math.round(v / 60)}m` : `${v}s`) }, splitLine: { lineStyle: { color: t.grid } } },
    series: [{ type: 'bar', barMaxWidth: 18, cursor: 'pointer', itemStyle: { borderRadius: [3, 3, 0, 0] }, data: mine.map((r) => ({ value: Math.round(r.duration_seconds ?? 0), itemStyle: { color: r.status === 'failed' ? t.sev.CRITICAL : r.status === 'succeeded' ? t.accent : t.text3 } })) }],
  }), [mine, t])
  const last = p.last_run
  return (
    <ChartCard title={`${m.tag} · ${m.title}`} question={m.desc} source="pipeline_runs" query={{ isLoading: false, isError: false, error: null }} height={130} png={false}
      empty={!mine.length} emptyText="Never run: start it to collect data"
      actions={<RunPipelineButton name={p.name} label="Run now" size="sm" />}
      caveat={done.length ? `${ok}/${done.length} succeeded · bar = run duration, red = failed` : undefined}
      style={{ height: '100%' }}
      render={() => (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1.2fr)', gap: 16, alignItems: 'start' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              {p.running ? <Badge tone="info">running</Badge> : last ? <StatusBadge status={last.status} /> : <Badge>never run</Badge>}
              <span className="muted" style={{ fontSize: 12 }}>{last ? `${fmtAgo(last.finished_at ?? last.started_at)} · ${fmtDuration(last.duration_seconds)} · ${last.trigger}` : ''}</span>
            </div>
            <KV items={stageFacts(p.name, (last?.summary ?? {}) as Record<string, any>).map((x) => ({ k: x.k, v: <span className="num">{x.v}</span> }))} />
          </div>
          <EChart option={option} height={130} renderer="svg" ariaLabel={`${p.name} run durations`} onEvents={{ click: (x: { dataIndex: number }) => nav(`/pipelines/runs/${mine[x.dataIndex].id}`) }} />
        </div>
      )} />
  )
}

export default function Pipelines() {
  const nav = useNavigate()
  const list = useQuery({ queryKey: ['pipelines'], queryFn: api.pipelines.list, refetchInterval: 3000 })
  const anyRunning = list.data?.some((p) => p.running) ?? false
  const runs = useQuery({ queryKey: ['pipelines', 'runs'], queryFn: () => api.pipelines.runs(undefined, 100), refetchInterval: anyRunning ? 3000 : 15000 })
  return (
    <>
      <PageHeader kicker="System" title="Pipelines & runs" subtitle="Each run starts from public sources, is logged line by line, and records per-source health. Re-running is safe: upserts are idempotent." />
      {list.isLoading ? <Loading /> : list.error ? <ErrorState error={list.error} /> : (
        <Grid>
          {(list.data ?? []).map((p) => <Span key={p.name} n={6}><PipelineCard p={p} runs={runs.data ?? []} /></Span>)}
        </Grid>
      )}
      <Card title="Run history" subtitle="Click a run for its live log and summary" padded={false}>
        <div style={{ padding: '0 12px 12px' }}>
          <DataTable<RunOut> rows={runs.data ?? []} rowKey={(r) => r.id} onRowClick={(r) => nav(`/pipelines/runs/${r.id}`)} maxHeight="60vh"
            columns={[
              { key: 'id', header: 'Run', sort: (r) => r.id, render: (r) => <span className="mono">#{r.id}</span> },
              { key: 'p', header: 'Pipeline', sort: (r) => r.pipeline, render: (r) => <Badge tone="accent">{META[r.pipeline]?.tag ?? ''} {r.pipeline}</Badge> },
              { key: 's', header: 'Status', sort: (r) => r.status, render: (r) => <StatusBadge status={r.status} /> },
              { key: 't', header: 'Trigger', sort: (r) => r.trigger, render: (r) => <span className="muted">{r.trigger}</span> },
              { key: 'st', header: 'Started', sort: (r) => r.started_at, render: (r) => <span className="num">{fmtDateTime(r.started_at)}</span> },
              { key: 'd', header: 'Duration', align: 'right', sort: (r) => r.duration_seconds, render: (r) => <span className="num">{fmtDuration(r.duration_seconds)}</span> },
              { key: 'sum', header: 'Summary', render: (r) => <span className="muted" style={{ fontSize: 12 }}>{stageFacts(r.pipeline, r.summary as Record<string, any>).slice(0, 4).map((x) => `${x.k} ${x.v}`).join(' · ') || (r.error ? r.error.split('\n')[0] : '—')}</span> },
            ]} />
        </div>
      </Card>
    </>
  )
}
