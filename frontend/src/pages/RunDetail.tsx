import { useEffect, useRef } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Loader2 } from 'lucide-react'
import { api } from '../lib/api'
import { PageHeader, Card, StatusBadge, Code, Loading, ErrorState } from '../components/ui'
import { StatStrip } from '../components/ui/controls'
import { Grid, Span } from '../components/ui/Grid'
import { fmtDateTime, fmtDuration } from '../lib/format'
import d from '../components/ui/dash.module.css'

export default function RunDetail() {
  const { id } = useParams()
  const runId = Number(id)
  const q = useQuery({ queryKey: ['pipelines', 'run', runId], queryFn: () => api.pipelines.run(runId), refetchInterval: (query) => (query.state.data?.status === 'running' || query.state.data?.status === 'queued' ? 2000 : false) })
  const logRef = useRef<HTMLDivElement>(null)
  const live = q.data?.status === 'running' || q.data?.status === 'queued'
  useEffect(() => { if (live && logRef.current) { const pre = logRef.current.querySelector('pre'); if (pre) pre.scrollTop = pre.scrollHeight } }, [q.data?.log, live])
  const back = <Link to="/pipelines" className="btn btn-ghost"><ArrowLeft size={14} /> Pipelines</Link>
  if (q.isLoading) return <><PageHeader kicker="System" title={`Run #${runId}`} actions={back} /><Loading rows={6} /></>
  if (q.error || !q.data) return <><PageHeader kicker="System" title={`Run #${runId}`} actions={back} /><ErrorState error={q.error ?? 'Run not found'} /></>
  const r = q.data
  const sources = ((r.summary as Record<string, any>)?.sources ?? {}) as Record<string, { status?: string; detail?: string } | string>
  const lines = r.log ? r.log.split('\n').length : 0
  return (
    <>
      <PageHeader kicker="System" title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>Run #{r.id} · {r.pipeline}<StatusBadge status={r.status} />{live && <Loader2 size={16} className="spin" style={{ color: 'var(--accent)' }} />}</span>}
        subtitle={live ? 'Live: the log refreshes every 2 seconds.' : `Finished ${fmtDateTime(r.finished_at)}`} actions={back} />
      <StatStrip items={[
        { label: 'Status', value: r.status }, { label: 'Trigger', value: r.trigger },
        { label: 'Started', value: fmtDateTime(r.started_at) }, { label: 'Duration', value: fmtDuration(r.duration_seconds) },
        { label: 'Log lines', value: String(lines) }, { label: 'Sources', value: String(Object.keys(sources).length) },
      ]} />
      {r.error && <Card title="Error" subtitle="The run failed; the traceback is kept for debugging"><Code>{r.error}</Code></Card>}
      {!!Object.keys(sources).length && (
        <div className={d.health} style={{ margin: '16px 0' }}>
          {Object.entries(sources).map(([name, info]) => {
            const st = typeof info === 'string' ? info : info.status ?? 'unknown'
            return (
              <div key={name} className={d.hcard}>
                <h3><span className={d.dot} data-state={st === 'ok' ? 'ok' : st === 'degraded' ? 'stale' : 'down'} />{name.replace(/_/g, ' ')}</h3>
                <dl><dt>Status</dt><dd>{st}</dd><dt>Detail</dt><dd>{typeof info === 'string' ? '—' : info.detail ?? '—'}</dd></dl>
              </div>
            )
          })}
        </div>
      )}
      <Grid>
        <Span n={8}><Card title="Log" subtitle={live ? 'Streaming' : 'Complete run log'}><div ref={logRef}><Code>{r.log || 'No log lines yet.'}</Code></div></Card></Span>
        <Span n={4}><Card title="Summary" subtitle="What the run produced"><Code>{JSON.stringify(r.summary, null, 2)}</Code></Card></Span>
      </Grid>
      {!!Object.keys(r.params ?? {}).length && <Card title="Parameters"><Code>{JSON.stringify(r.params, null, 2)}</Code></Card>}
    </>
  )
}
