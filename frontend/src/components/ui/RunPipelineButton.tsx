import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, Play } from 'lucide-react'
import { api, ApiError } from '../../lib/api'
import { Button, EmptyState } from './index'
import type { ReactNode } from 'react'

export function useRunPipeline(name: string) {
  const qc = useQueryClient()
  const pipelines = useQuery({ queryKey: ['pipelines'], queryFn: api.pipelines.list, refetchInterval: 4000 })
  const running = pipelines.data?.find((p) => p.name === name)?.running ?? false
  const mutation = useMutation({
    mutationFn: () => api.pipelines.trigger(name),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['pipelines'] }) },
  })
  return { running, trigger: () => mutation.mutate(), pending: mutation.isPending, error: mutation.error as ApiError | null }
}

export function RunPipelineButton({ name, label, variant = 'primary', size = 'md' }: { name: string; label?: string; variant?: 'primary' | 'secondary'; size?: 'sm' | 'md' }) {
  const { running, trigger, pending, error } = useRunPipeline(name)
  return (
    <span className="analyst-only" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <Button variant={variant} size={size} disabled={running || pending} onClick={trigger} title={running ? 'Pipeline already running' : `Run ${name} pipeline`}>
        {running ? <Loader2 size={14} className="spin" /> : <Play size={14} />} {running ? 'Running…' : (label ?? `Run ${name} pipeline`)}
      </Button>
      {error && <span style={{ fontSize: 12, color: 'var(--bad-text)' }}>{error.message}</span>}
    </span>
  )
}

/** Empty state that explains which pipeline fills this page and lets the analyst start it. */
export function ModuleEmpty({ pipeline, title, hint, icon }: { pipeline: string; title: string; hint?: ReactNode; icon?: ReactNode }) {
  return (
    <EmptyState
      icon={icon}
      title={title}
      hint={hint ?? <>No data has been collected yet. Run the <span className="mono">{pipeline}</span> pipeline to ingest public sources, then return here.</>}
      action={<RunPipelineButton name={pipeline} />}
    />
  )
}

/** Treats a 404 / 503 from a not-yet-implemented or empty module as "no data". */
export function isNoData(error: unknown): boolean {
  if (error instanceof ApiError) return error.status === 404 || error.status === 503
  // A SyntaxError means the server answered with HTML (route not mounted yet, SPA fallback) instead of JSON.
  return error instanceof SyntaxError
}
