import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, CircleHelp, CircleSlash, SearchX } from 'lucide-react'
import { api } from '../../lib/api'
import type { EntityType, Verdict } from '../../lib/types'
import { VerdictBadge } from './index'
import { fmtDateTime } from '../../lib/format'

const OPTIONS: { value: Verdict; label: string; icon: typeof CheckCircle2; hint: string }[] = [
  { value: 'agree', label: 'Agree', icon: CheckCircle2, hint: 'The automation got this right' },
  { value: 'over_flag', label: 'Over-flagged', icon: CircleSlash, hint: 'Wrongly grouped, labelled or flagged' },
  { value: 'miss', label: 'Missed', icon: SearchX, hint: 'Something the automation should have caught' },
  { value: 'unsure', label: 'Unsure', icon: CircleHelp, hint: 'Cannot tell from the evidence' },
]

/** Hand-check widget: records agree / over-flag / miss / unsure for any entity (feeds the Analyst review page). */
export function ReviewPanel({ entityType, entityId, compact }: { entityType: EntityType; entityId: number; compact?: boolean }) {
  const qc = useQueryClient()
  const [note, setNote] = useState('')
  const reviews = useQuery({ queryKey: ['reviews', entityType, entityId], queryFn: () => api.reviews.list(entityType, entityId) })
  const create = useMutation({
    mutationFn: (verdict: Verdict) => api.reviews.create({ entity_type: entityType, entity_id: entityId, verdict, note: note || null }),
    onSuccess: () => {
      setNote('')
      for (const k of ['reviews', 'overview', entityType, 'phishing', 'landscape']) qc.invalidateQueries({ queryKey: [k] })
    },
  })
  const latest = reviews.data?.[0]
  return (
    <div className="analyst-only" style={{ display: 'grid', gap: compact ? 8 : 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--fs-sm)' }}>
        <span className="muted">Current verdict</span><VerdictBadge verdict={latest?.verdict ?? null} />
        {latest && <span className="muted">· {fmtDateTime(latest.created_at)}</span>}
      </div>
      {!compact && (
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} placeholder="Why does the automation agree, miss or over-flag here?"
          style={{ width: '100%', border: '1px solid var(--border)', background: 'var(--surface-2)', color: 'var(--text)', borderRadius: 8, padding: '7px 10px', font: 'inherit', fontSize: 13, resize: 'vertical' }} />
      )}
      <div style={{ display: 'grid', gridTemplateColumns: compact ? 'repeat(auto-fill, minmax(92px, 1fr))' : 'repeat(2, minmax(0, 1fr))', gap: 6, justifyContent: 'start' }}>
        {OPTIONS.map((o) => (
          <button key={o.value} className="btn" title={o.hint} disabled={create.isPending} onClick={() => create.mutate(o.value)}
            aria-pressed={latest?.verdict === o.value}
            style={latest?.verdict === o.value ? { borderColor: 'color-mix(in srgb, var(--accent) 55%, transparent)', background: 'var(--accent-soft)' } : undefined}>
            <o.icon size={14} />{o.label}
          </button>
        ))}
      </div>
      {!compact && !!reviews.data?.length && (
        <ul style={{ listStyle: 'none', margin: 0, padding: '8px 0 0', borderTop: '1px solid var(--border)', display: 'grid', gap: 6, fontSize: 'var(--fs-sm)', color: 'var(--text-3)' }}>
          {reviews.data.slice(0, 5).map((r) => <li key={r.id} style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}><VerdictBadge verdict={r.verdict} /><span>{fmtDateTime(r.created_at)}</span>{r.note && <span style={{ color: 'var(--text-2)' }}>{r.note}</span>}</li>)}
        </ul>
      )}
    </div>
  )
}
