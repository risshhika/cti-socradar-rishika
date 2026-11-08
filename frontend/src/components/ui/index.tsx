/**
 * Shared primitives, restyled on the Mintverse design system (components/ui.tsx, ui.module.css, controls.module.css).
 * Export names are kept from the first design so pages keep compiling while they are rebuilt.
 */
import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowDown, ArrowUp, ArrowUpDown, ExternalLink, Inbox } from 'lucide-react'
import s from './ui.module.css'
import c from './controls.module.css'
import { cx, fmtInt } from '../../lib/format'
import type { KeyCount, Verdict } from '../../lib/types'

/* ---------- layout ---------- */

export function PageHeader({ title, subtitle, actions, kicker }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; kicker?: string }) {
  return (
    <header style={{ display: 'flex', alignItems: 'flex-end', gap: 16, flexWrap: 'wrap', marginBottom: 20 }}>
      <div style={{ flex: 1, minWidth: 240 }}>
        {kicker && <div className={s.kicker}>{kicker}</div>}
        <h1 style={{ fontSize: 'var(--fs-xl)' }}>{title}</h1>
        {subtitle && <p style={{ margin: '4px 0 0', color: 'var(--text-3)', fontSize: 'var(--fs-md)' }}>{subtitle}</p>}
      </div>
      {actions && <div className="analyst-only" style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>{actions}</div>}
    </header>
  )
}

/** Panel with an optional title row. For charts prefer ChartCard (question + source + table twin + PNG). */
export function Card({ title, subtitle, actions, children, className, padded = true }: { title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; padded?: boolean }) {
  return (
    <section className={cx(s.panel, className)}>
      {(title || actions) && (
        <div className={s.panelHead}>
          <div style={{ minWidth: 0, flex: 1 }}>
            {title && <h2 className={s.panelTitle}>{title}</h2>}
            {subtitle && <div className={s.panelSub}>{subtitle}</div>}
          </div>
          {actions && <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>{actions}</div>}
        </div>
      )}
      <div style={padded ? { padding: title || actions ? '0 16px 16px' : 16 } : undefined}>{children}</div>
    </section>
  )
}

/** Simple stat tile (no trend). For headline KPIs with a sparkline and delta use KpiTile. */
export function StatTile({ label, value, hint, tone, icon, to }: { label: string; value: ReactNode; hint?: ReactNode; tone?: 'ok' | 'warn' | 'danger' | 'info' | 'accent'; icon?: ReactNode; to?: string }) {
  const color = tone === 'ok' ? 'var(--good-text)' : tone === 'warn' ? 'var(--sev-medium)' : tone === 'danger' ? 'var(--bad-text)' : tone ? 'var(--accent)' : undefined
  const body = (
    <div className={s.stat}>
      <div className={s.statLabel}><span>{label}</span>{icon && <span style={{ marginLeft: 'auto', color: color ?? 'var(--text-3)', display: 'inline-flex' }}>{icon}</span>}</div>
      <div className={s.statValue} style={{ color }}>{value}</div>
      {hint && <div className={s.statHint}>{hint}</div>}
    </div>
  )
  return to ? <Link to={to} className={s.statLink}>{body}</Link> : body
}

/* ---------- badges ---------- */

type Tone = 'neutral' | 'ok' | 'warn' | 'danger' | 'info' | 'accent'
const TONE: Record<Tone, string | undefined> = { neutral: undefined, ok: 'good', warn: 'warn', danger: 'bad', info: 'accent', accent: 'accent' }

export function Badge({ children, tone = 'neutral', className, title }: { children: ReactNode; tone?: Tone; className?: string; title?: string }) {
  return <span className={cx(s.badge, className)} data-tone={TONE[tone]} title={title}>{children}</span>
}

const SEV_VAR: Record<string, string> = { CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)', MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)', UNKNOWN: 'var(--sev-unknown)' }

/** Severity always carries its label: colour is never the only signal. */
export function SeverityPill({ severity, label, score }: { severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | string; label?: string; score?: number | null }) {
  const sev = (severity || 'UNKNOWN').toUpperCase()
  return (
    <span className={s.pill}>
      <span className={s.pillDot} style={{ background: SEV_VAR[sev] ?? SEV_VAR.UNKNOWN }} />
      {label ?? (sev === 'UNKNOWN' ? 'Unscored' : sev.charAt(0) + sev.slice(1).toLowerCase())}
      {score != null && <span className="num">{Number.isInteger(score) ? score : score.toFixed(2)}</span>}
    </span>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const tone = ({ succeeded: 'ok', ok: 'ok', active: 'ok', final: 'ok', running: 'info', queued: 'info', draft: 'info', failed: 'danger', down: 'danger', error: 'danger', blocked: 'warn', degraded: 'warn', dormant: 'warn', offline: 'warn' } as Record<string, Tone>)[status] ?? 'neutral'
  return <Badge tone={tone}>{status}</Badge>
}

/** Confidence as a pill on the severity ramp (high confidence = strong signal). */
export function ConfidenceBadge({ value }: { value: number | string }) {
  const n = typeof value === 'number' ? value : value === 'high' ? 0.9 : value === 'medium' ? 0.6 : 0.3
  const label = typeof value === 'string' ? value[0].toUpperCase() + value.slice(1) : `${Math.round(n * 100)}%`
  return <SeverityPill severity={n >= 0.75 ? 'HIGH' : n >= 0.5 ? 'MEDIUM' : 'LOW'} label={label} />
}

/* ---------- controls ---------- */

export function Button({ children, onClick, variant = 'secondary', size = 'md', disabled, type = 'button', className, title }: { children: ReactNode; onClick?: () => void; variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; size?: 'sm' | 'md'; disabled?: boolean; type?: 'button' | 'submit'; className?: string; title?: string }) {
  const v = variant === 'primary' ? 'btn btn-primary' : variant === 'ghost' ? 'btn btn-ghost' : 'btn'
  return (
    <button type={type} title={title} disabled={disabled} onClick={onClick} className={cx(v, className)}
      style={{ ...(size === 'sm' ? { height: 28, padding: '0 10px', fontSize: 'var(--fs-sm)' } : {}), ...(variant === 'danger' ? { color: 'var(--bad-text)' } : {}) }}>
      {children}
    </button>
  )
}

export function LinkButton({ href, children, download }: { href: string; children: ReactNode; download?: boolean }) {
  return <a href={href} download={download} className="btn btn-ghost" style={{ textDecoration: 'none' }}>{children}</a>
}

export function Input({ value, onChange, placeholder, className, type = 'text' }: { value: string | number; onChange: (v: string) => void; placeholder?: string; className?: string; type?: string }) {
  return <input type={type} value={value} placeholder={placeholder} aria-label={placeholder} onChange={(e) => onChange(e.target.value)} className={cx(c.input, className)} style={{ paddingLeft: 10 }} />
}

export function Select({ value, onChange, options, className, placeholder }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; className?: string; placeholder?: string }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} className={cx(c.select, className)} aria-label={placeholder}>
      {placeholder !== undefined && <option value="">{placeholder}</option>}
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  )
}

export function Tabs<T extends string>({ value, onChange, tabs }: { value: T; onChange: (v: T) => void; tabs: { value: T; label: string; count?: number }[] }) {
  return (
    <div className={s.tabs} role="tablist">
      {tabs.map((t) => (
        <button key={t.value} role="tab" aria-selected={value === t.value} className={s.tab} onClick={() => onChange(t.value)}>
          {t.label}{t.count != null && <span className={s.tabCount}>{fmtInt(t.count)}</span>}
        </button>
      ))}
    </div>
  )
}

/* ---------- states ---------- */

export function EmptyState({ title, hint, action, icon }: { title: string; hint?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className={s.state}>
      {icon ?? <Inbox size={20} />}
      <div className={s.stateTitle}>{title}</div>
      {hint && <div style={{ maxWidth: 460 }}>{hint}</div>}
      {action && <div style={{ marginTop: 6 }}>{action}</div>}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error ?? 'Something went wrong')
  return (
    <div className={s.state} role="alert">
      <AlertTriangle size={20} />
      <div className={s.stateTitle}>Couldn't load this data</div>
      <div>{msg}</div>
      {onRetry && <button className="btn" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function Skeleton({ className, height = 16, width = '100%' }: { className?: string; height?: number; width?: number | string }) {
  return <div className={cx(s.skeleton, className)} style={className ? undefined : { height, width }} aria-hidden />
}

export function Loading({ rows = 4 }: { rows?: number }) {
  return <div style={{ display: 'grid', gap: 8, padding: '6px 0' }} aria-busy="true">{Array.from({ length: rows }).map((_, i) => <Skeleton key={i} height={30} />)}</div>
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className={s.kbd}>{children}</kbd>
}

/* ---------- data display ---------- */

export interface Column<T> {
  key: string
  header: ReactNode
  render: (row: T) => ReactNode
  width?: string
  align?: 'left' | 'right'
  className?: string
  /** Makes the column sortable (client-side) on this value. */
  sort?: (row: T) => number | string | null | undefined
}

/** Table on the Mintverse DataTable look, with optional client-side sorting per column. */
export function DataTable<T>({ rows, columns, rowKey, onRowClick, empty, dense, maxHeight }: { rows: T[]; columns: Column<T>[]; rowKey: (r: T) => string | number; onRowClick?: (r: T) => void; empty?: ReactNode; dense?: boolean; maxHeight?: string }) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null)
  const sorted = useMemo(() => {
    if (!sort) return rows
    const col = columns.find((c) => c.key === sort.key)
    if (!col?.sort) return rows
    const get = col.sort
    return [...rows].sort((a, b) => {
      const va = get(a), vb = get(b)
      if (va == null && vb == null) return 0
      if (va == null) return 1
      if (vb == null) return -1
      return (va < vb ? -1 : va > vb ? 1 : 0) * sort.dir
    })
  }, [rows, columns, sort])
  if (!rows.length) return <>{empty ?? <EmptyState title="Nothing to show" />}</>
  return (
    <div className={s.tableWrap} style={{ maxHeight }}>
      <table className="data" style={dense ? { fontSize: 'var(--fs-sm)' } : undefined}>
        <thead>
          <tr>
            {columns.map((col) => {
              const active = sort?.key === col.key
              return (
                <th key={col.key} style={{ width: col.width, textAlign: col.align }} aria-sort={active ? (sort!.dir === 1 ? 'ascending' : 'descending') : 'none'}>
                  {col.sort ? (
                    <button className="sort" onClick={() => setSort(active ? (sort!.dir === -1 ? { key: col.key, dir: 1 } : null) : { key: col.key, dir: -1 })}>
                      {col.header}{active ? (sort!.dir === 1 ? <ArrowUp size={12} /> : <ArrowDown size={12} />) : <ArrowUpDown size={12} opacity={0.4} />}
                    </button>
                  ) : col.header}
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => (
            <tr key={rowKey(r)} className={cx(onRowClick && 'clickable')} tabIndex={onRowClick ? 0 : undefined}
              onClick={onRowClick ? () => onRowClick(r) : undefined} onKeyDown={onRowClick ? (e) => e.key === 'Enter' && onRowClick(r) : undefined}>
              {columns.map((col) => <td key={col.key} className={col.className} style={{ textAlign: col.align, fontVariantNumeric: col.align === 'right' ? 'tabular-nums' : undefined }}>{col.render(r)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Inline ranked bars (Mintverse "Bars"): label · track · value. Cheap, crisp, no canvas. */
export function KeyCountBars({ data, max, labelWidth = 140, onClick, format = fmtInt, color = 'var(--seq-4)' }: { data: KeyCount[]; max?: number; labelWidth?: number; onClick?: (k: string) => void; format?: (n: number) => string; color?: string }) {
  if (!data.length) return <EmptyState title="No data" />
  const top = max ?? Math.max(...data.map((d) => d.count), 1)
  return (
    <div style={{ display: 'grid', gap: 8, paddingTop: 4 }}>
      {data.map((d) => (
        <div key={d.key} className={cx(s.barRow, onClick && s.barRowClick)} style={{ gridTemplateColumns: `minmax(80px, ${labelWidth}px) 1fr 74px` }} onClick={onClick ? () => onClick(d.key) : undefined}>
          <span className={s.barLabel} title={d.key}>{d.key}</span>
          <div className={s.barTrack}><i style={{ width: `${(d.count / top) * 100}%`, background: color }} /></div>
          <span className="num" style={{ textAlign: 'right', color: 'var(--text-2)' }}>{format(d.count)}{d.share != null && <span className="muted"> {Math.round(d.share * 100)}%</span>}</span>
        </div>
      ))}
    </div>
  )
}

export function KV({ items }: { items: { k: ReactNode; v: ReactNode }[] }) {
  return (
    <dl className={s.kv}>
      {items.map((it, i) => (<div key={i} style={{ display: 'contents' }}><dt>{it.k}</dt><dd>{it.v}</dd></div>))}
    </dl>
  )
}

export function Ext({ href, children }: { href: string; children?: ReactNode }) {
  return <a href={href} target="_blank" rel="noreferrer noopener" style={{ display: 'inline-flex', alignItems: 'center', gap: 4, wordBreak: 'break-all' }}>{children ?? href}<ExternalLink size={11} style={{ flexShrink: 0 }} /></a>
}

export function Code({ children, className }: { children: ReactNode; className?: string }) {
  return <pre className={cx(s.code, className)}>{children}</pre>
}

export function Pagination({ page, size, total, onPage }: { page: number; size: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size))
  return (
    <div className={s.pager}>
      <span>{fmtInt(total)} records · page {page} of {pages}</span>
      <div style={{ display: 'flex', gap: 6 }}>
        <Button size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</Button>
        <Button size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</Button>
      </div>
    </div>
  )
}

/** Proportional meter (cohesion, relevance, confidence) as a thin track. */
export function Meter({ value, width = 64, color = 'var(--accent)' }: { value: number; width?: number; color?: string }) {
  const v = Math.max(0, Math.min(1, value || 0))
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }} title={`${Math.round(v * 100)}%`}>
      <span className={s.barTrack} style={{ width, display: 'inline-block' }}><i style={{ width: `${v * 100}%`, background: color }} /></span>
      <span className="num muted" style={{ fontSize: 'var(--fs-xs)' }}>{Math.round(v * 100)}%</span>
    </span>
  )
}

export const VERDICTS: { value: Verdict; label: string; tone: 'ok' | 'danger' | 'warn' | 'neutral' }[] = [
  { value: 'agree', label: 'Agree', tone: 'ok' },
  { value: 'over_flag', label: 'Over-flagged', tone: 'danger' },
  { value: 'miss', label: 'Missed', tone: 'warn' },
  { value: 'unsure', label: 'Unsure', tone: 'neutral' },
]

export function VerdictBadge({ verdict }: { verdict: Verdict | null | undefined }) {
  if (!verdict) return <span className="muted" style={{ fontSize: 'var(--fs-sm)' }}>—</span>
  const v = VERDICTS.find((x) => x.value === verdict)!
  return <Badge tone={v.tone}>{v.label}</Badge>
}
