import type { CSSProperties, ReactNode } from 'react'
import g from './grid.module.css'
import d from './dash.module.css'
import { cx } from '../../lib/format'

/** 12-column dashboard grid (Mintverse grid.module.css). Children use <Span n={4|6|8|12|3}>. */
export function Grid({ children, style, className }: { children: ReactNode; style?: CSSProperties; className?: string }) {
  return <div className={cx(g.grid, className)} style={{ marginBottom: 16, ...style }}>{children}</div>
}
export function Span({ n, children, style }: { n: 3 | 4 | 6 | 8 | 12; children: ReactNode; style?: CSSProperties }) {
  const cls = { 3: g.s3, 4: g.s4, 6: g.s6, 8: g.s8, 12: g.s12 }[n]
  return <div className={cls} style={{ minWidth: 0, display: 'flex', flexDirection: 'column', ...style }}>{children}</div>
}
/** Four-up KPI row that collapses to two and one column. */
export function KpiRow({ children }: { children: ReactNode }) {
  return <div className={d.kpis}>{children}</div>
}
/** Small coloured legend row for custom (non-ECharts) visuals. */
export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return <div className={g.legend}>{items.map((i) => <span key={i.label}><i style={{ background: i.color }} />{i.label}</span>)}</div>
}
/** Uppercase divider between dashboard bands. */
export function SectionLabel({ children }: { children: ReactNode }) {
  return <div className="section-label">{children}</div>
}
