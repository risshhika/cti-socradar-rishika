import { useMemo, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import s from './KpiTile.module.css'
import { EChart } from '../../charts/EChart'
import { sparkline } from '../../charts/options'
import { Skeleton } from './index'
import { deltaTone, fmtNum } from '../../lib/viz'
import { useTheme } from '../../theme/ThemeProvider'

export interface Kpi {
  label: string
  value: number | null | undefined
  /** shown right of the label, e.g. "this month" */
  window?: string
  /** trend points, oldest first */
  spark?: number[]
  sparkLabels?: string[]
  /** previous-period value: the tile computes delta and % from it */
  prev?: number | null
  /** true: rising is bad news (threat counts). false: rising is good. null: neutral. */
  upIsBad?: boolean | null
  source: string
  note?: ReactNode
  to?: string
  format?: (n: number) => string
  /** render the value with a unit suffix, e.g. "%" */
  suffix?: string
}

function Delta({ value, prev, upIsBad }: { value: number; prev: number; upIsBad: boolean | null }) {
  const delta = value - prev
  const tone = deltaTone(delta, upIsBad)
  const Icon = delta > 0 ? ArrowUpRight : delta < 0 ? ArrowDownRight : Minus
  const pct = prev ? Math.round((delta / prev) * 100) : null
  const text = pct != null ? `${delta > 0 ? '+' : ''}${pct}%` : `${delta > 0 ? '+' : ''}${fmtNum(delta)}`
  return (
    <span className={s.delta} data-tone={tone} title={`Previous period: ${fmtNum(prev)}`}>
      <Icon size={14} aria-hidden />{delta === 0 ? 'no change' : text}
    </span>
  )
}

/** Headline KPI (ported from Mintverse KpiTile): value, delta vs previous period, sparkline, source line. */
export function KpiTile({ kpi, loading }: { kpi?: Kpi; loading?: boolean }) {
  const { tokens } = useTheme()
  const spark = kpi?.spark ?? []
  const option = useMemo(() => sparkline(spark, tokens, { labels: kpi?.sparkLabels }), [spark, tokens, kpi?.sparkLabels])
  if (loading || !kpi) {
    return (
      <div className={s.tile}>
        <Skeleton height={14} width="60%" />
        <Skeleton height={34} width="40%" />
        <Skeleton height={44} />
      </div>
    )
  }
  const fmt = kpi.format ?? fmtNum
  const body = (
    <>
      <div className={s.label}>{kpi.label}<span className={s.window}>{kpi.window ?? ''}</span></div>
      <div className={s.row}>
        <span className={s.value}>{kpi.value == null ? '—' : fmt(kpi.value)}{kpi.suffix && kpi.value != null ? <span style={{ fontSize: '0.6em', marginLeft: 2 }}>{kpi.suffix}</span> : null}</span>
        {kpi.value != null && kpi.prev != null && <Delta value={kpi.value} prev={kpi.prev} upIsBad={kpi.upIsBad === undefined ? true : kpi.upIsBad} />}
        {kpi.prev != null && <span className={s.vs}>vs {fmt(kpi.prev)} prior</span>}
      </div>
      <div className={s.spark}>
        {spark.length > 1 ? <EChart option={option} height={44} renderer="svg" ariaLabel={`${kpi.label} trend`} /> : <div style={{ height: 44, display: 'flex', alignItems: 'center', color: 'var(--text-3)', fontSize: 12 }}>No trend yet</div>}
      </div>
      <div className={s.foot}><span>{kpi.source}{kpi.note ? <> · {kpi.note}</> : null}</span></div>
    </>
  )
  return kpi.to ? <Link to={kpi.to} className={s.tile} title={`Open ${kpi.label.toLowerCase()}`}>{body}</Link> : <div className={s.tile}>{body}</div>
}
