import { NavLink } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import s from './Sidebar.module.css'
import { NAV } from './nav'
import { api } from '../../lib/api'
import { fmtAgo } from '../../lib/format'

/** Footer health: one dot per pipeline (last run outcome) plus one per data source from the last runs. */
function PipelineHealth({ rail }: { rail: boolean }) {
  const pipelines = useQuery({ queryKey: ['pipelines'], queryFn: api.pipelines.list, refetchInterval: 5000 })
  const overview = useQuery({ queryKey: ['overview'], queryFn: api.overview, refetchInterval: 30000 })
  const items = [
    ...(pipelines.data ?? []).map((p) => ({
      key: p.name, label: `${p.name} pipeline`,
      state: p.running ? 'ok' : !p.last_run ? 'stale' : p.last_run.status === 'succeeded' ? 'ok' : 'down',
      detail: p.running ? 'running now' : p.last_run ? `${p.last_run.status} ${fmtAgo(p.last_run.finished_at)}` : 'never run',
    })),
    ...(overview.data?.sources ?? []).map((src) => ({
      key: `${src.module}:${src.name}`, label: src.name.replace(/_/g, ' '),
      state: src.status === 'ok' ? 'ok' : src.status === 'degraded' ? 'stale' : 'down', detail: src.detail ?? src.status,
    })),
  ]
  const healthy = items.filter((i) => i.state === 'ok').length
  const title = items.map((i) => `${i.label}: ${i.detail}`).join('\n')
  return (
    <div className={s.health} title={title}>
      <div className={s.dots} aria-hidden>{items.map((i) => <span key={i.key} className={s.hdot} data-state={i.state} />)}</div>
      {!rail && items.length > 0 && <span>{healthy}/{items.length} feeds healthy</span>}
    </div>
  )
}

export function Sidebar({ rail, mobileOpen, onToggleRail }: { rail: boolean; mobileOpen: boolean; onToggleRail: () => void }) {
  const overview = useQuery({ queryKey: ['overview'], queryFn: api.overview, refetchInterval: 30000 })
  const counts: Record<string, number | undefined> = {
    campaigns: overview.data?.phishing.campaigns_active,
    scope: overview.data?.landscape.victims_month_scope,
  }
  return (
    <aside className={s.sidebar} data-rail={rail} data-open={mobileOpen}>
      <NavLink to="/" className={s.brand} aria-label="CTI Ops home">
        <img className={s.logoImg} src="/brand/ctiops-mark.svg" width={30} height={30} alt="" />
        {!rail && <span className={s.brandText}><b>CTI Ops</b><span>Threat intelligence services</span></span>}
      </NavLink>
      <nav className={s.nav} aria-label="Main">
        {NAV.map((g) => (
          <div className={s.group} key={g.label}>
            {!rail && <div className={s.groupLabel} style={{ display: 'flex', alignItems: 'center' }}>{g.label}{g.tag && <span className={s.tag}>{g.tag}</span>}</div>}
            {g.items.map((item) => {
              const count = item.badge ? counts[item.badge] : undefined
              return (
                <NavLink key={item.to} to={item.to} end={item.to === '/' || item.to === '/phishing' || item.to === '/landscape'} className={s.item} title={rail ? item.label : undefined}>
                  <item.icon size={17} />
                  {!rail && <span className={s.label}>{item.label}</span>}
                  {!rail && !!count && <span className={s.count} title={item.badge === 'scope' ? 'In-scope victims this month' : 'Active campaigns'}>{count}</span>}
                  {rail && !!count && <span className={s.dot} />}
                </NavLink>
              )
            })}
          </div>
        ))}
      </nav>
      <div className={s.footer}>
        <PipelineHealth rail={rail} />
        <button className={`icon-btn ${s.collapse}`} onClick={onToggleRail} aria-label={rail ? 'Expand sidebar' : 'Collapse sidebar'} title={rail ? 'Expand sidebar' : 'Collapse sidebar'}>
          {rail ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
        </button>
      </div>
    </aside>
  )
}
