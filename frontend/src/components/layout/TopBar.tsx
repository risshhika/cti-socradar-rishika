import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Loader2, Menu, Moon, Presentation, Search, Sun } from 'lucide-react'
import s from './TopBar.module.css'
import { Kbd } from '../ui'
import { api } from '../../lib/api'
import { useTheme } from '../../theme/ThemeProvider'
import { fmtAgo } from '../../lib/format'

function LiveIndicator() {
  const { data, isError } = useQuery({ queryKey: ['pipelines'], queryFn: api.pipelines.list, refetchInterval: 5000 })
  if (!data && !isError) return null
  const running = data?.filter((p) => p.running) ?? []
  const failed = data?.filter((p) => !p.running && p.last_run?.status === 'failed') ?? []
  const newest = data?.map((p) => p.last_run?.finished_at).filter(Boolean).sort().at(-1) as string | undefined
  const state = isError || failed.length ? 'stale' : 'ok'
  const text = isError ? 'API unreachable' : running.length ? `Running · ${running.map((r) => r.name).join(', ')}` : failed.length ? `${failed.length} pipeline failed` : newest ? `Updated ${fmtAgo(newest)}` : 'No runs yet'
  return (
    <Link to="/pipelines" className={s.fresh} data-state={state} title="Pipelines & runs" style={{ textDecoration: 'none' }}>
      {running.length ? <Loader2 size={13} className="spin" style={{ color: 'var(--accent)' }} /> : <i aria-hidden />}
      <span className={s.freshText}>{text}</span>
    </Link>
  )
}

function ScopeChips() {
  const { data } = useQuery({ queryKey: ['scope'], queryFn: api.scope.get })
  if (!data) return null
  return (
    <div className={s.scope}>
      <Link to="/settings" className={s.chip} title="Phishing scope (P4)"><b>P4</b>{data.phishing.sector} · {data.phishing.brands.length} brands · {data.phishing.days_back}d</Link>
      <Link to="/settings" className={s.chip} title="Landscape scope (P6)"><b>P6</b>{data.landscape.sector} · {data.landscape.region} · {data.landscape.months} mo</Link>
    </div>
  )
}

export function TopBar({ onSearch, onMenu }: { onSearch: () => void; onMenu: () => void }) {
  const { theme, toggleTheme, present, togglePresent } = useTheme()
  const isMac = typeof navigator !== 'undefined' && navigator.platform.toLowerCase().includes('mac')
  return (
    <header className={s.topbar} data-topbar>
      <button className={`icon-btn ${s.menu}`} onClick={onMenu} aria-label="Open navigation"><Menu size={18} /></button>
      <button className={s.search} onClick={onSearch} aria-label="Search (Command K)">
        <Search size={15} />
        <span>Search actors, campaigns, victims, kits…</span>
        <Kbd>{isMac ? '⌘K' : 'Ctrl K'}</Kbd>
      </button>
      <ScopeChips />
      <div className={s.right}>
        <LiveIndicator />
        <button className="icon-btn" onClick={toggleTheme} aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} title={theme === 'dark' ? 'Light theme' : 'Dark theme'}>
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
        <button className="icon-btn" onClick={togglePresent} aria-pressed={present} aria-label="Presentation mode" title="Presentation mode (larger type, hides analyst controls)"><Presentation size={16} /></button>
      </div>
    </header>
  )
}
