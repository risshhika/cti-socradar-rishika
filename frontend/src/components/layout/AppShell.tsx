import { Suspense, useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import s from './AppShell.module.css'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { CommandPalette } from './CommandPalette'
import { Skeleton } from '../ui'
import { useTheme } from '../../theme/ThemeProvider'

function PageFallback() {
  return (
    <div style={{ display: 'grid', gap: 16 }} aria-busy="true" aria-label="Loading page">
      <Skeleton height={28} width={260} />
      <Skeleton height={120} />
      <Skeleton height={260} />
    </div>
  )
}

function useNarrow(): boolean {
  const query = '(max-width: 1100px) and (min-width: 769px)'
  const [narrow, setNarrow] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const mq = window.matchMedia(query)
    const on = () => setNarrow(mq.matches)
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [])
  return narrow
}

/** Shell ported from Mintverse: pinned sidebar + top bar, only the content column scrolls; ⌘K palette. */
export function AppShell() {
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem('ctiops-sidebar') === 'rail' } catch { return false } })
  const [mobileOpen, setMobileOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const { present } = useTheme()
  const narrow = useNarrow()
  const location = useLocation()

  useEffect(() => setMobileOpen(false), [location.pathname])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteOpen((o) => !o) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  const toggleCollapsed = () => setCollapsed((c) => { try { localStorage.setItem('ctiops-sidebar', c ? 'full' : 'rail') } catch { /* not persisted */ } return !c })
  const rail = collapsed || present || narrow
  return (
    <div className={s.shell} data-rail={rail}>
      <Sidebar rail={rail} mobileOpen={mobileOpen} onToggleRail={toggleCollapsed} />
      <div className={s.scrim} data-open={mobileOpen} onClick={() => setMobileOpen(false)} />
      <div className={s.main}>
        <TopBar onSearch={() => setPaletteOpen(true)} onMenu={() => setMobileOpen(true)} />
        <main className={s.content} id="main">
          <div style={{ maxWidth: 1680, margin: '0 auto' }}>
            <Suspense fallback={<PageFallback />}><Outlet /></Suspense>
          </div>
        </main>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  )
}
