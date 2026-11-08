import { useEffect, type ReactNode } from 'react'
import { X } from 'lucide-react'
import s from './DetailDrawer.module.css'

/** Right-hand detail drawer (Mintverse DetailDrawer look). Escape or the scrim closes it. */
export function Drawer({ open, onClose, title, subtitle, kind, badges, children, width = 560 }: { open: boolean; onClose: () => void; title?: ReactNode; subtitle?: ReactNode; kind?: string; badges?: ReactNode; children: ReactNode; width?: number }) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])
  if (!open) return null
  return (
    <>
      <div className={s.overlay} onClick={onClose} />
      <aside className={s.panel} style={{ width: `min(${width}px, 100vw)` }} role="dialog" aria-modal>
        <div className={s.head}>
          <div className={s.headText}>
            {kind && <div className={s.kind}>{kind}</div>}
            {title && <div className={s.title}>{title}</div>}
            {subtitle && <div style={{ marginTop: 4, color: 'var(--text-3)', fontSize: 'var(--fs-sm)' }}>{subtitle}</div>}
            {badges && <div className={s.badges}>{badges}</div>}
          </div>
          <button onClick={onClose} className="icon-btn" aria-label="Close"><X size={16} /></button>
        </div>
        <div className={s.body}>{children}</div>
      </aside>
    </>
  )
}
