import { useState } from 'react'
import { ImageOff } from 'lucide-react'

const frame = { borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface-3)' } as const

/** Thumbnail with a hover preview. urlscan screenshots load from urlscan.io directly (no key needed). */
export function ScreenshotThumb({ src, alt, size = 44 }: { src: string | null | undefined; alt?: string; size?: number }) {
  const [failed, setFailed] = useState(false)
  const [hover, setHover] = useState(false)
  if (!src || failed) return <span style={{ ...frame, width: size, height: size * 0.75, display: 'inline-grid', placeItems: 'center', color: 'var(--text-3)' }}><ImageOff size={13} /></span>
  return (
    <span style={{ position: 'relative', display: 'inline-block' }} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
      <img src={src} alt={alt ?? 'screenshot'} loading="lazy" onError={() => setFailed(true)} style={{ ...frame, width: size, height: size * 0.75, objectFit: 'cover', objectPosition: 'top', display: 'block' }} />
      {hover && (
        <span style={{ position: 'absolute', left: '100%', top: 0, zIndex: 30, marginLeft: 8, width: 380, padding: 4, borderRadius: 10, border: '1px solid var(--border-strong)', background: 'var(--surface-1)', boxShadow: 'var(--shadow-2)' }}>
          <img src={src} alt={alt ?? 'screenshot'} style={{ width: '100%', maxHeight: 280, objectFit: 'contain', borderRadius: 6, display: 'block' }} />
        </span>
      )}
    </span>
  )
}

export function ScreenshotLarge({ src, alt }: { src: string | null | undefined; alt?: string }) {
  const [failed, setFailed] = useState(false)
  if (!src || failed) return <div style={{ ...frame, height: 220, display: 'grid', placeItems: 'center', color: 'var(--text-3)', fontSize: 12, gap: 6, alignContent: 'center' }}><ImageOff size={20} />No screenshot for this sample</div>
  return <a href={src} target="_blank" rel="noreferrer noopener"><img src={src} alt={alt ?? 'screenshot'} loading="lazy" onError={() => setFailed(true)} style={{ ...frame, width: '100%', aspectRatio: '16 / 10', maxHeight: 440, objectFit: 'contain', objectPosition: 'top', display: 'block' }} /></a>
}
