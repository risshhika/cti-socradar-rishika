import { useState } from 'react'
import { Check, Copy } from 'lucide-react'

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button className="btn btn-ghost" style={{ height: 28, padding: '0 8px', fontSize: 'var(--fs-sm)' }} onClick={async () => { try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500) } catch { /* clipboard blocked */ } }}>
      {done ? <Check size={13} style={{ color: 'var(--good-text)' }} /> : <Copy size={13} />} {done ? 'Copied' : label}
    </button>
  )
}
