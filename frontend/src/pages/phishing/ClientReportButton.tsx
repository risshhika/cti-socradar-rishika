import { useState } from 'react'
import { FileOutput } from 'lucide-react'
import { api } from '../../lib/api'

/** Opens the client-facing report (approved template, internal sources blocked) for one campaign.
 *  The server refuses campaigns whose pages collect nothing (409) and text naming internal tools (422);
 *  the reason is shown inline, with an analyst override for script-built forms confirmed by eye. */
export function ClientReportButton({ id }: { id: number }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<{ code: number; text: string } | null>(null)

  async function open(force = false) {
    setBusy(true); setErr(null)
    const url = api.phishing.clientReportUrl(id, { force })
    try {
      const r = await fetch(url)
      if (!r.ok) {
        const j = await r.json().catch(() => ({}))
        const d = j.detail
        setErr({ code: r.status, text: typeof d === 'string' ? d : d?.error ?? `HTTP ${r.status}` })
        return
      }
      const blob = new Blob([await r.text()], { type: 'text/html' })
      window.open(URL.createObjectURL(blob), '_blank', 'noopener')
    } finally { setBusy(false) }
  }

  return (
    <span style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
      <span style={{ display: 'inline-flex', gap: 6 }}>
        <button className="btn btn-primary" disabled={busy} onClick={() => open(false)} title="Client report in the approved template">
          <FileOutput size={14} /> {busy ? 'Building…' : 'Client report'}
        </button>
        <a className="btn btn-ghost" href={api.phishing.clientReportUrl(id, { download: true })} title="Download .html (upload to Google Docs to edit)">.html</a>
      </span>
      {err && (
        <span style={{ maxWidth: 420, fontSize: 12, color: 'var(--sev-high, #c44)', textAlign: 'right' }}>
          {err.text}
          {err.code === 409 && <> <button className="btn btn-ghost" style={{ padding: '0 6px' }} onClick={() => open(true)}>I've confirmed it's phishing, build anyway</button></>}
        </span>
      )}
    </span>
  )
}
