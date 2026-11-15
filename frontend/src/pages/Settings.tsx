import { useEffect, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Save, X, Plus, KeyRound, RotateCcw } from 'lucide-react'
import { api } from '../lib/api'
import { PageHeader, Card, Badge, Loading, ErrorState } from '../components/ui'
import { Grid, Span } from '../components/ui/Grid'
import { RunPipelineButton } from '../components/ui/RunPipelineButton'
import type { Scope } from '../lib/types'
import f from './forms.module.css'

const SECTORS = ['Professional Services', 'Manufacturing', 'Technology', 'Healthcare', 'Retail & E-Commerce', 'Financial Services', 'Transportation', 'Education', 'Government & Defense', 'Agriculture and Food Production', 'Energy & Utilities', 'Hospitality', 'Other']
const REGIONS = ['Global', 'Europe', 'North America', 'LATAM', 'MENA', 'Sub-Saharan Africa', 'South Asia', 'East Asia', 'Southeast Asia', 'Oceania', 'Central Asia', 'DACH', 'Nordics', 'UK&I', 'Benelux']

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className={f.field}><span>{label}{hint && <small>{hint}</small>}</span>{children}</label>
}

function TagInput({ values, onChange, placeholder }: { values: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [draft, setDraft] = useState('')
  const add = () => { const v = draft.trim(); if (v && !values.includes(v)) onChange([...values, v]); setDraft('') }
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center', border: '1px solid var(--border)', background: 'var(--surface-2)', borderRadius: 8, padding: '6px 8px' }}>
      {values.map((v) => <Badge key={v} tone="accent">{v}<button type="button" onClick={() => onChange(values.filter((x) => x !== v))} aria-label={`Remove ${v}`} style={{ border: 0, background: 'none', color: 'inherit', cursor: 'pointer', padding: 0, marginLeft: 2, display: 'inline-flex' }}><X size={11} /></button></Badge>)}
      <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add() } }} onBlur={add} placeholder={placeholder}
        style={{ flex: 1, minWidth: 120, border: 0, outline: 0, background: 'transparent', color: 'var(--text)', fontSize: 13 }} />
    </div>
  )
}

export default function Settings() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['scope'], queryFn: api.scope.get })
  const [draft, setDraft] = useState<Scope | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  useEffect(() => { if (q.data && !draft) setDraft(structuredClone(q.data)) }, [q.data, draft])
  const save = useMutation({ mutationFn: (s: Scope) => api.scope.put(s), onSuccess: (s) => { qc.setQueryData(['scope'], s); setDraft(structuredClone(s)); setMsg('Saved to config/scope.yaml. Re-run the pipelines to apply the new scope.'); setTimeout(() => setMsg(null), 6000) } })
  if (q.isLoading || (!draft && !q.error)) return <><PageHeader kicker="System" title="Scope & settings" /><Loading /></>
  if (q.error || !draft) return <><PageHeader kicker="System" title="Scope & settings" /><ErrorState error={q.error} /></>
  const p = draft.phishing, l = draft.landscape
  const setP = (patch: Partial<Scope['phishing']>) => setDraft({ ...draft, phishing: { ...p, ...patch } })
  const setL = (patch: Partial<Scope['landscape']>) => setDraft({ ...draft, landscape: { ...l, ...patch } })
  const dirty = JSON.stringify(draft) !== JSON.stringify(q.data)
  const regionOpts = REGIONS.includes(l.region) ? REGIONS : [...REGIONS, l.region]

  return (
    <>
      <PageHeader kicker="System" title="Scope & settings" subtitle="Analyst inputs for both pipelines, stored in config/scope.yaml so a clean-start run reproduces the same scope."
        actions={<><button className="btn" disabled={!dirty} onClick={() => setDraft(structuredClone(q.data!))}><RotateCcw size={14} /> Discard</button><button className="btn btn-primary" disabled={!dirty || save.isPending} onClick={() => save.mutate(draft)}><Save size={14} /> Save scope</button></>} />
      {msg && <div style={{ marginBottom: 16, padding: '9px 12px', borderRadius: 8, fontSize: 13, color: 'var(--good-text)', border: '1px solid color-mix(in srgb, var(--good) 40%, transparent)', background: 'color-mix(in srgb, var(--good) 8%, transparent)' }}>{msg}</div>}
      {save.error && <div style={{ marginBottom: 16 }}><ErrorState error={save.error} /></div>}
      <Grid>
        <Span n={6}>
          <Card title="P4 · Phishing campaign scope" subtitle="Sector, watched brands and the window applied to WhoisDS, urlscan.io, OpenPhish and PhishTank" actions={<RunPipelineButton name="phishing" label="Run P4" size="sm" variant="secondary" />}>
            <Field label="Sector"><input value={p.sector} onChange={(e) => setP({ sector: e.target.value })} /></Field>
            <Field label="Watched brands" hint="Press Enter after each brand. Brands drive urlscan.io searches and brand detection."><TagInput values={p.brands} onChange={(brands) => setP({ brands })} placeholder="Add a brand…" /></Field>
            <div className={f.grid3}>
              <Field label="Window (days)" hint="all sources + retention"><input type="number" min={1} value={p.days_back} onChange={(e) => setP({ days_back: Number(e.target.value) })} /></Field>
              <Field label="Max samples" hint="per run"><input type="number" min={10} value={p.max_samples} onChange={(e) => setP({ max_samples: Number(e.target.value) })} /></Field>
              <Field label="Queries per brand" hint="30/min keyless"><input type="number" min={1} value={p.urlscan_queries_per_brand} onChange={(e) => setP({ urlscan_queries_per_brand: Number(e.target.value) })} /></Field>
            </div>
          </Card>
        </Span>
        <Span n={6}>
          <Card title="P6 · Threat landscape scope" subtitle="Sector and region define what counts as in scope; the window sets trend and briefing depth" actions={<RunPipelineButton name="landscape" label="Run P6" size="sm" variant="secondary" />}>
            <div className={f.grid3}>
              <Field label="Sector"><select value={l.sector} onChange={(e) => setL({ sector: e.target.value })}>{(SECTORS.includes(l.sector) ? SECTORS : [...SECTORS, l.sector]).map((s) => <option key={s}>{s}</option>)}</select></Field>
              <Field label="Region" hint="Region, sub-region or ISO-2"><select value={regionOpts.includes(l.region) ? l.region : ''} onChange={(e) => setL({ region: e.target.value })}>{regionOpts.map((r) => <option key={r}>{r}</option>)}</select></Field>
              <Field label="Months"><input type="number" min={1} max={24} value={l.months} onChange={(e) => setL({ months: Number(e.target.value) })} /></Field>
            </div>
            <Field label="Custom region code" hint="Overrides the list, e.g. DE or TR"><input value={l.region} onChange={(e) => setL({ region: e.target.value })} /></Field>
            <Field label="IAB reporting feeds" hint="RSS or Atom feeds of public vendor blogs and news mined for access-broker listings and prices">
              <div style={{ display: 'grid', gap: 6 }}>
                {l.iab_feeds.map((feed, i) => (
                  <div key={i} style={{ display: 'flex', gap: 6 }}>
                    <input className="mono" style={{ flex: 1, border: '1px solid var(--border)', background: 'var(--surface-2)', color: 'var(--text)', borderRadius: 8, padding: '7px 10px', fontSize: 12.5 }} value={feed} onChange={(e) => setL({ iab_feeds: l.iab_feeds.map((x, j) => (j === i ? e.target.value : x)) })} />
                    <button type="button" className="icon-btn" title="Remove feed" onClick={() => setL({ iab_feeds: l.iab_feeds.filter((_, j) => j !== i) })}><X size={14} /></button>
                  </div>
                ))}
                <button type="button" className="btn btn-ghost" style={{ justifySelf: 'start' }} onClick={() => setL({ iab_feeds: [...l.iab_feeds, ''] })}><Plus size={14} /> Add feed</button>
              </div>
            </Field>
          </Card>
        </Span>
      </Grid>
      <Card title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}><KeyRound size={15} /> Environment</span>} subtitle="Optional keys read from .env at the repository root. Everything runs without them; keys only add coverage and prose quality.">
        <table className={f.tbl}>
          <thead><tr><th>Variable</th><th>What it unlocks</th></tr></thead>
          <tbody>
            <tr><td className="mono">CTIOPS_URLSCAN_API_KEY</td><td className="secondary">urlscan.io result and DOM API instead of visiting pages directly; wildcard searches; higher rate limits.</td></tr>
            <tr><td className="mono">CTIOPS_ANTHROPIC_API_KEY</td><td className="secondary">LLM-assisted sector and size classification, IAB extraction and briefing prose. Every prompt is logged to data/artifacts/prompts.jsonl.</td></tr>
            <tr><td className="mono">CTIOPS_DATA_DIR</td><td className="secondary">Where the SQLite database, HTTP cache and captured artifacts live (default ./data).</td></tr>
          </tbody>
        </table>
      </Card>
    </>
  )
}
