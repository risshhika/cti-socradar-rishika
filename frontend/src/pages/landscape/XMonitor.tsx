import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AtSign, Crosshair, FileJson, Image as ImageIcon } from 'lucide-react'
import { api } from '../../lib/api'
import type { XPost, XIdentify } from '../../lib/api'
import { PageHeader, Card, DataTable, Badge, Loading, ErrorState, Ext, KV, Meter, Button, Input } from '../../components/ui'
import { Drawer } from '../../components/ui/Drawer'
import { FilterBar, SearchInput, Select, StatStrip } from '../../components/ui/controls'
import { SectionLabel } from '../../components/ui/Grid'
import { RunPipelineButton } from '../../components/ui/RunPipelineButton'
import { fmtDate, fmtInt, fmtUsd } from '../../lib/format'

const usd = (v: number | null | undefined) => (v == null ? '—' : v >= 1e9 ? `$${(v / 1e9).toFixed(1)}B` : v >= 1e6 ? `$${(v / 1e6).toFixed(1)}M` : fmtUsd(v))
const opt = (all: string, xs: string[]) => [{ value: '', label: all }, ...xs.map((x) => ({ value: x, label: x }))]

export default function XMonitor() {
  const [f, setF] = useState({ query: '', revenue_band: '', employee_band: '', fin_subtype: '', status: '' })
  const [q, setQ] = useState('')
  const [sel, setSel] = useState<XPost | null>(null)
  const status = useQuery({ queryKey: ['x', 'status'], queryFn: api.x.status })
  const params = Object.fromEntries(Object.entries(f).filter(([, v]) => v))
  const list = useQuery({ queryKey: ['x', 'posts', params], queryFn: () => api.x.posts(params), placeholderData: (p) => p })
  const rows = useMemo(() => {
    const n = q.trim().toLowerCase()
    return (list.data ?? []).filter((r) => !n || `${r.text} ${r.victim_name ?? ''} ${r.author_handle ?? ''}`.toLowerCase().includes(n))
  }, [list.data, q])
  const all = list.data ?? []
  const set = (k: keyof typeof f) => (v: string) => setF((s) => ({ ...s, [k]: v }))
  const st = status.data

  const header = (
    <PageHeader kicker="P6 · Threat landscape" title="X access-broker monitor"
      subtitle={<>Public X posts matching the IAB queries{st?.accounts?.length ? <> and everything posted by {st.accounts.map((a) => `@${a}`).join(', ')}</> : null}, narrowed to {st?.sectors.join(', ') || 'financial services'}. Every match keeps the API record, its images and a rendered post card, each hashed at capture. Victims are sized from public company registries.</>}
      actions={<RunPipelineButton name="x_iab" label="Run X monitor" />} />
  )
  if (list.isLoading || status.isLoading) return <>{header}<Loading rows={8} /></>
  if (list.error) return <>{header}<ErrorState error={list.error} /></>

  return (
    <>
      {header}
      {st && (!st.x_api || !st.registries) && (
        <Card><div style={{ fontSize: 13.5, display: 'grid', gap: 6 }}>
          {!st.x_api && <div><b>X API not configured.</b> Add <code>CTIOPS_X_BEARER_TOKEN=…</code> (Basic tier or higher, for recent search) to <code>.env</code> and restart the server.</div>}
          {!st.registries && <div><b>Revenue and employee lookups are off.</b> Wikidata and SEC EDGAR require a contact User-Agent: set <code>CTIOPS_REGISTRY_USER_AGENT="ctiops-research/0.1 (you@example.org)"</code>. Until then only GLEIF (legal name, country) is used.</div>}
        </div></Card>
      )}
      <StatStrip items={[
        { label: 'Financial posts kept', value: fmtInt(all.length) },
        { label: 'With images preserved', value: fmtInt(all.filter((r) => r.media.some((m) => m.sha256)).length) },
        { label: 'Victim named', value: fmtInt(all.filter((r) => r.victim_name).length), sub: `${fmtInt(all.filter((r) => r.victim_confirmed).length)} analyst-confirmed` },
        { label: 'Company data found', value: fmtInt(all.filter((r) => r.org).length) },
        { label: 'Claim a revenue', value: fmtInt(all.filter((r) => r.claimed_revenue_usd).length) },
        { label: 'Quote a price', value: fmtInt(all.filter((r) => r.price_usd_min).length) },
      ]} />

      <SectionLabel>Queries sent to X</SectionLabel>
      <Card padded>
        <div style={{ display: 'grid', gap: 6, fontSize: 12.5 }}>
          {st?.queries.map((x) => (
            <div key={x.label}><b>{x.label}</b> <span className="muted">· {fmtInt(all.filter((r) => r.queries.includes(x.label)).length)} kept</span><br /><code style={{ fontSize: 11.5 }}>{x.sent_as}</code></div>
          ))}
        </div>
      </Card>

      <SectionLabel>Posts</SectionLabel>
      <FilterBar>
        <SearchInput value={q} onChange={setQ} placeholder="Search text, victim, author…" />
        <Select label="Query" value={f.query} onChange={set('query')} options={opt('All queries', st?.queries.map((x) => x.label) ?? [])} />
        <Select label="Revenue" value={f.revenue_band} onChange={set('revenue_band')} options={opt('Any revenue', st?.revenue_bands ?? [])} />
        <Select label="Employees" value={f.employee_band} onChange={set('employee_band')} options={opt('Any size', st?.employee_bands ?? [])} />
        <Select label="Industry" value={f.fin_subtype} onChange={set('fin_subtype')} options={opt('All financial', Array.from(new Set(all.map((r) => r.fin_subtype).filter(Boolean) as string[])).sort())} />
        <Select label="Triage" value={f.status} onChange={set('status')} options={opt('Any status', ['new', 'relevant', 'noise'])} />
        <span className="muted" style={{ marginLeft: 'auto', fontSize: 12.5 }}>{fmtInt(rows.length)} posts</span>
      </FilterBar>
      <DataTable<XPost> rows={rows} rowKey={(r) => r.id} onRowClick={setSel} maxHeight="70vh"
        empty={<Card><div className="muted" style={{ padding: 16 }}>{all.length ? 'No posts match these filters.' : 'No posts yet. Run the X monitor once the API token is set.'}</div></Card>}
        columns={[
          { key: 'd', header: 'Posted', sort: (r) => r.created_at ?? '', render: (r) => <span className="num" style={{ whiteSpace: 'nowrap' }}>{fmtDate(r.created_at)}</span> },
          { key: 'a', header: 'Author', render: (r) => <span className="muted">@{r.author_handle}</span> },
          { key: 'c', header: 'Card', render: (r) => (r.card ? <img src={r.card} alt="" style={{ width: 90, border: '1px solid var(--border)', borderRadius: 4 }} /> : null) },
          { key: 't', header: 'Post', render: (r) => <div style={{ maxWidth: 380, whiteSpace: 'normal', fontSize: 12.5 }}>{r.text.slice(0, 180)}{r.text.length > 180 ? '…' : ''}</div> },
          { key: 'v', header: 'Victim', render: (r) => r.victim_name ? <span>{r.victim_name}{r.victim_confirmed && <Badge tone="ok" className="ml-1">confirmed</Badge>}</span> : <span className="muted">—</span> },
          { key: 'i', header: 'Industry', sort: (r) => r.fin_subtype ?? '', render: (r) => r.fin_subtype ?? <span className="muted">—</span> },
          { key: 'r', header: 'Revenue', sort: (r) => r.org?.revenue_usd ?? r.claimed_revenue_usd ?? 0, render: (r) => r.revenue_band ? <span title={r.revenue_basis ?? ''}>{r.revenue_band}{r.revenue_basis === 'claimed in post' && <span className="muted"> (claimed)</span>}</span> : <span className="muted">—</span> },
          { key: 'e', header: 'Employees', sort: (r) => r.org?.employees ?? 0, render: (r) => r.employee_band ?? <span className="muted">—</span> },
          { key: 'x', header: 'Access', render: (r) => <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, maxWidth: 160 }}>{r.access_types.slice(0, 3).map((x) => <Badge key={x}>{x}</Badge>)}</div> },
          { key: 'p', header: 'Price', align: 'right', sort: (r) => r.price_usd_min ?? 0, render: (r) => usd(r.price_usd_min) },
          { key: 'rl', header: 'Relevance', sort: (r) => r.relevance, render: (r) => <Meter value={r.relevance} width={52} /> },
        ]} />
      <PostDrawer post={sel} onClose={() => setSel(null)} onSaved={setSel} />
    </>
  )
}

function PostDrawer({ post, onClose, onSaved }: { post: XPost | null; onClose: () => void; onSaved: (p: XPost) => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const save = useMutation({
    mutationFn: (b: { victim_name?: string; status?: string; refresh?: boolean }) => api.x.update(post!.id, b),
    onSuccess: (p) => { onSaved(p); qc.invalidateQueries({ queryKey: ['x', 'posts'] }) },
  })
  const identify = useMutation({ mutationFn: () => api.x.identify(post!.id) })
  if (!post) return null
  const o = post.org
  const id = identify.data
  return (
    <Drawer open={!!post} onClose={onClose} kind="X post" width={720} title={`@${post.author_handle}`} subtitle={<>{fmtDate(post.created_at)} · <Ext href={post.url}>open on X</Ext></>}
      badges={<>{post.queries.map((x) => <Badge key={x}>{x}</Badge>)}<Badge tone={post.status === 'relevant' ? 'accent' : post.status === 'noise' ? 'neutral' : 'info'}>{post.status}</Badge></>}>
      <div style={{ display: 'grid', gap: 18 }}>
        {post.shot && <a href={post.shot} target="_blank" rel="noreferrer" title="Screenshot as shown on x.com"><img src={post.shot} alt="Screenshot of the post on x.com" style={{ width: '100%', border: '1px solid var(--border)', borderRadius: 6 }} /></a>}
        {post.card && <a href={post.card} target="_blank" rel="noreferrer"><img src={post.card} alt="Preserved post card" style={{ width: '100%', border: '1px solid var(--border)', borderRadius: 6 }} /></a>}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <Button size="sm" onClick={() => save.mutate({ status: 'relevant' })}>Mark relevant</Button>
          <Button size="sm" variant="ghost" onClick={() => save.mutate({ status: 'noise' })}>Mark noise</Button>
          <a className="btn btn-ghost" href={`/api/landscape/x/posts/${post.id}/record.json`} target="_blank" rel="noreferrer"><FileJson size={14} /> API record</a>
        </div>
        <Card title="Victim" subtitle="Confirm or correct the company named in the post; company data is looked up on save.">
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
            <Input value={name || post.victim_name || ''} onChange={setName} placeholder="Company name" />
            <Button size="sm" variant="primary" disabled={save.isPending} onClick={() => save.mutate({ victim_name: name || post.victim_name || '' })}>{save.isPending ? 'Looking up…' : 'Save and look up'}</Button>
            {o && <Button size="sm" variant="ghost" onClick={() => save.mutate({ refresh: true })}>Refresh</Button>}
          </div>
          {post.victim_candidates.length > 0 && <div style={{ fontSize: 12.5, marginBottom: 10 }}>Candidates: {post.victim_candidates.map((c) => <button key={c} className="btn btn-ghost" style={{ padding: '0 6px' }} onClick={() => setName(c)}>{c}</button>)}</div>}
          {!post.victim_confirmed && (post.countries.length > 0 || post.tech.length > 0) && (
            <div style={{ marginBottom: 10 }}>
              <Button size="sm" variant="ghost" disabled={identify.isPending} onClick={() => identify.mutate()}>
                <Crosshair size={14} /> {identify.isPending ? 'Searching…' : 'Identify victim (companies + Shodan)'}
              </Button>
              <span className="muted" style={{ fontSize: 11.5, marginLeft: 8 }}>
                {post.countries.join(', ') || 'no country'}{post.tech.length > 0 ? ` · ${post.tech.join(', ')}` : ''}
              </span>
            </div>
          )}
          {id && <IdentifyResult id={id} onPick={(n) => { setName(n); save.mutate({ victim_name: n }) }} />}
          <KV items={[
            { k: 'Legal name', v: o?.legal_name ?? '—' },
            { k: 'Industry', v: o?.industry ? <>{o.industry}{o.fin_subtype && <Badge className="ml-1">{o.fin_subtype}</Badge>}</> : post.fin_subtype ? <>{post.fin_subtype} <span className="muted">(from post)</span></> : '—' },
            { k: 'Revenue', v: o?.revenue_usd ? <>{usd(o.revenue_usd)} <span className="muted">({o.revenue_year ?? 'year n/a'}) · {o.revenue_band}</span></> : post.claimed_revenue_usd ? <>{usd(post.claimed_revenue_usd)} <span className="muted">claimed in post</span></> : '—' },
            { k: 'Employees', v: o?.employees ? <>{fmtInt(o.employees)} <span className="muted">({o.employees_year ?? 'year n/a'}) · {o.employee_band}</span></> : '—' },
            { k: 'Country', v: o?.country ?? (post.countries.join(', ') || '—') },
            { k: 'Website', v: o?.website ? <Ext href={o.website}>{o.website}</Ext> : '—' },
            { k: 'Sources', v: o?.sources.length ? o.sources.map((s) => <div key={s.source}><Ext href={s.url}>{s.source}</Ext> <span className="muted">· {s.fields.join(', ')} · {s.fetched}</span></div>) : <span className="muted">{post.victim_name ? 'not found in public registries' : 'no victim set'}</span> },
          ]} />
        </Card>
        <KV items={[
          { k: 'Post text', v: <div style={{ whiteSpace: 'pre-wrap' }}>{post.text}</div> },
          { k: 'Access types', v: post.access_types.join(', ') || '—' },
          { k: 'Asking price', v: post.price_usd_min ? `${usd(post.price_usd_min)}${post.price_usd_max && post.price_usd_max !== post.price_usd_min ? ` – ${usd(post.price_usd_max)}` : ''}` : '—' },
          { k: 'Forums named', v: post.forums.join(', ') || '—' },
          { k: 'Financial terms', v: post.financial_terms.join(', ') || '—' },
          { k: 'Links', v: post.links.length ? post.links.map((l) => <div key={l}><Ext href={l}>{l.slice(0, 80)}</Ext></div>) : '—' },
          { k: 'Evidence hashes', v: <div style={{ fontSize: 11.5, wordBreak: 'break-all' }}>record {post.raw_sha256}<br />card {post.card_sha256}{post.shot_sha256 && <><br />x.com screenshot {post.shot_sha256}</>}{post.media.filter((m) => m.sha256).map((m, i) => <span key={i}><br />image {i + 1} {m.sha256}</span>)}</div> },
          { k: 'Relevance', v: <Meter value={post.relevance} width={90} /> },
        ]} />
        {post.media.some((m) => m.file) && (
          <Card title={<><ImageIcon size={14} /> Original images</>}>
            <div style={{ display: 'grid', gap: 10 }}>{post.media.filter((m) => m.file).map((m) => <a key={m.file} href={m.file!} target="_blank" rel="noreferrer"><img src={m.file!} alt={m.alt ?? ''} style={{ width: '100%', border: '1px solid var(--border)' }} /></a>)}</div>
          </Card>
        )}
      </div>
    </Drawer>
  )
}

function IdentifyResult({ id, onPick }: { id: XIdentify; onPick: (name: string) => void }) {
  const band = `$${(id.revenue_band[0] / 1e9).toFixed(1)}B–$${(id.revenue_band[1] / 1e9).toFixed(1)}B`
  return (
    <Card title="Victim identification" subtitle={id.disclaimer}>
      <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
        {id.country ?? 'no country'} · revenue {band} · {id.tech.join(', ') || 'no tech named'} · shortlist from {id.firmographic_source} ({id.firmographic_count}) · Shodan hosts {id.shodan_count}
      </div>
      {id.notes.map((n, i) => <div key={i} className="muted" style={{ fontSize: 11.5 }}>· {n}</div>)}
      {id.shodan_error && <div style={{ fontSize: 11.5, color: 'var(--sev-high, #c44)' }}>· Shodan: {id.shodan_error}</div>}
      {id.candidates.length === 0 && <div className="muted" style={{ fontSize: 12.5, marginTop: 8 }}>No company matched the country and revenue band.</div>}
      <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
        {id.candidates.map((c) => (
          <div key={c.name} style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '8px 10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'baseline' }}>
              <b>{c.name}</b>
              <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                <Badge tone={c.confidence === 'High' ? 'ok' : c.confidence === 'Medium' ? 'accent' : 'neutral'}>{c.confidence}</Badge>
                <Button size="sm" onClick={() => onPick(c.name)}>Use</Button>
              </span>
            </div>
            <div className="muted" style={{ fontSize: 11.5, marginTop: 3 }}>
              {c.revenue_band}{c.employees ? ` · ${fmtInt(c.employees)} staff` : ''}{c.country ? ` · ${c.country}` : ''}{c.shodan_host ? ` · Shodan ${c.shodan_host}${c.shodan_hostnames[0] ? ` (${c.shodan_hostnames[0]})` : ''}` : ''}
            </div>
            <div style={{ fontSize: 11.5, marginTop: 3 }}>{c.why.join('; ')}</div>
          </div>
        ))}
      </div>
      {id.shodan_leads.length > 0 && (
        <div style={{ marginTop: 10, fontSize: 11.5 }}>
          <b>Other Shodan hosts running the tech</b> (not matched to a shortlisted firm):
          {id.shodan_leads.map((h) => <div key={h.ip} className="muted">{h.ip} · {h.org ?? h.ssl_cn ?? '?'}{h.hostnames[0] ? ` · ${h.hostnames[0]}` : ''}</div>)}
        </div>
      )}
    </Card>
  )
}

export const XIcon = AtSign
