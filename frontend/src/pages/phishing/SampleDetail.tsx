import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, FileCode2 } from 'lucide-react'
import { api } from '../../lib/api'
import { PageHeader, Card, Badge, StatusBadge, ConfidenceBadge, VerdictBadge, KV, Code, Button, Loading, ErrorState, Ext } from '../../components/ui'
import { StatStrip } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ReviewPanel } from '../../components/ui/ReviewPanel'
import { ScreenshotLarge } from '../../components/ui/Screenshot'
import { fmtDateTime, fmtInt } from '../../lib/format'
import { countryName, flag } from '../../charts/countries'
import { Chips, DetectionTypeBadge, KICKER, MATCH_KIND_LABEL, RankFactors, ThreatPill } from './shared'

const strs = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => (typeof x === 'string' ? x : typeof x === 'object' && x && 'value' in x ? String((x as { value: unknown }).value) : JSON.stringify(x))) : [])
const Label = ({ children }: { children: string }) => <div className="muted" style={{ fontSize: 11, fontWeight: 600, letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 6 }}>{children}</div>

function HtmlViewer({ id }: { id: number }) {
  const [open, setOpen] = useState(false)
  const q = useQuery({ queryKey: ['phishing', 'sample-html', id], enabled: open, queryFn: async () => { const r = await fetch(`/api/phishing/samples/${id}/html`); if (!r.ok) throw new Error(`HTTP ${r.status}: captured HTML not available`); return r.text() } })
  return (
    <Card title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}><FileCode2 size={15} /> Captured HTML</span>} subtitle="Shown as plain text only. The page is never rendered."
      actions={<Button size="sm" onClick={() => setOpen((o) => !o)}>{open ? 'Hide source' : 'View source as text'}</Button>}>
      {open ? (q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} /> : <Code>{q.data}</Code>) : <div className="muted" style={{ fontSize: 13 }}>The raw page source is stored under data/artifacts. Open it here as inert text.</div>}
    </Card>
  )
}

export default function SampleDetail() {
  const { id } = useParams()
  const sid = Number(id)
  const q = useQuery({ queryKey: ['phishing', 'sample', sid], queryFn: () => api.phishing.sample(sid) })
  const back = <Link to="/phishing/samples" className="btn btn-ghost"><ArrowLeft size={14} /> Samples</Link>
  if (q.isLoading) return <><PageHeader kicker={KICKER} title="Sample" actions={back} /><Loading rows={8} /></>
  if (q.error || !q.data) return <><PageHeader kicker={KICKER} title="Sample" actions={back} /><ErrorState error={q.error ?? 'Not found'} /></>
  const s = q.data
  const ft = s.features ?? {}
  const forms = Array.isArray(ft.forms) ? (ft.forms as Record<string, unknown>[]) : []
  const meta = (ft._meta ?? {}) as Record<string, unknown>
  return (
    <>
      <PageHeader kicker={KICKER}
        title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>Sample #{s.id}<StatusBadge status={s.fetch_status} />{s.brand && <Badge tone="accent">{s.brand}</Badge>}<VerdictBadge verdict={s.review_verdict} /></span>}
        subtitle={<span className="mono" style={{ wordBreak: 'break-all' }}>{s.url}</span>} actions={back} />

      <StatStrip items={[
        { label: 'DOM tags', value: ft.tag_count != null ? fmtInt(Number(ft.tag_count)) : '—', sub: ft.dom_depth != null ? `depth ${ft.dom_depth}` : undefined },
        { label: 'Forms', value: fmtInt(Number(ft.form_count ?? forms.length)), sub: ft.has_password_field ? 'has a password field' : 'no password field' },
        { label: 'Input fields', value: fmtInt(strs(ft.input_names).length) },
        { label: 'External scripts', value: fmtInt(strs(ft.scripts).length), sub: `${strs(ft.script_hosts).length} hosts` },
        { label: 'Inline JS', value: ft.inline_js_bytes != null ? `${fmtInt(Math.round(Number(ft.inline_js_bytes) / 1024))} KB` : '—', sub: `${fmtInt(Number(ft.inline_script_count ?? 0))} blocks` },
        { label: 'Visible text', value: ft.text_length != null ? fmtInt(Number(ft.text_length)) : '—', sub: 'characters' },
        { label: 'Domain age', value: meta.domainAgeDays != null ? `${meta.domainAgeDays} d` : '—', sub: meta.apexDomainAgeDays != null ? `apex ${meta.apexDomainAgeDays} d` : 'urlscan' },
      ]} />

      <Grid>
        <Span n={4}>
          <Card title="Page">
            <ScreenshotLarge src={s.screenshot_url} alt={s.title ?? s.url} />
            <div style={{ marginTop: 12 }}><KV items={[
              { k: 'Title', v: s.title ?? <span className="muted">—</span> },
              { k: 'Brand', v: s.brand ? <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>{s.brand}<ConfidenceBadge value={s.brand_confidence} /></span> : <span className="muted">not detected</span> },
              { k: 'Campaign', v: s.campaign_id ? <Link to={`/phishing/campaigns/${s.campaign_id}`} className="mono">{s.campaign_name ?? `#${s.campaign_id}`}</Link> : <span className="muted">unclustered</span> },
              { k: 'Kit', v: s.kit_id ? <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}><Link to={`/phishing/kits/${s.kit_id}`}>{s.kit_name}</Link><ConfidenceBadge value={s.kit_confidence} /></span> : <span className="muted">no match</span> },
            ]} /></div>
          </Card>
        </Span>
        <Span n={4}>
          <Card title="Collection & infrastructure">
            <KV items={[
              { k: 'URL', v: <span className="mono" style={{ wordBreak: 'break-all' }}>{s.url}</span> },
              { k: 'Final URL', v: s.final_url ? <span className="mono" style={{ wordBreak: 'break-all' }}>{s.final_url}</span> : '—' },
              { k: 'Domain', v: <span className="mono">{s.domain ?? '—'}</span> },
              { k: 'Apex · TLD', v: <span className="mono">{s.apex_domain ?? '—'} · .{s.tld ?? '—'}</span> },
              { k: 'IP', v: <span className="mono">{s.ip ?? '—'}</span> },
              { k: 'Hosting', v: s.asn ? <span><span className="mono">{s.asn}</span> {s.asn_name}</span> : '—' },
              { k: 'Country', v: s.country ? `${flag(s.country)} ${countryName(s.country)}` : '—' },
              { k: 'TLS', v: meta.tlsIssuer ? `${meta.tlsIssuer}${meta.server ? ` · server ${meta.server}` : ''}` : '—' },
              { k: 'Source', v: <span>{(s.sources?.length ? s.sources : [s.source]).join(' + ')}{s.source_id && <> · <Ext href={`https://urlscan.io/result/${s.source_id}/`}>urlscan result</Ext></>}</span> },
              { k: 'Duplicates', v: s.duplicate_count ? <span>{s.duplicate_count} merged report{s.duplicate_count > 1 ? 's' : ''}{s.duplicate_urls.length > 0 && <div style={{ marginTop: 4, maxHeight: 120, overflow: 'auto' }}>{s.duplicate_urls.map((u) => <div key={u} className="mono muted" style={{ fontSize: 11, wordBreak: 'break-all' }}>{u}</div>)}</div>}</span> : <span className="muted">none</span> },
              { k: 'Dedup key', v: <span className="mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{s.dedup_key ?? '—'}</span> },
              { k: 'Tags', v: <Chips items={s.source_tags} mono={false} /> },
              { k: 'First seen', v: fmtDateTime(s.first_seen) },
              { k: 'Fetched', v: `${fmtDateTime(s.fetched_at)} · ${s.fetch_status}${s.http_status ? ` · HTTP ${s.http_status}` : ''}` },
              { k: 'HTML', v: s.html_sha256 ? <span className="mono" style={{ wordBreak: 'break-all' }}>{s.html_sha256.slice(0, 24)}… · {fmtInt(s.html_size)} B</span> : <span className="muted">not captured</span> },
              { k: 'Struct hash', v: <span className="mono">{s.struct_hash ?? '—'}</span> },
            ]} />
          </Card>
        </Span>
        <Span n={4}>
          <Card title={<span style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>Threat rank <ThreatPill tier={s.threat_tier} score={s.threat_score} /></span>}
            subtitle={<DetectionTypeBadge type={s.detection_type} />}>
            {s.squat && <div style={{ marginBottom: 10 }}><KV items={[
              { k: 'Imitates', v: <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}><Badge tone="accent">{s.squat.brand}</Badge>{MATCH_KIND_LABEL[s.squat.kind] ?? s.squat.kind}</span> },
              { k: 'Evidence', v: <span className="mono" style={{ fontSize: 12 }}>{s.squat.evidence}</span> },
              ...(s.squat.lure_words.length ? [{ k: 'Lure words', v: <span className="mono">{s.squat.lure_words.join(' ')}</span> }] : []),
            ]} /></div>}
            <RankFactors factors={s.rank_factors} />
          </Card>
          <div style={{ height: 16 }} />
          <Card title="Hand check" subtitle="Is this phishing for the detected brand, and is it in the right campaign?"><ReviewPanel entityType="sample" entityId={s.id} /></Card>
        </Span>
      </Grid>

      <Grid>
        <Span n={6}>
          <Card title="Credential surface" subtitle="Forms, fields and where they submit">
            {forms.length ? (
              <div style={{ display: 'grid', gap: 8 }}>{forms.map((fm, i) => (
                <div key={i} style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 10, fontSize: 12 }}>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}><Badge>{String(fm.method ?? 'GET').toUpperCase()}</Badge><span className="mono" style={{ wordBreak: 'break-all' }}>{String(fm.action || '(same page)')}</span></div>
                  <div style={{ marginTop: 6 }}><Chips items={strs(fm.inputs ?? fm.input_names)} /></div>
                </div>
              ))}</div>
            ) : <div className="muted" style={{ fontSize: 13 }}>No forms on the captured page.</div>}
            <div style={{ marginTop: 12 }}><Label>Input names</Label><Chips items={strs(ft.input_names)} /></div>
            <div style={{ marginTop: 12 }}><Label>Exfil endpoints · form actions</Label><Chips items={[...strs(ft.exfil), ...strs(ft.form_actions)]} tone="danger" /></div>
          </Card>
        </Span>
        <Span n={6}>
          <Card title="Kit & evasion markers" subtitle="Signals used for kit fingerprinting">
            <div style={{ display: 'grid', gap: 12 }}>
              <div><Label>Kit markers</Label><Chips items={strs(ft.kit_markers)} tone="accent" /></div>
              <div><Label>Anti-bot / cloaking</Label><Chips items={strs(ft.antibot)} tone="warn" /></div>
              <div><Label>Obfuscation</Label><Chips items={strs(ft.obfuscation)} tone="warn" /></div>
              <div><Label>URL path markers</Label><Chips items={[...strs(ft.path_markers), ...strs(ft.path_tokens)]} /></div>
              <div><Label>Script hosts</Label><Chips items={strs(ft.script_hosts)} /></div>
              <div><Label>Image files</Label><Chips items={strs(ft.image_names)} max={16} /></div>
              <div style={{ display: 'flex', gap: 24, fontSize: 12 }}>
                <div><Label>Favicon hash</Label><span className="mono">{ft.favicon_hash ? String(ft.favicon_hash) : '—'}</span></div>
                <div><Label>Generator</Label><span>{ft.meta_generator ? String(ft.meta_generator) : '—'}</span></div>
              </div>
            </div>
          </Card>
        </Span>
      </Grid>
      <Grid>
        <Span n={6}><Card title="Visible-text vocabulary" subtitle="Tokens used for text similarity"><Chips items={strs(ft.text_tokens)} mono={false} max={90} /></Card></Span>
        <Span n={6}><Card title="Linked resources" subtitle="Hosts the page pulls stylesheets and images from"><div style={{ display: 'grid', gap: 12 }}><div><Label>Link hosts</Label><Chips items={strs(ft.link_hosts)} /></div><div><Label>Image hosts</Label><Chips items={strs(ft.image_hosts)} /></div><div><Label>Scripts</Label><Chips items={strs(ft.scripts)} max={20} /></div></div></Card></Span>
      </Grid>
      <HtmlViewer id={s.id} />
    </>
  )
}
