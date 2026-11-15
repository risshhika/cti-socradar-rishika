import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Download, ExternalLink, FileText, Printer, Search } from 'lucide-react'
import { api } from '../../lib/api'
import type { BrandReport } from '../../lib/types'
import { Badge, Card, ErrorState, KV, Loading, PageHeader } from '../../components/ui'
import { Select, StatStrip } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { CopyButton } from '../../components/ui/CopyButton'
import { useFilters } from '../../components/ui/useParams'
import { countryName, flag } from '../../charts/countries'
import { fmtDateTime, fmtInt } from '../../lib/format'
import { DETECTION_TYPE_LABEL, KICKER, MATCH_KIND_LABEL, ThreatPill } from './shared'

const H = ({ n, children }: { n: number; children: string }) => (
  <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, margin: '28px 0 10px' }}>
    <span className="mono muted" style={{ fontSize: 12 }}>{String(n).padStart(2, '0')}</span>
    <h2 style={{ margin: 0, fontSize: 17 }}>{children}</h2>
  </div>
)
const Tags = ({ items }: { items: string[] }) => items.length
  ? <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 4 }}>{items.map((x) => <Badge key={x}>{x}</Badge>)}</span>
  : <span className="muted">—</span>

/** Generates an executive report for one brand from the live P4 data (every figure computed on request). */
export default function BrandReportPage() {
  const nav = useNavigate()
  const f = useFilters<'brand'>()
  const brands = useQuery({ queryKey: ['phishing', 'report-brands'], queryFn: api.phishing.reportBrands })
  const [pick, setPick] = useState('')
  const brand = f.get('brand')
  useEffect(() => { if (!pick && brands.data?.length) setPick(brand || brands.data.find((b) => b.in_scope)?.brand || brands.data[0].brand) }, [brands.data, brand, pick])
  const q = useQuery({ queryKey: ['phishing', 'report', brand], queryFn: () => api.phishing.brandReport(brand), enabled: !!brand, retry: false, staleTime: 5 * 60_000 })
  const r = q.data as BrandReport | undefined

  const picker = (
    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
      <Select label="Brand" value={pick} onChange={setPick}
        options={(brands.data ?? []).map((b) => ({ value: b.brand, label: `${b.brand} · ${b.samples} pages${b.in_scope ? '' : ' (outside scope)'}` }))} />
      <button className="btn btn-primary" disabled={!pick || q.isFetching} onClick={() => { f.set('brand', pick); if (pick === brand) q.refetch() }}>
        <FileText size={14} /> {q.isFetching ? 'Generating…' : 'Generate report'}
      </button>
      {r && <>
        <a className="btn" href={api.phishing.brandReportHtml(r.brand, true)}><Download size={14} /> Download HTML</a>
        <a className="btn btn-ghost" href={api.phishing.brandReportHtml(r.brand, false)} target="_blank" rel="noreferrer"><Printer size={14} /> Printable / PDF</a>
      </>}
    </div>
  )

  return (
    <>
      <PageHeader kicker={KICKER} title={r ? `${r.brand}: executive phishing report` : 'Executive brand report'}
        subtitle={r ? `${r.sector} · last ${r.window_days} days · generated ${fmtDateTime(r.generated_at)}` : 'Pick a brand to turn the current phishing data into an end-to-end executive report.'}
        actions={picker} />
      {!brand ? <Card><span className="muted">Choose a brand and press <b>Generate report</b>. The report covers an executive summary, the numbers, how the brand is targeted, a live use case with screenshot, the kit fingerprint, urlscan queries to find more, geography, user impact and defensive steps.</span></Card>
        : q.isLoading || (q.isFetching && !r) ? <Loading rows={12} />
        : q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} />
        : r && <ReportBody r={r} onSample={(id) => nav(`/phishing/samples/${id}`)} />}
    </>
  )
}

function ReportBody({ r, onSample }: { r: BrandReport; onSample: (id: number) => void }) {
  const n = r.numbers, t = r.targeting, uc = r.use_case, fp = r.fingerprint, g = r.geography
  return (
    <div style={{ maxWidth: 1100 }}>
      <H n={1}>Executive summary</H>
      <Card>
        <p style={{ margin: 0, fontSize: 15, lineHeight: 1.6 }}>{r.executive_summary}</p>
        <div style={{ marginTop: 14, padding: '10px 14px', borderLeft: '4px solid var(--sev-critical)', background: 'color-mix(in srgb, var(--sev-critical) 8%, transparent)', borderRadius: 6, fontWeight: 600 }}>
          Impact: {r.impact_one_line}
        </div>
      </Card>

      <H n={2}>Numbers at a glance</H>
      <StatStrip items={[
        { label: 'Phishing pages', value: fmtInt(n.pages), sub: `${(n.share_of_all * 100).toFixed(1)}% of all collected` },
        { label: 'Live now', value: fmtInt(n.live), sub: `${n.blocked} cloaked · ${n.offline} taken down` },
        { label: 'Critical + high', value: fmtInt(n.critical + n.high), sub: `${n.critical} critical` },
        { label: 'Campaigns', value: fmtInt(n.campaigns), sub: `${n.multi_page_campaigns} multi-page · ${n.active_campaigns} active` },
        { label: 'Distinct kits', value: fmtInt(n.kits), sub: `${n.named_kits} publicly documented` },
        { label: 'Lookalike hosts', value: fmtInt(n.typosquat_hosts), sub: `${n.new_domain_leads} registered this week` },
        { label: 'Detections ready', value: fmtInt(n.detections), sub: `${n.duplicates_merged} duplicate reports merged` },
      ]} />
      <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>Sources: {Object.entries(n.sources).map(([k, v]) => `${k} ${v}`).join(' · ')}</div>

      <H n={3}>Brand targeting</H>
      <Card>
        <KV items={[
          { k: 'Rank among brands', v: t.rank_among_brands ? `#${t.rank_among_brands} most-impersonated in the window` : '—' },
          { k: 'How it is imitated', v: <Tags items={Object.entries(t.detection_types).map(([k, v]) => `${DETECTION_TYPE_LABEL[k] ?? k}: ${v}`)} /> },
          { k: 'Hostname tricks', v: <Tags items={Object.entries(t.squat_kinds).map(([k, v]) => `${MATCH_KIND_LABEL[k] ?? k}: ${v}`)} /> },
          { k: 'Hosting', v: <span>{t.dedicated_domains} on dedicated domains; free platforms: <Tags items={t.hosting_platforms.map((p) => `${p.platform} · ${p.pages}`)} /></span> },
          { k: 'Lure words', v: <Tags items={t.lure_words.map((w) => `${w.word} · ${w.count}`)} /> },
          { k: 'Data requested', v: <Tags items={t.credential_surface.map((c) => `${c.asset} · ${c.pages} pages`)} /> },
          { k: 'Kits in use', v: <Tags items={t.kits.map((k) => `${k.name} · ${k.pages}`)} /> },
          { k: 'Page themes', v: <Tags items={t.title_themes} /> },
        ]} />
      </Card>

      <H n={4}>Threat use case</H>
      {uc ? (
        <Grid>
          <Span n={8}>
            <Card padded={false}>
              <img src={uc.screenshot} alt="Screenshot of the live phishing page" style={{ width: '100%', display: 'block', borderRadius: '8px 8px 0 0', background: 'var(--surface-2)' }} />
              <div style={{ padding: '10px 14px', fontSize: 13 }}>{uc.caption}</div>
            </Card>
          </Span>
          <Span n={4}>
            <Card title="Why this page" subtitle={uc.live_within_48h ? 'Re-verified live in the last 48 hours' : 'Captured earlier in the window'}>
              <KV items={[
                { k: 'Threat rank', v: <ThreatPill tier={uc.threat_tier} score={uc.threat_score} /> },
                { k: 'Verified live', v: fmtDateTime(uc.verified_live_at) },
                { k: 'First seen', v: fmtDateTime(uc.first_seen) },
                { k: 'Hosting', v: <span>{uc.country ? `${flag(uc.country)} ${countryName(uc.country)} · ` : ''}{uc.hosting ?? '—'}</span> },
                { k: 'Asks for', v: <Tags items={uc.assets_requested} /> },
              ]} />
              <button className="btn btn-ghost" style={{ marginTop: 10 }} onClick={() => onSample(uc.sample_id)}><ExternalLink size={14} /> Open sample (analysts)</button>
            </Card>
          </Span>
        </Grid>
      ) : <Card><span className="muted">No live page with a screenshot in the window.</span></Card>}

      <H n={5}>Fingerprint reference</H>
      <Card>
        {fp ? <KV items={[
          { k: 'Kit', v: fp.kit ? <span><b>{fp.kit.name}</b> · {fp.kit.family} · <Badge tone={fp.kit.source === 'signature' ? 'ok' : 'warn'}>{fp.kit.source === 'signature' ? 'public signature' : 'inferred from cluster'}</Badge> · confidence {Math.round((fp.kit.confidence ?? 0) * 100)}%<div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{fp.kit.description}</div></span> : 'Unmatched' },
          { k: 'Matched markers', v: <Tags items={fp.matched_markers} /> },
          { k: 'Campaign', v: fp.campaign ? `${fp.campaign.name} · ${fp.campaign.pages} pages · ${fp.campaign.domains} domains · ${fp.campaign.ips} IPs · cohesion ${fp.campaign.cohesion} (${fp.campaign.method})` : 'Standalone page' },
          { k: 'Shared artefacts', v: fp.campaign?.shared_markers.length ? <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{fp.campaign.shared_markers.map((m) => <code key={m} className="mono" style={{ fontSize: 11 }}>{m}</code>)}</span> : '—' },
          { k: 'Page hashes', v: <span className="mono" style={{ fontSize: 12 }}>DOM simhash {fp.page.dom_simhash ?? '—'} · favicon {fp.page.favicon_hash ?? '—'}</span> },
          { k: 'Evasion', v: <Tags items={[...fp.page.obfuscation, ...fp.page.antibot]} /> },
          { k: 'Public references', v: fp.kit?.references.length ? <div>{fp.kit.references.map((u) => <div key={u}><a href={u} target="_blank" rel="noreferrer">{u}</a></div>)}</div> : '—' },
        ]} /> : <span className="muted">No use case, so no fingerprint.</span>}
      </Card>

      <H n={6}>Find more on urlscan.io</H>
      <Card padded={false}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead><tr className="muted" style={{ textAlign: 'left' }}><th style={{ padding: '8px 12px' }}>What it finds</th><th>Query</th><th style={{ textAlign: 'right', paddingRight: 12 }}>Results now</th></tr></thead>
          <tbody>{r.urlscan_queries.map((x) => (
            <tr key={x.query} style={{ borderTop: '1px solid var(--border)' }}>
              <td style={{ padding: '8px 12px', verticalAlign: 'top', width: '30%' }}><b>{x.label}</b><div className="muted" style={{ fontSize: 12 }}>{x.why}</div></td>
              <td style={{ verticalAlign: 'top', padding: '8px 0' }}>
                <code className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{x.query}</code>
                <div style={{ display: 'flex', gap: 6, marginTop: 4 }}><CopyButton text={x.query} /><a className="btn btn-ghost" href={x.link} target="_blank" rel="noreferrer"><Search size={13} /> Run on urlscan</a></div>
              </td>
              <td className="num" style={{ textAlign: 'right', paddingRight: 12, verticalAlign: 'top', paddingTop: 8 }}>{x.results_now != null ? fmtInt(x.results_now) : <span className="muted" title={x.error ?? 'needs an API key'}>—</span>}</td>
            </tr>))}
          </tbody>
        </table>
      </Card>

      <H n={7}>Impact in one line</H>
      <Card><b>{r.impact_one_line}</b></Card>

      <H n={8}>Geographical footprint</H>
      <Card>
        <KV items={[
          { k: 'Hosting countries', v: <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 4 }}>{g.countries.map((c) => <Badge key={c.country} tone={c.new_recently ? 'danger' : 'neutral'}>{flag(c.country)} {countryName(c.country)} · {c.pages}{c.new_recently ? ' · new' : ''}</Badge>)}</span> },
          { k: 'Expansion', v: g.new_countries.length ? `Hosting appeared in ${g.new_countries.map(countryName).join(', ')} only in the second half of the window.` : 'No new hosting countries in the second half of the window.' },
          { k: 'Networks', v: <div>{g.asns.map((a) => <div key={a.asn}>{a.asn} · {a.pages}</div>)}</div> },
          { k: 'Top-level domains', v: <Tags items={g.tlds.map((x) => `.${x.tld} · ${x.pages}`)} /> },
        ]} />
      </Card>

      <H n={9}>Impact for everyday users</H>
      <Card padded={false}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead><tr className="muted" style={{ textAlign: 'left' }}><th style={{ padding: '8px 12px' }}>What they lose</th><th>What happens next</th><th>Evidence</th></tr></thead>
          <tbody>{r.user_impact.map((u) => (
            <tr key={u.asset} style={{ borderTop: '1px solid var(--border)' }}><td style={{ padding: '8px 12px' }}><b>{u.asset}</b></td><td>{u.consequence}</td><td className="muted">{u.evidence}</td></tr>))}
          </tbody>
        </table>
      </Card>

      <H n={10}>Defensive steps</H>
      <Grid>
        <Span n={6}><Card title="For the organisation"><ul style={{ margin: 0, paddingLeft: 18 }}>{r.defense.organisation.map((x) => <li key={x} style={{ marginBottom: 6 }}>{x}</li>)}</ul>
          <div style={{ marginTop: 8 }}><Link to="/phishing/detections">Open detections</Link> · <Link to={`/phishing/campaigns?brand=${encodeURIComponent(r.brand)}`}>Campaigns for {r.brand}</Link></div></Card></Span>
        <Span n={6}><Card title="For customers"><ul style={{ margin: 0, paddingLeft: 18 }}>{r.defense.customers.map((x) => <li key={x} style={{ marginBottom: 6 }}>{x}</li>)}</ul></Card></Span>
      </Grid>
      <p className="muted" style={{ fontSize: 12, marginTop: 24 }}>{r.method_note}</p>
    </div>
  )
}
