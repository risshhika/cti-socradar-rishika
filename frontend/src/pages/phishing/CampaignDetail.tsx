import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft } from 'lucide-react'
import { api } from '../../lib/api'
import { fetchCampaignGraph, qstate } from '../../lib/phishingViz'
import { PageHeader, Card, Badge, StatusBadge, ConfidenceBadge, VerdictBadge, KV, Loading, ErrorState, Ext, Tabs, EmptyState, DataTable } from '../../components/ui'
import { StatStrip } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ReviewPanel } from '../../components/ui/ReviewPanel'
import { useTheme } from '../../theme/ThemeProvider'
import { columns, horizontalBars, networkGraph, radar } from '../../charts/options'
import { fmtDate, fmtInt, fmtPct } from '../../lib/format'
import { fmtDay } from '../../lib/viz'
import type { KeyCount } from '../../lib/types'
import { Chips, DetectionList, ExportButtons, KICKER, SampleTable, Viz, fitRadar, tame } from './shared'
import { ClientReportButton } from './ClientReportButton'

const asKc = (v: unknown): KeyCount[] => (Array.isArray(v) ? v.map((x) => (typeof x === 'string' ? { key: x, count: 1 } : { key: String((x as Record<string, unknown>).key ?? (x as Record<string, unknown>).value ?? ''), count: Number((x as Record<string, unknown>).count ?? 1) })) : [])
const asStr = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))) : [])
const GROUP_LABEL: Record<string, string> = { input_names: 'Form field names', script_hosts: 'Script hosts', path_markers: 'URL path markers', obfuscation: 'Obfuscation', antibot: 'Anti-bot / cloaking', image_names: 'Shared image files' }

export default function CampaignDetail() {
  const { id } = useParams()
  const cid = Number(id)
  const nav = useNavigate()
  const { tokens: t } = useTheme()
  const [tab, setTab] = useState<'samples' | 'detections' | 'related'>('samples')
  const q = useQuery({ queryKey: ['phishing', 'campaign', cid], queryFn: () => api.phishing.campaign(cid) })
  const g = useQuery({ queryKey: ['phishing', 'campaign-graph', cid], queryFn: () => fetchCampaignGraph(cid) })
  const d = q.data
  const s = (d?.campaign.summary ?? {}) as Record<string, unknown>

  const o = useMemo(() => {
    if (!d) return null
    const gd = g.data
    const takedown = asKc(s.takedown_targets)
    return {
      graph: gd ? tame(networkGraph(gd.nodes, gd.links, gd.categories, t, { labelMin: 1 }), { repulsion: 120, gravity: 0.12, edgeLength: [30, 80] }) : undefined,
      daily: gd ? columns(gd.days.map((day, i) => ({ label: fmtDay(day, { month: 'short', day: 'numeric' }), value: gd.daily[i], title: day })), t, { unit: 'pages', showValues: true }) : undefined,
      radar: gd ? fitRadar(radar(gd.radar_dims.map((n) => ({ name: n, max: 1 })), [{ name: d.campaign.name, values: gd.profile }], t)) : undefined,
      asns: horizontalBars(asKc(s.top_asns).slice(0, 8).map((x) => ({ label: x.key, value: x.count })), t, { unit: 'pages', labelWidth: 150, color: t.series[3] }),
      apex: horizontalBars(asKc(s.top_apex_domains).slice(0, 8).map((x) => ({ label: x.key, value: x.count })), t, { unit: 'pages', labelWidth: 150, color: t.series[1] }),
      ips: horizontalBars(asKc(s.top_ips).slice(0, 8).map((x) => ({ label: x.key, value: x.count })), t, { unit: 'pages', labelWidth: 120, color: t.series[2] }),
      takedown,
    }
  }, [d, g.data, s, t])

  const back = <Link to="/phishing/campaigns" className="btn btn-ghost"><ArrowLeft size={14} /> Campaigns</Link>
  if (q.isLoading) return <><PageHeader kicker={KICKER} title="Campaign" actions={back} /><Loading rows={8} /></>
  if (q.error || !d) return <><PageHeader kicker={KICKER} title="Campaign" actions={back} /><ErrorState error={q.error ?? 'Not found'} /></>
  const c = d.campaign
  const kit = d.kit
  const groups = (s.shared_marker_groups ?? {}) as Record<string, string[]>
  const gq = qstate(g)
  const related = g.data?.related_campaigns ?? []

  return (
    <>
      <PageHeader kicker={KICKER}
        title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}><span className="mono">{c.name}</span><StatusBadge status={c.status} />{c.brand && <Badge tone="accent">{c.brand}</Badge>}<Badge>{c.cluster_method}</Badge><VerdictBadge verdict={c.review_verdict} /></span>}
        subtitle={`${fmtDate(c.first_seen)} → ${fmtDate(c.last_seen)} · ${c.sector ?? 'sector n/a'}${kit ? ` · kit: ${kit.name}` : ''}`}
        actions={<>{back}<ClientReportButton id={c.id} /><ExportButtons campaignId={c.id} formats={['campaign-cards', 'stix', 'sigma', 'yara', 'iocs']} /></>} />

      <StatStrip items={[
        { label: 'Pages', value: fmtInt(c.sample_count), sub: `${d.samples.filter((x) => x.fetch_status === 'ok').length} captured live` },
        { label: 'Domains', value: fmtInt(c.domain_count), sub: 'distinct apex domains' },
        { label: 'IPs', value: fmtInt(c.ip_count), sub: 'urlscan-observed' },
        { label: 'Cohesion', value: c.sample_count > 1 ? fmtPct(c.cohesion) : '—', sub: c.sample_count > 1 ? 'mean pairwise similarity' : 'single page' },
        { label: 'Kit confidence', value: kit ? fmtPct(c.kit_confidence) : '—', sub: kit ? `${kit.source} kit` : 'no kit match' },
        { label: 'Detections', value: fmtInt(d.detections.length), sub: 'Sigma · YARA · IOC' },
        { label: 'Related campaigns', value: fmtInt(related.length), sub: 'share infrastructure' },
      ]} />

      <Grid>
        <Span n={8}><Viz title="Infrastructure around this campaign" question="What domains, IPs, hosting and exfil endpoints does it use, and which other campaigns share them?" source="captured pages · urlscan.io" query={gq} height={430} option={o?.graph}
          onEvents={{ click: (p: { dataType: string; data: { campaign_id?: number; kit_id?: number } }) => { if (p.dataType !== 'node') return; if (p.data.campaign_id && p.data.campaign_id !== cid) nav(`/phishing/campaigns/${p.data.campaign_id}`); else if (p.data.kit_id) nav(`/phishing/kits/${p.data.kit_id}`) } }}
          caveat={g.data ? `${g.data.nodes.length} nodes · ${related.length} related campaigns · click a node to open it` : undefined}
          table={g.data ? { columns: ['node', 'type', 'pages'], rows: g.data.nodes.map((n) => [n.name, g.data!.categories[n.category], n.value]) } : undefined} /></Span>
        <Span n={4}>
          <Card title="Kit attribution" subtitle={kit ? `${kit.source === 'signature' ? 'Matched a public kit signature' : 'Inferred from markers shared by this cluster'}` : 'No kit signature reached the threshold'}>
            <KV items={[
              { k: 'Kit', v: kit ? <Link to={`/phishing/kits/${kit.id}`}>{kit.name}</Link> : <span className="muted">none</span> },
              { k: 'Family', v: kit?.family ?? '—' },
              { k: 'Confidence', v: kit ? <ConfidenceBadge value={c.kit_confidence} /> : '—' },
              { k: 'Markers', v: kit ? `${kit.markers.length} in signature` : '—' },
              { k: 'Password field', v: s.has_password_field_share != null ? fmtPct(Number(s.has_password_field_share)) + ' of pages' : '—' },
            ]} />
            {kit?.description && <p style={{ margin: '10px 0 0', color: 'var(--text-3)', fontSize: 'var(--fs-sm)' }}>{kit.description}</p>}
            {!!kit?.references?.length && <div style={{ marginTop: 8, display: 'grid', gap: 2, fontSize: 12 }}>{kit.references.slice(0, 3).map((r) => <Ext key={r} href={r}>{r.replace(/^https?:\/\//, '').slice(0, 48)}</Ext>)}</div>}
            <div style={{ borderTop: '1px solid var(--border)', marginTop: 14, paddingTop: 12 }}>
              <div className="muted" style={{ fontSize: 11, fontWeight: 600, letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 8 }}>Hand check</div>
              <ReviewPanel entityType="campaign" entityId={c.id} />
            </div>
          </Card>
        </Span>
      </Grid>

      <Grid>
        <Span n={4}><Viz title="Pages per day" question="When was this campaign active?" source="first-seen timestamps" query={gq} height={220} option={o?.daily}
          table={g.data ? { columns: ['day', 'pages'], rows: g.data.days.map((x, i) => [x, g.data!.daily[i]]) } : undefined} /></Span>
        <Span n={4}><Viz title="Capability profile" question="What share of its live pages harvest credentials, obfuscate, cloak or exfiltrate?" source="feature extraction" query={gq} height={220} option={o?.radar}
          table={g.data ? { columns: ['capability', 'share of pages'], rows: g.data.radar_dims.map((n, i) => [n, `${Math.round(g.data!.profile[i] * 100)}%`]) } : undefined} /></Span>
        <Span n={4}>
          <Card title="Takedown targets" subtitle="Ranked by pages served: report these first">
            {o?.takedown.length ? (
              <div style={{ display: 'grid', gap: 8 }}>
                {asKc(s.takedown_targets).slice(0, 8).map((x, i) => {
                  const raw = (s.takedown_targets as Record<string, unknown>[])[i] ?? {}
                  return <div key={i} style={{ display: 'grid', gridTemplateColumns: '64px 1fr 40px', gap: 8, alignItems: 'center', fontSize: 12.5 }}>
                    <Badge tone={raw.type === 'exfil' ? 'danger' : raw.type === 'asn' ? 'warn' : 'neutral'}>{String(raw.type ?? 'target')}</Badge>
                    <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text)' }} title={x.key}>{x.key}</span>
                    <span className="num muted" style={{ textAlign: 'right' }}>{x.count}</span>
                  </div>
                })}
              </div>
            ) : <EmptyState title="No takedown targets extracted" />}
          </Card>
        </Span>
      </Grid>

      <Grid>
        <Span n={4}><Viz title="Apex domains" question="Which registered domains host it?" source="sample URLs" query={qstate(q)} height={190} option={o?.apex} empty={!asKc(s.top_apex_domains).length} emptyText="No domains" /></Span>
        <Span n={4}><Viz title="Hosting networks" question="Which ASNs serve the pages?" source="urlscan.io ASN" query={qstate(q)} height={190} option={o?.asns} empty={!asKc(s.top_asns).length} emptyText="No hosting data (OpenPhish-only campaign)" /></Span>
        <Span n={4}><Viz title="IP addresses" question="Which IPs serve the pages?" source="urlscan.io page.ip" query={qstate(q)} height={190} option={o?.ips} empty={!asKc(s.top_ips).length} emptyText="No IP data" /></Span>
      </Grid>

      <Grid>
        <Span n={12}>
          <Card title="Shared fingerprint" subtitle="Markers present across this campaign's pages: these drive the clustering, kit match and YARA rule">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
              {Object.entries(GROUP_LABEL).map(([k, label]) => (
                <div key={k}><div className="muted" style={{ fontSize: 11, fontWeight: 600, letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 6 }}>{label}</div><Chips items={asStr(groups[k])} max={14} tone={k === 'antibot' || k === 'obfuscation' ? 'warn' : undefined} /></div>
              ))}
              <div><div className="muted" style={{ fontSize: 11, fontWeight: 600, letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 6 }}>Page titles</div><Chips items={asStr(s.title_examples)} mono={false} max={6} /></div>
              <div><div className="muted" style={{ fontSize: 11, fontWeight: 600, letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 6 }}>Exfil endpoints / form actions</div><Chips items={[...asStr(s.exfil_endpoints), ...asStr(s.form_actions)]} tone="danger" max={10} /></div>
            </div>
          </Card>
        </Span>
      </Grid>

      <Tabs value={tab} onChange={setTab} tabs={[{ value: 'samples', label: 'Pages', count: d.samples.length }, { value: 'detections', label: 'Detections', count: d.detections.length }, { value: 'related', label: 'Related campaigns', count: related.length }]} />
      {tab === 'samples' && <SampleTable rows={d.samples} hideCampaign />}
      {tab === 'detections' && <DetectionList items={d.detections} />}
      {tab === 'related' && (
        <DataTable rows={related} rowKey={(r) => r.id} onRowClick={(r) => nav(`/phishing/campaigns/${r.id}`)} empty={<EmptyState title="No other campaign shares this infrastructure" />}
          columns={[{ key: 'n', header: 'Campaign', render: (r) => <span className="mono">{r.name}</span> }, { key: 's', header: 'Pages', align: 'right', render: (r) => r.samples }]} />
      )}
    </>
  )
}
