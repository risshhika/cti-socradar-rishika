import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft } from 'lucide-react'
import { api } from '../../lib/api'
import { usePhishingViz, qstate } from '../../lib/phishingViz'
import { PageHeader, Card, Badge, ConfidenceBadge, Loading, ErrorState, Ext, Tabs, DataTable, Meter, VerdictBadge } from '../../components/ui'
import { StatStrip } from '../../components/ui/controls'
import { Grid, Span } from '../../components/ui/Grid'
import { ReviewPanel } from '../../components/ui/ReviewPanel'
import { useTheme } from '../../theme/ThemeProvider'
import { columns, horizontalBars, radar } from '../../charts/options'
import { fmtDate, fmtInt } from '../../lib/format'
import { fmtDay } from '../../lib/viz'
import type { CampaignOut } from '../../lib/types'
import { DetectionList, KICKER, SampleTable, Viz, fitRadar } from './shared'

export default function KitDetail() {
  const { id } = useParams()
  const kid = Number(id)
  const nav = useNavigate()
  const { tokens: t } = useTheme()
  const [tab, setTab] = useState<'markers' | 'campaigns' | 'samples' | 'detections'>('markers')
  const q = useQuery({ queryKey: ['phishing', 'kit', kid], queryFn: () => api.phishing.kit(kid) })
  const v = usePhishingViz()
  const prof = v.data?.kit_profiles.find((k) => k.id === kid)

  const o = useMemo(() => {
    const d = v.data
    if (!d || !prof) return null
    const avg = d.radar_dims.map((_, i) => d.kit_profiles.reduce((a, k) => a + k.profile[i], 0) / Math.max(1, d.kit_profiles.length))
    return {
      radar: fitRadar(radar(d.radar_dims.map((n) => ({ name: n, max: 1 })), [{ name: prof.name, values: prof.profile }, { name: 'Average kit', values: avg }], t), '52%'),
      daily: columns(d.days.map((x, i) => ({ label: fmtDay(x, { month: 'short', day: 'numeric' }), value: prof.daily[i], title: x })), t, { unit: 'pages', showValues: true, color: t.series[6] }),
      brands: horizontalBars(prof.brands.map((b) => ({ label: b.key, value: b.count })), t, { unit: 'pages', labelWidth: 100 }),
    }
  }, [v.data, prof, t])

  const back = <Link to="/phishing/kits" className="btn btn-ghost"><ArrowLeft size={14} /> Kits</Link>
  if (q.isLoading) return <><PageHeader kicker={KICKER} title="Kit" actions={back} /><Loading rows={8} /></>
  if (q.error || !q.data) return <><PageHeader kicker={KICKER} title="Kit" actions={back} /><ErrorState error={q.error ?? 'Not found'} /></>
  const { kit, campaigns, samples, detections } = q.data
  const qs = qstate(v)
  return (
    <>
      <PageHeader kicker={KICKER} title={<span style={{ display: 'inline-flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>{kit.name}<Badge tone={kit.source === 'signature' ? 'accent' : 'neutral'}>{kit.source === 'signature' ? 'named kit' : 'inferred kit'}</Badge>{kit.family && <Badge>{kit.family}</Badge>}</span>}
        subtitle={kit.description ?? (kit.source === 'inferred' ? 'Inferred from markers this cluster shares; no public signature matched.' : undefined)} actions={back} />
      <StatStrip items={[
        { label: 'Pages', value: fmtInt(kit.sample_count) }, { label: 'Campaigns', value: fmtInt(kit.campaign_count) },
        { label: 'Brands', value: fmtInt(prof?.brands.length ?? 0), sub: prof?.brands.slice(0, 3).map((b) => b.key).join(', ') },
        { label: 'Signature markers', value: fmtInt(kit.markers.length) }, { label: 'First seen', value: fmtDate(kit.first_seen) }, { label: 'Last seen', value: fmtDate(kit.last_seen) },
      ]} />
      <Grid>
        <Span n={4}><Viz title="Capability profile" question="How does this kit compare to the average kit seen this window?" source="feature extraction on live pages" query={qs} height={260} option={o?.radar} empty={!prof} emptyText="No live pages for this kit"
          table={prof && v.data ? { columns: ['capability', 'this kit', 'average'], rows: v.data.radar_dims.map((n, i) => [n, `${Math.round(prof.profile[i] * 100)}%`, `${Math.round((v.data!.kit_profiles.reduce((a, k) => a + k.profile[i], 0) / v.data!.kit_profiles.length) * 100)}%`]) } : undefined} /></Span>
        <Span n={4}><Viz title="Deployment by day" question="When was this kit active?" source="first-seen timestamps" query={qs} height={260} option={o?.daily} empty={!prof} /></Span>
        <Span n={4}><Viz title="Brands targeted" question="Which brands does this kit impersonate?" source="brand detection" query={qs} height={260} option={o?.brands} empty={!prof?.brands.length} /></Span>
      </Grid>
      <Grid>
        <Span n={8}>
          <Card title="References" subtitle="Public reporting the signature is built from">
            {kit.references.length ? <div style={{ display: 'grid', gap: 4, fontSize: 13 }}>{kit.references.map((r) => <Ext key={r} href={r} />)}</div> : <span className="muted">No public references (inferred kit).</span>}
          </Card>
        </Span>
        <Span n={4}><Card title="Hand check" subtitle="Is this attribution right?"><ReviewPanel entityType="kit" entityId={kit.id} /></Card></Span>
      </Grid>
      <Tabs value={tab} onChange={setTab} tabs={[{ value: 'markers', label: 'Signature markers', count: kit.markers.length }, { value: 'campaigns', label: 'Campaigns', count: campaigns.length }, { value: 'samples', label: 'Pages', count: samples.length }, { value: 'detections', label: 'Detections', count: detections.length }]} />
      {tab === 'markers' && (
        <DataTable rows={kit.markers.map((m, i) => ({ ...m, _i: i })) as (Record<string, any>)[]} rowKey={(r) => r._i}
          columns={[
            { key: 'label', header: 'Marker', sort: (r) => String(r.label ?? ''), render: (r) => <span style={{ color: 'var(--text)' }}>{String(r.label ?? '—')}</span> },
            { key: 'type', header: 'Type', sort: (r) => String(r.type ?? ''), render: (r) => <Badge>{String(r.type ?? '')}</Badge> },
            { key: 'pattern', header: 'Pattern', render: (r) => <span className="mono" style={{ display: 'inline-block', maxWidth: 520, overflow: 'hidden', textOverflow: 'ellipsis' }} title={String(r.pattern ?? r.value ?? '')}>{String(r.pattern ?? r.value ?? '')}</span> },
            { key: 'w', header: 'Weight', align: 'right', sort: (r) => Number(r.weight ?? 0), render: (r) => <span className="num">{String(r.weight ?? '')}</span> },
          ]} />
      )}
      {tab === 'campaigns' && (
        <DataTable<CampaignOut> rows={campaigns} rowKey={(r) => r.id} onRowClick={(r) => nav(`/phishing/campaigns/${r.id}`)}
          columns={[
            { key: 'n', header: 'Campaign', sort: (r) => r.name, render: (r) => <span className="mono" style={{ color: 'var(--text)' }}>{r.name}</span> },
            { key: 'b', header: 'Brand', sort: (r) => r.brand, render: (r) => r.brand ? <Badge tone="accent">{r.brand}</Badge> : <span className="muted">—</span> },
            { key: 's', header: 'Pages', align: 'right', sort: (r) => r.sample_count, render: (r) => <span className="num">{r.sample_count}</span> },
            { key: 'c', header: 'Kit confidence', sort: (r) => r.kit_confidence, render: (r) => <ConfidenceBadge value={r.kit_confidence} /> },
            { key: 'coh', header: 'Cohesion', sort: (r) => r.cohesion, render: (r) => <Meter value={r.cohesion} color="var(--series-7)" /> },
            { key: 'f', header: 'First seen', sort: (r) => r.first_seen, render: (r) => <span className="muted num">{fmtDate(r.first_seen)}</span> },
            { key: 'v', header: 'Verdict', render: (r) => <VerdictBadge verdict={r.review_verdict} /> },
          ]} />
      )}
      {tab === 'samples' && <SampleTable rows={samples} hideKit />}
      {tab === 'detections' && <DetectionList items={detections} showCampaign />}
    </>
  )
}
