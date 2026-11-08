import { useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { FileSearch } from 'lucide-react'
import { api } from '../../lib/api'
import { usePhishingViz, qstate, type KitProfile } from '../../lib/phishingViz'
import { PageHeader, Badge, Loading, ErrorState } from '../../components/ui'
import { StatStrip, Segmented } from '../../components/ui/controls'
import { Grid, Span, SectionLabel } from '../../components/ui/Grid'
import { ModuleEmpty, RunPipelineButton } from '../../components/ui/RunPipelineButton'
import { EChart } from '../../charts/EChart'
import { useTheme } from '../../theme/ThemeProvider'
import { donut, matrixHeatmap, radar, slot, timeSeries } from '../../charts/options'
import { fmtDate, fmtInt } from '../../lib/format'
import { fmtDay } from '../../lib/viz'
import { useFilters } from '../../components/ui/useParams'
import { KICKER, Viz } from './shared'
import s from '../../components/ui/ui.module.css'

/** 'Unnamed HSBC kit de90aa' → 'HSBC · de90aa' for axis and legend labels; named kits stay as they are. */
const shortKit = (n: string) => (n.startsWith('Unnamed ') ? n.replace(/^Unnamed /, '').replace(/ kit /, ' · ') : n.length > 22 ? `${n.slice(0, 21)}…` : n)

function KitCard({ k, dims }: { k: KitProfile; dims: string[] }) {
  const { tokens: t } = useTheme()
  const opt = useMemo(() => {
    const r = radar(dims.map((n) => ({ name: n.replace(' / cloaking', '').replace('Shared image assets', 'Images'), max: 1 })), [{ name: k.name, values: k.profile }], t) as Record<string, any>
    return { ...r, radar: { ...r.radar, radius: '62%', axisName: { ...r.radar.axisName, fontSize: 9.5 } }, tooltip: { show: false } }
  }, [k, dims, t])
  return (
    <Link to={`/phishing/kits/${k.id}`} className={s.panel} style={{ textDecoration: 'none', color: 'inherit', padding: '12px 14px', gap: 6 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text)' }} title={k.name}>{k.name}</div>
          <div className="muted" style={{ fontSize: 12 }}>{k.family ?? 'unknown family'} · {fmtDate(k.first_seen)} → {fmtDate(k.last_seen)}</div>
        </div>
        <Badge tone={k.source === 'signature' ? 'accent' : 'neutral'}>{k.source === 'signature' ? 'named' : 'inferred'}</Badge>
      </div>
      <EChart option={opt} height={150} renderer="svg" ariaLabel={`${k.name} capability profile`} />
      <div style={{ display: 'flex', gap: 14, fontSize: 12, color: 'var(--text-3)' }}>
        <span><b className="num" style={{ color: 'var(--text)' }}>{fmtInt(k.samples)}</b> {k.samples === 1 ? 'page' : 'pages'}</span>
        <span><b className="num" style={{ color: 'var(--text)' }}>{fmtInt(k.campaigns)}</b> {k.campaigns === 1 ? 'campaign' : 'campaigns'}</span>
        <span style={{ marginLeft: 'auto', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{k.brands.slice(0, 2).map((b) => b.key).join(', ')}</span>
      </div>
    </Link>
  )
}

export default function Kits() {
  const nav = useNavigate()
  const { tokens: t } = useTheme()
  const f = useFilters<'source'>()
  const v = usePhishingViz()
  const kits = useQuery({ queryKey: ['phishing', 'kits'], queryFn: api.phishing.kits })
  const src = f.get('source') || 'all'
  const profiles = (v.data?.kit_profiles ?? []).filter((k) => src === 'all' || k.source === src)
  const qs = qstate(v)

  const o = useMemo(() => {
    const d = v.data
    if (!d) return null
    const top = d.kit_profiles.slice(0, 7)
    const short = (x: string) => fmtDay(x, { month: 'short', day: 'numeric' })
    return {
      split: donut([{ name: 'Named (signature)', value: d.kit_split.named, color: t.series[0] }, { name: 'Inferred (unnamed)', value: d.kit_split.inferred, color: t.series[6] }, { name: 'No kit', value: d.kit_split.none, color: t.other }], t, { centerLabel: 'clustered pages' }),
      matrix: (() => {
        const m = matrixHeatmap(d.brand_kit.kits.map(shortKit), d.brand_kit.brands, d.brand_kit.cells, t, { unit: 'pages', showValues: true, yWidth: 100 }) as Record<string, any>
        return { ...m, grid: { ...m.grid, bottom: 44 }, xAxis: { ...m.xAxis, axisLabel: { ...m.xAxis.axisLabel, rotate: 28, interval: 0, fontSize: 10 } } }
      })(),
      activity: timeSeries(d.days, top.slice(0, 6).map((k, i) => ({ name: shortKit(k.name), data: k.daily, type: 'bar' as const, stack: 'kits', color: slot(t, i) })), t, { xFormat: short }),
    }
  }, [v.data, t])

  if (v.isLoading) return <><PageHeader kicker={KICKER} title="Kit fingerprints" /><Loading rows={8} /></>
  if (v.error) return <><PageHeader kicker={KICKER} title="Kit fingerprints" /><ErrorState error={v.error} /></>
  if (!v.data?.kit_profiles.length) return <><PageHeader kicker={KICKER} title="Kit fingerprints" /><ModuleEmpty pipeline="phishing" title="No kits fingerprinted yet" icon={<FileSearch size={24} />} /></>
  const d = v.data
  const named = d.kit_profiles.filter((k) => k.source === 'signature')
  return (
    <>
      <PageHeader kicker={KICKER} title="Kit fingerprints" subtitle="Named kits come from public-reporting signatures (kits.yaml). Inferred kits are clusters that share markers no signature covers yet: candidates to name."
        actions={<><Segmented value={src} onChange={(x) => f.set('source', x === 'all' ? '' : x)} label="Kit source" options={[{ value: 'all', label: 'All' }, { value: 'signature', label: 'Named' }, { value: 'inferred', label: 'Inferred' }]} /><RunPipelineButton name="phishing" label="Run pipeline" variant="secondary" /></>} />
      <StatStrip items={[
        { label: 'Kits seen', value: fmtInt(d.kit_profiles.length), sub: `${fmtInt(kits.data?.length ?? 0)} in signature DB + inferred` },
        { label: 'Named kits', value: fmtInt(named.length), sub: named.slice(0, 3).map((k) => k.name).join(', ') || 'none matched' },
        { label: 'Inferred kits', value: fmtInt(d.kit_profiles.length - named.length), sub: 'awaiting a name' },
        { label: 'Pages attributed', value: fmtInt(d.kit_split.named + d.kit_split.inferred), sub: `${fmtInt(d.kit_split.none)} clustered without a kit` },
      ]} />
      <Grid>
        <Span n={4}><Viz title="Attribution split" question="How much clustered activity maps to a known kit?" source="kits.yaml · clustering" query={qs} height={240} option={o?.split}
          table={{ columns: ['attribution', 'pages'], rows: [['named', d.kit_split.named], ['inferred', d.kit_split.inferred], ['none', d.kit_split.none]] }} /></Span>
        <Span n={8}><Viz title="Kit activity" question="Which kits were deployed on which days?" source="first-seen timestamps" query={qs} height={240} option={o?.activity}
          table={{ columns: ['kit', ...d.days], rows: d.kit_profiles.slice(0, 7).map((k) => [k.name, ...k.daily]) }} /></Span>
      </Grid>
      <Grid>
        <Span n={12}><Viz title="Kit × brand" question="Which kits are reused against several brands? A kit hitting many brands is a phishing-as-a-service platform." source="kit attribution · brand detection" query={qs} height={Math.max(260, d.brand_kit.brands.length * 30 + 130)} option={o?.matrix}
          onEvents={{ click: (p: { componentType: string; value: [number, number, number] }) => { if (p.componentType !== 'series') return; const name = d.brand_kit.kits[p.value[0]]; const k = d.kit_profiles.find((x) => x.name === name); if (k) nav(`/phishing/kits/${k.id}`) } }}
          table={{ columns: ['brand', ...d.brand_kit.kits], rows: d.brand_kit.brands.map((b, bi) => [b, ...d.brand_kit.kits.map((_, ki) => d.brand_kit.cells.find((c) => c[0] === ki && c[1] === bi)?.[2] ?? 0)]) }} /></Span>
      </Grid>
      <SectionLabel>Kit profiles · {profiles.length}</SectionLabel>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16 }}>
        {profiles.map((k) => <KitCard key={k.id} k={k} dims={d.radar_dims} />)}
      </div>
    </>
  )
}
