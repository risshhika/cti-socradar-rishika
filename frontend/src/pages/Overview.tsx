import { useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import { api } from '../lib/api'
import { usePhishingViz, qstate } from '../lib/phishingViz'
import { PageHeader, Badge, StatusBadge, EmptyState } from '../components/ui'
import { KpiTile } from '../components/ui/KpiTile'
import { Grid, KpiRow, Span, SectionLabel } from '../components/ui/Grid'
import { RunPipelineButton } from '../components/ui/RunPipelineButton'
import { ChartCard } from '../components/ui/ChartCard'
import { EChart } from '../charts/EChart'
import { useTheme } from '../theme/ThemeProvider'
import { funnel, horizontalBars, ratioGauge, timeSeries, worldChoropleth } from '../charts/options'
import { countryName } from '../charts/countries'
import { fmtAgo, fmtDuration, fmtInt } from '../lib/format'
import { fmtYm } from '../lib/viz'
import { Viz, fitFunnel, fitGauge, tame } from './phishing/shared'
import d from '../components/ui/dash.module.css'

const ENTITY_LABEL: Record<string, string> = { campaign: 'Campaigns', sample: 'Samples', kit: 'Kits', victim: 'Victims', actor: 'Actors', iab: 'IAB listings', briefing: 'Briefings' }

function Trend({ trend, change }: { trend: string; change: number | null }) {
  const Icon = trend === 'rising' ? ArrowUpRight : trend === 'falling' ? ArrowDownRight : Minus
  const tone = trend === 'rising' ? 'danger' : trend === 'falling' ? 'ok' : trend === 'new' ? 'warn' : 'neutral'
  return <Badge tone={tone}><Icon size={12} />{trend === 'new' ? 'new' : change != null ? `${change > 0 ? '+' : ''}${Math.round(change * 100)}%` : trend}</Badge>
}

export default function Overview() {
  const nav = useNavigate()
  const { tokens: t } = useTheme()
  const ov = useQuery({ queryKey: ['overview'], queryFn: api.overview, refetchInterval: 30000 })
  const pv = usePhishingViz()
  const ls = useQuery({ queryKey: ['landscape', 'stats', {}], queryFn: () => api.landscape.stats(), retry: false })
  const camps = useQuery({ queryKey: ['phishing', 'campaigns', { status: 'active', min_samples: 2 }], queryFn: () => api.phishing.campaigns({ status: 'active', min_samples: 2 }), retry: false })
  const o = ov.data
  const p = pv.data
  const l = ls.data

  // Last complete month vs the one before (the current month is partial).
  const tl = l?.timeline ?? []
  const full = tl.length >= 2 ? tl.slice(0, -1) : tl
  const cur = full.at(-1)
  const prev = full.at(-2)

  const charts = useMemo(() => ({
    phishMap: p ? tame(worldChoropleth(p.countries, t, { unit: 'phishing pages hosted' })) : undefined,
    victimMap: l ? tame(worldChoropleth(l.by_country_scope.map((c) => ({ iso2: c.key, value: c.count })), t, { unit: `${l.sector} victims`, zoomTo: l.region === 'Europe' || ['DACH', 'Nordics', 'UK&I', 'Benelux'].includes(l.region) ? 'europe' : 'world' })) : undefined,
    funnel: p ? fitFunnel(funnel(p.funnel, t), t.text) : undefined,
    victims: l ? timeSeries(l.timeline.map((x) => x.period), [
      { name: 'All leak-site victims', data: l.timeline.map((x) => x.value), type: 'bar', color: t.series[0] },
      { name: `In scope (${l.sector} · ${l.region})`, data: l.timeline.map((x) => x.secondary ?? 0), yAxisIndex: 1, color: t.series[1] },
    ], t, { rightAxisName: 'in scope', xFormat: fmtYm }) : undefined,
    actors: l ? horizontalBars(l.top_actors_scope.slice(0, 8).map((a) => ({ label: a.key, value: a.count })), t, { unit: 'victims', labelWidth: 100, color: t.series[1] }) : undefined,
  }), [p, l, t])

  const reviews = o?.reviews ?? []
  const lsq = { isLoading: ls.isLoading, isError: ls.isError && !(ls.error instanceof SyntaxError), error: ls.error, refetch: ls.refetch }
  const running = useQuery({ queryKey: ['pipelines'], queryFn: api.pipelines.list, refetchInterval: 5000 })

  return (
    <>
      <PageHeader kicker="Command" title="Command Center"
        subtitle={o ? `P4 ${o.scope.phishing.sector} · ${o.scope.phishing.brands.length} brands  ·  P6 ${o.scope.landscape.sector} in ${o.scope.landscape.region} · ${o.scope.landscape.months} months` : 'Both intelligence services at a glance'}
        actions={<><RunPipelineButton name="phishing" label="Run P4" variant="secondary" /><RunPipelineButton name="landscape" label="Run P6" variant="secondary" /></>} />

      <SectionLabel>P4 · Phishing campaigns · last 7 days</SectionLabel>
      <KpiRow>
        <KpiTile loading={!p} kpi={p ? { label: 'Phishing pages', value: p.kpis.samples.cur, prev: p.kpis.samples.prev, window: '7 days', spark: p.daily_total, sparkLabels: p.days, source: 'urlscan.io · OpenPhish · PhishTank · WhoisDS', to: '/phishing/samples' } : undefined} />
        <KpiTile loading={!p} kpi={p ? { label: 'New campaigns', value: p.kpis.campaigns_new.cur, prev: p.kpis.campaigns_new.prev, window: '7 days', spark: p.daily_new_campaigns, sparkLabels: p.days, source: 'clustering', note: `${o?.phishing.campaigns_active ?? '…'} active`, to: '/phishing/campaigns' } : undefined} />
        <KpiTile loading={!p} kpi={p ? { label: 'Kits attributed', value: p.kit_profiles.length, window: 'window', spark: p.daily_clustered, sparkLabels: p.days, source: 'kits.yaml', note: `${p.kit_profiles.filter((k) => k.source === 'signature').length} named · ${p.kit_profiles.filter((k) => k.source !== 'signature').length} inferred`, to: '/phishing/kits', upIsBad: null } : undefined} />
        <KpiTile loading={!p} kpi={p ? { label: 'Detections shipped', value: p.kpis.detections.cur, prev: p.kpis.detections.prev, window: '7 days', spark: p.daily_detections ?? [], sparkLabels: p.days, source: 'Sigma · YARA · IOC', note: `${fmtInt(o?.phishing.detections)} total`, to: '/phishing/detections', upIsBad: null } : undefined} />
      </KpiRow>
      <SectionLabel>P6 · {l ? `${l.sector} · ${l.region}` : 'Threat landscape'} · {cur ? fmtYm(cur.period) : 'last full month'}</SectionLabel>
      <KpiRow>
        <KpiTile loading={ls.isLoading} kpi={l && cur ? { label: 'Victims in scope', value: cur.secondary ?? 0, prev: prev?.secondary ?? null, window: fmtYm(cur.period), spark: full.map((x) => x.secondary ?? 0), sparkLabels: full.map((x) => x.period), source: 'ransomware.live', note: `${fmtInt(o?.landscape.victims_month_scope)} so far this month`, to: '/landscape/victims' } : undefined} />
        <KpiTile loading={ls.isLoading} kpi={l && cur ? { label: 'All leak-site victims', value: cur.value, prev: prev?.value ?? null, window: fmtYm(cur.period), spark: full.map((x) => x.value), sparkLabels: full.map((x) => x.period), source: 'ransomware.live', note: `${fmtInt(l.victims_sector)} in ${l.sector} worldwide`, to: '/landscape' } : undefined} />
        <KpiTile loading={ls.isLoading} kpi={l ? { label: 'Actors hitting scope', value: l.actors_active_scope, window: `${l.months.length} months`, source: 'ransomware.live groups', note: `${fmtInt(l.actors_active_window)} active overall`, to: '/landscape/actors', upIsBad: true } : undefined} />
        <KpiTile loading={ls.isLoading} kpi={l ? { label: 'Access-broker listings', value: l.iab.in_scope, window: `${l.months.length} months`, spark: l.iab.timeline.map((x) => x.value), sparkLabels: l.iab.timeline.map((x) => x.period), source: 'public reporting', note: l.iab.price_median ? `median $${fmtInt(l.iab.price_median)}` : `${fmtInt(l.iab.listings)} total`, to: '/landscape/iab' } : undefined} />
      </KpiRow>

      <Grid>
        <Span n={6}><Viz title="Where phishing is hosted" question="Which countries host this window's phishing pages?" source="urlscan.io page.country" query={qstate(pv)} height={300} option={charts.phishMap} needsWorld empty={!!p && !p.countries.length}
          table={p ? { columns: ['country', 'pages'], rows: p.countries.map((c) => [countryName(c.iso2), c.value]) } : undefined} /></Span>
        <Span n={6}><Viz title={l ? `Where ${l.sector.toLowerCase()} victims are` : 'Where in-scope victims are'} question={l ? `Which ${l.region} countries have ${l.sector} organisations on leak sites in the window?` : 'In-scope ransomware victims by country'} source="ransomware.live · RansomLook" query={lsq} height={300} option={charts.victimMap} needsWorld empty={!!l && !l.by_country_scope.length}
          table={l ? { columns: ['country', 'victims'], rows: l.by_country_scope.map((c) => [countryName(c.key), c.count]) } : undefined} /></Span>
      </Grid>
      <Grid>
        <Span n={4}><Viz title="Phishing pipeline funnel" question="How much collected phishing survives to an attributed campaign?" source="last P4 run" query={qstate(pv)} height={240} option={charts.funnel} /></Span>
        <Span n={4}><Viz title="Leak-site tempo" question="How many victims are posted each month, and how many are in scope?" source="ransomware.live" query={lsq} height={240} option={charts.victims} caveat="current month is partial"
          table={l ? { columns: ['month', 'all', 'in scope'], rows: l.timeline.map((x) => [x.period, x.value, x.secondary ?? 0]) } : undefined} /></Span>
        <Span n={4}><Viz title="Who is hitting scope" question={l ? `Which groups post the most ${l.sector} victims in ${l.region}?` : 'Top actors in scope'} source="ransomware.live" query={lsq} height={240} option={charts.actors}
          onEvents={{ click: (e: { name: string }) => nav(`/landscape/actors/${encodeURIComponent(e.name)}`) }} /></Span>
      </Grid>

      <div className={d.two}>
        <section className={d.panel} aria-label="Largest active campaigns">
          <div className={d.panelHead}><h2>Largest active phishing campaigns</h2><Link to="/phishing/campaigns?status=active" className="secondary">All campaigns →</Link></div>
          {camps.data && !camps.data.length && <EmptyState title="No active multi-page campaigns" />}
          {(camps.data ?? []).slice().sort((a, b) => b.sample_count - a.sample_count).slice(0, 7).map((c) => (
            <div key={c.id} className={d.row} onClick={() => nav(`/phishing/campaigns/${c.id}`)}>
              <Badge tone="accent">{c.brand ?? 'unbranded'}</Badge>
              <div className={d.rowMain}><b className="mono">{c.name}</b><span>{c.sample_count} pages · {c.domain_count} domains · {c.ip_count} IPs · {c.kit_name ?? 'no kit'}</span></div>
              <span className="muted num" style={{ fontSize: 12 }}>{fmtAgo(c.last_seen)}</span>
            </div>
          ))}
        </section>
        <section className={d.panel} aria-label="Actor movers">
          <div className={d.panelHead}><h2>Ransomware actor movers</h2><Link to="/landscape/actors" className="secondary">All actors →</Link></div>
          {l && !l.actor_trends.length && <EmptyState title="No actor trend data" />}
          {(l?.actor_trends ?? []).slice(0, 7).map((a) => (
            <div key={a.id} className={d.row} onClick={() => nav(`/landscape/actors/${encodeURIComponent(a.slug)}`)}>
              <Trend trend={a.trend} change={a.mom_change} />
              <div className={d.rowMain}><b>{a.name}</b><span>{a.victim_count_window} victims in window · {a.victim_count_scope} in scope · {a.top_sectors.slice(0, 2).map((s) => s.key).join(', ')}</span></div>
              <StatusBadge status={a.status} />
            </div>
          ))}
        </section>
      </div>

      <SectionLabel>Platform health</SectionLabel>
      <div className={d.health} style={{ marginBottom: 16 }}>
        {(running.data ?? []).map((pl) => (
          <div key={pl.name} className={d.hcard}>
            <h3><span className={d.dot} data-state={pl.running ? 'ok' : pl.last_run?.status === 'succeeded' ? 'ok' : pl.last_run ? 'down' : 'stale'} />{pl.name === 'phishing' ? 'P4 phishing pipeline' : 'P6 landscape pipeline'}</h3>
            <dl>
              <dt>Status</dt><dd>{pl.running ? 'running now' : pl.last_run?.status ?? 'never run'}</dd>
              <dt>Last run</dt><dd>{fmtAgo(pl.last_run?.finished_at)}</dd>
              <dt>Duration</dt><dd>{fmtDuration(pl.last_run?.duration_seconds)}</dd>
              <dt>Trigger</dt><dd>{pl.last_run?.trigger ?? '—'}</dd>
            </dl>
          </div>
        ))}
        {(o?.sources ?? []).map((s) => (
          <div key={`${s.module}:${s.name}`} className={d.hcard} title={s.detail ?? ''}>
            <h3><span className={d.dot} data-state={s.status === 'ok' ? 'ok' : s.status === 'degraded' ? 'stale' : 'down'} />{s.name.replace(/_/g, ' ')}</h3>
            <dl>
              <dt>Module</dt><dd>{s.module === 'phishing' ? 'P4 phishing' : 'P6 landscape'}</dd>
              <dt>Status</dt><dd>{s.status}</dd>
              <dt>Checked</dt><dd>{fmtAgo(s.checked_at)}</dd>
              <dt>Detail</dt><dd style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.detail ?? '—'}</dd>
            </dl>
          </div>
        ))}
      </div>

      <Grid>
        <Span n={12}>
          <ChartCard title="Hand-check precision" question="Of the outputs an analyst has checked, what share did the automation get right? (agree ÷ (agree + over-flagged))" source="analyst verdicts" query={qstate(ov)} height={150} png={false}
            empty={!reviews.length} emptyText="No hand checks recorded yet: open any campaign, kit, victim or actor and record a verdict"
            table={{ columns: ['entity', 'reviewed', 'agree', 'over-flagged', 'missed', 'unsure'], rows: reviews.map((r) => [ENTITY_LABEL[r.entity_type] ?? r.entity_type, r.reviewed, r.agree, r.over_flag, r.miss, r.unsure]) }}
            render={() => (
              <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.max(1, reviews.length)}, minmax(140px, 1fr))`, gap: 12 }}>
                {reviews.map((r) => (
                  <Link key={r.entity_type} to="/review" style={{ textDecoration: 'none', color: 'inherit' }}>
                    <EChart option={fitGauge(ratioGauge(r.precision_proxy, t, { label: `${ENTITY_LABEL[r.entity_type] ?? r.entity_type} · ${r.reviewed} checked` }))} height={150} renderer="svg" ariaLabel={`${r.entity_type} precision`} />
                  </Link>
                ))}
              </div>
            )} />
        </Span>
      </Grid>
    </>
  )
}
