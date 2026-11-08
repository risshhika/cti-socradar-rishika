import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Globe, Wrench } from 'lucide-react'
import { api } from '../../lib/api'
import { PageHeader, Card, DataTable, Badge, StatusBadge, VerdictBadge, Loading, ErrorState, Tabs } from '../../components/ui'
import { KpiTile } from '../../components/ui/KpiTile'
import { Grid, Span, SectionLabel } from '../../components/ui/Grid'
import { StatStrip } from '../../components/ui/controls'
import { Drawer } from '../../components/ui/Drawer'
import { ReviewPanel } from '../../components/ui/ReviewPanel'
import { calendarHeatmap, donut, horizontalBars, radar, timeSeries, worldChoropleth } from '../../charts/options'
import { countryName } from '../../charts/countries'
import { fmtDate, fmtInt } from '../../lib/format'
import { fmtYm } from '../../lib/viz'
import { landscapeViz, lastFullIdx } from '../../lib/landscapeViz'
import type { VictimOut } from '../../lib/types'
import { Country, SRC, SectionTitle, SizeBadge, TrendBadge, VictimBadges, VictimDetail, Viz, monthLabel, tuneMap, useTokens, useWindow } from './shared'

const TACTIC_ORDER = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Stealth', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact']

export default function ActorDetail() {
  const { slug = '' } = useParams()
  const t = useTokens()
  const [w] = useWindow()
  const [tab, setTab] = useState<'scope' | 'recent'>('scope')
  const [sel, setSel] = useState<VictimOut | null>(null)
  const q = useQuery({ queryKey: ['landscape', 'actor', slug], queryFn: () => api.landscape.actor(slug), retry: false })
  const vz = useQuery({ queryKey: ['landscape', 'actor-viz', slug, w], queryFn: () => landscapeViz.actor(slug, w), retry: false })
  const scope = useQuery({ queryKey: ['scope'], queryFn: api.scope.get })
  const v = vz.data
  const vq = { isLoading: vz.isLoading, isError: vz.isError, error: vz.error, isFetching: vz.isFetching, refetch: vz.refetch }

  const charts = useMemo(() => v && {
    monthly: timeSeries(v.months, [{ name: 'All victims', data: v.monthly.total, type: 'bar' }, { name: 'In scope', data: v.monthly.scope, type: 'bar', color: t.series[1] }], t, {}),
    radar: radar(v.radar.sectors.map((s) => ({ name: s.length > 16 ? `${s.slice(0, 15)}…` : s, max: Math.max(5, Math.ceil(Math.max(...v.radar.actor, ...v.radar.landscape) / 5) * 5) })),
      [{ name: 'This actor', values: v.radar.actor }, { name: 'Whole landscape', values: v.radar.landscape }], t),
    world: tuneMap(worldChoropleth(v.countries, t, { unit: 'victims' }), v.countries, [], false),
    calendar: calendarHeatmap(v.calendar, [`${v.months[0]}-01`, new Date().toISOString().slice(0, 10)], t, 'posts', 20),
    regions: horizontalBars(v.regions.slice(0, 8).map((r) => ({ label: r.key, value: r.count })), t, { unit: 'victims', labelWidth: 110 }),
    sizes: donut(v.sizes.map((s) => ({ name: s.key, value: s.count, color: s.key === 'unknown' ? t.other : undefined })), t, { centerLabel: 'victims', legend: 'bottom' }),
    sectors: horizontalBars(v.sectors.slice(0, 8).map((r) => ({ label: r.key, value: r.count })), t, { unit: 'victims', labelWidth: 130, color: t.series[2] }),
  }, [v, t])

  const back = <Link to="/landscape/actors" className="btn btn-ghost" style={{ textDecoration: 'none' }}><ArrowLeft size={14} /> All actors</Link>
  if (q.isLoading) return <><PageHeader kicker="P6 · Ransomware actor" title="Loading…" actions={back} /><Loading rows={8} /></>
  if (q.error || !q.data) return <><PageHeader kicker="P6 · Ransomware actor" title="Actor not found" actions={back} /><ErrorState error={q.error ?? 'Not found'} /></>
  const d = q.data, a = d.actor
  const locTitles = new Set(d.locations.map((l) => String(l.title ?? '').toLowerCase()))
  const aliases = a.aliases.filter((x) => x.toLowerCase() !== a.name.toLowerCase() && !locTitles.has(x.toLowerCase()))
  const toolGroups = d.tools.reduce<Record<string, string[]>>((acc, tool) => {
    const m = tool.match(/^(.*) \(([^()]+)\)$/)
    const [name, cat] = m ? [m[1], m[2]] : [tool, 'Other']
    ;(acc[cat] ??= []).push(name)
    return acc
  }, {})
  const ttps = [...(v?.ttps ?? [])].sort((x, y) => (TACTIC_ORDER.indexOf(x.tactic ?? '') + 99) % 99 - (TACTIC_ORDER.indexOf(y.tactic ?? '') + 99) % 99)
  const li = v ? lastFullIdx(v.months) : 0
  const victimCols = [
    { key: 'v', header: 'Victim', sort: (r: VictimOut) => r.victim.toLowerCase(), render: (r: VictimOut) => <div style={{ maxWidth: 280 }}><div style={{ color: 'var(--text)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.victim}</div>{r.domain && <div className="mono muted" style={{ fontSize: 11 }}>{r.domain}</div>}</div> },
    { key: 's', header: 'Sector', sort: (r: VictimOut) => r.sector ?? '', render: (r: VictimOut) => r.sector ?? <span className="muted">unknown</span> },
    { key: 'c', header: 'Country', sort: (r: VictimOut) => r.country ?? '', render: (r: VictimOut) => <Country cc={r.country} region={r.region} /> },
    { key: 'z', header: 'Size', render: (r: VictimOut) => <SizeBadge band={r.size_band} /> },
    { key: 'd', header: 'Posted', align: 'right' as const, sort: (r: VictimOut) => r.discovered ?? '', render: (r: VictimOut) => <span className="num">{fmtDate(r.discovered ?? r.attack_date)}</span> },
    { key: 'sc', header: 'Scope', render: (r: VictimOut) => <Badge tone={r.in_scope ? 'accent' : 'neutral'}>{r.in_scope ? 'in scope' : 'out'}</Badge> },
    { key: 'rv', header: 'Review', render: (r: VictimOut) => <VerdictBadge verdict={r.review_verdict} /> },
  ]

  return (
    <>
      <PageHeader kicker="P6 · Ransomware actor"
        title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>{a.name}<StatusBadge status={a.status} /><TrendBadge trend={a.trend} mom={a.mom_change} /></span>}
        subtitle={<>{aliases.length > 0 && <>aka {aliases.join(', ')} · </>}posting since {fmtDate(a.first_seen)} · last post {fmtDate(a.last_seen)}</>}
        actions={<>{back}{d.profile_url && <a className="btn btn-ghost" href={d.profile_url} target="_blank" rel="noreferrer noopener" style={{ textDecoration: 'none' }}><Globe size={14} /> ransomware.live</a>}</>} />

      <Grid>
        <Span n={3}><KpiTile loading={!v} kpi={v && { label: 'Victims posted', value: v.monthly.total[li], prev: v.monthly.total[li - 1], window: monthLabel(v.months[li]), spark: v.monthly.total, sparkLabels: v.months, source: SRC.rl, note: `${fmtInt(v.window_total)} in window` }} /></Span>
        <Span n={3}><KpiTile loading={!v} kpi={v && { label: 'In our scope', value: v.monthly.scope[li], prev: v.monthly.scope[li - 1], window: monthLabel(v.months[li]), spark: v.monthly.scope, sparkLabels: v.months, source: SRC.rl, note: `${a.victim_count_scope} in window${scope.data ? ` · ${scope.data.landscape.sector} · ${scope.data.landscape.region}` : ''}`, to: `/landscape/victims?group=${encodeURIComponent(a.name)}` }} /></Span>
        <Span n={6}>
          <StatStrip items={[
            { label: 'Countries hit', value: fmtInt(v?.countries.length ?? 0), sub: v?.countries.slice(0, 3).map((c) => countryName(c.iso2)).join(', ') },
            { label: 'Regions', value: fmtInt(v?.regions.filter((r) => r.key !== 'Unknown').length ?? 0), sub: v?.regions[0] ? `mostly ${v.regions[0].key}` : undefined },
            { label: 'All-time victims', value: fmtInt(a.victim_count_total), sub: `since ${fmtDate(a.first_seen)}` },
            { label: 'ATT&CK techniques', value: fmtInt(ttps.reduce((n, x) => n + x.count, 0)), sub: `${ttps.length} tactics` },
            { label: 'Tools reported', value: fmtInt(d.tools.length), sub: `${Object.keys(toolGroups).length} categories` },
            { label: 'Leak sites', value: fmtInt(d.locations.length), sub: `${d.locations.filter((l) => l.available).length} reachable at last check` },
          ]} />
        </Span>
      </Grid>

      <Grid>
        <Span n={8}><Viz title="Monthly activity" question="Is this group speeding up, and how much of it lands on us?" source={SRC.rl} query={vq} height={260} option={charts?.monthly ?? null}
          table={v && { columns: ['month', 'all', 'in scope'], rows: v.months.map((m, i) => [fmtYm(m), v.monthly.total[i], v.monthly.scope[i]]) }} caveat={`${monthLabel(v?.months[v.months.length - 1])} is partial`} /></Span>
        <Span n={4}><Viz title="Sector focus" question="Does it over-index on any sector compared with the whole landscape?" source={SRC.rl} query={vq} height={260} option={charts?.radar ?? null}
          table={v && { columns: ['sector', 'actor %', 'landscape %'], rows: v.radar.sectors.map((s, i) => [s, v.radar.actor[i], v.radar.landscape[i]]) }} caveat="% of victims in window" /></Span>
        <Span n={8}><Viz title="Where it hits" question="Which countries does it post victims from?" source={SRC.rl} query={vq} height={320} option={charts?.world ?? null} needsWorld empty={!v?.countries.length}
          table={v && { columns: ['country', 'victims'], rows: v.countries.map((c) => [countryName(c.iso2), c.value]) }} /></Span>
        <Span n={4}><Viz title="Regions" question="How is that spread across regions?" source={SRC.rl} query={vq} height={320} option={charts?.regions ?? null} empty={!v?.regions.length} /></Span>
        <Span n={6}><Viz title="Posting days" question="Does it post steadily or in dumps?" source={SRC.rl} query={vq} height={230} option={charts?.calendar ?? null} empty={!v?.calendar.length}
          table={v && { columns: ['day', 'posts'], rows: v.calendar }} /></Span>
        <Span n={3}><Viz title="Sectors" question="Which sectors, by count?" source={SRC.rl} query={vq} height={230} option={charts?.sectors ?? null} empty={!v?.sectors.length} /></Span>
        <Span n={3}><Viz title="Victim size" question="Big game or long tail?" source={SRC.rl} query={vq} height={230} option={charts?.sizes ?? null} empty={!v?.sizes.length} caveat="size from leak post" /></Span>
      </Grid>

      <SectionLabel>How it operates</SectionLabel>
      <Card title="ATT&CK techniques" subtitle={ttps.length ? `${ttps.reduce((n, x) => n + x.count, 0)} techniques across ${ttps.length} tactics, as published on the group profile` : 'No ATT&CK mapping published for this actor'}>
        {ttps.length ? (
          <div style={{ display: 'grid', gridAutoFlow: 'column', gridAutoColumns: 'minmax(150px, 1fr)', gap: 8, overflowX: 'auto', paddingBottom: 6, width: 0, minWidth: '100%' }}>
            {ttps.map((tac) => (
              <div key={tac.tactic_id ?? tac.tactic} style={{ minWidth: 0 }}>
                <div style={{ padding: '8px 10px', borderRadius: 8, background: 'var(--accent-soft)', marginBottom: 6 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>{tac.tactic}</div>
                  <div className="muted" style={{ fontSize: 11 }}><span className="mono">{tac.tactic_id}</span> · {tac.count} technique{tac.count === 1 ? '' : 's'}</div>
                </div>
                <div style={{ display: 'grid', gap: 4 }}>
                  {tac.techniques.map((x, i) => (
                    <div key={`${x.id}-${i}`} title={x.details ?? undefined} style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: `color-mix(in srgb, var(--seq-4) ${Math.min(40, 10 + tac.count * 3)}%, var(--surface-1))`, fontSize: 11.5, lineHeight: 1.35 }}>
                      <div className="mono" style={{ color: 'var(--text)', fontSize: 10.5 }}>{x.id}</div>
                      <div style={{ color: 'var(--text-2)' }}>{x.name}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : <div className="muted" style={{ padding: '18px 0', textAlign: 'center' }}>Nothing mapped.</div>}
      </Card>

      <Grid style={{ marginTop: 16 }}>
        <Span n={4}>
          <Card title="Profile" subtitle="From the ransomware.live group page">
            <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-2)', whiteSpace: 'pre-wrap', maxHeight: 260, overflow: 'auto' }}>{d.description || 'No public description.'}</p>
          </Card>
        </Span>
        <Span n={4}>
          <Card title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><Wrench size={14} /> Tooling</span>} subtitle={`${d.tools.length} tools reported`}>
            {Object.keys(toolGroups).length ? <div style={{ display: 'grid', gap: 10 }}>{Object.entries(toolGroups).map(([cat, items]) => (
              <div key={cat}><SectionTitle>{cat.replace(/([a-z])([A-Z])/g, '$1 $2')}</SectionTitle><div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{items.map((x) => <Badge key={x}>{x}</Badge>)}</div></div>
            ))}</div> : <div className="muted">None recorded.</div>}
          </Card>
        </Span>
        <Span n={4}>
          <Card title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><Globe size={14} /> Leak-site infrastructure</span>} subtitle="Data-leak, negotiation and admin sites (listed, never visited)">
            {d.locations.length ? <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 6 }}>{d.locations.slice(0, 10).map((l, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                <Badge tone={l.available ? 'ok' : 'neutral'}>{l.available ? 'up' : 'down'}</Badge>{l.type && <Badge>{String(l.type)}</Badge>}
                <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-2)', minWidth: 0, flex: 1 }} title={String(l.fqdn ?? l.slug)}>{String(l.fqdn ?? l.slug ?? '')}</span>
              </div>
            ))}{d.locations.length > 10 && <div className="muted" style={{ fontSize: 11 }}>+{d.locations.length - 10} more</div>}</div> : <div className="muted">None recorded.</div>}
          </Card>
        </Span>
      </Grid>

      <Card padded={false}>
        <div style={{ padding: '6px 16px 0' }}><Tabs value={tab} onChange={setTab} tabs={[{ value: 'scope', label: 'In-scope victims', count: d.scope_victims.length }, { value: 'recent', label: 'Recent victims', count: d.recent_victims.length }]} /></div>
        <div style={{ padding: '0 16px 16px' }}>
          <DataTable<VictimOut> rows={tab === 'scope' ? d.scope_victims : d.recent_victims} rowKey={(r) => r.id} dense maxHeight="60vh" onRowClick={setSel} columns={victimCols}
            empty={<div className="muted" style={{ padding: 24, textAlign: 'center' }}>{tab === 'scope' ? 'No victims in scope for this actor.' : 'No recent victims.'}</div>} />
        </div>
      </Card>
      <div style={{ marginTop: 16 }}><Card title="Analyst review" subtitle="Is this actor's in-scope activity, sector mix and trend attributed correctly?"><ReviewPanel entityType="actor" entityId={a.id} /></Card></div>
      <Drawer open={!!sel} onClose={() => setSel(null)} kind="Victim" title={sel?.victim} subtitle={sel ? <>{sel.group} · posted {fmtDate(sel.discovered ?? sel.attack_date)}</> : undefined} badges={sel ? <VictimBadges v={sel} /> : undefined}>{sel && <VictimDetail v={sel} />}</Drawer>
    </>
  )
}
