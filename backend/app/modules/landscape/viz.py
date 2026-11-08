"""Chart-ready aggregations for the P6 dashboards (one call per page, plain JSON).

Everything is computed from columns already in the DB in a single pass per table, so a call stays well under
400 ms on the ~6k-victim window. Shapes are documented in frontend/src/lib/landscapeViz.ts.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from sqlmodel import Session, select

from ...models import CyberIncident, IABListing, RansomVictim, ThreatActor
from .classify import SECTORS, sector_matches
from .collectors import months_back
from .regions import countries_in

SIZE_ORDER = ["enterprise", "large", "mid", "small", "unknown"]
REGION_ORDER = ["North America", "Europe", "LATAM", "MENA", "East Asia", "Southeast Asia", "South Asia", "Oceania",
                "Sub-Saharan Africa", "CIS", "Unknown"]


def _day(v: Any) -> str | None:
    return v.strftime("%Y-%m-%d") if v else None


def _cells(xs: list[str], ys: list[str], counts: dict[tuple[str, str], int]) -> list[list[int]]:
    xi = {x: i for i, x in enumerate(xs)}
    yi = {y: i for i, y in enumerate(ys)}
    return [[xi[x], yi[y], n] for (x, y), n in counts.items() if x in xi and y in yi and n]


def _series(counter: Counter, months: list[str]) -> list[int]:
    return [counter.get(m, 0) for m in months]


def landscape_viz(session: Session, sector: str, region: str, n_months: int) -> dict[str, Any]:
    months = months_back(n_months)
    start = months[0]
    allowed = countries_in(region)
    cols = (RansomVictim.id, RansomVictim.group, RansomVictim.month, RansomVictim.discovered, RansomVictim.attack_date,
            RansomVictim.country, RansomVictim.region, RansomVictim.sector, RansomVictim.size_band,
            RansomVictim.cross_source_match, RansomVictim.source)
    rows = session.exec(select(*cols).where(RansomVictim.month >= start)).all()

    def in_region(cc: str | None) -> bool:
        return allowed is None or (cc or "").upper() in allowed

    total_m, scope_m, sector_m, region_m = Counter(), Counter(), Counter(), Counter()
    scope_actors_m: dict[str, set[str]] = defaultdict(set)
    scope_days, region_days, sector_days = Counter(), Counter(), Counter()
    country_sector, country_all, country_region = Counter(), Counter(), Counter()
    sector_month_region: dict[tuple[str, str], int] = Counter()
    sector_region: dict[tuple[str, str], int] = Counter()
    actor_month_all: dict[tuple[str, str], int] = Counter()
    actor_month_scope: dict[tuple[str, str], int] = Counter()
    actor_window, actor_scope, actor_region = Counter(), Counter(), Counter()
    actor_countries: dict[str, set[str]] = defaultdict(set)
    actor_sectors: dict[str, Counter] = defaultdict(Counter)
    flows_as: dict[tuple[str, str], int] = Counter()
    flows_sr: dict[tuple[str, str], int] = Counter()
    region_country_scope: dict[str, Counter] = defaultdict(Counter)
    sector_size_region: dict[str, Counter] = defaultdict(Counter)
    cross_m, cross_n_m = Counter(), Counter()
    cross_actor, cross_actor_n = Counter(), Counter()
    sector_tot = Counter()

    for (_id, group, month, discovered, attack, cc, reg, sec, size, cross, source) in rows:
        cc = (cc or "").upper() or None
        sec = sec or "Other"
        reg = reg or "Unknown"
        size = size or "unknown"
        day = _day(discovered or attack)
        is_sector = sector_matches(sec, sector)
        is_region = in_region(cc)
        total_m[month] += 1
        sector_tot[sec] += 1
        actor_window[group] += 1
        actor_month_all[(month, group)] += 1
        if cc:
            actor_countries[group].add(cc)
            country_all[cc] += 1
        actor_sectors[group][sec] += 1
        sector_region[(reg, sec)] += 1
        flows_as[(group, sec)] += 1
        flows_sr[(sec, reg)] += 1
        if source == "ransomware_live":
            cross_n_m[month] += 1
            cross_actor_n[group] += 1
            if cross:
                cross_m[month] += 1
                cross_actor[group] += 1
        if is_sector:
            sector_m[month] += 1
            if day:
                sector_days[day] += 1
            if cc:
                country_sector[cc] += 1
            region_country_scope[reg][cc or "??"] += 1
        if is_region:
            region_m[month] += 1
            actor_region[group] += 1
            if day:
                region_days[day] += 1
            if cc:
                country_region[cc] += 1
            sector_month_region[(month, sec)] += 1
            sector_size_region[sec][size] += 1
        if is_sector and is_region:
            scope_m[month] += 1
            scope_actors_m[month].add(group)
            actor_scope[group] += 1
            actor_month_scope[(month, group)] += 1
            if day:
                scope_days[day] += 1

    # ---- sector composition within region (top 8 + Other bucket)
    reg_sec_tot = Counter()
    for (m, s), n in sector_month_region.items():
        reg_sec_tot[s] += n
    top_secs = [s for s, _ in reg_sec_tot.most_common() if s != "Other"][:8]
    sector_series: dict[str, list[int]] = {s: [sector_month_region.get((m, s), 0) for m in months] for s in top_secs}
    other = [sum(n for (mm, s), n in sector_month_region.items() if mm == m and s not in top_secs) for m in months]
    if any(other):
        sector_series["Other"] = other

    # ---- actor × month (region, all sectors) and in scope
    top_region_actors = [a for a, _ in actor_region.most_common(15)]
    top_scope_actors = [a for a, _ in actor_scope.most_common(15)]

    # ---- bump: monthly rank among all actors (global window), for the 8 biggest
    top_global = [a for a, _ in actor_window.most_common(8)]
    ranks: dict[str, list[int | None]] = {a: [] for a in top_global}
    for m in months:
        ordered = sorted(((n, a) for (mm, a), n in actor_month_all.items() if mm == m), key=lambda t: (-t[0], t[1]))
        pos = {a: i + 1 for i, (_, a) in enumerate(ordered)}
        for a in top_global:
            ranks[a].append(pos.get(a))
    max_rank = max([r for v in ranks.values() for r in v if r] or [1])

    # ---- sankey: top 10 actors -> sector -> region (sectors beyond top 7 folded)
    sank_actors = [a for a, _ in actor_window.most_common(10)]
    sank_secs = [s for s, _ in sector_tot.most_common(8)]
    links_as: Counter = Counter()
    links_sr: Counter = Counter()
    for (a, s), n in flows_as.items():
        if a in sank_actors:
            links_as[(a, s if s in sank_secs else "Other")] += n
    used_secs = {s for (_, s) in links_as}
    for (s, r), n in flows_sr.items():
        s2 = s if s in sank_secs else "Other"
        if s2 in used_secs:
            links_sr[(s2, r)] += n
    # keep only the sector->region volume that came from the shown actors (proportional scaling keeps widths honest)
    sec_from_actors = Counter()
    for (a, s), n in links_as.items():
        sec_from_actors[s] += n
    sec_total = Counter()
    for (s, r), n in links_sr.items():
        sec_total[s] += n
    sankey_nodes: list[dict[str, Any]] = []
    sankey_links: list[dict[str, Any]] = []
    for a in sank_actors:
        sankey_nodes.append({"name": a, "depth": 0})
    for s in sorted(used_secs, key=lambda x: -sec_from_actors[x]):
        sankey_nodes.append({"name": f"{s} ", "depth": 1})  # trailing space keeps sector names distinct from actors
    regions_used: set[str] = set()
    for (a, s), n in links_as.items():
        sankey_links.append({"source": a, "target": f"{s} ", "value": n})
    for (s, r), n in links_sr.items():
        scaled = round(n * sec_from_actors[s] / sec_total[s]) if sec_total[s] else 0
        if scaled:
            sankey_links.append({"source": f"{s} ", "target": f"  {r}", "value": scaled})
            regions_used.add(r)
    for r in [x for x in REGION_ORDER if x in regions_used] + sorted(regions_used - set(REGION_ORDER)):
        sankey_nodes.append({"name": f"  {r}", "depth": 2})

    # ---- sector × region matrix
    regions_present = [r for r in REGION_ORDER if any(sector_region.get((r, s)) for s in SECTORS)]
    sectors_present = [s for s, _ in sector_tot.most_common()]

    # ---- sunburst region › country (scope sector, global)
    sunburst = []
    for reg_name, cnt in sorted(region_country_scope.items(), key=lambda kv: -sum(kv[1].values())):
        children = [{"name": cc, "value": n} for cc, n in cnt.most_common(12)]
        rest = sum(n for _, n in cnt.most_common()[12:])
        if rest:
            children.append({"name": "Other", "value": rest})
        sunburst.append({"name": reg_name, "children": children})

    # ---- treemap sector › size (region, known sizes only)
    tree = []
    size_known = size_all = 0
    for sec_name, cnt in sorted(sector_size_region.items(), key=lambda kv: -sum(kv[1].values())):
        size_all += sum(cnt.values())
        kids = [{"name": b, "value": cnt[b]} for b in SIZE_ORDER if b != "unknown" and cnt.get(b)]
        size_known += sum(k["value"] for k in kids)
        if kids:
            tree.append({"name": sec_name, "children": kids})
    size_sector_cells = {(s, b): cnt.get(b, 0) for s, cnt in sector_size_region.items() for b in SIZE_ORDER}

    # ---- cross-source
    cross_by_month = [{"period": m, "n": cross_n_m.get(m, 0), "matched": cross_m.get(m, 0),
                       "rate": round(cross_m[m] / cross_n_m[m], 4) if cross_n_m.get(m) else None} for m in months]
    cross_by_actor = [{"actor": a, "n": cross_actor_n[a], "matched": cross_actor[a],
                       "rate": round(cross_actor[a] / cross_actor_n[a], 4)} for a, _ in cross_actor_n.most_common(12)]

    # ---- IAB
    iab_rows = session.exec(select(IABListing).where(IABListing.relevance >= 0.2)).all()
    iab_rows = [r for r in iab_rows if not r.month or r.month >= start]
    price_by_access: dict[str, list[float]] = defaultdict(list)
    bubbles: list[dict[str, Any]] = []
    access_month: Counter = Counter()
    iab_m = Counter()
    for r in iab_rows:
        if r.month:
            iab_m[r.month] += 1
        types = r.access_types or ["Unspecified"]
        for t in types:
            if r.month:
                access_month[(r.month, t)] += 1
        prices = [p for p in (r.price_usd_min, r.price_usd_max) if p]
        for p in dict.fromkeys(prices):
            price_by_access[types[0]].append(p)
        if r.revenue_usd and prices:
            bubbles.append({"id": r.id, "title": r.title, "revenue": r.revenue_usd, "price": max(prices),
                            "access_type": types[0], "region": r.region, "month": r.month})
    access_types = [t for t, _ in Counter(t for (m, t) in access_month.elements()).most_common(12)]
    all_prices = [p for v in price_by_access.values() for p in v]

    # ---- incidents
    inc_m = Counter()
    for month in session.exec(select(CyberIncident.month).where(CyberIncident.in_scope == True)).all():  # noqa: E712
        inc_m[month] += 1
    inc_all_m = Counter(session.exec(select(CyberIncident.month)).all())

    # ---- actor summary (bubbles + cards)
    slugs = {a.name.lower(): (a.slug, a.status) for a in session.exec(select(ThreatActor))}
    actor_summary = []
    for a, n in actor_window.most_common(80):
        slug, status = slugs.get(a.lower(), (None, "unknown"))
        actor_summary.append({"name": a, "slug": slug, "status": status, "window": n, "scope": actor_scope.get(a, 0),
                              "region": actor_region.get(a, 0), "countries": len(actor_countries.get(a, ())),
                              "top_sector": actor_sectors[a].most_common(1)[0][0] if actor_sectors.get(a) else None,
                              "monthly": [actor_month_all.get((m, a), 0) for m in months]})

    return {
        "sector": sector, "region": region, "months": months, "partial_month": months[-1],
        "series": {
            "total": _series(total_m, months), "scope": _series(scope_m, months), "sector": _series(sector_m, months),
            "region": _series(region_m, months), "scope_actors": [len(scope_actors_m.get(m, ())) for m in months],
            "cross_rate": [c["rate"] for c in cross_by_month], "iab": _series(iab_m, months),
            "incidents_scope": _series(inc_m, months), "incidents": _series(inc_all_m, months),
        },
        "calendar": {
            "scope": sorted([d, n] for d, n in scope_days.items()),
            "region": sorted([d, n] for d, n in region_days.items()),
            "sector": sorted([d, n] for d, n in sector_days.items()),
        },
        "world": {
            "sector": [{"iso2": c, "value": n} for c, n in country_sector.items()],
            "all": [{"iso2": c, "value": n} for c, n in country_all.items()],
            "region_all": [{"iso2": c, "value": n} for c, n in country_region.items()],
            "region_countries": sorted(allowed) if allowed else [],
        },
        "sector_month": {"months": months, "series": sector_series},
        "actor_month": {
            "region": {"actors": top_region_actors, "cells": _cells(months, top_region_actors, actor_month_all)},
            "scope": {"actors": top_scope_actors, "cells": _cells(months, top_scope_actors, actor_month_scope)},
        },
        "bump": {"actors": top_global, "ranks": ranks, "max_rank": max_rank},
        "sankey": {"nodes": sankey_nodes, "links": sankey_links},
        "sector_region": {"regions": regions_present, "sectors": sectors_present,
                          "cells": _cells(regions_present, sectors_present, sector_region)},
        "sunburst": sunburst,
        "size_tree": tree, "size_coverage": round(size_known / size_all, 4) if size_all else None,
        "size_sector": {"sizes": SIZE_ORDER, "sectors": [s for s, _ in sorted(sector_size_region.items(), key=lambda kv: -sum(kv[1].values()))],
                        "cells": _cells(SIZE_ORDER, [s for s in sector_size_region], {(b, s): n for (s, b), n in size_sector_cells.items()})},
        "cross_source": {"by_month": cross_by_month, "by_actor": cross_by_actor},
        "iab": {
            "price_by_access": {k: sorted(v) for k, v in sorted(price_by_access.items(), key=lambda kv: -len(kv[1]))},
            "bubbles": bubbles,
            "access_month": {"months": months, "types": access_types, "cells": _cells(months, access_types, access_month)},
            "price_median": round(statistics.median(all_prices), 2) if all_prices else None,
            "with_price": sum(1 for r in iab_rows if r.price_usd_min),
            "listings": len(iab_rows),
        },
        "actors": actor_summary,
    }


def actor_viz(session: Session, actor: ThreatActor, n_months: int) -> dict[str, Any]:
    months = months_back(n_months)
    start = months[0]
    mine = session.exec(select(RansomVictim.month, RansomVictim.discovered, RansomVictim.attack_date, RansomVictim.country,
                               RansomVictim.region, RansomVictim.sector, RansomVictim.size_band, RansomVictim.in_scope)
                        .where(RansomVictim.group == actor.name)).all()
    overall = Counter(s or "Other" for s in session.exec(select(RansomVictim.sector).where(RansomVictim.month >= start)).all())
    days, countries, sectors, regions, sizes, month_all, month_scope = Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    for (month, disc, att, cc, reg, sec, size, scope) in mine:
        if not month or month < start:
            continue
        d = _day(disc or att)
        if d:
            days[d] += 1
        if cc:
            countries[cc.upper()] += 1
        sectors[sec or "Other"] += 1
        regions[reg or "Unknown"] += 1
        sizes[size or "unknown"] += 1
        month_all[month] += 1
        if scope:
            month_scope[month] += 1
    total_mine = sum(sectors.values()) or 1
    total_all = sum(overall.values()) or 1
    ordered = [s for s, _ in sectors.most_common()] + [s for s, _ in overall.most_common() if s not in sectors]
    radar_secs = ordered[:8]
    ttp_rows = []
    for t in actor.ttps or []:
        techs = t.get("techniques") or []
        ttp_rows.append({"tactic_id": t.get("tactic_id"), "tactic": t.get("tactic_name"), "count": len(techs),
                         "techniques": [{"id": x.get("technique_id"), "name": x.get("technique_name"),
                                         "details": x.get("technique_details")} for x in techs]})
    return {
        "months": months,
        "monthly": {"total": _series(month_all, months), "scope": _series(month_scope, months)},
        "calendar": sorted([d, n] for d, n in days.items()),
        "countries": [{"iso2": c, "value": n} for c, n in countries.most_common()],
        "sectors": [{"key": s, "count": n} for s, n in sectors.most_common()],
        "regions": [{"key": r, "count": n} for r, n in regions.most_common()],
        "sizes": [{"key": b, "count": sizes.get(b, 0)} for b in SIZE_ORDER if sizes.get(b)],
        "radar": {"sectors": radar_secs,
                  "actor": [round(100 * sectors.get(s, 0) / total_mine, 1) for s in radar_secs],
                  "landscape": [round(100 * overall.get(s, 0) / total_all, 1) for s in radar_secs]},
        "ttps": ttp_rows,
        "window_total": sum(month_all.values()),
    }
