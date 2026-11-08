"""Aggregations shared by the API and the briefing generator."""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone

from sqlmodel import Session, select

from ...api.common import key_counts, last_run
from ...models import CyberIncident, IABListing, RansomVictim, ThreatActor
from ...schemas import ActorOut, IABStats, KeyCount, LandscapeStats, TimePoint
from .classify import sector_matches
from .collectors import months_back
from .regions import countries_in


def victim_in(v: RansomVictim, sector: str, allowed: set[str] | None) -> bool:
    return sector_matches(v.sector, sector) and (allowed is None or (v.country or "").upper() in allowed)


def actor_out(a: ThreatActor, months: list[str] | None = None) -> ActorOut:
    trend, mom = actor_trend(a.monthly_counts or {}, months)
    return ActorOut(id=a.id, slug=a.slug, name=a.name, aliases=a.aliases or [], status=a.status, first_seen=a.first_seen,
                    last_seen=a.last_seen, victim_count_total=a.victim_count_total, victim_count_scope=a.victim_count_scope,
                    victim_count_window=a.victim_count_window, monthly_counts=a.monthly_counts or {},
                    monthly_counts_scope=a.monthly_counts_scope or {}, top_sectors=a.top_sectors or [],
                    top_countries=a.top_countries or [], trend=trend, mom_change=mom)


def trend_between(prev: int, last: int) -> str:
    if prev == 0 and last == 0:
        return "flat"
    if prev == 0:
        return "new"
    ch = (last - prev) / prev
    return "rising" if ch >= 0.25 else "falling" if ch <= -0.25 else "flat"


def actor_trend(monthly: dict[str, int], months: list[str] | None = None) -> tuple[str, float | None]:
    """Compare the last two *complete* months. rising/falling at ±25%, new if nothing before."""
    months = months or months_back(3)
    if len(months) < 3:
        return "flat", None
    prev, last = monthly.get(months[-3], 0), monthly.get(months[-2], 0)
    if prev == 0 and last == 0:
        return "flat", None
    if prev == 0:
        return "new", None
    change = (last - prev) / prev
    if change >= 0.25:
        return "rising", round(change, 3)
    if change <= -0.25:
        return "falling", round(change, 3)
    return "flat", round(change, 3)


def iab_stats(session: Session, sector: str, region: str, months: list[str]) -> IABStats:
    rows = session.exec(select(IABListing).where(IABListing.relevance >= 0.2)).all()
    rows = [r for r in rows if not r.month or r.month >= months[0]]
    prices = [r.price_usd_min for r in rows if r.price_usd_min] + [r.price_usd_max for r in rows if r.price_usd_max and r.price_usd_max != r.price_usd_min]
    tl = Counter(r.month for r in rows if r.month)
    points = []
    for r in rows:
        if r.price_usd_min and r.month:
            points.append({"month": r.month, "price": r.price_usd_min, "access_type": (r.access_types or ["unknown"])[0],
                           "title": r.title, "id": r.id})
            if r.price_usd_max and r.price_usd_max != r.price_usd_min:
                points.append({"month": r.month, "price": r.price_usd_max, "access_type": (r.access_types or ["unknown"])[0],
                               "title": r.title, "id": r.id})
    return IABStats(
        listings=len(rows), in_scope=sum(1 for r in rows if r.in_scope), with_price=sum(1 for r in rows if r.price_usd_min),
        price_median=round(statistics.median(prices), 2) if prices else None,
        price_min=min(prices) if prices else None, price_max=max(prices) if prices else None,
        access_types=key_counts([a for r in rows for a in (r.access_types or [])], top=12),
        regions=key_counts([r.region for r in rows], top=10),
        sectors=key_counts([s for r in rows for s in (r.sectors or [])], top=10),
        sources=key_counts([r.source for r in rows], top=10),
        timeline=[TimePoint(period=m, value=tl.get(m, 0)) for m in months],
        price_points=sorted(points, key=lambda p: p["month"]),
    )


def compute_stats(session: Session, sector: str, region: str, n_months: int) -> LandscapeStats:
    months = months_back(n_months)
    window_start = months[0]
    allowed = countries_in(region)
    victims = session.exec(select(RansomVictim).where(RansomVictim.month >= window_start)).all()
    scope = [v for v in victims if victim_in(v, sector, allowed)]
    sector_only = [v for v in victims if sector_matches(v.sector, sector)]
    region_only = [v for v in victims if allowed is None or (v.country or "").upper() in allowed]

    tl_total = Counter(v.month for v in victims)
    tl_scope = Counter(v.month for v in scope)
    timeline = [TimePoint(period=m, value=tl_total.get(m, 0), secondary=tl_scope.get(m, 0)) for m in months]

    # sector share by month (top 6 + Other), computed within region
    sec_counter = Counter(v.sector or "Unknown" for v in region_only)
    top_secs = [s for s, _ in sec_counter.most_common(6)]
    by_month: dict[str, Counter] = defaultdict(Counter)
    for v in region_only:
        if v.month:
            by_month[v.month][v.sector if v.sector in top_secs else "Other"] += 1
    share = [{"period": m, **{s: by_month[m].get(s, 0) for s in top_secs + ["Other"]}} for m in months]

    actors = session.exec(select(ThreatActor)).all()
    scope_actor_counts = Counter(v.group for v in scope)
    window_actor_counts = Counter(v.group for v in region_only)
    movers = sorted((actor_out(a, months) for a in actors if a.victim_count_window > 0),
                    key=lambda a: (-(a.monthly_counts.get(months[-2], 0) + a.monthly_counts.get(months[-1], 0)), a.name))[:12]

    cross = [v for v in victims if v.source == "ransomware_live"]
    cross_rate = round(sum(1 for v in cross if v.cross_source_match) / len(cross), 4) if cross else None
    if len(months) >= 3:
        prev, last = tl_scope.get(months[-3], 0), tl_scope.get(months[-2], 0)
        mom = round((last - prev) / prev, 3) if prev else None
    else:
        mom = None
    incidents_scope = session.exec(select(CyberIncident).where(CyberIncident.in_scope == True)).all()  # noqa: E712

    return LandscapeStats(
        sector=sector, region=region, months=months, victims_total=len(victims), victims_scope=len(scope),
        victims_sector=len(sector_only), victims_region=len(region_only),
        actors_active_window=len([a for a in actors if a.victim_count_window > 0]),
        actors_active_scope=len(scope_actor_counts), cross_source_rate=cross_rate, timeline=timeline,
        by_sector=key_counts([v.sector for v in region_only], top=13),
        by_region=key_counts([v.region for v in victims], top=10),
        by_country_scope=key_counts([v.country for v in scope], top=12),
        by_size_scope=key_counts([v.size_band for v in scope], top=5),
        top_actors_window=[KeyCount(key=k, count=n, share=round(n / max(len(region_only), 1), 4)) for k, n in window_actor_counts.most_common(10)],
        top_actors_scope=[KeyCount(key=k, count=n, share=round(n / max(len(scope), 1), 4)) for k, n in scope_actor_counts.most_common(10)],
        sector_share_by_month=share, actor_trends=movers, iab=iab_stats(session, sector, region, months),
        incidents_scope=len([i for i in incidents_scope if not i.month or i.month >= window_start]),
        mom_scope_change=mom, last_run=last_run(session, "landscape"),
    )


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
