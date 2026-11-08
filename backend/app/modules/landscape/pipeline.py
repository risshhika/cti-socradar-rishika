"""P6 pipeline: leak-site victims -> classification -> cross-source check -> actors -> IAB reporting -> incidents
-> trends -> monthly briefing. Runs from a clean start; every stage is idempotent (upserts)."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, select

from ...models import CyberIncident, IABListing, RansomVictim, ThreatActor
from ...pipelines.runner import RunContext
from ..common import llm
from ..common.http import CachedClient
from . import briefing, collectors as col, iab as iabmod
from .classify import (llm_classify, normalize_name, normalize_sector, sector_from_keywords, sector_matches,
                       size_band)
from .regions import countries_in, region_for_country

BATCH = 500


def slugify(name: str) -> str:
    """Same rule as the frontend: lowercase, runs of non-alphanumerics -> '-'."""
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    if not slug:  # non-latin names: stable hash so the slug is still unique and URL-safe
        import hashlib
        slug = "actor-" + hashlib.sha1((name or "").encode()).hexdigest()[:8]
    return slug


def _norm_group(g: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (g or "").lower())


def _group_match(a: str, b: str) -> bool:
    a, b = _norm_group(a), _norm_group(b)
    return bool(a and b) and (a == b or a.startswith(b) or b.startswith(a))


# --------------------------------------------------------------------------- stage 1+2: victims

def ingest_victims(ctx: RunContext, session: Session, client: CachedClient, months: list[str], scope_sector: str,
                   allowed: set[str] | None, status: col.SourceStatus) -> dict[str, Any]:
    existing: dict[str, int] = {sid: vid for sid, vid in session.exec(select(RansomVictim.source_id, RansomVictim.id))}
    current = months[-1]
    seen, new, updated, failed_months = 0, 0, 0, []
    llm_queue: list[RansomVictim] = []
    for ym in months:
        rows = col.fetch_victims_month(client, ym, fresh=(ym == current))
        if rows is None:
            failed_months.append(ym)
            ctx.log(f"ransomware.live {ym}: fetch failed")
            continue
        ctx.log(f"ransomware.live {ym}: {len(rows)} victims")
        pending = 0
        for r in rows:
            seen += 1
            sid = col.victim_source_id(r)
            attack, disc = col.parse_dt(r.get("attackdate")), col.parse_dt(r.get("discovered"))
            country = (r.get("country") or "").strip().upper() or None
            if country and len(country) != 2:
                country = None
            text = " ".join(str(x) for x in [r.get("victim"), r.get("domain"), r.get("description")] if x)
            if r.get("activity"):
                sector, method = normalize_sector(r["activity"]), "source"
            else:
                sector = sector_from_keywords(text)
                method = "keyword" if sector else "unknown"
            band, basis = size_band(r.get("description"), r.get("victim") or "", sector)
            data = dict(
                source="ransomware_live", source_id=sid, victim=(r.get("victim") or "").strip()[:300] or "(unnamed)",
                domain=(r.get("domain") or "").strip().lower()[:200] or None, group=(r.get("group") or "unknown").strip(),
                attack_date=attack, discovered=disc, month=col.month_key(attack or disc), country=country,
                region=region_for_country(country), sector_raw=r.get("activity"), sector=sector, sector_method=method,
                size_band=band, size_basis=basis, description=(r.get("description") or None),
                data_size=(str(r.get("data_size")) if r.get("data_size") else None),
                ransom_demand=(str(r.get("ransom")) if r.get("ransom") else None),
                press=(r.get("press") if isinstance(r.get("press"), list) else ([r["press"]] if r.get("press") else [])),
                url=r.get("url") or None,
            )
            data["in_scope"] = sector_matches(sector, scope_sector) and (allowed is None or (country or "") in allowed)
            if sid in existing:
                v = session.get(RansomVictim, existing[sid])
                for k, val in data.items():
                    setattr(v, k, val)
                updated += 1
            else:
                v = RansomVictim(**data)
                new += 1
            session.add(v)
            if method == "unknown":
                llm_queue.append(v)
            pending += 1
            if pending >= BATCH:
                session.commit()
                pending = 0
        session.commit()
    # LLM upgrade for unknown sectors (batched)
    llm_done = 0
    if llm.available() and llm_queue:
        ctx.log(f"LLM sector classification for {len(llm_queue)} victims without sector")
        for i in range(0, len(llm_queue), 25):
            batch = llm_queue[i:i + 25]
            res = llm_classify([{"id": str(j), "victim": v.victim, "domain": v.domain, "description": v.description} for j, v in enumerate(batch)])
            for j, v in enumerate(batch):
                sec = res.get(str(j))
                if sec:
                    v.sector, v.sector_method = sec, "llm"
                    v.in_scope = sector_matches(sec, scope_sector) and (allowed is None or (v.country or "") in allowed)
                    session.add(v)
                    llm_done += 1
            session.commit()
    if failed_months and len(failed_months) == len(months):
        status.set("ransomware_live", "down", "all monthly victim fetches failed")
    elif failed_months:
        status.set("ransomware_live", "degraded", f"failed months: {failed_months}")
    else:
        status.set("ransomware_live", "ok", f"{seen} victim records over {len(months)} months")
    return {"records_seen": seen, "new": new, "updated": updated, "failed_months": failed_months,
            "llm_classified": llm_done, "unknown_sector_remaining": len(llm_queue) - llm_done}


# --------------------------------------------------------------------------- stage 3: cross-source

def cross_source(ctx: RunContext, session: Session, months: list[str], status: col.SourceStatus) -> dict[str, Any]:
    """Confirm ransomware.live victims against independent leak-site scrapers (RansomLook live + ransomwatch archive).
    The rate is computed only over the period both sides cover (from the oldest live post onwards)."""
    posts: list[dict[str, Any]] = []
    details = []
    rl = col.fetch_ransomlook_posts()
    if rl is None:
        details.append("ransomlook: unreachable")
    else:
        posts += rl
        details.append(f"ransomlook: {len(rl)} posts")
    rw = col.fetch_ransomwatch_posts()
    if rw is None:
        details.append("ransomwatch: unreachable")
    else:
        posts += rw
        details.append(f"ransomwatch: {len(rw)} posts (archive)")
    if not posts:
        status.set("ransomwatch", "down", "; ".join(details))
        return {"matched": 0, "rate": None, "posts": 0, "coverage_from": None}
    window_start = datetime.strptime(months[0], "%Y-%m").replace(tzinfo=timezone.utc) - timedelta(days=10)
    index: dict[str, list[tuple[str, datetime | None]]] = defaultdict(list)
    kept, dates = 0, []
    for p in posts:
        d = col.parse_dt(p.get("discovered"))
        if d and d < window_start:
            continue
        index[normalize_name(p.get("post_title", ""))].append((p.get("group_name", ""), d))
        kept += 1
        if d:
            dates.append(d)
    coverage_from = min(dates) if dates else None
    victims = session.exec(select(RansomVictim).where(RansomVictim.month >= months[0])).all()
    matched, covered = 0, 0
    for i, v in enumerate(victims):
        hit = False
        for grp, d in index.get(normalize_name(v.victim), []):
            if not _group_match(grp, v.group):
                continue
            vd = v.attack_date or v.discovered
            if d is None or vd is None or abs((d - vd).days) <= 7:
                hit = True
                break
        if v.cross_source_match != hit:
            v.cross_source_match = hit
            session.add(v)
        matched += hit
        vd = v.discovered or v.attack_date
        if coverage_from and vd and vd >= coverage_from:
            covered += 1
        if i % BATCH == 0:
            session.commit()
    session.commit()
    rate = round(matched / covered, 4) if covered else None
    status.set("ransomwatch", "ok" if rl is not None else "degraded",
               "; ".join(details) + f"; {kept} posts in window; {matched}/{covered} victims confirmed since {coverage_from.date() if coverage_from else 'n/a'}")
    ctx.log(f"cross-source: {matched}/{covered} victims confirmed in overlap window ({(rate or 0) * 100:.1f}%); {'; '.join(details)}")
    return {"matched": matched, "covered": covered, "rate": rate, "posts": kept,
            "coverage_from": coverage_from.isoformat() if coverage_from else None}


# --------------------------------------------------------------------------- stage 4: actors

def _flatten_tools(tools: Any) -> list[str]:
    """ransomware.live returns either a list of names or {category: [tools]}; normalise to strings."""
    out: list[str] = []

    def add(x: Any, cat: str | None = None) -> None:
        if isinstance(x, str):
            label = f"{x} ({cat})" if cat else x
            if x.strip() and label not in out:
                out.append(label)
        elif isinstance(x, dict):
            if isinstance(x.get("name"), str) and len(x) <= 3:
                add(x["name"], cat)
            else:
                for k, v in x.items():
                    add(v, str(k))
        elif isinstance(x, list):
            for v in x:
                add(v, cat)

    add(tools)
    return out[:60]

def build_actors(ctx: RunContext, session: Session, client: CachedClient, months: list[str], scope_sector: str,
                 allowed: set[str] | None, status: col.SourceStatus) -> dict[str, Any]:
    groups = col.fetch_groups(client)
    if groups is None:
        status.set("ransomware_live_groups", "down", "groups endpoint failed")
        groups = []
    victims = session.exec(select(RansomVictim)).all()
    by_group: dict[str, list[RansomVictim]] = defaultdict(list)
    for v in victims:
        by_group[_norm_group(v.group)].append(v)
    cutoff = datetime.now(timezone.utc) - timedelta(days=60)
    all_actors = session.exec(select(ThreatActor)).all()
    existing_by_name: dict[str, ThreatActor] = {}
    for a in sorted(all_actors, key=lambda a: (a.slug != slugify(a.name), a.id)):  # prefer rows with the canonical slug
        if a.name.lower() in existing_by_name:
            session.delete(a)  # stale duplicate from an older slug rule
        else:
            existing_by_name[a.name.lower()] = a
    session.commit()
    existing = {a.slug: a for a in existing_by_name.values()}
    names = {_norm_group(g.get("name", "")): g for g in groups}
    # include groups that have victims but no profile
    for key in by_group:
        names.setdefault(key, {"name": by_group[key][0].group})
    n = 0
    for key, g in names.items():
        name = g.get("name") or key
        slug = slugify(name)
        vs = by_group.get(key, [])
        dates = [d for d in ((v.attack_date or v.discovered) for v in vs) if d]
        window = [v for v in vs if v.month and v.month >= months[0]]
        scope = [v for v in window if v.in_scope]
        aliases = []
        if g.get("altname"):
            aliases.append(str(g["altname"]))
        for loc in g.get("locations") or []:
            t = (loc.get("title") or "").strip()
            if t and len(t) < 40 and t.lower() not in {"", "404 - compromised", "home", "index"} and t not in aliases:
                aliases.append(t)
        a = existing.get(slug) or existing_by_name.get(name.lower()) or ThreatActor(slug=slug, name=name)
        a.slug, a.name, a.aliases = slug, name, aliases[:6]
        existing[slug] = a
        a.description = g.get("description") or a.description
        a.first_seen, a.last_seen = (min(dates) if dates else None), (max(dates) if dates else None)
        a.status = "active" if a.last_seen and a.last_seen >= cutoff else ("dormant" if dates else "unknown")
        a.victim_count_total, a.victim_count_window, a.victim_count_scope = len(vs), len(window), len(scope)
        a.monthly_counts = dict(sorted(Counter(v.month for v in vs if v.month).items()))
        a.monthly_counts_scope = dict(sorted(Counter(v.month for v in scope if v.month).items()))
        a.top_sectors = [{"key": k or "Unknown", "count": c} for k, c in Counter(v.sector for v in window).most_common(5)]
        a.top_countries = [{"key": k or "??", "count": c} for k, c in Counter(v.country for v in window).most_common(5)]
        a.ttps, a.tools = g.get("ttps") or [], _flatten_tools(g.get("tools"))
        a.locations = [{k: v for k, v in loc.items() if k != "screen"} for loc in (g.get("locations") or []) if isinstance(loc, dict)]
        a.profile_url = f"https://www.ransomware.live/group/{name}"
        a.updated_at = datetime.now(timezone.utc)
        session.add(a)
        n += 1
        if n % 100 == 0:
            session.commit()
    session.commit()
    if groups:
        status.set("ransomware_live_groups", "ok", f"{len(groups)} group profiles")
    ctx.log(f"actors: {n} upserted ({len(groups)} with profiles)")
    return {"actors": n, "profiles": len(groups)}


# --------------------------------------------------------------------------- stage 5: IAB

def ingest_iab(ctx: RunContext, session: Session, feeds: list[str], scope_sector: str, allowed: set[str] | None,
               status: col.SourceStatus, max_articles_per_feed: int = 60, max_pages: int = 12) -> dict[str, Any]:
    client = CachedClient("iab_feeds")
    group_names = [a.name for a in session.exec(select(ThreatActor)).all()]
    existing = {u: i for u, i in session.exec(select(IABListing.source_url, IABListing.id))}
    feed_status: dict[str, str] = {}
    entries = candidates = new = updated = 0
    for url in feeds:
        items, st = iabmod.fetch_feed_paginated(url, client, max_pages=int(max_pages))
        feed_status[url] = f"{st} ({len(items)} entries)"
        entries += len(items)
        cands = [it for it in items if it["url"] and iabmod.is_candidate(it["title"], it["summary"] + " " + it.get("content", ""))]
        ctx.log(f"feed {url}: {len(items)} entries, {len(cands)} IAB candidates")
        for it in cands[:max_articles_per_feed]:
            candidates += 1
            body = "" if len(it.get("content", "")) > 1500 else iabmod.fetch_article_text(it["url"], client)
            rec = iabmod.build_listing(it, body, group_names)
            rec["month"] = iabmod.month_of(rec["published"])
            in_region = allowed is None or any(c in allowed for c in rec["countries"])
            in_sector = any(sector_matches(s, scope_sector) for s in rec["sectors"])
            rec["in_scope"] = rec["relevance"] >= 0.2 and ((bool(rec["countries"]) and in_region) or in_sector)
            if it["url"] in existing:
                row = session.get(IABListing, existing[it["url"]])
                for k, val in rec.items():
                    setattr(row, k, val)
                updated += 1
            else:
                row = IABListing(**rec)
                new += 1
            session.add(row)
        session.commit()
    ok = sum(1 for s in feed_status.values() if s.startswith("ok"))
    status.set("iab_feeds", "ok" if ok == len(feeds) else ("degraded" if ok else "down"),
               f"{ok}/{len(feeds)} feeds, {entries} entries, {candidates} IAB candidates")
    return {"feeds": len(feeds), "feeds_ok": ok, "entries": entries, "candidates": candidates, "new": new, "updated": updated,
            "feed_status": feed_status}


# --------------------------------------------------------------------------- stage 6: incidents

def ingest_incidents(ctx: RunContext, session: Session, client: CachedClient, scope_sector: str,
                     allowed: set[str] | None) -> dict[str, Any]:
    rows = col.fetch_cyberattacks(client)
    existing = {s: i for s, i in session.exec(select(CyberIncident.source_id, CyberIncident.id))}
    n = 0
    for r in rows:
        sid = r.get("link") or ("ca:" + col.stable_id(r.get("domain", ""), str(r.get("date", ""))))
        d = col.parse_dt(r.get("date")) or col.parse_dt(r.get("added"))
        summary = (r.get("summary") or r.get("description") or "").strip()
        title = (r.get("title") or r.get("domain") or summary.split(". ")[0][:120] or "Incident").strip()
        country = (r.get("country") or "").upper() or None
        sector = sector_from_keywords(f"{title} {summary}")
        actor = r.get("claim_gang") if isinstance(r.get("claim_gang"), str) else None
        data = dict(source_id=sid, date=d, month=col.month_key(d), title=title[:300], summary=summary or None,
                    domain=r.get("domain") or None, country=country if country and len(country) == 2 else None,
                    region=region_for_country(country), sector=sector, actor=actor, link=r.get("link") or None)
        data["in_scope"] = sector_matches(sector, scope_sector) and (allowed is None or (data["country"] or "") in allowed)
        if sid in existing:
            row = session.get(CyberIncident, existing[sid])
            for k, val in data.items():
                setattr(row, k, val)
        else:
            row = CyberIncident(**data)
        session.add(row)
        n += 1
    session.commit()
    ctx.log(f"incidents: {n} public breach reports processed")
    return {"incidents": n}


# --------------------------------------------------------------------------- orchestrator

def run(ctx: RunContext) -> dict[str, Any]:
    sc = ctx.scope.landscape
    n_months = int(ctx.params.get("months", sc.months)) + 1  # +1 for month-over-month
    sector, region = ctx.params.get("sector", sc.sector), ctx.params.get("region", sc.region)
    allowed = countries_in(region)
    months = col.months_back(n_months)
    status = col.SourceStatus()
    client = col.rl_client()
    ctx.log(f"scope: sector={sector!r} region={region!r} window={months[0]}..{months[-1]} llm={'on' if llm.available() else 'off'}")

    with ctx.session() as session:
        s1 = ingest_victims(ctx, session, client, months, sector, allowed, status)
        s3 = cross_source(ctx, session, months, status)
        s4 = build_actors(ctx, session, client, months, sector, allowed, status)
        s5 = ingest_iab(ctx, session, sc.iab_feeds, sector, allowed, status, max_pages=int(ctx.params.get("feed_pages", 12)))
        s6 = ingest_incidents(ctx, session, client, sector, allowed)
        total = session.exec(select(RansomVictim)).all()
        in_scope = [v for v in total if v.in_scope and v.month and v.month >= months[0]]
        ctx.log(f"in-scope victims ({sector} · {region}) in window: {len(in_scope)} of {len([v for v in total if v.month and v.month >= months[0]])}")
        briefs = []
        for period in (months[-2], months[-1]):
            b = briefing.generate(session, period, sector, region, use_llm=bool(ctx.params.get("use_llm", False)))
            briefs.append({"id": b.id, "period": b.period, "generator": b.generator})
            ctx.log(f"briefing {period}: {b.title}")

    return {"window": months, "sector": sector, "region": region, "victims": s1, "cross_source": s3, "actors": s4,
            "iab": s5, "incidents": s6, "in_scope_victims": len(in_scope), "briefings": briefs, "sources": status.data}
