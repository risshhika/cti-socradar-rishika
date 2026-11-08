"""Monthly CISO briefing generator (Markdown). Template-driven; optional LLM rewrite of the narrative parts."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlmodel import Session, select

from ...models import Briefing, CyberIncident, IABListing, RansomVictim, ThreatActor
from ..common import llm
from .classify import sector_matches
from .collectors import months_back
from .regions import countries_in
from .trends import trend_between, victim_in

_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent)), autoescape=select_autoescape([]),
                   trim_blocks=False, lstrip_blocks=False)

ARROWS = {"rising": "▲", "falling": "▼", "flat": "▶", "new": "★"}

TTP_CONTROLS = {
    "T1133": "External remote services (VPN/RDP) abused for entry → enforce MFA and patch edge appliances",
    "T1078": "Valid accounts used for entry → monitor for credential-stuffing and stealer-log exposure",
    "T1566": "Phishing as initial access → tighten mail filtering and user reporting",
    "T1190": "Exploitation of public-facing applications → prioritise edge/VPN/CVE patching",
    "T1486": "Data encrypted for impact → verify offline backups and restoration drills",
    "T1567": "Exfiltration to cloud storage → egress monitoring and DLP on large outbound transfers",
    "T1021": "Lateral movement over RDP/SMB → segment networks and restrict admin protocols",
    "T1003": "Credential dumping → protect LSASS, deploy tiered admin model",
}


def _label(ym: str) -> str:
    return datetime.strptime(ym, "%Y-%m").strftime("%B %Y")


def _delta(a: int, b: int) -> str:
    if a == 0:
        return "new" if b else "–"
    ch = (b - a) / a
    return f"{'+' if ch >= 0 else ''}{ch * 100:.0f}%"


def _pct(n: int, d: int) -> int:
    return round(100 * n / d) if d else 0


def generate(session: Session, period: str, sector: str, region: str, use_llm: bool = False) -> Briefing:
    allowed = countries_in(region)
    months = months_back(3, datetime.strptime(period, "%Y-%m").date().replace(day=28))
    prev_m, cur_m = months[-2], months[-1]
    victims = session.exec(select(RansomVictim).where(RansomVictim.month.in_([months[0], prev_m, cur_m]))).all()
    cur = [v for v in victims if v.month == cur_m]
    prev = [v for v in victims if v.month == prev_m]
    cur_scope = [v for v in cur if victim_in(v, sector, allowed)]
    prev_scope = [v for v in prev if victim_in(v, sector, allowed)]
    cur_region = [v for v in cur if allowed is None or (v.country or "").upper() in allowed]
    prev_region = [v for v in prev if allowed is None or (v.country or "").upper() in allowed]

    iab_rows = session.exec(select(IABListing).where(IABListing.relevance >= 0.2)).all()
    iab_cur = [r for r in iab_rows if r.month == cur_m]
    iab_prev = [r for r in iab_rows if r.month == prev_m]
    prices = [r.price_usd_min for r in iab_cur if r.price_usd_min] + [r.price_usd_max for r in iab_cur if r.price_usd_max]
    prices_sorted = sorted(prices)
    iab_scope = [r for r in iab_cur if r.in_scope]
    notable = sorted(iab_cur, key=lambda r: (-(r.in_scope), -r.relevance))[:6]

    actors = {a.name.lower(): a for a in session.exec(select(ThreatActor)).all()}
    scope_counts = Counter(v.group for v in cur_scope)
    region_counts = Counter(v.group for v in cur_region)
    top_names = [g for g, _ in (scope_counts + region_counts).most_common(7)]
    actor_rows = []
    for g in top_names[:7]:
        a = actors.get(g.lower())
        mc = (a.monthly_counts if a else {}) or Counter(v.month for v in victims if v.group == g)
        trend = trend_between(mc.get(prev_m, 0), mc.get(cur_m, 0))
        actor_rows.append({"name": g, "trend": trend, "arrow": ARROWS.get(trend, ""), "c3": mc.get(months[0], 0),
                           "c2": mc.get(prev_m, 0), "c1": mc.get(cur_m, 0), "scope": scope_counts.get(g, 0),
                           "sectors": ", ".join(s["key"] for s in (a.top_sectors[:3] if a and a.top_sectors else []))})

    incidents = [i for i in session.exec(select(CyberIncident).where(CyberIncident.month == cur_m)).all() if i.in_scope][:6]

    # priorities derived from data
    priorities: list[str] = []
    ttp_counter: Counter[str] = Counter()
    for g in top_names[:5]:
        a = actors.get(g.lower())
        tids = {(tech.get("technique_id") or "").split(".")[0]
                for t in ((a.ttps if a else []) or []) for tech in t.get("techniques", [])}
        for tid in tids:
            if tid in TTP_CONTROLS:
                ttp_counter[tid] += 1
    for tid, _ in ttp_counter.most_common(2):
        priorities.append(f"{TTP_CONTROLS[tid]} (used by {ttp_counter[tid]} of the top groups hitting {region}).")
    access_types = Counter(a for r in iab_cur for a in (r.access_types or []))
    if access_types:
        top_access = ", ".join(k for k, _ in access_types.most_common(3))
        priorities.append(f"Brokered access this month is dominated by {top_access}: audit exposed remote-access services, enforce MFA, and hunt for stealer-log credentials for your domains.")
    if cur_scope:
        sizes = Counter(v.size_band for v in cur_scope)
        dom = sizes.most_common(1)[0][0]
        priorities.append(f"{len(cur_scope)} {sector} organisations in {region} were posted this month, mostly {dom if dom != 'unknown' else 'of unstated'} size; benchmark your third parties and subsidiaries of similar profile against the actors above.")
    if len(priorities) < 3:
        priorities.append("Validate offline backups and restoration time against the groups listed; leak-site posting means exfiltration already happened, so test your detection of large outbound transfers.")

    share_cur = _pct(len(cur_scope), len(cur_region))
    share_prev = _pct(len(prev_scope), len(prev_region)) if prev_region else None
    exec_summary = [
        f"{len(cur_scope)} {sector} organisations in {region} appeared on ransomware leak sites in {_label(cur_m)} "
        f"({_delta(len(prev_scope), len(cur_scope))} vs {_label(prev_m)}); {sector} was {share_cur}% of regional victims.",
        (f"Most active against the sector/region: {', '.join(f'{g} ({n})' for g, n in scope_counts.most_common(3))}."
         if scope_counts else f"Most active in {region} overall: {', '.join(f'{g} ({n})' for g, n in region_counts.most_common(3))}."),
        (f"Public reporting captured {len(iab_cur)} initial-access-broker items this month"
         + (f"; advertised access priced ${prices_sorted[0]:,.0f}–${prices_sorted[-1]:,.0f}" if prices_sorted else "") + "."),
    ]

    sm = Counter(v.sector_method for v in cur_region)
    dq = {"cross_rate": (f"{_pct(sum(1 for v in cur if v.cross_source_match), len(cur))}%" if cur else "n/a"),
          "sector_source": _pct(sm.get("source", 0), len(cur_region)), "sector_keyword": _pct(sm.get("keyword", 0), len(cur_region)),
          "sector_llm": _pct(sm.get("llm", 0), len(cur_region)), "sector_unknown": _pct(sm.get("unknown", 0), len(cur_region)),
          "size_known": _pct(sum(1 for v in cur_scope if v.size_band != "unknown"), len(cur_scope))}

    stats = {
        "period": cur_m, "scope_victims": len(cur_scope), "prev_scope_victims": len(prev_scope), "region_victims": len(cur_region),
        "total_victims": len(cur), "sector_share_pct": share_cur, "top_groups_scope": scope_counts.most_common(5),
        "top_groups_region": region_counts.most_common(5), "iab_reports": len(iab_cur), "iab_price_min": prices_sorted[0] if prices_sorted else None,
        "iab_price_max": prices_sorted[-1] if prices_sorted else None, "access_types": access_types.most_common(5),
        "countries": Counter(v.country for v in cur_scope).most_common(8), "sizes": Counter(v.size_band for v in cur_scope).most_common(),
        "data_quality": dq,
    }

    generator = "template"
    if use_llm and llm.available():
        out = llm.complete_json(
            "briefing_narrative",
            "You write terse monthly CISO threat briefings. Given JSON stats for one sector/region, return JSON "
            "{\"exec_summary\": [3 bullets], \"priorities\": [3 bullets]}. Be concrete, cite the numbers, no fluff, no speculation beyond the data.",
            json.dumps(stats, default=str), max_tokens=900)
        if out and isinstance(out.get("exec_summary"), list) and isinstance(out.get("priorities"), list):
            exec_summary = [str(x) for x in out["exec_summary"]][:4]
            priorities = [str(x) for x in out["priorities"]][:4]
            generator = "llm"

    tpl = _env.get_template("briefing_template.md.j2")
    title = f"{sector} · {region} — Ransomware & Initial-Access Briefing, {_label(cur_m)}"
    md = tpl.render(
        title=title, sector=sector, region=region, period_label=_label(cur_m), prev_label=_label(prev_m),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"), exec_summary=exec_summary, delta=_delta,
        prev={"scope": len(prev_scope), "region": len(prev_region), "total": len(prev), "actors": len(set(v.group for v in prev_region)), "iab": len(iab_prev)},
        cur={"scope": len(cur_scope), "region": len(cur_region), "total": len(cur), "actors": len(set(v.group for v in cur_region)), "iab": len(iab_cur)},
        sector_share=share_cur, sector_share_prev=share_prev,
        victims=[{"victim": v.victim, "country": v.country, "group": v.group, "size_band": v.size_band, "size_basis": v.size_basis,
                  "date": (v.attack_date or v.discovered).strftime("%Y-%m-%d") if (v.attack_date or v.discovered) else "–"}
                 for v in sorted(cur_scope, key=lambda v: v.attack_date or v.discovered or datetime.min.replace(tzinfo=timezone.utc), reverse=True)[:15]],
        victims_more=max(0, len(cur_scope) - 15), actors=actor_rows, m3=_label(months[0])[:3], m2=_label(prev_m)[:3], m1=_label(cur_m)[:3],
        iab={"count": len(iab_cur), "in_scope": len(iab_scope), "price_median": prices_sorted[len(prices_sorted) // 2] if prices_sorted else None,
             "price_min": prices_sorted[0] if prices_sorted else None, "price_max": prices_sorted[-1] if prices_sorted else None,
             "access_types": ", ".join(f"{k} ({n})" for k, n in access_types.most_common(6)),
             "notable": [{"title": r.title, "url": r.source_url, "source": r.source, "price": r.price_usd_min,
                          "access": ", ".join(r.access_types[:3])} for r in notable]},
        incidents=[{"title": i.title, "country": i.country, "summary": (i.summary or "")[:220], "link": i.link} for i in incidents],
        priorities=priorities, dq=dq,
    )

    existing = session.exec(select(Briefing).where(Briefing.period == cur_m, Briefing.sector == sector, Briefing.region == region)).first()
    if existing:
        existing.title, existing.markdown, existing.stats, existing.generator = title, md, stats, generator
        existing.generated_at, existing.status = datetime.now(timezone.utc), "draft"
        b = existing
    else:
        b = Briefing(period=cur_m, sector=sector, region=region, title=title, markdown=md, stats=stats, generator=generator)
    session.add(b)
    session.commit()
    session.refresh(b)
    return b
