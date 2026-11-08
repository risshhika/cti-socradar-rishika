"""Aggregates for the P4 dashboards (one call per page). Everything is computed in memory from the samples and
campaigns tables: the dataset is a few hundred rows per run, so this stays well under 100 ms."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, select

from ...models import Detection, PhishCampaign, PhishKit, PhishSample

GRAPH_CATEGORIES = ["Campaign", "Domain", "IP", "Hosting ASN", "Kit", "Exfil endpoint"]
RADAR_DIMS = ["Credential form", "External scripts", "Obfuscation", "Anti-bot / cloaking", "Exfil channel", "Kit path markers", "Shared image assets"]


def _day(dt: datetime | None) -> str | None:
    return dt.date().isoformat() if dt else None


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _asn_label(s: PhishSample) -> str | None:
    if not s.asn and not s.asn_name:
        return None
    name = (s.asn_name or "").split(" - ")[0].split(",")[0].strip()
    return f"{s.asn} {name}".strip() if s.asn else name


def _short(s: str, n: int = 28) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _days_range(samples: list[PhishSample]) -> list[str]:
    ds = sorted({s.first_seen.date() for s in samples if s.first_seen})
    if not ds:
        return []
    out, d = [], ds[0]
    while d <= ds[-1]:
        out.append(d.isoformat())
        d += timedelta(days=1)
    return out


def _radar_profile(samples: list[PhishSample]) -> list[float]:
    ok = [s for s in samples if s.fetch_status == "ok" and s.features]
    if not ok:
        return [0.0] * len(RADAR_DIMS)
    n = len(ok)

    def share(pred) -> float:
        return round(sum(1 for s in ok if pred(s.features)) / n, 3)

    return [
        share(lambda f: bool(f.get("has_password_field")) or bool(f.get("input_names"))),
        share(lambda f: len(f.get("script_hosts") or []) > 0),
        share(lambda f: bool(f.get("obfuscation"))),
        share(lambda f: bool(f.get("antibot"))),
        share(lambda f: bool(f.get("exfil")) or bool(f.get("form_actions"))),
        share(lambda f: bool(f.get("path_markers")) or bool(f.get("kit_markers"))),
        share(lambda f: bool(f.get("image_names"))),
    ]


def compute(session: Session) -> dict[str, Any]:
    samples = list(session.exec(select(PhishSample)))
    camps = list(session.exec(select(PhishCampaign)))
    kits = {k.id: k for k in session.exec(select(PhishKit))}
    dets = list(session.exec(select(Detection)))
    camp_by_id = {c.id: c for c in camps}
    days = _days_range(samples)
    day_idx = {d: i for i, d in enumerate(days)}

    # ---- daily series
    daily_total = [0] * len(days)
    daily_clustered = [0] * len(days)
    daily_by_source: dict[str, list[int]] = defaultdict(lambda: [0] * len(days))
    brand_day: Counter = Counter()
    camp_daily: dict[int, list[int]] = defaultdict(lambda: [0] * len(days))
    for s in samples:
        d = _day(s.first_seen)
        if d is None:
            continue
        i = day_idx[d]
        daily_total[i] += 1
        daily_by_source[s.source][i] += 1
        if s.campaign_id:
            daily_clustered[i] += 1
            camp_daily[s.campaign_id][i] += 1
        brand_day[(s.brand or "Unbranded", d)] += 1

    brand_counts = Counter(s.brand or "Unbranded" for s in samples)
    top_brands = [b for b, _ in brand_counts.most_common(12)]
    brand_day_cells = [[day_idx[d], top_brands.index(b), n] for (b, d), n in brand_day.items() if b in top_brands]

    # campaigns first seen per day (new campaigns)
    daily_new_campaigns = [0] * len(days)
    for c in camps:
        d = _day(c.first_seen)
        if d in day_idx:
            daily_new_campaigns[day_idx[d]] += 1

    det_per_camp = Counter(d.campaign_id for d in dets if d.campaign_id)
    daily_detections = [0] * len(days)
    for c in camps:
        dd = _day(c.first_seen)
        if dd in day_idx:
            daily_detections[day_idx[dd]] += det_per_camp.get(c.id, 0)

    # ---- KPI windows: last 7 days vs prior 7 (relative to newest sample)
    newest = max((_aware(s.first_seen) for s in samples if s.first_seen), default=datetime.now(timezone.utc))
    w1, w0 = newest - timedelta(days=7), newest - timedelta(days=14)

    def window(items, get):
        cur = sum(1 for x in items if (t := _aware(get(x))) and t > w1)
        prev = sum(1 for x in items if (t := _aware(get(x))) and w0 < t <= w1)
        return cur, prev

    s_cur, s_prev = window(samples, lambda s: s.first_seen)
    c_cur, c_prev = window(camps, lambda c: c.first_seen)
    cur_brands = {s.brand for s in samples if s.brand and (t := _aware(s.first_seen)) and t > w1}
    prev_brands = {s.brand for s in samples if s.brand and (t := _aware(s.first_seen)) and w0 < t <= w1}
    camp_ids_cur = {c.id for c in camps if (t := _aware(c.first_seen)) and t > w1}
    camp_ids_prev = {c.id for c in camps if (t := _aware(c.first_seen)) and w0 < t <= w1}
    kpis = {
        "samples": {"cur": s_cur, "prev": s_prev},
        "campaigns_new": {"cur": c_cur, "prev": c_prev},
        "brands": {"cur": len(cur_brands), "prev": len(prev_brands)},
        "detections": {"cur": sum(1 for d in dets if d.campaign_id in camp_ids_cur),
                       "prev": sum(1 for d in dets if d.campaign_id in camp_ids_prev)},
        "window_end": newest.isoformat(),
    }

    # ---- funnel
    featurized = sum(1 for s in samples if s.struct_hash)
    funnel = [
        {"name": "Collected", "value": len(samples)},
        {"name": "Fetched live", "value": sum(1 for s in samples if s.fetch_status == "ok")},
        {"name": "Featurised", "value": featurized},
        {"name": "Clustered", "value": sum(1 for s in samples if s.campaign_id)},
        {"name": "Kit attributed", "value": sum(1 for s in samples if s.kit_id)},
    ]
    kit_split = {
        "named": sum(1 for s in samples if s.kit_id and kits.get(s.kit_id) and kits[s.kit_id].source == "signature"),
        "inferred": sum(1 for s in samples if s.kit_id and kits.get(s.kit_id) and kits[s.kit_id].source == "inferred"),
        "none": sum(1 for s in samples if s.campaign_id and not s.kit_id),
    }

    # ---- sankey brand → kit → hosting
    asn_counts = Counter(_asn_label(s) for s in samples if _asn_label(s))
    top_asns = {a for a, _ in asn_counts.most_common(8)}
    kit_flow = Counter(kits[s.kit_id].name for s in samples if s.campaign_id and s.kit_id in kits)
    top_kits = {k for k, _ in kit_flow.most_common(8)}
    flows: Counter = Counter()
    for s in samples:
        if not s.campaign_id:
            continue
        b = s.brand or "Unbranded"
        if b not in top_brands[:8]:
            b = "Other brands"
        k = kits[s.kit_id].name if s.kit_id and s.kit_id in kits else "No kit match"
        if k != "No kit match" and k not in top_kits:
            k = "Other kits"
        a = _asn_label(s)
        a = a if a in top_asns else ("Other hosting" if a else "Hosting unknown")
        flows[(f"{b}", f"{k} ")] += 1  # trailing space keeps kit and hosting namespaces apart
        flows[(f"{k} ", f"{_short(a, 30)}  ")] += 1
    sk_nodes: dict[str, int] = {}
    for (src, dst) in flows:
        for name in (src, dst):
            sk_nodes.setdefault(name, 0 if not name.endswith(" ") else (2 if name.endswith("  ") else 1))
    sankey = {
        "nodes": [{"name": n, "depth": d} for n, d in sk_nodes.items()],
        "links": [{"source": a, "target": b, "value": v} for (a, b), v in flows.items()],
    }

    # ---- hosting tree ASN › TLD and countries
    tree: dict[str, Counter] = defaultdict(Counter)
    for s in samples:
        a = _asn_label(s) or "Hosting unknown"
        tree[a][f".{s.tld}" if s.tld else "?"] += 1
    tree_sorted = sorted(tree.items(), key=lambda kv: -sum(kv[1].values()))
    head, rest = tree_sorted[:14], tree_sorted[14:]
    hosting_tree = [{"name": _short(a, 34), "value": sum(c.values()), "children": [{"name": t, "value": n} for t, n in c.most_common(6)]} for a, c in head]
    if rest:
        hosting_tree.append({"name": "Other", "value": sum(sum(c.values()) for _, c in rest)})
    countries = [{"iso2": k, "value": v} for k, v in Counter(s.country for s in samples if s.country).most_common()]

    # ---- campaign bubbles + cohesion histogram + per-campaign daily
    bubbles = []
    for c in camps:
        if c.sample_count < 2 or not c.first_seen:
            continue
        bubbles.append({"id": c.id, "name": c.name, "brand": c.brand or "Unbranded", "kit": kits[c.kit_id].name if c.kit_id in kits else None,
                        "first_seen": _aware(c.first_seen).isoformat(), "last_seen": _aware(c.last_seen).isoformat() if c.last_seen else None,
                        "samples": c.sample_count, "domains": c.domain_count, "ips": c.ip_count, "cohesion": round(c.cohesion, 3),
                        "method": c.cluster_method})
    edges = [0.5, 0.6, 0.7, 0.8, 0.9, 1.01]
    labels = ["<0.5", "0.5–0.6", "0.6–0.7", "0.7–0.8", "0.8–0.9", "0.9–1.0"]
    hist = [0] * len(labels)
    for c in camps:
        if c.sample_count < 2:
            continue
        idx = next((i for i, e in enumerate(edges) if c.cohesion < e), len(edges) - 1)
        hist[idx] += 1
    cohesion_hist = [{"bucket": l, "count": n} for l, n in zip(labels, hist)]

    # ---- matrices
    det_types = sorted({d.type for d in dets})
    det_targets = sorted({d.target for d in dets})
    det_matrix = [[det_types.index(t), det_targets.index(g), n] for (t, g), n in Counter((d.type, d.target) for d in dets).items()]
    kit_names_used = [kits[k].name for k, _ in Counter(s.kit_id for s in samples if s.kit_id in kits).most_common(12)]
    bk = Counter((s.brand or "Unbranded", kits[s.kit_id].name) for s in samples if s.kit_id in kits)
    bk_brand_totals: Counter = Counter()
    for (b, _k), n in bk.items():
        bk_brand_totals[b] += n
    bk_brands = [b for b, _ in bk_brand_totals.most_common(10)]
    brand_kit = {"brands": bk_brands, "kits": kit_names_used,
                 "cells": [[kit_names_used.index(k), bk_brands.index(b), n] for (b, k), n in bk.items() if b in bk_brands and k in kit_names_used]}

    # ---- kit radar profiles
    by_kit: dict[int, list[PhishSample]] = defaultdict(list)
    for s in samples:
        if s.kit_id:
            by_kit[s.kit_id].append(s)
    kit_profiles = []
    for kid, ss in sorted(by_kit.items(), key=lambda kv: -len(kv[1])):
        k = kits.get(kid)
        if not k:
            continue
        brands = Counter(s.brand or "Unbranded" for s in ss)
        days_seen = sorted({_day(s.first_seen) for s in ss if s.first_seen})
        kit_profiles.append({"id": kid, "name": k.name, "source": k.source, "family": k.family, "samples": len(ss),
                             "campaigns": len({s.campaign_id for s in ss if s.campaign_id}), "profile": _radar_profile(ss),
                             "brands": [{"key": b, "count": n} for b, n in brands.most_common(5)],
                             "daily": [sum(1 for s in ss if _day(s.first_seen) == d) for d in days],
                             "first_seen": days_seen[0] if days_seen else None, "last_seen": days_seen[-1] if days_seen else None})

    hour_dow = Counter((t.weekday(), t.hour) for s in samples if (t := _aware(s.first_seen)))

    return {
        "days": days,
        "hour_dow": [[h, d, n] for (d, h), n in hour_dow.items()],
        "daily_total": daily_total,
        "daily_clustered": daily_clustered,
        "daily_new_campaigns": daily_new_campaigns,
        "daily_detections": daily_detections,
        "daily_by_source": dict(daily_by_source),
        "brands": [{"key": b, "count": n} for b, n in brand_counts.most_common(15)],
        "brand_day": {"brands": top_brands, "cells": brand_day_cells},
        "kpis": kpis,
        "funnel": funnel,
        "kit_split": kit_split,
        "sankey": sankey,
        "graph": infra_graph(samples, camps, kits, camp_by_id),
        "hosting_tree": hosting_tree,
        "countries": countries,
        "bubbles": bubbles,
        "cohesion_hist": cohesion_hist,
        "detections_matrix": {"types": det_types, "targets": det_targets, "cells": det_matrix},
        "detections_by_type": [{"key": k, "count": v} for k, v in Counter(d.type for d in dets).most_common()],
        "brand_kit": brand_kit,
        "kit_profiles": kit_profiles,
        "radar_dims": RADAR_DIMS,
        "tlds": [{"key": f".{k}", "count": v} for k, v in Counter(s.tld for s in samples if s.tld).most_common(12)],
        "fetch_status": [{"key": k, "count": v} for k, v in Counter(s.fetch_status for s in samples).most_common()],
        "campaign_daily": {str(k): v for k, v in camp_daily.items()},
        "graph_categories": GRAPH_CATEGORIES,
    }


def _exfil_hosts(s: PhishSample) -> list[str]:
    f = s.features or {}
    out = []
    for e in (f.get("exfil") or []):
        v = e.get("value") if isinstance(e, dict) else e
        if v:
            out.append(str(v)[:60])
    for a in (f.get("form_actions") or []):
        host = a.split("/")[2] if isinstance(a, str) and a.startswith("http") and a.count("/") >= 2 else None
        if host and host != s.domain:
            out.append(host)
    return out


def infra_graph(samples: list[PhishSample], camps: list[PhishCampaign], kits: dict[int, PhishKit],
                camp_by_id: dict[int, PhishCampaign], focus: int | None = None, cap: int = 250) -> dict[str, Any]:
    """Campaign ↔ domain ↔ IP ↔ ASN ↔ kit ↔ exfil graph. With `focus`, only that campaign plus every other campaign
    sharing a domain, IP or exfil endpoint with it (one hop)."""
    by_camp: dict[int, list[PhishSample]] = defaultdict(list)
    for s in samples:
        if s.campaign_id:
            by_camp[s.campaign_id].append(s)

    # which campaigns use each infrastructure value
    users: dict[tuple[int, str], set[int]] = defaultdict(set)
    for cid, ss in by_camp.items():
        for s in ss:
            if s.apex_domain:
                users[(1, s.apex_domain)].add(cid)
            if s.ip:
                users[(2, s.ip)].add(cid)
            if (a := _asn_label(s)):
                users[(3, a)].add(cid)
            for x in _exfil_hosts(s):
                users[(5, x)].add(cid)

    if focus is not None:
        chosen = {focus}
        for key, cids in users.items():
            if focus in cids and key[0] in (1, 2, 5):
                chosen |= cids
        chosen_list = sorted(chosen, key=lambda c: (c != focus, -len(by_camp.get(c, []))))[:40]
    else:
        shared_camps = {c for key, cids in users.items() if len(cids) >= 2 and key[0] in (1, 2, 5) for c in cids}
        multi = [c.id for c in camps if c.sample_count >= 2]
        ranked = sorted(set(multi) | shared_camps, key=lambda c: -len(by_camp.get(c, [])))
        chosen_list = ranked[:60]
    chosen = set(chosen_list)

    nodes: dict[str, dict[str, Any]] = {}
    links: Counter = Counter()

    def node(cat: int, key: str, name: str, value: int = 1) -> str:
        nid = f"{cat}:{key}"
        if nid in nodes:
            nodes[nid]["value"] += value
        else:
            nodes[nid] = {"id": nid, "name": name, "category": cat, "value": value}
        return nid

    for cid in chosen_list:
        c = camp_by_id.get(cid)
        ss = by_camp.get(cid, [])
        if not c:
            continue
        cn = node(0, str(cid), f"{c.name} · {c.brand or 'unbranded'}", len(ss))
        nodes[cn]["campaign_id"] = cid
        if c.kit_id in kits:
            kn = node(4, str(c.kit_id), kits[c.kit_id].name, len(ss))
            nodes[kn]["kit_id"] = c.kit_id
            links[(cn, kn)] += 1
        for s in ss:
            dn = node(1, s.apex_domain, s.apex_domain, 1) if s.apex_domain else None
            if dn:
                links[(cn, dn)] += 1
            ipn = node(2, s.ip, s.ip, 1) if s.ip else None
            if ipn and dn:
                links[(dn, ipn)] += 1
            elif ipn:
                links[(cn, ipn)] += 1
            a = _asn_label(s)
            if a:
                an = node(3, a, _short(a, 30), 1)
                links[((ipn or dn or cn), an)] += 1
            for x in _exfil_hosts(s):
                xn = node(5, x, x, 1)
                links[(cn, xn)] += 1

    # cap: drop single-use leaf domains/IPs first, keep shared infrastructure
    if len(nodes) > cap:
        degree = Counter()
        for (a, b) in links:
            degree[a] += 1
            degree[b] += 1
        removable = sorted((n for n in nodes.values() if n["category"] in (1, 2) and degree[n["id"]] <= 1), key=lambda n: n["value"])
        for n in removable[: len(nodes) - cap]:
            nodes.pop(n["id"], None)
        links = Counter({k: v for k, v in links.items() if k[0] in nodes and k[1] in nodes})

    shared = sum(1 for key, cids in users.items() if key[0] in (1, 2, 5) and len(cids & chosen) >= 2)
    return {"nodes": list(nodes.values()), "links": [{"source": a, "target": b, "value": v} for (a, b), v in links.items()],
            "categories": GRAPH_CATEGORIES, "campaigns": len(chosen), "shared_infra": shared}


def campaign_graph(session: Session, campaign_id: int) -> dict[str, Any]:
    samples = list(session.exec(select(PhishSample)))
    camps = list(session.exec(select(PhishCampaign)))
    kits = {k.id: k for k in session.exec(select(PhishKit))}
    camp_by_id = {c.id: c for c in camps}
    g = infra_graph(samples, camps, kits, camp_by_id, focus=campaign_id, cap=180)
    own = [s for s in samples if s.campaign_id == campaign_id]
    days = _days_range(own)
    g["days"] = days
    g["daily"] = [sum(1 for s in own if _day(s.first_seen) == d) for d in days]
    g["related_campaigns"] = [{"id": n["campaign_id"], "name": n["name"], "samples": n["value"]} for n in g["nodes"]
                              if n["category"] == 0 and n.get("campaign_id") != campaign_id]
    g["profile"] = _radar_profile(own)
    g["radar_dims"] = RADAR_DIMS
    return g
