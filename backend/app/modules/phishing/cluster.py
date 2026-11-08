"""Two-stage campaign clustering.

Stage 1: exact grouping on (DOM simhash, brand) - identical templates.
Stage 2: DBSCAN (scikit-learn, precomputed distance) over the stage-1 representatives using
         d = 0.5 * hamming(simhash)/64 + 0.5 * (1 - jaccard(feature_set)).
Singletons with a detected brand become singleton campaigns; brand-less singletons stay unclustered.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import numpy as np
from sklearn.cluster import DBSCAN

from .features import feature_set, hamming

EPS = 0.42
MIN_SAMPLES = 2


@dataclass
class Item:
    sample_id: int
    struct_hash: int
    brand: str | None
    fset: set[str]
    features: dict[str, Any]
    url: str
    apex: str | None
    ip: str | None
    asn: str | None
    asn_name: str | None
    country: str | None
    tld: str | None
    first_seen: Any = None


@dataclass
class Cluster:
    members: list[Item]
    method: str  # structural | dbscan | singleton
    cohesion: float = 0.0
    brand: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def distance(a: Item, b: Item) -> float:
    return 0.5 * hamming(a.struct_hash, b.struct_hash) / 64 + 0.5 * (1 - _jaccard(a.fset, b.fset))


def _group_key(it: Item) -> tuple[int, str | None]:
    return it.struct_hash, it.brand


def cluster_items(items: list[Item], eps: float = EPS, min_samples: int = MIN_SAMPLES) -> list[Cluster]:
    if not items:
        return []
    # ---- stage 1: exact template groups
    groups: dict[tuple[int, str | None], list[Item]] = defaultdict(list)
    for it in items:
        groups[_group_key(it)].append(it)
    reps = [members[0] for members in groups.values()]
    rep_members = list(groups.values())

    # ---- stage 2: DBSCAN over representatives
    n = len(reps)
    labels = np.full(n, -1)
    if n >= 2:
        D = np.zeros((n, n))
        for i in range(n):
            for j in range(i + 1, n):
                d = distance(reps[i], reps[j])
                # different detected brands should not merge unless templates are near-identical
                if reps[i].brand and reps[j].brand and reps[i].brand != reps[j].brand:
                    d = min(1.0, d + 0.3)
                D[i, j] = D[j, i] = d
        labels = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed").fit_predict(D)

    clusters: list[Cluster] = []
    by_label: dict[int, list[int]] = defaultdict(list)
    for idx, lab in enumerate(labels):
        by_label[int(lab)].append(idx)
    for lab, idxs in by_label.items():
        if lab == -1:
            for idx in idxs:
                members = rep_members[idx]
                if len(members) >= 2:
                    clusters.append(Cluster(members=members, method="structural"))
                elif members[0].brand:
                    clusters.append(Cluster(members=members, method="singleton"))
            continue
        members = [m for idx in idxs for m in rep_members[idx]]
        method = "dbscan" if len(idxs) > 1 else "structural"
        clusters.append(Cluster(members=members, method=method))

    for c in clusters:
        c.cohesion = cohesion(c.members)
        c.brand = Counter(m.brand for m in c.members if m.brand).most_common(1)[0][0] if any(m.brand for m in c.members) else None
        c.summary = summarize(c.members)
    clusters.sort(key=lambda c: (-len(c.members), c.brand or "~", min((m.sample_id for m in c.members), default=0)))
    return clusters


def cohesion(members: list[Item]) -> float:
    if len(members) < 2:
        return 1.0
    sims, cap = [], 0
    for i in range(len(members)):
        for j in range(i + 1, len(members)):
            sims.append(1 - distance(members[i], members[j]))
            cap += 1
            if cap > 2000:
                break
    return round(float(np.mean(sims)), 3) if sims else 1.0


def _top(values, n=8) -> list[dict[str, Any]]:
    c = Counter(v for v in values if v)
    return [{"key": k, "count": v} for k, v in c.most_common(n)]


def summarize(members: list[Item]) -> dict[str, Any]:
    n = len(members)
    paths = [urlparse(m.url).path or "/" for m in members]
    shared: dict[str, list[str]] = {}
    for key in ("input_names", "script_hosts", "path_markers", "obfuscation", "antibot", "image_names", "kit_markers"):
        cnt = Counter(v for m in members for v in set(m.features.get(key, []) or []))
        shared[key] = [k for k, v in sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))[:12] if v >= max(2, n * 0.5) or n == 1]
    exfil_types = Counter(e["type"] for m in members for e in m.features.get("exfil", []))
    shared["exfil_types"] = [k for k, _ in exfil_types.most_common(6)]
    exfil_counts = _top([e["value"] for m in members for e in m.features.get("exfil", []) if e["type"] != "form_action"], 10)
    form_counts = _top([f.get("action_host") for m in members for f in m.features.get("forms", []) if f.get("external_action")], 10)
    apexes = _top([m.apex for m in members], 15)
    asns = _top([f"{m.asn} {m.asn_name or ''}".strip() for m in members if m.asn], 8)
    takedown = (
        [{"type": "domain", "value": a["key"], "count": a["count"]} for a in apexes[:10]]
        + [{"type": "exfil", "value": e["key"], "count": e["count"]} for e in exfil_counts[:5]]
        + [{"type": "form_endpoint", "value": f["key"], "count": f["count"]} for f in form_counts[:5]]
        + [{"type": "hosting_asn", "value": a["key"], "count": a["count"]} for a in asns[:3]]
    )
    prefixes = {"input_names": "input", "script_hosts": "script", "path_markers": "path", "obfuscation": "obfuscation",
                "antibot": "antibot", "image_names": "image", "kit_markers": "kit", "exfil_types": "exfil"}
    flat_markers = [f"{prefixes[k]}:{v}" for k in prefixes for v in shared.get(k, [])]
    return {
        # [{key, count}] lists
        "top_tlds": _top([m.tld for m in members]),
        "top_apex_domains": apexes,
        "top_asns": asns,
        "top_countries": _top([m.country for m in members]),
        "top_ips": _top([m.ip for m in members]),
        "top_paths": _top(paths),
        # string lists
        "shared_markers": flat_markers[:40],
        "title_examples": list(dict.fromkeys(m.features.get("title") for m in members if m.features.get("title")))[:5],
        "form_actions": [f["key"] for f in form_counts],
        "exfil_endpoints": [e["key"] for e in exfil_counts],
        # [{type, value, count}]
        "takedown_targets": takedown,
        # grouped markers (dict of string lists) for kit inference and campaign cards
        "shared_marker_groups": shared,
        "has_password_field_share": round(sum(1 for m in members if m.features.get("has_password_field")) / n, 2),
        "sources": _top([m.features.get("_source") for m in members]),
    }
