"""Kit fingerprinting: score captured pages against kits.yaml signatures and infer unnamed kits from clusters."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

KITS_FILE = Path(__file__).with_name("kits.yaml")
MIN_HITS = 2


@dataclass
class KitSignature:
    slug: str
    name: str
    family: str | None
    description: str
    threshold: float
    references: list[str]
    markers: list[dict[str, Any]]
    _compiled: list[tuple[dict[str, Any], re.Pattern]] = field(default_factory=list)

    def compiled(self) -> list[tuple[dict[str, Any], re.Pattern]]:
        if not self._compiled:
            self._compiled = [(m, re.compile(m["pattern"], re.I | re.S)) for m in self.markers]
        return self._compiled


@lru_cache
def load_signatures(path: str | None = None) -> list[KitSignature]:
    with open(path or KITS_FILE) as fh:
        raw = yaml.safe_load(fh) or {}
    return [KitSignature(slug=k["slug"], name=k["name"], family=k.get("family"), description=k.get("description", ""),
                         threshold=float(k.get("threshold", 3.0)), references=k.get("references", []),
                         markers=k.get("markers", [])) for k in raw.get("kits", [])]


def _haystacks(html: str, url: str, features: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "html": [html or ""],
        "url_path": [url],
        "script_host": list(features.get("script_hosts", [])),
        "form_field": list(features.get("input_names", [])),
        "form_action": list(features.get("form_actions", [])),
        "title": [features.get("title") or ""],
        "text": [" ".join(features.get("text_tokens", []))],
        "brand": [features.get("brand") or ""],
    }


def score_kit(sig: KitSignature, html: str, url: str, features: dict[str, Any]) -> tuple[float, list[dict[str, Any]]]:
    hays = _haystacks(html, url, features)
    score = 0.0
    hits: list[dict[str, Any]] = []
    for marker, rx in sig.compiled():
        for hay in hays.get(marker["type"], []):
            if hay and rx.search(hay):
                score += float(marker.get("weight", 1.0))
                hits.append({"type": marker["type"], "label": marker.get("label", marker["pattern"]),
                             "weight": marker.get("weight", 1.0)})
                break
    return score, hits


def fingerprint(html: str, url: str, features: dict[str, Any]) -> dict[str, Any] | None:
    """Best matching kit or None (needs >= MIN_HITS distinct markers). Confidence = min(0.98, score / (threshold * 1.6))."""
    best: dict[str, Any] | None = None
    for sig in load_signatures():
        score, hits = score_kit(sig, html, url, features)
        # require two independent markers: a single string (e.g. a kit name inside base64) is too weak alone
        if score >= sig.threshold and len(hits) >= MIN_HITS and (best is None or score > best["score"]):
            best = {"slug": sig.slug, "name": sig.name, "family": sig.family, "description": sig.description,
                    "references": sig.references, "score": score,
                    "confidence": round(min(0.98, score / (sig.threshold * 1.6)), 2), "hits": hits}
    return best


def kit_markers_for_sample(html: str, url: str, features: dict[str, Any]) -> list[str]:
    """All marker labels that fired for any kit (stored in features for cluster summaries)."""
    labels: list[str] = []
    for sig in load_signatures():
        _, hits = score_kit(sig, html, url, features)
        labels.extend(f"{sig.slug}:{h['label']}" for h in hits)
    return sorted(set(labels))


def infer_kit(brand: str | None, struct_hash: str, shared: dict[str, Any]) -> dict[str, Any]:
    """Describe an unnamed kit from the markers shared across a cluster (analysts can rename it)."""
    b = re.sub(r"[^a-z0-9]", "", (brand or "unknown").lower())
    slug = f"inferred-{b}-{struct_hash[:6]}"
    markers = []
    for key in ("input_names", "script_hosts", "path_markers", "obfuscation", "antibot", "exfil_types", "image_names"):
        for v in shared.get(key, [])[:6]:
            markers.append({"type": key, "label": v, "weight": 1.0, "pattern": re.escape(str(v))})
    desc = (f"Unnamed kit inferred from a cluster of {shared.get('sample_count', '?')} pages impersonating "
            f"{brand or 'an unknown brand'}; shares {len(markers)} structural markers (DOM simhash {struct_hash[:8]}…).")
    return {"slug": slug, "name": f"Unnamed {brand or 'generic'} kit {struct_hash[:6]}", "family": "inferred",
            "description": desc, "markers": markers, "references": []}
