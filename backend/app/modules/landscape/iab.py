"""Initial-access-broker (IAB) activity mined from public reporting (vendor blogs / news RSS feeds).

Only public articles are read; no forums or marketplaces are visited. Extraction is regex-first with an optional
LLM pass (see common.llm) that upgrades access type / price / geography when an API key is configured.
"""
from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timezone
from typing import Any

import feedparser
from bs4 import BeautifulSoup

from ..common import llm
from ..common.http import CachedClient
from .classify import SECTORS, normalize_sector, sectors_from_keywords
from .collectors import parse_dt
from .regions import countries_from_text, region_for_country

log = logging.getLogger(__name__)

IAB_PATTERNS: list[tuple[str, float]] = [  # (regex, weight)
    (r"initial[- ]access[- ]broker", 3.0), (r"\bIABs?\b", 2.5), (r"access[- ]for[- ]sale", 2.5),
    (r"selling (?:corporate |network |remote |vpn |rdp )?access", 2.5), (r"access (?:listing|offer|sale|seller|auction)", 2.0),
    (r"\bRDP access\b", 1.5), (r"\bVPN access\b", 1.5), (r"\bCitrix\b", 0.8), (r"domain admin", 1.2),
    (r"corporate access", 1.5), (r"network access", 1.0), (r"access brokers?", 2.0), (r"\brevenue (?:of|\$)", 0.8),
    (r"\$\s?\d[\d,.]*k?\b[^.]{0,60}\baccess\b|\baccess\b[^.]{0,60}\$\s?\d[\d,.]*k?\b", 2.0),
    (r"(?:exploit|xss|ramp|breach(?:ed)?forums?|dark ?web) (?:forum|market)", 0.8), (r"\baffiliates?\b", 0.4),
    (r"ransomware", 0.4), (r"compromised (?:credentials|accounts)", 0.6), (r"\bcredential(s)? (?:sale|market)", 1.0),
]
_IAB_RES = [(re.compile(p, re.I), w) for p, w in IAB_PATTERNS]
_TRIGGER_RE = re.compile(r"initial[- ]access[- ]broker|\bIABs?\b|access[- ]for[- ]sale|selling (?:corporate |network |remote |vpn |rdp )?access|access brokers?|RDP access|VPN access|corporate access|domain admin|access (?:listing|auction)", re.I)

ACCESS_TYPES: dict[str, re.Pattern[str]] = {
    "RDP": re.compile(r"\bRDP\b|remote desktop", re.I),
    "VPN": re.compile(r"\bVPN\b", re.I),
    "Citrix": re.compile(r"\bcitrix\b", re.I),
    "Fortinet": re.compile(r"\bforti(net|gate|os)\b", re.I),
    "Pulse/Ivanti": re.compile(r"\bpulse secure\b|\bivanti\b", re.I),
    "Webshell": re.compile(r"\bweb ?shell\b", re.I),
    "Domain Admin": re.compile(r"domain admin(istrator)?|\bDA\b access", re.I),
    "Local Admin": re.compile(r"local admin(istrator)?", re.I),
    "Shell": re.compile(r"\b(reverse )?shell access\b|\bssh\b", re.I),
    "cPanel/Hosting": re.compile(r"\bcpanel\b|\bplesk\b|hosting panel", re.I),
    "ESXi": re.compile(r"\besxi\b|\bvmware\b|\bvcenter\b", re.I),
    "Email/O365": re.compile(r"\b(office ?365|o365|m365|outlook web|owa|exchange|email access|mailbox)\b", re.I),
    "Cloud": re.compile(r"\b(aws|azure|gcp|cloud console|okta)\b", re.I),
    "Stealer logs": re.compile(r"info ?stealer|stealer logs?", re.I),
    "Cobalt Strike/Beacon": re.compile(r"cobalt strike|\bbeacon\b", re.I),
}

_PRICE_RE = re.compile(
    r"(?:\$|usd\s?|us\$)\s?(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)\s?(k|thousand|million|m|bn|billion)?"
    r"|(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?)\s?(k|thousand|million)?\s?(?:usd|dollars|us dollars|bucks)\b", re.I)
_RANGE_RE = re.compile(r"(?:\$|usd\s?)?\s?(\d[\d,.]*)\s?(k)?\s?(?:-|–|to)\s?(?:\$|usd\s?)?\s?(\d[\d,.]*)\s?(k|thousand|million|m)?", re.I)
_REVENUE_CTX = re.compile(r"(revenue|turnover)[^.$]{0,50}?(?:\$|usd\s?)\s?(\d[\d,.]*)\s?(k|thousand|million|m|bn|billion)?|(?:\$|usd\s?)\s?(\d[\d,.]*)\s?(k|thousand|million|m|bn|billion)?[^.]{0,40}(revenue|turnover|in sales)", re.I)
_BROKER_RE = re.compile(r"(?:broker|actor|seller|user|threat actor|persona)s?\s+(?:known as|named|dubbed|called|handle)\s+[\"'“‘]?([A-Za-z0-9_\-.]{3,24})[\"'”’]?|[\"“‘]([A-Za-z0-9_\-.]{3,20})[\"”’]\s+(?:is|was|,)?\s*(?:an?|the)\s+(?:initial access )?broker", re.I)


def _unit(n: float, unit: str | None) -> float:
    u = (unit or "").lower()
    if u in {"k", "thousand"}:
        return n * 1e3
    if u in {"m", "million"}:
        return n * 1e6
    if u in {"bn", "billion"}:
        return n * 1e9
    return n


def _num(s: str) -> float | None:
    try:
        return float(s.replace(",", ""))
    except ValueError:
        return None


def extract_prices(text: str) -> tuple[float | None, float | None]:
    """Access prices in USD (min, max). Only amounts within 120 chars of an access/sale/price keyword count;
    amounts that look like victim revenue are excluded."""
    if not text:
        return None, None
    vals: list[float] = []
    for m in re.finditer(r"(access|sale|sold|selling|price[sd]?|cost|listing|offer\w*|asking|auction|bid|buy|purchase)", text, re.I):
        window = text[max(0, m.start() - 120): m.end() + 120]
        if re.search(r"revenue|turnover|in sales|ransom (demand|payment)|paid|extort", window, re.I):
            # keep only if a price word is nearer than the revenue word — simple heuristic: skip the window
            if not re.search(r"(price|cost|for sale|asking|sold for)", window, re.I):
                continue
        for pm in _PRICE_RE.finditer(window):
            if pm.group(1):
                n, unit = _num(pm.group(1)), pm.group(2)
            else:
                n, unit = _num(pm.group(3)), pm.group(4)
            if n is None:
                continue
            v = _unit(n, unit)
            if 50 <= v <= 5_000_000:
                vals.append(v)
                # range continuation: "$1,500 - 2,500" / "USD 1,500 to 2.5k"
                tail = window[pm.end(): pm.end() + 20]
                rm = re.match(r"\s?(?:-|–|to)\s?(?:\$|usd\s?)?(\d[\d,]*(?:\.\d+)?)\s?(k|thousand|million|m)?", tail, re.I)
                if rm:
                    n2 = _num(rm.group(1))
                    if n2 is not None:
                        v2 = _unit(n2, rm.group(2) or (unit if not rm.group(2) and unit in ("k",) else None))
                        if 50 <= v2 <= 5_000_000:
                            vals.append(v2)
    if not vals:
        return None, None
    return min(vals), max(vals)


def extract_revenue(text: str) -> float | None:
    if not text:
        return None
    best = None
    for m in _REVENUE_CTX.finditer(text):
        num = m.group(2) or m.group(4)
        unit = m.group(3) or m.group(5)
        n = _num(num) if num else None
        if n is None:
            continue
        v = _unit(n, unit)
        if v >= 1e5:
            best = max(best or 0, v)
    return best


def extract_access_types(text: str) -> list[str]:
    return [name for name, pat in ACCESS_TYPES.items() if pat.search(text or "")]


def extract_brokers(text: str) -> list[str]:
    out: list[str] = []
    for m in _BROKER_RE.finditer(text or ""):
        h = (m.group(1) or m.group(2) or "").strip()
        if h and h.lower() not in {"the", "and", "that", "this", "also"} and h not in out:
            out.append(h)
    return out[:6]


_AMBIGUOUS_ACTORS = {"play", "cloak", "space", "money", "everest", "inc", "mad", "lynx", "meow", "hunters", "embargo",
                     "nova", "frag", "stormous", "sarcoma", "fog", "sun", "safepay", "cactus", "dragon", "arcus", "el dorado",
                     "eldorado", "underground", "global", "dread", "storm", "payload", "team", "crypto", "shadow", "black",
                     "white", "dark", "night", "kill", "data", "leak", "leaks", "anonymous", "gang", "group", "pro", "ransom",
                     "apt73", "bl00dy", "monti", "medusa", "trinity", "space bears", "spacebears", "handala", "funksec",
                     "babuk", "kraken", "royal", "brain", "cipher", "cloak", "flocker", "interlock", "lock", "weyhro", "j"}


_NEVER_ACTORS = {"underground", "global", "dread", "payload", "team", "data", "leak", "leaks", "pro", "group", "gang",
                 "ransom", "anonymous", "black", "white", "dark", "night", "crypto", "shadow", "unknown", "money", "space",
                 "storm", "kill", "inc", "mad", "sun", "fog", "j", "lock", "brain", "cipher", "trinity", "royal", "kraken"}


def extract_actors(text: str, group_names: list[str]) -> list[str]:
    """Ransomware groups named in the text. Short or dictionary-like names need a ransomware context nearby."""
    low = (text or "").lower()
    found = []
    for g in group_names:
        gl = g.lower()
        if len(gl) < 3 or gl in _NEVER_ACTORS:
            continue
        if len(gl) < 6 or gl in _AMBIGUOUS_ACTORS:
            pat = rf"\b{re.escape(gl)}\b[^.]{{0,40}}(ransomware|group|gang|leak site|operation|affiliates?)|(ransomware|group|gang|operation)[^.]{{0,40}}\b{re.escape(gl)}\b"
            if not re.search(pat, low):
                continue
        elif not re.search(rf"\b{re.escape(gl)}\b", low):
            continue
        found.append(g)
    return found[:8]


def relevance_score(text: str) -> float:
    if not text:
        return 0.0
    words = max(len(text.split()), 1)
    score = 0.0
    for pat, w in _IAB_RES:
        n = len(pat.findall(text))
        if n:
            score += w * min(n, 5) ** 0.7
    # normalise by length so long general articles don't inflate; clamp 0..1
    dens = score / (words / 400 + 1)
    return round(min(dens / 10.0, 1.0), 3)


def is_candidate(title: str, summary: str) -> bool:
    return bool(_TRIGGER_RE.search(f"{title} {summary}"))


# --------------------------------------------------------------------------- fetching

def fetch_feed(url: str, client: CachedClient) -> tuple[list[dict[str, Any]], str]:
    resp = client.get(url, ttl=1800)
    if resp is None or resp.status_code != 200:
        return [], f"http {resp.status_code if resp is not None else 'error'}"
    parsed = feedparser.parse(resp.text)
    title = (parsed.feed.get("title") or url) if parsed.feed else url
    items = []
    for e in parsed.entries:
        items.append({
            "source": title,
            "url": e.get("link") or "",
            "title": html.unescape(e.get("title") or "").strip(),
            "summary": BeautifulSoup(e.get("summary") or e.get("description") or "", "lxml").get_text(" ", strip=True),
            "published": parse_dt(e.get("published") or e.get("updated") or e.get("created")),
            "content": " ".join(BeautifulSoup(c.get("value", ""), "lxml").get_text(" ", strip=True)
                                for c in (e.get("content") or [])),
        })
    return items, "ok"


def fetch_feed_paginated(url: str, client: CachedClient, max_pages: int = 12) -> tuple[list[dict[str, Any]], str]:
    """WordPress-style feeds expose history via ?paged=N. Walk pages until no new URLs appear."""
    items, st = fetch_feed(url, client)
    if st != "ok" or not items:
        return items, st
    base_source = re.sub(r"^\s*page \d+\s*[-–]\s*", "", items[0]["source"], flags=re.I)
    for it in items:
        it["source"] = base_source
    seen = {i["url"] for i in items}
    sep = "&" if "?" in url else "?"
    for page in range(2, max_pages + 1):
        more, st2 = fetch_feed(f"{url}{sep}paged={page}", client)
        fresh = [m for m in more if m["url"] and m["url"] not in seen]
        if st2 != "ok" or not fresh:
            break
        for m in fresh:
            m["source"] = base_source
        items += fresh
        seen.update(m["url"] for m in fresh)
    return items, "ok"


def fetch_article_text(url: str, client: CachedClient) -> str:
    resp = client.get(url, ttl=7 * 24 * 3600)
    if resp is None or resp.status_code != 200 or "html" not in resp.headers.get("content-type", "html"):
        return ""
    soup = BeautifulSoup(resp.text, "lxml")
    for t in soup(["script", "style", "nav", "header", "footer", "aside", "form", "noscript"]):
        t.decompose()
    main = soup.find("article") or soup.find("main") or soup.body or soup
    text = main.get_text(" ", strip=True)
    return re.sub(r"\s+", " ", text)[:40000]


_LLM_SYSTEM = ("You are a CTI analyst extracting initial-access-broker (IAB) market facts from a public article. "
               "Return JSON with keys: is_iab (bool), access_types (list of strings from: " + ", ".join(ACCESS_TYPES) +
               "), price_usd_min (number|null), price_usd_max (number|null), revenue_usd (number|null, victim revenue "
               "claimed in listings), countries (ISO2 list), sectors (list from: " + ", ".join(SECTORS) +
               "), brokers (handles), actors (ransomware groups), relevance (0-1), one_line (string <=160 chars).")


def llm_extract(title: str, text: str) -> dict[str, Any] | None:
    if not llm.available():
        return None
    return llm.complete_json("iab_extraction", _LLM_SYSTEM, f"TITLE: {title}\n\nARTICLE:\n{text[:12000]}", max_tokens=800)


def build_listing(item: dict[str, Any], body: str, group_names: list[str]) -> dict[str, Any]:
    text = " ".join(x for x in [item["title"], item["summary"], item.get("content", ""), body] if x)
    rel = relevance_score(text)
    pmin, pmax = extract_prices(text)
    ccs = countries_from_text(text)[:5]
    regions = [region_for_country(c) for c in ccs if region_for_country(c)]
    region = regions[0] if regions else None
    rec: dict[str, Any] = {
        "source": item["source"], "source_url": item["url"], "published": item["published"], "title": item["title"][:300],
        "summary": (item["summary"] or "")[:1500] or None,
        "excerpt": _excerpt(text), "access_types": extract_access_types(text), "price_usd_min": pmin, "price_usd_max": pmax,
        "revenue_usd": extract_revenue(text), "countries": ccs, "region": region,
        "sectors": sectors_from_keywords(text, top=3), "brokers": extract_brokers(text),
        "actors": extract_actors(text, group_names), "relevance": rel, "extraction_method": "regex",
    }
    if rel >= 0.25:
        out = llm_extract(item["title"], text)
        if out and isinstance(out, dict):
            rec["extraction_method"] = "llm"
            if out.get("access_types"):
                rec["access_types"] = [a for a in out["access_types"] if a in ACCESS_TYPES] or rec["access_types"]
            for k in ("price_usd_min", "price_usd_max", "revenue_usd"):
                if isinstance(out.get(k), (int, float)):
                    rec[k] = float(out[k])
            if out.get("countries"):
                rec["countries"] = [c.upper() for c in out["countries"] if isinstance(c, str) and len(c) == 2]
                regs = [region_for_country(c) for c in rec["countries"]]
                rec["region"] = next((r for r in regs if r), rec["region"])
            if out.get("sectors"):
                rec["sectors"] = [s for s in (normalize_sector(x) for x in out["sectors"]) if s] or rec["sectors"]
            if out.get("brokers"):
                rec["brokers"] = [str(b) for b in out["brokers"]][:6]
            if out.get("actors"):
                rec["actors"] = [str(a) for a in out["actors"]][:8]
            if isinstance(out.get("relevance"), (int, float)):
                rec["relevance"] = round(float(out["relevance"]), 3)
            if out.get("is_iab") is False:
                rec["relevance"] = min(rec["relevance"], 0.2)
            if out.get("one_line"):
                rec["summary"] = str(out["one_line"])[:300]
    return rec


def _excerpt(text: str, width: int = 420) -> str | None:
    if not text:
        return None
    m = _TRIGGER_RE.search(text)
    if not m:
        return text[:width]
    start = max(0, m.start() - width // 2)
    return ("…" if start else "") + text[start:start + width].strip() + "…"


def month_of(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).strftime("%Y-%m") if dt else None
