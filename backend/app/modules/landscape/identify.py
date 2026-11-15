"""Identify an unnamed IAB victim: shortlist companies by country + revenue band + sector, then cross-check
which of them exposes the named technology on Shodan.

Example (the 7 Aug post): "VPN access to an unidentified financial services organization in India with
estimated annual revenue between $1 billion and $5 billion ... Pulse Secure ... 10,000+ hosts".
  1. Firmographics: Indian financial firms with revenue in the $1-5B band
       - ZoomInfo company search when enterprise credentials are set, else the Wikidata Query Service (keyless).
  2. Technographics: Shodan hosts in India running Pulse Secure (passive read of Shodan's own scan data).
  3. Cross-reference: a firm whose domain/name appears on a Shodan Pulse Secure host, and whose revenue is in
     band, is a strong lead.

Passive and non-attributive: we read Shodan's database and public registries, never connect to any discovered
host, and every result is an unconfirmed lead for an analyst to confirm, never an automatic victim assignment.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from sqlmodel import Session

from ...config import get_settings
from ...models import XPost
from ..common.http import CachedClient, RateLimiter
from . import firmographics as fg
from .classify import normalize_name
from .regions import country_matches_region  # noqa: F401  (region helpers live here)
from .xmon import TECH_PATTERNS

SPARQL = "https://query.wikidata.org/sparql"
SPARQL_UA = "ctiops-research/0.1 (CTI candidate project; passive company lookups)"
DORKABLE = {name: None for name, _, dork in TECH_PATTERNS if dork}

# ISO-3166 alpha-2 -> Wikidata country QID, for the financial centres IAB posts usually name.
COUNTRY_QID = {
    "IN": "Q668", "US": "Q30", "GB": "Q145", "DE": "Q183", "FR": "Q142", "CA": "Q16", "AU": "Q408", "BR": "Q155",
    "SG": "Q334", "AE": "Q878", "SA": "Q851", "QA": "Q846", "JP": "Q17", "KR": "Q884", "HK": "Q8646", "TH": "Q869",
    "ID": "Q252", "MY": "Q833", "PH": "Q928", "VN": "Q881", "ZA": "Q258", "NG": "Q1033", "KE": "Q114", "TR": "Q43",
    "MX": "Q96", "NL": "Q55", "CH": "Q39", "ES": "Q29", "IT": "Q38", "PL": "Q36", "SE": "Q34", "IE": "Q27",
}
# How a product shows up in Shodan's scan data. One query per detection method, because OR-ing filters needs
# a Corporate plan; a space (implicit AND of country + one filter) works on every plan. Most specific first.
SHODAN_DORK = {
    "Pulse Secure": ['product:"Pulse Secure"', 'http.html:"Pulse Connect Secure"', 'http.title:"Pulse Secure"'],
    "Citrix": ['http.title:"Citrix Gateway"', 'http.html:"NetScaler"', 'product:"Citrix NetScaler Gateway"'],
    "Fortinet": ['product:"Fortinet"', 'http.title:"FortiGate"'],
    "Cisco AnyConnect": ['http.title:"SSL VPN Service"', 'http.html:"AnyConnect"'],
    "GlobalProtect": ['http.title:"GlobalProtect Portal"', 'http.html:"GlobalProtect"'],
    "SonicWall": ['product:"SonicWALL"', 'http.html:"SonicWall"'],
    "Check Point": ['http.title:"Check Point"'],
}
MAX_SHODAN_QUERIES = 6  # one query credit each; cap per identify run


class ShodanUnavailable(RuntimeError):
    pass


# --------------------------------------------------------------------------- firmographic shortlist

INDUSTRY_QIDS = ("wd:Q22687", "wd:Q806718", "wd:Q837171", "wd:Q43183", "wd:Q319845", "wd:Q4120832", "wd:Q218005")
# bank, commercial bank, financial services, insurance, savings bank, financial institution, investment bank


def _sparql_query(country_qid: str) -> str:
    inds = " ".join(INDUSTRY_QIDS)
    # revenue is OPTIONAL (so firms Wikidata has no figure for still list), with its point-in-time qualifier so
    # we can keep the latest statement per company rather than the largest.
    return f"""SELECT DISTINCT ?org ?orgLabel ?rev ?unitLabel ?pit ?emp ?web ?ctyLabel WHERE {{
  ?org wdt:P17 wd:{country_qid} .
  {{ ?org wdt:P31/wdt:P279* wd:Q22687 . }}
  UNION {{ ?org wdt:P452 ?ind . VALUES ?ind {{ {inds} }} }}
  UNION {{ ?org wdt:P31/wdt:P279* ?fi . VALUES ?fi {{ {inds} }} }}
  OPTIONAL {{
    ?org p:P2139 ?rvStmt .
    ?rvStmt psv:P2139 ?rvNode .
    ?rvNode wikibase:quantityAmount ?rev ; wikibase:quantityUnit ?unit .
    OPTIONAL {{ ?rvStmt pq:P585 ?pit . }}
  }}
  OPTIONAL {{ ?org wdt:P1128 ?emp . }}
  OPTIONAL {{ ?org wdt:P856 ?web . }}
  OPTIONAL {{ ?org wdt:P17 ?cty . }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en,[AUTO_LANGUAGE]" . }}
}}"""


def _unit_to_usd(unit_label: str | None) -> float:
    cur = (unit_label or "").lower()
    rates = {"united states dollar": 1.0, "euro": 1.08, "pound sterling": 1.27, "indian rupee": 0.012,
             "japanese yen": 0.0067, "swiss franc": 1.13, "canadian dollar": 0.73, "australian dollar": 0.66,
             "chinese yuan": 0.14, "renminbi": 0.14, "brazilian real": 0.18, "hong kong dollar": 0.128,
             "singapore dollar": 0.74, "south korean won": 0.00073, "turkish lira": 0.03, "south african rand": 0.054,
             "uae dirham": 0.27, "qatari riyal": 0.27, "saudi riyal": 0.27, "thai baht": 0.028, "mexican peso": 0.055}
    return next((v for k, v in rates.items() if k in cur), 0.0)


def wikidata_search(country_iso2: str, rev_min: float, rev_max: float, client: CachedClient) -> list[dict[str, Any]]:
    """Financial firms in a country with latest revenue in [rev_min, rev_max] USD, from the Wikidata Query Service.
    The Query Service enforces the Wikimedia robot policy, so it needs the CTIOPS_REGISTRY_USER_AGENT contact UA."""
    qid = COUNTRY_QID.get((country_iso2 or "").upper())
    ua = get_settings().registry_user_agent
    if not qid or not ua:
        return []
    data = client.get_json(SPARQL + "?format=json&query=" + quote(_sparql_query(qid)),
                           headers={"User-Agent": ua, "Accept": "application/sparql-results+json"})
    if not data:
        return []
    firms: dict[str, dict[str, Any]] = {}
    for b in data.get("results", {}).get("bindings", []):
        org = b["org"]["value"]
        name = b.get("orgLabel", {}).get("value")
        if not name or re.match(r"^Q\d+$", name):  # unlabelled entity
            continue
        if re.search(r"\b(branch|atm|sub-?office|extension counter)\b", name, re.I):  # individual branches, not companies
            continue
        year = int(b["pit"]["value"][:4]) if b.get("pit") else 0
        rate = _unit_to_usd(b.get("unitLabel", {}).get("value"))
        usd = float(b["rev"]["value"]) * rate if (b.get("rev") and rate) else None
        f = firms.setdefault(org, {"name": name, "qid": org.rsplit("/", 1)[-1], "revenue_usd": None, "revenue_year": None,
                                   "employees": int(float(b["emp"]["value"])) if b.get("emp") else None,
                                   "website": b.get("web", {}).get("value"), "country": b.get("ctyLabel", {}).get("value"),
                                   "source": "Wikidata"})
        # keep the most recent revenue statement for each company
        if usd is not None and (f["revenue_usd"] is None or year >= (f["revenue_year"] or 0)):
            f["revenue_usd"], f["revenue_year"] = usd, year
    # firms with revenue in band, plus financial firms Wikidata has no revenue for (revenue unknown)
    return [f for f in firms.values()
            if f["revenue_usd"] is None or rev_min <= f["revenue_usd"] <= rev_max]


def zoominfo_search(country: str, rev_min: float, rev_max: float, sector: str) -> list[dict[str, Any]] | None:
    """ZoomInfo company search (enterprise). Untested without credentials: field names per your contract docs."""
    s = get_settings()
    if not (s.zoominfo_username and s.zoominfo_password):
        return None
    with httpx.Client(timeout=30) as c:
        auth = c.post("https://api.zoominfo.com/authenticate",
                      json={"username": s.zoominfo_username, "password": s.zoominfo_password})
        if auth.status_code != 200:
            return None
        jwt = auth.json().get("jwt")
        body = {"country": country, "revenueMin": int(rev_min / 1000), "revenueMax": int(rev_max / 1000),
                "industryKeywords": sector, "rpp": 25}  # ZoomInfo revenue is in $000s
        r = c.post("https://api.zoominfo.com/search/company", json=body, headers={"Authorization": f"Bearer {jwt}"})
        if r.status_code != 200:
            return None
        out = []
        for d in (r.json().get("data") or []):
            out.append({"name": d.get("name"), "website": d.get("website"), "revenue_usd": (d.get("revenue") or 0) * 1000,
                        "employees": d.get("employeeCount"), "country": d.get("country"), "zoominfo_id": d.get("id"),
                        "source": "ZoomInfo"})
        return out


# --------------------------------------------------------------------------- Shodan technographics

def shodan_search(tech: list[str], country_iso2: str, key: str, limit: int = 100) -> list[dict[str, Any]]:
    """Hosts in a country running any of the named edge products. Reads Shodan's stored scan data (passive).
    One query per detection method (merged, deduped by IP) to stay within every plan's filter rules."""
    filters: list[str] = []
    for t in tech:
        filters.extend(SHODAN_DORK.get(t, []))
    if not filters or not country_iso2:
        return []
    client = CachedClient("shodan", ttl=6 * 3600, rate=RateLimiter(1, 1))
    cc = country_iso2.upper()
    by_ip: dict[str, dict[str, Any]] = {}
    ok = False
    for query in filters[:MAX_SHODAN_QUERIES]:
        # a plain API-client User-Agent: the default browser UA trips Shodan's Cloudflare bot check
        resp = client.get(f"https://api.shodan.io/shodan/host/search?key={quote(key)}"
                          f"&query={quote(f'country:{cc} {query}')}&minify=true",
                          headers={"User-Agent": "ctiops-research/0.1 (+passive Shodan API client)"})
        if resp is None:
            continue
        if resp.status_code == 401:
            raise ShodanUnavailable("Shodan rejected the API key")
        if resp.status_code in (400, 403):
            continue  # a filter this plan does not support (e.g. http.html needs membership); try the next method
        if resp.status_code == 429:
            raise ShodanUnavailable("Shodan rate/credit limit reached")
        if resp.status_code != 200:
            continue
        ok = True
        for m in (resp.json().get("matches") or []):
            ip = m.get("ip_str")
            if ip and ip not in by_ip:
                by_ip[ip] = {"ip": ip, "org": m.get("org"), "isp": m.get("isp"),
                             "hostnames": m.get("hostnames") or [], "domains": m.get("domains") or [],
                             "product": m.get("product"), "port": m.get("port"),
                             "ssl_cn": (((m.get("ssl") or {}).get("cert") or {}).get("subject") or {}).get("CN")}
            if len(by_ip) >= limit:
                break
    if not ok and not by_ip:
        raise ShodanUnavailable("Shodan returned no usable result for the available filters")
    return list(by_ip.values())


# --------------------------------------------------------------------------- cross-reference

def _domains(firm: dict[str, Any]) -> set[str]:
    host = urlsplit(firm.get("website") or "").hostname or ""
    host = host.lower().removeprefix("www.")
    return {host} if host else set()


def _shodan_match(firm: dict[str, Any], hits: list[dict[str, Any]]) -> dict[str, Any] | None:
    fdoms = _domains(firm)
    fname = normalize_name(firm["name"])
    tokens = [w for w in fname.split() if len(w) > 3]
    for h in hits:
        hay = " ".join(h["hostnames"] + h["domains"] + [h.get("org") or "", h.get("ssl_cn") or ""]).lower()
        if (fdoms and any(d and d in hay for d in fdoms)) or (tokens and all(w in hay for w in tokens)):
            return h
    return None


def identify_victim(session: Session, post: XPost) -> dict[str, Any]:
    s = get_settings()
    country = (post.countries or [None])[0]
    tech = [t for t in (post.tech or []) if t in DORKABLE]
    # revenue band: an explicit range in the post wins, else bracket the single figure, else the whole market
    lo, hi = _revenue_band(post)
    sector = "banking financial services"
    notes: list[str] = []
    missing: list[str] = []

    firms = zoominfo_search(country or "", lo, hi, sector) if (s.zoominfo_username and s.zoominfo_password) else None
    fsource = "ZoomInfo"
    if firms is None:
        fsource = "Wikidata Query Service"
        client = CachedClient("identify", ttl=7 * 86400, rate=RateLimiter(2, 1))
        firms = wikidata_search(country or "", lo, hi, client)
        if not s.zoominfo_username:
            notes.append("ZoomInfo credentials not set; used the free Wikidata Query Service for the shortlist.")
        if not s.registry_user_agent:
            missing.append("CTIOPS_REGISTRY_USER_AGENT")
            notes.append("The Wikidata Query Service needs a contact User-Agent (CTIOPS_REGISTRY_USER_AGENT); shortlist skipped.")
    if not country or country.upper() not in COUNTRY_QID:
        notes.append("The post names no country we can map, so the firmographic shortlist is empty.")

    hits: list[dict[str, Any]] = []
    shodan_error = None
    if tech:
        if s.shodan_api_key:
            try:
                hits = shodan_search(tech, country or "", s.shodan_api_key)
            except ShodanUnavailable as e:
                shodan_error = str(e)
        else:
            missing.append("CTIOPS_SHODAN_API_KEY")
            notes.append(f"Shodan key not set; cannot verify which host runs {', '.join(tech)}.")
    elif post.tech:
        notes.append(f"{', '.join(post.tech)} is not an internet-facing product, so Shodan cannot locate it.")

    candidates = []
    for f in firms:
        rev = f.get("revenue_usd")
        in_band = rev is not None and lo <= rev <= hi
        match = _shodan_match(f, hits)
        why = []
        if rev is not None:
            why.append(f"revenue ${_hr(rev)}" + (f" ({f['revenue_year']})" if f.get("revenue_year") else "")
                       + (" is in band" if in_band else " is outside the band"))
        else:
            why.append("revenue not on public registries")
        if match:
            why.append(f"exposes {', '.join(tech)} on {match['ip']}" + (f" ({match['hostnames'][0]})" if match['hostnames'] else ""))
        # a revenue-unknown firm is only a lead if Shodan ties it to the tech; an out-of-band firm, likewise
        if not match and not in_band:
            continue
        conf = "High" if match and in_band else ("Medium" if match or in_band else "Low")
        candidates.append({"name": f["name"], "website": f.get("website"), "revenue_usd": rev,
                           "revenue_band": fg.revenue_band(rev) if rev else "unknown", "employees": f.get("employees"),
                           "country": f.get("country"), "shodan_host": match["ip"] if match else None,
                           "shodan_hostnames": match["hostnames"] if match else [], "confidence": conf, "why": why,
                           "source": f["source"]})
    rank = {"High": 0, "Medium": 1, "Low": 2}
    candidates.sort(key=lambda c: (rank[c["confidence"]], -(c["revenue_usd"] or 0)))
    in_band = sum(1 for f in firms if f.get("revenue_usd") and lo <= f["revenue_usd"] <= hi)
    if firms and in_band == 0 and not hits:
        notes.append(f"Of {len(firms)} {country or ''} financial firms, Wikidata has a revenue figure for very few and "
                     f"none fell in the band. A Shodan key would surface the exposed firm by its tech regardless; "
                     f"ZoomInfo would give fuller revenue coverage.")

    # Shodan hosts whose org didn't map to any shortlisted firm — still leads worth an eye
    matched_ips = {c["shodan_host"] for c in candidates if c["shodan_host"]}
    extra = [{"ip": h["ip"], "org": h["org"], "hostnames": h["hostnames"], "product": h.get("product"), "ssl_cn": h.get("ssl_cn")}
             for h in hits if h["ip"] not in matched_ips][:15]

    return {
        "post_id": post.id, "country": country, "revenue_band": [lo, hi], "tech": post.tech, "host_count": post.host_count,
        "firmographic_source": fsource, "firmographic_count": len(firms), "shodan_count": len(hits),
        "candidates": candidates[:12], "shodan_leads": extra, "shodan_error": shodan_error, "notes": notes,
        "missing_keys": missing,
        "disclaimer": "Unconfirmed leads from public company data and Shodan's scan database. No host was contacted. "
                      "Confirm before recording a victim.",
    }


def _revenue_band(post: XPost) -> tuple[float, float]:
    m = re.search(r"\$?\s*(\d+(?:\.\d+)?)\s*(?:billion|bn|b)\b.{0,12}?(?:and|-|to|–)\s*\$?\s*(\d+(?:\.\d+)?)\s*(?:billion|bn|b)\b",
                  post.text, re.I)
    if m:
        return float(m.group(1)) * 1e9, float(m.group(2)) * 1e9
    if post.claimed_revenue_usd:
        v = post.claimed_revenue_usd
        return v * 0.5, v * 2  # bracket a single figure
    return 1e8, 1e11  # no figure: the whole mid/large market


def _hr(v: float) -> str:
    return f"{v / 1e9:.0f}B" if v >= 1e9 else f"{v / 1e6:.0f}M"
