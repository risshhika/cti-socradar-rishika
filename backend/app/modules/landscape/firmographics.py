"""Firmographics for IAB victims: revenue, employee count, industry, from public registries.

Providers, tried in order; each value keeps the provider, URL and date it came from:
  ZoomInfo Enrich API  only when CTIOPS_ZOOMINFO_USERNAME / _PASSWORD are set (enterprise contract)
  Wikidata             revenue (P2139), employees (P1128), industry (P452), country, website, ticker, LEI
  SEC EDGAR            SIC industry and latest annual revenue from XBRL (US filers)
  (both need CTIOPS_REGISTRY_USER_AGENT with a contact, per Wikimedia and SEC policy)
  GLEIF                legal name, country and LEI (no revenue / staff; disambiguation only)

Results are banded so analysts can narrow by size: revenue and employee bands, financial sub-type.
"""
from __future__ import annotations

import difflib
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from sqlmodel import Session, select

from ...config import get_settings
from ...models import Organization
from ..common.http import CachedClient, RateLimiter
from .classify import normalize_name
from .xmon import fin_subtype

# rough FX to USD for revenue reported in other currencies (order-of-magnitude banding only)
FX = {"Q4917": ("USD", 1.0), "Q4916": ("EUR", 1.08), "Q25224": ("GBP", 1.27), "Q8146": ("JPY", 0.0067),
      "Q25344": ("CHF", 1.13), "Q1104069": ("CAD", 0.73), "Q259502": ("AUD", 0.66), "Q80524": ("INR", 0.012),
      "Q39099": ("CNY", 0.14), "Q173117": ("BRL", 0.18), "Q122922": ("SEK", 0.095), "Q132643": ("NOK", 0.092),
      "Q25417": ("DKK", 0.145), "Q202040": ("KRW", 0.00073), "Q31015": ("HKD", 0.128), "Q190951": ("SGD", 0.74),
      "Q4730": ("MXN", 0.055), "Q172872": ("TRY", 0.03), "Q81893": ("ZAR", 0.054), "Q41044": ("RUB", 0.011)}
REVENUE_BANDS = [(10e6, "<$10M"), (100e6, "$10M-$100M"), (1e9, "$100M-$1B"), (10e9, "$1B-$10B"), (float("inf"), "$10B+")]
EMPLOYEE_BANDS = [(50, "1-50"), (200, "51-200"), (1000, "201-1,000"), (10000, "1,001-10,000"), (float("inf"), "10,000+")]
SEC_REVENUE_TAGS = ["Revenues", "RevenuesNetOfInterestExpense", "RevenueFromContractWithCustomerExcludingAssessedTax",
                    "InterestAndDividendIncomeOperating", "SalesRevenueNet"]


def _ua() -> dict[str, str]:
    return {"User-Agent": get_settings().registry_user_agent or ""}


def revenue_band(v: float | None) -> str | None:
    return None if v is None else next(b for lim, b in REVENUE_BANDS if v < lim)


def employee_band(v: int | None) -> str | None:
    return None if v is None else next(b for lim, b in EMPLOYEE_BANDS if v <= lim)


def _similar(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, normalize_name(a), normalize_name(b)).ratio()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- Wikidata

def _claims(ent: dict[str, Any], prop: str) -> list[dict[str, Any]]:
    return [c for c in ent.get("claims", {}).get(prop, []) if c.get("mainsnak", {}).get("snaktype") == "value"]


def _year(c: dict[str, Any]) -> int | None:
    for q in c.get("qualifiers", {}).get("P585", []):
        t = (q.get("datavalue") or {}).get("value", {}).get("time", "")
        m = re.match(r"[+-](\d{4})", t)
        if m:
            return int(m.group(1))
    return None


def _latest(ent: dict[str, Any], prop: str) -> tuple[dict[str, Any] | None, int | None]:
    cs = _claims(ent, prop)
    if not cs:
        return None, None
    pref = [c for c in cs if c.get("rank") == "preferred"] or cs
    best = max(pref, key=lambda c: _year(c) or 0)
    return best["mainsnak"]["datavalue"]["value"], _year(best)


def wikidata(name: str, client: CachedClient) -> dict[str, Any] | None:
    s = client.get_json("https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json&language=en&type=item&limit=6"
                        f"&search={quote(name)}", headers=_ua())
    if not s:
        return None
    cands = [h for h in s.get("search", []) if _similar(h.get("label", ""), name) >= 0.72]
    for h in cands[:4]:
        data = client.get_json(f"https://www.wikidata.org/wiki/Special:EntityData/{h['id']}.json", headers=_ua())
        ent = (data or {}).get("entities", {}).get(h["id"])
        if not ent:
            continue
        # a company: has industry, revenue, employees, or an LEI / ticker
        if not any(_claims(ent, p) for p in ("P452", "P2139", "P1128", "P1278", "P249", "P414")):
            continue
        out: dict[str, Any] = {"legal_name": h.get("label"), "identifiers": {"wikidata": h["id"]},
                               "description": h.get("description")}
        rev, ry = _latest(ent, "P2139")
        if rev:
            cur, rate = FX.get(rev.get("unit", "").rsplit("/", 1)[-1], (None, None))
            if rate:
                out["revenue_usd"], out["revenue_year"] = float(rev["amount"]) * rate, ry
                if cur != "USD":
                    out["revenue_note"] = f"converted from {cur}"
        emp, ey = _latest(ent, "P1128")
        if emp:
            out["employees"], out["employees_year"] = int(float(emp["amount"])), ey
        ind_ids = [c["mainsnak"]["datavalue"]["value"]["id"] for c in _claims(ent, "P452")][:4]
        ctry = [c["mainsnak"]["datavalue"]["value"]["id"] for c in _claims(ent, "P17")][:1]
        ids = ind_ids + ctry
        if ids:
            lab = client.get_json("https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&props=labels&languages=en"
                                  f"&ids={'|'.join(ids)}", headers=_ua()) or {}
            labels = {k: v.get("labels", {}).get("en", {}).get("value") for k, v in lab.get("entities", {}).items()}
            out["industry"] = ", ".join(l for l in (labels.get(i) for i in ind_ids) if l) or None
            out["industry_codes"] = [f"wikidata:{i}" for i in ind_ids]
            if ctry:
                out["country"] = labels.get(ctry[0])
        web, _ = _latest(ent, "P856")
        if web:
            out["website"] = web
        for prop, key in (("P1278", "lei"), ("P249", "ticker")):
            v, _ = _latest(ent, prop)
            if isinstance(v, str):
                out["identifiers"][key] = v
        out["match_score"] = round(_similar(h.get("label", ""), name), 2)
        out["source"] = {"source": "Wikidata", "url": f"https://www.wikidata.org/wiki/{h['id']}", "fetched": _now(),
                         "fields": [k for k in ("revenue_usd", "employees", "industry", "country", "website") if out.get(k)]}
        return out
    return None


# --------------------------------------------------------------------------- SEC EDGAR

def sec(name: str, client: CachedClient, ua: str) -> dict[str, Any] | None:
    h = {"User-Agent": ua}
    tickers = client.get_json("https://www.sec.gov/files/company_tickers.json", headers=h, ttl=7 * 86400)
    if not tickers:
        return None
    best = max(tickers.values(), key=lambda r: _similar(r["title"], name), default=None)
    if not best or _similar(best["title"], name) < 0.8:
        return None
    cik = f"{int(best['cik_str']):010d}"
    sub = client.get_json(f"https://data.sec.gov/submissions/CIK{cik}.json", headers=h) or {}
    out: dict[str, Any] = {"legal_name": sub.get("name") or best["title"], "identifiers": {"cik": cik, "ticker": best["ticker"]},
                           "match_score": round(_similar(best["title"], name), 2)}
    if sub.get("sicDescription"):
        out["industry"], out["industry_codes"] = sub["sicDescription"], [f"SIC:{sub.get('sic')}"]
    st = (sub.get("addresses") or {}).get("business", {}).get("stateOrCountryDescription")
    if st:
        out["country"] = "United States" if len(st) == 2 or st.isupper() else st
    for tag in SEC_REVENUE_TAGS:
        c = client.get_json(f"https://data.sec.gov/api/xbrl/companyconcept/CIK{cik}/us-gaap/{tag}.json", headers=h)
        vals = [v for v in ((c or {}).get("units", {}).get("USD") or []) if v.get("form") == "10-K" and v.get("fp") == "FY"]
        if vals:
            v = max(vals, key=lambda v: v.get("end", ""))
            out["revenue_usd"], out["revenue_year"] = float(v["val"]), int(v["end"][:4])
            break
    out["source"] = {"source": "SEC EDGAR", "url": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}",
                     "fetched": _now(), "fields": [k for k in ("revenue_usd", "industry", "country") if out.get(k)]}
    return out


# --------------------------------------------------------------------------- GLEIF

def _name_match(legal: str, name: str) -> bool:
    """Same name, or the legal name extends it ("Bangkok Bank" -> "Bangkok Bank Public Company Limited")."""
    a, b = normalize_name(name), normalize_name(legal)
    if a == b:
        return True
    if len(a) >= 6 and b.startswith(a + " "):
        extra = re.sub(r"[^a-z ]", "", b[len(a):]).split()
        return all(w in LEGAL_FORM_WORDS for w in extra)
    return False


LEGAL_FORM_WORDS = {"public", "pcl", "sae", "qpsc", "pjsc", "psc", "pqsc", "tbk", "bhd", "berhad", "sab", "cv", "de", "saa",
                    "s", "a", "q", "p", "c", "j", "e", "ojsc", "jsc", "pao", "ao", "asa", "abp", "oyj", "na", "fsb"}


def gleif(name: str, client: CachedClient, country_hint: str | None = None) -> dict[str, Any] | None:
    """Head-office legal entity only: foreign branches (category BRANCH) carry the branch's country, and funds or
    subsidiaries that merely start with the name are excluded by _name_match. When several entities share the
    name (QNB Qatar, QNB S.A.E. Egypt), the one in the country the post names wins."""
    base = "https://api.gleif.org/api/v1"
    found: dict[str, dict[str, Any]] = {}
    for url in (f"{base}/lei-records?filter[entity.legalName]={quote(name)}&page[size]=50",
                f"{base}/lei-records?filter[fulltext]={quote(name)}&page[size]=50"):
        for d in (client.get_json(url) or {}).get("data") or []:
            found[d["id"]] = d
    comp = client.get_json(f"{base}/autocompletions?field=fulltext&q={quote(name)}") or {}
    for d in comp.get("data", []):
        lei = ((d.get("relationships") or {}).get("lei-records") or {}).get("data", {}).get("id")
        if lei and lei not in found and _name_match(d.get("attributes", {}).get("value", ""), name):
            one = client.get_json(f"{base}/lei-records/{lei}")
            if one and one.get("data"):
                found[lei] = one["data"]
    rows = [d for d in found.values()
            if d["attributes"]["entity"].get("category") not in ("BRANCH", "FUND") and d["attributes"]["entity"].get("status") == "ACTIVE"
            and _name_match(d["attributes"]["entity"]["legalName"]["name"], name)]
    if not rows:
        return None
    rows.sort(key=lambda d: (d["attributes"]["entity"].get("legalAddress", {}).get("country") != country_hint,
                             -_similar(d["attributes"]["entity"]["legalName"]["name"], name),
                             len(d["attributes"]["entity"]["legalName"]["name"])))
    e = rows[0]["attributes"]["entity"]
    return {"legal_name": e["legalName"]["name"], "country": e.get("legalAddress", {}).get("country"),
            "identifiers": {"lei": rows[0]["id"]}, "match_score": round(_similar(e["legalName"]["name"], name), 2),
            "source": {"source": "GLEIF", "url": f"https://search.gleif.org/#/record/{rows[0]['id']}", "fetched": _now(),
                       "fields": ["legal_name", "country"]}}


# --------------------------------------------------------------------------- ZoomInfo (optional, enterprise API)

def zoominfo(name: str, website: str | None) -> dict[str, Any] | None:
    """ZoomInfo Enrich API. Not exercised without credentials: verify field names against your contract's docs."""
    s = get_settings()
    if not (s.zoominfo_username and s.zoominfo_password):
        return None
    with httpx.Client(timeout=30) as c:
        auth = c.post("https://api.zoominfo.com/authenticate", json={"username": s.zoominfo_username, "password": s.zoominfo_password})
        if auth.status_code != 200:
            return None
        jwt = auth.json().get("jwt")
        body = {"matchCompanyInput": [{"companyName": name, **({"companyWebsite": website} if website else {})}],
                "outputFields": ["id", "name", "website", "revenue", "employeeCount", "industries", "country"]}
        r = c.post("https://api.zoominfo.com/enrich/company", json=body, headers={"Authorization": f"Bearer {jwt}"})
        if r.status_code != 200:
            return None
        res = (((r.json().get("data") or {}).get("result") or [{}])[0].get("data") or [{}])[0]
    if not res:
        return None
    rev = res.get("revenue")  # ZoomInfo reports revenue in thousands of USD
    return {"legal_name": res.get("name"), "website": res.get("website"), "country": res.get("country"),
            "revenue_usd": float(rev) * 1000 if rev else None, "employees": res.get("employeeCount"),
            "industry": ", ".join(i.get("name", "") for i in (res.get("industries") or [])[:3]) or None,
            "identifiers": {"zoominfo": res.get("id")}, "match_score": 1.0,
            "source": {"source": "ZoomInfo", "url": "https://app.zoominfo.com", "fetched": _now(),
                       "fields": ["revenue_usd", "employees", "industry"]}}


# --------------------------------------------------------------------------- merge + cache

def lookup(session: Session, name: str, refresh: bool = False, country_hint: str | None = None) -> Organization:
    key = normalize_name(name)
    org = session.exec(select(Organization).where(Organization.name_key == key)).first()
    if org and not refresh:
        return org
    client = CachedClient("firmographics", ttl=7 * 86400, rate=RateLimiter(5, 1))
    s = get_settings()
    found = []
    ua = s.registry_user_agent
    for fn in (lambda: zoominfo(name, None), lambda: wikidata(name, client) if ua else None,
               lambda: sec(name, client, ua) if ua else None, lambda: gleif(name, client, country_hint)):
        try:
            r = fn()
        except (httpx.HTTPError, KeyError, ValueError, TypeError):
            r = None
        if r:
            found.append(r)
    org = org or Organization(name_key=key, query_name=name)
    org.query_name = name
    org.sources, org.identifiers = [], {}
    for k in ("legal_name", "website", "country", "industry", "industry_codes", "revenue_usd", "revenue_year",
              "employees", "employees_year"):
        setattr(org, k, None if k != "industry_codes" else [])
    for r in found:  # first provider with a value wins (order above = trust order)
        for k in ("legal_name", "website", "country", "industry", "revenue_usd", "revenue_year", "employees", "employees_year"):
            if getattr(org, k) is None and r.get(k) is not None:
                setattr(org, k, r[k])
        if not org.industry_codes and r.get("industry_codes"):
            org.industry_codes = r["industry_codes"]
        org.identifiers = {**r.get("identifiers", {}), **org.identifiers}
        org.sources = org.sources + [r["source"]]
    org.match_score = max((r.get("match_score", 0) for r in found), default=0.0)
    org.revenue_band = revenue_band(org.revenue_usd)
    org.employee_band = employee_band(org.employees)
    desc = " ".join(filter(None, [org.industry, org.legal_name, name] + [r.get("description") or "" for r in found]))
    org.fin_subtype = fin_subtype(desc)
    org.status = "ok" if found else "not_found"
    org.fetched_at = datetime.now(timezone.utc)
    session.add(org)
    session.commit()
    session.refresh(org)
    return org
