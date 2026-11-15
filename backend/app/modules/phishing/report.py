"""Executive brand report: one brand, end to end, from the current P4 data.

Every number is computed from the database at generation time; nothing is hand-entered. The threat
use case is a real sample that answered our fetch within the last 48 hours and has a urlscan screenshot;
its caption deliberately omits the domain (reports travel to non-technical readers -- the full indicator
stays in the platform and the IOC exports).
"""
from __future__ import annotations

import base64
import html
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from sqlmodel import Session, select

from ...config import get_settings, load_scope
from ...models import Detection, DomainLead, PhishCampaign, PhishKit, PhishSample
from ..common.http import CachedClient
from .rank import platform_of
from .typosquat import build_specs

LIVE_WINDOW = timedelta(hours=48)

# What a filled-in form gives the attacker, keyed on input-field names seen on the brand's pages.
CREDENTIAL_CLASSES = [
    ("password", r"pass|pwd|pin\b|passcode", "account passwords", "account takeover: logging in as the victim, changing recovery details"),
    ("otp", r"otp|2fa|mfa|code|token|sms|verif", "one-time / MFA codes", "real-time MFA bypass: the attacker replays the code within seconds"),
    ("card", r"card|ccnum|cc_?num|cvv|cvc|expir|exp_?(month|year|date)", "payment-card data", "card fraud and unauthorised purchases"),
    ("seed", r"seed|mnemonic|phrase|private_?key|recovery|wallet|word\d", "wallet seed phrases / keys", "irreversible theft of crypto funds"),
    ("identity", r"ssn|dob|birth|mother|national_?id|passport|tax", "identity data (DOB, SSN, ID numbers)", "identity theft and new-account fraud"),
    ("email", r"email|e-?mail|login|user", "usernames / email addresses", "targeted follow-up phishing and credential stuffing"),
]


def _utc(d: datetime | None) -> datetime | None:
    return None if d is None else (d if d.tzinfo else d.replace(tzinfo=timezone.utc))


def _brand_samples(session: Session, brand: str) -> list[PhishSample]:
    return [s for s in session.exec(select(PhishSample))
            if s.brand == brand or (s.squat or {}).get("brand") == brand]


def available_brands(session: Session) -> list[dict[str, Any]]:
    c = Counter()
    live = Counter()
    for s in session.exec(select(PhishSample)):
        b = s.brand or (s.squat or {}).get("brand")
        if b:
            c[b] += 1
            live[b] += s.fetch_status == "ok"
    scope = set(load_scope().phishing.brands)
    return [{"brand": b, "samples": n, "live": live[b], "in_scope": b in scope} for b, n in c.most_common()]


# --------------------------------------------------------------------------- sections

def _asks(s: PhishSample, key: str, r: re.Pattern, form_only: bool = False) -> bool:
    """Does this page ask for this data class? Form fields first; kits that collect in on-page widgets
    (seed-phrase grids, card iframes) are caught through their matched kit-marker labels."""
    f = s.features or {}
    if any(r.search(str(x)) for x in f.get("input_names", [])):
        return True
    if key == "password" and f.get("has_password_field"):
        return True
    if form_only:
        return False
    labels = " ".join(str(h.get("label") or "") for h in f.get("kit_hits", []))
    return bool(labels) and key in ("seed", "card", "otp") and bool(r.search(labels))


def _credential_surface(samples: list[PhishSample]) -> list[dict[str, Any]]:
    out = []
    live = [s for s in samples if s.fetch_status == "ok"]
    for key, rx, what, impact in CREDENTIAL_CLASSES:
        r = re.compile(rx, re.I)
        n = sum(1 for s in live if _asks(s, key, r))
        if n:
            out.append({"key": key, "asset": what, "impact": impact, "pages": n, "share": round(n / max(1, len(live)), 2)})
    return out


def _pick_use_case(session: Session, samples: list[PhishSample], now: datetime, brand: str) -> PhishSample | None:
    """Live within 48h + urlscan screenshot. Ranked for a useful end-to-end story: threat score, plus a bonus
    when the page matches a publicly documented kit (citable fingerprint) and sits in a multi-page campaign."""
    # the page itself must render the brand (a matching hostname alone can be coincidence)
    shows = [s for s in samples if s.brand and s.brand_confidence >= 0.5 and s.brand == (s.squat or {}).get("brand", s.brand)]
    pool = shows or samples
    # ...and it must harvest something: a brand word on a page with nothing to steal is not phishing
    harvest_rx = [(k, re.compile(rx, re.I)) for k, rx, _, _ in CREDENTIAL_CLASSES if k != "email"]
    harvesting = [s for s in pool if any(_asks(s, k, r) for k, r in harvest_rx)]
    pool = harvesting or pool
    cands = [s for s in pool if s.fetch_status == "ok" and s.screenshot_url and s.fetched_at
             and now - _utc(s.fetched_at) <= LIVE_WINDOW]
    if not cands:  # fall back to any captured page with a screenshot (flagged as not re-verified)
        cands = [s for s in pool if s.fetch_status == "ok" and s.screenshot_url]
    kit_src = {k.id: k.source for k in session.exec(select(PhishKit))}
    camp_size = {c.id: c.sample_count for c in session.exec(select(PhishCampaign))}

    brand_rx = re.compile(r"(?<![a-z0-9])" + re.escape(brand.lower()) + r"(?![a-z0-9])")

    def story(s: PhishSample) -> float:
        bonus = 15 if kit_src.get(s.kit_id) == "signature" else 5 if s.kit_id else 0
        bonus += 20 if brand_rx.search((s.title or "").lower()) else 0  # page visibly claims the brand
        bonus += 8 if camp_size.get(s.campaign_id, 0) > 1 else 0
        return (s.threat_score or 0) + bonus

    cands.sort(key=lambda s: (-story(s), -(_utc(s.first_seen) or now).timestamp()))
    return cands[0] if cands else None


DOMAINISH = re.compile(r"\b[\w-]+(\.[\w-]+)+\b")
# warning / holding pages (CDN phishing interstitials, redirects, errors) are not the lure's theme
INTERSTITIAL = re.compile(r"suspected phishing|redirect|just a moment|attention required|access denied|"
                          r"forbidden|not found|^4\d\d|^5\d\d|loading|please wait|account suspended", re.I)


def _split_assets(s: PhishSample) -> tuple[list[str], list[str]]:
    """(asked for on this page's form, harvested later in the kit's flow per its matched markers).
    The screenshot shows the first; the caption must not claim the page displays the second."""
    on_page, in_kit = [], []
    for key, rx, what, _ in CREDENTIAL_CLASSES:
        r = re.compile(rx, re.I)
        if _asks(s, key, r, form_only=True):
            on_page.append(what)
        elif _asks(s, key, r):
            in_kit.append(what)
    return on_page, in_kit


def _caption(s: PhishSample, brand: str) -> str:
    """Describe the page without naming the domain (titles can embed it, so scrub domain-like tokens)."""
    plat = platform_of(s.domain)
    where = f"a free {plat.split('.')[0].title()} subdomain" if plat else "a dedicated lookalike domain" \
        if (s.squat or {}).get("brand") == brand else "a compromised or throwaway site"
    country = f", hosted in {s.country}" if s.country else ""
    title = DOMAINISH.sub("[redacted]", s.title or "").strip()
    on_page, in_kit = _split_assets(s)
    asks = ", ".join(on_page[:3]) if on_page else "sign-in details"
    seen = _utc(s.fetched_at).strftime("%d %b %Y %H:%M UTC") if s.fetched_at else "recently"
    return (f"Live {brand} impersonation served from {where}{country}. The page"
            + (f" (titled “{title[:70]}”)" if title and "[redacted]" not in title else "")
            + f" asks the visitor for {asks}"
            + (f"; its kit goes on to harvest {', '.join(in_kit[:2])}" if in_kit else "")
            + f". Verified reachable {seen}.")


def _fingerprint(session: Session, s: PhishSample) -> dict[str, Any]:
    kit = session.get(PhishKit, s.kit_id) if s.kit_id else None
    camp = session.get(PhishCampaign, s.campaign_id) if s.campaign_id else None
    f = s.features or {}
    summ = (camp.summary or {}) if camp else {}
    return {
        "kit": {"name": kit.name, "family": kit.family, "source": kit.source, "confidence": s.kit_confidence,
                "description": kit.description if kit.source == "signature" else
                (f"Not a publicly documented kit: inferred from {kit.sample_count} page{'s' if kit.sample_count != 1 else ''} "
                 f"in {kit.campaign_count} campaign{'s' if kit.campaign_count != 1 else ''} that share one DOM template "
                 f"and {len(kit.markers or [])} structural markers. Analysts can name it once attributed."),
                "references": kit.references or [],
                "pages": kit.sample_count, "campaigns": kit.campaign_count} if kit else None,
        "matched_markers": [h.get("label") or h.get("pattern") for h in f.get("kit_hits", [])][:10],
        "campaign": {"name": camp.name, "pages": camp.sample_count, "domains": camp.domain_count, "ips": camp.ip_count,
                     "cohesion": camp.cohesion, "method": camp.cluster_method, "status": camp.status,
                     "first_seen": camp.first_seen, "last_seen": camp.last_seen,
                     "shared_markers": summ.get("shared_markers", [])[:12],
                     "exfil_endpoints": summ.get("exfil_endpoints", [])[:5]} if camp else None,
        "page": {"dom_simhash": s.struct_hash, "favicon_hash": f.get("favicon_hash"), "html_sha256": s.html_sha256,
                 "input_names": f.get("input_names", [])[:12], "script_hosts": f.get("script_hosts", [])[:8],
                 "obfuscation": f.get("obfuscation", []), "antibot": f.get("antibot", []),
                 "exfil": [e.get("type") for e in f.get("exfil", [])][:6], "image_names": f.get("image_names", [])[:8]},
        "detection_type": s.detection_type, "squat": {k: (s.squat or {}).get(k) for k in ("kind", "evidence", "lure_words")} if s.squat else None,
        "rank_factors": s.rank_factors or [],
    }


def _urlscan_queries(brand: str, scope, fp: dict[str, Any] | None, asn: str | None) -> list[dict[str, Any]]:
    spec = build_specs([brand], scope.brand_fragments, scope.brand_domains, scope.brand_exclusions)[0]
    official = sorted(spec.official)
    not_official = " AND ".join(f"NOT page.apexDomain:{d}" for d in official[:6])
    win = f"date:>now-{scope.window_days}d"
    qs = [
        ("Lookalike domains (brand embedded)", f"page.domain:*{spec.slug}* AND {not_official} AND {win}",
         "every scanned host containing the brand outside its official domains"),
    ]
    if len(spec.fragments) > 1:
        chain = "*" + "*".join(spec.fragments) + "*"
        qs.append(("Fragment variants (split / hyphenated brand)", f"page.domain:{chain} AND {not_official} AND {win}",
                   f"catches {'-'.join(spec.fragments)}, {'.'.join(spec.fragments)} and padded spellings"))
    qs.append(("Brand-titled pages on foreign domains", f'page.title:"{brand}" AND {not_official} AND {win}',
               "content-only impersonation: random hostnames that render the brand"))
    qs.append(("Already tagged phishing for the brand", f"task.tags:phishing AND (page.title:\"{brand}\" OR page.domain:*{spec.slug}*) AND {win}",
               "pages urlscan's own classifiers flagged"))
    if fp:
        imgs = [i for i in (fp.get("page") or {}).get("image_names", []) if len(i) > 6 and not i.startswith("data")]
        if imgs:
            qs.append(("Kit artefact (shared image file)", f'filename:"{imgs[0]}" AND {win}',
                       "same kit asset on other hosts, regardless of brand wording"))
        if asn:
            qs.append(("Same hosting network", f'page.asn:{asn} AND page.title:"{brand}" AND {win}',
                       "brand pages on the network hosting the use case"))
    return [{"label": l, "query": q, "why": w, "link": "https://urlscan.io/search/#" + quote(q)} for l, q, w in qs]


def _count_queries(queries: list[dict[str, Any]]) -> None:
    """Live result counts so the reader sees each query works today (API key only; 1 search each)."""
    key = get_settings().urlscan_api_key
    if not key:
        return
    client = CachedClient("urlscan_report", ttl=1800)
    for q in queries:
        resp = client.get(f"https://urlscan.io/api/v1/search/?q={quote(q['query'])}&size=1", headers={"API-Key": key})
        if resp is not None and resp.status_code == 200:
            try:
                q["results_now"] = resp.json().get("total")
            except ValueError:
                q["results_now"] = None
        else:
            q["results_now"] = None
            q["error"] = f"HTTP {resp.status_code}" if resp is not None else "no response"


def _geography(samples: list[PhishSample], now: datetime, window_days: int) -> dict[str, Any]:
    half = now - timedelta(days=window_days / 2)
    early = Counter(s.country for s in samples if s.country and (_utc(s.first_seen) or now) < half)
    late = Counter(s.country for s in samples if s.country and (_utc(s.first_seen) or now) >= half)
    allc = early + late
    countries = [{"country": c, "pages": n, "new_recently": c in late and c not in early} for c, n in allc.most_common(12)]
    asns = Counter(f"{s.asn} {s.asn_name or ''}".strip() for s in samples if s.asn)
    tlds = Counter(s.tld for s in samples if s.tld)
    cc_tlds = [{"tld": t, "pages": n} for t, n in tlds.most_common(15) if len(t.split(".")[-1]) == 2][:8]
    return {"countries": countries, "new_countries": [c["country"] for c in countries if c["new_recently"]],
            "asns": [{"asn": a, "pages": n} for a, n in asns.most_common(6)],
            "tlds": [{"tld": t, "pages": n} for t, n in tlds.most_common(8)], "country_code_tlds": cc_tlds}


# --------------------------------------------------------------------------- report

def build_brand_report(session: Session, brand: str, count_queries: bool = True) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    scope = load_scope().phishing
    all_samples = session.exec(select(PhishSample)).all()
    samples = _brand_samples(session, brand)
    if not samples:
        return {"brand": brand, "error": f"No {brand} samples in the current {scope.window_days}-day window."}
    live = [s for s in samples if s.fetch_status == "ok"]
    tiers = Counter(s.threat_tier for s in samples if s.threat_tier)
    dtypes = Counter(s.detection_type for s in samples if s.detection_type)
    camps = [c for c in session.exec(select(PhishCampaign)) if c.brand == brand]
    kit_ids = Counter(s.kit_id for s in samples if s.kit_id)
    kits = {k.id: k for k in session.exec(select(PhishKit)) if k.id in kit_ids}
    leads = [d for d in session.exec(select(DomainLead)) if d.brand == brand]
    srcs = Counter(src for s in samples for src in (s.sources or [s.source]))
    days = Counter((_utc(s.first_seen) or now).strftime("%Y-%m-%d") for s in samples)
    det_count = len([d for d in session.exec(select(Detection)) if d.campaign_id in {c.id for c in camps}])
    creds = _credential_surface(samples)

    numbers = {
        "window_days": scope.window_days, "pages": len(samples), "share_of_all": round(len(samples) / max(1, len(all_samples)), 3),
        "live": len(live), "blocked": sum(1 for s in samples if s.fetch_status == "blocked"),
        "offline": sum(1 for s in samples if s.fetch_status == "offline"),
        "critical": tiers.get("critical", 0), "high": tiers.get("high", 0), "medium": tiers.get("medium", 0), "low": tiers.get("low", 0),
        "typosquat_hosts": dtypes.get("typosquat", 0), "content_only": dtypes.get("content", 0),
        "campaigns": len(camps), "active_campaigns": sum(1 for c in camps if c.status == "active"),
        "multi_page_campaigns": sum(1 for c in camps if c.sample_count > 1),
        "kits": len(kits), "named_kits": sum(1 for k in kits.values() if k.source == "signature"),
        "typosquat_leads": len(leads), "new_domain_leads": sum(1 for d in leads if "nrd" in (d.sources or [])),
        "detections": det_count, "duplicates_merged": sum(s.duplicate_count or 0 for s in samples),
        "sources": dict(srcs), "daily": [{"day": d, "pages": n} for d, n in sorted(days.items())],
    }

    plats = Counter(platform_of(s.domain) for s in samples if platform_of(s.domain))
    lures = Counter(w for s in samples for w in ((s.squat or {}).get("lure_words") or []))
    kinds = Counter((s.squat or {}).get("kind") for s in samples if s.squat)
    targeting = {
        "rank_among_brands": next((i + 1 for i, b in enumerate(available_brands(session)) if b["brand"] == brand), None),
        "detection_types": dict(dtypes), "squat_kinds": dict(kinds),
        "lure_words": [{"word": w, "count": n} for w, n in lures.most_common(10)],
        "hosting_platforms": [{"platform": p, "pages": n} for p, n in plats.most_common(6)],
        "dedicated_domains": sum(1 for s in samples if not platform_of(s.domain)),
        "title_themes": [t for t, _ in Counter(DOMAINISH.sub("[redacted]", s.title or "").strip()
                                               for s in live if s.title and not INTERSTITIAL.search(s.title)).most_common(6) if t],
        "credential_surface": creds,
        "kits": [{"name": k.name, "source": k.source, "pages": kit_ids[k.id]} for k in sorted(kits.values(), key=lambda k: -kit_ids[k.id])][:6],
    }

    uc = _pick_use_case(session, samples, now, brand)
    use_case = None
    fp = None
    if uc:
        fp = _fingerprint(session, uc)
        on_page, in_kit = _split_assets(uc)
        uc_creds = on_page + in_kit
        use_case = {
            "sample_id": uc.id, "screenshot": f"/api/phishing/samples/{uc.id}/screenshot",
            "caption": _caption(uc, brand), "threat_score": uc.threat_score, "threat_tier": uc.threat_tier,
            "verified_live_at": uc.fetched_at, "live_within_48h": bool(uc.fetched_at and now - _utc(uc.fetched_at) <= LIVE_WINDOW),
            "first_seen": uc.first_seen, "country": uc.country, "hosting": uc.asn_name or uc.asn,
            "platform": platform_of(uc.domain), "assets_requested": uc_creds,
        }
    queries = _urlscan_queries(brand, scope, fp, uc.asn if uc else None)
    if count_queries:
        _count_queries(queries)
    geo = _geography(samples, now, scope.window_days)

    top_asset = creds[0]["asset"] if creds else "credentials"
    impact_line = (f"{numbers['live']} live pages impersonate {brand} to steal {top_asset}"
                   + (f" and {creds[1]['asset']}" if len(creds) > 1 else "")
                   + f"; {numbers['typosquat_hosts']} use lookalike hostnames that pass a casual glance.")
    worst = [c for c in creds if c["key"] in ("seed", "card", "otp")]
    user_impact = [
        {"asset": c["asset"], "consequence": c["impact"], "evidence": f"requested on {c['pages']} live page{'s' if c['pages'] > 1 else ''}"}
        for c in creds]
    summary = (
        f"In the last {scope.window_days} days the platform tracked {numbers['pages']} phishing pages impersonating {brand} "
        f"({numbers['share_of_all']:.0%} of all phishing collected), {numbers['live']} of them live when checked. "
        f"They group into {numbers['campaigns']} campaigns, {numbers['multi_page_campaigns']} spanning multiple pages, "
        f"built on {numbers['kits']} distinct kit{'s' if numbers['kits'] != 1 else ''}"
        + (f" ({numbers['named_kits']} matching publicly documented families)" if numbers['named_kits'] else "") + ". "
        f"{numbers['typosquat_hosts']} pages sit on hostnames that imitate the brand and {numbers['new_domain_leads']} brand lookalikes "
        f"were registered this week; {numbers['critical'] + numbers['high']} rank critical or high. "
        + (f"The most damaging pages request {', '.join(c['asset'] for c in worst)}." if worst else
           f"Pages primarily harvest {top_asset}.")
    )
    takedown = []
    for c in sorted(camps, key=lambda c: -c.sample_count)[:5]:
        for t in (c.summary or {}).get("takedown_targets", [])[:4]:
            if t.get("type") in ("domain", "hosting_asn", "exfil"):
                takedown.append({"campaign": c.name, **t})
    defense = {
        "organisation": [
            f"Request takedown of the {min(len(takedown), 12)} highest-volume hosts and exfiltration endpoints (listed in the platform's campaign cards).",
            f"Block the {numbers['detections']} generated detections at the web and mail gateway (Sigma, YARA, URL regex, IOC lists).",
            f"Watch newly-registered domains for the fragment pattern {'*'.join(build_specs([brand], scope.brand_fragments)[0].fragments)}* daily; "
            f"{numbers['new_domain_leads']} matched this week.",
            "Save the urlscan queries below as alerts so new pages surface within minutes of a scan.",
            "Report free-hosting abuse (" + ", ".join(p["platform"] for p in targeting["hosting_platforms"][:3]) + ") to each platform's abuse desk."
            if targeting["hosting_platforms"] else "Report hosting abuse to the networks listed under geography.",
        ],
        "customers": [
            f"Only sign in through the official app or by typing the {brand} address; never from a link in email, SMS or ads.",
            f"{brand} will never ask for a full password, one-time code" + (", or wallet recovery phrase" if any(c['key'] == 'seed' for c in creds) else "")
            + " by message or on a page you reached from a link.",
            "Turn on app-based or passkey sign-in; codes sent by SMS can be relayed in real time by these kits.",
            "If you entered details on a suspicious page: change the password, revoke sessions, and contact support immediately.",
        ],
    }
    return {
        "brand": brand, "generated_at": now, "window_days": scope.window_days, "sector": scope.sector,
        "executive_summary": summary, "impact_one_line": impact_line, "numbers": numbers, "targeting": targeting,
        "use_case": use_case, "fingerprint": fp, "urlscan_queries": queries, "geography": geo,
        "user_impact": user_impact, "defense": defense, "takedown_targets": takedown[:12],
        "method_note": ("Sources: WhoisDS newly-registered domains, urlscan.io, OpenPhish, PhishTank. Pages are deduplicated "
                        "across sources, captured once, fingerprinted against public kit signatures and clustered by DOM structure "
                        "and shared artefacts. Threat rank is an explainable 0-100 score."),
    }


# --------------------------------------------------------------------------- screenshot + HTML export

def screenshot_bytes(s: PhishSample) -> bytes | None:
    """urlscan's stored screenshot (passive: served by urlscan, not the phishing host), cached on disk."""
    if not s.screenshot_url:
        return None
    path = get_settings().artifacts_dir / "phishing" / "screenshots" / f"{s.source_id or s.id}.png"
    if path.exists():
        return path.read_bytes()
    import httpx
    try:
        r = httpx.get(s.screenshot_url, timeout=30, follow_redirects=True, headers={"User-Agent": get_settings().user_agent})
    except httpx.HTTPError:
        return None
    if r.status_code != 200 or not r.headers.get("content-type", "").startswith("image/"):
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(r.content)
    return r.content


def render_html(rep: dict[str, Any], shot: bytes | None) -> str:
    e = lambda v: html.escape(str(v if v is not None else "—"))  # noqa: E731 - every value is attacker-influenced
    n = rep["numbers"]
    t = rep["targeting"]
    uc = rep.get("use_case")
    fp = rep.get("fingerprint") or {}
    kit = fp.get("kit")
    camp = fp.get("campaign")
    geo = rep["geography"]
    img = (f'<img src="data:image/png;base64,{base64.b64encode(shot).decode()}" alt="Screenshot of the live phishing page">'
           if shot else '<div class="noshot">Screenshot unavailable</div>')
    rows = lambda items: "".join(items)  # noqa: E731
    kpis = [("Phishing pages", n["pages"]), ("Live now", n["live"]), ("Critical + high", n["critical"] + n["high"]),
            ("Campaigns", n["campaigns"]), ("Distinct kits", n["kits"]), ("Lookalike hosts", n["typosquat_hosts"]),
            ("New lookalike domains", n["new_domain_leads"]), ("Detections ready", n["detections"])]
    css = """
    body{font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1d24;margin:0;background:#f4f5f7}
    main{max-width:960px;margin:24px auto;background:#fff;padding:40px 48px;border-radius:10px}
    h1{font-size:26px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px;padding-bottom:6px;border-bottom:2px solid #e6e8ec}
    .muted{color:#667085}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}
    .kpi{border:1px solid #e6e8ec;border-radius:8px;padding:10px 12px}.kpi b{display:block;font-size:22px}
    .impact{background:#fff4f2;border-left:4px solid #d92d20;padding:12px 16px;border-radius:6px;font-weight:600}
    table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid #eef0f3;padding:6px 8px;text-align:left;vertical-align:top}
    th{color:#667085;font-weight:600}code{font:12px/1.4 ui-monospace,Consolas,monospace;background:#f2f4f7;padding:2px 5px;border-radius:4px;word-break:break-all}
    figure{margin:0}figure img{width:100%;border:1px solid #e6e8ec;border-radius:8px}figcaption{color:#475467;font-size:13px;margin-top:6px}
    .noshot{padding:60px;text-align:center;border:1px dashed #d0d5dd;color:#98a2b3;border-radius:8px}
    .tag{display:inline-block;background:#eef4ff;color:#3538cd;border-radius:10px;padding:1px 8px;font-size:12px;margin:2px}
    .new{background:#fef3f2;color:#b42318}ul{padding-left:20px}@media print{body{background:#fff}main{margin:0;padding:24px}}
    """
    q_rows = rows(f"<tr><td><b>{e(q['label'])}</b><div class='muted'>{e(q['why'])}</div></td>"
                  f"<td><code>{e(q['query'])}</code></td><td>{e(q.get('results_now', '—'))}</td></tr>" for q in rep["urlscan_queries"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(rep['brand'])} phishing: executive report</title><style>{css}</style></head><body><main>
<div class="muted">CTI Ops · P4 Phishing Intelligence · {e(rep['sector'])}</div>
<h1>{e(rep['brand'])}: phishing threat report</h1>
<div class="muted">Last {e(rep['window_days'])} days · generated {e(rep['generated_at'].strftime('%d %b %Y %H:%M UTC'))}</div>

<h2>Executive summary</h2><p>{e(rep['executive_summary'])}</p>
<div class="impact">Impact: {e(rep['impact_one_line'])}</div>

<h2>Numbers at a glance</h2>
<div class="kpis">{rows(f'<div class="kpi"><span class="muted">{e(k)}</span><b>{e(v)}</b></div>' for k, v in kpis)}</div>
<p class="muted">Sources: {e(', '.join(f'{k} {v}' for k, v in n['sources'].items()))} · {e(n['duplicates_merged'])} duplicate reports merged ·
{e(round(n['share_of_all'] * 100, 1))}% of all phishing collected in the window.</p>

<h2>How {e(rep['brand'])} is targeted</h2>
<table><tr><th>Lookalike hostnames</th><td>{e(n['typosquat_hosts'])} pages ({e(', '.join(f'{k} {v}' for k, v in t['squat_kinds'].items()) or 'none')})</td></tr>
<tr><th>Content-only impersonation</th><td>{e(n['content_only'])} pages on hostnames that never mention the brand</td></tr>
<tr><th>Hosting</th><td>{e(t['dedicated_domains'])} on dedicated domains; free platforms: {e(', '.join(f"{p['platform']} ({p['pages']})" for p in t['hosting_platforms']) or 'none')}</td></tr>
<tr><th>Lure words</th><td>{rows(f'<span class="tag">{e(w["word"])} · {e(w["count"])}</span>' for w in t['lure_words']) or '—'}</td></tr>
<tr><th>Data requested</th><td>{rows(f'<span class="tag">{e(c["asset"])} · {e(c["pages"])}</span>' for c in t['credential_surface']) or '—'}</td></tr>
<tr><th>Kits in use</th><td>{rows(f'<span class="tag">{e(k["name"])} · {e(k["pages"])}</span>' for k in t['kits']) or '—'}</td></tr></table>

<h2>Threat use case</h2>
{f'<figure>{img}<figcaption>{e(uc["caption"])}</figcaption></figure><p class="muted">Threat rank {e(uc["threat_score"])}/100 ({e(uc["threat_tier"])}). {"Re-verified live within the last 48 hours." if uc["live_within_48h"] else "Captured earlier in the window; not re-verified in the last 48 hours."}</p>' if uc else '<p class="muted">No live page with a screenshot in the window.</p>'}

<h2>Fingerprint reference</h2>
<table>
<tr><th>Kit</th><td>{e(kit['name']) if kit else 'Unmatched'}{f" · {e(kit['family'])} · {'public signature' if kit['source'] == 'signature' else 'inferred from cluster'} · confidence {e(round((kit['confidence'] or 0) * 100))}%" if kit else ''}
{('<div class="muted">' + e(kit['description']) + '</div>') if kit else ''}</td></tr>
<tr><th>Matched markers</th><td>{rows(f'<span class="tag">{e(m)}</span>' for m in fp.get('matched_markers', [])) or '—'}</td></tr>
<tr><th>Campaign</th><td>{f"{e(camp['name'])} · {e(camp['pages'])} pages · {e(camp['domains'])} domains · {e(camp['ips'])} IPs · cohesion {e(camp['cohesion'])} ({e(camp['method'])})" if camp else 'Standalone page'}</td></tr>
<tr><th>Shared artefacts</th><td>{rows(f'<code>{e(m)}</code> ' for m in (camp or {}).get('shared_markers', [])[:10]) or '—'}</td></tr>
<tr><th>Page hashes</th><td>DOM simhash <code>{e((fp.get('page') or {}).get('dom_simhash'))}</code> · favicon <code>{e((fp.get('page') or {}).get('favicon_hash'))}</code></td></tr>
<tr><th>Public references</th><td>{rows(f'<div><code>{e(r)}</code></div>' for r in (kit or {}).get('references', [])) or '—'}</td></tr></table>

<h2>Find more of this on urlscan.io</h2>
<table><tr><th>What it finds</th><th>Query</th><th>Results now</th></tr>{q_rows}</table>

<h2>Geographical footprint</h2>
<table><tr><th>Hosting countries</th><td>{rows(f'<span class="tag {"new" if c["new_recently"] else ""}">{e(c["country"])} · {e(c["pages"])}{" · new" if c["new_recently"] else ""}</span>' for c in geo['countries']) or '—'}</td></tr>
<tr><th>Networks</th><td>{rows(f'<div>{e(a["asn"])} · {e(a["pages"])}</div>' for a in geo['asns']) or '—'}</td></tr>
<tr><th>Top-level domains</th><td>{rows(f'<span class="tag">.{e(x["tld"])} · {e(x["pages"])}</span>' for x in geo['tlds']) or '—'}</td></tr></table>
{f'<p>Expansion: hosting appeared in {e(", ".join(geo["new_countries"]))} only in the second half of the window.</p>' if geo['new_countries'] else ''}

<h2>Impact for everyday users</h2>
<table><tr><th>What they lose</th><th>What happens next</th><th>Evidence</th></tr>
{rows(f'<tr><td>{e(u["asset"])}</td><td>{e(u["consequence"])}</td><td class="muted">{e(u["evidence"])}</td></tr>' for u in rep['user_impact'])}</table>

<h2>Defensive steps</h2>
<b>For the organisation</b><ul>{rows(f'<li>{e(x)}</li>' for x in rep['defense']['organisation'])}</ul>
<b>For customers</b><ul>{rows(f'<li>{e(x)}</li>' for x in rep['defense']['customers'])}</ul>
<p class="muted" style="margin-top:32px">{e(rep['method_note'])}</p>
</main></body></html>"""
