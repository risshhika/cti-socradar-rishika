"""Client-facing campaign report (the approved template, 15 Nov 2026).

A report is a *spec* (plain dict, JSON-serialisable) rendered by client_report.html.j2:

* `build_from_campaign()` fills a spec from a P4 campaign: hosts, shared infrastructure, linkage
  evidence, what the pages collect, hunting queries, IOCs, ATT&CK mapping, recommendations.
* An analyst can override any field (or write a whole spec by hand for a manual investigation,
  see docs/reports/*.json) and render it the same way.

Client rule: the report never names the internal tools or feeds that found the activity, and never
quotes their verdict scores. `leak_check()` scans every visible string; `render()` refuses to produce
a report that fails it. Hunting queries keep their field syntax but never name the service.
"""
from __future__ import annotations

import base64
import html
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup
from sqlmodel import Session, select

from ...config import load_scope
from ...models import DomainLead, PhishCampaign, PhishKit, PhishSample
from .rank import platform_of
from .typosquat import build_specs

# --------------------------------------------------------------------------- client rule

# Internal tools, feeds and process words a client must not see.
SOURCE_TERMS = [
    r"url\s*scan(?:\.io)?", r"open\s*phish", r"phish\s*tank", r"whois\s*ds", r"crt\.sh", r"cert\s*stream",
    r"virus\s*total", r"hybrid[\s-]*analysis", r"any\.run", r"shodan", r"censys", r"@ecarlesi",
    r"(?:automated|classifier)\s+(?:verdict|score)", r"verdict\s+score", r"scored\s+(?:it|them|both|\d+)",
    r"stored\s+(?:scan|scans|screenshot|copy)", r"captured\s+by\s+(?:our|the|a)?\s*(?:scanner|crawler|sandbox|tool|feed)",
    r"\bP4\s+pipeline\b", r"ctiops\b",
]
_LEAK = re.compile("|".join(f"(?:{t})" for t in SOURCE_TERMS), re.I)


def _strings(obj: Any, path: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("src",):  # image sources are not visible text (Docs re-hosts the image on import)
                continue
            yield from _strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def leak_check(spec: dict[str, Any]) -> list[dict[str, str]]:
    """Every visible string that names an internal tool/feed or quotes a verdict score."""
    out = []
    for path, text in _strings(spec):
        for m in _LEAK.finditer(text):
            out.append({"field": path, "term": m.group(0), "context": text[max(0, m.start() - 40): m.end() + 40]})
    return out


# --------------------------------------------------------------------------- defanging + rich text

def defang(value: str, kind: str = "domain") -> str:
    """domain/url: every dot; ip: last dot only (house style in tables); file: the extension dot."""
    v = value.strip()
    if "[.]" in v or "[:]" in v:
        return v
    if kind in ("ip", "ip_full") and ":" in v and "." not in v:  # IPv6: last colon
        head, _, tail = v.rpartition(":")
        return f"{head}[:]{tail}"
    if kind == "ip":
        head, _, tail = v.rpartition(".")
        return f"{head}[.]{tail}" if head else v
    if kind == "ip_full":
        return v.replace(".", "[.]")
    if kind == "file":
        return re.sub(r"\.(\w{1,5})$", r"[.]\1", v)
    v = re.sub(r"^http", "hxxp", v)
    return v.replace(".", "[.]")


IOC_INLINE = re.compile(r"\[\[(.+?)\]\]")
BOLD = re.compile(r"\*\*(.+?)\*\*")


def rich(text: str) -> Markup:
    """Escape, then [[x]] -> red italic IOC (defanged by the author), **x** -> bold."""
    t = html.escape(str(text or ""), quote=False)
    t = IOC_INLINE.sub(lambda m: f'<i style="color: #A61B1B;">{m.group(1)}</i>', t)
    t = BOLD.sub(r"<b>\1</b>", t)
    return Markup(t.replace("\n", "<br>"))


_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent)), autoescape=select_autoescape(["html", "j2"]))
_env.filters["rich"] = rich


class NotReportable(ValueError):
    """The campaign lacks evidence of phishing (nothing is collected), so no client report is produced."""


class ClientLeakError(ValueError):
    def __init__(self, leaks):
        self.leaks = leaks
        super().__init__("report names internal sources: " + ", ".join(sorted({l['term'] for l in leaks})))


def render(spec: dict[str, Any]) -> str:
    leaks = leak_check(spec)
    if leaks:
        raise ClientLeakError(leaks)
    return _env.get_template("client_report.html.j2").render(s=_with_defaults(spec))


def _with_defaults(spec: dict[str, Any]) -> dict[str, Any]:
    s = dict(spec)
    s.setdefault("kicker", "THREAT INTELLIGENCE REPORT  |  PHISHING CAMPAIGN ANALYSIS")
    s.setdefault("classification", "TLP:CLEAR")
    s.setdefault("date", datetime.now(timezone.utc).strftime("%d %B %Y").lstrip("0"))
    s.setdefault("disclaimer", "Prepared for SOCRadar as part of a Senior CTI Ops Engineer candidate project. "
                               "Not an official SOCRadar publication. Indicators are defanged.")
    s.setdefault("figures", [])
    s.setdefault("related", {"intro": "", "items": []})
    s["linkage"] = {"heading": "Why we assess one operator", **s.get("linkage", {})}
    s["kit"] = {"heading": "How the kit works", "ordered": True, "live_panel_label": "This is a live panel:", **s.get("kit", {})}
    for i, f in enumerate(s["figures"], 1):
        f.setdefault("n", i)
        f.setdefault("alt", f.get("caption", "")[:120])
    return s


def embed_image(data: bytes, mime: str = "image/png") -> str:
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


# --------------------------------------------------------------------------- auto-fill from a campaign

CDN_ASNS = {"AS13335", "AS16509", "AS14618", "AS15169", "AS8075", "AS20940", "AS16625", "AS54113", "AS209242", "AS396982"}
BANK_BRANDS = {"Chase", "Wells Fargo", "Bank of America", "HSBC", "Barclays", "Santander", "Revolut", "Citi", "CIBC", "RBC",
               "Lloyds", "NatWest", "TD", "ING", "BBVA", "Monzo", "Starling"}
DYN_DNS = ("duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "freedns.afraid.org", "dynu.net", "servehttp.com")
PLAIN_EVASION = {"atob": "decodes its content at runtime (base64)", "long_base64": "hides content in long encoded blocks",
                 "document_write": "writes the page with script", "eval": "evaluates obfuscated script",
                 "ua_check": "checks the visitor's browser before showing the form", "devtools_block": "blocks browser developer tools", "recaptcha": "shows a CAPTCHA gate",
                 "turnstile": "shows a Cloudflare Turnstile gate", "hcaptcha": "shows a CAPTCHA gate",
                 "devtools": "blocks browser developer tools", "geo": "filters visitors by location"}
EXFIL_WORDS = {"telegram_bot": "a Telegram bot", "email": "an attacker mailbox", "discord_webhook": "a Discord webhook",
               "form_action": "an off-site form endpoint"}


def _utc(d):
    return None if d is None else (d if d.tzinfo else d.replace(tzinfo=timezone.utc))


def _when(d) -> str:
    d = _utc(d)
    return d.strftime("%d %b %Y, %H:%M UTC").lstrip("0") if d else "date unknown"


def _dyn_or_platform(host: str) -> str | None:
    host = (host or "").lower()
    return next((p for p in DYN_DNS if host.endswith("." + p)), None) or platform_of(host)


def _asset_list(members: list[PhishSample]) -> list[str]:
    from .report import _credential_surface  # same data classes as the executive report
    return [c["asset"] for c in _credential_surface(members)]


def build_from_campaign(session: Session, campaign_id: int, reporter: str, classification: str = "TLP:CLEAR",
                        date: str | None = None, screenshots: str = "embed", force: bool = False) -> dict[str, Any]:
    from .report import screenshot_bytes
    c = session.get(PhishCampaign, campaign_id)
    if c is None:
        raise ValueError("campaign not found")
    members = sorted(session.exec(select(PhishSample).where(PhishSample.campaign_id == c.id)).all(),
                     key=lambda m: _utc(m.first_seen) or datetime.max.replace(tzinfo=timezone.utc))
    kit = session.get(PhishKit, c.kit_id) if c.kit_id else None
    scope = load_scope().phishing
    brand = c.brand or "unbranded"
    spec_b = build_specs([brand], scope.brand_fragments, scope.brand_domains, scope.brand_exclusions)[0] if c.brand else None
    hosts = list(dict.fromkeys(m.domain for m in members if m.domain))
    n_hosts = len(hosts)
    live = [m for m in members if m.fetch_status == "ok"]
    assets = _asset_list(members)
    confirmed_visually = False
    if not assets and force:
        assets, confirmed_visually = ["sign-in details"], True
    if not assets:
        raise NotReportable(f"No page in {c.name} asks the visitor for anything (no forms, fields or harvesting markers). "
                            "This is typical of parked, redirecting or holding pages; confirm it is phishing before reporting.")

    # ---- infrastructure and linkage evidence
    all_by_ip = Counter(ip for ip in session.exec(select(PhishSample.ip)) if ip)
    ip_c = Counter(m.ip for m in members if m.ip)
    asn_name = {m.ip: (m.asn_name or m.asn or "") for m in members if m.ip}
    asn_of = {m.ip: m.asn for m in members if m.ip}
    # dedicated only when the network is known, is not a CDN, and the hosts are not on a shared platform
    on_platform = {m.ip for m in members if m.ip and platform_of(m.domain)}
    dedicated = [ip for ip, n in ip_c.items() if n >= 2 and all_by_ip[ip] == n and asn_of.get(ip)
                 and asn_of.get(ip) not in CDN_ASNS and ip not in on_platform]
    html_c = Counter(m.html_sha256 for m in members if m.html_sha256)
    same_html = [(h, n) for h, n in html_c.items() if n >= 2]
    struct_c = Counter(m.struct_hash for m in members if m.struct_hash)
    same_struct = [(h, n) for h, n in struct_c.items() if n >= 2]
    fav_c = Counter((m.features or {}).get("favicon_hash") for m in members if (m.features or {}).get("favicon_hash"))
    exfil_c = Counter(e.get("value") for m in members for e in (m.features or {}).get("exfil", []) if e.get("type") != "form_action")
    action_c = Counter(f.get("action_host") for m in members for f in (m.features or {}).get("forms", []) if f.get("external_action"))
    services = Counter(_dyn_or_platform(h) for h in hosts if _dyn_or_platform(h))
    span_h = ((_utc(members[-1].first_seen) - _utc(members[0].first_seen)).total_seconds() / 3600
              if len(members) > 1 and members[0].first_seen and members[-1].first_seen else 0)

    rows, strong = [], 0
    for ip in dedicated:
        rows.append(["Dedicated server", f"{ip_c[ip]} hosts resolve to {defang(ip, 'ip')}, and no unrelated sites were seen on that address.", "Strong"])
        strong += 1
    for h, n in same_html[:1]:
        rows.append(["Identical page", f"Same HTML SHA-256 ({h[:8]}...{h[-7:]}) on {n} hosts.", "Strong"])
        strong += 1
    for h, n in same_struct[:1]:
        if not same_html:
            rows.append(["Same page template", f"{n} pages share one page structure (template fingerprint {h[:8]}).", "Strong"])
            strong += 1
    for v, n in exfil_c.most_common(1):
        if n >= 2:
            rows.append(["Shared collection point", f"{n} pages send data to the same destination.", "Strong"])
            strong += 1
    for v, n in action_c.most_common(1):
        if n >= 2:
            rows.append(["Shared form endpoint", f"{n} pages post their forms to {defang(v)}.", "Strong"])
            strong += 1
    for v, n in fav_c.most_common(1):
        if n >= 2:
            rows.append(["Same favicon", f"{n} pages use an identical icon file.", "Supporting"])
    if kit and kit.source == "signature":
        rows.append(["Same kit", f"Pages match the {kit.name} kit signature.", "Supporting"])
    if services:
        svc, n = services.most_common(1)[0]
        rows.append(["Naming and hosting", f"{n} of {n_hosts} hosts use {svc} names built from the brand and trust words"
                     if c.brand else f"{n} of {n_hosts} hosts use {svc}", "Supporting"])
    if span_h:
        rows.append(["Timing", f"First seen within {span_h / 24:.1f} days of each other." if span_h >= 48
                     else f"First seen within {span_h:.0f} hours of each other.", "Supporting"])
    confidence = "High" if strong >= 2 else "Medium" if strong == 1 else "Low"

    # ---- hosting phrase for titles
    if dedicated:
        infra = "one dedicated server" if len(dedicated) == 1 else f"{len(dedicated)} dedicated servers"
    elif services:
        infra = f"{services.most_common(1)[0][0]} hosts"
    else:
        infra = f"{len(ip_c)} hosting address{'es' if len(ip_c) != 1 else ''}"
    operator = "A single operator" if confidence == "High" else "An operator"

    # ---- kit / page behaviour
    f0 = Counter()
    for m in members:
        for x in (m.features or {}).get("obfuscation", []) + (m.features or {}).get("antibot", []):
            f0[x] += 1
    evasion = [PLAIN_EVASION.get(x, x.replace("_", " ")) for x, _ in f0.most_common(4)]
    exfil_types = Counter(e.get("type") for m in members for e in (m.features or {}).get("exfil", []))
    paths = Counter()
    for m in members:
        for f in (m.features or {}).get("forms", []):
            a = (f.get("action") or "")
            pm = re.search(r"/([\w-]+\.(?:php|aspx?|jsp|cgi))", a)
            if pm:
                paths[pm.group(1)] += 1
    steps = [f"The page asks for {', '.join(assets[:4])}."
             + (" The form is built by script when the page loads, so the requested fields were confirmed visually." if confirmed_visually else "")]
    if paths:
        steps.append("Entries are posted to " + ", ".join(f"[[{defang(p, 'file')}]]" for p, _ in paths.most_common(3)) + " on the same host.")
    if exfil_types:
        steps.append("Collected data is sent to " + ", ".join(EXFIL_WORDS.get(t, t) for t in exfil_types) + ".")
    if evasion:
        steps.append("To avoid automated analysis, the page " + "; ".join(evasion) + ".")
    if kit:
        steps.append(f"The page matches the {kit.name} kit" + (f" ({kit.family})" if kit.family else "") + "."
                     if kit.source == "signature" else "The page template is not a publicly documented kit and is tracked as a new kit.")

    # ---- figures (domain-free captions)
    figs = []
    rep = sorted([m for m in live if m.screenshot_url], key=lambda m: -(m.threat_score or 0))
    if rep:
        m = rep[0]
        data = screenshot_bytes(m) if screenshots == "embed" else None
        src = embed_image(data) if data else (m.screenshot_url or "")
        title = re.sub(r"\b[\w-]+(\.[\w-]+)+\b", "", m.title or "").strip(" |-")
        figs.append({"section": "kit", "src": src, "caption":
                     f"A page from this campaign" + (f" titled “{title[:60]}”" if title else "")
                     + f", imitating {brand} and asking for {', '.join(assets[:2])}."})

    # ---- related, not linked: same brand and same title or kit, different infrastructure
    related = []
    my_ips, my_titles = set(ip_c), Counter(m.title for m in members if m.title)
    top_title = my_titles.most_common(1)[0][0] if my_titles else None
    if c.brand:
        for oc in session.exec(select(PhishCampaign).where(PhishCampaign.brand == c.brand, PhishCampaign.id != c.id)):
            om = session.exec(select(PhishSample).where(PhishSample.campaign_id == oc.id)).all()
            if not om or my_ips & {x.ip for x in om if x.ip}:
                continue
            same_kit = kit is not None and oc.kit_id == kit.id
            same_title = top_title and any(x.title == top_title for x in om)
            if same_kit or same_title:
                x = om[0]
                related.append({"name": defang(x.domain or ""), "text": f"(first seen {_when(x.first_seen)}). "
                                + ("Same kit" if same_kit else "Same page title") + " on different hosting, so the link is not established yet."})
            if len(related) >= 3:
                break

    # ---- hunting
    queries = []
    for ip in dedicated[:2]:
        queries.append(["Same server", [["page.ip:", ip, None]]])
    for h, _ in same_html[:1]:
        queries.append(["Same page on any host", [["hash:", h, None]]])
    if c.brand and spec_b:
        svc = services.most_common(1)[0][0] if services else None
        if svc:
            queries.append(["Next host on the same service", [["page.domain:", f"*{spec_b.slug}*", "AND"], ["page.domain:", f"*{svc}*", None]]])
        else:
            queries.append(["Brand lookalike hosts", [["page.domain:", f"*{spec_b.slug}*", "AND NOT"],
                                                     ["page.apexDomain:", sorted(spec_b.official)[0], None]]])
    if top_title and c.brand and spec_b:
        queries.append(["Title reuse", [["page.title:", f"\"{top_title}\"", "AND NOT"], ["page.apexDomain:", sorted(spec_b.official)[0], None]]])
    proxy = []
    svc0 = services.most_common(1)[0][0] if services else None
    if paths:
        proxy.append("In web proxy logs, alert on requests" + (f" to any [[*.{svc0}]] host" if svc0 else " to the hosts listed below")
                     + " whose path ends in " + " or ".join(f"[[/{defang(p, 'file')}]]" for p, _ in paths.most_common(2)) + ".")
    if dedicated:
        proxy.append("Alert on any connection to " + ", ".join(f"[[{defang(ip, 'ip_full')}]]" for ip in dedicated) + ".")
    if not proxy:
        proxy.append("In web proxy and DNS logs, alert on the hosts and addresses listed under indicators of compromise.")

    # ---- IOCs
    iocs = [["Domain", defang(h), f"Campaign host, first seen {_when(next(m.first_seen for m in members if m.domain == h))[:11]}"] for h in hosts[:20]]
    iocs += [["IPv4", defang(ip, "ip"), (f"Dedicated server, {asn_name.get(ip, '')}" if ip in dedicated else f"Hosting, {asn_name.get(ip, '')}").rstrip(", ")]
             for ip in ip_c if asn_of.get(ip) not in CDN_ASNS][:6]
    iocs += [["SHA-256", h, "Page HTML"] for h, _ in same_html[:2]]
    if paths:
        iocs.append(["URL path", ", ".join(f"/{p}" for p, _ in paths.most_common(4)), "Capture endpoints"])
    for v, _ in exfil_c.most_common(3):
        iocs.append(["Exfiltration", defang(v), "Collection destination"])
    iocs += [["Domain", r["name"], "Related, not linked"] for r in related]

    # ---- ATT&CK
    mitre = []
    if dedicated:
        mitre.append(["T1583.003 Acquire Infrastructure: Virtual Private Server", "Dedicated server hosting every page"])
    if services and any(s in DYN_DNS for s in services):
        mitre.append(["T1583.001 Acquire Infrastructure: Domains", "Brand-themed hostnames on a free dynamic DNS service"])
    elif services:
        mitre.append(["T1583.006 Acquire Infrastructure: Web Services", f"Pages hosted on {', '.join(services)}"])
    else:
        mitre.append(["T1583.001 Acquire Infrastructure: Domains", "Brand-themed lookalike domains"])
    mitre.append(["T1566.002 Phishing: Spearphishing Link", "Delivery method assumed: a link to the lookalike host"])
    if any(a in assets for a in ("account passwords", "usernames / email addresses")):
        mitre.append(["T1056.003 Input Capture: Web Portal Capture", "A fake sign-in page records the details the victim enters"])
    if "one-time / MFA codes" in assets:
        mitre.append(["T1111 Multi-Factor Authentication Interception", "One-time codes collected for immediate reuse"])
    if evasion:
        mitre.append(["T1027 Obfuscated Files or Information", "Encoded or script-built page content"])

    # ---- impact
    short = {"account passwords": "account takeover", "one-time / MFA codes": "real-time bypass of one-time codes",
             "payment-card data": "card fraud", "wallet seed phrases / keys": "irreversible theft of crypto funds",
             "identity data (DOB, SSN, ID numbers)": "identity theft", "usernames / email addresses": "follow-up phishing"}
    effects = list(dict.fromkeys(short[a] for a in assets if a in short))
    impact = [["Customers", "a victim who completes the flow loses " + ", ".join(assets[:3])
               + (", which allows " + " and ".join(effects[:3]) if effects else "") + "."],
              [f"{brand if c.brand else 'The brand'}", "fraud losses and customer reimbursement, plus support load from compromised accounts."]]

    # ---- recommendations
    abuse = []
    if services:
        abuse.append(f"Report the hosts to {', '.join(services)} for takedown")
    if dedicated:
        nets = sorted({(asn_name.get(ip) or "").split(" - ")[-1].split(",")[0].strip() or "the hosting provider" for ip in dedicated})
        abuse.append("report " + ", ".join(defang(ip, "ip") for ip in dedicated) + " to the abuse desk of " + ", ".join(nets))
    if not abuse:
        abuse.append("Request takedown of the hosts listed under indicators of compromise from their registrars and hosting providers")
    rec_brand = ["; ".join(abuse) + ".", "Watch for new hosts with the hunting queries above, checked at least daily."]
    if "one-time / MFA codes" in assets:
        rec_brand.append("Move customers who use SMS codes toward app-based or passkey sign-in, and tell them the bank never asks for a code on a page reached from a link.")
    elif "account passwords" in assets:
        rec_brand.append("Encourage customers to turn on app-based or passkey sign-in, so a stolen password alone does not open the account.")
    blk = [defang(ip, "ip") for ip in dedicated]
    rec_soc = ["Block " + (", ".join(blk) + " and " if blk else "") + "the hosts listed above at web and mail gateways."]
    if paths:
        rec_soc.append("Hunt proxy logs for the " + " and ".join(f"[[{defang(p, 'file')}]]" for p, _ in paths.most_common(2)) + " pattern described above.")
    rec_soc.append(f"Flag {brand + ' ' if c.brand else ''}sessions that start from a new device right after a sign-in from an unfamiliar location, for fraud review.")

    # ---- summary and titles
    title = (f"{brand} phishing campaign on {infra}" if c.brand else f"Phishing campaign on {infra}")
    subtitle = f"{n_hosts} host{'s' if n_hosts != 1 else ''}, {len(live)} live, collecting {', '.join(assets[:2])}"
    summary = [
        f"{operator} is running a {brand + ' ' if c.brand else ''}phishing campaign across {n_hosts} host{'s' if n_hosts != 1 else ''} on {infra}, "
        f"collecting {', '.join(assets[:3])}. "
        + ("The hosts share infrastructure and page content, so we assess them as one operation. " if confidence != "Low" else
           "The hosts share page content but no infrastructure, so the operator link is weak. ")
        + (f"{len(live)} page{'s were' if len(live) != 1 else ' was'} live when last checked." if live else ""),
        "We recommend blocking the listed hosts and addresses at web and mail gateways, filing abuse reports with the hosting "
        "providers, and hunting for the patterns described below. Details and indicators follow.",
    ]
    glance = [
        ["Targeted brand", c.brand or "No single brand"],
        ["Observed hosts", "\n".join(f"{defang(h)} ({_when(next(m.first_seen for m in members if m.domain == h))})" for h in hosts[:6])
         + (f"\n... and {n_hosts - 6} more" if n_hosts > 6 else "")],
        ["Infrastructure", (", ".join(f"[[{defang(ip, 'ip')}]]" + (f" ({asn_name[ip]})" if asn_name.get(ip) else "") for ip, _ in ip_c.most_common(3))
                            + (f"; hosted on {', '.join(services)}" if services else "")) or "Not resolved"],
        ["Data stolen", ", ".join(a[0].upper() + a[1:] for a in assets)],
        ["Operator linkage", f"{confidence} confidence: " + (", ".join(r[0].lower() for r in rows[:4]) or "no shared infrastructure found")],
        ["Status", f"{'Active' if c.status == 'active' else 'Dormant'} in the {scope.window_days}-day window ending "
                   f"{datetime.now(timezone.utc).strftime('%d %b %Y').lstrip('0')}"],
    ]
    now = datetime.now(timezone.utc)
    return {
        "title": title, "subtitle": subtitle, "reporter": reporter, "classification": classification,
        "date": date or now.strftime("%d %B %Y").lstrip("0"), "report_id": f"CTI-P4-{now:%Y-%m}-{c.id:03d}",
        "executive_summary": summary, "at_a_glance": glance,
        "linkage": {"intro": f"The {n_hosts} hosts were grouped by shared infrastructure and page content. "
                             f"{'These observations link them:' if rows else 'No shared infrastructure was found.'}", "rows": rows},
        "kit": {"intro": f"The pages imitate {brand if c.brand else 'a trusted brand'}. Analysis of the page code shows:",
                "steps": steps, "ordered": False, "live_panel": None},
        "figures": figs,
        "related": {"intro": f"Other {brand} pages share the same kit or title but use different hosting, so we track them separately.",
                    "items": related},
        "impact": impact, "hunting": {"queries": queries, "proxy": " ".join(proxy)}, "iocs": iocs, "mitre": mitre,
        "recommendations": [[("For the bank and its brand-protection team" if c.brand in BANK_BRANDS else "For the brand-protection team"), rec_brand],
                            ["For SOC and fraud teams", rec_soc]],
    }


def resolve_images(spec: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    """Figures with a local path become embedded data URIs, so the report is one self-contained file."""
    for f in spec.get("figures", []):
        src = f.get("src") or ""
        if src and not src.startswith(("data:", "http://", "https://")):
            p = (base_dir / src).resolve()
            mime = "image/jpeg" if p.suffix.lower() in (".jpg", ".jpeg") else "image/png"
            f["src"] = embed_image(p.read_bytes(), mime)
    return spec


def render_spec_file(path: str | Path) -> str:
    import json
    p = Path(path)
    spec = json.loads(p.read_text(encoding="utf-8"))
    return render(resolve_images(spec, p.parent))


def merge_overrides(spec: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Analyst edits win: top-level keys replace; dicts (linkage, kit, related, hunting) merge one level."""
    out = dict(spec)
    for k, v in (overrides or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out


# --------------------------------------------------------------------------- brand report (Chase format + brand stats)

LURE_KEYWORDS = ["login", "signin", "secure", "verify", "account", "update", "online", "support", "auth", "confirm",
                 "alert", "service", "bank", "wallet", "recover", "reset", "unlock", "billing", "payment", "help",
                 "access", "portal", "customer", "client", "notice", "suspend", "refund", "claim", "mfa", "otp",
                 "app", "web", "mobile", "id"]
SHORT_KW = {"app", "web", "id", "mfa", "otp"}  # matched as whole tokens only (else 'id' hits every 'paid')
COUNTRY = {"US": "United States", "GB": "United Kingdom", "DE": "Germany", "NL": "Netherlands", "FR": "France",
           "CA": "Canada", "RU": "Russia", "SG": "Singapore", "JP": "Japan", "HK": "Hong Kong", "IN": "India",
           "BR": "Brazil", "AU": "Australia", "IE": "Ireland", "LT": "Lithuania", "BG": "Bulgaria", "CN": "China",
           "TR": "Turkey", "ID": "Indonesia", "VN": "Vietnam", "UA": "Ukraine", "PL": "Poland", "SE": "Sweden",
           "FI": "Finland", "CH": "Switzerland", "ES": "Spain", "IT": "Italy", "KR": "South Korea", "MY": "Malaysia"}


def _keywords(s: PhishSample) -> set[str]:
    from urllib.parse import urlsplit
    raw = s.url or ""
    u = urlsplit(raw if "://" in raw else "http://" + raw)
    text = ((s.domain or u.hostname or "") + " " + u.path).lower()
    toks = [t for t in re.split(r"[^a-z0-9]+", text) if t]
    out = set()
    for k in LURE_KEYWORDS:
        if k in SHORT_KW:
            if k in toks:
                out.add(k)
        elif any(k in t for t in toks):
            out.add(k)
    return out


def _lc(text: str) -> str:
    """Lower-case the first letter unless the sentence starts with a name (Chase, HSBC, A single...)."""
    w = text.split(" ", 1)[0]
    return text if (w[1:2].isupper() or w in BANK_BRANDS or w[:1].isupper() and w.lower() not in ("a", "an", "the", "one"))        else text[0].lower() + text[1:]


def _brand_of(s: PhishSample) -> str | None:
    return s.brand or (s.squat or {}).get("brand")


def brand_landscape(session: Session, brand: str, charts: bool = True) -> dict[str, Any]:
    """Brand-wide numbers and charts for the window (every value computed from the database at build time)."""
    from . import report_charts as ch
    from .report import _credential_surface
    now = datetime.now(timezone.utc)
    scope = load_scope().phishing
    everything = session.exec(select(PhishSample)).all()
    mine = [s for s in everything if _brand_of(s) == brand]
    if not mine:
        raise NotReportable(f"No {brand} pages in the current {scope.window_days}-day window.")
    live = [s for s in mine if s.fetch_status == "ok"]
    camps = [c for c in session.exec(select(PhishCampaign)) if c.brand == brand]
    kits = {s.kit_id for s in mine if s.kit_id}
    tiers = Counter(s.threat_tier for s in mine)
    squats = [s for s in mine if s.detection_type == "typosquat"]
    leads = [d for d in session.exec(select(DomainLead)) if d.brand == brand]
    brands_c = Counter(_brand_of(s) for s in everything if _brand_of(s))
    rank = next((i + 1 for i, (b, _) in enumerate(brands_c.most_common()) if b == brand), None)
    creds = _credential_surface(mine)

    kw_mine = Counter(k for s in mine for k in _keywords(s))
    kw_all = Counter(k for s in everything for k in _keywords(s))
    kw_rows = [(k, c / len(mine), kw_all[k] / max(1, len(everything))) for k, c in kw_mine.most_common(10)]
    countries = Counter(COUNTRY.get(s.country, s.country) for s in mine if s.country)
    tlds = Counter("." + s.tld.lstrip(".") for s in mine if s.tld)
    nets = Counter((s.asn_name or s.asn or "").split(",")[0].strip()[:38] for s in mine if (s.asn_name or s.asn))
    start = (now - timedelta(days=scope.window_days - 1)).date()
    by_day = Counter((_utc(s.first_seen) or now).date() for s in mine)
    days = [((start + timedelta(days=i)).isoformat(), by_day.get(start + timedelta(days=i), 0)) for i in range(scope.window_days)]

    n = {"pages": len(mine), "share": len(mine) / max(1, len(everything)), "live": len(live), "campaigns": len(camps),
         "multi": sum(1 for c in camps if c.sample_count > 1), "kits": len(kits), "lookalike": len(squats),
         "content_only": sum(1 for s in mine if s.detection_type == "content"),
         "new_lookalikes": sum(1 for d in leads if "nrd" in (d.sources or [])),
         "critical_high": tiers.get("critical", 0) + tiers.get("high", 0), "countries": len(countries), "tlds": len(tlds),
         "rank": rank, "brands": len(brands_c)}

    def pc(x):
        return f"{x:.0%}"

    stats = [
        ["Phishing pages", f"{n['pages']} ({pc(n['share'])} of all phishing pages tracked; rank {rank} of {n['brands']} brands)"],
        ["Live when checked", str(n["live"])],
        ["Campaigns", f"{n['campaigns']} ({n['multi']} spanning more than one page)"],
        ["Distinct phishing kits", str(n["kits"])],
        ["Lookalike hostnames", f"{n['lookalike']} pages; {n['content_only']} more show the brand on unrelated hostnames"],
        ["New lookalike domains registered", str(n["new_lookalikes"])],
        ["Rated critical or high", str(n["critical_high"])],
        ["Hosting countries / top-level domains", f"{n['countries']} / {n['tlds']}"],
    ]

    figs = []
    if charts:
        def add(png, caption):
            figs.append({"section": "landscape", "chart": True, "src": embed_image(png), "caption": caption})
        if sum(v for _, v in days):
            add(ch.daily(days, f"New {brand} phishing pages per day"),
                f"New {brand} phishing pages first seen each day, {days[0][0]} to {days[-1][0]}.")
        if kw_rows:
            add(ch.paired_hbar(kw_rows, "Lure keywords in hostnames and paths", brand, "All brands"),
                f"Share of {brand} pages whose hostname or path contains each keyword, against all phishing pages in the dataset.")
        add(ch.hbar(brands_c.most_common(10), "Phishing pages by targeted brand", highlight=brand),
            f"Pages per impersonated brand across the dataset, {brand} highlighted.")
        if countries:
            add(ch.hbar(countries.most_common(10), "Hosting country"),
                f"Countries hosting {brand} phishing pages, by number of pages.")
        if tlds:
            add(ch.hbar(tlds.most_common(10), "Top-level domain"),
                f"Top-level domains used by {brand} phishing hostnames, by number of pages.")
        if nets:
            add(ch.hbar(nets.most_common(8), "Hosting network"),
                f"Networks hosting {brand} phishing pages. Large cloud and CDN networks reflect shared hosting, not operator intent.")
        if creds:
            add(ch.hbar(sorted(((c["asset"], c["pages"]) for c in creds), key=lambda x: -x[1]), "Data requested by live pages"),
                f"What live {brand} phishing pages ask the visitor for, by number of pages.")
    top_kw = ", ".join(f"[[{k}]]" for k, *_ in kw_rows[:4])
    intro = (f"In the {scope.window_days} days to {now.strftime('%d %B %Y').lstrip('0')} we tracked {n['pages']} phishing pages "
             f"impersonating {brand}, {pc(n['share'])} of all phishing pages tracked in that period; {n['live']} were live when checked. "
             + (f"Hostnames and paths most often add the words {top_kw}. " if top_kw else "")
             + (f"Most pages are hosted in {countries.most_common(1)[0][0]}" if countries else "Hosting is spread out")
             + (f", and the most used top-level domain is {tlds.most_common(1)[0][0]}." if tlds else "."))
    return {"numbers": n, "stats": stats, "figures": figs, "intro": intro, "creds": creds, "camps": camps,
            "window_days": scope.window_days, "now": now, "live": live, "mine": mine}


def build_for_brand(session: Session, brand: str, reporter: str, classification: str = "TLP:CLEAR",
                    date: str | None = None, screenshots: str = "embed", charts: bool = True) -> dict[str, Any]:
    """The approved Chase layout for one brand: brand-wide statistics and charts, then the brand's strongest
    reportable campaign in full (linkage, kit, IOCs, hunting). Without a reportable campaign the report covers
    the brand-wide picture only."""
    from .report import _pick_use_case
    land = brand_landscape(session, brand, charts=charts)
    n, now = land["numbers"], land["now"]
    lead_sample = _pick_use_case(session, land["mine"], now, brand)
    lead_cid = lead_sample.campaign_id if lead_sample else None
    # lead campaign: the strongest operator evidence wins (strong linkage rows, then hosts, live, figure)
    order = sorted(land["camps"], key=lambda c: (c.sample_count < 2, c.status != "active", -c.sample_count))[:12]
    best, camp_spec, lead = None, None, None
    for c in order:
        try:
            sp = build_from_campaign(session, c.id, reporter, classification, date, screenshots="link")
        except NotReportable:
            continue
        rows = sp["linkage"]["rows"]
        score = (sum(r[2] == "Strong" for r in rows), len(rows), c.sample_count, bool(sp["figures"]), c.id == lead_cid)
        if best is None or score > best:
            best, lead = score, c
    if lead is not None:
        camp_spec = build_from_campaign(session, lead.id, reporter, classification, date, screenshots)

    period = f"last {land['window_days']} days"
    if camp_spec:
        spec = camp_spec
        first = camp_spec["executive_summary"][0]
        spec["executive_summary"] = [land["intro"], "The most significant campaign: " + _lc(first),
                                     camp_spec["executive_summary"][1]]
        spec["subtitle"] = f"Brand activity in the {period} and the leading campaign: {_lc(camp_spec['title'])}"
        spec["title"] = f"{brand} phishing: {period}"
    else:
        assets = [c["asset"] for c in land["creds"]]
        hosts = sorted(land["live"] or land["mine"], key=lambda s: -(s.threat_score or 0))
        spec = {
            "title": f"{brand} phishing: {period}",
            "subtitle": f"{n['pages']} pages, {n['live']} live, no single operator identified",
            "reporter": reporter, "classification": classification, "date": date or now.strftime("%d %B %Y").lstrip("0"),
            "executive_summary": [land["intro"], "No campaign in this period shows enough shared infrastructure to attribute "
                                  "it to one operator, so this report covers the brand-wide picture. The highest-rated hosts "
                                  "are listed as indicators."],
            "at_a_glance": [["Targeted brand", brand],
                            ["Data stolen", ", ".join(a[0].upper() + a[1:] for a in assets) or "Sign-in details"],
                            ["Status", f"Active in the {land['window_days']}-day window ending {now.strftime('%d %b %Y').lstrip('0')}"]],
            "linkage": {"intro": "", "rows": []}, "kit": {"intro": "", "steps": []},
            "impact": [["Customers", "a victim who completes the flow loses " + (", ".join(assets[:3]) or "their sign-in details") + "."],
                       [brand, "fraud losses and customer reimbursement, plus support load from compromised accounts."]],
            "hunting": {"queries": [], "proxy": "In web proxy and DNS logs, alert on the hosts listed under indicators of compromise."},
            "iocs": [["Domain", defang(s.domain), f"{(s.threat_tier or 'rated').title()} rating, first seen {_when(s.first_seen)[:11]}"]
                     for s in hosts[:20] if s.domain],
            "mitre": [["T1583.001 Acquire Infrastructure: Domains", "Brand-themed lookalike domains"],
                      ["T1566.002 Phishing: Spearphishing Link", "Delivery method assumed: a link to the lookalike host"],
                      ["T1056.003 Input Capture: Web Portal Capture", "A fake sign-in page records the details the victim enters"]],
            "recommendations": [
                [("For the bank and its brand-protection team" if brand in BANK_BRANDS else "For the brand-protection team"),
                 ["Request takedown of the hosts listed under indicators of compromise.",
                  "Watch for new hosts with the hunting queries above, checked at least daily."]],
                ["For SOC and fraud teams", ["Block the hosts listed above at web and mail gateways."]]],
        }
    spec["kicker"] = "THREAT INTELLIGENCE REPORT  |  BRAND PHISHING ANALYSIS"
    slug = re.sub(r"[^A-Z0-9]", "", brand.upper())[:8]
    spec["report_id"] = f"CTI-P4-{now:%Y-%m}-{slug}" + (f"-{lead.id:03d}" if lead else "")
    spec["at_a_glance"] = [["Pages in the " + period, f"{n['pages']} ({n['live']} live, {n['critical_high']} rated critical or high)"]] \
        + spec["at_a_glance"]

    # brand-wide hunting queries first, then the campaign's own
    sc = load_scope().phishing
    sb = build_specs([brand], sc.brand_fragments, sc.brand_domains, sc.brand_exclusions)[0]
    off = sorted(sb.official)[0] if sb.official else None
    bq = [["Any host containing the brand",
           [["page.domain:", f"*{sb.slug}*", "AND NOT" if off else None]] + ([["page.apexDomain:", off, None]] if off else [])]]
    if len(sb.fragments) > 1:
        bq.append(["Split or padded brand spellings", [["page.domain:", "*" + "*".join(sb.fragments) + "*", None]]])
    if off:
        bq.append(["Brand title on other domains", [["page.title:", f"\"{brand}\"", "AND NOT"], ["page.apexDomain:", off, None]]])
    have = {str(q[1]) for q in bq}
    spec["hunting"]["queries"] = bq + [q for q in spec["hunting"]["queries"] if str(q[1]) not in have]
    spec["landscape"] = {"heading": f"{brand} phishing in the {period}", "intro": land["intro"], "stats": land["stats"]}
    spec["figures"] = land["figures"] + spec.get("figures", [])
    return spec
