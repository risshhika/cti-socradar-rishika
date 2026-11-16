"""X (Twitter) IAB monitor: recent-search queries, preserved evidence, financial / fintech extraction.

Passive only: reads public posts through the official X API v2 recent-search endpoint (7-day window) and
downloads attached images from X's own media CDN. Nothing is posted, no account is followed or contacted.

Evidence kept per post, under data/artifacts/x/<tweet_id>/:
  record.json   the API record as received (post, author, media), SHA-256 stored on the row
  media_*.jpg   every attached image at original resolution, SHA-256 stored per image
  card.png      a rendered post card (author, timestamps, URL, text, images, hashes) for reports and review
"""
from __future__ import annotations

import hashlib
import json
import re
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

from ...config import get_settings
from . import iab as iabmod
from .regions import countries_from_text

SEARCH_URL = "https://api.x.com/2/tweets/search/recent"
TWEET_FIELDS = "created_at,author_id,lang,attachments,entities,public_metrics,conversation_id"
MEDIA_FIELDS = "url,preview_image_url,type,width,height,alt_text"
USER_FIELDS = "username,name,created_at,verified"

# Sector narrowing appended to every query so the X read quota is spent on financial / fintech posts only.
SECTOR_CLAUSES = {
    "Financial Services": '(bank OR banking OR fintech OR "financial" OR "credit union" OR insurance OR payments '
                          'OR brokerage OR "crypto exchange" OR lender OR neobank OR "wealth management")',
}

FIN_SUBTYPES: list[tuple[str, re.Pattern[str]]] = [
    ("Credit union", re.compile(r"\bcredit unions?\b", re.I)),
    ("Crypto exchange", re.compile(r"\b(crypto(currency)? exchange|exchange wallet|crypto platform|defi|dex|web3 (wallet|exchange))\b", re.I)),
    ("Payments", re.compile(r"\b(payments?( processor| provider| gateway| company| platform| switch)|psp|acquirer|card processing|merchant services|remittance|money transfer|digital wallet|stored-value)\b", re.I)),
    ("Insurance", re.compile(r"\b(insurance|insurer|underwriter|reinsurance|assurance)\b", re.I)),
    ("Brokerage / asset management", re.compile(r"\b(brokerage|broker-dealer|asset management|wealth management|investment (firm|bank)|hedge fund|trading platform|securities firm|forex (brokers?|trading|platform))\b", re.I)),
    ("Fintech", re.compile(r"\b(fintech|neobank|digital bank\w*|banking app|banking software|bnpl|buy now,? pay later)\b", re.I)),
    ("Bank", re.compile(r"\b(banks?|banking|bancorp|banco|banque|banca|central bank|financial institution|savings and loan|savings and credit)\b", re.I)),
    ("Lending", re.compile(r"\b(lender|lending|mortgage|loans?|microfinance|micro-?lender|credit company)\b", re.I)),
]
FIN_ANY = re.compile("|".join(f"(?:{r.pattern})" for _, r in FIN_SUBTYPES) + r"|\bfinancial\b", re.I)
# false friends: "bank holiday", "food bank" ... and victim *data* types at non-financial firms ("payment details",
# "bank details", "banking records" leaked from a retailer or an agency do not make the victim a financial firm)
FIN_NOISE = re.compile(r"\b(bank holiday|food banks?|blood banks?|power banks?|data banks?|river ?banks?|memory banks?|piggy banks?"
                       r"|payment[- ]?(?:card )?(?:information|info|details|data)|(?:payroll )?bank(?:ing)? (?:details|records|information|data|account details)"
                       r"|payments? (?:and|or) (?:card|billing)|billing and payment)\b", re.I)

FORUMS = {"Exploit": r"\bexploit(\.in| forum)\b", "XSS": r"\bxss(\.is| forum)\b", "BreachForums": r"\bbreach ?forums?\b",
          "RAMP": r"\bramp (forum|marketplace)\b|\bramp4u\b", "DarkForums": r"\bdark ?forums\b", "LeakBase": r"\bleak ?base\b",
          "Telegram": r"\btelegram (channel|group|shop)\b"}
FORUM_RES = {k: re.compile(v, re.I) for k, v in FORUMS.items()}

# victim candidates: names ending in a financial word, "Bank of X", or a domain in the text
ORG_RE = re.compile(
    r"\b((?:[A-Z][\w&'.-]*[ ]){0,4}(?:Bank|Bancorp|Banco|Banque|Credit Union|Financial|Finance|Capital|Securities|Insurance|"
    r"Assurance|Payments?|Pay|Trust|Savings|Investments?|Holdings|Exchange|Brokerage|Fintech)"
    r"(?:[ ](?:of|de|del|do)(?:[ ][A-Z][\w&'.-]*){1,3})?)\b")
NOISE_WORDS = (r"(?:The|A|An|Selling|Sale|Access|Initial|Breach|Hacked|Leaked|Alleged|Allegedly|New|US|USA|UK|EU|From|Preventive|"
               r"Alert|Data|Exfiltration|Seller|Seller Claims|Claims|Claim|Tied|To|Account|Card|And|Of|Customer|Confirms|"
               r"Database|Leak|For|Lists|Listed|Ransom|Inc)")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|co|bank|finance|fi|uk|de|fr|it|es|nl|ch|au|ca|in|br|mx|sg|ae|sa|tr|pl|ru|ua|za|ng|ke|id|my|ph|vn|hk|jp|kr|cn|tw|us|eu))\b", re.I)
GENERIC_ORG = {"bank", "the bank", "a bank", "us bank", "financial", "finance", "capital", "insurance", "payments", "pay",
               "trust", "exchange", "holdings", "investments", "investment", "securities", "savings", "brokerage", "fintech",
               "credit union", "initial access", "access", "breach", "corporate access", "crypto exchange",
               "digital bank", "central bank", "payment platform", "financial services"}
NOT_VICTIM_DOMAINS = re.compile(r"(^|\.)(x|twitter|t|tiktok|youtube|youtu|github|medium|linkedin|facebook|instagram|telegram|t\.me|"
                                r"bleepingcomputer|therecord|securityweek|darkreading|thehackernews|databreaches|cybernews|"
                                r"hackread|socradar|kelacyber|kela|flashpoint|intel471|hudsonrock|falconfeeds|darkwebinformer|"
                                r"ransomware\.live|ransomlook|bit|ow|lnkd|tinyurl|archive)\.(com|co|io|net|org|ly|me|in|live|is|ph)$", re.I)


# --------------------------------------------------------------------------- query building

ACCOUNTS_LABEL = "Watched accounts"


def account_query(handles: list[str]) -> str | None:
    """Everything the watched accounts post (no has:images: their text posts name victims too)."""
    hs = [h.strip().lstrip("@") for h in handles if h and h.strip()]
    if not hs:
        return None
    return "(" + " OR ".join(f"from:{h}" for h in hs) + ")"


def all_queries(queries: list[dict[str, str]], accounts: list[str]) -> list[dict[str, str]]:
    """The keyword queries plus one query for the watched accounts (sector narrowing is added by build_query)."""
    out = list(queries)
    aq = account_query(accounts)
    if aq:
        out.append({"label": ACCOUNTS_LABEL, "query": aq})
    return out


def build_query(q: str, sectors: list[str]) -> str:
    """User query + sector narrowing + no retweets. X caps a query at 512 characters (Basic)."""
    clauses = [SECTOR_CLAUSES[s] for s in sectors if s in SECTOR_CLAUSES]
    already_fin = bool(re.search(r"\b(bank|fintech|financial)\b", q, re.I))
    out = q.strip()
    if clauses and not already_fin:
        out += " " + clauses[0]
    if "-is:retweet" not in out:
        out += " -is:retweet"
    return out[:512]


# --------------------------------------------------------------------------- extraction

def financial_terms(text: str) -> list[str]:
    clean = FIN_NOISE.sub(" ", text)
    return sorted({m.group(0).lower() for m in FIN_ANY.finditer(clean)})


def fin_subtype(text: str) -> str | None:
    clean = FIN_NOISE.sub(" ", text)
    for name, rx in FIN_SUBTYPES:
        if rx.search(clean):
            return name
    return "Financial (unspecified)" if re.search(r"\bfinancial\b", clean, re.I) else None


def victim_candidates(text: str, links: list[str]) -> list[str]:
    out: list[str] = []
    # lines written in capitals ("ALLEGED EXFILTRATION FROM QATAR NATIONAL BANK") are title-cased first
    lines = [(ln.title().replace(" Of ", " of ").replace(" De ", " de ") if sum(c.isupper() for c in ln) > 0.6 * max(1, sum(c.isalpha() for c in ln)) else ln)
             for ln in text.splitlines()]
    for m in ORG_RE.finditer("\n".join(lines)):
        name = (m.group(1) or "").strip(" .,-")
        while re.match(NOISE_WORDS + r"\s+", name):
            name = re.sub("^" + NOISE_WORDS + r"\s+", "", name)
        if len(name) > 3 and name.lower() not in GENERIC_ORG and " " in name:
            out.append(name)
    hosts = [urlsplit(u).hostname or "" for u in links] + [d.lower() for d in DOMAIN_RE.findall(text)]
    for h in hosts:
        h = h.lower().removeprefix("www.")
        if h and not NOT_VICTIM_DOMAINS.search(h) and "." in h:
            out.append(h)
    return list(dict.fromkeys(out))[:8]


# IAB shorthand: "$1.2B revenue", "rev: 500M", "revenue $80kk"
_REV_SHORT = re.compile(r"(?:rev(?:enue)?|turnover|annual sales)\s*[:=~-]?\s*(?:of\s*)?\$?\s*(\d+(?:[.,]\d+)?)\s*(kk|k|m|mm|mln|b|bn|bln|billion|million)\b"
                        r"|\$\s*(\d+(?:[.,]\d+)?)\s*(kk|k|m|mm|mln|b|bn|bln|billion|million)\b\s*(?:in\s*)?(?:rev(?:enue)?|turnover|annual sales)", re.I)
_MULT = {"k": 1e3, "kk": 1e6, "m": 1e6, "mm": 1e6, "mln": 1e6, "million": 1e6, "b": 1e9, "bn": 1e9, "bln": 1e9, "billion": 1e9}


def claimed_revenue(text: str) -> float | None:
    m = _REV_SHORT.search(text)
    if m:
        num, unit = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        return float(num.replace(",", ".")) * _MULT[unit.lower()]
    return iabmod.extract_revenue(text)


# Named technology / products in a listing. The VPN and edge appliances (dorkable: True) can be searched for
# on Shodan to narrow down which exposed host belongs to an unnamed victim; EDR agents are not internet-facing.
TECH_PATTERNS: list[tuple[str, str, bool]] = [
    ("Pulse Secure", r"pulse ?(?:secure|connect)|ivanti connect secure|pulse vpn", True),
    ("Citrix", r"citrix|netscaler|citrix gateway", True),
    ("Fortinet", r"fortinet|fortigate|fortios|forticlient|forti ?vpn", True),
    ("Cisco AnyConnect", r"anyconnect|cisco asa|cisco ?vpn", True),
    ("GlobalProtect", r"globalprotect|global protect|palo alto|pan-os", True),
    ("SonicWall", r"sonicwall|sonic ?wall", True),
    ("Check Point", r"check ?point", True),
    ("Carbon Black", r"carbon ?black", False),
    ("CrowdStrike", r"crowdstrike|falcon sensor", False),
    ("SentinelOne", r"sentinelone|sentinel one", False),
]
TECH_RES = [(name, re.compile(rx, re.I), dork) for name, rx, dork in TECH_PATTERNS]
HOST_COUNT = re.compile(r"(\d[\d,]*)\s*\+?\s*(?:hosts|endpoints|machines|systems|workstations|servers|devices)", re.I)


def tech_stack(text: str) -> list[str]:
    return [name for name, rx, _ in TECH_RES if rx.search(text)]


def host_count(text: str) -> int | None:
    m = HOST_COUNT.search(text)
    return int(m.group(1).replace(",", "")) if m else None


def extract(text: str, links: list[str], alt_texts: list[str]) -> dict[str, Any]:
    full = " ".join([text] + alt_texts)
    pmin, pmax = iabmod.extract_prices(full)
    return {
        "financial_terms": financial_terms(full), "fin_subtype": fin_subtype(full),
        "access_types": iabmod.extract_access_types(full), "price_usd_min": pmin, "price_usd_max": pmax,
        "claimed_revenue_usd": claimed_revenue(full), "countries": countries_from_text(full),
        "forums": [k for k, rx in FORUM_RES.items() if rx.search(full)],
        "victim_candidates": victim_candidates(text, links), "relevance": iabmod.relevance_score(full),
        "tech": tech_stack(full), "host_count": host_count(full),
    }


def in_sectors(ex: dict[str, Any], sectors: list[str]) -> bool:
    return "Financial Services" in sectors and bool(ex["financial_terms"])


# --------------------------------------------------------------------------- X API

class XUnavailable(RuntimeError):
    pass


def search(query: str, token: str, start_time: datetime | None = None, since_id: str | None = None,
           max_pages: int = 2, client: httpx.Client | None = None) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    """Recent search, newest first. Returns (posts with author/media joined, newest id, meta)."""
    own = client is None
    client = client or httpx.Client(timeout=30)
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "ctiops-iab-monitor/0.1"}
    params: dict[str, Any] = {"query": query, "max_results": 100, "tweet.fields": TWEET_FIELDS,
                              "expansions": "attachments.media_keys,author_id", "media.fields": MEDIA_FIELDS,
                              "user.fields": USER_FIELDS}
    if since_id:
        params["since_id"] = since_id
    elif start_time:
        params["start_time"] = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    posts, newest, meta_out = [], None, {"pages": 0, "result_count": 0}
    try:
        for _ in range(max_pages):
            r = client.get(SEARCH_URL + "?" + urlencode(params), headers=headers)
            if r.status_code == 401:
                raise XUnavailable("X API rejected the bearer token (401)")
            if r.status_code == 403:
                raise XUnavailable("X API access tier does not include recent search (403)")
            if r.status_code == 429:
                reset = r.headers.get("x-rate-limit-reset")
                meta_out["rate_limited_until"] = reset
                break
            r.raise_for_status()
            body = r.json()
            meta = body.get("meta", {})
            meta_out["pages"] += 1
            meta_out["result_count"] += meta.get("result_count", 0)
            newest = newest or meta.get("newest_id")
            inc = body.get("includes", {})
            users = {u["id"]: u for u in inc.get("users", [])}
            media = {m["media_key"]: m for m in inc.get("media", [])}
            for t in body.get("data", []):
                keys = (t.get("attachments") or {}).get("media_keys", [])
                posts.append({"tweet": t, "author": users.get(t.get("author_id"), {}),
                              "media": [media[k] for k in keys if k in media]})
            if not meta.get("next_token"):
                break
            params["next_token"] = meta["next_token"]
    finally:
        if own:
            client.close()
    return posts, newest, meta_out


# --------------------------------------------------------------------------- evidence

def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def evidence_dir(tweet_id: str) -> Path:
    d = get_settings().artifacts_dir / "x" / re.sub(r"\D", "", tweet_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_record(p: dict[str, Any]) -> tuple[str, str]:
    d = evidence_dir(p["tweet"]["id"])
    raw = json.dumps(p, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")
    (d / "record.json").write_bytes(raw)
    return str((d / "record.json").relative_to(get_settings().artifacts_dir)), _sha(raw)


def save_media(p: dict[str, Any], client: httpx.Client) -> list[dict[str, Any]]:
    """Images at original size from X's media CDN (pbs.twimg.com); video posters for videos/GIFs."""
    d = evidence_dir(p["tweet"]["id"])
    out = []
    for i, m in enumerate(p["media"]):
        src = m.get("url") or m.get("preview_image_url")
        rec = {"key": m.get("media_key"), "type": m.get("type"), "url": src, "alt": m.get("alt_text"),
               "width": m.get("width"), "height": m.get("height"), "path": None, "sha256": None}
        host = urlsplit(src or "").hostname or ""
        if src and host.endswith("twimg.com"):
            fetch = src + ("?name=orig" if m.get("type") == "photo" and "?" not in src else "")
            try:
                r = client.get(fetch, timeout=30)
                if r.status_code == 200 and r.headers.get("content-type", "").startswith("image/"):
                    ext = ".png" if "png" in r.headers["content-type"] else ".jpg"
                    f = d / f"media_{i + 1}{ext}"
                    f.write_bytes(r.content)
                    rec["path"] = str(f.relative_to(get_settings().artifacts_dir))
                    rec["sha256"] = _sha(r.content)
            except httpx.HTTPError:
                pass
        out.append(rec)
    return out


def _font(size: int, bold: bool = False):
    from PIL import ImageFont
    import matplotlib
    base = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
    for name in (["arialbd.ttf", "DejaVuSans-Bold.ttf"] if bold else ["arial.ttf", "DejaVuSans.ttf"]):
        for root in (Path("C:/Windows/Fonts"), base):
            if (root / name).exists():
                return ImageFont.truetype(str(root / name), size)
    return ImageFont.load_default()


def render_card(post: dict[str, Any], media: list[dict[str, Any]], raw_sha: str, query_labels: list[str]) -> tuple[str, str]:
    """A self-describing evidence image of the post: who, when, where, what, and the hashes of what was kept."""
    from PIL import Image, ImageDraw
    t, a = post["tweet"], post["author"]
    W, pad = 1000, 32
    f_b, f_r, f_s, f_t = _font(22, True), _font(20), _font(15), _font(21)
    lines = []
    for para in (t.get("text") or "").splitlines() or [""]:
        lines += textwrap.wrap(para, 78) or [""]
    imgs = []
    art = get_settings().artifacts_dir
    for m in media:
        if m.get("path"):
            try:
                im = Image.open(art / m["path"]).convert("RGB")
                im.thumbnail(((W - 2 * pad - 12) // (2 if len(media) > 1 else 1), 520))
                imgs.append((im, m))
            except Exception:
                continue
    rows = [imgs[i:i + 2] for i in range(0, len(imgs), 2)]
    img_h = sum(max(im.height for im, _ in r) + 12 for r in rows)
    H = pad + 34 + 26 + 26 + 18 + len(lines) * 28 + 16 + img_h + 20 + 4 * 22 + pad
    card = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(card)
    d.rectangle([0, 0, W - 1, H - 1], outline="#C9D3E0", width=2)
    d.rectangle([0, 0, 8, H], fill="#12305A")
    y = pad
    d.text((pad, y), f"{a.get('name') or 'Unknown'}  @{a.get('username') or t.get('author_id')}", font=f_b, fill="#0B1F3A")
    y += 34
    created = t.get("created_at", "")
    d.text((pad, y), f"Posted {created.replace('T', ' ').replace('.000Z', ' UTC')}   |   captured "
                     f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}", font=f_s, fill="#4A5566")
    y += 26
    d.text((pad, y), f"https://x.com/{a.get('username') or 'i'}/status/{t['id']}", font=f_s, fill="#1D5FBF")
    y += 26 + 18
    for ln in lines:
        d.text((pad, y), ln, font=f_t, fill="#1F2733")
        y += 28
    y += 16
    for r in rows:
        x = pad
        for im, _ in r:
            card.paste(im, (x, y))
            d.rectangle([x, y, x + im.width, y + im.height], outline="#C9D3E0")
            x += im.width + 12
        y += max(im.height for im, _ in r) + 12
    y += 20
    d.line([pad, y - 8, W - pad, y - 8], fill="#E1E6EE")
    d.text((pad, y), "Matched queries: " + ", ".join(query_labels), font=f_s, fill="#4A5566")
    d.text((pad, y + 22), f"API record SHA-256: {raw_sha}", font=f_s, fill="#4A5566")
    for i, m in enumerate([m for m in media if m.get("sha256")][:2]):
        d.text((pad, y + 44 + 22 * i), f"Image {i + 1} SHA-256: {m['sha256']}", font=f_s, fill="#4A5566")
    import io
    buf = io.BytesIO()
    card.save(buf, format="PNG", optimize=True)
    data = buf.getvalue()
    f = evidence_dir(t["id"]) / "card.png"
    f.write_bytes(data)
    return str(f.relative_to(art)), _sha(data)


def window_start(days: int = 7) -> datetime:
    # recent search reaches back 7 days; stay a minute inside the edge
    return datetime.now(timezone.utc) - timedelta(days=min(days, 7)) + timedelta(minutes=1)
