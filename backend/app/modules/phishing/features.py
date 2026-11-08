"""HTML feature extraction for P4 (BeautifulSoup + lxml).

Produces the `features` dict stored on PhishSample plus a 64-bit DOM simhash used for structural clustering.
Simhash follows Charikar (2002) as popularised by Manku et al. (2007) for near-duplicate detection.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from .collectors import split_host

BRAND_KEYWORDS: dict[str, list[str]] = {
    "PayPal": ["paypal", "pp-logo", "paypalobjects"],
    "Chase": ["chase", "jpmorgan", "chase.com"],
    "Wells Fargo": ["wells fargo", "wellsfargo"],
    "Bank of America": ["bank of america", "bankofamerica", "bofa"],
    "HSBC": ["hsbc"],
    "Barclays": ["barclays"],
    "Santander": ["santander"],
    "Revolut": ["revolut"],
    "Coinbase": ["coinbase"],
    "Binance": ["binance"],
    "Microsoft": ["microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint", "microsoftonline", "msftauth"],
    "Google": ["google", "gmail", "gstatic"],
    "Apple": ["apple id", "icloud", "appleid"],
    "Amazon": ["amazon"],
    "Netflix": ["netflix"],
    "DHL": ["dhl"],
    "USPS": ["usps"],
    "Facebook": ["facebook", "meta business"],
    "Instagram": ["instagram"],
    "WhatsApp": ["whatsapp"],
    "Telegram": ["telegram"],
    "Steam": ["steampowered", "steam community"],
    "MetaMask": ["metamask"],
    "Trust Wallet": ["trust wallet", "trustwallet"],
    "LinkedIn": ["linkedin"],
    "DocuSign": ["docusign"],
    "Adobe": ["adobe", "acrobat"],
    "Dropbox": ["dropbox"],
    "Capital One": ["capital one", "capitalone"],
    "Citi": ["citibank", "citi.com"],
    "American Express": ["american express", "americanexpress", "amex"],
    "Zelle": ["zelle"],
    "Cash App": ["cash app", "cashapp"],
    "Venmo": ["venmo"],
    "Netease": ["netease", "163.com"],
    "Yahoo": ["yahoo"],
    "AT&T": ["att.net", "at&t"],
    "Spotify": ["spotify"],
    "Roblox": ["roblox"],
    "Discord": ["discord"],
}

OBFUSCATION_PATTERNS = {
    "eval": re.compile(r"\beval\s*\("),
    "atob": re.compile(r"\batob\s*\("),
    "unescape": re.compile(r"\bunescape\s*\("),
    "fromCharCode": re.compile(r"String\.fromCharCode"),
    "packer": re.compile(r"eval\(function\(p,a,c,k,e,"),
    "long_hex": re.compile(r"(\\x[0-9a-fA-F]{2}){12,}"),
    "long_base64": re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"),
    "document_write": re.compile(r"document\.write\s*\("),
}
ANTIBOT_PATTERNS = {
    "cloudflare_turnstile": re.compile(r"challenges\.cloudflare\.com/turnstile"),
    "recaptcha": re.compile(r"google\.com/recaptcha|grecaptcha"),
    "hcaptcha": re.compile(r"hcaptcha\.com"),
    "devtools_block": re.compile(r"disableDevtool|oncontextmenu\s*=|keyCode\s*==\s*123|debugger;"),
    "ua_check": re.compile(r"HTTP_USER_AGENT|navigator\.userAgent", re.I),
    "ip_lookup": re.compile(r"ipapi\.co|ip-api\.com|ipinfo\.io|ipgeolocation", re.I),
    "bot_blocklist": re.compile(r"googlebot|phishtank|urlscan|netcraft|bingbot|crawler", re.I),
    "blur_background": re.compile(r"filter:\s*blur\(", re.I),
}
EXFIL_PATTERNS = {
    "telegram_bot": re.compile(r"api\.telegram\.org/bot(\d{6,}:[A-Za-z0-9_-]{30,})"),
    "discord_webhook": re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@(?:gmail|yandex|protonmail|outlook|hotmail|mail)\.(?:com|ru|ch)"),
    "form_service": re.compile(r"(formspree\.io|getform\.io|formsubmit\.co|emailjs\.com|usebasin\.com|formcarry\.com)[^\"'\s]*"),
    "firebase": re.compile(r"[a-z0-9-]+\.firebaseio\.com|firebasestorage\.googleapis\.com"),
}
PATH_MARKERS = re.compile(r"/(login|signin|sign-in|verify|verification|secure|account|update|billing|confirm|auth|validate|webmail|owa|office|wallet|connect|sync|unlock|limited)[a-z0-9_-]*(?=\.php|\.html|/|$|\?)", re.I)
RANDOM_DIR = re.compile(r"/[A-Za-z0-9]{16,}/")
STOPWORDS = set("the a an and or of to in for on with your you is are be this that it as at by from we our not can will if".split())
WORD = re.compile(r"[a-z][a-z0-9'-]{2,}")


def _hash64(token: str) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode("utf-8", "replace"), digest_size=8).digest(), "big")


def simhash(tokens: list[str]) -> int:
    """64-bit simhash of a token multiset (weights = occurrences)."""
    if not tokens:
        return 0
    v = [0] * 64
    for tok, w in Counter(tokens).items():
        h = _hash64(tok)
        for i in range(64):
            v[i] += w if (h >> i) & 1 else -w
    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= 1 << i
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def dom_tokens(soup: BeautifulSoup) -> tuple[list[str], int, int]:
    """Tag-sequence tokens (tag + depth bucket + class count) plus tag_count and max depth."""
    tokens: list[str] = []
    max_depth = 0
    count = 0
    root = soup.find("html") or soup
    # iterative DFS: real phishing pages can nest thousands of levels deep (obfuscated / broken markup)
    stack = [(child, 0) for child in reversed(list(getattr(root, "children", [])))]
    while stack and count < 20000:
        node, depth = stack.pop()
        name = getattr(node, "name", None)
        if not name:
            continue
        count += 1
        max_depth = max(max_depth, depth)
        classes = node.get("class") or []
        tokens.append(f"{name}|{min(depth // 2, 9)}|{min(len(classes), 3)}")
        stack.extend((c, depth + 1) for c in reversed(list(getattr(node, "children", []))))
    return tokens, count, max_depth


def detect_brand(text: str, title: str | None, url: str, hint: str | None) -> tuple[str | None, float]:
    hay_title = (title or "").lower()
    hay_url = url.lower()
    hay_text = text.lower()[:20000]
    scores: dict[str, float] = {}
    for brand, kws in BRAND_KEYWORDS.items():
        s = 0.0
        for kw in kws:
            if kw in hay_title:
                s += 2.0
            if kw.replace(" ", "") in hay_url.replace("-", "").replace(".", ""):
                s += 1.0
            n = hay_text.count(kw)
            if n:
                s += min(n, 5) * 0.4
        if s:
            scores[brand] = s
    if hint and hint in BRAND_KEYWORDS:
        scores[hint] = scores.get(hint, 0) + 0.8
    if not scores:
        return (hint, 0.3) if hint else (None, 0.0)
    brand, s = max(scores.items(), key=lambda kv: kv[1])
    conf = min(0.98, 0.35 + s / 10)
    return brand, round(conf, 2)


def extract_features(html: str, url: str, brand_hint: str | None = None) -> dict[str, Any]:
    soup = BeautifulSoup(html or "", "lxml")
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        c.extract()
    final_host, final_apex, _ = split_host(url)
    title = (soup.title.get_text(" ", strip=True) if soup.title else None) or None

    forms: list[dict[str, Any]] = []
    input_names: set[str] = set()
    form_actions: set[str] = set()
    has_password = False
    for f in soup.find_all("form"):
        action = (f.get("action") or "").strip()
        abs_action = urljoin(url, action) if action else url
        action_host = urlparse(abs_action).hostname
        inputs = []
        for inp in f.find_all(["input", "select", "textarea"]):
            name = (inp.get("name") or inp.get("id") or "").strip().lower()
            itype = (inp.get("type") or inp.name or "text").lower()
            if itype == "password":
                has_password = True
            if name and itype not in ("hidden", "submit", "button"):
                input_names.add(name)
            inputs.append({"name": name, "type": itype})
        forms.append({"action": abs_action, "action_host": action_host, "method": (f.get("method") or "get").lower(),
                      "inputs": inputs[:30], "external_action": bool(action_host and action_host != final_host)})
        form_actions.add(abs_action)

    scripts_src: list[str] = []
    script_hosts: set[str] = set()
    inline_scripts = 0
    inline_js = []
    for sc in soup.find_all("script"):
        src = sc.get("src")
        if src:
            abs_src = urljoin(url, src)
            scripts_src.append(abs_src)
            h = urlparse(abs_src).hostname
            if h and h != final_host:
                script_hosts.add(h.lower())
        else:
            inline_scripts += 1
            inline_js.append(sc.get_text())
    js_blob = "\n".join(inline_js)

    link_hosts: set[str] = set()
    favicon = None
    for ln in soup.find_all("link"):
        href = ln.get("href")
        rel = " ".join(ln.get("rel") or []).lower()
        if href:
            abs_href = urljoin(url, href)
            h = urlparse(abs_href).hostname
            if h and h != final_host:
                link_hosts.add(h.lower())
            if "icon" in rel and not favicon:
                favicon = abs_href
    meta_generator = None
    for m in soup.find_all("meta"):
        if (m.get("name") or "").lower() == "generator":
            meta_generator = m.get("content")
    image_hosts: set[str] = set()
    image_names: list[str] = []
    for img in soup.find_all("img"):
        src = img.get("src") or ""
        if src.startswith("data:"):
            continue
        abs_src = urljoin(url, src)
        h = urlparse(abs_src).hostname
        if h and h != final_host:
            image_hosts.add(h.lower())
        name = urlparse(abs_src).path.rsplit("/", 1)[-1].lower()
        if name:
            image_names.append(name)

    for t in soup(["script", "style", "noscript"]):
        t.extract()
    text = soup.get_text(" ", strip=True)
    words = [w for w in WORD.findall(text.lower()) if w not in STOPWORDS]
    text_tokens = [w for w, _ in Counter(words).most_common(200)]

    raw = html or ""
    obfuscation = [k for k, p in OBFUSCATION_PATTERNS.items() if p.search(raw)]
    antibot = [k for k, p in ANTIBOT_PATTERNS.items() if p.search(raw)]
    exfil: list[dict[str, str]] = []
    for kind, p in EXFIL_PATTERNS.items():
        for m in p.finditer(raw):
            val = m.group(0)
            if kind == "telegram_bot":
                val = "api.telegram.org/bot" + m.group(1)[:12] + "…"
            exfil.append({"type": kind, "value": val[:160]})
            if len(exfil) > 20:
                break
    for f in forms:
        if f["external_action"]:
            exfil.append({"type": "form_action", "value": f["action"][:200]})

    path = urlparse(url).path or "/"
    path_markers = sorted({m.group(1).lower() for m in PATH_MARKERS.finditer(path)})
    if RANDOM_DIR.search(path):
        path_markers.append("random_token_dir")
    if re.search(r"\.php($|\?)", path):
        path_markers.append("php")
    path_tokens = [p.lower() for p in re.split(r"[/._-]+", path) if p and not re.fullmatch(r"[A-Za-z0-9]{12,}", p)][:12]

    brand, brand_conf = detect_brand(text, title, url, brand_hint)
    tokens, tag_count, depth = dom_tokens(soup)
    struct = simhash(tokens)

    favicon_hash = hashlib.sha1(favicon.encode()).hexdigest()[:12] if favicon else None
    return {
        "title": title,
        "forms": forms[:10],
        "form_count": len(forms),
        "has_password_field": has_password,
        "input_names": sorted(input_names)[:40],
        "form_actions": sorted(form_actions)[:10],
        "scripts": scripts_src[:40],
        "script_hosts": sorted(script_hosts)[:30],
        "inline_script_count": inline_scripts,
        "inline_js_bytes": len(js_blob),
        "link_hosts": sorted(link_hosts)[:30],
        "image_hosts": sorted(image_hosts)[:30],
        "image_names": image_names[:30],
        "favicon": favicon,
        "favicon_hash": favicon_hash,
        "meta_generator": meta_generator,
        "text_tokens": text_tokens,
        "text_length": len(text),
        "obfuscation": obfuscation,
        "antibot": antibot,
        "exfil": exfil[:25],
        "path_markers": path_markers,
        "path_tokens": path_tokens,
        "brand": brand,
        "brand_confidence": brand_conf,
        "tag_count": tag_count,
        "dom_depth": depth,
        "struct_hash": f"{struct:016x}",
        "final_host": final_host,
        "final_apex": final_apex,
    }


def feature_set(features: dict[str, Any]) -> set[str]:
    """Flattened token set used for Jaccard similarity between samples."""
    s: set[str] = set()
    s.update(f"in:{n}" for n in features.get("input_names", []))
    s.update(f"sh:{h}" for h in features.get("script_hosts", []))
    s.update(f"pt:{t}" for t in features.get("path_tokens", []))
    s.update(f"pm:{t}" for t in features.get("path_markers", []))
    s.update(f"tx:{t}" for t in features.get("text_tokens", [])[:60])
    s.update(f"ob:{t}" for t in features.get("obfuscation", []))
    s.update(f"ab:{t}" for t in features.get("antibot", []))
    s.update(f"im:{t}" for t in features.get("image_names", [])[:15])
    if features.get("favicon_hash"):
        s.add(f"fav:{features['favicon_hash']}")
    if features.get("meta_generator"):
        s.add(f"gen:{features['meta_generator']}")
    for e in features.get("exfil", []):
        s.add(f"ex:{e['type']}")
    for f in features.get("forms", []):
        if f.get("action_host"):
            s.add(f"fa:{f['action_host']}")
    return s
