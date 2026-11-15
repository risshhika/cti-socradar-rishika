"""De-duplication for P4 samples.

The same phishing page reaches us many times: urlscan and OpenPhish both report it, every victim
gets a personalised link (/x7Kq9.../?email=bob@corp.com), and scanners resubmit with and without
`www.`, trailing slashes or tracking parameters. Counting each as a separate sample inflates
campaigns and wastes fetches. Three levels, cheapest first:

  1. canonical URL  (before fetch) -- host without www, no scheme/port/fragment, tracking and
     victim parameters dropped, random path segments templated. Same key = same page.
  2. same host + identical HTML (after fetch) -- byte-identical capture under different URLs.
  3. same host + same DOM structure (after features) -- the page differs only in injected values
     (victim email, CSRF token), so the tag-sequence simhash is identical.

Duplicates are merged into one *primary* sample (live capture first, then urlscan scan with a
screenshot, then earliest seen). The primary keeps every source, the earliest first_seen, the
union of tags and up to 25 alternate URLs, so nothing reported by a feed is lost.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlsplit

# Parameters that identify the victim or the click, never the page.
DROP_PARAMS = {
    "email", "e", "mail", "em", "user", "username", "usr", "u", "login", "uid", "userid", "id_user", "account",
    "token", "t", "tok", "session", "sessionid", "sid", "ssid", "key", "k", "hash", "h", "code", "otp", "nonce",
    "ref", "referrer", "src", "source", "cid", "rid", "clickid", "click_id", "fbclid", "gclid", "msclkid", "dclid",
    "mc_eid", "mc_cid", "_hsenc", "_hsmi", "igshid", "yclid", "trk", "track", "tracking", "campaign", "c", "s", "v",
    "ts", "time", "timestamp", "cache", "cb", "_", "r", "rand", "random", "lang", "locale", "hl",
}
EMAIL = re.compile(r"[^/@\s]+@[^/@\s]+\.[a-z]{2,}", re.I)
B64_EMAIL = re.compile(r"^[A-Za-z0-9+/_-]{12,}={0,2}$")
RAND = re.compile(r"^(?=.*\d)(?=.*[a-zA-Z])[A-Za-z0-9_\-]{12,}$")
HEX = re.compile(r"^[a-f0-9]{8,}$", re.I)
NUM = re.compile(r"^\d{3,}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _segment(seg: str) -> str:
    seg = unquote(seg)
    if EMAIL.search(seg):
        return "{email}"
    base, dot, ext = seg.rpartition(".")
    if dot and 1 <= len(ext) <= 5 and ext.isalpha() and base:
        return f"{_segment(base)}.{ext.lower()}"
    if UUID.match(seg):
        return "{uuid}"
    if HEX.match(seg):
        return "{hex}"
    if NUM.match(seg):
        return "{num}"
    if RAND.match(seg) or (len(seg) >= 24 and B64_EMAIL.match(seg)):
        return "{rand}"
    return seg.lower()


def canonical_host(host: str | None) -> str:
    host = (host or "").lower().strip().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def canonical_url(url: str) -> str:
    """Stable key for 'the same page'. Not a valid URL -- only for comparison."""
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip().lower()
    host = canonical_host(p.hostname)
    if p.port and p.port not in (80, 443):
        host = f"{host}:{p.port}"
    segs = [s for s in re.split(r"/+", p.path or "") if s]
    path = "/" + "/".join(_segment(s) for s in segs)
    if path in ("/index.html", "/index.php", "/index.htm", "/default.aspx"):
        path = "/"
    keys = sorted({k.lower() for k, v in parse_qsl(p.query, keep_blank_values=True)
                   if k.lower() not in DROP_PARAMS and not k.lower().startswith("utm_") and not EMAIL.search(v or "")})
    return host + path + (("?" + "&".join(keys)) if keys else "")


def primary_rank(s) -> tuple:
    """Lower sorts first: live capture, then urlscan scan (has screenshot/uuid), then earliest seen, then lowest id."""
    seen = s.first_seen.timestamp() if s.first_seen else float("inf")
    return (0 if s.fetch_status == "ok" else 1, 0 if s.source_id else 1, seen, s.id or 0)
