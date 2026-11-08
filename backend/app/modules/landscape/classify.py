"""Victim classification: sector taxonomy normalisation, keyword / LLM sector inference, size banding."""
from __future__ import annotations

import re
import unicodedata
from typing import Any

from ..common import llm

SECTORS: list[str] = [
    "Professional Services", "Manufacturing", "Technology", "Healthcare", "Retail & E-Commerce",
    "Financial Services", "Transportation", "Education", "Government & Defense",
    "Agriculture and Food Production", "Energy & Utilities", "Hospitality", "Other",
]

# Source vocab variants -> taxonomy
_SECTOR_ALIASES: dict[str, str] = {
    "business services": "Professional Services", "consulting": "Professional Services", "legal": "Professional Services",
    "law": "Professional Services", "accounting": "Professional Services", "services": "Professional Services",
    "construction": "Manufacturing", "industrial": "Manufacturing", "automotive": "Manufacturing",
    "it": "Technology", "software": "Technology", "telecom": "Technology", "telecommunications": "Technology",
    "health": "Healthcare", "medical": "Healthcare", "pharma": "Healthcare", "pharmaceutical": "Healthcare",
    "retail": "Retail & E-Commerce", "e-commerce": "Retail & E-Commerce", "consumer": "Retail & E-Commerce",
    "finance": "Financial Services", "financial": "Financial Services", "banking": "Financial Services",
    "insurance": "Financial Services", "real estate": "Financial Services",
    "logistics": "Transportation", "transport": "Transportation", "aviation": "Transportation",
    "education": "Education", "school": "Education", "university": "Education",
    "government": "Government & Defense", "public sector": "Government & Defense", "defense": "Government & Defense",
    "defence": "Government & Defense", "military": "Government & Defense",
    "agriculture": "Agriculture and Food Production", "food": "Agriculture and Food Production",
    "food & beverage": "Agriculture and Food Production",
    "energy": "Energy & Utilities", "utilities": "Energy & Utilities", "oil": "Energy & Utilities",
    "hospitality": "Hospitality", "tourism": "Hospitality", "hotel": "Hospitality", "entertainment": "Hospitality",
    "media": "Hospitality", "not for profit": "Other", "non-profit": "Other", "nonprofit": "Other",
}

# keyword -> sector (checked against victim name + domain + description, lowercase)
SECTOR_KEYWORDS: list[tuple[str, re.Pattern[str]]] = [
    ("Healthcare", re.compile(r"\b(hospital|clinic|medical|health ?care|healthcare|pharma\w*|dental|dentist|physician|surgery|surgical|nursing|hospice|diagnostic|radiolog\w*|oncolog\w*|orthop\w*|therap\w*|patients?|medic(al|ine)|biotech\w*|laborator(y|ies)|ambulance|nhs|klinik|krankenhaus|hôpital|ospedale|salud|sanit[aä]\w*|mental health|wellness|optometr\w*|veterinar\w*)\b")),
    ("Financial Services", re.compile(r"\b(bank\w*|credit union|insurance|insurer|assurance|financ\w*|capital|invest\w*|asset management|wealth|mortgage|lending|loan|fintech|payments?|brokerage|accountanc\w*|cpa\b|tax (service|advis)\w*|real estate|realty|properties)\b")),
    ("Education", re.compile(r"\b(universit\w*|college|school|academy|academ\w*|institute of technology|k-?12|school district|education|campus|lyc[ée]e|hochschule|scuola|escuela|école)\b")),
    ("Government & Defense", re.compile(r"\b(government|municipal\w*|city of|county|ministry|ministère|department of|federal|state of|public (authority|administration)|council|township|defen[cs]e|military|army|navy|police|sheriff|court|agency|prefecture|commune|gemeinde|ayuntamiento|comune)\b")),
    ("Energy & Utilities", re.compile(r"\b(energy|electric\w*|utility|utilities|power (plant|grid|company)|oil|gas|petrol\w*|solar|wind|water (authority|district|utility)|renewable|nuclear|pipeline|mining|mine|minerals)\b")),
    ("Transportation", re.compile(r"\b(logistic\w*|transport\w*|shipping|freight|trucking|haulage|airline|airport|aviation|railway|rail|maritime|port authority|courier|fleet|cargo|forwarding|airways)\b")),
    ("Agriculture and Food Production", re.compile(r"\b(farm\w*|agri\w*|agro\w*|food(s)?|beverage|dairy|meat|poultry|seafood|brewery|brewing|winery|vineyard|bakery|grain|crop|fisher\w*|cattle|produce|nutrition)\b")),
    ("Hospitality", re.compile(r"\b(hotel\w*|resort|hospitality|restaurant\w*|casino|travel|tourism|cruise|leisure|entertainment|cinema|theat(er|re)|gaming|sports? club|stadium|catering|media|broadcast\w*|publishing|newspaper|radio|television)\b")),
    ("Retail & E-Commerce", re.compile(r"\b(retail\w*|e-?commerce|store|shop\w*|supermarket|grocery|boutique|fashion|apparel|clothing|footwear|jewel\w*|furniture|cosmetic\w*|wholesale|distribut(or|ion)|dealer\w*|mall|outlet|marketplace)\b")),
    ("Technology", re.compile(r"\b(software|technolog\w*|tech\b|it services|information technology|cloud|saas|data cent(er|re)|hosting|telecom\w*|cyber\w*|digital|systems?|solutions|computing|semiconductor\w*|electronics|networks?|internet|web|app(s|lication)?\b)\b")),
    ("Manufacturing", re.compile(r"\b(manufactur\w*|industr\w*|engineering|fabricat\w*|machin\w*|automotive|auto parts|steel|metal\w*|plastic\w*|chemical\w*|factory|plant|components?|precision|tooling|construction|builders?|contractor\w*|cement|concrete|aerospace|packaging|textile\w*|printing|equipment|foundry|welding)\b")),
    ("Professional Services", re.compile(r"\b(consult\w*|law (firm|office)|attorneys?|lawyers?|legal|llp\b|accounting|auditing|advisory|staffing|recruit\w*|hr\b|marketing|advertising|architect\w*|design|engineering services|professional services|outsourc\w*|business services|notar\w*|surveyors?|management)\b")),
]

_LEGAL_SUFFIX = re.compile(r"\b(inc|incorporated|llc|ltd|limited|plc|gmbh|ag|sa|srl|bv|nv|co|corp|corporation|company|group|holdings?|pty|pvt|llp|lp|kg|oy|ab|as|sas|sarl|spa|the)\b")
_NON_ALNUM = re.compile(r"[^a-z0-9 ]+")


def normalize_name(name: str) -> str:
    """Casefold, strip punctuation and legal suffixes -> comparable key for cross-source matching."""
    s = unicodedata.normalize("NFKD", name or "")
    s = "".join(ch for ch in s if not unicodedata.combining(ch)).casefold()
    s = re.sub(r"https?://|www\.", "", s)
    s = s.replace("&", " and ").replace("'", "").replace("’", "")
    s = re.sub(r"(?<=\b[a-z])\.(?=[a-z]\b|\s|$)", "", s)  # s.p.a. -> spa, l.l.c -> llc
    s = _NON_ALNUM.sub(" ", s)
    s = _LEGAL_SUFFIX.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip()
    # drop a trailing TLD-like token from domains used as names
    s = re.sub(r"\s(com|net|org|io|co|uk|de|fr|it|es|nl)$", "", s)
    return s


def normalize_sector(raw: str | None) -> str | None:
    if not raw:
        return None
    r = raw.strip()
    for s in SECTORS:
        if s.lower() == r.lower():
            return s
    low = r.lower()
    if low in _SECTOR_ALIASES:
        return _SECTOR_ALIASES[low]
    for alias, sector in _SECTOR_ALIASES.items():
        if alias in low:
            return sector
    return "Other"


def sector_from_keywords(text: str) -> str | None:
    """Return the sector whose keyword set hits most; ties broken by list order (more specific first)."""
    low = (text or "").lower()
    best, best_hits = None, 0
    for sector, pat in SECTOR_KEYWORDS:
        hits = len(pat.findall(low))
        if hits > best_hits:
            best, best_hits = sector, hits
    return best


def sectors_from_keywords(text: str, top: int = 3) -> list[str]:
    low = (text or "").lower()
    scored = [(len(pat.findall(low)), i, sector) for i, (sector, pat) in enumerate(SECTOR_KEYWORDS)]
    return [s for n, _, s in sorted(scored, key=lambda t: (-t[0], t[1])) if n > 0][:top]


def sector_matches(sector: str | None, wanted: str) -> bool:
    if not wanted or wanted.lower() in {"all", "any", "*"}:
        return True
    return bool(sector) and normalize_sector(sector) == normalize_sector(wanted)


# --------------------------------------------------------------------------- size

_MONEY = r"(?:\$|usd\s?|us\$|€|eur\s?|£|gbp\s?)?\s?(\d{1,3}(?:[,.]\d{3})+|\d+(?:\.\d+)?)\s?(billion|bn|million|mn|m|k|thousand)?\b"
_REVENUE_RE = re.compile(r"(revenue|turnover|sales)[^.$€£\d]{0,40}" + _MONEY, re.I)
_MONEY_FIRST_RE = re.compile(_MONEY + r"[^.]{0,30}(revenue|turnover|in sales|annual sales)", re.I)
_EMPLOYEES_RE = re.compile(r"(\d{1,3}(?:[,.]\d{3})*|\d+)\+?\s?(employees|staff|workers|people|personnel|team members)", re.I)
_EMPLOYEES_RANGE_RE = re.compile(r"(\d+)\s?[-–]\s?(\d+)\s?(employees|staff|workers)", re.I)


def _to_usd(num: str, unit: str | None) -> float:
    n = float(num.replace(",", "")) if num.count(",") and not num.count(".") else float(num.replace(",", ""))
    unit = (unit or "").lower()
    if unit in {"billion", "bn"}:
        n *= 1e9
    elif unit in {"million", "mn", "m"}:
        n *= 1e6
    elif unit in {"k", "thousand"}:
        n *= 1e3
    return n


def revenue_from_text(text: str) -> float | None:
    if not text:
        return None
    m = _REVENUE_RE.search(text)
    if m:
        return _to_usd(m.group(2), m.group(3))
    m = _MONEY_FIRST_RE.search(text)
    if m:
        return _to_usd(m.group(1), m.group(2))
    return None


def employees_from_text(text: str) -> int | None:
    if not text:
        return None
    m = _EMPLOYEES_RANGE_RE.search(text)
    if m:
        return int(m.group(2))
    m = _EMPLOYEES_RE.search(text)
    if m:
        try:
            return int(m.group(1).replace(",", "").replace(".", ""))
        except ValueError:
            return None
    return None


def size_band(description: str | None, name: str = "", sector: str | None = None) -> tuple[str, str | None]:
    """Return (band, basis). Bands: small (<$10M / <50 staff), mid (<$100M / <500), large (<$1B / <5000),
    enterprise (>=$1B / >=5000), unknown."""
    text = description or ""
    rev = revenue_from_text(text)
    if rev is not None and rev >= 1e5:
        band = "small" if rev < 1e7 else "mid" if rev < 1e8 else "large" if rev < 1e9 else "enterprise"
        return band, (f"revenue ≈ ${rev/1e6:,.0f}M" if rev >= 1e6 else f"revenue ≈ ${rev/1e3:,.0f}K")
    emp = employees_from_text(text)
    if emp is not None and emp > 0:
        band = "small" if emp < 50 else "mid" if emp < 500 else "large" if emp < 5000 else "enterprise"
        return band, f"{emp:,} employees"
    low = f"{name} {text}".lower()
    if re.search(r"\b(fortune 500|multinational|global leader|publicly traded|listed on|nasdaq|nyse|s&p 500)\b", low):
        return "enterprise", "described as multinational / listed"
    if sector in {"Government & Defense", "Education"} or re.search(r"\b(universit\w*|ministry|county|city of|hospital)\b", low):
        return "large", "public body / institution heuristic"
    if re.search(r"\b(family[- ]owned|small business|local|boutique|independent)\b", low):
        return "small", "described as small / local"
    return "unknown", None


# --------------------------------------------------------------------------- LLM batch

_SYSTEM = ("You are a CTI analyst normalising ransomware victim records. Classify each victim's industry "
           "sector into exactly one of: " + ", ".join(SECTORS) + ". Use the company name, domain and description.")


def llm_classify(batch: list[dict[str, Any]]) -> dict[str, str]:
    """batch items: {id, victim, domain, description}. Returns {id: sector}. Empty when LLM unavailable."""
    if not llm.available() or not batch:
        return {}
    lines = [f'{b["id"]}\t{b.get("victim","")}\t{b.get("domain","")}\t{(b.get("description") or "")[:300]}' for b in batch]
    user = ("Rows are: id<TAB>victim<TAB>domain<TAB>description.\n" + "\n".join(lines) +
            '\nReturn JSON {"<id>": "<sector>", ...} with one entry per row.')
    out = llm.complete_json("victim_sector_classification", _SYSTEM, user, max_tokens=1200) or {}
    result: dict[str, str] = {}
    for k, v in out.items():
        sec = normalize_sector(str(v))
        if sec:
            result[str(k)] = sec
    return result
