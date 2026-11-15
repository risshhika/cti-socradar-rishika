"""Brand typosquat detection for hostnames (P4 detection type A).

A brand is described by an ordered list of *fragments* -- the analyst's `pay*pal*`, `coin*base*`,
`wel*far*go` notation. A hostname label matches when the fragments appear in order with only a
small gap between them, after homoglyph normalisation. On top of that we check for the whole brand
embedded in the label and for one/two-character typos (Damerau-Levenshtein), so we catch:

    pay-pal-ai.vercel.app      -> embed (separators stripped) + lure word "ai"
    paypa1-secure.com          -> homoglyph (1 -> l)
    wellsfarg0-online.net      -> fragment wel..far..go with homoglyph
    coinbsae-help.pages.dev    -> typo (transposition)

Labels that never mention the brand (``ehrjhefer.vercel.app``) are *not* matched here; they are
caught by page content (detection type B) in features.py / fingerprint.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

# Characters attackers substitute for letters. Each maps to the letter(s) it imitates.
HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "0": ("o",), "1": ("l", "i"), "3": ("e",), "4": ("a",), "5": ("s",), "7": ("t",), "8": ("b",),
    "@": ("a",), "$": ("s",), "!": ("i",),
}
MULTI_GLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))

# Words phishers pair with a brand. A hit raises the threat rank, it never creates a match by itself.
DEFAULT_LURE_WORDS = (
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security", "account", "accounts",
    "support", "help", "helpdesk", "service", "services", "update", "recover", "recovery", "unlock", "auth",
    "wallet", "kyc", "billing", "invoice", "payment", "refund", "claim", "reward", "bonus", "airdrop", "ai",
    "online", "web", "portal", "app", "mobile", "id", "confirm", "alert", "case", "dispute", "limited", "restore",
)

# Ordinary words that contain (or are one typo from) a brand. Blanked out before matching so that
# "revolution" is not Revolut and "purchase" is not Chase. Extend per brand via scope `brand_exclusions`.
DEFAULT_EXCLUSIONS: dict[str, tuple[str, ...]] = {
    "revolut": ("revolution", "revolt", "resolut"),
    "chase": ("purchase", "chaser", "chasse", "chasing"),
    "binance": ("ambiance", "finance", "balance", "bilanc"),
    "paypal": ("paywall", "pappal", "papal", "paypay"),
    "santander": ("santoandre", "santana"),
    "barclays": ("barclayscenter",),
    "hsbc": (),
}

SEPARATORS = re.compile(r"[-_.]+")
MAX_GAP = 4  # characters allowed between consecutive fragments (separators or filler)


@dataclass
class BrandSpec:
    name: str
    slug: str                       # "wellsfargo"
    fragments: list[str]            # ["wel", "far", "go"]
    official: set[str] = field(default_factory=set)  # registrable domains owned by the brand
    exclusions: tuple[str, ...] = ()                 # collision words blanked before matching


@dataclass
class SquatMatch:
    brand: str
    kind: str          # embed | homoglyph | fragment | typo
    score: float       # 0..1 strength of the hostname evidence
    label: str         # the hostname part that matched
    evidence: str      # human-readable explanation
    lure_words: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"brand": self.brand, "kind": self.kind, "score": round(self.score, 2), "label": self.label,
                "evidence": self.evidence, "lure_words": self.lure_words}


def slugify(brand: str) -> str:
    return re.sub(r"[^a-z0-9]", "", brand.lower())


def auto_fragments(brand: str) -> list[str]:
    """Split a brand into fragments when the analyst did not give any.

    Multi-word brands split on words ("Bank of America" -> bank, america; stop-words dropped).
    Single words of 7+ characters split near the middle at a consonant/vowel boundary; shorter
    words stay whole -- splitting "chase" into "ch*ase" would match half the internet.
    """
    words = [w for w in re.split(r"[^a-z0-9]+", brand.lower()) if w and w not in {"of", "the", "and", "de", "la"}]
    if len(words) > 1:
        return words
    w = words[0] if words else slugify(brand)
    if len(w) < 7:
        return [w]
    mid = len(w) // 2
    vowels = set("aeiouy")
    for off in (0, 1, -1, 2, -2):
        i = mid + off
        if 3 <= i <= len(w) - 3 and (w[i - 1] in vowels) != (w[i] in vowels):
            return [w[:i], w[i:]]
    return [w[:mid], w[mid:]]


def build_specs(brands: list[str], fragments: dict[str, list[str]] | None = None,
                official: dict[str, list[str]] | None = None,
                exclusions: dict[str, list[str]] | None = None) -> list[BrandSpec]:
    fragments, official, exclusions = fragments or {}, official or {}, exclusions or {}
    specs = []
    for b in brands:
        slug = slugify(b)
        frags = [slugify(f) for f in fragments.get(b, []) if slugify(f)] or auto_fragments(b)
        own = {d.lower().strip() for d in official.get(b, [])} or {f"{slug}.com"}
        words = {*DEFAULT_EXCLUSIONS.get(slug, ()), *(slugify(x) for x in exclusions.get(b, []))}
        # an exclusion inside the brand itself would blank every real hit ("evolut" in "revolut")
        excl = tuple(sorted((w for w in words if w and w not in slug), key=len, reverse=True))
        specs.append(BrandSpec(name=b, slug=slug, fragments=frags, official=own, exclusions=excl))
    return specs


# --------------------------------------------------------------------------- normalisation

def _variants(text: str) -> set[str]:
    """Homoglyph-normalised spellings of `text` (bounded: ambiguous glyphs give at most a few variants)."""
    out = {text}
    for a, b in MULTI_GLYPHS:
        out |= {v.replace(a, b) for v in out}
    for glyph, letters in HOMOGLYPHS.items():
        if any(glyph in v for v in out):
            out = {v.replace(glyph, l) for v in out for l in letters} | out
        if len(out) > 32:
            break
    return out


def _damerau(a: str, b: str, limit: int) -> int:
    """Optimal-string-alignment distance with early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


@lru_cache(maxsize=256)
def fragment_regex(fragments: tuple[str, ...]) -> re.Pattern[str]:
    gap = f".{{0,{MAX_GAP}}}?"
    return re.compile(gap.join(re.escape(f) for f in fragments))


# --------------------------------------------------------------------------- matching

def registrable(host: str) -> str:
    """Cheap registrable-domain guess, good enough to exclude the brand's own domains."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _lures(text: str, words: tuple[str, ...]) -> list[str]:
    tokens = set(t for t in SEPARATORS.split(text) if t)
    flat = SEPARATORS.sub("", text)
    hits = [w for w in words if w in tokens or (len(w) >= 5 and w.replace("-", "") in flat)]
    return sorted(set(hits))


def match_host(host: str, specs: list[BrandSpec], lure_words: tuple[str, ...] = DEFAULT_LURE_WORDS) -> SquatMatch | None:
    """Best brand match for a hostname, or None. Official brand domains never match."""
    host = (host or "").lower().strip(".")
    if not host:
        return None
    reg = registrable(host)
    # Look at everything left of the public suffix: "secure-paypal.example.vercel.app" -> labels before "vercel.app"
    labels = host.split(".")[:-1] if "." in host else [host]
    best: SquatMatch | None = None
    for spec in specs:
        if reg in spec.official or any(host == d or host.endswith("." + d) for d in spec.official):
            continue
        for label in labels:
            m = _match_label(label, spec)
            if m and (best is None or m.score > best.score):
                best = m
    if best:
        best.lure_words = _lures(host, lure_words)
    return best


def _embed_ok(label: str, flat: str, slug: str) -> bool:
    """Long brands embed anywhere. Short ones (chase, hsbc) must stand alone as a token, sit at the start
    of the label, or be glued to a lure word / digits -- otherwise 'purchase' would match Chase."""
    if len(slug) >= 6:
        return True
    tokens = [t for t in SEPARATORS.split(label) if t]
    if slug in tokens or flat.startswith(slug):
        return True
    for t in tokens:
        if slug in t:
            rest = t.replace(slug, "", 1)
            if rest.isdigit() or rest in DEFAULT_LURE_WORDS:
                return True
    return False


def _typo_ok(label: str, window: str, slug: str) -> bool:
    """A near-miss spelling only counts when it is clearly brand-shaped: it carries a lure word
    (coinbsae-help) or is most of a short token (paypla.com). Long words that merely contain a
    near-miss (pappalardocounseling) are rejected."""
    if _lures(label, DEFAULT_LURE_WORDS):
        return True
    for t in SEPARATORS.split(label):
        if len(t) >= len(window) - 1 and len(t) <= len(slug) + 3 and _damerau(t[: len(window)], window, 0) == 0:
            return True
    return False


def _match_label(label: str, spec: BrandSpec) -> SquatMatch | None:
    flat = SEPARATORS.sub("", label)
    for word in spec.exclusions:
        if word and word in flat:
            flat = flat.replace(word, "#")
            label = "#".join(label.split(word)) if word in label else label
    if not flat.strip("#"):
        return None
    slug = spec.slug
    # 1. brand embedded verbatim (with or without separators): paypal-login, pay-pal-ai
    if slug in flat and _embed_ok(label, flat, slug):
        how = "verbatim" if slug in label else "split by separators"
        return SquatMatch(spec.name, "embed", 1.0, label, f"'{slug}' embedded in '{label}' ({how})")
    variants = _variants(flat) - {flat}
    # 2. homoglyph: paypa1, c0inbase, wellsfarg0
    for v in variants:
        if slug in v and _embed_ok(label, v, slug):
            return SquatMatch(spec.name, "homoglyph", 0.95, label, f"'{label}' reads as '{slug}' after homoglyph substitution")
    # 3. fragments in order with small gaps: wel*far*go, coin*base
    if len(spec.fragments) > 1:
        rx = fragment_regex(tuple(spec.fragments))
        for v in (flat, *variants):
            m = rx.search(v)
            if m:
                gap = len(m.group(0)) - sum(len(f) for f in spec.fragments)
                score = max(0.6, 0.9 - 0.06 * gap)
                pat = "*".join(spec.fragments) + "*"
                return SquatMatch(spec.name, "fragment", score, label, f"fragments {pat} matched '{m.group(0)}' (gap {gap})")
    # 4. typo: one edit for short brands, two for long ones, over every window of brand length +-1.
    #    Typosquats keep the first letter (paypla, coinbsae); requiring it stops binance~finance, chase~chose.
    if len(slug) >= 6:
        limit = 1 if len(slug) < 9 else 2
        for v in (flat, *variants):
            for size in (len(slug) - 1, len(slug), len(slug) + 1):
                for i in range(0, max(1, len(v) - size + 1)):
                    window = v[i:i + size]
                    if len(window) < len(slug) - 1 or window[0] != slug[0]:
                        continue
                    d = _damerau(window, slug, limit)
                    if 0 < d <= limit and _typo_ok(label, window, slug):
                        return SquatMatch(spec.name, "typo", 0.8 if d == 1 else 0.65, label,
                                          f"'{window}' is {d} edit{'s' if d > 1 else ''} from '{slug}'")
    return None
