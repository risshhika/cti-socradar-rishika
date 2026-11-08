"""ISO-3166 alpha-2 -> region / sub-region mapping used for scoping and classification."""
from __future__ import annotations

REGIONS: dict[str, list[str]] = {
    "North America": ["US", "CA", "MX", "BM", "GL", "PM"],
    "LATAM": ["AR", "BO", "BR", "CL", "CO", "CR", "CU", "DO", "EC", "SV", "GT", "HN", "NI", "PA", "PY", "PE",
              "PR", "UY", "VE", "JM", "TT", "BS", "BB", "HT", "BZ", "GY", "SR", "AW", "CW", "KY", "VG", "VI",
              "AG", "DM", "GD", "KN", "LC", "VC", "MQ", "GP", "GF"],
    "Europe": ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
               "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB", "NO", "CH", "IS", "LI",
               "UA", "MD", "BY", "RS", "ME", "MK", "AL", "BA", "XK", "AD", "MC", "SM", "VA", "GI", "JE", "GG",
               "IM", "FO", "AX"],
    "CIS": ["RU", "BY", "GE", "AM", "AZ", "KZ", "UZ", "TM", "KG", "TJ"],
    "MENA": ["AE", "SA", "QA", "KW", "BH", "OM", "YE", "IQ", "IR", "IL", "PS", "JO", "LB", "SY", "TR", "EG",
             "LY", "TN", "DZ", "MA", "EH", "SD"],
    "Sub-Saharan Africa": ["NG", "ZA", "KE", "GH", "ET", "TZ", "UG", "RW", "SN", "CI", "CM", "ZM", "ZW", "MZ",
                           "AO", "BW", "NA", "MW", "MU", "MG", "ML", "BF", "NE", "TD", "SO", "DJ", "ER", "SS",
                           "CD", "CG", "GA", "GQ", "BJ", "TG", "SL", "LR", "GN", "GW", "GM", "CV", "ST", "SC",
                           "KM", "LS", "SZ", "MR", "CF", "BI", "RE", "YT"],
    "South Asia": ["IN", "PK", "BD", "LK", "NP", "BT", "MV", "AF"],
    "East Asia": ["CN", "JP", "KR", "KP", "TW", "HK", "MO", "MN"],
    "Southeast Asia": ["SG", "MY", "TH", "ID", "PH", "VN", "KH", "LA", "MM", "BN", "TL"],
    "Oceania": ["AU", "NZ", "PG", "FJ", "SB", "VU", "WS", "TO", "NC", "PF", "GU", "FM", "KI", "MH", "NR", "PW", "TV"],
}

SUB_REGIONS: dict[str, list[str]] = {
    "DACH": ["DE", "AT", "CH"],
    "Nordics": ["DK", "FI", "IS", "NO", "SE"],
    "UK&I": ["GB", "IE"],
    "Benelux": ["BE", "NL", "LU"],
    "Iberia": ["ES", "PT"],
    "CEE": ["PL", "CZ", "SK", "HU", "RO", "BG", "SI", "HR", "RS", "BA", "ME", "MK", "AL", "XK", "LT", "LV",
            "EE", "UA", "MD", "BY"],
    "EU": ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
           "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"],
    "GCC": ["AE", "SA", "QA", "KW", "BH", "OM"],
    "ANZ": ["AU", "NZ"],
    "APAC": [],  # filled below
}

_COUNTRY_TO_REGION: dict[str, str] = {cc: region for region, ccs in REGIONS.items() for cc in ccs}
SUB_REGIONS["APAC"] = REGIONS["South Asia"] + REGIONS["East Asia"] + REGIONS["Southeast Asia"] + REGIONS["Oceania"]

COUNTRY_NAMES: dict[str, str] = {
    "united states": "US", "usa": "US", "us": "US", "u.s": "US", "u.s.": "US", "america": "US", "american": "US", "canada": "CA",
    "canadian": "CA", "mexico": "MX", "mexican": "MX", "brazil": "BR", "brazilian": "BR", "argentina": "AR",
    "chile": "CL", "colombia": "CO", "peru": "PE", "united kingdom": "GB", "uk": "GB", "britain": "GB",
    "british": "GB", "england": "GB", "scotland": "GB", "ireland": "IE", "irish": "IE", "germany": "DE",
    "german": "DE", "france": "FR", "french": "FR", "spain": "ES", "spanish": "ES", "italy": "IT",
    "italian": "IT", "netherlands": "NL", "dutch": "NL", "belgium": "BE", "belgian": "BE", "switzerland": "CH",
    "swiss": "CH", "austria": "AT", "austrian": "AT", "poland": "PL", "polish": "PL", "sweden": "SE",
    "swedish": "SE", "norway": "NO", "norwegian": "NO", "denmark": "DK", "danish": "DK", "finland": "FI",
    "finnish": "FI", "portugal": "PT", "portuguese": "PT", "greece": "GR", "greek": "GR", "czech": "CZ",
    "czechia": "CZ", "hungary": "HU", "hungarian": "HU", "romania": "RO", "romanian": "RO", "ukraine": "UA",
    "ukrainian": "UA", "russia": "RU", "russian": "RU", "turkey": "TR", "türkiye": "TR", "turkish": "TR",
    "israel": "IL", "israeli": "IL", "uae": "AE", "united arab emirates": "AE", "emirati": "AE",
    "saudi arabia": "SA", "saudi": "SA", "qatar": "QA", "egypt": "EG", "egyptian": "EG", "south africa": "ZA",
    "nigeria": "NG", "nigerian": "NG", "kenya": "KE", "india": "IN", "indian": "IN", "pakistan": "PK",
    "bangladesh": "BD", "china": "CN", "chinese": "CN", "japan": "JP", "japanese": "JP", "south korea": "KR",
    "korea": "KR", "korean": "KR", "taiwan": "TW", "taiwanese": "TW", "hong kong": "HK", "singapore": "SG",
    "malaysia": "MY", "malaysian": "MY", "thailand": "TH", "thai": "TH", "indonesia": "ID", "indonesian": "ID",
    "philippines": "PH", "filipino": "PH", "vietnam": "VN", "vietnamese": "VN", "australia": "AU",
    "australian": "AU", "new zealand": "NZ", "kazakhstan": "KZ", "luxembourg": "LU", "lithuania": "LT",
    "latvia": "LV", "estonia": "EE", "slovakia": "SK", "slovenia": "SI", "croatia": "HR", "serbia": "RS",
    "bulgaria": "BG", "iceland": "IS", "cyprus": "CY", "malta": "MT", "morocco": "MA", "algeria": "DZ",
    "tunisia": "TN", "jordan": "JO", "lebanon": "LB", "kuwait": "KW", "oman": "OM", "bahrain": "BH",
    "iran": "IR", "iranian": "IR", "iraq": "IQ", "venezuela": "VE", "ecuador": "EC", "costa rica": "CR",
    "panama": "PA", "guatemala": "GT", "dominican republic": "DO", "puerto rico": "PR",
}


def region_for_country(cc: str | None) -> str | None:
    if not cc:
        return None
    return _COUNTRY_TO_REGION.get(cc.strip().upper())


def countries_in(region: str) -> set[str] | None:
    """Return the ISO2 set for a region, sub-region, country code or None for Global."""
    r = (region or "").strip()
    if not r or r.lower() in {"global", "world", "all"}:
        return None
    for name, ccs in REGIONS.items():
        if name.lower() == r.lower():
            return set(ccs)
    for name, ccs in SUB_REGIONS.items():
        if name.lower() == r.lower():
            return set(ccs)
    if len(r) == 2 and r.upper() in _COUNTRY_TO_REGION:
        return {r.upper()}
    cc = COUNTRY_NAMES.get(r.lower())
    if cc:
        return {cc}
    return set()  # unknown region -> nothing in scope


def country_matches_region(cc: str | None, region: str) -> bool:
    allowed = countries_in(region)
    if allowed is None:
        return True
    return bool(cc) and cc.upper() in allowed


def countries_from_text(text: str) -> list[str]:
    """Find country mentions (names / demonyms) in text, return ISO2 codes ordered by first occurrence."""
    low = f" {text.lower()} "
    found: dict[str, int] = {}
    for name, cc in COUNTRY_NAMES.items():
        if len(name) <= 3:
            idx = low.find(f" {name} ")
        else:
            idx = low.find(name)
        if idx >= 0 and (cc not in found or idx < found[cc]):
            found[cc] = idx
    return [cc for cc, _ in sorted(found.items(), key=lambda kv: kv[1])]
