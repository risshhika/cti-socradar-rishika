"""Canonical-URL de-duplication: per-victim links collapse to one page, different pages stay apart."""
from datetime import datetime, timedelta, timezone

from app.modules.phishing.collectors import Candidate
from app.modules.phishing.dedupe import canonical_host, canonical_url
from app.modules.phishing.pipeline import merge_candidates


def test_same_page_variants_share_a_key():
    base = canonical_url("https://secure-paypal.example.com/login/")
    for v in [
        "http://www.secure-paypal.example.com/login",
        "https://SECURE-PAYPAL.example.com:443/login?utm_source=mail#top",
        "https://secure-paypal.example.com/login?email=bob@corp.com&token=abc123",
        "https://secure-paypal.example.com//login/?e=Ym9iQGNvcnAuY29t",
    ]:
        assert canonical_url(v) == base, v


def test_victim_tokens_in_path_are_templated():
    a = canonical_url("https://sup-x.pages.dev/9f8e7d6c5b4a3f2e1d0c/verify.php")
    b = canonical_url("https://sup-x.pages.dev/0a1b2c3d4e5f60718293/verify.php")
    c = canonical_url("https://sup-x.pages.dev/s/bob@corp.com/")
    d = canonical_url("https://sup-x.pages.dev/s/alice@corp.com/")
    assert a == b and c == d


def test_different_pages_stay_distinct():
    assert canonical_url("https://x.com/login") != canonical_url("https://x.com/wallet")
    assert canonical_url("https://x.com/a") != canonical_url("https://y.com/a")
    assert canonical_url("https://x.com/p?step=2") != canonical_url("https://x.com/p")  # step is a page param


def test_canonical_host():
    assert canonical_host("WWW.Example.COM.") == "example.com"
    assert canonical_host(None) == ""


def test_cross_source_merge_keeps_urlscan_primary_and_all_sources():
    now = datetime.now(timezone.utc)
    op = Candidate(url="http://evil-paypal.com/login?email=a@b.co", source="openphish", first_seen=now - timedelta(hours=5),
                   tags=["phishing"], brand_hint="PayPal")
    us = Candidate(url="https://evil-paypal.com/login", source="urlscan", source_id="uuid-1", first_seen=now,
                   tags=["phishing", "paypal"])
    out, merged = merge_candidates([op, us])
    assert merged == 1 and len(out) == 1
    c = out[0]
    assert c.source == "urlscan" and c.source_id == "uuid-1"
    assert c.meta["_sources"] == ["openphish", "urlscan"]
    assert c.first_seen == op.first_seen            # earliest report wins
    assert c.brand_hint == "PayPal"                 # hint carried over from the other source
    assert op.url in c.meta["_alt_urls"]


def test_phishtank_target_maps_to_scope_brand():
    from app.modules.phishing.collectors import PhishTankCollector, _brand_slug
    slugs = {_brand_slug(b): b for b in ["PayPal", "HSBC", "Binance", "Bank of America"]}
    assert PhishTankCollector._brand("HSBC Group", "https://x.example/", slugs) == "HSBC"
    assert PhishTankCollector._brand("PayPal", "https://x.example/", slugs) == "PayPal"
    assert PhishTankCollector._brand("Other", "https://binance-login.example/", slugs) == "Binance"
    assert PhishTankCollector._brand("Allegro", "https://allegro.example/", slugs) is None
