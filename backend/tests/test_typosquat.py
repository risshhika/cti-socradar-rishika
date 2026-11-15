"""Typosquat matcher + threat rank. Positives are the analyst's examples; negatives are real NRD noise
that an earlier version flagged (revolution~Revolut, purchase~Chase, finance~Binance)."""
import pytest

from app.modules.phishing.rank import threat_rank, tier_for
from app.modules.phishing.typosquat import auto_fragments, build_specs, match_host

BRANDS = ["PayPal", "Chase", "Wells Fargo", "Bank of America", "HSBC", "Barclays", "Santander", "Revolut",
          "Coinbase", "Binance"]
FRAGS = {"PayPal": ["pay", "pal"], "Wells Fargo": ["wel", "far", "go"], "Coinbase": ["coin", "base"],
         "Binance": ["bin", "ance"]}
OFFICIAL = {"PayPal": ["paypal.com", "paypalobjects.com"], "Chase": ["chase.com"]}
SPECS = build_specs(BRANDS, FRAGS, OFFICIAL)


@pytest.mark.parametrize("host,brand,kind", [
    ("pay-pal-ai.vercel.app", "PayPal", "embed"),
    ("paypa1-secure.com", "PayPal", "homoglyph"),
    ("wellsfarg0-online.net", "Wells Fargo", "homoglyph"),
    ("welsfargo-help.com", "Wells Fargo", "fragment"),
    ("coinbsae-help.pages.dev", "Coinbase", "typo"),
    ("pro-coinbase--login.pages.dev", "Coinbase", "embed"),
    ("chase-login.top", "Chase", "embed"),
    ("binnance-airdrop.com", "Binance", "fragment"),
    ("revolut-verify.com", "Revolut", "embed"),
    ("bankofamerica-alert.com", "Bank of America", "embed"),
    ("paypla.com", "PayPal", "typo"),
])
def test_typosquats_match(host, brand, kind):
    m = match_host(host, SPECS)
    assert m is not None, host
    assert (m.brand, m.kind) == (brand, kind)


@pytest.mark.parametrize("host", [
    "ehrjhefer.vercel.app",           # type B: no brand in the name, caught by content instead
    "www.paypal.com", "cdn.paypalobjects.com", "secure.chase.com",  # official
    "purchase.com", "purchase6812.surf", "finance-news.com", "chosen.io", "binfinancial.org",
    "revolutionrising.us", "complaintresolutionco.com", "pappalardocounseling.it", "coastalbase.net",
])
def test_lookalikes_do_not_match(host):
    assert match_host(host, SPECS) is None


def test_lure_words_and_fragments():
    m = match_host("pay-pal-ai.vercel.app", SPECS)
    assert "ai" in m.lure_words
    assert auto_fragments("Bank of America") == ["bank", "america"]
    assert auto_fragments("Chase") == ["chase"]  # short brands are never split
    paypal = next(s for s in SPECS if s.name == "PayPal")
    assert paypal.fragments == ["pay", "pal"]


def test_rank_orders_typosquat_above_content_only():
    page = {"brand": "PayPal", "brand_confidence": 0.9, "has_password_field": True}
    squat = match_host("pay-pal-ai.vercel.app", SPECS).as_dict()
    a = threat_rank(host="pay-pal-ai.vercel.app", squat=squat, features=page, fetch_status="ok")
    b = threat_rank(host="ehrjhefer.vercel.app", squat=None, features=page, fetch_status="ok")
    assert a["detection_type"] == "typosquat" and b["detection_type"] == "content"
    assert a["score"] > b["score"]
    assert a["tier"] in ("critical", "high")
    assert all("detail" in f for f in a["factors"])


def test_rank_offline_and_unattributed():
    r = threat_rank(host="random.example", squat=None, features={}, fetch_status="offline")
    assert r["detection_type"] == "unattributed" and r["score"] == 0 and r["tier"] == "low"
    assert tier_for(70) == "critical" and tier_for(50) == "high" and tier_for(30) == "medium"
