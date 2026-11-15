"""Executive report safety: captions never name the domain; attacker-controlled text is escaped in HTML."""
from datetime import datetime, timezone

from app.models import PhishSample
from app.modules.phishing.report import _caption, _split_assets, render_html


def sample(**kw) -> PhishSample:
    base = dict(id=1, url="https://coinbase-help-desk.example/login", domain="coinbase-help-desk.example", source="urlscan",
                fetch_status="ok", fetched_at=datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc), country="US",
                title="Sign in | coinbase-help-desk.example", squat={"brand": "Coinbase"},
                features={"input_names": ["email", "password"], "has_password_field": True,
                          "kit_hits": [{"label": "seed-phrase harvesting copy"}]})
    base.update(kw)
    return PhishSample(**base)


def test_caption_never_contains_the_domain():
    s = sample()
    cap = _caption(s, "Coinbase")
    assert "coinbase-help-desk" not in cap and ".example" not in cap
    assert "dedicated lookalike domain" in cap


def test_assets_split_between_page_and_kit():
    on_page, in_kit = _split_assets(sample())
    assert "account passwords" in on_page
    assert "wallet seed phrases / keys" in in_kit and "wallet seed phrases / keys" not in on_page


def test_free_platform_wording():
    cap = _caption(sample(domain="coinbase-x.pages.dev", url="https://coinbase-x.pages.dev/"), "Coinbase")
    assert "free Pages subdomain" in cap and "pages.dev" not in cap


def test_html_escapes_attacker_text():
    evil = "<script>alert(1)</script>"
    rep = {
        "brand": "X", "sector": "s", "window_days": 7, "generated_at": datetime.now(timezone.utc),
        "executive_summary": evil, "impact_one_line": evil, "method_note": "m",
        "numbers": {k: 0 for k in ("pages", "live", "critical", "high", "campaigns", "kits", "typosquat_hosts",
                                    "new_domain_leads", "detections", "duplicates_merged", "share_of_all", "content_only")} | {"sources": {}},
        "targeting": {"squat_kinds": {}, "dedicated_domains": 0, "hosting_platforms": [], "lure_words": [{"word": evil, "count": 1}],
                      "credential_surface": [], "kits": []},
        "use_case": {"caption": evil, "threat_score": 1, "threat_tier": "low", "live_within_48h": True},
        "fingerprint": {"kit": None, "matched_markers": [evil], "campaign": None, "page": {}},
        "urlscan_queries": [{"label": evil, "why": evil, "query": evil}],
        "geography": {"countries": [], "asns": [], "tlds": [], "new_countries": []},
        "user_impact": [], "defense": {"organisation": [evil], "customers": []},
    }
    out = render_html(rep, None)
    assert "<script" not in out.lower()
    assert "&lt;script&gt;" in out
