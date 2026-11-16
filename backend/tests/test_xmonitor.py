"""X IAB monitor: query narrowing, financial filter, extraction, evidence card, firmographic bands and parsing."""
from pathlib import Path

from app.modules.landscape import firmographics as fg
from app.modules.landscape import xmon

POST = ("Selling RDP access to a US credit union, $1.2B revenue, domain admin. Price $4,000. "
        "DM on XSS forum. Target: Lakeside Federal Credit Union lakesidefcu.org")


def test_query_is_narrowed_to_finance_and_drops_retweets():
    q = xmon.build_query('("initial access" OR "access broker") has:images', ["Financial Services"])
    assert q.startswith('("initial access" OR "access broker") has:images (bank OR')
    assert q.endswith("-is:retweet") and len(q) <= 512
    # a query that already names finance is not narrowed twice
    q3 = xmon.build_query('("bank" OR "financial institution" OR "fintech") ("access" OR "breach") has:images', ["Financial Services"])
    assert "credit union" not in q3


def test_financial_filter_and_false_friends():
    assert xmon.financial_terms("access to a regional bank in Brazil")
    assert not xmon.financial_terms("Happy bank holiday! Donate to the food bank, charge your power bank")
    assert xmon.fin_subtype("selling access to a payments processor") == "Payments"
    assert xmon.fin_subtype("credit union VPN") == "Credit union"
    assert xmon.fin_subtype("crypto exchange admin panel") == "Crypto exchange"


def test_extraction_from_iab_post():
    ex = xmon.extract(POST, [], [])
    assert ex["fin_subtype"] == "Credit union"
    assert "RDP" in ex["access_types"]
    assert ex["claimed_revenue_usd"] == 1.2e9
    assert ex["price_usd_min"] == 4000
    assert "XSS" in ex["forums"]
    assert "Lakeside Federal Credit Union" in ex["victim_candidates"] and "lakesidefcu.org" in ex["victim_candidates"]
    assert xmon.in_sectors(ex, ["Financial Services"])


def test_news_and_social_domains_are_not_victims():
    c = xmon.victim_candidates("via bleepingcomputer.com and t.co/abc", ["https://www.bleepingcomputer.com/news/x"])
    assert c == []


def test_watched_accounts_query():
    qs = xmon.all_queries([{"label": "IAB keywords", "query": '"initial access" has:images'}], ["DailyDarkWeb", "@DarkWebInformer"])
    acc = qs[-1]
    assert acc["label"] == xmon.ACCOUNTS_LABEL
    assert acc["query"] == "(from:DailyDarkWeb OR from:DarkWebInformer)"
    sent = xmon.build_query(acc["query"], ["Financial Services"])
    assert "has:images" not in sent and "(bank OR" in sent and sent.endswith("-is:retweet")
    assert xmon.all_queries([], []) == []


def test_bands():
    assert fg.revenue_band(1.2e9) == "$1B-$10B" and fg.revenue_band(5e6) == "<$10M" and fg.revenue_band(None) is None
    assert fg.employee_band(150) == "51-200" and fg.employee_band(25000) == "10,000+"


def test_evidence_card_renders_and_hashes(tmp_path, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(type(get_settings()), "artifacts_dir", property(lambda self: tmp_path))
    post = {"tweet": {"id": "1857000000000000001", "text": POST, "created_at": "2026-11-14T10:00:00.000Z", "author_id": "42"},
            "author": {"username": "someanalyst", "name": "Some Analyst"}, "media": []}
    raw_path, raw_sha = xmon.save_record(post)
    card_path, card_sha = xmon.render_card(post, [], raw_sha, ["Remote access for sale"])
    png = (tmp_path / card_path).read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n" and len(card_sha) == 64 and len(raw_sha) == 64
    assert (tmp_path / raw_path).exists()


def test_wikidata_parsing(monkeypatch):
    ent = {"claims": {
        "P2139": [{"mainsnak": {"snaktype": "value", "datavalue": {"value": {"amount": "+150000000000", "unit": "http://www.wikidata.org/entity/Q4917"}}},
                   "qualifiers": {"P585": [{"datavalue": {"value": {"time": "+2023-00-00T00:00:00Z"}}}]}, "rank": "normal"}],
        "P1128": [{"mainsnak": {"snaktype": "value", "datavalue": {"value": {"amount": "+300000"}}},
                   "qualifiers": {"P585": [{"datavalue": {"value": {"time": "+2023-12-31T00:00:00Z"}}}]}, "rank": "normal"}],
        "P452": [{"mainsnak": {"snaktype": "value", "datavalue": {"value": {"id": "Q22687"}}}, "rank": "normal"}],
        "P17": [{"mainsnak": {"snaktype": "value", "datavalue": {"value": {"id": "Q30"}}}, "rank": "normal"}],
    }}

    class Fake:
        def get_json(self, url, **kw):
            if "wbsearchentities" in url:
                return {"search": [{"id": "Q192314", "label": "JPMorgan Chase", "description": "American bank"}]}
            if "EntityData" in url:
                return {"entities": {"Q192314": ent}}
            return {"entities": {"Q22687": {"labels": {"en": {"value": "banking"}}}, "Q30": {"labels": {"en": {"value": "United States"}}}}}

    r = fg.wikidata("JPMorgan Chase", Fake())
    assert r["revenue_usd"] == 150e9 and r["revenue_year"] == 2023
    assert r["employees"] == 300000 and r["industry"] == "banking" and r["country"] == "United States"
    assert r["source"]["source"] == "Wikidata"
