"""Victim identification: tech extraction, Shodan dork building, firmographic parsing, cross-reference ranking."""
import pytest

from app.models import XPost
from app.modules.landscape import identify as idmod
from app.modules.landscape import xmon

POST = ("A forum actor claims to be selling VPN access to an unidentified financial services organization in India "
        "with estimated annual revenue between $1 billion and $5 billion. Pulse Secure VPN access, local administrator "
        "privileges, a network containing approximately 10,000+ hosts, Carbon Black deployed as the AV/EDR.")


def test_tech_and_host_count_extraction():
    assert xmon.tech_stack(POST) == ["Pulse Secure", "Carbon Black"]
    assert xmon.host_count(POST) == 10000
    ex = xmon.extract(POST, [], [])
    assert ex["tech"] == ["Pulse Secure", "Carbon Black"] and ex["host_count"] == 10000


def test_revenue_band_from_range():
    p = XPost(tweet_id="1", url="u", text=POST)
    lo, hi = idmod._revenue_band(p)
    assert lo == 1e9 and hi == 5e9


def test_revenue_band_brackets_single_figure():
    p = XPost(tweet_id="1", url="u", text="$16B revenue", claimed_revenue_usd=16e9)
    lo, hi = idmod._revenue_band(p)
    assert lo == 8e9 and hi == 32e9


def test_shodan_dork_only_builds_for_edge_tech():
    assert "Carbon Black" not in idmod.DORKABLE and "Pulse Secure" in idmod.DORKABLE


def test_shodan_match_by_domain_and_name():
    hits = [{"ip": "203.0.113.9", "org": "Example Telecom", "hostnames": ["vpn.acmebank.in"], "domains": ["acmebank.in"], "ssl_cn": None}]
    assert idmod._shodan_match({"name": "Acme Bank", "website": "https://www.acmebank.in"}, hits)["ip"] == "203.0.113.9"
    assert idmod._shodan_match({"name": "Other Bank", "website": "https://other.in"}, hits) is None


def test_unit_conversion():
    assert idmod._unit_to_usd("Indian rupee") == 0.012
    assert idmod._unit_to_usd("United States dollar") == 1.0
    assert idmod._unit_to_usd("klingon dram") == 0.0


def test_identify_ranks_shodan_match_first(monkeypatch):
    firms = [
        {"name": "Acme Bank", "website": "https://acmebank.in", "revenue_usd": 3e9, "employees": 9000, "country": "India", "source": "Wikidata"},
        {"name": "Beta Finance", "website": "https://beta.in", "revenue_usd": 2e9, "employees": 4000, "country": "India", "source": "Wikidata"},
    ]
    hits = [{"ip": "203.0.113.9", "org": "ISP", "hostnames": ["vpn.beta.in"], "domains": ["beta.in"], "product": "Pulse Secure", "ssl_cn": None}]
    monkeypatch.setattr(idmod, "wikidata_search", lambda *a, **k: firms)
    monkeypatch.setattr(idmod, "zoominfo_search", lambda *a, **k: None)
    monkeypatch.setattr(idmod, "shodan_search", lambda *a, **k: hits)
    monkeypatch.setattr(idmod.get_settings(), "shodan_api_key", "k", raising=False)
    import types
    s = idmod.get_settings()
    object.__setattr__(s, "shodan_api_key", "k")
    p = XPost(tweet_id="1", url="u", text=POST, countries=["IN"], tech=["Pulse Secure", "Carbon Black"])
    res = idmod.identify_victim(_FakeSession(), p)
    assert res["candidates"][0]["name"] == "Beta Finance"      # Shodan match wins over higher revenue
    assert res["candidates"][0]["confidence"] == "High"
    assert res["candidates"][0]["shodan_host"] == "203.0.113.9"


class _FakeSession:
    pass


@pytest.mark.parametrize("country,ok", [("IN", True), ("ZZ", False)])
def test_country_mapping(country, ok):
    assert (country.upper() in idmod.COUNTRY_QID) == ok
