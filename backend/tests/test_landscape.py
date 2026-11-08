from datetime import datetime, timezone

from app.modules.landscape import classify, iab, regions
from app.modules.landscape.pipeline import _flatten_tools, slugify
from app.modules.landscape.trends import actor_trend, trend_between


def test_region_mapping_and_scope_sets():
    assert regions.region_for_country("DE") == "Europe"
    assert regions.region_for_country("us") == "North America"
    assert regions.region_for_country("RU") == "CIS"
    assert regions.region_for_country(None) is None
    assert regions.countries_in("Global") is None
    assert regions.countries_in("DACH") == {"DE", "AT", "CH"}
    assert "GB" in regions.countries_in("europe") and "RU" not in regions.countries_in("Europe")
    assert regions.countries_in("FR") == {"FR"}
    assert regions.countries_in("Germany") == {"DE"}
    assert regions.countries_in("Narnia") == set()
    assert regions.country_matches_region("NL", "Benelux") and not regions.country_matches_region("NL", "Nordics")
    assert regions.countries_from_text("A German hospital and a US clinic")[:2] == ["DE", "US"]


def test_sector_normalisation_and_keywords():
    assert classify.normalize_sector("healthcare") == "Healthcare"
    assert classify.normalize_sector("Business Services") == "Professional Services"
    assert classify.normalize_sector("Totally new thing") == "Other"
    assert classify.sector_from_keywords("St Mary's Hospital NHS Trust") == "Healthcare"
    assert classify.sector_from_keywords("Acme Logistics & Freight GmbH") == "Transportation"
    assert classify.sector_from_keywords("xyz") is None
    assert classify.sector_matches("Healthcare", "healthcare") and not classify.sector_matches("Technology", "Healthcare")
    assert classify.sector_matches(None, "all")


def test_size_banding():
    assert classify.size_band("Annual revenue of $45 million") == ("mid", "revenue ≈ $45M")
    assert classify.size_band("The company employs 2,300 employees worldwide")[0] == "large"
    assert classify.size_band("A publicly traded multinational listed on NASDAQ")[0] == "enterprise"
    assert classify.size_band("Family-owned bakery")[0] == "small"
    assert classify.size_band(None, "Ministry of Health", "Government & Defense")[0] == "large"
    assert classify.size_band("Nothing useful here") == ("unknown", None)
    assert classify.revenue_from_text("revenue: USD 2.5 billion") == 2.5e9


def test_name_normalisation_for_cross_source():
    n = classify.normalize_name
    assert n("St. Mary's Hospital, Inc.") == n("St Marys Hospital")
    assert n("ACME Logistics GmbH & Co. KG") == "acme logistics and"
    assert n("https://www.example-corp.com") == "example"  # TLD and legal suffix stripped
    assert n("Dompé Farmaceutici S.p.A.") == n("Dompe Farmaceutici") == "dompe farmaceutici"


def test_iab_extraction():
    text = ('An initial access broker known as "miyako" is selling VPN access to a US healthcare network with revenue '
            'of $250 million. The RDP access listing is priced at $1,500 - $2,500; a Citrix access was sold for USD 3k. '
            'Qilin ransomware affiliates have bought from this broker.')
    assert iab.is_candidate("Broker sells VPN access", "")
    assert not iab.is_candidate("New iPhone released", "nothing here")
    assert iab.extract_prices(text) == (1500.0, 3000.0)
    assert iab.extract_revenue(text) == 250_000_000.0
    assert {"RDP", "VPN", "Citrix"} <= set(iab.extract_access_types(text))
    assert iab.extract_brokers(text) == ["miyako"]
    assert iab.extract_actors(text, ["qilin", "play", "akira"]) == ["qilin"]
    assert iab.relevance_score(text) > 0.5 > iab.relevance_score("The weather was lovely in Lisbon today.")
    assert iab.extract_prices("Ransom demand of $5,000,000 was paid") == (None, None)


def test_trends():
    assert trend_between(10, 20) == "rising" and trend_between(20, 10) == "falling"
    assert trend_between(0, 5) == "new" and trend_between(10, 11) == "flat" and trend_between(0, 0) == "flat"
    months = ["2026-08", "2026-09", "2026-10"]
    assert actor_trend({"2026-08": 4, "2026-09": 10}, months) == ("rising", 1.5)
    assert actor_trend({}, months) == ("flat", None)
    assert actor_trend({"2026-09": 3}, months) == ("new", None)
    assert datetime.now(timezone.utc).tzinfo is not None


def test_slugify_and_tools_flattening():
    assert slugify("Black X") == "black-x" and slugify("lockbit3") == "lockbit3" and slugify("Space Bears!") == "space-bears"
    assert slugify("владивосток").startswith("actor-")
    assert _flatten_tools(["Mimikatz", "Cobalt Strike"]) == ["Mimikatz", "Cobalt Strike"]
    assert _flatten_tools([{"CredentialTheft": ["Mimikatz"], "RMM-Tools": ["AnyDesk"]}]) == ["Mimikatz (CredentialTheft)", "AnyDesk (RMM-Tools)"]
    assert _flatten_tools({"Offsec": "Cobalt Strike"}) == ["Cobalt Strike (Offsec)"]
    assert _flatten_tools(None) == [] and all(isinstance(x, str) for x in _flatten_tools([{"name": "PsExec"}]))
