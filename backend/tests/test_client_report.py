"""Client report: the approved template renders, internal sources are blocked, IOCs are defanged."""
import json
import re
from pathlib import Path

import pytest

from app.modules.phishing import client_report as cr

SPEC = Path(__file__).resolve().parents[2] / "docs" / "reports" / "chase-live-panel-2026-11-15.json"


def load():
    return json.loads(SPEC.read_text(encoding="utf-8"))


def test_approved_chase_spec_renders_in_template_order():
    html = cr.render_spec_file(SPEC)
    order = ["Executive summary", "At a glance", "Why we assess one operator", "How the kit works",
             "Related activity, not linked", "Impact", "Detection and hunting:", "Indicators of compromise",
             "MITRE ATT&amp;CK mapping", "Recommendations"]
    pos = [html.index(f">{h}</h1>") for h in order]
    assert pos == sorted(pos)
    assert "Rishika Desai" in html and "TLP:CLEAR" in html
    assert html.count("data:image/png;base64,") == 2          # figures embedded, report is self-contained
    assert 'color: #A61B1B;">login[.]php' in html             # prose IOCs: red italic, defanged
    assert "<b>page.ip:</b>104.194.139.2" in html             # query field names bold
    assert "page-break-before: always" in html


@pytest.mark.parametrize("text", [
    "citing the stored urlscan.io scans", "seen on URLScan", "reported by OpenPhish", "PhishTank verified",
    "newly registered (WhoisDS)", "found via crt.sh", "the automated verdict was clean", "it scored 100",
])
def test_internal_sources_are_refused(text):
    spec = load()
    spec["recommendations"][0][1].append(text)
    with pytest.raises(cr.ClientLeakError):
        cr.render(spec)


def test_hunting_query_syntax_is_allowed_and_image_src_ignored():
    spec = load()
    spec["figures"][0]["src"] = "https://urlscan.io/screenshots/x.png"  # not visible text
    assert cr.leak_check(spec) == []


def test_user_text_is_escaped():
    spec = load()
    spec["executive_summary"][0] = "<script>alert(1)</script> and [[evil[.]com]]"
    html = cr.render(spec)
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


def test_defang_house_style():
    assert cr.defang("chase-verify.duckdns.org") == "chase-verify[.]duckdns[.]org"
    assert cr.defang("104.194.139.2", "ip") == "104.194.139[.]2"
    assert cr.defang("104.194.139.2", "ip_full") == "104[.]194[.]139[.]2"
    assert cr.defang("login.php", "file") == "login[.]php"
    assert cr.defang("https://x.com/a") == "hxxps://x[.]com/a"
    assert cr.defang("already[.]defanged.com") == "already[.]defanged.com"


def test_ipv6_is_defanged():
    assert cr.defang("2a02:4780:44::f3ef", "ip") == "2a02:4780:44:[:]f3ef"


def test_brand_report_has_stats_and_charts():
    """Against the live database: Chase format, brand statistics, charts, no internal source names."""
    from sqlmodel import Session

    from app.db import get_engine, init_db
    from app.modules.phishing.report import available_brands
    init_db()
    with Session(get_engine()) as s:
        brands = [b["brand"] for b in available_brands(s)]
        if not brands:
            pytest.skip("no phishing data collected yet")
        spec = cr.build_for_brand(s, brands[0], "Tester", screenshots="link")
    html = cr.render(spec)
    assert f"{brands[0]} phishing in the last" in html and "Phishing pages" in html
    assert html.count("data:image/png;base64,") >= 3          # charts embedded
    for h in ("Executive summary", "At a glance", "Detection and hunting:", "Indicators of compromise", "Recommendations"):
        assert f">{h}</h1>" in html
    assert not re.search(r"urlscan|openphish|phishtank|whoisds", re.sub(r'src="[^"]*"', "", html), re.I)
