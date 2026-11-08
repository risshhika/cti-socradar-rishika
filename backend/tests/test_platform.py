"""Platform-level tests: scope config round trip, key_counts helper, review summary math."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app import config
from app.api.common import key_counts
from app.api.reviews import summarize
from app.models import AnalystReview


def test_scope_round_trip(tmp_path: Path, monkeypatch):
    class S:  # minimal stand-in for Settings
        scope_file = tmp_path / "scope.yaml"

    monkeypatch.setattr(config, "get_settings", lambda: S())
    scope = config.Scope()
    scope.phishing.brands = ["PayPal", "Revolut"]
    scope.landscape.region = "DACH"
    config.save_scope(scope)
    loaded = config.load_scope()
    assert loaded.phishing.brands == ["PayPal", "Revolut"]
    assert loaded.landscape.region == "DACH"
    assert loaded.landscape.months == 6


def test_key_counts_shares_and_none_label():
    kc = key_counts(["a", "a", None, "b", ""], top=5)
    assert kc[0].key == "a" and kc[0].count == 2 and abs(kc[0].share - 0.4) < 1e-9
    assert {k.key for k in kc} == {"a", "unknown", "b"}


def test_review_summary_uses_latest_verdict_per_entity():
    class FakeExec:
        def __init__(self, rows):
            self.rows = rows

        def all(self):
            return self.rows

    class FakeSession:
        def __init__(self, rows):
            self.rows = rows

        def exec(self, q):  # the query filters by entity_type; emulate for 'campaign' only
            et = None
            for crit in q._where_criteria:
                if getattr(crit.right, "value", None) in ("campaign", "sample", "kit", "victim", "actor", "iab", "briefing"):
                    et = crit.right.value
            return FakeExec([r for r in self.rows if r.entity_type == et])

    now = datetime.now(timezone.utc)
    rows = [
        AnalystReview(entity_type="campaign", entity_id=1, verdict="over_flag", created_at=now),
        AnalystReview(entity_type="campaign", entity_id=1, verdict="agree", created_at=now),  # latest wins
        AnalystReview(entity_type="campaign", entity_id=2, verdict="over_flag", created_at=now),
        AnalystReview(entity_type="campaign", entity_id=3, verdict="miss", created_at=now),
    ]
    out = summarize(FakeSession(rows))
    camp = next(s for s in out if s.entity_type == "campaign")
    assert camp.reviewed == 3 and camp.agree == 1 and camp.over_flag == 1 and camp.miss == 1
    assert camp.precision_proxy == 0.5
