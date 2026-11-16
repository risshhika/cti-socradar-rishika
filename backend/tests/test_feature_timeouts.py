"""Several hung pages are abandoned together in one pool teardown, not timed out one after another."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import _hang_helper  # noqa: E402

from app.modules.phishing import pipeline as pl  # noqa: E402


class _Ctx:
    def __init__(self):
        self.lines = []

    def log(self, m):
        self.lines.append(m)


def test_hung_pages_are_dropped_in_one_teardown(monkeypatch):
    monkeypatch.setattr(pl, "_featurize", _hang_helper.featurize)
    monkeypatch.setattr(pl, "_read_html", lambda rel: "<html><body>x</body></html>")
    monkeypatch.setattr(pl, "FEATURE_TIMEOUT", 4.0)
    monkeypatch.setattr(pl, "FEATURE_WORKERS", 4)
    jobs = [(i, None, f"https://ok{i}.example/", None) for i in range(6)]
    jobs += [(100 + i, None, f"https://hang{i}.example/", None) for i in range(3)]
    t0 = time.monotonic()
    res = pl._featurize_all(_Ctx(), jobs)
    elapsed = time.monotonic() - t0
    assert all(not isinstance(res[i], Exception) for i in range(6))
    assert all(isinstance(res[100 + i], TimeoutError) for i in range(3))
    # one cap (4s) plus pool start-up, not three caps back to back (12s+)
    assert elapsed < 11, f"took {elapsed:.1f}s"
