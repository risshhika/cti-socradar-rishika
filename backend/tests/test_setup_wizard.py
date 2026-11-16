"""First-run setup: a fresh clone cannot start without its own keys, and .env edits never lose other lines."""
import pytest

from app import cli
from app import setup_wizard as w


@pytest.fixture
def fresh_clone(tmp_path, monkeypatch):
    """No .env, no setup marker, no keys in the environment: what someone sees after git clone."""
    monkeypatch.setattr(w, "ENV_PATH", tmp_path / ".env")
    monkeypatch.delenv("CTIOPS_SKIP_SETUP", raising=False)
    monkeypatch.delenv(w.DONE_KEY, raising=False)
    for k in w.KEYS:
        monkeypatch.delenv(k.env, raising=False)
    return tmp_path / ".env"


def test_fresh_clone_is_not_configured(fresh_clone):
    assert not w.is_configured()
    assert all("not set" in line for line in w.status_lines())


def test_serve_refused_without_setup_when_not_interactive(fresh_clone, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert w.preflight("serve") is False
    assert "app.cli setup" in capsys.readouterr().err
    # the CLI exits non-zero before touching the database or starting the server
    assert cli.main(["serve"]) == 2
    assert cli.main(["run", "phishing"]) == 2


def test_interactive_user_who_declines_setup_cannot_start(fresh_clone, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    assert w.preflight("serve") is False


def test_setup_writes_keys_and_marker(fresh_clone, monkeypatch):
    answers = {"CTIOPS_REPORT_REPORTER": "Jane Analyst", "CTIOPS_URLSCAN_API_KEY": "us-key-1234567890"}

    def fake_ask(k, current):
        return answers.get(k.env)  # None = skip

    monkeypatch.setattr(w, "_ask", fake_ask)
    monkeypatch.setattr(w, "_yes", lambda q, default: False)  # no network key check
    assert w.run_setup()
    env = w.read_env()
    assert env["CTIOPS_REPORT_REPORTER"] == "Jane Analyst" and env["CTIOPS_URLSCAN_API_KEY"] == "us-key-1234567890"
    assert env[w.DONE_KEY] == "1" and w.is_configured()
    assert "CTIOPS_SHODAN_API_KEY" not in env  # skipped keys are not written
    assert "us-key-1234567890" not in "\n".join(w.status_lines())  # secrets never displayed in full


def test_write_env_keeps_other_lines_and_clears(fresh_clone):
    fresh_clone.write_text("# my comment\nCTIOPS_DATA_DIR=./data\nCTIOPS_SHODAN_API_KEY=old\n", encoding="utf-8")
    w.write_env({"CTIOPS_SHODAN_API_KEY": "", "CTIOPS_REPORT_REPORTER": "A B"})
    text = fresh_clone.read_text(encoding="utf-8")
    assert "# my comment" in text and "CTIOPS_DATA_DIR=./data" in text
    assert "CTIOPS_SHODAN_API_KEY" not in text  # '-' / empty clears
    assert 'CTIOPS_REPORT_REPORTER="A B"' in text and w.read_env()["CTIOPS_REPORT_REPORTER"] == "A B"


def test_skip_flag_for_automated_tests(fresh_clone, monkeypatch):
    monkeypatch.setenv("CTIOPS_SKIP_SETUP", "1")
    assert w.preflight("run") is True
