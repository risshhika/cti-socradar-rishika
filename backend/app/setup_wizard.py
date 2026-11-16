"""First-run setup: every user supplies their own API keys before the platform runs.

API keys are personal (each is tied to the account and quota of whoever created it), so none ship with the
repository. `python -m app.cli setup` asks for each one, explains what it unlocks and where to get it, and
writes them to `.env` at the repo root (git-ignored). `serve` and `run` refuse to start until setup has been
completed once on this machine; non-interactive starts (CI, IDE launchers) get an explanation instead of a
prompt. Set CTIOPS_SKIP_SETUP=1 only for automated tests.
"""
from __future__ import annotations

import getpass
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import REPO_ROOT

ENV_PATH = REPO_ROOT / ".env"
DONE_KEY = "CTIOPS_SETUP_COMPLETE"


@dataclass(frozen=True)
class Key:
    env: str
    label: str
    unlocks: str
    get_it: str
    secret: bool = True
    recommended: bool = False


KEYS: list[Key] = [
    Key("CTIOPS_REPORT_REPORTER", "Your name (printed as reporter on client reports)",
        "the reporter line on every client and brand report", "your own name", secret=False, recommended=True),
    Key("CTIOPS_URLSCAN_API_KEY", "urlscan.io API key",
        "P4: higher search quotas and downloading scan DOMs instead of visiting phishing pages directly",
        "free account at https://urlscan.io/user/signup, then Settings & API -> API key", recommended=True),
    Key("CTIOPS_REGISTRY_USER_AGENT", "Contact User-Agent for public company registries",
        "P6: victim revenue, employees and industry from Wikidata and SEC EDGAR (both refuse anonymous clients)",
        'a string with your contact, e.g. ctiops-research/0.1 (you@example.org)', secret=False, recommended=True),
    Key("CTIOPS_SHODAN_API_KEY", "Shodan API key",
        "P6: which exposed host runs a product named in an access-broker post (victim identification)",
        "https://account.shodan.io (search filters need a paid membership)"),
    Key("CTIOPS_X_BEARER_TOKEN", "X (Twitter) API bearer token",
        "P6: scheduled X access-broker monitoring (queries and watched accounts)",
        "https://developer.x.com, Basic tier or higher (recent search)"),
    Key("CTIOPS_ZOOMINFO_USERNAME", "ZoomInfo API username", "P6: company search and enrichment (enterprise contract)",
        "your ZoomInfo admin, Admin Portal -> API", secret=False),
    Key("CTIOPS_ZOOMINFO_PASSWORD", "ZoomInfo API password", "used with the ZoomInfo username", "your ZoomInfo admin"),
    Key("CTIOPS_ANTHROPIC_API_KEY", "Anthropic API key",
        "optional LLM upgrades: sector classification, IAB extraction, briefing prose",
        "https://console.anthropic.com -> API keys"),
]


# --------------------------------------------------------------------------- .env read / write

def read_env(path: Path | None = None) -> dict[str, str]:
    path = path or ENV_PATH
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = s.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def write_env(values: dict[str, str], path: Path | None = None) -> None:
    """Update or add keys, keeping every other line (comments, unrelated settings) as it was."""
    path = path or ENV_PATH
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    seen: set[str] = set()
    out = []
    for line in lines:
        k = line.split("=", 1)[0].strip() if "=" in line and not line.strip().startswith("#") else None
        if k in values:
            seen.add(k)
            if values[k] != "":
                out.append(f"{k}={_quote(values[k])}")
            continue  # an emptied value removes the line
        out.append(line)
    for k, v in values.items():
        if k not in seen and v != "":
            out.append(f"{k}={_quote(v)}")
    path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)  # owner-only where the OS supports it
    except OSError:
        pass


def _quote(v: str) -> str:
    return f'"{v}"' if any(c in v for c in " #'") and not v.startswith('"') else v


def _mask(v: str) -> str:
    return "set" if len(v) < 8 else f"set (...{v[-4:]})"


# --------------------------------------------------------------------------- status + preflight

def is_configured(env: dict[str, str] | None = None) -> bool:
    env = read_env() if env is None else env
    return os.environ.get(DONE_KEY, env.get(DONE_KEY, "")) == "1"


def status_lines(env: dict[str, str] | None = None) -> list[str]:
    env = read_env() if env is None else env
    rows = []
    for k in KEYS:
        v = os.environ.get(k.env) or env.get(k.env, "")
        state = (_mask(v) if k.secret else f"set ({v})") if v else "not set"
        rows.append(f"  {'OK ' if v else ' - '} {k.label:<52} {state}")
    return rows


def preflight(command: str, assume_yes: bool = False) -> bool:
    """Called before `serve` / `run`. True = go ahead. Runs setup on first use; never starts unconfigured."""
    if os.environ.get("CTIOPS_SKIP_SETUP") == "1":
        return True
    env = read_env()
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not is_configured(env):
        print("\nThis copy of the CTI Ops platform has not been set up on this machine yet.\n"
              "API keys are personal and are NOT included in the repository: you need your own.")
        if not interactive:
            print(f"\nRefusing to {command} without setup. In a terminal, run:\n\n"
                  f"    cd backend && python -m app.cli setup\n\n"
                  f"(CTIOPS_SKIP_SETUP=1 bypasses this for automated tests only.)", file=sys.stderr)
            return False
        if not assume_yes and not _yes("Run setup now?", default=True):
            print("Setup is required before the platform can run. Exiting.")
            return False
        return run_setup()
    print("\nAPI keys in use (from .env, never shared via git):")
    print("\n".join(status_lines(env)))
    missing = [k for k in KEYS if k.recommended and not (os.environ.get(k.env) or env.get(k.env))]
    if missing and interactive and not assume_yes:
        print("\nRecommended keys missing: " + ", ".join(k.label for k in missing)
              + ".\nThe matching features will be degraded. Run `python -m app.cli setup` to add them.")
        if not _yes(f"Continue to {command} anyway?", default=True):
            return False
    return True


# --------------------------------------------------------------------------- interactive setup

def _yes(q: str, default: bool) -> bool:
    try:
        a = input(f"{q} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    except EOFError:
        return default
    return default if not a else a.startswith("y")


def _ask(k: Key, current: str) -> str | None:
    """New value, '' to clear, or None to keep the current one."""
    print(f"\n{k.label}{'  (recommended)' if k.recommended else ''}")
    print(f"  Unlocks: {k.unlocks}")
    print(f"  Get it:  {k.get_it}")
    hint = f"current: {_mask(current) if k.secret else current}; Enter keeps it, '-' clears it" if current \
        else "Enter to skip"
    prompt = f"  Value ({hint}): "
    try:
        v = (getpass.getpass(prompt) if k.secret else input(prompt)).strip()
    except EOFError:
        return None
    if v == "-":
        return ""
    return v or None


def check_keys(env: dict[str, str]) -> list[str]:
    """Light validation against each service's free account endpoint (no searches, no quota spent)."""
    import httpx
    out = []
    with httpx.Client(timeout=15, headers={"User-Agent": "ctiops-setup/0.1"}) as c:
        if env.get("CTIOPS_URLSCAN_API_KEY"):
            try:
                r = c.get("https://urlscan.io/user/quotas/", headers={"API-Key": env["CTIOPS_URLSCAN_API_KEY"]})
                out.append(f"  urlscan.io: {'valid' if r.status_code == 200 else f'rejected (HTTP {r.status_code})'}")
            except httpx.HTTPError as e:
                out.append(f"  urlscan.io: could not check ({type(e).__name__})")
        if env.get("CTIOPS_SHODAN_API_KEY"):
            try:
                r = c.get("https://api.shodan.io/api-info", params={"key": env["CTIOPS_SHODAN_API_KEY"]})
                plan = r.json().get("plan") if r.status_code == 200 else None
                out.append(f"  Shodan: {f'valid (plan: {plan})' if plan else f'rejected (HTTP {r.status_code})'}")
            except (httpx.HTTPError, ValueError) as e:
                out.append(f"  Shodan: could not check ({type(e).__name__})")
    return out


def run_setup() -> bool:
    env = read_env()
    print("\n=== CTI Ops platform setup ===\n"
          f"Keys are saved to {ENV_PATH} (git-ignored, owner-only). Nothing is sent anywhere except, if you\n"
          "agree at the end, a validity check to urlscan.io and Shodan using your own keys.\n"
          "Every key is optional, but features that need a missing key are switched off.")
    updates: dict[str, str] = {}
    for k in KEYS:
        v = _ask(k, env.get(k.env, ""))
        if v is not None:
            updates[k.env] = v
    merged = {**env, **updates}
    if any(merged.get(k) for k in ("CTIOPS_URLSCAN_API_KEY", "CTIOPS_SHODAN_API_KEY")) and _yes("\nCheck the keys now?", True):
        print("\n".join(check_keys(merged)) or "  nothing to check")
    updates[DONE_KEY] = "1"
    write_env(updates)
    print("\nSaved. Current configuration:")
    print("\n".join(status_lines(read_env())))
    print("\nRe-run `python -m app.cli setup` any time to change a key.\n")
    _reload_settings()
    return True


def _reload_settings() -> None:
    from .config import get_settings
    get_settings.cache_clear()


def reporter_name(explicit: str | None = None) -> str:
    """Report author: the --reporter flag, else CTIOPS_REPORT_REPORTER, else scope.yaml, else 'Analyst'."""
    from .config import get_settings, load_scope
    return explicit or get_settings().report_reporter or load_scope().phishing.report_reporter or "Analyst"
