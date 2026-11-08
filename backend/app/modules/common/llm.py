"""Optional Claude helper. Everything in the platform works without a key; the LLM only upgrades
classification quality and briefing prose. Every prompt is logged to data/artifacts/prompts.jsonl so
the know-how report can list them."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from ...config import get_settings

log = logging.getLogger(__name__)


def available() -> bool:
    return bool(get_settings().anthropic_api_key)


def _log_prompt(purpose: str, system: str, user: str, output: str | None) -> None:
    s = get_settings()
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "model": s.anthropic_model, "purpose": purpose,
           "system": system, "user": user[:4000], "output": (output or "")[:4000]}
    with (s.artifacts_dir / "prompts.jsonl").open("a") as fh:
        fh.write(json.dumps(rec) + "\n")


def complete(purpose: str, system: str, user: str, max_tokens: int = 1500, json_mode: bool = False) -> str | None:
    """Return model text or None when no key / failure. Never raises."""
    s = get_settings()
    if not s.anthropic_api_key:
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=s.anthropic_api_key)
        msg = client.messages.create(
            model=s.anthropic_model,
            max_tokens=max_tokens,
            system=system + ("\nRespond with a single JSON object and nothing else." if json_mode else ""),
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(getattr(b, "text", "") for b in msg.content)
        _log_prompt(purpose, system, user, text)
        return text
    except Exception as exc:  # network, auth, quota
        log.warning("LLM call failed (%s): %s", purpose, exc)
        _log_prompt(purpose, system, user, f"ERROR: {exc}")
        return None


def complete_json(purpose: str, system: str, user: str, max_tokens: int = 1500) -> dict[str, Any] | None:
    text = complete(purpose, system, user, max_tokens=max_tokens, json_mode=True)
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.split("\n", 1)[1] if "\n" in text else text
    try:
        return json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except ValueError:
                return None
    return None
