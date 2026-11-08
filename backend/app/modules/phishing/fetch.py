"""Direct, passive page capture for P4 (allowed by the brief: "visiting them directly").

Safety: GET only, no JavaScript execution, no form submission, 10 s timeout, 2 MB cap, at most 3 redirects,
realistic desktop User-Agent, final URL recorded. HTML is stored on disk and only ever served back as
text/plain.
"""
from __future__ import annotations

import hashlib
import logging
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from ...config import get_settings

log = logging.getLogger(__name__)
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 10.0
MAX_REDIRECTS = 3
HTML_DIR = "phishing/html"


@dataclass
class FetchResult:
    status: str  # ok | offline | blocked | error | skipped
    http_status: int | None = None
    final_url: str | None = None
    html: str | None = None
    sha256: str | None = None
    size: int | None = None
    html_path: str | None = None
    ip: str | None = None
    content_type: str | None = None
    fetched_at: datetime | None = None
    error: str | None = None


def _resolve(host: str | None) -> str | None:
    if not host:
        return None
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def store_html(html: str) -> tuple[str, str, int]:
    data = html.encode("utf-8", "replace")
    sha = hashlib.sha256(data).hexdigest()
    rel = f"{HTML_DIR}/{sha}.html"
    path: Path = get_settings().artifacts_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(data)
    return sha, rel, len(data)


def fetch_page(url: str, client: httpx.Client | None = None) -> FetchResult:
    s = get_settings()
    own = client is None
    client = client or httpx.Client(
        timeout=TIMEOUT, follow_redirects=True, max_redirects=MAX_REDIRECTS,
        headers={"User-Agent": s.user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                 "Accept-Language": "en-US,en;q=0.9"},
    )
    now = datetime.now(timezone.utc)
    ip = _resolve(urlparse(url).hostname)
    try:
        with client.stream("GET", url) as resp:
            ctype = resp.headers.get("content-type", "")
            chunks, total = [], 0
            for chunk in resp.iter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BYTES:
                    break
            body = b"".join(chunks)[:MAX_BYTES]
            final_url = str(resp.url)
            code = resp.status_code
        if code in (401, 403, 429, 503) and len(body) < 20_000:
            status = "blocked"
        elif code >= 400:
            status = "offline"
        else:
            status = "ok"
        html = body.decode(resp.encoding or "utf-8", errors="replace") if body else ""
        sha, rel, size = store_html(html) if html else (None, None, 0)
        return FetchResult(status=status, http_status=code, final_url=final_url, html=html if status == "ok" else html,
                           sha256=sha, size=size, html_path=rel, ip=ip, content_type=ctype, fetched_at=now)
    except httpx.TooManyRedirects as exc:
        return FetchResult(status="error", error=f"too many redirects: {exc}", ip=ip, fetched_at=now)
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
        return FetchResult(status="offline", error=str(exc)[:200], ip=ip, fetched_at=now)
    except httpx.HTTPError as exc:
        return FetchResult(status="error", error=str(exc)[:200], ip=ip, fetched_at=now)
    except Exception as exc:  # noqa: BLE001 - never let one page kill the batch
        return FetchResult(status="error", error=f"{type(exc).__name__}: {str(exc)[:160]}", ip=ip, fetched_at=now)
    finally:
        if own:
            client.close()


def make_client() -> httpx.Client:
    s = get_settings()
    return httpx.Client(timeout=TIMEOUT, follow_redirects=True, max_redirects=MAX_REDIRECTS,
                        headers={"User-Agent": s.user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                                 "Accept-Language": "en-US,en;q=0.9"})
