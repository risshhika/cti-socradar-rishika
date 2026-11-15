"""Pipeline "x_iab": run the X monitor queries, keep financial / fintech posts with evidence, enrich victims."""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

import httpx
from sqlmodel import Session, select

from ...config import get_settings
from ...models import XPost
from ...pipelines.runner import RunContext
from . import firmographics as fg
from . import xmon

STATE = "x_monitor_state.json"  # newest post id per query, so each run reads only new posts


def _state_path():
    return get_settings().cache_dir / STATE


def _load_state() -> dict[str, str]:
    p = _state_path()
    try:
        return json.loads(p.read_text()) if p.exists() else {}
    except ValueError:
        return {}


def store_post(session: Session, p: dict[str, Any], label: str, sectors: list[str], client: httpx.Client) -> tuple[XPost | None, bool]:
    """Upsert one API post. Returns (row or None if out of sector, created?)."""
    t = p["tweet"]
    row = session.exec(select(XPost).where(XPost.tweet_id == t["id"])).first()
    if row:
        if label not in row.queries:
            row.queries = row.queries + [label]
            session.add(row)
        return row, False
    links = [u.get("expanded_url") or u.get("url") for u in (t.get("entities") or {}).get("urls", []) if u.get("expanded_url") or u.get("url")]
    links = [u for u in links if "x.com/" not in u and "twitter.com/" not in u]
    alts = [m.get("alt_text") or "" for m in p["media"]]
    ex = xmon.extract(t.get("text", ""), links, alts)
    if not xmon.in_sectors(ex, sectors):
        return None, False
    raw_path, raw_sha = xmon.save_record(p)
    media = xmon.save_media(p, client)
    card_path, card_sha = xmon.render_card(p, media, raw_sha, [label])
    a = p["author"]
    created = t.get("created_at")
    row = XPost(tweet_id=t["id"], url=f"https://x.com/{a.get('username') or 'i'}/status/{t['id']}", author_id=t.get("author_id"),
                author_handle=a.get("username"), author_name=a.get("name"),
                created_at=datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None,
                lang=t.get("lang"), text=t.get("text", ""), queries=[label], links=links, media=media,
                metrics=t.get("public_metrics") or {}, raw_path=raw_path, raw_sha256=raw_sha, card_path=card_path,
                card_sha256=card_sha, **ex)
    if ex["victim_candidates"]:
        row.victim_name = ex["victim_candidates"][0]
    session.add(row)
    return row, True


def enrich(session: Session, row: XPost, refresh: bool = False) -> None:
    if not row.victim_name:
        return
    org = fg.lookup(session, row.victim_name, refresh=refresh, country_hint=(row.countries or [None])[0])
    row.org_id = org.id if org.status == "ok" else None
    session.add(row)


def run(ctx: RunContext) -> dict[str, Any]:
    sc = ctx.scope.landscape
    token = get_settings().x_bearer_token
    sectors = ctx.params.get("sectors") or sc.x_sectors
    if not sc.x_queries:
        raise RuntimeError("no X queries configured (landscape.x_queries in config/scope.yaml)")
    if not token:
        raise RuntimeError("CTIOPS_X_BEARER_TOKEN is not set in .env: the X monitor needs an X API bearer token "
                           "(Basic tier or higher for recent search)")
    state = _load_state()
    pages = int(ctx.params.get("max_pages", sc.x_max_pages))
    out: dict[str, Any] = {"sectors": sectors, "queries": {}}
    kept = new = 0
    with ctx.session() as session, httpx.Client(timeout=30, follow_redirects=True) as media_client:
        for q in sc.x_queries:
            label, query = q["label"], xmon.build_query(q["query"], sectors)
            ctx.log(f"query {label!r}: {query}")
            try:
                posts, newest, meta = xmon.search(query, token, start_time=xmon.window_start(), since_id=state.get(label),
                                                  max_pages=pages)
            except xmon.XUnavailable as e:
                ctx.log(f"  stopped: {e}")
                out["error"] = str(e)
                break
            except httpx.HTTPError as e:
                ctx.log(f"  failed: {e}")
                out["queries"][label] = {"error": str(e)}
                continue
            q_kept = q_new = 0
            for p in posts:
                row, created = store_post(session, p, label, sectors, media_client)
                q_kept += row is not None
                q_new += created
            session.commit()
            if newest:
                state[label] = newest
            ctx.log(f"  {len(posts)} posts read, {q_kept} financial/fintech kept, {q_new} new"
                    + (f" (rate limited until {meta['rate_limited_until']})" if meta.get("rate_limited_until") else ""))
            out["queries"][label] = {"read": len(posts), "kept": q_kept, "new": q_new, **meta}
            kept, new = kept + q_kept, new + q_new
        _state_path().write_text(json.dumps(state))
        # enrich new victims (one registry lookup per distinct name; cached for a week)
        todo = session.exec(select(XPost).where(XPost.victim_name.is_not(None), XPost.org_id.is_(None))).all()
        names = {}
        for row in todo:
            names.setdefault(row.victim_name, []).append(row)
        for name, rows in list(names.items())[:40]:
            org = fg.lookup(session, name, country_hint=(rows[0].countries or [None])[0])
            for row in rows:
                row.org_id = org.id if org.status == "ok" else None
                session.add(row)
            ctx.log(f"company data {name!r}: {org.status}"
                    + (f", {org.revenue_band or 'revenue n/a'}, {org.employee_band or 'staff n/a'}, {org.industry or 'industry n/a'}"
                       if org.status == "ok" else ""))
        session.commit()
    out.update({"kept": kept, "new": new, "enriched_names": len(names)})
    return out


# --------------------------------------------------------------------------- browser capture import

def browser_item_to_post(it: dict[str, Any]) -> dict[str, Any]:
    """A post read from x.com search results in the browser -> the API record shape store_post expects."""
    imgs = [u for u in it.get("images", []) if "pbs.twimg.com/media" in u]
    media = []
    for i, u in enumerate(imgs):
        base = u.split("?")[0]
        fmt = re.search(r"format=(\w+)", u)
        media.append({"media_key": f"b{i}", "type": "photo", "url": base + (f".{fmt.group(1)}" if fmt and "." not in base.rsplit("/", 1)[-1] else ""),
                      "alt_text": (it.get("alts") or [None] * len(imgs))[i] if i < len(it.get("alts") or []) else None})
    return {"tweet": {"id": str(it["id"]), "text": it.get("text", ""), "created_at": it.get("created_at"),
                      "author_id": it.get("handle"), "entities": {"urls": [{"expanded_url": u} for u in it.get("links", [])]}},
            "author": {"username": it.get("handle"), "name": it.get("name")}, "media": media,
            "capture": {"method": "browser", "search_url": it.get("search_url"), "read_at": it.get("read_at")}}


def import_browser_posts(session: Session, items: list[dict[str, Any]], sectors: list[str]) -> dict[str, Any]:
    kept, new, skipped = [], 0, 0
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for it in items:
            p = browser_item_to_post(it)
            row, created = store_post(session, p, it.get("query", "browser"), sectors, client)
            if row is None:
                skipped += 1
                continue
            row.capture_method = "browser" if created else row.capture_method
            session.add(row)
            kept.append(row.tweet_id)
            new += created
        session.commit()
    return {"read": len(items), "kept": len(kept), "new": new, "out_of_sector": skipped, "kept_ids": kept}


def attach_shot(session: Session, tweet_id: str, image: bytes) -> XPost | None:
    """Store the x.com screenshot of a post next to its evidence, hashed."""
    import hashlib
    row = session.exec(select(XPost).where(XPost.tweet_id == str(tweet_id))).first()
    if not row:
        return None
    ext = ".png" if image[:4] == bytes([0x89, 0x50, 0x4E, 0x47]) else ".jpg"
    f = xmon.evidence_dir(row.tweet_id) / f"xcom_screenshot{ext}"
    f.write_bytes(image)
    row.shot_path = str(f.relative_to(get_settings().artifacts_dir))
    row.shot_sha256 = hashlib.sha256(image).hexdigest()
    session.add(row)
    session.commit()
    return row
