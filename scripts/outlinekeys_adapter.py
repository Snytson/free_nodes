#!/usr/bin/env python3
"""Daily adapter for recent OutlineKeys entries.

The adapter is intentionally stateful:
- remote refreshes are throttled to once per 24 hours;
- after the first bootstrap, the monotonic key id is used as the cursor so
  scheduler delays do not create gaps;
- detail pages that fail are kept as pending and retried on the next refresh;
- only exact URI duplicates are removed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import requests
from share_link_extractor import extract_uri_records

BASE_URL = "https://outlinekeys.com/"
CACHE_PATH = Path(__file__).resolve().parents[1] / "output" / "metadata" / "outlinekeys_daily_cache.json"
WINDOW_SECONDS = 24 * 60 * 60
MAX_PAGES = 500
REQUEST_TIMEOUT = 20
REQUEST_DELAY_SECONDS = 0.10
URI_RE = re.compile(r"(?i)(?:vless|vmess|trojan|ss)://[^\s<>\"']+")
AGE_RE = re.compile(r"\b(\d+)\s+(minute|minutes|hour|hours|day|days)\s+ago\b", re.I)


@dataclass(frozen=True)
class KeyRef:
    key_id: int
    url: str
    age_seconds: int | None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _age_seconds(text: str) -> int | None:
    match = AGE_RE.search(text)
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if unit.startswith("minute"):
        return amount * 60
    if unit.startswith("hour"):
        return amount * 60 * 60
    return amount * 24 * 60 * 60


def parse_listing(html: str) -> list[KeyRef]:
    soup = BeautifulSoup(html, "html.parser")
    found: list[KeyRef] = []
    seen: set[int] = set()
    for anchor in soup.find_all("a", href=True):
        absolute = urljoin(BASE_URL, anchor.get("href", ""))
        parsed = urlparse(absolute)
        if parsed.netloc.lower() not in {"outlinekeys.com", "www.outlinekeys.com"}:
            continue
        match = re.fullmatch(r"/key/(\d+)/?", parsed.path)
        if not match:
            continue
        key_id = int(match.group(1))
        if key_id in seen:
            continue
        seen.add(key_id)
        found.append(KeyRef(key_id, absolute, _age_seconds(" ".join(anchor.stripped_strings))))
    return found


def extract_uri(html: str) -> str | None:
    records = extract_uri_records(html, html_source=True)
    return records[0].uri if records else None


def _load_cache(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_cache(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _request_text(session: requests.Session, url: str) -> str:
    response = session.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.text


def _discover(session: requests.Session, *, last_key_id: int | None) -> tuple[list[KeyRef], int | None]:
    selected: list[KeyRef] = []
    newest_seen = last_key_id
    boundary_found = False
    for page in range(1, MAX_PAGES + 1):
        url = BASE_URL if page == 1 else f"{BASE_URL}?page={page}"
        refs = parse_listing(_request_text(session, url))
        if not refs:
            raise RuntimeError(f"OutlineKeys page {page} contained no key links")
        page_ids = [item.key_id for item in refs]
        page_max = max(page_ids)
        newest_seen = page_max if newest_seen is None else max(newest_seen, page_max)
        if last_key_id is None:
            selected.extend(item for item in refs if item.age_seconds is not None and item.age_seconds < WINDOW_SECONDS)
            known_ages = [item.age_seconds for item in refs if item.age_seconds is not None]
            if any(age >= WINDOW_SECONDS for age in known_ages):
                boundary_found = True
                break
        else:
            selected.extend(item for item in refs if item.key_id > last_key_id)
            if min(page_ids) <= last_key_id:
                boundary_found = True
                break
        time.sleep(REQUEST_DELAY_SECONDS)
    if not boundary_found:
        mode = "24h bootstrap" if last_key_id is None else f"cursor {last_key_id}"
        raise RuntimeError(f"OutlineKeys pagination boundary not reached for {mode} within {MAX_PAGES} pages")
    unique = {item.key_id: item for item in selected}
    return sorted(unique.values(), key=lambda item: item.key_id), newest_seen


def collect_outlinekeys(*, cache_path: Path = CACHE_PATH, now: datetime | None = None, session: requests.Session | None = None) -> list[dict]:
    now = now or _utc_now()
    cache = _load_cache(cache_path)
    last_attempt = _parse_iso(cache.get("last_attempt_at"))
    if last_attempt is not None:
        elapsed = (now - last_attempt).total_seconds()
        if 0 <= elapsed < WINDOW_SECONDS:
            rows = cache.get("rows") or []
            print(f"INFO OutlineKeys: using daily cache nodes={len(rows)} age_seconds={int(elapsed)}")
            return rows

    last_key_id = cache.get("last_key_id") if isinstance(cache.get("last_key_id"), int) else None
    pending: dict[int, str] = {}
    for item in cache.get("pending") or []:
        if isinstance(item, dict) and isinstance(item.get("key_id"), int) and isinstance(item.get("url"), str):
            pending[item["key_id"]] = item["url"]

    own_session = session is None
    session = session or requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; VPN-Nodes/1.0)", "Accept": "text/html,application/xhtml+xml"})
    attempt_at = _iso(now)
    try:
        discovered, newest_seen = _discover(session, last_key_id=last_key_id)
        refs = dict(pending)
        refs.update({item.key_id: item.url for item in discovered})
        rows: list[dict] = []
        seen_uris: set[str] = set()
        failed: list[dict] = []
        for key_id, url in sorted(refs.items()):
            try:
                records = extract_uri_records(_request_text(session, url), html_source=True)
                if not records:
                    raise RuntimeError("supported URI not found")
                record = records[0]
                uri = record.uri
                if uri not in seen_uris:
                    seen_uris.add(uri)
                    rows.append({"url": uri, **record.source_fields()})
            except Exception as exc:
                failed.append({"key_id": key_id, "url": url, "error": str(exc)[:300]})
            time.sleep(REQUEST_DELAY_SECONDS)
        _write_cache(cache_path, {"version": 1, "last_attempt_at": attempt_at, "last_success_at": attempt_at, "last_key_id": newest_seen, "pending": failed, "rows": rows})
        print(f"OK OutlineKeys: new_keys={len(discovered)} retried={len(pending)} nodes={len(rows)} pending={len(failed)} cursor={newest_seen}")
        return rows
    except Exception as exc:
        fallback_rows = cache.get("rows") or []
        state = dict(cache)
        state.update({"version": 1, "last_attempt_at": attempt_at, "last_error": str(exc)[:500]})
        _write_cache(cache_path, state)
        if fallback_rows:
            print(f"WARN OutlineKeys: refresh failed; using previous daily cache nodes={len(fallback_rows)} error={exc}")
            return fallback_rows
        raise
    finally:
        if own_session:
            session.close()
