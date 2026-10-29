#!/usr/bin/env python3
"""Collect the newest mixed-protocol FreeProxyDB pages.

The public search API returns at most 100 records per request and limits the
total records returned per client IP. Every run therefore reads pages 1..20,
ordered by the most recent check, for a maximum of 2,000 current nodes. A
short-lived snapshot is used only as a fallback when a run is interrupted; it
is never used to continue into older pages.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CACHE_FILE = ROOT / "output" / "metadata" / "freeproxydb_cache.json"
BASE_URL = "https://freeproxydb.com/api/proxy/search"
PROTOCOLS = ("vless", "vmess", "trojan", "ss")
SUPPORTED_PREFIXES = tuple(f"{protocol}://" for protocol in PROTOCOLS)

PAGE_SIZE = 100
MAX_PAGES = 20
PAGE_DELAY = max(
    0.0,
    float(os.environ.get("FREEPROXYDB_PAGE_DELAY", "2")),
)
SNAPSHOT_MAX_AGE_HOURS = max(
    1,
    int(os.environ.get("FREEPROXYDB_CACHE_MAX_AGE_HOURS", "72")),
)
MAX_RETRIES = 3


class RateLimited(RuntimeError):
    """The public API record quota has been reached for this runner IP."""


def fetch_json(url: str) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "VPN-Nodes-Catalog/1.0",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                # A short sleep does not reliably reset the per-IP record
                # quota. Keep the previous snapshot instead.
                raise RateLimited("public API record quota reached") from exc
            if 500 <= exc.code < 600 and attempt < MAX_RETRIES:
                time.sleep(attempt * 5)
                continue
            raise
        except (OSError, json.JSONDecodeError):
            if attempt >= MAX_RETRIES:
                raise
            time.sleep(attempt * 5)

    raise RuntimeError("FreeProxyDB request failed")


def build_url(page: int) -> str:
    params = {
        "protocol": ",".join(PROTOCOLS),
        "speed": "0,60",
        "page_index": page,
        "page_size": PAGE_SIZE,
        "order_by": "last_checked",
        "order_dir": "desc",
    }
    return BASE_URL + "?" + urllib.parse.urlencode(params)


def extract_uri(item) -> str:
    if isinstance(item, str):
        value = item.strip()
        return value if value.startswith(SUPPORTED_PREFIXES) else ""

    if not isinstance(item, dict):
        return ""

    for key in (
        "connect_string",
        "uri",
        "config",
        "link",
        "url",
        "v2ray",
        "subscription",
    ):
        value = item.get(key)
        if isinstance(value, str):
            value = value.strip()
            if value.startswith(SUPPORTED_PREFIXES):
                return value

    return ""


def _positive_int(*values) -> int:
    for value in values:
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number > 0:
            return number
    return 0


def extract_data(payload: dict) -> tuple[list, int]:
    if not isinstance(payload, dict):
        return [], 0

    container = payload.get("data", [])
    if isinstance(container, dict):
        rows = (
            container.get("data")
            or container.get("items")
            or container.get("list")
            or []
        )
        total = _positive_int(
            container.get("total_count"),
            container.get("total"),
            container.get("count"),
            payload.get("total_count"),
            payload.get("total"),
        )
        return (rows if isinstance(rows, list) else []), total

    total = _positive_int(payload.get("total_count"), payload.get("total"))
    return (container if isinstance(container, list) else []), total


def _load_snapshot(now: int) -> dict[str, int]:
    if not CACHE_FILE.is_file():
        return {}

    try:
        payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    cutoff = now - SNAPSHOT_MAX_AGE_HOURS * 3600
    nodes: dict[str, int] = {}
    for item in payload.get("nodes", []):
        if not isinstance(item, dict):
            continue

        uri = str(item.get("uri") or "").strip()
        try:
            seen_at = int(item.get("last_seen_at") or 0)
        except (TypeError, ValueError):
            continue

        if uri.startswith(SUPPORTED_PREFIXES) and seen_at >= cutoff:
            nodes[uri] = max(nodes.get(uri, 0), seen_at)

    return nodes


def _save_snapshot(
    nodes: dict[str, int],
    *,
    total_count: int,
    pages_fetched: int,
    complete: bool,
    rate_limited: bool,
    now: int,
) -> dict[str, int]:
    limit = PAGE_SIZE * MAX_PAGES
    cutoff = now - SNAPSHOT_MAX_AGE_HOURS * 3600
    ordered = sorted(
        (
            (uri, seen_at)
            for uri, seen_at in nodes.items()
            if uri.startswith(SUPPORTED_PREFIXES) and seen_at >= cutoff
        ),
        key=lambda row: (-row[1], row[0]),
    )[:limit]
    kept = dict(ordered)

    payload = {
        "schema": 2,
        "mode": "newest_mixed_protocol_pages",
        "generated_at": now,
        "protocols": list(PROTOCOLS),
        "order_by": "last_checked",
        "order_dir": "desc",
        "page_size": PAGE_SIZE,
        "max_pages": MAX_PAGES,
        "snapshot_max_age_hours": SNAPSHOT_MAX_AGE_HOURS,
        "total_count_reported": total_count,
        "pages_fetched": pages_fetched,
        "complete": complete,
        "rate_limited": rate_limited,
        "nodes": [
            {"uri": uri, "last_seen_at": seen_at}
            for uri, seen_at in ordered
        ],
    }

    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = CACHE_FILE.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(CACHE_FILE)
    return kept


def collect_freeproxydb() -> list[dict]:
    now = int(time.time())
    previous = _load_snapshot(now)
    current: dict[str, int] = {}
    total_count = 0
    pages_fetched = 0
    rate_limited = False
    reached_end = False

    for page in range(1, MAX_PAGES + 1):
        try:
            payload = fetch_json(build_url(page))
        except RateLimited as exc:
            rate_limited = True
            print(
                f"INFO FreeProxyDB page {page}: {exc}; "
                "using the latest available snapshot"
            )
            break
        except Exception as exc:
            print(
                f"WARN FreeProxyDB page {page}: {exc}; "
                "using the latest available snapshot"
            )
            break

        data, reported_total = extract_data(payload)
        total_count = max(total_count, reported_total)
        if not data:
            reached_end = True
            break

        pages_fetched += 1
        for item in data:
            uri = extract_uri(item)
            if uri:
                current[uri] = now

        print(
            f"FreeProxyDB page {page}: records={len(data)} "
            f"newest_snapshot={len(current)} "
            f"total={total_count or 'unknown'}"
        )

        if len(data) < PAGE_SIZE:
            reached_end = True
            break
        if page < MAX_PAGES:
            time.sleep(PAGE_DELAY)

    complete = reached_end or pages_fetched == MAX_PAGES
    if complete:
        selected = current
    else:
        # A partial failure must not publish zero nodes. Fresh rows take
        # priority, then the previous newest-2,000 snapshot fills the gap.
        selected = dict(current)
        for uri, seen_at in sorted(
            previous.items(),
            key=lambda row: (-row[1], row[0]),
        ):
            if len(selected) >= PAGE_SIZE * MAX_PAGES:
                break
            selected.setdefault(uri, seen_at)

    selected = _save_snapshot(
        selected,
        total_count=total_count,
        pages_fetched=pages_fetched,
        complete=complete,
        rate_limited=rate_limited,
        now=now,
    )

    counts = Counter(uri.split("://", 1)[0].lower() for uri in selected)
    rows = [
        {
            "name": f"FreeProxyDB-{uri.split('://', 1)[0].lower()}",
            "source": "FreeProxyDB-api",
            "url": uri,
            "protocol": uri.split("://", 1)[0].lower(),
        }
        for uri in sorted(selected)
    ]

    details = ", ".join(
        f"{protocol}={counts.get(protocol, 0)}"
        for protocol in PROTOCOLS
    )
    print(
        f"OK source FreeProxyDB-api: newest={len(rows)} "
        f"pages={pages_fetched}/{MAX_PAGES} "
        f"fallback={not complete} ({details})"
    )
    return rows

