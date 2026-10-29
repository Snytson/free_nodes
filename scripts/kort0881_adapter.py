#!/usr/bin/env python3
"""Dynamic adapter for every feed listed by kort0881/vpn-checker-backend."""

from __future__ import annotations

import hashlib
import urllib.request
from urllib.parse import urlsplit

import update_catalog as catalog


SOURCE_NAME = "kort0881-vpn-checker-backend"
INDEX_URL = (
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/"
    "main/checked/subscriptions_list.txt"
)
ALLOWED_HOST = "raw.githubusercontent.com"
ALLOWED_PATH_PREFIX = "/kort0881/vpn-checker-backend/main/checked/"
MAX_INDEX_BYTES = 256_000
MAX_FEED_BYTES = 64 * 1024 * 1024
TIMEOUT_SECONDS = 20


def fetch_bytes(url: str, max_bytes: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "VPN-Nodes-Catalog/1.0"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"kort0881 feed exceeds size limit: {url}")
    return data


def is_allowed_feed_url(url: str) -> bool:
    parsed = urlsplit(url.strip())
    return (
        parsed.scheme == "https"
        and parsed.hostname == ALLOWED_HOST
        and parsed.path.startswith(ALLOWED_PATH_PREFIX)
        and parsed.path.endswith(".txt")
    )


def extract_subscription_urls(index_text: str) -> list[str]:
    """Return every allowed child feed in index order, without URL duplicates."""
    urls: list[str] = []
    seen: set[str] = set()

    for raw_line in index_text.splitlines():
        line = raw_line.strip()
        if not line.startswith("https://"):
            continue
        if not is_allowed_feed_url(line) or line in seen:
            continue
        seen.add(line)
        urls.append(line)

    return urls


def collect_kort0881() -> list[dict]:
    index_data = fetch_bytes(INDEX_URL, MAX_INDEX_BYTES)
    urls = extract_subscription_urls(index_data.decode("utf-8", errors="replace"))
    if not urls:
        raise RuntimeError("kort0881 index contains no allowed child feeds")

    rows: list[dict] = []
    fetched = 0
    unique_files = 0
    duplicate_files = 0
    failures: list[str] = []

    # Hash first for speed, then compare the bytes themselves before declaring
    # two child feeds identical. This keeps dedup strictly byte-for-byte.
    seen_payloads: dict[str, list[bytes]] = {}

    for url in urls:
        try:
            data = fetch_bytes(url, MAX_FEED_BYTES)
            fetched += 1

            digest = hashlib.sha256(data).hexdigest()
            bucket = seen_payloads.setdefault(digest, [])
            if any(data == previous for previous in bucket):
                duplicate_files += 1
                print(f"INFO source {SOURCE_NAME}: exact duplicate child skipped: {url}")
                continue
            bucket.append(data)
            unique_files += 1

            text = data.decode("utf-8", errors="replace")
            rows.extend(catalog.parse_lines(text, SOURCE_NAME))
        except Exception as exc:
            failures.append(f"{url}: {exc}")
            print(f"WARN source {SOURCE_NAME}: child feed failed: {url}: {exc}")

    if fetched == 0:
        raise RuntimeError(
            "all kort0881 child feeds failed: " + "; ".join(failures[:3])
        )

    print(
        f"OK source {SOURCE_NAME}: index_feeds={len(urls)} fetched={fetched} "
        f"unique_files={unique_files} exact_duplicate_files={duplicate_files} "
        f"nodes={len(rows)} failures={len(failures)}"
    )
    return rows


if __name__ == "__main__":
    collect_kort0881()
