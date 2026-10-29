#!/usr/bin/env python3
"""Build candidates from telegram_channels.json only."""
from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
TELEGRAM_CATALOG = ROOT / "sources" / "telegram_channels.json"
OUT = ROOT / "output" / "metadata" / "telegram_candidates.json"
TELEGRAM_TIMEOUT = (3.0, 12.0)
DEFAULT_MAX_PAGES = 4
DEFAULT_MAX_URIS = 2000
PAGE_DELAY = 0.10
CHANNEL_WORKERS = 16
URI_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>`]+", re.IGNORECASE)


def telegram_page(channel: str, before: int | None = None) -> str:
    url = f"https://t.me/s/{channel}"
    if before:
        url += f"?before={before}"
    response = catalog.session.get(url, timeout=TELEGRAM_TIMEOUT)
    response.raise_for_status()
    return response.text


def next_before(channel: str, page: str, current: int | None) -> int | None:
    candidates: set[int] = set()
    for match in re.finditer(r"[?&]before=(\d+)", page, re.IGNORECASE):
        value = int(match.group(1))
        if value > 0:
            candidates.add(value)
    pattern = re.compile(rf"(?:https?://t\.me/|/)(?:s/)?{re.escape(channel)}/(\d+)(?:[\"'/?#]|$)", re.IGNORECASE)
    for match in pattern.finditer(page):
        value = int(match.group(1))
        if value > 0:
            candidates.add(value)
    if current is not None:
        candidates = {value for value in candidates if value < current}
    return min(candidates) if candidates else None


def collect_channel(channel: str, max_pages: int, max_uris: int) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    before: int | None = None
    pages_ok = 0
    for page_number in range(max_pages):
        try:
            page = telegram_page(channel, before)
        except Exception as exc:
            if page_number == 0:
                raise
            print(f"WARN telegram @{channel} page={page_number + 1}: {exc}")
            break
        pages_ok += 1
        for row in catalog.parse_lines(page, f"telegram:@{channel}", html_source=True):
            uri = row["uri"]
            if uri not in seen:
                seen.add(uri)
                rows.append(row)
                if len(rows) >= max_uris:
                    break
        if len(rows) >= max_uris:
            break
        before = next_before(channel, page, before)
        if before is None:
            break
        if page_number + 1 < max_pages:
            time.sleep(PAGE_DELAY)
    print(f"INFO telegram @{channel}: pages={pages_ok} accepted={len(rows)}")
    return rows


def main() -> int:
    cfg = json.loads(TELEGRAM_CATALOG.read_text(encoding="utf-8"))
    channels = []
    seen = set()
    for raw in cfg.get("channels", []):
        channel = str(raw).lstrip("@").strip()
        if channel and channel.lower() not in seen:
            seen.add(channel.lower())
            channels.append(channel)

    max_pages = max(1, min(int(cfg.get("max_pages", DEFAULT_MAX_PAGES)), 25)) if isinstance(cfg, dict) else DEFAULT_MAX_PAGES
    max_uris = max(100, min(int(cfg.get("max_uris", DEFAULT_MAX_URIS)), 20000)) if isinstance(cfg, dict) else DEFAULT_MAX_URIS
    rows: list[dict] = []
    health: list[dict] = []
    started_all = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CHANNEL_WORKERS) as executor:
        futures = {executor.submit(collect_channel, channel, max_pages, max_uris): channel for channel in channels}
        for future in as_completed(futures):
            channel = futures[future]
            started = time.perf_counter()
            try:
                found = future.result()
                rows.extend(found)
                health.append({"name": f"telegram:@{channel}", "ok": True, "nodes": len(found),
                               "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            except Exception as exc:
                health.append({"name": f"telegram:@{channel}", "ok": False, "nodes": 0,
                               "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
                print(f"WARN telegram @{channel}: {exc}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_ms": round((time.perf_counter() - started_all) * 1000, 1),
        "channel_workers": CHANNEL_WORKERS,
        "rows": rows,
        "channels": health,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO telegram_candidates={len(rows)} elapsed_ms={round((time.perf_counter() - started_all) * 1000, 1)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
