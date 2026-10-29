#!/usr/bin/env python3
"""ClashXW daily dated subscription adapter."""

from __future__ import annotations

import base64
import datetime
import re
import urllib.request
from share_link_extractor import extract_uri_records


BASE_URL = "https://node.freeclashnode.com/uploads"
PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://")


def fetch_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "VPN-Nodes-Catalog/1.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return response.read().decode("utf-8", errors="ignore")


def build_daily_urls() -> list[str]:
    day = datetime.datetime.utcnow()
    year = day.strftime("%Y")
    month = day.strftime("%m")
    date = day.strftime("%Y%m%d")

    return [
        f"{BASE_URL}/{year}/{month}/{index}-{date}.txt"
        for index in range(0, 100)
    ]


def decode_base64(text: str) -> str:
    try:
        raw = "".join(text.split())
        return base64.b64decode(raw + "==").decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_nodes(text: str) -> list[dict]:
    rows = []
    seen = set()

    for content in (text, decode_base64(text)):
        for record in extract_uri_records(content):
            line = record.uri
            if line not in seen:
                seen.add(line)
                rows.append(
                    {
                        "name": "ClashXW-Daily",
                        "source": "clashxw-daily",
                        "url": line,
                        **record.source_fields(),
                    }
                )

    return rows


def collect_clashxw_daily() -> list[dict]:
    rows = []
    seen = set()

    for url in build_daily_urls():
        try:
            found = extract_nodes(fetch_text(url))

            for item in found:
                if item["url"] not in seen:
                    seen.add(item["url"])
                    rows.append(item)

            if found:
                print(f"OK ClashXW file: {url} nodes={len(found)}")

        except Exception:
            continue

    print(f"OK source ClashXW-Daily total: {len(rows)}")
    return rows
