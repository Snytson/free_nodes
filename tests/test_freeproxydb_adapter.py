#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import tempfile
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import freeproxydb_adapter as adapter


def node(number: int) -> dict:
    return {
        "connect_string": (
            f"vless://{number:08d}-1111-1111-1111-111111111111"
            f"@node{number}.example:443?security=tls"
        )
    }


originals = {
    "CACHE_FILE": adapter.CACHE_FILE,
    "PAGE_SIZE": adapter.PAGE_SIZE,
    "MAX_PAGES": adapter.MAX_PAGES,
    "PAGE_DELAY": adapter.PAGE_DELAY,
    "fetch_json": adapter.fetch_json,
}

try:
    with tempfile.TemporaryDirectory() as temporary:
        adapter.CACHE_FILE = Path(temporary) / "freeproxydb_cache.json"
        adapter.PAGE_SIZE = 2
        adapter.MAX_PAGES = 2
        adapter.PAGE_DELAY = 0

        calls: list[int] = []
        first_pages = {
            1: [node(1), node(2)],
            2: [node(3), node(4)],
        }

        def fetch_first(url: str) -> dict:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            page = int(query["page_index"][0])
            calls.append(page)
            assert query["order_by"] == ["last_checked"]
            assert query["order_dir"] == ["desc"]
            assert query["protocol"] == [",".join(adapter.PROTOCOLS)]
            return {
                "data": {
                    "data": first_pages[page],
                    "total_count": 8,
                }
            }

        adapter.fetch_json = fetch_first
        first = adapter.collect_freeproxydb()
        assert len(first) == 4
        assert calls == [1, 2]

        # Every run must restart at page 1 and replace the previous snapshot;
        # it must never continue to page 3 or accumulate older pages.
        calls.clear()
        second_pages = {
            1: [node(5), node(6)],
            2: [node(7), node(8)],
        }

        def fetch_second(url: str) -> dict:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            page = int(query["page_index"][0])
            calls.append(page)
            return {
                "data": {
                    "data": second_pages[page],
                    "total_count": 8,
                }
            }

        adapter.fetch_json = fetch_second
        second = adapter.collect_freeproxydb()
        assert len(second) == 4
        assert calls == [1, 2]
        assert not any("node1.example" in row["url"] for row in second)
        state = json.loads(adapter.CACHE_FILE.read_text(encoding="utf-8"))
        assert state["mode"] == "newest_mixed_protocol_pages"
        assert state["order_by"] == "last_checked"
        assert "next_page" not in state

        # If a later run is rate-limited before collecting anything, return
        # the previous newest snapshot instead of an empty source.
        def rate_limited(_url: str) -> dict:
            raise adapter.RateLimited("test quota")

        adapter.fetch_json = rate_limited
        third = adapter.collect_freeproxydb()
        assert [row["url"] for row in third] == [row["url"] for row in second]
        state = json.loads(adapter.CACHE_FILE.read_text(encoding="utf-8"))
        assert state["rate_limited"] is True
        assert state["complete"] is False
finally:
    for name, value in originals.items():
        setattr(adapter, name, value)


print("OK FreeProxyDB newest 20-page snapshot")

