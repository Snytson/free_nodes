#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import outlinekeys_adapter as adapter

class Response:
    def __init__(self, text: str, status: int = 200):
        self.text = text
        self.status_code = status
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

class Session:
    def __init__(self, pages: dict[str, Response]):
        self.pages = pages
        self.calls: list[str] = []
        self.headers = {}
    def get(self, url: str, timeout: int):
        self.calls.append(url)
        if url not in self.pages:
            raise RuntimeError(f"unexpected URL {url}")
        return self.pages[url]

def listing(*items: tuple[int, str]) -> str:
    body = "\n".join(f'<a href="/key/{key_id}/">#{key_id} {age} Vless Online</a>' for key_id, age in items)
    return f"<html><body>{body}</body></html>"

def detail(uri: str) -> str:
    return f"<html><body><p>{uri}</p></body></html>"

now = datetime(2026, 9, 15, 0, 0, tzinfo=timezone.utc)
with tempfile.TemporaryDirectory() as tmp:
    cache = Path(tmp) / "cache.json"
    first = Session({
        adapter.BASE_URL: Response(listing((110, "30 minutes ago"), (109, "2 hours ago"), (108, "1 days ago"))),
        f"{adapter.BASE_URL}key/109/": Response(detail("vless://uuid@example.com:443?security=tls")),
        f"{adapter.BASE_URL}key/110/": Response(detail("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:443")),
    })
    rows = adapter.collect_outlinekeys(cache_path=cache, now=now, session=first)
    assert {row["url"].split("://", 1)[0] for row in rows} == {"vless", "ss"}
    assert f"{adapter.BASE_URL}key/108/" not in first.calls

    cached = Session({})
    assert adapter.collect_outlinekeys(cache_path=cache, now=now + timedelta(hours=12), session=cached) == rows
    assert cached.calls == []

    second = Session({
        adapter.BASE_URL: Response(listing((113, "1 hours ago"), (112, "2 hours ago"), (110, "1 days ago"))),
        f"{adapter.BASE_URL}key/112/": Response(detail("trojan://secret@example.net:443")),
        f"{adapter.BASE_URL}key/113/": Response(detail("vless://next@example.net:443")),
    })
    rows2 = adapter.collect_outlinekeys(cache_path=cache, now=now + timedelta(hours=25), session=second)
    assert {row["url"].split("://", 1)[0] for row in rows2} == {"vless", "trojan"}

    third = Session({
        adapter.BASE_URL: Response(listing((115, "1 hours ago"), (114, "2 hours ago"), (113, "1 days ago"))),
        f"{adapter.BASE_URL}key/114/": Response("temporary failure", 503),
        f"{adapter.BASE_URL}key/115/": Response(detail("ss://YWVzLTI1Ni1nY206bmV4dA@example.net:80")),
    })
    adapter.collect_outlinekeys(cache_path=cache, now=now + timedelta(hours=50), session=third)

    fourth = Session({
        adapter.BASE_URL: Response(listing((116, "1 hours ago"), (115, "1 days ago"))),
        f"{adapter.BASE_URL}key/114/": Response(detail("trojan://recovered@example.org:443")),
        f"{adapter.BASE_URL}key/116/": Response(detail("vless://latest@example.org:443")),
    })
    rows4 = adapter.collect_outlinekeys(cache_path=cache, now=now + timedelta(hours=75), session=fourth)
    assert {row["url"].split("://", 1)[0] for row in rows4} == {"vless", "trojan"}

print("OK OutlineKeys daily adapter")
