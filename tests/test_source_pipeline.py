#!/usr/bin/env python3
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

try:
    import requests  # noqa: F401
except ModuleNotFoundError:
    class Session:
        def __init__(self):
            self.headers = {}

        def get(self, *args, **kwargs):
            raise AssertionError("unexpected network request in unit test")

    sys.modules["requests"] = SimpleNamespace(Session=Session)

import build_sources_candidates as builder
import update_catalog as catalog


VLESS_A = "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls&type=ws#a"
VLESS_B = "vless://22222222-2222-2222-2222-222222222222@b.example:443?security=tls&type=ws#b"

rows = catalog.parse_lines(VLESS_A + VLESS_B, "joined")
assert [row["host"] for row in rows] == ["a.example", "b.example"]

# A single malformed bracketed endpoint previously aborted the whole source.
malformed = "vless://33333333-3333-3333-3333-333333333333@[1.2.3.4]:443?security=tls"
rows = catalog.parse_lines(malformed + "\n" + VLESS_A, "mixed-quality")
assert len(rows) == 1 and rows[0]["host"] == "a.example"

invalid_ss = "ss://not-a-cipher-password@ss.example:443#bad"
valid_ss = "ss://aes-256-gcm:password@ss.example:443#good"
assert catalog.parse_lines(invalid_ss, "ss") == []
assert len(catalog.parse_lines(valid_ss, "ss")) == 1

modern_vmess = (
    "vmess://55555555-5555-5555-5555-555555555555@vmess.example:443"
    "?encryption=auto&security=tls&type=ws&host=cdn.example&path=%2Fws#modern"
)
modern_rows = catalog.parse_lines(modern_vmess, "modern-vmess")
assert len(modern_rows) == 1
assert modern_rows[0]["protocol"] == "vmess"
assert modern_rows[0]["host"] == "vmess.example"
assert modern_rows[0]["port"] == 443
assert modern_rows[0]["uri"] == modern_vmess

modern_vmess_html = (
    "vmess://66666666-6666-6666-6666-666666666666@html.example:443"
    "?encryption=auto&amp;host=cdn.example&amp;path=%2Fws"
    "&amp;security=tls&amp;type=ws#html"
)
html_rows = catalog.parse_lines(modern_vmess_html, "modern-vmess-html")
assert len(html_rows) == 1
assert html_rows[0]["host"] == "html.example"
assert html_rows[0]["port"] == 443
assert html_rows[0]["uri"] == modern_vmess_html

modern_vmess_wrong_port = (
    "vmess://77777777-7777-7777-7777-777777777777@ignored.example:8443"
    "?encryption=auto&security=tls&type=ws#ignored"
)
assert catalog.parse_lines(modern_vmess_wrong_port, "modern-vmess-port") == []

clash_yaml = """proxies:
- name: supported-vless
  type: vless
  server: clash.example
  port: 443
  uuid: 44444444-4444-4444-4444-444444444444
  tls: true
  network: ws
- name: unsupported-port
  type: trojan
  server: ignored.example
  port: 8443
  password: secret
"""
original_fetch = catalog.fetch
try:
    catalog.fetch = lambda _url: clash_yaml.encode("utf-8")
    clash_rows = catalog.collect_source({
        "name": "clash-fixture",
        "url": "https://example.invalid/clash.yaml",
        "format": "clash_yaml",
    })
finally:
    catalog.fetch = original_fetch

assert len(clash_rows) == 1
assert clash_rows[0]["protocol"] == "vless"
assert clash_rows[0]["host"] == "clash.example"
assert clash_rows[0]["source"] == "clash-fixture"

special_rows: list[dict] = []
health: list[dict] = []
builder.collect_special(
    "adapter",
    lambda: [{"url": VLESS_A}, {"url": VLESS_B}],
    special_rows,
    health,
    normalize=True,
)
assert len(special_rows) == 2
assert all(row["source"] == "adapter" for row in special_rows)
assert health[0]["raw_nodes"] == 2 and health[0]["nodes"] == 2

nested_rows: list[dict] = []
nested_health: list[dict] = []
builder.collect_special(
    "nested-adapter",
    lambda: [{"url": "https://example.invalid/server/1", "metadata": {"links": [VLESS_A]}}],
    nested_rows,
    nested_health,
    normalize=True,
)
assert len(nested_rows) == 1 and nested_health[0]["ok"] is True

assert "Authorization" not in catalog.session.headers
seen: list[tuple[str, dict]] = []


class Response:
    def raise_for_status(self):
        return None

    def json(self):
        return []


original_get = catalog.session.get
original_token = catalog.GITHUB_TOKEN
try:
    catalog.GITHUB_TOKEN = "test-token"

    def fake_get(url, **kwargs):
        seen.append((url, kwargs.get("headers", {})))
        return Response()

    catalog.session.get = fake_get
    catalog.github_api_json("https://api.github.com/repos/example/repo/contents")
    catalog.github_api_json("https://example.com/api")
finally:
    catalog.session.get = original_get
    catalog.GITHUB_TOKEN = original_token

assert seen[0][1].get("Authorization") == "Bearer test-token"
assert "Authorization" not in seen[1][1]

# Per-source headers are passed only when explicitly configured.
source_header_calls = []
original_fetch = catalog.fetch
try:
    def fake_source_fetch(url, headers=None):
        source_header_calls.append((url, headers))
        return VLESS_A.encode("utf-8")

    catalog.fetch = fake_source_fetch
    header_rows = catalog.collect_source({
        "name": "header-fixture",
        "url": "https://example.invalid/sub.txt",
        "headers": {
            "User-Agent": "Mozilla/5.0 test",
            "Referer": "https://example.invalid/",
        },
    })
finally:
    catalog.fetch = original_fetch

assert len(header_rows) == 1
assert source_header_calls == [(
    "https://example.invalid/sub.txt",
    {
        "User-Agent": "Mozilla/5.0 test",
        "Referer": "https://example.invalid/",
    },
)]

print("OK source pipeline security, normalization, and configured source headers")
