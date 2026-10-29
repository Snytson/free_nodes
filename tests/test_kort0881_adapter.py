#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import kort0881_adapter as adapter


FAST = (
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/"
    "main/checked/RU_Best/ru_white_part1.txt?ts=1"
)
ALL = (
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/"
    "main/checked/RU_Best/ru_white_all_part1.txt?ts=2"
)
WHITE = (
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/"
    "main/checked/RU_Best/ru_white_all_WHITE.txt?ts=3"
)
BLACK = (
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/"
    "main/checked/RU_Best/ru_white_all_BLACK.txt?ts=4"
)

INDEX_FIXTURE = f"""
=== 🇷🇺 RUSSIA (FAST) ===
{FAST}

=== 🇷🇺 RUSSIA (ALL) ===
{ALL}
https://example.com/kort0881/vpn-checker-backend/main/checked/evil.txt

=== ✅ WHITE RUSSIA (ALL) ===
{WHITE}

=== ⚠️ BLACK RUSSIA (ALL) ===
{BLACK}
{BLACK}
"""

urls = adapter.extract_subscription_urls(INDEX_FIXTURE)
assert urls == [FAST, ALL, WHITE, BLACK]
assert adapter.is_allowed_feed_url(FAST)
assert not adapter.is_allowed_feed_url(
    "https://raw.githubusercontent.com/other/repo/main/checked/feed.txt"
)
assert not adapter.is_allowed_feed_url(
    "https://example.com/kort0881/vpn-checker-backend/main/checked/feed.txt"
)

VLESS = (
    "vless://11111111-1111-1111-1111-111111111111@a.example:443"
    "?encryption=none&security=tls&type=ws#a"
)
TROJAN = (
    "trojan://secret@b.example:443?security=tls&type=ws"
    "&host=b.example&path=%2Fws#b"
)
SS = "ss://aes-256-gcm:password@192.0.2.10:443#c"

# FAST and ALL are deliberately byte-for-byte identical. The adapter must
# download both current URLs but parse the identical payload only once.
payloads = {
    adapter.INDEX_URL: INDEX_FIXTURE.encode("utf-8"),
    FAST: (VLESS + "\n").encode("utf-8"),
    ALL: (VLESS + "\n").encode("utf-8"),
    WHITE: (TROJAN + "\n").encode("utf-8"),
    BLACK: (SS + "\n").encode("utf-8"),
}

original_fetch = adapter.fetch_bytes
try:
    adapter.fetch_bytes = lambda url, _max_bytes: payloads[url]
    rows = adapter.collect_kort0881()
finally:
    adapter.fetch_bytes = original_fetch

assert len(rows) == 3
assert {row["protocol"] for row in rows} == {"vless", "trojan", "shadowsocks"}
assert {row["host"] for row in rows} == {"a.example", "b.example", "192.0.2.10"}
assert all(row["source"] == adapter.SOURCE_NAME for row in rows)
assert all(row["port"] == 443 for row in rows)

print("OK kort0881 all-index feeds with byte-exact child dedup")
