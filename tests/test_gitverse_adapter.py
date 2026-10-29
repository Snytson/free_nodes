from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

if importlib.util.find_spec("requests") is None:
    class _Headers(dict):
        def update(self, *args, **kwargs):
            super().update(*args, **kwargs)

    class _Session:
        def __init__(self):
            self.headers = _Headers()

    sys.modules["requests"] = types.SimpleNamespace(Session=_Session)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_catalog
from gitverse_adapter import gitverse_fallback_urls

PRIMARY = "https://vless.svinakraft.workers.dev/vless.txt"
FALLBACK = "https://gitverse.ru/api/repos/Nokls/FlareFeed/raw/branch/main/public/vless.txt"
VLESS_443 = b"vless://11111111-1111-1111-1111-111111111111@vpn.example:443?security=tls#test\n"
VLESS_80 = b"vless://11111111-1111-1111-1111-111111111111@vpn.example:80?security=none#test\n"


def source_item():
    return {
        "name": "svinakraft-vless",
        "url": PRIMARY,
        "gitverse_fallback_urls": [FALLBACK],
    }


def test_validation():
    assert gitverse_fallback_urls(source_item()) == [FALLBACK]
    bad = {**source_item(), "gitverse_fallback_urls": ["https://example.com/sub.txt"]}
    try:
        gitverse_fallback_urls(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("non-GitVerse fallback was accepted")


def run_with_fetch(fake_fetch):
    original = update_catalog.fetch
    update_catalog.fetch = fake_fetch
    try:
        return update_catalog.collect_source(source_item())
    finally:
        update_catalog.fetch = original


def test_primary_wins():
    calls = []

    def fake_fetch(url):
        calls.append(url)
        if url == FALLBACK:
            raise AssertionError("fallback must not run when primary succeeds")
        return VLESS_443

    rows = run_with_fetch(fake_fetch)
    assert len(rows) == 1
    assert calls == [PRIMARY]


def test_fallback_after_primary_error():
    calls = []

    def fake_fetch(url):
        calls.append(url)
        if url == PRIMARY:
            raise OSError("primary unavailable")
        return VLESS_443

    rows = run_with_fetch(fake_fetch)
    assert len(rows) == 1
    assert calls == [PRIMARY, FALLBACK]


def test_fallback_after_empty_primary():
    calls = []

    def fake_fetch(url):
        calls.append(url)
        if url == PRIMARY:
            return b""
        return VLESS_443

    rows = run_with_fetch(fake_fetch)
    assert len(rows) == 1
    assert calls == [PRIMARY, FALLBACK]


if __name__ == "__main__":
    test_validation()
    test_primary_wins()
    test_fallback_after_primary_error()
    test_fallback_after_empty_primary()
    print("OK GitVerse fallback adapter")
