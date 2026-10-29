#!/usr/bin/env python3
"""Offline checks for the GitHub subscription discovery helpers."""
import base64
import sys
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import discover_github_sources as discovery  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def test_plain_node_list(self):
        text = "vmess://abc\nvless://u@h:443?security=tls#n\n"
        kind, payload = discovery.classify(text)
        self.assertEqual(kind, "nodes")
        self.assertEqual(len(payload), 2)

    def test_base64_node_list_is_decoded(self):
        raw = "vless://11111111-1111-1111-1111-111111111111@a.example:443#a\n"
        encoded = base64.b64encode(raw.encode()).decode()
        kind, payload = discovery.classify(encoded)
        self.assertEqual(kind, "nodes")
        self.assertTrue(payload[0].startswith("vless://"))

    def test_clash_yaml_is_flagged(self):
        text = "proxies:\n  - {name: a, type: vless, server: a.example, port: 443}\n"
        self.assertEqual(discovery.classify(text), ("clash", []))

    def test_subscription_urls_are_extracted(self):
        text = ("订阅：https://sub.example/api/v1/client/subscribe?token=abc\n"
                "镜像 https://mirror.example/sub/xyz\n")
        kind, payload = discovery.classify(text)
        self.assertEqual(kind, "urls")
        self.assertEqual(payload, ["https://sub.example/api/v1/client/subscribe?token=abc",
                                   "https://mirror.example/sub/xyz"])

    def test_readme_noise_is_ignored(self):
        text = ("[![build](https://img.shields.io/badge/x)](https://github.com/o/r/actions)\n"
                "见 https://github.com/o/r/releases 或 https://t.me/channel\n")
        self.assertEqual(discovery.classify(text), ("none", []))

    def test_empty_body(self):
        self.assertEqual(discovery.classify("  \n"), ("none", []))


class MergeTests(unittest.TestCase):
    def test_dedupes_existing_urls_and_caps(self):
        existing = [{"name": "known", "url": "https://raw.githubusercontent.com/o/r/main/sub.txt"}]
        discovered = [
            {"name": "gh-o-r-sub", "url": "https://raw.githubusercontent.com/o/r/main/sub.txt/"},
            {"name": "gh-a-b-sub", "url": "https://raw.githubusercontent.com/a/b/main/sub.txt"},
            {"name": "gh-a-b-sub", "url": "https://example.test/subscription"},
            {"name": "gh-c-d-sub", "url": "https://example.test/other"},
        ]
        merged, added = discovery.merge(existing, discovered, cap=2)
        self.assertEqual(len(added), 2)
        self.assertEqual(len(merged), 3)
        names = [item["name"] for item in added]
        self.assertEqual(len(set(names)), 2)

    def test_format_is_preserved(self):
        merged, added = discovery.merge([], [
            {"name": "gh-x", "url": "https://raw.githubusercontent.com/x/y/main/c.yaml",
             "format": "clash_yaml"},
        ], cap=5)
        self.assertEqual(added[0]["format"], "clash_yaml")
        self.assertEqual(merged[0]["url"], "https://raw.githubusercontent.com/x/y/main/c.yaml")

    def test_blocked_urls_are_not_readded(self):
        url = "https://raw.githubusercontent.com/x/y/main/sub.txt"
        merged, added = discovery.merge([], [{"name": "gh-x", "url": url}], cap=5, blocked={url})
        self.assertEqual(added, [])
        self.assertEqual(merged, [])

    def test_placeholder_urls_are_rejected(self):
        merged, added = discovery.merge([], [
            {"name": "gh-a", "url": "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/sub.txt"},
            {"name": "gh-b", "url": "https://example.com/sub?token=x"},
            {"name": "gh-c", "url": "http://127.0.0.1:8080/sub"},
            {"name": "gh-d", "url": "https://real.test/sub.txt"},
        ], cap=9)
        self.assertEqual([item["name"] for item in added], ["gh-d"])

    def test_placeholder_paths_are_not_scanned(self):
        tree = [{"type": "blob", "path": "configs.example.txt", "size": 10},
                {"type": "blob", "path": "sub.txt", "size": 10}]
        self.assertEqual(discovery.candidate_paths(tree), ["sub.txt"])

    def test_invalid_scheme_is_rejected(self):
        merged, added = discovery.merge([], [{"name": "bad", "url": "ftp://example.test/x"}], cap=5)
        self.assertEqual(added, [])
        self.assertEqual(merged, [])


class PathTests(unittest.TestCase):
    def test_candidate_paths_are_bounded(self):
        tree = [{"type": "blob", "path": f"sub/list{i}.txt", "size": 100} for i in range(20)]
        tree += [{"type": "blob", "path": "logo.png", "size": 100},
                 {"type": "tree", "path": "sub", "size": 0},
                 {"type": "blob", "path": "docs/v2ray.txt", "size": 100}]
        chosen = discovery.candidate_paths(tree)
        self.assertEqual(len(chosen), 4)
        self.assertNotIn("logo.png", chosen)
        self.assertIn("docs/v2ray.txt", chosen)

    def test_normalize_url_ignores_case_and_trailing_slash(self):
        self.assertEqual(discovery.normalize_url("https://Example.TEST/a/"),
                         "https://example.test/a")


class RetryTests(unittest.TestCase):
    def setUp(self):
        self._fetch = discovery.fetch

    def tearDown(self):
        discovery.fetch = self._fetch

    def test_api_json_retries_transient_failures(self):
        calls = {"count": 0}

        def flaky(url, token, **kwargs):
            calls["count"] += 1
            if calls["count"] < 3:
                raise OSError("connection reset")
            return b'{"ok": true}'

        discovery.fetch = flaky
        payload = discovery.api_json("https://api.test/x", None, attempts=3, delay=0)
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(calls["count"], 3)

    def test_api_json_gives_up_after_attempts(self):
        def down(url, token, **kwargs):
            raise OSError("down")

        discovery.fetch = down
        with self.assertRaises(OSError):
            discovery.api_json("https://api.test/x", None, attempts=2, delay=0)


class SearchTests(unittest.TestCase):
    def setUp(self):
        self._api_json = discovery.api_json

    def tearDown(self):
        discovery.api_json = self._api_json

    def test_search_returns_partial_results_when_a_page_fails(self):
        pages = [{f"full_name": f"o/r{i}"} for i in range(2)]

        def fake(url, token, **kwargs):
            page = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["page"][0]
            if page == "1":
                return {"items": pages}
            raise OSError("truncated")

        discovery.api_json = fake
        repos = discovery.search_repositories("v2ray", 300, None)
        self.assertEqual([item["full_name"] for item in repos], ["o/r0", "o/r1"])


if __name__ == "__main__":
    unittest.main()
