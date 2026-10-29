#!/usr/bin/env python3
"""Offline checks for the source health ledger, pruning and disabling rules."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import source_health  # noqa: E402

NOW = datetime(2026, 1, 11, 12, 0, tzinfo=timezone.utc)


def hours_ago(hours: float) -> str:
    return source_health.iso(NOW - timedelta(hours=hours))


def healthy(name: str, nodes: int = 5) -> dict:
    return {"name": name, "ok": True, "nodes": nodes}


def row(source: str, uri: str) -> dict:
    return {"source": source, "uri": uri}


class LoadTests(unittest.TestCase):
    def test_missing_ledger_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = source_health.load_ledger(Path(tmp) / "missing.json")
        self.assertEqual(ledger["sources"], {})

    def test_corrupt_ledger_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{oops", encoding="utf-8")
            ledger = source_health.load_ledger(path)
        self.assertEqual(ledger["sources"], {})


class CollectionTests(unittest.TestCase):
    def test_first_observation_stamps_the_window(self):
        ledger = source_health.load_ledger(Path("never-there.json"))
        source_health.record_collection(ledger, [healthy("a")], [row("a", "vless://x")],
                                        NOW, urls={"a": "https://raw.test/a.txt"})
        item = ledger["sources"]["a"]
        self.assertEqual(item["first_seen_at"], source_health.iso(NOW))
        self.assertEqual(item["last_changed_at"], source_health.iso(NOW))
        self.assertEqual(item["last_checked_at"], source_health.iso(NOW))
        self.assertEqual(item["observed_runs"], 1)
        self.assertEqual(item["url"], "https://raw.test/a.txt")

    def test_unchanged_content_keeps_the_change_timestamp(self):
        ledger = {"sources": {"a": {
            "name": "a",
            "first_seen_at": hours_ago(200),
            "last_changed_at": hours_ago(200),
            "fingerprint": source_health.fingerprint(["vless://x"]),
            "observed_runs": 3,
        }}}
        source_health.record_collection(ledger, [healthy("a")], [row("a", "vless://x")], NOW)
        item = ledger["sources"]["a"]
        self.assertEqual(item["last_changed_at"], hours_ago(200))
        self.assertEqual(item["observed_runs"], 4)

    def test_changed_content_moves_the_change_timestamp(self):
        ledger = {"sources": {"a": {
            "name": "a",
            "first_seen_at": hours_ago(200),
            "last_changed_at": hours_ago(200),
            "fingerprint": source_health.fingerprint(["vless://old"]),
            "observed_runs": 3,
        }}}
        source_health.record_collection(ledger, [healthy("a")], [row("a", "vless://new")], NOW)
        self.assertEqual(ledger["sources"]["a"]["last_changed_at"], source_health.iso(NOW))

    def test_failed_fetch_records_the_error_only(self):
        ledger = {"sources": {"a": {"name": "a", "first_seen_at": hours_ago(200),
                                    "last_changed_at": hours_ago(200)}}}
        source_health.record_collection(
            ledger, [{"name": "a", "ok": False, "nodes": 0, "error": "timeout"}], [], NOW)
        item = ledger["sources"]["a"]
        self.assertEqual(item["last_changed_at"], hours_ago(200))
        self.assertEqual(item["last_error"], "timeout")

    def test_skipped_disabled_source_is_not_counted(self):
        ledger = {"sources": {"a": {"name": "a", "disabled": True, "observed_runs": 7}}}
        source_health.record_collection(
            ledger, [{"name": "a", "ok": False, "nodes": 0, "skipped": "disabled"}], [], NOW)
        self.assertEqual(ledger["sources"]["a"]["observed_runs"], 7)

    def test_member_rows_fold_into_the_parent_source(self):
        ledger = source_health.load_ledger(Path("never-there.json"))
        source_health.record_collection(ledger, [healthy("tree", 2)],
                                        [row("tree:mirror/1.txt", "vless://x")], NOW)
        self.assertIn("tree", ledger["sources"])
        self.assertNotIn("tree:mirror/1.txt", ledger["sources"])


class VerificationTests(unittest.TestCase):
    def test_verified_nodes_stamp_validity(self):
        ledger = source_health.load_ledger(Path("never-there.json"))
        source_health.record_verification(ledger, {"a": 3, "b": 0}, NOW)
        self.assertEqual(ledger["sources"]["a"]["last_valid_at"], source_health.iso(NOW))
        self.assertEqual(ledger["sources"]["a"]["valid_runs"], 1)
        self.assertEqual(ledger["sources"]["b"]["invalid_runs"], 1)
        self.assertNotIn("last_valid_at", ledger["sources"]["b"])

    def test_invalid_runs_accumulate(self):
        ledger = {"sources": {"a": {"name": "a", "invalid_runs": 2}}}
        source_health.record_verification(ledger, {"a": 0}, NOW)
        self.assertEqual(ledger["sources"]["a"]["invalid_runs"], 3)


class DecisionTests(unittest.TestCase):
    def test_unchanged_content_for_five_days_is_pruned(self):
        ledger = {"sources": {"a": {"name": "a", "first_seen_at": hours_ago(300),
                                    "last_changed_at": hours_ago(121),
                                    "last_valid_at": hours_ago(10),
                                    "observed_runs": 40}}}
        decisions = source_health.decide(ledger, NOW)
        self.assertEqual([item["action"] for item in decisions], ["prune"])
        self.assertTrue(ledger["sources"]["a"]["pruned"])

    def test_recent_change_is_kept(self):
        ledger = {"sources": {"a": {"name": "a", "first_seen_at": hours_ago(300),
                                    "last_changed_at": hours_ago(119),
                                    "last_valid_at": hours_ago(1),
                                    "observed_runs": 40}}}
        self.assertEqual(source_health.decide(ledger, NOW), [])

    def test_no_verified_node_for_five_days_is_disabled(self):
        ledger = {"sources": {"a": {"name": "a", "first_seen_at": hours_ago(200),
                                    "last_changed_at": hours_ago(2),
                                    "last_valid_at": hours_ago(121),
                                    "observed_runs": 25}}}
        decisions = source_health.decide(ledger, NOW)
        self.assertEqual([item["action"] for item in decisions], ["disable"])
        self.assertEqual(ledger["sources"]["a"]["disabled_reason"], "no_verified_nodes")

    def test_never_valid_source_is_disabled_after_the_window(self):
        ledger = {"sources": {"a": {"name": "a", "first_seen_at": hours_ago(121),
                                    "last_changed_at": hours_ago(1),
                                    "observed_runs": 3}}}
        self.assertEqual([item["action"] for item in source_health.decide(ledger, NOW)],
                         ["disable"])

    def test_short_tracking_window_is_not_enough(self):
        ledger = {"sources": {"a": {"name": "a", "first_seen_at": hours_ago(20),
                                    "last_changed_at": hours_ago(1),
                                    "observed_runs": 2}}}
        self.assertEqual(source_health.decide(ledger, NOW), [])

    def test_single_observation_is_not_enough(self):
        ledger = {"sources": {"a": {"name": "a", "first_seen_at": hours_ago(121),
                                    "last_changed_at": hours_ago(1),
                                    "observed_runs": 1}}}
        self.assertEqual(source_health.decide(ledger, NOW), [])

    def test_already_disabled_source_is_left_alone(self):
        ledger = {"sources": {"a": {"name": "a", "first_seen_at": hours_ago(500),
                                    "last_changed_at": hours_ago(400),
                                    "disabled": True, "observed_runs": 60}}}
        self.assertEqual(source_health.decide(ledger, NOW), [])


class BudgetTests(unittest.TestCase):
    def stale_ledger(self, count: int) -> dict:
        return {"sources": {
            f"src{i}": {"name": f"src{i}", "first_seen_at": hours_ago(300),
                        "last_changed_at": hours_ago(200),
                        "last_valid_at": hours_ago(1), "observed_runs": 40}
            for i in range(count)
        }}

    def test_prune_budget_limits_one_run(self):
        ledger = self.stale_ledger(100)
        decisions = source_health.decide(ledger, NOW, prune_budget=5)
        self.assertEqual(len(decisions), 5)
        self.assertEqual(ledger["deferred"], 95)

    def test_catalog_keeps_a_floor_of_active_sources(self):
        ledger = self.stale_ledger(10)
        decisions = source_health.decide(ledger, NOW, prune_budget=100, keep_at_least=30)
        self.assertEqual(len(decisions), 5)
        self.assertEqual(sum(1 for item in ledger["sources"].values()
                             if not item.get("pruned")), 5)

    def test_disable_budget_limits_one_run(self):
        ledger = {"sources": {
            f"src{i}": {"name": f"src{i}", "first_seen_at": hours_ago(300),
                        "last_changed_at": hours_ago(1), "observed_runs": 40}
            for i in range(100)
        }}
        decisions = source_health.decide(ledger, NOW, disable_budget=3)
        self.assertEqual([item["action"] for item in decisions], ["disable"] * 3)
        self.assertEqual(ledger["deferred"], 97)


class MergeTests(unittest.TestCase):
    def test_newer_collection_observation_wins(self):
        base = {"sources": {"a": {"name": "a", "last_checked_at": hours_ago(10),
                                  "observed_runs": 2}}}
        incoming = {"sources": {"a": {"name": "a", "last_checked_at": hours_ago(1),
                                      "observed_runs": 3}}}
        merged = source_health.merge_ledger(base, incoming)
        self.assertEqual(merged["sources"]["a"]["last_checked_at"], hours_ago(1))
        self.assertEqual(merged["sources"]["a"]["observed_runs"], 3)

    def test_older_collection_observation_is_ignored(self):
        base = {"sources": {"a": {"name": "a", "last_checked_at": hours_ago(1)}}}
        incoming = {"sources": {"a": {"name": "a", "last_checked_at": hours_ago(30)}}}
        merged = source_health.merge_ledger(base, incoming)
        self.assertEqual(merged["sources"]["a"]["last_checked_at"], hours_ago(1))

    def test_missing_payload_is_a_noop(self):
        base = {"sources": {}}
        self.assertEqual(source_health.merge_ledger(base, None)["sources"], {})


class CatalogTests(unittest.TestCase):
    def write(self, tmp: str, payload: dict) -> Path:
        path = Path(tmp) / "sources.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return path

    def test_pruned_entries_are_removed_and_disabled_entries_flagged(self):
        catalog = {
            "version": 1,
            "mode": "direct-public-sources",
            "sources": [
                {"name": "keep", "url": "https://a.test/x.txt"},
                {"name": "stale", "url": "https://b.test/x.txt"},
                {"name": "dead", "url": "https://c.test/x.txt"},
            ],
        }
        ledger = {"sources": {"stale": {"pruned": True},
                              "dead": {"disabled": True, "disabled_at": source_health.iso(NOW),
                                       "disabled_reason": "no_verified_nodes"}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, catalog)
            result = source_health.apply_to_catalog(path, ledger, NOW)
            payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(result["removed"], ["stale"])
        self.assertEqual(result["disabled"], ["dead"])
        self.assertTrue(result["changed"])
        self.assertEqual(payload["mode"], "direct-public-sources")
        self.assertEqual([item["name"] for item in payload["sources"]], ["keep", "dead"])
        dead = payload["sources"][1]
        self.assertTrue(dead["disabled"])
        self.assertEqual(dead["disabled_reason"], "no_verified_nodes")
        self.assertEqual(dead["disabled_at"], source_health.iso(NOW))

    def test_dry_run_leaves_the_file_untouched(self):
        catalog = {"version": 1, "sources": [{"name": "stale", "url": "https://b.test/x.txt"}]}
        ledger = {"sources": {"stale": {"pruned": True}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, catalog)
            before = path.read_text(encoding="utf-8")
            result = source_health.apply_to_catalog(path, ledger, NOW, dry_run=True)
            after = path.read_text(encoding="utf-8")
        self.assertEqual(before, after)
        self.assertTrue(result["changed"])
        self.assertEqual(result["removed"], ["stale"])

    def test_blocked_urls_cover_pruned_and_disabled_sources(self):
        ledger = {"sources": {
            "a": {"pruned": True, "url": "https://a.test/x.txt"},
            "b": {"disabled": True, "url": "https://b.test/y.txt"},
            "c": {"url": "https://c.test/z.txt"},
        }}
        blocked = source_health.blocked_urls(ledger)
        self.assertEqual(blocked, {"https://a.test/x.txt/".rstrip("/"), "https://b.test/y.txt"})
        self.assertNotIn("https://c.test/z.txt", blocked)

    def test_summary_counts(self):
        ledger = {"sources": {
            "a": {"pruned": True},
            "b": {"disabled": True},
            "c": {},
        }}
        summary = source_health.summarise(ledger, [], NOW, 120, 120)
        self.assertEqual(summary["counts"]["tracked"], 3)
        self.assertEqual(summary["counts"]["active"], 1)
        self.assertEqual(summary["counts"]["disabled"], 1)
        self.assertEqual(summary["counts"]["pruned"], 1)
        self.assertEqual(summary["counts"]["decided_this_run"], 0)
        self.assertEqual(summary["policy"]["prune_after_unchanged_hours"], 120)
        self.assertEqual(summary["policy"]["prune_budget_per_run"],
                         source_health.PRUNE_BUDGET)


class CollectorSkipTests(unittest.TestCase):
    def test_disabled_source_is_skipped_by_the_collector(self):
        try:
            import singbox_pipeline.collect as collect
        except Exception as exc:  # pragma: no cover - optional collector deps
            self.skipTest(f"collector unavailable: {exc}")

        calls: list[str] = []

        def fake(item):
            calls.append(item["name"])
            return [{"uri": "vless://x", "protocol": "vless", "source": item["name"]}]

        original = collect.catalog.collect_source
        collect.catalog.collect_source = fake
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "sources.json"
                path.write_text(json.dumps({"sources": [
                    {"name": "live", "url": "https://a.test/x.txt"},
                    {"name": "dead", "url": "https://b.test/y.txt", "disabled": True},
                ]}), encoding="utf-8")
                rows, health, urls = collect.collect_all(
                    path, skip_specials=True, skip_telegram=True, skip_v2nodes=True)
        finally:
            collect.catalog.collect_source = original

        self.assertEqual(calls, ["live"])
        self.assertEqual(len(rows), 1)
        self.assertEqual([item["name"] for item in health], ["live", "dead"])
        self.assertEqual(health[1]["skipped"], "disabled")
        self.assertEqual(urls, {"live": "https://a.test/x.txt", "dead": "https://b.test/y.txt"})


if __name__ == "__main__":
    unittest.main()
