#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import source_freshness


def row(source: str, credential: str) -> dict:
    uri = f"vless://{credential}@example.com:443?security=tls&type=ws#test"
    return {
        "source": source,
        "uri": uri,
        "protocol": "vless",
        "host": "example.com",
        "port": 443,
    }


with TemporaryDirectory() as tmp:
    state = Path(tmp) / "source_freshness.json"
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    same = "11111111-1111-1111-1111-111111111111"
    health = [
        {"name": "source-a", "ok": True, "nodes": 1},
        {"name": "source-b", "ok": True, "nodes": 1},
    ]

    # Identical/mirror sources are both included. Node-level dedup runs later.
    active, annotated, summary = source_freshness.apply_source_freshness(
        [row("source-a", same), row("source-b", same)],
        health,
        state,
        max_stale_hours=72,
        now=started,
    )
    assert len(active) == 2
    assert summary["active_sources"] == 2
    assert summary["stale_sources"] == 0
    assert summary["duplicate_sources"] == 0
    assert summary["filtering_policy"] == "all_healthy_nonempty_sources"
    assert summary["max_stale_hours"] is None
    assert all(x["competition_active"] for x in annotated)
    assert all(x["included_nodes"] == 1 for x in annotated)

    # Unchanged sources remain included even far beyond the former 72-hour limit.
    active, annotated, summary = source_freshness.apply_source_freshness(
        [row("source-a", same), row("source-b", same)],
        health,
        state,
        max_stale_hours=1,
        now=started + timedelta(days=365),
    )
    assert len(active) == 2
    assert summary["active_sources"] == 2
    assert summary["stale_sources"] == 0
    assert all(x["freshness_reason"] == "unchanged_included" for x in annotated)

    # A changed source remains included too; freshness is diagnostic only.
    changed = "22222222-2222-2222-2222-222222222222"
    active, annotated, summary = source_freshness.apply_source_freshness(
        [row("source-a", same), row("source-b", changed)],
        health,
        state,
        now=started + timedelta(days=366),
    )
    assert len(active) == 2
    b = next(x for x in annotated if x["name"] == "source-b")
    assert b["competition_active"] is True
    assert b["freshness_reason"] == "changed"

    # Failed/empty sources naturally contribute no rows; they are not freshness exclusions.
    health_with_unusable = [
        *health,
        {"name": "failed-source", "ok": False, "nodes": 0, "error": "test"},
        {"name": "empty-source", "ok": True, "nodes": 0},
    ]
    active, annotated, summary = source_freshness.apply_source_freshness(
        [row("source-a", same), row("source-b", same)],
        health_with_unusable,
        state,
        now=started + timedelta(days=367),
    )
    assert len(active) == 2
    assert summary["failed_sources"] == 1
    assert summary["empty_sources"] == 1
    assert summary["stale_sources"] == 0
    assert summary["duplicate_sources"] == 0

print("OK all healthy non-empty sources always included")
