#!/usr/bin/env python3
"""Track source content changes for diagnostics without filtering sources.

Every healthy, non-empty source is included on every run, regardless of how long
its content has remained unchanged and regardless of whether another source has
identical content. Source-level freshness and mirror status are observational
only; node-level deduplication later in the pipeline removes duplicate nodes.
"""
from __future__ import annotations

import hashlib
import html
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: object, fallback: datetime) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return fallback


def _row_identity(uri: str) -> str:
    # Freshness is diagnostic: compare the cleaned source text that was actually
    # collected. Connection-level equivalence is handled once, later, by the
    # sing-box outbound identity in the collection step.
    return "raw:" + html.unescape(uri.strip())


def _fingerprint(rows: list[dict]) -> tuple[str, int]:
    identities = sorted({
        _row_identity(str(row.get("uri") or ""))
        for row in rows
        if str(row.get("uri") or "").strip()
    })
    digest = hashlib.sha256("\n".join(identities).encode("utf-8")).hexdigest()
    return digest, len(identities)


def _load_state(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    sources = payload.get("sources", {}) if isinstance(payload, dict) else {}
    return sources if isinstance(sources, dict) else {}


def apply_source_freshness(
    rows: list[dict],
    health: list[dict],
    state_path: Path,
    max_stale_hours: int | None = None,
    now: datetime | None = None,
) -> tuple[list[dict], list[dict], dict]:
    """Include every healthy non-empty source and persist diagnostic state.

    max_stale_hours is accepted only for backward compatibility with older
    callers. It never filters a source.
    """
    _ = max_stale_hours
    current_time = (now or _utc_now()).astimezone(timezone.utc)
    previous = _load_state(state_path)

    health_by_name: dict[str, dict] = {}
    health_order: list[str] = []
    for entry in health:
        name = str(entry.get("name") or "UNKNOWN")
        if name not in health_by_name:
            health_order.append(name)
        health_by_name[name] = dict(entry)
    known_health_names = set(health_by_name)

    def canonical_source(row: dict) -> str:
        name = str(row.get("source") or "UNKNOWN")
        if name in known_health_names:
            return name
        # github_api/github_tree collectors retain the member path after a colon.
        parent = name.split(":", 1)[0]
        return parent if parent in known_health_names else name

    rows_by_source: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        rows_by_source[canonical_source(row)].append(row)
    for name in rows_by_source:
        if name not in health_by_name:
            health_order.append(name)
            health_by_name[name] = {
                "name": name,
                "ok": True,
                "nodes": len(rows_by_source[name]),
            }

    current: dict[str, dict] = {}
    for name in health_order:
        entry = health_by_name[name]
        source_rows = rows_by_source.get(name, [])
        prior = previous.get(name, {}) if isinstance(previous.get(name), dict) else {}
        usable = bool(entry.get("ok")) and bool(source_rows)

        if usable:
            fingerprint, semantic_nodes = _fingerprint(source_rows)
            changed = fingerprint != str(prior.get("fingerprint") or "")
            if changed or not prior.get("last_changed_at"):
                last_changed = current_time
            else:
                last_changed = _parse_iso(prior.get("last_changed_at"), current_time)

            state = {
                "fingerprint": fingerprint,
                "semantic_nodes": semantic_nodes,
                "last_checked_at": _iso(current_time),
                "last_changed_at": _iso(last_changed),
                "fresh": True,
                "competition_active": True,
                "freshness_reason": "changed" if changed else "unchanged_included",
                "duplicate_of": None,
            }
        else:
            last_changed = _parse_iso(prior.get("last_changed_at"), current_time)
            state = {
                **prior,
                "last_checked_at": _iso(current_time),
                "last_changed_at": _iso(last_changed),
                "fresh": False,
                "competition_active": False,
                "freshness_reason": "fetch_failed" if not entry.get("ok") else "empty_source",
                "duplicate_of": None,
                "semantic_nodes": int(prior.get("semantic_nodes") or 0),
            }
        current[name] = state

    included: list[dict] = []
    included_by_source: dict[str, int] = defaultdict(int)
    for row in rows:
        name = canonical_source(row)
        if current.get(name, {}).get("competition_active"):
            included.append(row)
            included_by_source[name] += 1

    annotated_health: list[dict] = []
    for name in health_order:
        state = current[name]
        last_changed = _parse_iso(state.get("last_changed_at"), current_time)
        entry = {
            **health_by_name[name],
            "fresh": bool(state.get("fresh")),
            "competition_active": bool(state.get("competition_active")),
            "included_nodes": included_by_source.get(name, 0),
            "last_changed_at": state.get("last_changed_at"),
            "age_hours": round(
                max(0.0, (current_time - last_changed).total_seconds() / 3600),
                2,
            ),
            "freshness_reason": state.get("freshness_reason"),
            "duplicate_of": None,
        }
        annotated_health.append(entry)

    summary = {
        "schema": 2,
        "generated_at": _iso(current_time),
        "filtering_policy": "all_healthy_nonempty_sources",
        "max_stale_hours": None,
        "sources_checked": len(current),
        "active_sources": sum(
            1 for state in current.values()
            if state.get("competition_active")
        ),
        "stale_sources": 0,
        "duplicate_sources": 0,
        "failed_sources": sum(
            1 for state in current.values()
            if state.get("freshness_reason") == "fetch_failed"
        ),
        "empty_sources": sum(
            1 for state in current.values()
            if state.get("freshness_reason") == "empty_source"
        ),
        "input_nodes": len(rows),
        "included_nodes": len(included),
        "sources": current,
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return included, annotated_health, summary
