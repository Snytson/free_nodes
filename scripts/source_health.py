#!/usr/bin/env python3
"""Track per-source freshness and yield, then prune or disable sources that fail.

Two rules, both measured over a five-day window (``--stale-hours`` /
``--invalid-hours``):

* ``prune``   - the source content has not changed for five days, so the address
                is removed from ``sources/sources.json``.
* ``disable`` - no node from that source passed the sing-box HTTPS check for five
                days, so the entry keeps its address but gains ``"disabled": true``
                and the collector skips it on later runs.

The ledger lives in ``output/metadata/source_health.json`` and is committed with
the catalog, so every run starts from the state the previous run produced.  The
``apply`` subcommand copies the ledger verdicts into ``sources/sources.json``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "output" / "metadata" / "source_health.json"
SOURCES = ROOT / "sources" / "sources.json"
SCHEMA = 1
STALE_HOURS = 120
INVALID_HOURS = 120
MIN_RUNS = 2
PRUNE_BUDGET = 25
DISABLE_BUDGET = 25
KEEP_AT_LEAST = 30
TIMESTAMP_FIELDS = ("first_seen_at", "last_checked_at", "last_ok_at", "last_changed_at")
COUNTER_FIELDS = ("observed_runs", "valid_runs", "invalid_runs", "last_verified_nodes")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def hours_since(value: object, now: datetime) -> float | None:
    parsed = parse_iso(value)
    if parsed is None:
        return None
    return max(0.0, (now - parsed).total_seconds() / 3600)


def fingerprint(uris: list[str]) -> str:
    identities = sorted({uri.strip() for uri in uris if uri and uri.strip()})
    return hashlib.sha256("\n".join(identities).encode("utf-8")).hexdigest()


def canonical_source(name: str, known: set[str]) -> str:
    """Map ``github_tree``-style ``parent:member`` labels back to the parent source."""
    if name in known:
        return name
    parent = name.split(":", 1)[0]
    return parent if parent in known else name


def load_ledger(path: Path) -> dict:
    payload: dict = {}
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
    sources = payload.get("sources") if isinstance(payload, dict) else None
    return {
        "schema": SCHEMA,
        "generated_at": payload.get("generated_at") if isinstance(payload, dict) else None,
        "sources": {str(key): dict(value) for key, value in (sources or {}).items()
                    if isinstance(value, dict)},
    }


def entry(ledger: dict, name: str, now: datetime) -> dict:
    sources = ledger.setdefault("sources", {})
    item = sources.get(name)
    if not isinstance(item, dict):
        item = {"name": name, "first_seen_at": iso(now)}
        sources[name] = item
    item.setdefault("name", name)
    item.setdefault("first_seen_at", iso(now))
    return item


def merge_ledger(base: dict, incoming: object) -> dict:
    """Fold the observations recorded by the collection job into the repo ledger."""
    if not isinstance(incoming, dict):
        return base
    now = utc_now()
    for name, extra in (incoming.get("sources") or {}).items():
        if not isinstance(extra, dict):
            continue
        current = base.setdefault("sources", {}).get(str(name))
        item = dict(current) if isinstance(current, dict) else entry(base, str(name), now)
        for key, value in extra.items():
            if key in TIMESTAMP_FIELDS:
                incoming_time = parse_iso(value)
                if incoming_time is None:
                    continue
                if parse_iso(item.get(key)) is None or incoming_time > parse_iso(item.get(key)):
                    item[key] = value
            elif key in COUNTER_FIELDS:
                item[key] = max(int(item.get(key) or 0), int(value or 0))
            elif key in ("disabled", "pruned"):
                item[key] = bool(item.get(key)) or bool(value)
            elif value is not None:
                item[key] = value
        base["sources"][str(name)] = item
    return base


def record_collection(ledger: dict, health: list[dict], rows: list[dict], now: datetime,
                      urls: dict[str, str] | None = None) -> dict:
    """Record what the collector saw: fetch status and content fingerprint."""
    known = {str(item.get("name") or "") for item in health if item.get("name")}
    grouped: dict[str, list[str]] = {}
    for row in rows:
        name = canonical_source(str(row.get("source") or "UNKNOWN"), known)
        grouped.setdefault(name, []).append(str(row.get("uri") or ""))

    for record in health:
        name = str(record.get("name") or "")
        if not name or record.get("skipped"):
            continue
        item = entry(ledger, name, now)
        if urls and name in urls:
            item["url"] = urls[name]
        item["last_checked_at"] = iso(now)
        item["observed_runs"] = int(item.get("observed_runs") or 0) + 1
        ok = bool(record.get("ok"))
        nodes = int(record.get("nodes") or 0)
        if ok and nodes:
            item["last_ok_at"] = iso(now)
            item["last_error"] = None
            item["last_collected_nodes"] = nodes
            digest = fingerprint(grouped.get(name, []))
            if digest != item.get("fingerprint"):
                item["fingerprint"] = digest
                item["last_changed_at"] = iso(now)
            item.setdefault("last_changed_at", iso(now))
        else:
            error = record.get("error") or ("empty_source" if ok else "fetch_failed")
            item["last_error"] = str(error)[:300]
    return ledger


def record_verification(ledger: dict, verified: dict[str, int], now: datetime) -> dict:
    """Record how many nodes per source survived the sing-box HTTPS check."""
    for name, count in verified.items():
        item = entry(ledger, str(name), now)
        count = int(count or 0)
        item["last_verified_nodes"] = count
        if count:
            item["last_valid_at"] = iso(now)
            item["valid_runs"] = int(item.get("valid_runs") or 0) + 1
            item["invalid_runs"] = 0
        else:
            item["invalid_runs"] = int(item.get("invalid_runs") or 0) + 1
    return ledger


def decide(ledger: dict, now: datetime, stale_hours: float = STALE_HOURS,
           invalid_hours: float = INVALID_HOURS, min_runs: int = MIN_RUNS,
           prune_budget: int = PRUNE_BUDGET, disable_budget: int = DISABLE_BUDGET,
           keep_at_least: int = KEEP_AT_LEAST) -> list[dict]:
    """Mark sources as pruned (remove address) or disabled (stop reading).

    Both verdicts are rate limited: a single run may prune or disable at most
    ``prune_budget``/``disable_budget`` sources, and the catalog never drops below
    ``min(keep_at_least, active // 2)`` active sources.  Without those guards one
    bad window could empty the source list and leave the pipeline with nothing to
    collect.  Deferred candidates are counted in ``ledger["deferred"]``.
    """
    sources = ledger.get("sources", {})
    active = sum(1 for item in sources.values()
                 if not item.get("disabled") and not item.get("pruned"))
    floor = min(keep_at_least, active // 2)
    decisions: list[dict] = []
    pruned = disabled = 0
    for name, item in sorted(sources.items()):
        if item.get("pruned") or item.get("disabled"):
            continue
        unchanged = hours_since(item.get("last_changed_at"), now)
        unverified = hours_since(item.get("last_valid_at"), now)
        tracked_for = hours_since(item.get("first_seen_at"), now)
        observed = int(item.get("observed_runs") or 0)

        prunable = unchanged is not None and unchanged >= stale_hours
        disablable = (tracked_for is not None and tracked_for >= invalid_hours
                      and observed >= min_runs
                      and (unverified is None or unverified >= invalid_hours))

        if prunable:
            if pruned >= prune_budget or active <= floor:
                ledger["deferred"] = int(ledger.get("deferred") or 0) + 1
                continue
            item["pruned"] = True
            item["pruned_at"] = iso(now)
            item["prune_reason"] = "content_unchanged"
            decisions.append({
                "name": name,
                "url": item.get("url"),
                "action": "prune",
                "reason": f"content unchanged for {unchanged:.1f}h (>={stale_hours}h)",
            })
            pruned += 1
            active -= 1
            continue
        if disablable:
            if disabled >= disable_budget or active <= floor:
                ledger["deferred"] = int(ledger.get("deferred") or 0) + 1
                continue
            item["disabled"] = True
            item["disabled_at"] = iso(now)
            item["disabled_reason"] = "no_verified_nodes"
            decisions.append({
                "name": name,
                "url": item.get("url"),
                "action": "disable",
                "reason": (f"no verified node for "
                           f"{'the whole tracking window' if unverified is None else f'{unverified:.1f}h'} "
                           f"while tracked for {tracked_for:.1f}h"),
            })
            disabled += 1
            active -= 1
    return decisions


def summarise(ledger: dict, decisions: list[dict], now: datetime, stale_hours: float,
              invalid_hours: float, min_runs: int = MIN_RUNS,
              prune_budget: int = PRUNE_BUDGET, disable_budget: int = DISABLE_BUDGET,
              keep_at_least: int = KEEP_AT_LEAST) -> dict:
    sources = ledger.get("sources", {})
    return {
        "schema": SCHEMA,
        "generated_at": iso(now),
        "policy": {
            "prune_after_unchanged_hours": stale_hours,
            "disable_after_unverified_hours": invalid_hours,
            "min_observed_runs": min_runs,
            "prune_budget_per_run": prune_budget,
            "disable_budget_per_run": disable_budget,
            "keep_at_least": keep_at_least,
            "prune_action": "remove the address from sources/sources.json",
            "disable_action": 'set "disabled": true; the collector skips the entry',
        },
        "counts": {
            "tracked": len(sources),
            "active": sum(1 for item in sources.values()
                          if not item.get("disabled") and not item.get("pruned")),
            "disabled": sum(1 for item in sources.values() if item.get("disabled")),
            "pruned": sum(1 for item in sources.values() if item.get("pruned")),
            "deferred": int(ledger.get("deferred") or 0),
            "decided_this_run": len(decisions),
        },
        "decisions": decisions,
        "sources": sources,
    }


def write_ledger(path: Path, ledger: dict, decisions: list[dict], now: datetime,
                 stale_hours: float = STALE_HOURS, invalid_hours: float = INVALID_HOURS,
                 min_runs: int = MIN_RUNS, prune_budget: int = PRUNE_BUDGET,
                 disable_budget: int = DISABLE_BUDGET,
                 keep_at_least: int = KEEP_AT_LEAST) -> dict:
    payload = summarise(ledger, decisions, now, stale_hours, invalid_hours, min_runs,
                        prune_budget, disable_budget, keep_at_least)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return payload


def blocked_urls(ledger: dict) -> set[str]:
    """URLs that must not be re-discovered once they were pruned or disabled."""
    blocked: set[str] = set()
    for item in ledger.get("sources", {}).values():
        if (item.get("pruned") or item.get("disabled")) and item.get("url"):
            blocked.add(str(item["url"]).strip().rstrip("/").lower())
    return blocked


def apply_to_catalog(path: Path, ledger: dict, now: datetime | None = None,
                     dry_run: bool = False) -> dict:
    catalog = json.loads(path.read_text(encoding="utf-8"))
    entries = catalog.get("sources") or []
    kept: list[dict] = []
    removed: list[str] = []
    disabled: list[str] = []
    stamp = iso(now or utc_now())
    for record in entries:
        if not isinstance(record, dict):
            continue
        name = str(record.get("name") or "")
        item = ledger.get("sources", {}).get(name) or {}
        if item.get("pruned"):
            removed.append(name)
            continue
        if item.get("disabled"):
            if not record.get("disabled"):
                record["disabled"] = True
                record["disabled_at"] = item.get("disabled_at") or stamp
                record["disabled_reason"] = item.get("disabled_reason") or "no_verified_nodes"
                disabled.append(name)
            kept.append(record)
            continue
        kept.append(record)
    changed = bool(removed or disabled)
    if changed and not dry_run:
        catalog["sources"] = kept
        path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"removed": removed, "disabled": disabled, "kept": len(kept),
            "changed": changed, "dry_run": dry_run}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=LEDGER)
    parser.add_argument("--sources", type=Path, default=SOURCES)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    ledger = load_ledger(args.ledger)
    if not ledger["sources"]:
        print(f"no ledger at {args.ledger}; nothing to apply")
        return 0
    result = apply_to_catalog(args.sources, ledger, dry_run=args.dry_run)
    print(f"kept={result['kept']} removed={len(result['removed'])} "
          f"disabled={len(result['disabled'])} changed={result['changed']} "
          f"dry_run={result['dry_run']}")
    for name in result["removed"][:20]:
        print(f"  - prune {name}")
    for name in result["disabled"][:20]:
        print(f"  - disable {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
