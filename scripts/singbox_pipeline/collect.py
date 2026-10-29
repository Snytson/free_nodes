#!/usr/bin/env python3
"""Collect share links from every configured source and pin a candidate snapshot.

The extraction layer is unchanged from the repository's collectors: the same
source list, the same adapter caches and the same literal share-link
preservation.  What is new is the single normalization boundary: every link is
converted to a sing-box outbound here, so an unsupported link is reported before
any runner time is spent on it.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import build_sources_candidates as specials  # noqa: E402
import build_telegram_candidates as telegram  # noqa: E402
import source_freshness  # noqa: E402
import update_catalog as catalog  # noqa: E402
import v2nodes_adapter  # noqa: E402
from singbox_pipeline import core  # noqa: E402
from singbox_pipeline.share_link import UnsupportedLink, outbound_identity, parse_share_link  # noqa: E402

SOURCES = ROOT / "sources" / "sources.json"
TELEGRAM = ROOT / "sources" / "telegram_channels.json"
OUT = ROOT / "output" / "metadata" / "singbox_candidates.json"
FRESHNESS = ROOT / "output" / "metadata" / "source_freshness.json"
CACHE_DIR = ROOT / "output" / "metadata"
DEFAULT_PORTS = {443}
SPECIAL_FORMATS = {"telegram_catalog", "telegram_html", "v2nodes"}
CHANNEL_WORKERS = 16


def snapshot_caches(destination: Path) -> int:
    """Copy adapter state next to the candidate snapshot so the publish job keeps it."""
    destination.mkdir(parents=True, exist_ok=True)
    copied = 0
    for path in sorted(CACHE_DIR.glob("*_cache.json")):
        shutil.copy2(path, destination / path.name)
        copied += 1
    return copied


def collect_telegram() -> tuple[list[dict], list[dict]]:
    cfg = json.loads(TELEGRAM.read_text(encoding="utf-8")) if TELEGRAM.is_file() else {}
    channels: list[str] = []
    seen: set[str] = set()
    for raw in cfg.get("channels", []) if isinstance(cfg, dict) else []:
        channel = str(raw).lstrip("@").strip()
        if channel and channel.lower() not in seen:
            seen.add(channel.lower())
            channels.append(channel)
    max_pages = max(1, min(int(cfg.get("max_pages", 4)), 25)) if isinstance(cfg, dict) else 4
    max_uris = max(100, min(int(cfg.get("max_uris", 2000)), 20000)) if isinstance(cfg, dict) else 2000
    rows: list[dict] = []
    health: list[dict] = []
    with ThreadPoolExecutor(max_workers=CHANNEL_WORKERS) as executor:
        futures = {
            executor.submit(telegram.collect_channel, channel, max_pages, max_uris): channel
            for channel in channels
        }
        for future in as_completed(futures):
            channel = futures[future]
            started = time.perf_counter()
            try:
                found = future.result()
                rows.extend(found)
                health.append({
                    "name": f"telegram:@{channel}",
                    "ok": True,
                    "nodes": len(found),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                })
            except Exception as exc:
                health.append({
                    "name": f"telegram:@{channel}",
                    "ok": False,
                    "nodes": 0,
                    "error": str(exc),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                })
    return rows, health


def collect_v2nodes(max_pages: int = 5000) -> tuple[list[dict], list[dict]]:
    started = time.perf_counter()
    try:
        uris = v2nodes_adapter.collect(
            start_url=v2nodes_adapter.BASE,
            max_pages=max_pages,
            preserve_original=True,
        )
        rows = catalog.parse_uri_records(uris, "v2nodes") if uris else []
        if not rows:
            raise RuntimeError("v2nodes returned no supported nodes")
        return rows, [{
            "name": "v2nodes",
            "ok": True,
            "nodes": len(rows),
            "raw_nodes": len(uris),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }]
    except Exception as exc:
        return [], [{
            "name": "v2nodes",
            "ok": False,
            "nodes": 0,
            "error": str(exc),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }]


def collect_all(
    sources_path: Path,
    *,
    skip_specials: bool = False,
    skip_telegram: bool = False,
    skip_v2nodes: bool = False,
    v2nodes_max_pages: int = 5000,
) -> tuple[list[dict], list[dict]]:
    cfg = json.loads(sources_path.read_text(encoding="utf-8"))
    rows: list[dict] = []
    health: list[dict] = []
    for item in cfg.get("sources", []):
        if item.get("format") in SPECIAL_FORMATS:
            continue
        started = time.perf_counter()
        try:
            found = catalog.collect_source(item)
            rows.extend(found)
            health.append({
                "name": item["name"],
                "ok": True,
                "nodes": len(found),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            })
            print(f"{'OK' if found else 'SKIP'} source {item['name']}: nodes={len(found)}")
        except Exception as exc:
            health.append({
                "name": item["name"],
                "ok": False,
                "nodes": 0,
                "error": str(exc),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            })
            print(f"WARN source {item['name']}: {exc}")

    if not skip_specials:
        specials.collect_special("freev2raynodes", specials.collect_freev2raynodes, rows, health)
        specials.collect_special("kort0881-vpn-checker-backend", specials.collect_kort0881, rows, health)
        specials.collect_special("FreeProxyDB-api", specials.collect_freeproxydb, rows, health, normalize=True)
        specials.collect_special("ClashXW-Daily", specials.collect_clashxw_daily, rows, health, normalize=True)
        specials.collect_special("ShareDaily-Clash", specials.collect_share_daily, rows, health, normalize=True)
        specials.collect_special("OutlineKeys-Daily", specials.collect_outlinekeys, rows, health, normalize=True)
    if not skip_specials and not skip_telegram:
        telegram_rows, telegram_health = collect_telegram()
        rows.extend(telegram_rows)
        health.extend(telegram_health)
    if not skip_specials and not skip_v2nodes:
        v2_rows, v2_health = collect_v2nodes(v2nodes_max_pages)
        rows.extend(v2_rows)
        health.extend(v2_health)
    return rows, health


def normalize_rows(
    rows: list[dict],
    allowed_ports: set[int],
) -> tuple[list[dict], list[dict], dict]:
    nodes: list[dict] = []
    failures: list[dict] = []
    seen: set[str] = set()
    counters = Counter()
    dedup_removed = 0
    for row in rows:
        uri = str(row.get("uri") or "").strip()
        if not uri:
            counters["empty_uri"] += 1
            continue
        source = str(row.get("source") or "UNKNOWN")
        try:
            parsed = parse_share_link(uri)
        except UnsupportedLink as exc:
            counters["unsupported"] += 1
            failures.append({"source": source, "protocol": row.get("protocol"), "stage": "unsupported", "error": str(exc)})
            continue
        if parsed["port"] not in allowed_ports:
            counters["port_filtered"] += 1
            continue
        identity = outbound_identity(parsed["outbound"])
        if identity in seen:
            dedup_removed += 1
            continue
        seen.add(identity)
        counters[parsed["protocol"]] += 1
        nodes.append({
            "index": len(nodes),
            "uri": uri,
            "protocol": parsed["protocol"],
            "host": parsed["host"],
            "port": parsed["port"],
            "remark": parsed["remark"],
            "transport": parsed["transport"],
            "security": parsed["security"],
            "source": source,
            "outbound_identity": identity,
            **({"original_uri": row["original_uri"]} if row.get("original_uri") else {}),
        })
    summary = {
        "input_rows": len(rows),
        "accepted": len(nodes),
        "deduplicated": dedup_removed,
        "conversion_failures": counters["unsupported"],
        "port_filtered": counters["port_filtered"],
        "empty_uri": counters["empty_uri"],
        "protocol_counts": {key: counters[key] for key in ("vless", "vmess", "trojan", "shadowsocks") if counters[key]},
    }
    return nodes, failures, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=SOURCES)
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--core-manifest", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--allowed-port", action="append", type=int, dest="allowed_ports")
    parser.add_argument("--allow-any-port", action="store_true")
    parser.add_argument("--skip-freshness", action="store_true")
    parser.add_argument("--freshness", type=Path, default=FRESHNESS)
    parser.add_argument("--skip-specials", action="store_true")
    parser.add_argument("--skip-telegram", action="store_true")
    parser.add_argument("--skip-v2nodes", action="store_true")
    parser.add_argument("--v2nodes-max-pages", type=int, default=5000)
    args = parser.parse_args()

    allowed_ports = set(args.allowed_ports or DEFAULT_PORTS)
    if args.allow_any_port:
        allowed_ports = set(range(1, 65536))

    manifest = None
    if args.core_manifest:
        manifest = core.validate_manifest(core.load_manifest(args.core_manifest), args.binary)
    elif args.binary:
        manifest = core.read_manifest(args.binary)

    started = time.perf_counter()
    rows, health = collect_all(
        args.sources,
        skip_specials=args.skip_specials,
        skip_telegram=args.skip_telegram,
        skip_v2nodes=args.skip_v2nodes,
        v2nodes_max_pages=args.v2nodes_max_pages,
    )
    if not rows:
        raise SystemExit("All sources returned no nodes")
    cached_files = snapshot_caches(args.output.parent / "cache")
    if not args.skip_freshness:
        rows, health, freshness = source_freshness.apply_source_freshness(rows, health, args.freshness)
    else:
        freshness = {}
    nodes, failures, summary = normalize_rows(rows, allowed_ports)
    if not nodes:
        raise SystemExit("No candidate could be converted to a sing-box outbound")

    payload = {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "core": manifest or {"name": "sing-box", "version": "unknown"},
        "allowed_ports": sorted(allowed_ports) if len(allowed_ports) < 32 else "any",
        "candidate_total": len(nodes),
        "protocol_counts": summary["protocol_counts"],
        "normalization": summary,
        "conversion_failures": failures[:500],
        "conversion_failure_total": len(failures),
        "cache_files": cached_files,
        "source_freshness": {key: value for key, value in freshness.items() if key != "sources"},
        "sources": health,
        "nodes": nodes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"OK singbox_candidates={len(nodes)} protocols={summary['protocol_counts']} "
        f"dedup={summary['deduplicated']} unsupported={summary['conversion_failures']} "
        f"port_filtered={summary['port_filtered']} elapsed_ms={payload['elapsed_ms']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
