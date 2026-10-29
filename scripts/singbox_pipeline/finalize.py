#!/usr/bin/env python3
"""Validate sing-box shard artifacts and publish a signed-catalog-ready tree.

The published artifact is still the original share link.  Connectivity is
proven by a real HTTPS request through the sing-box outbound; the shard
artifacts are checked for complete coverage before anything is published.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import country_resolver  # noqa: E402
import pycountry  # noqa: E402
from singbox_pipeline import core  # noqa: E402
from singbox_pipeline.runner import digest  # noqa: E402

PROTOCOL_ORDER = ("vless", "vmess", "trojan", "shadowsocks")
PROTOCOL_FILENAME = {
    "vless": "vless.txt",
    "vmess": "vmess.txt",
    "trojan": "trojan.txt",
    "shadowsocks": "shadowsocks.txt",
}
COUNTRY_SHARD_SIZE = 1000
COUNTRY_SHARD_MAX_BYTES = 4 * 1024 * 1024
ISO = re.compile(r"^[A-Z]{2}$")


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"Expected a JSON object: {path}")
    return value


def write_lines(path: Path, values: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def fallback_country(row: dict) -> tuple[str, str]:
    try:
        exit_ip = ipaddress.ip_address(str(row.get("exit_ip") or "").strip())
    except ValueError:
        exit_ip = None
    if exit_ip is not None and exit_ip.is_global:
        code = country_resolver.country_from_ip(str(exit_ip))
        value = str(code or "").upper()
        if ISO.fullmatch(value) and value != "XX":
            return value, "exit_ip"
    host = str(row.get("host") or "").strip().strip("[]")
    if host:
        ip = country_resolver.resolve_ip(host)
        if ip:
            code = country_resolver.country_from_ip(ip)
            value = str(code or "").upper()
            if ISO.fullmatch(value) and value != "XX":
                return value, "entry_host"
        return "XX", "entry_host"
    return "XX", "unresolved"


def speed_value(row: dict) -> float:
    speed = row.get("_speed")
    if not isinstance(speed, dict) or speed.get("status") != "MEASURED":
        return 0.0
    try:
        return max(0.0, float(speed.get("bits_per_second") or 0))
    except (TypeError, ValueError):
        return 0.0


def country_sort_key(row: dict) -> tuple:
    speed = speed_value(row)
    measured = 0 if speed > 0 else 1
    try:
        delay = max(0.0, float(row.get("delay_ms") or 0))
    except (TypeError, ValueError):
        delay = float("inf")
    return (measured, -speed if measured == 0 else 0.0, delay, int(row["index"]))


def load_shards(results_root: Path, candidates: dict, candidates_digest: str, shards: int) -> tuple[list[dict], list[dict]]:
    manifest = candidates.get("core") or {}
    core.validate_manifest(manifest)
    summaries = sorted(results_root.rglob("summary.json"))
    if len(summaries) != shards:
        raise SystemExit(f"Expected {shards} shard summaries, got {len(summaries)}")
    summary_rows = [read_json(path) for path in summaries]
    ids = sorted(int(row.get("shard", -1)) for row in summary_rows)
    if ids != list(range(shards)):
        raise SystemExit(f"Shard coverage mismatch: {ids}")
    expected = Counter(str(node.get("protocol") or "") for node in candidates["nodes"])
    expected_by_protocol = Counter({protocol: expected.get(protocol, 0) for protocol in PROTOCOL_ORDER})
    expected_by_shard: dict[tuple[int, str], int] = Counter()
    for position, node in enumerate(candidates["nodes"]):
        expected_by_shard[(position % shards, str(node.get("protocol") or ""))] += 1
    if any(expected.get(name, 0) for name in expected if name not in PROTOCOL_ORDER):
        raise SystemExit("Candidate snapshot contains an unexpected protocol")

    assigned = Counter()
    tested = Counter()
    working_expected = Counter()
    success_expected: dict[str, Counter] = {protocol: Counter() for protocol in PROTOCOL_ORDER}
    failures_expected: dict[str, Counter] = {protocol: Counter() for protocol in PROTOCOL_ORDER}
    workers = None
    for summary in summary_rows:
        if (summary.get("schema") != 2 or summary.get("shards") != shards
                or summary.get("candidates_sha256") != candidates_digest
                or summary.get("core") != manifest):
            raise SystemExit(f"Shard provenance mismatch: shard={summary.get('shard')}")
        workers = int(summary.get("workers") or 0)
        if workers < 1:
            raise SystemExit("Shard worker count is invalid")
        protocols = summary.get("protocols")
        if not isinstance(protocols, dict):
            raise SystemExit("Shard protocol summary is missing")
        shard = int(summary["shard"])
        for protocol in PROTOCOL_ORDER:
            row = protocols.get(protocol)
            if not isinstance(row, dict):
                raise SystemExit(f"Missing {protocol} summary in shard {shard}")
            want = expected_by_shard[(shard, protocol)]
            if (row.get("assigned") != want or row.get("tested") != want
                    or not 0 <= int(row.get("working", -1)) <= want
                    or row.get("failed") != want - int(row.get("working", -1))):
                raise SystemExit(f"Incomplete {protocol} coverage in shard {shard}")
            assigned[protocol] += int(row["assigned"])
            tested[protocol] += int(row["tested"])
            working_expected[protocol] += int(row["working"])
            success_expected[protocol].update(row.get("success_targets") or {})
            failures_expected[protocol].update(row.get("failure_stages") or {})

    for protocol in PROTOCOL_ORDER:
        if assigned[protocol] != expected_by_protocol[protocol] or tested[protocol] != expected_by_protocol[protocol]:
            raise SystemExit(f"Incomplete coverage for {protocol}")

    rows: list[dict] = []
    failures: list[dict] = []
    seen: set[int] = set()
    for path in sorted(results_root.rglob("working.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            index = int(row.get("index", -1))
            if index in seen:
                raise SystemExit(f"Duplicate working index: {index}")
            seen.add(index)
            if index < 0 or index >= len(candidates["nodes"]):
                raise SystemExit(f"Working index outside the candidate snapshot: {index}")
            node = candidates["nodes"][index]
            if (row.get("protocol") != node.get("protocol")
                    or row.get("raw") != node.get("uri")
                    or row.get("outbound_identity") != node.get("outbound_identity")
                    or row.get("shard") != index % shards):
                raise SystemExit(f"Working row does not match the tested candidate: {index}")
            if not str(row.get("success_target") or ""):
                raise SystemExit(f"Working row has no successful target: {index}")
            row["host"] = node.get("host")
            row["port"] = node.get("port")
            row["source"] = node.get("source")
            rows.append(row)
    for path in sorted(results_root.rglob("failed.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                failures.append(json.loads(line))

    actual = Counter(str(row["protocol"]) for row in rows)
    actual_success: dict[str, Counter] = {protocol: Counter() for protocol in PROTOCOL_ORDER}
    for row in rows:
        actual_success[str(row["protocol"])][str(row["success_target"])] += 1
    for protocol in PROTOCOL_ORDER:
        if actual[protocol] != working_expected[protocol]:
            raise SystemExit(f"Working artifact mismatch for {protocol}: {actual[protocol]} != {working_expected[protocol]}")
        if actual_success[protocol] != success_expected[protocol]:
            raise SystemExit(f"Success target artifact mismatch for {protocol}")
    if len(rows) + len(failures) != sum(expected_by_protocol.values()):
        raise SystemExit("Working/failed artifact accounting mismatch")
    if not rows:
        raise SystemExit("Refusing to publish an empty sing-box-verified catalog")

    for row in rows:
        row["_speed"] = row.get("speed") if isinstance(row.get("speed"), dict) else None
    return rows, failures, {"workers": workers, "expected": expected_by_protocol,
                            "tested": tested, "working": working_expected,
                            "success": success_expected, "failure_stages": failures_expected}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=ROOT / "output")
    parser.add_argument("--shards", type=int, default=8)
    parser.add_argument("--source-freshness", type=Path)
    parser.add_argument("--cache-root", type=Path)
    args = parser.parse_args()

    candidates = read_json(args.candidates)
    nodes = candidates.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise SystemExit("Candidate pool is empty or invalid")
    candidates_digest = digest(args.candidates)
    rows, failures, accounting = load_shards(args.results_root, candidates, candidates_digest, args.shards)

    xx_rows = [row for row in rows if not ISO.fullmatch(str(row.get("country") or "").upper())]
    for row in rows:
        row["country"] = str(row.get("country") or "XX").upper()
    geoip_attempted = 0
    geoip_classified = 0
    exit_classified = 0
    entry_classified = 0
    if xx_rows:
        with ThreadPoolExecutor(max_workers=64) as pool:
            results = list(pool.map(fallback_country, xx_rows))
        for row, (code, source) in zip(xx_rows, results):
            geoip_attempted += 1
            if code != "XX":
                row["country"] = code
                geoip_classified += 1
                if source == "exit_ip":
                    exit_classified += 1
                else:
                    entry_classified += 1

    rows.sort(key=lambda row: (PROTOCOL_ORDER.index(str(row["protocol"])), int(row["index"])))
    identity_seen: set[str] = set()
    unique: list[dict] = []
    duplicates = 0
    for row in rows:
        identity = str(row.get("outbound_identity") or "")
        if identity and identity in identity_seen:
            duplicates += 1
            continue
        identity_seen.add(identity)
        row["country"] = str(row.get("country") or "XX").upper()
        unique.append(row)
    rows = unique

    output = args.output_root
    metadata = output / "metadata"
    freshness_payload = None
    if args.source_freshness and args.source_freshness.is_file():
        freshness_payload = read_json(args.source_freshness)
    for name in ("countries", "country_shards", "protocols", "active", "backup", "metadata"):
        path = output / name
        if path.exists():
            shutil.rmtree(path)
    for path in (output / "countries", output / "country_shards", output / "protocols", metadata):
        path.mkdir(parents=True, exist_ok=True)

    cache_root = args.cache_root or (args.candidates.parent / "cache")
    if cache_root.is_dir():
        for path in sorted(cache_root.glob("*_cache.json")):
            shutil.copy2(path, metadata / path.name)

    groups: dict[str, list[dict]] = {}
    protocols: dict[str, list[dict]] = {protocol: [] for protocol in PROTOCOL_ORDER}
    for row in rows:
        groups.setdefault(str(row["country"]), []).append(row)
        protocols[str(row["protocol"])].append(row)

    for protocol in PROTOCOL_ORDER:
        write_lines(output / "protocols" / PROTOCOL_FILENAME[protocol], [str(row["raw"]) for row in protocols[protocol]])

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    countries_meta: list[dict] = []
    published_shards = 0
    country_counts: dict[str, int] = {}
    for country in sorted(groups):
        country_rows = groups[country]
        country_rows.sort(key=country_sort_key)
        uris = [str(row["raw"]) for row in country_rows]
        country_counts[country] = len(uris)
        write_lines(output / "countries" / f"{country}.txt", uris)
        shard_dir = output / "country_shards" / country
        shard_count = 0
        for shard_index, start in enumerate(range(0, len(uris), COUNTRY_SHARD_SIZE)):
            chunk = uris[start:start + COUNTRY_SHARD_SIZE]
            data = ("\n".join(chunk) + "\n").encode("utf-8")
            if len(data) > COUNTRY_SHARD_MAX_BYTES:
                raise SystemExit(f"Country shard too large: {country}/{shard_index:03d}")
            shard_dir.mkdir(parents=True, exist_ok=True)
            (shard_dir / f"{shard_index:03d}.txt").write_bytes(data)
            shard_count += 1
        published_shards += shard_count
        match = pycountry.countries.get(alpha_2=country)
        countries_meta.append({
            "code": country,
            "name": str(match.name) if match is not None else country,
            "nodes": len(uris),
            "active": 0,
            "backup": len(uris),
            "shards": shard_count,
            "shard_size": COUNTRY_SHARD_SIZE,
            "shard_path": f"output/country_shards/{country}",
        })

    (metadata / "countries.json").write_text(
        json.dumps({"schema": 2, "generated_at": generated_at, "shard_size": COUNTRY_SHARD_SIZE,
                    "countries": countries_meta}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    if freshness_payload is not None:
        (metadata / "source_freshness.json").write_text(
            json.dumps(freshness_payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    else:
        (metadata / "source_freshness.json").write_text(
            json.dumps(candidates.get("source_freshness") or {}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    measured = sum(1 for row in rows if speed_value(row) > 0)
    unmeasured = len(rows) - measured
    speed_report = {
        "schema": 1,
        "generated_at": generated_at,
        "policy": "fixed 1 MiB Cloudflare sample through the same sing-box outbound; startup delay recorded separately",
        "summary": {"measured": measured, "unmeasured": unmeasured, "missing_shards": 0},
        "nodes": [
            {
                "protocol": row["protocol"],
                "index": row["index"],
                "delay_ms": row.get("delay_ms"),
                "speed": row.get("speed"),
            }
            for row in rows
        ],
    }
    (metadata / "node_speeds.json").write_text(
        json.dumps(speed_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    total = len(rows)
    protocol_counts = {protocol: len(protocols[protocol]) for protocol in PROTOCOL_ORDER}
    geoip_summary = {
        "provider": "GeoLite2-Country",
        "scope": "working_xx_only",
        "attempted": geoip_attempted,
        "exit_ip_classified": exit_classified,
        "entry_host_classified": entry_classified,
        "classified": geoip_classified,
        "unresolved": geoip_attempted - geoip_classified,
    }
    manifest = candidates.get("core") or {}
    success_totals = Counter()
    for protocol in PROTOCOL_ORDER:
        success_totals.update(accounting["success"][protocol])
    test_summary = {}
    for protocol in PROTOCOL_ORDER:
        test_summary[protocol] = {
            "source_total": accounting["expected"][protocol],
            "tested": accounting["tested"][protocol],
            "working": accounting["working"][protocol],
            "failed": accounting["tested"][protocol] - accounting["working"][protocol],
            "success_targets": dict(sorted(accounting["success"][protocol].items())),
            "published_after_dedup": protocol_counts[protocol],
            "failure_stages": dict(sorted(accounting["failure_stages"][protocol].items())),
        }

    app_pool = {
        "schema": 24,
        "generated_at": generated_at,
        "mode": "singbox_https_verified",
        "liveness_test": "one mixed inbound per node; authenticated HTTPS through the candidate sing-box outbound",
        "final_runtime_test": "sing-box 1.14.x; multiple public HTTPS targets; accepted status per target",
        "core": manifest,
        "shards": args.shards,
        "workers_per_shard": accounting["workers"],
        "total_concurrency": args.shards * int(accounting["workers"] or 0),
        "candidate_total": len(nodes),
        "tested_total": sum(accounting["tested"].values()),
        "working_total": total + duplicates,
        "published_total": total,
        "published_country_nodes": total,
        "duplicates_removed_after_singbox": duplicates,
        "protocols": protocol_counts,
        "countries": country_counts,
        "country_policy": "Cloudflare trace loc; GeoLite2 exit IP then entry host for XX",
        "country_shard_size": COUNTRY_SHARD_SIZE,
        "country_shards_generated": True,
        "published_country_shards": published_shards,
        "success_targets": dict(sorted(success_totals.items())),
        "geoip_xx_fallback": geoip_summary,
        "speed_ranking": speed_report["summary"],
        "source_failures": sum(1 for row in candidates.get("sources") or [] if not row.get("ok")),
        "source_freshness": candidates.get("source_freshness") or {},
        "sources": candidates.get("sources") or [],
        "test_summary": test_summary,
    }
    (metadata / "app_pool.json").write_text(
        json.dumps(app_pool, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    country_names = {item["code"]: item["name"] for item in countries_meta}
    legacy_index = {
        "schema": 11,
        "generated_at": generated_at,
        "tcp_reachable_total": len(nodes),
        "xray_included": total,
        "config_conversion_failed": int((candidates.get("normalization") or {}).get("conversion_failures") or 0),
        "active": 0,
        "backup": total,
        "failed_after_core": sum(accounting["tested"].values()) - total,
        "healthy": total,
        "published_total": total,
        "countries": len(country_counts),
        "published_by_country": {
            country: {"active": 0, "backup": count, "total": count}
            for country, count in sorted(country_counts.items())
        },
        "country_names": country_names,
        "health_policy": "sing-box authenticated HTTPS response required before publication.",
        "core": manifest,
        "country_policy": "Cloudflare trace country; exit IP GeoLite2 then entry host for XX nodes",
        "geoip_xx_fallback": geoip_summary,
        "xray_success_endpoints": dict(sorted(success_totals.items())),
        "speed_ranking": speed_report["summary"],
        "test_summary": test_summary,
    }
    (metadata / "index.json").write_text(
        json.dumps(legacy_index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print(
        f"OK FINAL singbox tested={sum(accounting['tested'].values())} working={total} "
        f"duplicates_removed={duplicates} published={total} countries={len(country_counts)} "
        f"shards={published_shards} speed_measured={measured} speed_unmeasured={unmeasured} "
        f"geoip_classified={geoip_classified} core={manifest.get('version')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
