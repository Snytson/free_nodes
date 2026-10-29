"""Shard runner: probe the assigned candidates and write immutable artifacts."""
from __future__ import annotations

import hashlib
import json
import queue
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import core, probe


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class PortAllocator:
    """Hand each worker a unique loopback port for the life of one probe."""

    def __init__(self, size: int):
        self._ports: queue.Queue[int] = queue.Queue()
        sockets = []
        try:
            for _ in range(max(1, size)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", 0))
                sockets.append(sock)
                self._ports.put(sock.getsockname()[1])
        finally:
            for sock in sockets:
                sock.close()

    def acquire(self) -> int:
        return self._ports.get()

    def release(self, port: int) -> None:
        self._ports.put(port)


def _result_row(node: dict, shard: int, result: dict) -> dict:
    return {
        "index": node["index"],
        "protocol": node["protocol"],
        "shard": shard,
        "raw": node["uri"],
        "outbound_identity": node["outbound_identity"],
        "delay_ms": result.get("delay_ms"),
        "success_target": result.get("success_target"),
        "http_status": result.get("http_status"),
        "http_version": result.get("http_version"),
        "country": result.get("country") or "XX",
        "exit_ip": result.get("exit_ip") or "",
        "colo": result.get("colo") or "",
        "elapsed_ms": result.get("elapsed_ms"),
        "speed": result.get("speed"),
    }


def run_shard(
    candidates_path: Path,
    binary: Path,
    *,
    shard: int,
    shards: int,
    output: Path,
    workers: int = 32,
    timeout: float = probe.DEFAULT_NODE_TIMEOUT,
    measure_speed: bool = False,
    core_manifest: dict | None = None,
    workdir: Path | None = None,
) -> dict:
    if shards < 1 or not 0 <= shard < shards:
        raise ValueError("invalid shard assignment")
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    if not isinstance(candidates, dict) or not isinstance(candidates.get("nodes"), list):
        raise ValueError("candidate snapshot is invalid")
    manifest = candidates.get("core") or {}
    core.validate_manifest(manifest, binary)
    if core_manifest is not None and core_manifest != manifest:
        raise ValueError("candidate snapshot was prepared by another sing-box runtime")
    nodes = candidates["nodes"]
    for position, node in enumerate(nodes):
        if node.get("index") != position:
            raise ValueError("candidate snapshot indices are not contiguous")

    assigned = [node for node in nodes if int(node["index"]) % shards == shard]
    output.mkdir(parents=True, exist_ok=True)
    if workdir is not None:
        workdir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    allocator = PortAllocator(min(max(1, workers), max(1, len(assigned))))
    working: list[dict] = []
    failed: list[dict] = []
    lock_errors: list[str] = []

    def one(node: dict) -> tuple[dict, dict]:
        port = allocator.acquire()
        try:
            result = probe.probe_link(
                binary,
                node["uri"],
                port,
                timeout=timeout,
                measure_speed=measure_speed,
                workdir=workdir,
            )
        finally:
            allocator.release(port)
        if result.get("outbound_identity") not in (None, node["outbound_identity"]):
            raise RuntimeError("probe converted the link to a different outbound identity")
        return node, result

    with ThreadPoolExecutor(max_workers=min(max(1, workers), max(1, len(assigned)))) as executor:
        futures = {executor.submit(one, node): node for node in assigned}
        completed = 0
        for future in as_completed(futures):
            node = futures[future]
            completed += 1
            try:
                node, result = future.result()
            except Exception as exc:
                lock_errors.append(f"{node['protocol']}/{node['index']}: {exc}")
                failed.append({
                    "index": node["index"],
                    "protocol": node["protocol"],
                    "stage": "runner_error",
                    "error": str(exc)[:300],
                })
                continue
            if result.get("ok"):
                working.append(_result_row(node, shard, result))
            else:
                failed.append({
                    "index": node["index"],
                    "protocol": node["protocol"],
                    "stage": result.get("stage") or "failed",
                    "error": str(result.get("error") or "")[:300],
                    "attempts": result.get("attempts") or [],
                })
            if completed % 250 == 0 or completed == len(assigned):
                print(f"INFO shard={shard} progress={completed}/{len(assigned)} working={len(working)}", flush=True)

    working.sort(key=lambda row: int(row["index"]))
    failed.sort(key=lambda row: int(row["index"]))
    if len(working) + len(failed) != len(assigned):
        raise RuntimeError("probe bookkeeping mismatch")

    protocols: dict[str, dict] = {}
    for protocol in ("vless", "vmess", "trojan", "shadowsocks"):
        subset = [node for node in assigned if node["protocol"] == protocol]
        ok = [row for row in working if row["protocol"] == protocol]
        bad = [row for row in failed if row["protocol"] == protocol]
        targets = Counter(str(row.get("success_target")) for row in ok)
        stages = Counter(str(row.get("stage")) for row in bad)
        protocols[protocol] = {
            "assigned": len(subset),
            "tested": len(subset),
            "working": len(ok),
            "failed": len(bad),
            "success_targets": dict(sorted(targets.items())),
            "failure_stages": dict(sorted(stages.items())),
        }

    summary = {
        "schema": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "shard": shard,
        "shards": shards,
        "workers": workers,
        "timeout_seconds": timeout,
        "measure_speed": bool(measure_speed),
        "candidate_total": len(nodes),
        "candidates_sha256": digest(candidates_path),
        "core": manifest,
        "protocols": protocols,
        "working_total": len(working),
        "failed_total": len(failed),
        "runner_errors": lock_errors[:20],
    }
    (output / "working.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in working),
        encoding="utf-8",
    )
    (output / "failed.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in failed),
        encoding="utf-8",
    )
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"OK shard={shard}/{shards} assigned={len(assigned)} working={len(working)} "
        f"failed={len(failed)} elapsed_ms={summary['elapsed_ms']}",
        flush=True,
    )
    return summary
