#!/usr/bin/env python3
"""Run one shard of the sing-box connectivity test."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from singbox_pipeline import core, runner  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--core-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, default=8)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=22.0)
    parser.add_argument("--measure-speed", action="store_true")
    parser.add_argument("--workdir", type=Path)
    args = parser.parse_args()
    manifest = core.validate_manifest(core.load_manifest(args.core_manifest), args.binary)
    runner.run_shard(
        args.candidates,
        args.binary,
        shard=args.shard,
        shards=args.shards,
        output=args.output,
        workers=args.workers,
        timeout=args.timeout,
        measure_speed=args.measure_speed,
        core_manifest=manifest,
        workdir=args.workdir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
