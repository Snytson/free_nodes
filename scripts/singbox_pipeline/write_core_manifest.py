#!/usr/bin/env python3
"""Write the pinned sing-box runtime manifest used by collect and shards."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from singbox_pipeline import core  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = core.read_manifest(args.binary)
    core.write_manifest(args.output, manifest)
    print(f"OK sing-box {manifest['version']} sha256={manifest['binary_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
