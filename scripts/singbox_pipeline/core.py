"""Pin the sing-box runtime used by one catalog run."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

REPOSITORY = "SagerNet/sing-box"
DEFAULT_VERSION = "1.14.4"
_VERSION = re.compile(r"^sing-box version\s+(\S+)")
_REVISION = re.compile(r"^Revision:\s*(\S+)", re.MULTILINE)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_manifest(binary: Path, *, source_url: str = "") -> dict:
    result = subprocess.run(
        [str(binary), "version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise RuntimeError(f"sing-box version failed: {output.strip()[:500]}")
    version_match = _VERSION.search(output.strip())
    if not version_match:
        raise RuntimeError("sing-box version output is not recognized")
    revision_match = _REVISION.search(output)
    version = version_match.group(1)
    return {
        "schema": 1,
        "name": "sing-box",
        "repository": REPOSITORY,
        "version": version,
        "revision": revision_match.group(1) if revision_match else "",
        "binary_sha256": digest(binary),
        "binary_bytes": binary.stat().st_size,
        "source": source_url or f"https://github.com/{REPOSITORY}/releases/tag/v{version}",
    }


def validate_manifest(manifest: dict, binary: Path | None = None) -> dict:
    if not isinstance(manifest, dict) or manifest.get("name") != "sing-box":
        raise ValueError("Expected a sing-box runtime manifest")
    version = str(manifest.get("version") or "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Runtime manifest has no pinned version")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("binary_sha256") or "")):
        raise ValueError("Runtime manifest has no binary SHA-256")
    if binary is not None and digest(binary) != manifest["binary_sha256"]:
        raise ValueError("sing-box binary SHA-256 mismatch")
    return manifest


def load_manifest(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object runtime manifest")
    return value


def write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
