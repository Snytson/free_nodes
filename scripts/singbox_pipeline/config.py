"""Build the minimal sing-box client configuration used for one node probe."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def client_config(outbound: dict, listen_port: int, *, log_level: str = "error") -> dict:
    """One mixed inbound and one node outbound.

    ``route.final`` makes the node outbound authoritative for every connection;
    there is no direct fallback, so a request can only succeed through the node.
    """
    if not isinstance(listen_port, int) or not 1 <= listen_port <= 65535:
        raise ValueError("listen_port must be a valid TCP port")
    if not isinstance(outbound, dict) or not outbound.get("type"):
        raise ValueError("outbound is missing")
    return {
        "log": {"level": log_level, "timestamp": False},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "probe-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }
        ],
        "outbounds": [{**outbound, "tag": "proxy"}],
        "route": {"final": "proxy"},
    }


def write_config(path: Path, config: dict) -> None:
    path.write_text(
        json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def check_config(binary: Path, config_path: Path, *, timeout: float = 10.0) -> tuple[bool, str]:
    """Run ``sing-box check`` and return ``(ok, diagnostic)``."""
    result = subprocess.run(
        [str(binary), "check", "-c", str(config_path)],
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode == 0:
        return True, ""
    text = (result.stderr or result.stdout).decode("utf-8", errors="replace")
    return False, text.strip()[-2000:]
