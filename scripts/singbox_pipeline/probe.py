"""Probe one node through a short-lived sing-box process.

A probe starts sing-box with one mixed inbound and the candidate outbound,
issues real HTTPS requests through that inbound, records the verified status,
exit country and optional download sample, then stops the process.  The
published share link is never rewritten from the generated outbound.
"""
from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import requests

from .config import client_config, write_config

TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=1048576"
SPEED_FALLBACK_URL = "https://proof.ovh.net/files/10Mb.dat"
TARGETS = (
    ("cloudflare", TRACE_URL, frozenset({200})),
    ("google", "https://www.gstatic.com/generate_204", frozenset({204})),
    ("microsoft", "https://www.microsoft.com/robots.txt", frozenset({200, 403})),
    ("example", "https://example.com/", frozenset({200})),
)
SAMPLE_BYTES = 1024 * 1024
STARTUP_TIMEOUT = 4.0
REQUEST_CONNECT_TIMEOUT = 5.0
REQUEST_READ_TIMEOUT = 6.0
DEFAULT_NODE_TIMEOUT = 22.0


def _stderr_tail(proc: subprocess.Popen, path: Path) -> str:
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    return text[-2000:]


def _wait_port(port: int, proc: subprocess.Popen, stderr_path: Path, deadline: float) -> None:
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            tail = _stderr_tail(proc, stderr_path)
            raise ProbeFailure("config", f"sing-box exited before listening: {tail}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise ProbeFailure("startup", "sing-box did not open the probe port")


class ProbeFailure(RuntimeError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def _trace_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and len(key) <= 32:
            fields[key.strip()] = value.strip()
    return fields


def _status_failure(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls"
    if isinstance(exc, requests.exceptions.ProxyError):
        return "proxy"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connect"
    return "network"


def _request_targets(session: requests.Session, deadline: float) -> tuple[dict | None, dict[str, str] | None, list[dict]]:
    failures: list[dict] = []
    for name, url, accepted in TARGETS:
        remaining = deadline - time.monotonic()
        if remaining <= 0.5:
            failures.append({"target": name, "stage": "timeout", "error": "node budget exhausted"})
            break
        started = time.perf_counter()
        try:
            response = session.get(
                url,
                timeout=(min(REQUEST_CONNECT_TIMEOUT, remaining), min(REQUEST_READ_TIMEOUT, remaining)),
                allow_redirects=False,
                verify=True,
            )
            elapsed = round((time.perf_counter() - started) * 1000, 1)
            if response.status_code not in accepted:
                failures.append({
                    "target": name,
                    "stage": "http_status",
                    "http_status": response.status_code,
                    "error": f"unexpected status {response.status_code}",
                })
                continue
            trace = _trace_fields(response.text[:16384]) if name == "cloudflare" else None
            return (
                {
                    "target": name,
                    "url": url,
                    "http_status": response.status_code,
                    "delay_ms": elapsed,
                    "http_version": _http_version(response),
                },
                trace,
                failures,
            )
        except requests.exceptions.RequestException as exc:
            failures.append({"target": name, "stage": _status_failure(exc), "error": str(exc)[:300]})
    return None, None, failures


def _http_version(response: requests.Response) -> str:
    try:
        return {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(
            int(response.raw.version), str(response.raw.version)
        )
    except Exception:
        return ""


def _read_sample(response: requests.Response, deadline: float) -> tuple[int, float | None, float | None]:
    total = 0
    first = None
    last = None
    for chunk in response.iter_content(64 * 1024):
        if not chunk:
            continue
        now = time.monotonic()
        if first is None:
            first = now
        last = now
        total += len(chunk)
        if total >= SAMPLE_BYTES or now >= deadline:
            break
    return total, first, last


def _measure_speed(session: requests.Session, deadline: float) -> dict | None:
    remaining = deadline - time.monotonic()
    if remaining < 1.5:
        return None
    try:
        response = session.get(
            SPEED_URL,
            stream=True,
            timeout=(min(4.0, remaining), min(5.0, remaining)),
            allow_redirects=False,
            verify=True,
        )
        if response.status_code != 200:
            return None
        total, first, last = _read_sample(response, deadline)
        if total < SAMPLE_BYTES or first is None or last is None or last <= first:
            return None
        return {
            "status": "MEASURED",
            "target": "cloudflare",
            "bytes": total,
            "bits_per_second": round(total * 8 / (last - first), 1),
        }
    except requests.exceptions.RequestException:
        return None


def probe_outbound(
    binary: Path,
    outbound: dict,
    listen_port: int,
    *,
    timeout: float = DEFAULT_NODE_TIMEOUT,
    measure_speed: bool = False,
    workdir: Path | None = None,
) -> dict:
    """Return a credential-free observation for one outbound."""
    started_at = time.monotonic()
    deadline = started_at + max(2.0, timeout)
    with tempfile.TemporaryDirectory(prefix="singbox-probe-", dir=workdir) as directory:
        root = Path(directory)
        config_path = root / "config.json"
        stderr_path = root / "stderr.log"
        write_config(config_path, client_config(outbound, listen_port))
        with stderr_path.open("wb") as stderr:
            proc = subprocess.Popen(
                [str(binary), "run", "-c", str(config_path)],
                cwd=directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
            )
        try:
            _wait_port(listen_port, proc, stderr_path, min(deadline, time.monotonic() + STARTUP_TIMEOUT))
            proxy = f"http://127.0.0.1:{listen_port}"
            session = requests.Session()
            session.trust_env = False
            session.proxies = {"http": proxy, "https": proxy}
            try:
                success, trace, failures = _request_targets(session, deadline)
                if success is None:
                    stage = failures[-1]["stage"] if failures else "network"
                    return {
                        "ok": False,
                        "stage": stage,
                        "error": failures[-1]["error"] if failures else "all targets failed",
                        "attempts": failures,
                        "elapsed_ms": round((time.monotonic() - started_at) * 1000, 1),
                    }
                country = ""
                exit_ip = ""
                colo = ""
                if trace:
                    exit_ip = trace.get("ip", "")
                    country = trace.get("loc", "").upper()
                    colo = trace.get("colo", "")
                speed = (
                    _measure_speed(session, min(deadline, time.monotonic() + 8.0))
                    if measure_speed
                    else None
                )
                return {
                    "ok": True,
                    "stage": "passed",
                    "success_target": success["target"],
                    "http_status": success["http_status"],
                    "delay_ms": success["delay_ms"],
                    "http_version": success["http_version"],
                    "country": country,
                    "exit_ip": exit_ip,
                    "colo": colo,
                    "speed": speed,
                    "attempts": failures,
                    "elapsed_ms": round((time.monotonic() - started_at) * 1000, 1),
                }
            finally:
                session.close()
        except ProbeFailure as exc:
            return {
                "ok": False,
                "stage": exc.stage,
                "error": str(exc),
                "attempts": [],
                "elapsed_ms": round((time.monotonic() - started_at) * 1000, 1),
            }
        except subprocess.SubprocessError as exc:
            return {
                "ok": False,
                "stage": "startup",
                "error": str(exc)[:500],
                "attempts": [],
                "elapsed_ms": round((time.monotonic() - started_at) * 1000, 1),
            }
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)


def probe_link(
    binary: Path,
    uri: str,
    listen_port: int,
    *,
    timeout: float = DEFAULT_NODE_TIMEOUT,
    measure_speed: bool = False,
    workdir: Path | None = None,
) -> dict:
    from .share_link import UnsupportedLink, outbound_identity, parse_share_link

    try:
        parsed = parse_share_link(uri)
    except UnsupportedLink as exc:
        return {"ok": False, "stage": "unsupported", "error": str(exc), "attempts": []}
    result = probe_outbound(
        binary,
        parsed["outbound"],
        listen_port,
        timeout=timeout,
        measure_speed=measure_speed,
        workdir=workdir,
    )
    result["protocol"] = parsed["protocol"]
    result["outbound_identity"] = outbound_identity(parsed["outbound"])
    result["host"] = parsed["host"]
    result["port"] = parsed["port"]
    return result
