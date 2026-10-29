#!/usr/bin/env python3
"""Adapter for the share-daily/node Clash YAML feed."""

from __future__ import annotations

import base64
import json
import urllib.request
from urllib.parse import quote, urlencode

import yaml


SOURCE_URL = "https://raw.githubusercontent.com/share-daily/node/main/clash.yaml"
ALLOWED_PORTS = {443}
SUPPORTED_TYPES = {"vless", "vmess", "trojan", "ss"}
MAX_BYTES = 2_000_000


def fetch_text(url: str = SOURCE_URL) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "VPN-Nodes-Catalog/1.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("share-daily Clash YAML exceeds size limit")
    return data.decode("utf-8", errors="replace")


def _port(proxy: dict) -> int | None:
    try:
        return int(proxy.get("port"))
    except (TypeError, ValueError):
        return None


def _text(proxy: dict, *keys: str) -> str:
    for key in keys:
        value = proxy.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _endpoint(host: str, port: int) -> str:
    host = host.strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


def _name(proxy: dict) -> str:
    return _text(proxy, "name") or "share-daily"


def _network(proxy: dict) -> str:
    return (_text(proxy, "network") or "tcp").lower()


def _security(proxy: dict) -> str:
    reality = proxy.get("reality-opts")
    if isinstance(reality, dict) and reality:
        return "reality"
    if proxy.get("tls") is True or str(proxy.get("tls") or "").lower() in {"true", "tls"}:
        return "tls"
    return "none"


def _ws_fields(proxy: dict) -> tuple[str, str]:
    opts = proxy.get("ws-opts")
    if not isinstance(opts, dict):
        return "", ""
    path = str(opts.get("path") or "").strip()
    host = ""
    headers = opts.get("headers")
    if isinstance(headers, dict):
        host = str(headers.get("Host") or headers.get("host") or "").strip()
    return path, host


def _grpc_service(proxy: dict) -> str:
    opts = proxy.get("grpc-opts")
    if not isinstance(opts, dict):
        return ""
    return str(
        opts.get("grpc-service-name")
        or opts.get("serviceName")
        or opts.get("service-name")
        or ""
    ).strip()


def _common_query(proxy: dict, *, include_encryption: bool = False) -> dict[str, str]:
    query: dict[str, str] = {}
    network = _network(proxy)
    if network:
        query["type"] = network

    security = _security(proxy)
    if security != "none":
        query["security"] = security

    if include_encryption:
        query["encryption"] = _text(proxy, "encryption") or "none"

    sni = _text(proxy, "servername", "sni")
    if sni:
        query["sni"] = sni

    fingerprint = _text(proxy, "client-fingerprint", "fingerprint", "fp")
    if fingerprint:
        query["fp"] = fingerprint

    flow = _text(proxy, "flow")
    if flow:
        query["flow"] = flow

    if proxy.get("skip-cert-verify") is True:
        query["allowInsecure"] = "1"

    alpn = proxy.get("alpn")
    if isinstance(alpn, list):
        values = [str(value).strip() for value in alpn if str(value).strip()]
        if values:
            query["alpn"] = ",".join(values)
    elif alpn not in (None, ""):
        query["alpn"] = str(alpn).strip()

    if network == "ws":
        path, host = _ws_fields(proxy)
        if path:
            query["path"] = path
        if host:
            query["host"] = host
    elif network == "grpc":
        service = _grpc_service(proxy)
        if service:
            query["serviceName"] = service

    reality = proxy.get("reality-opts")
    if isinstance(reality, dict):
        pbk = str(
            reality.get("public-key")
            or reality.get("publicKey")
            or reality.get("pbk")
            or ""
        ).strip()
        sid = str(
            reality.get("short-id")
            or reality.get("shortId")
            or reality.get("sid")
            or ""
        ).strip()
        if pbk:
            query["pbk"] = pbk
        if sid:
            query["sid"] = sid

    return query


def _vless_uri(proxy: dict, host: str, port: int) -> str | None:
    uuid = _text(proxy, "uuid")
    if not uuid:
        return None
    query = _common_query(proxy, include_encryption=True)
    return (
        f"vless://{quote(uuid, safe='')}@{_endpoint(host, port)}"
        f"?{urlencode(query)}#{quote(_name(proxy), safe='')}"
    )


def _trojan_uri(proxy: dict, host: str, port: int) -> str | None:
    password = _text(proxy, "password")
    if not password:
        return None
    query = _common_query(proxy)
    return (
        f"trojan://{quote(password, safe='')}@{_endpoint(host, port)}"
        f"?{urlencode(query)}#{quote(_name(proxy), safe='')}"
    )


def _ss_uri(proxy: dict, host: str, port: int) -> str | None:
    cipher = _text(proxy, "cipher")
    password = _text(proxy, "password")
    if not cipher or not password:
        return None
    userinfo = f"{cipher}:{password}".encode("utf-8")
    encoded = base64.urlsafe_b64encode(userinfo).decode("ascii").rstrip("=")
    return f"ss://{encoded}@{_endpoint(host, port)}#{quote(_name(proxy), safe='')}"


def _vmess_uri(proxy: dict, host: str, port: int) -> str | None:
    uuid = _text(proxy, "uuid")
    if not uuid:
        return None

    network = _network(proxy)
    path = ""
    http_host = ""
    if network == "ws":
        path, http_host = _ws_fields(proxy)
    elif network == "grpc":
        path = _grpc_service(proxy)

    payload: dict[str, str] = {
        "v": "2",
        "ps": _name(proxy),
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": _text(proxy, "alterId", "alter-id") or "0",
        "scy": _text(proxy, "cipher") or "auto",
        "net": network,
        "type": "none",
        "host": http_host,
        "path": path,
        "tls": "tls" if _security(proxy) in {"tls", "reality"} else "",
        "sni": _text(proxy, "servername", "sni"),
    }
    encoded = base64.b64encode(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return f"vmess://{encoded}"


def proxy_to_uri(proxy: dict) -> str | None:
    if not isinstance(proxy, dict):
        return None

    proxy_type = _text(proxy, "type").lower()
    if proxy_type not in SUPPORTED_TYPES:
        return None

    host = _text(proxy, "server")
    port = _port(proxy)
    if not host or port not in ALLOWED_PORTS:
        return None

    if proxy_type == "vless":
        return _vless_uri(proxy, host, port)
    if proxy_type == "vmess":
        return _vmess_uri(proxy, host, port)
    if proxy_type == "trojan":
        return _trojan_uri(proxy, host, port)
    if proxy_type == "ss":
        return _ss_uri(proxy, host, port)
    return None


def extract_nodes(text: str) -> list[dict]:
    payload = yaml.safe_load(text)
    if not isinstance(payload, dict):
        return []

    proxies = payload.get("proxies")
    if not isinstance(proxies, list):
        return []

    rows: list[dict] = []
    seen: set[str] = set()
    for proxy in proxies:
        uri = proxy_to_uri(proxy)
        if not uri or uri in seen:
            continue
        seen.add(uri)
        rows.append(
            {
                "name": "ShareDaily-Clash",
                "source": "share-daily-node",
                "url": uri,
            }
        )
    return rows


def collect_share_daily() -> list[dict]:
    rows = extract_nodes(fetch_text())
    print(f"OK source ShareDaily-Clash total: {len(rows)}")
    return rows


if __name__ == "__main__":
    collect_share_daily()
