"""Convert vless/vmess/trojan/ss share links into sing-box outbounds.

This module is the single place that interprets a share link for testing.  It
never mutates the link and never fills in a missing credential: a link that
cannot be expressed as a sing-box outbound is rejected with a stable reason.

The output is a plain ``dict`` so it can be serialized in candidate snapshots
and checked with ``sing-box check``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from urllib.parse import parse_qs, unquote, urlparse

SUPPORTED_SCHEMES = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "ss": "shadowsocks"}
SS_METHODS = {
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
}
VMESS_SECURITY = {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"}
UTLS_FINGERPRINTS = {
    "chrome_psk",
    "chrome_psk_shuffle",
    "chrome_padding_psk_shuffle",
    "chrome_pq",
    "chrome_pq_psk",
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
}
TLS_MODES = {"tls", "reality", "xtls"}
IDENTITY_SCHEMA = "sing-box-outbound-v1"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class UnsupportedLink(ValueError):
    """A share link cannot be represented as a sing-box outbound."""


def scheme_of(uri: str) -> str | None:
    if not isinstance(uri, str):
        return None
    text = uri.strip()
    head, sep, _ = text.partition("://")
    if not sep:
        return None
    return SUPPORTED_SCHEMES.get(head.lower())


def _clean(value: str) -> str:
    return _CONTROL.sub("", value).strip()


def _b64text(value: str) -> str:
    text = "".join(value.split())
    if not text:
        raise UnsupportedLink("empty base64 value")
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except Exception:
        try:
            raw = base64.b64decode(padded, altchars=b"-_", validate=False)
        except Exception as exc:
            raise UnsupportedLink("invalid base64 value") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsupportedLink("base64 value is not UTF-8") from exc


def _query(query: dict[str, list[str]], *names: str, default: str = "") -> str:
    for name in names:
        values = query.get(name)
        if values:
            for value in values:
                if value != "":
                    return value
    return default


def _flag(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _alpn(query: dict[str, list[str]]) -> list[str]:
    values: list[str] = []
    for raw in query.get("alpn", []) + query.get("alpns", []):
        for item in raw.split(","):
            item = item.strip()
            if item:
                values.append(item)
    return values


def _fingerprint(value: str) -> str:
    value = value.strip().lower()
    return value if value in UTLS_FINGERPRINTS else "chrome"


def _tls_options(
    *,
    mode: str,
    server_name: str,
    insecure: bool,
    alpn: list[str],
    fingerprint: str = "",
    public_key: str = "",
    short_id: str = "",
) -> dict | None:
    mode = (mode or "").strip().lower()
    if mode not in TLS_MODES:
        return None
    options: dict = {"enabled": True}
    if server_name:
        options["server_name"] = server_name
    if insecure:
        options["insecure"] = True
    if alpn:
        options["alpn"] = alpn
    if mode == "reality":
        if not public_key:
            raise UnsupportedLink("reality link has no public key")
        options["reality"] = {"enabled": True, "public_key": public_key, "short_id": short_id}
        options["utls"] = {"enabled": True, "fingerprint": _fingerprint(fingerprint)}
    elif fingerprint:
        options["utls"] = {"enabled": True, "fingerprint": _fingerprint(fingerprint)}
    return options


def _transport(kind: str, query: dict[str, list[str]]) -> dict | None:
    kind = (kind or "").strip().lower()
    if kind in {"", "tcp", "raw", "none"}:
        return None
    path = _query(query, "path", "serviceName", "service_name", default="/")
    host = _query(query, "host", "Host")
    if kind == "ws":
        transport: dict = {"type": "ws", "path": path or "/"}
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if kind == "grpc":
        return {"type": "grpc", "service_name": _query(query, "serviceName", "service_name", "path").lstrip("/")}
    if kind in {"http", "h2"}:
        transport = {"type": "http", "path": path or "/"}
        if host:
            transport["host"] = [part.strip() for part in host.split(",") if part.strip()]
        return transport
    if kind == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path or "/"}
        if host:
            transport["host"] = host
        return transport
    if kind == "quic":
        return {"type": "quic"}
    raise UnsupportedLink(f"unsupported transport: {kind}")


def _endpoint(parsed) -> tuple[str, int]:
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsupportedLink("invalid port") from exc
    if not host or not port or not 1 <= port <= 65535:
        raise UnsupportedLink("missing server or port")
    return _clean(host), port


def _vless(uri: str) -> dict:
    parsed = urlparse(uri)
    host, port = _endpoint(parsed)
    user = unquote(parsed.username or "").strip()
    if not user:
        raise UnsupportedLink("vless link has no UUID")
    query = parse_qs(parsed.query, keep_blank_values=True)
    mode = _query(query, "security", default="none").lower()
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": user,
    }
    flow = _query(query, "flow")
    if flow:
        outbound["flow"] = flow
    packet_encoding = _query(query, "packetEncoding", "packet_encoding")
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding
    transport = _transport(_query(query, "type", "net", default="tcp"), query)
    if transport:
        outbound["transport"] = transport
    tls = _tls_options(
        mode=mode,
        server_name=_query(query, "sni", "peer", "serverName", "server_name") or _query(query, "host"),
        insecure=_flag(_query(query, "allowInsecure", "insecure", "skip-cert-verify")),
        alpn=_alpn(query),
        fingerprint=_query(query, "fp", "fingerprint"),
        public_key=_query(query, "pbk", "public-key", "public_key"),
        short_id=_query(query, "sid", "short-id", "short_id"),
    )
    if tls:
        outbound["tls"] = tls
    return outbound


def _trojan(uri: str) -> dict:
    parsed = urlparse(uri)
    host, port = _endpoint(parsed)
    password = unquote(parsed.username or "").strip()
    if not password:
        raise UnsupportedLink("trojan link has no password")
    query = parse_qs(parsed.query, keep_blank_values=True)
    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "password": password,
    }
    transport = _transport(_query(query, "type", "net", default="tcp"), query)
    if transport:
        outbound["transport"] = transport
    mode = _query(query, "security", default="tls") or "tls"
    tls = _tls_options(
        mode=mode,
        server_name=_query(query, "sni", "peer", "serverName", "server_name") or _query(query, "host"),
        insecure=_flag(_query(query, "allowInsecure", "insecure", "skip-cert-verify")),
        alpn=_alpn(query),
        fingerprint=_query(query, "fp", "fingerprint"),
        public_key=_query(query, "pbk", "public-key", "public_key"),
        short_id=_query(query, "sid", "short-id", "short_id"),
    )
    if tls:
        outbound["tls"] = tls
    return outbound


def _vmess_json(uri: str) -> dict | None:
    payload = unquote(uri[8:].split("#", 1)[0].strip())
    if not payload or "@" in payload:
        return None
    try:
        decoded = _b64text(payload)
        obj = json.loads(decoded)
    except (UnsupportedLink, ValueError):
        return None
    if not isinstance(obj, dict) or not (obj.get("add") or obj.get("address")):
        return None
    host = _clean(str(obj.get("add") or obj.get("address") or ""))
    try:
        port = int(obj.get("port"))
    except (TypeError, ValueError):
        raise UnsupportedLink("vmess JSON has no port")
    if not host or not 1 <= port <= 65535:
        raise UnsupportedLink("vmess JSON has an invalid endpoint")
    user = str(obj.get("id") or obj.get("uuid") or "").strip()
    if not user:
        raise UnsupportedLink("vmess JSON has no UUID")
    cipher = str(obj.get("scy") or obj.get("security") or "auto").strip().lower()
    cipher = cipher if cipher in VMESS_SECURITY else "auto"
    try:
        alter_id = int(obj.get("aid") or obj.get("alterId") or 0)
    except (TypeError, ValueError):
        alter_id = 0
    fake_query = {
        "path": [str(obj.get("path") or "/")],
        "host": [str(obj.get("host") or "")],
        "serviceName": [str(obj.get("path") or "")],
    }
    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": user,
        "security": cipher,
        "alter_id": max(0, alter_id),
    }
    transport = _transport(str(obj.get("net") or obj.get("type") or "tcp"), fake_query)
    if transport:
        outbound["transport"] = transport
    tls = _tls_options(
        mode=str(obj.get("tls") or "none").lower(),
        server_name=str(obj.get("sni") or obj.get("host") or ""),
        insecure=_flag(str(obj.get("allowInsecure") or obj.get("skip-cert-verify") or "")),
        alpn=[part.strip() for part in str(obj.get("alpn") or "").split(",") if part.strip()],
        fingerprint=str(obj.get("fp") or ""),
    )
    if tls:
        outbound["tls"] = tls
    return outbound


def _vmess(uri: str) -> dict:
    legacy = _vmess_json(uri)
    if legacy is not None:
        return legacy
    parsed = urlparse(uri)
    host, port = _endpoint(parsed)
    user = unquote(parsed.username or "").strip()
    if not user:
        raise UnsupportedLink("vmess link has no UUID")
    query = parse_qs(parsed.query, keep_blank_values=True)
    cipher = _query(query, "scy", "encryption", default="auto").lower()
    if cipher not in VMESS_SECURITY:
        cipher = "auto"
    try:
        alter_id = max(0, int(_query(query, "aid", "alterId", default="0") or 0))
    except ValueError:
        alter_id = 0
    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": user,
        "security": cipher,
        "alter_id": alter_id,
    }
    transport = _transport(_query(query, "type", "net", default="tcp"), query)
    if transport:
        outbound["transport"] = transport
    mode = _query(query, "tls")
    if not mode:
        candidate = _query(query, "security").lower()
        mode = candidate if candidate in TLS_MODES else "none"
    tls = _tls_options(
        mode=mode,
        server_name=_query(query, "sni", "peer", "serverName", "server_name") or _query(query, "host"),
        insecure=_flag(_query(query, "allowInsecure", "insecure", "skip-cert-verify")),
        alpn=_alpn(query),
        fingerprint=_query(query, "fp", "fingerprint"),
        public_key=_query(query, "pbk", "public-key", "public_key"),
        short_id=_query(query, "sid", "short-id", "short_id"),
    )
    if tls:
        outbound["tls"] = tls
    return outbound


def _shadowsocks(uri: str) -> dict:
    body = uri[5:]
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
    query: dict[str, list[str]] = {}
    if "?" in body:
        body, query_text = body.split("?", 1)
        query = parse_qs(query_text, keep_blank_values=True)
    body = unquote(body).strip()
    if not body:
        raise UnsupportedLink("ss link is empty")
    if "@" in body:
        userinfo, endpoint = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = _b64text(userinfo)
        if ":" not in userinfo:
            raise UnsupportedLink("ss credentials are malformed")
        method, password = userinfo.split(":", 1)
    else:
        decoded = _b64text(body)
        if "@" not in decoded:
            raise UnsupportedLink("ss link has no endpoint")
        userinfo, endpoint = decoded.rsplit("@", 1)
        if ":" not in userinfo:
            raise UnsupportedLink("ss credentials are malformed")
        method, password = userinfo.split(":", 1)
    method = method.strip().lower()
    if method not in SS_METHODS:
        raise UnsupportedLink(f"unsupported ss method: {method or 'missing'}")
    if not password:
        raise UnsupportedLink("ss link has no password")
    parsed = urlparse("//" + endpoint)
    host, port = _endpoint(parsed)
    outbound = {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }
    plugin = _query(query, "plugin")
    if plugin:
        name, _, opts = plugin.partition(";")
        name = name.strip()
        if name:
            outbound["plugin"] = name
            if opts:
                outbound["plugin_opts"] = opts
    return outbound


def parse_share_link(uri: str) -> dict:
    """Return ``{outbound, protocol, host, port, remark}`` or raise."""
    if not isinstance(uri, str):
        raise UnsupportedLink("link is not text")
    uri = uri.strip()
    if not uri or _CONTROL.search(uri) or any(ch in uri for ch in "\r\n"):
        raise UnsupportedLink("link contains control characters")
    protocol = scheme_of(uri)
    if protocol is None:
        raise UnsupportedLink("unsupported scheme")
    if protocol == "vless":
        outbound = _vless(uri)
    elif protocol == "vmess":
        outbound = _vmess(uri)
    elif protocol == "trojan":
        outbound = _trojan(uri)
    else:
        outbound = _shadowsocks(uri)
    remark = ""
    if "#" in uri:
        remark = _clean(unquote(uri.split("#", 1)[1]))
    return {
        "outbound": outbound,
        "protocol": protocol,
        "host": outbound["server"],
        "port": int(outbound["server_port"]),
        "remark": remark,
        "transport": str(outbound.get("transport", {}).get("type", "tcp")),
        "security": "reality" if outbound.get("tls", {}).get("reality", {}).get("enabled") else (
            "tls" if outbound.get("tls", {}).get("enabled") else "none"
        ),
    }


def outbound_identity(outbound: dict) -> str:
    """Stable credential-inclusive identity of effective connection settings."""
    payload = {key: value for key, value in outbound.items() if key not in {"tag", "name"}}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{IDENTITY_SCHEMA}:{hashlib.sha256(encoded).hexdigest()}"


def is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False
