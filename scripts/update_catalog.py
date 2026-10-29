from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

import requests

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from gitverse_adapter import gitverse_fallback_urls
from share_daily_adapter import extract_nodes as extract_clash_nodes
from share_link_extractor import ExtractedURI, extract_uri_records

ROOT = SCRIPTS_DIR.parent
OUT = ROOT / "output"
MAX_SOURCE_BYTES = 20_000_000
CONNECT_TIMEOUT = 1.5
READ_TIMEOUT = 8.0
ALLOWED_PORTS = {443}
PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}

session = requests.Session()
session.headers.update({"User-Agent": "Ahmed-VPN-Nodes/2.0 (+public-aggregator)"})
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

VMESS_DIAGNOSTICS = {"seen": 0, "decode_ok": 0, "decode_failed": 0}
URI_RE = re.compile(
    r"""(?:vless|vmess|trojan|ss)://(?:(?!(?:vless|vmess|trojan|ss)://)[^'"\s,<>\x60])+""",
    re.IGNORECASE,
)


def fetch(url: str, headers: dict[str, str] | None = None) -> bytes:
    if headers:
        response = session.get(
            url,
            headers=headers,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            stream=True,
        )
    else:
        response = session.get(
            url,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            stream=True,
        )
    response.raise_for_status()
    data = bytearray()
    for chunk in response.iter_content(8192):
        data.extend(chunk)
        if len(data) > MAX_SOURCE_BYTES:
            break
    return bytes(data[:MAX_SOURCE_BYTES])


def maybe_decode(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    compact = re.sub(r"\s+", "", text)
    if len(compact) > 100 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
            candidate = decoded.decode("utf-8", errors="replace")
            if any(x in candidate for x in ("vless://", "vmess://", "trojan://", "ss://")):
                return candidate
        except Exception:
            pass
    return text


def protocol_from_uri(uri: str) -> str | None:
    scheme = uri.split(":", 1)[0].lower()
    return "shadowsocks" if scheme == "ss" else scheme if scheme in PROTOCOLS else None


def extract_uris(text: str) -> list[str]:
    """Extract every URI, including links concatenated without whitespace."""
    return [item.uri for item in extract_uri_records(text)]


def _decode_ss_parts(uri: str):
    raw = unquote(uri.split("://", 1)[1].split("#", 1)[0].strip())
    raw = raw.split("?", 1)[0]
    if "@" in raw:
        userinfo, endpoint = raw.rsplit("@", 1)
        if ":" not in userinfo:
            try:
                userinfo = base64.urlsafe_b64decode(
                    userinfo + "=" * (-len(userinfo) % 4)
                ).decode("utf-8", errors="strict")
            except Exception:
                return None
    else:
        try:
            decoded = base64.urlsafe_b64decode(
                raw + "=" * (-len(raw) % 4)
            ).decode("utf-8", errors="strict")
            userinfo, endpoint = decoded.rsplit("@", 1)
        except Exception:
            return None
    if ":" not in userinfo:
        return None
    method, password = userinfo.split(":", 1)
    parsed = urlparse("//" + endpoint)
    try:
        port = parsed.port
    except ValueError:
        return None
    if not method.strip() or not password or not parsed.hostname or not port:
        return None
    return parsed.hostname, port, method.strip().lower(), password


def _decode_vmess_payload(uri: str):
    # Modern Xray share links use vmess://UUID@host:port?... .  Keep the raw
    # URI unchanged here; later merge normalization owns HTML entity cleanup.
    parsed = urlparse(uri)
    try:
        modern_port = parsed.port
    except ValueError:
        modern_port = None
    if parsed.username is not None and parsed.hostname and modern_port:
        user_id = unquote(parsed.username).strip()
        if not user_id:
            return None
        return (
            parsed.hostname,
            modern_port,
            unquote(parsed.fragment or ""),
            parse_qs(parsed.query),
        )

    # Legacy vmess://BASE64(JSON) remains supported.
    payload = unquote(uri.split("://", 1)[1].split("#", 1)[0].strip())
    if not payload:
        return None
    padded = payload + "=" * (-len(payload) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=False)
        obj = json.loads(decoded.decode("utf-8-sig", errors="strict"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    host = str(obj.get("add") or obj.get("address") or "").strip()
    try:
        port = int(obj.get("port"))
    except (TypeError, ValueError):
        return None
    if not host or not port:
        return None
    remark = str(obj.get("ps") or obj.get("remark") or "").strip()
    query = {}
    for src, dst in (("id", "uuid"), ("aid", "alterId"), ("net", "type"), ("host", "host"), ("path", "path"), ("tls", "security"), ("sni", "sni"), ("scy", "encryption")):
        if obj.get(src) not in (None, ""):
            query[dst] = [str(obj[src])]
    return host, port, remark, query


def endpoint_from_uri(uri: str):
    scheme = uri.split(":", 1)[0].lower()
    try:
        if scheme == "vmess":
            VMESS_DIAGNOSTICS["seen"] += 1
            decoded = _decode_vmess_payload(uri)
            if decoded:
                VMESS_DIAGNOSTICS["decode_ok"] += 1
                return decoded
            VMESS_DIAGNOSTICS["decode_failed"] += 1
        if scheme == "ss":
            decoded_ss = _decode_ss_parts(uri)
            if decoded_ss:
                host, port, _, _ = decoded_ss
                parsed = urlparse(uri)
                return host, port, unquote(parsed.fragment or ""), parse_qs(parsed.query)
        parsed = urlparse(uri)
        return parsed.hostname, parsed.port, unquote(parsed.fragment or ""), parse_qs(parsed.query)
    except Exception:
        return None, None, "", {}


def valid_uri(uri: str, protocol: str) -> bool:
    try:
        if len(re.findall(r"(?:vless|vmess|trojan|ss)://", uri, re.I)) != 1:
            return False
        if protocol == "vmess":
            return _decode_vmess_payload(uri) is not None
        if protocol == "shadowsocks":
            return _decode_ss_parts(uri) is not None
        parsed = urlparse(uri)
        port = parsed.port
        return bool(parsed.hostname and port and parsed.username)
    except (TypeError, ValueError, UnicodeError):
        return False


def dedup_key(uri: str) -> str:
    host, port, _, query = endpoint_from_uri(uri)
    scheme = protocol_from_uri(uri) or ""
    if not host or not port:
        return uri
    identity = [scheme, host.lower(), str(port)]
    for key in ("uuid", "sid", "sni", "serverName", "path", "type", "security", "encryption", "method"):
        value = query.get(key, [""])[0]
        if value:
            identity.append(f"{key}={value}")
    return "|".join(identity)


def parse_uri_records(records: list[ExtractedURI], source_name: str):
    rows = []
    for item in records:
        uri = item.uri
        try:
            protocol = protocol_from_uri(uri)
            if not protocol or not valid_uri(uri, protocol):
                continue
            host, port, remark, _ = endpoint_from_uri(uri)
            if not host or port not in ALLOWED_PORTS:
                continue
            rows.append({"uri": uri, "protocol": protocol, "host": host, "port": port, "remark": remark, "country": "UNKNOWN", "source": source_name, **item.source_fields()})
        except (TypeError, ValueError, UnicodeError):
            # A malformed node must never discard the remaining source file.
            continue
    return rows


def parse_lines(text: str, source_name: str, source_hint_country: str | None = None, *, html_source: bool | None = None):
    text = maybe_decode(text.encode("utf-8", errors="ignore"))
    if html_source is not True:
        text = "\n".join(line for line in text.splitlines()
                         if not line.lstrip().startswith(("#", "//", "proxies:", "proxy-groups:")))
    return parse_uri_records(extract_uri_records(text, html_source=html_source), source_name)


def parse_vpngate_csv(data: bytes, source_name: str) -> list[dict]:
    text = data.decode("utf-8-sig", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    header_index = next((i for i, line in enumerate(lines) if line.startswith("#HostName,")), None)
    if header_index is None:
        raise ValueError("VPN Gate CSV header not found")
    reader = csv.DictReader(io.StringIO("\n".join(lines[header_index:])))
    rows: list[dict] = []
    for row in reader:
        cfg_b64 = str(row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not cfg_b64:
            continue
        try:
            config = base64.b64decode(cfg_b64 + "=" * (-len(cfg_b64) % 4)).decode("utf-8", errors="replace")
        except Exception:
            continue
        remotes = re.findall(r"^\s*remote\s+(\S+)\s+(\d+)\b", config, flags=re.MULTILINE)
        allowed = [(host, int(port)) for host, port in remotes if int(port) in ALLOWED_PORTS]
        if not allowed:
            continue
        host, port = allowed[0]
        rows.append({
            "uri": f"openvpn://{host}:{port}#{source_name}",
            "protocol": "openvpn",
            "host": host,
            "port": port,
            "server": host,
            "country": str(row.get("CountryShort") or "UNKNOWN").strip().upper() or "UNKNOWN",
            "country_name": str(row.get("CountryLong") or "").strip(),
            "source": source_name,
            "score": row.get("Score"),
            "ping": row.get("Ping"),
            "speed": row.get("Speed"),
            "config_b64": cfg_b64,
        })
    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    (meta / "openvpn_candidates.json").write_text(json.dumps({"generated_by": source_name, "nodes": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO {source_name}: OpenVPN candidates={len(rows)}")
    return rows


def github_api_json(url: str):
    parsed = urlparse(url)
    headers = {}
    if GITHUB_TOKEN and parsed.scheme == "https" and parsed.hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    response = session.get(url, headers=headers, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
    response.raise_for_status()
    return response.json()


def github_index(url: str):
    payload = github_api_json(url)
    return payload if isinstance(payload, list) else []


def github_tree_entries(url: str):
    payload = github_api_json(url)
    return [x for x in payload.get("tree", []) if x.get("type") == "blob"] if isinstance(payload, dict) else []


def collect_github_api_source(item):
    rows = []
    for entry in github_index(item["url"]):
        if entry.get("type") != "file" or not entry.get("download_url"):
            continue
        try:
            rows.extend(parse_lines(fetch(entry["download_url"]).decode("utf-8", errors="replace"), f"{item['name']}:{entry.get('name','')}"))
        except Exception as exc:
            print(f"WARN {item['name']}/{entry.get('name','')}: {exc}")
    return rows


def collect_github_tree_source(item):
    rows = []
    for entry in github_tree_entries(item["url"]):
        path = entry.get("path", "")
        if item.get("path_regex") and not re.search(item["path_regex"], path, re.I):
            continue
        raw = f"https://raw.githubusercontent.com/{item['owner']}/{item['repo']}/{item.get('ref','main')}/{path}"
        try:
            rows.extend(parse_lines(fetch(raw).decode("utf-8", errors="replace"), f"{item['name']}:{path}"))
        except Exception as exc:
            print(f"WARN {item['name']}/{path}: {exc}")
    return rows


def parse_clash_yaml(data: bytes, source_name: str) -> list[dict]:
    candidates = extract_clash_nodes(data.decode("utf-8", errors="replace"))
    uris = [str(candidate.get("url") or "").strip() for candidate in candidates]
    return parse_lines("\n".join(uri for uri in uris if uri), source_name)


def _collect_source_once(item):
    fmt = item.get("format")
    if fmt == "github_api":
        return collect_github_api_source(item)
    if fmt == "github_tree":
        return collect_github_tree_source(item)

    configured_headers = item.get("headers") or {}
    if not isinstance(configured_headers, dict):
        raise ValueError(f"source headers must be an object: {item.get('name', 'UNKNOWN')}")
    headers = {
        str(key): str(value)
        for key, value in configured_headers.items()
        if str(key).strip() and str(value).strip()
    }

    def fetch_source() -> bytes:
        if headers:
            return fetch(item["url"], headers=headers)
        return fetch(item["url"])

    if fmt == "vpngate_csv":
        return parse_vpngate_csv(fetch_source(), item["name"])
    if fmt == "clash_yaml":
        return parse_clash_yaml(fetch_source(), item["name"])
    if item.get("kind") == "country_template":
        return []
    return parse_lines(fetch_source().decode("utf-8", errors="replace"), item["name"])


def collect_source(item):
    urls = [item["url"], *gitverse_fallback_urls(item)]
    failures = []
    successful_fetch = False

    for index, url in enumerate(urls):
        candidate = {**item, "url": url}
        try:
            rows = _collect_source_once(candidate)
            successful_fetch = True
        except Exception as exc:
            failures.append(f"{url}: {exc}")
            if index + 1 < len(urls):
                print(f"WARN {item['name']}: primary failed; trying GitVerse fallback: {exc}")
            continue

        if rows:
            if index:
                print(f"INFO {item['name']}: GitVerse fallback active, nodes={len(rows)}")
            return rows
        if index + 1 < len(urls):
            print(f"WARN {item['name']}: primary returned 0 supported nodes; trying GitVerse fallback")

    if failures and not successful_fetch:
        raise RuntimeError("; ".join(failures))
    return []


def load_previous_snapshot():
    return []
