#!/usr/bin/env python3
import base64
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import share_daily_adapter as adapter
import update_catalog as catalog

FIXTURE = """
proxies:
  - name: vless-reality
    type: vless
    server: fresh.example
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    network: tcp
    tls: true
    servername: example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: public-key-value
      short-id: abcd
  - name: vmess-ws
    type: vmess
    server: vmess.example
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
    alterId: 0
    cipher: auto
    network: ws
    tls: false
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example
  - name: trojan-grpc
    type: trojan
    server: trojan.example
    port: 443
    password: secret
    network: grpc
    tls: true
    sni: trojan-sni.example
    grpc-opts:
      grpc-service-name: svc
  - name: ss-allowed
    type: ss
    server: 192.0.2.10
    port: 443
    cipher: aes-256-gcm
    password: pass
  - name: blocked-80
    type: vless
    server: blocked80.example
    port: 80
    uuid: 55555555-5555-5555-5555-555555555555
  - name: wrong-port
    type: vless
    server: wrong.example
    port: 8443
    uuid: 33333333-3333-3333-3333-333333333333
  - name: unsupported-http
    type: http
    server: http.example
    port: 443
"""

rows = adapter.extract_nodes(FIXTURE)
assert len(rows) == 4
uris = [row["url"] for row in rows]

vless = next(uri for uri in uris if uri.startswith("vless://"))
parsed = urlparse(vless)
query = parse_qs(parsed.query)
assert parsed.hostname == "fresh.example"
assert parsed.port == 443
assert parsed.username == "11111111-1111-1111-1111-111111111111"
assert query["security"] == ["reality"]
assert query["sni"] == ["example.com"]
assert query["fp"] == ["chrome"]
assert query["pbk"] == ["public-key-value"]
assert query["sid"] == ["abcd"]

vmess = next(uri for uri in uris if uri.startswith("vmess://"))
payload = vmess.split("://", 1)[1]
decoded = json.loads(base64.b64decode(payload).decode("utf-8"))
assert decoded["add"] == "vmess.example"
assert decoded["port"] == "443"
assert decoded["net"] == "ws"
assert decoded["path"] == "/ws"
assert decoded["host"] == "cdn.example"
assert decoded["tls"] == ""

trojan = next(uri for uri in uris if uri.startswith("trojan://"))
parsed = urlparse(trojan)
query = parse_qs(parsed.query)
assert parsed.hostname == "trojan.example"
assert parsed.port == 443
assert query["type"] == ["grpc"]
assert query["security"] == ["tls"]
assert query["sni"] == ["trojan-sni.example"]
assert query["serviceName"] == ["svc"]

ss = next(uri for uri in uris if uri.startswith("ss://"))
userinfo = ss.split("://", 1)[1].split("@", 1)[0]
decoded_userinfo = base64.urlsafe_b64decode(
    userinfo + "=" * (-len(userinfo) % 4)
).decode("utf-8")
assert decoded_userinfo == "aes-256-gcm:pass"

assert not any("wrong.example" in uri for uri in uris)
assert not any("blocked80.example" in uri for uri in uris)
assert not any("http.example" in uri for uri in uris)

normalized = []
for row in rows:
    normalized.extend(catalog.parse_lines(row["url"], "ShareDaily-Clash"))
assert len(normalized) == 4
assert {row["protocol"] for row in normalized} == {
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
}
assert {row["port"] for row in normalized} == {443}
assert catalog.parse_lines("trojan://pw@blocked.example:80#blocked", "port-policy") == []

print("OK share-daily Clash adapter")
