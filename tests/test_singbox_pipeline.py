"""Tests for the sing-box collection, conversion, probing and publication path."""
from __future__ import annotations

import base64
import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from singbox_pipeline import collect, config, core, probe, runner  # noqa: E402
from singbox_pipeline.share_link import (  # noqa: E402
    UnsupportedLink,
    outbound_identity,
    parse_share_link,
)

SINGBOX = os.environ.get("SINGBOX_BINARY", "").strip()
UUID = "11111111-2222-3333-4444-555555555555"


def ss_link(method: str, password: str, host: str, port: int, remark: str = "ss") -> str:
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    return f"ss://{userinfo}@{host}:{port}#{remark}"


class ShareLinkTests(unittest.TestCase):
    def test_vless_reality_ws(self):
        uri = (
            f"vless://{UUID}@example.com:443?type=ws&security=reality&pbk=public-key&sid=abcd"
            "&fp=chrome&sni=cdn.example.com&path=%2Fws&host=cdn.example.com#Node%20One"
        )
        parsed = parse_share_link(uri)
        outbound = parsed["outbound"]
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["uuid"], UUID)
        self.assertEqual(outbound["server"], "example.com")
        self.assertEqual(outbound["server_port"], 443)
        self.assertEqual(outbound["tls"]["server_name"], "cdn.example.com")
        self.assertEqual(outbound["tls"]["reality"], {"enabled": True, "public_key": "public-key", "short_id": "abcd"})
        self.assertEqual(outbound["tls"]["utls"], {"enabled": True, "fingerprint": "chrome"})
        self.assertEqual(outbound["transport"], {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"}})
        self.assertEqual(parsed["remark"], "Node One")
        self.assertEqual(parsed["security"], "reality")

    def test_trojan_grpc(self):
        uri = "trojan://secret@example.com:443?type=grpc&serviceName=svc&security=tls&sni=example.com#t"
        outbound = parse_share_link(uri)["outbound"]
        self.assertEqual(outbound["type"], "trojan")
        self.assertEqual(outbound["password"], "secret")
        self.assertEqual(outbound["transport"], {"type": "grpc", "service_name": "svc"})
        self.assertTrue(outbound["tls"]["enabled"])

    def test_vmess_legacy_json(self):
        payload = {
            "v": "2",
            "ps": "legacy",
            "add": "legacy.example.com",
            "port": "443",
            "id": UUID,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "host": "legacy.example.com",
            "path": "/ray",
            "tls": "tls",
            "sni": "legacy.example.com",
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        outbound = parse_share_link("vmess://" + encoded)["outbound"]
        self.assertEqual(outbound["type"], "vmess")
        self.assertEqual(outbound["uuid"], UUID)
        self.assertEqual(outbound["security"], "auto")
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertEqual(outbound["transport"]["path"], "/ray")
        self.assertTrue(outbound["tls"]["enabled"])

    def test_vmess_modern_uri(self):
        uri = f"vmess://{UUID}@example.com:443?type=ws&security=tls&scy=auto&path=%2Fvm&host=example.com#m"
        outbound = parse_share_link(uri)["outbound"]
        self.assertEqual(outbound["type"], "vmess")
        self.assertEqual(outbound["transport"]["headers"], {"Host": "example.com"})
        self.assertTrue(outbound["tls"]["enabled"])

    def test_shadowsocks_sip002_and_legacy(self):
        sip002 = parse_share_link(ss_link("aes-128-gcm", "p@ss", "example.com", 443))["outbound"]
        self.assertEqual(sip002["type"], "shadowsocks")
        self.assertEqual(sip002["method"], "aes-128-gcm")
        self.assertEqual(sip002["password"], "p@ss")
        legacy_payload = base64.urlsafe_b64encode(b"aes-256-gcm:secret@example.org:8443").decode().rstrip("=")
        legacy = parse_share_link(f"ss://{legacy_payload}#legacy")["outbound"]
        self.assertEqual(legacy["server"], "example.org")
        self.assertEqual(legacy["server_port"], 8443)

    def test_identity_ignores_tag_and_fragment(self):
        first = parse_share_link(f"vless://{UUID}@example.com:443?security=tls#One")["outbound"]
        second = parse_share_link(f"vless://{UUID}@example.com:443?security=tls#Two")["outbound"]
        self.assertEqual(outbound_identity(first), outbound_identity(second))
        changed = parse_share_link(f"vless://{UUID}@example.com:443?security=tls&sni=other.example#One")["outbound"]
        self.assertNotEqual(outbound_identity(first), outbound_identity(changed))

    def test_rejects_unrepresentable_links(self):
        cases = [
            "http://example.com",
            f"vless://example.com:443?security=tls",
            f"vless://{UUID}@example.com:443?type=xhttp",
            f"vless://{UUID}@example.com:443?security=reality",
            "ss://" + base64.urlsafe_b64encode(b"rot13:pass@example.com:443").decode().rstrip("="),
            "vless://" + UUID + "@example.com:99999",
        ]
        for uri in cases:
            with self.subTest(uri=uri):
                with self.assertRaises(UnsupportedLink):
                    parse_share_link(uri)


class ConfigTests(unittest.TestCase):
    def test_client_config_has_no_direct_fallback(self):
        parsed = parse_share_link(ss_link("aes-128-gcm", "p", "example.com", 443))
        built = config.client_config(parsed["outbound"], 18080)
        self.assertEqual([item["type"] for item in built["inbounds"]], ["mixed"])
        self.assertEqual(len(built["outbounds"]), 1)
        self.assertEqual(built["outbounds"][0]["tag"], "proxy")
        self.assertEqual(built["route"]["final"], "proxy")

    @unittest.skipUnless(SINGBOX, "SINGBOX_BINARY is not set")
    def test_generated_configs_pass_singbox_check(self):
        samples = [
            parse_share_link(
                f"vless://{UUID}@example.com:443?type=ws&security=reality&pbk=XuvRZl-03pX1IqcgyyaeXiaQUsObaZekikPzewJ4FXc&sid=12"
                "&fp=chrome&sni=cdn.example.com&path=%2Fws#r"
            ),
            parse_share_link(f"vmess://{UUID}@example.com:443?type=ws&security=tls&path=%2F#v"),
            parse_share_link("trojan://secret@example.com:443?type=grpc&serviceName=svc#t"),
            parse_share_link(ss_link("aes-128-gcm", "password", "example.com", 443)),
        ]
        binary = Path(SINGBOX)
        with tempfile.TemporaryDirectory(prefix="singbox-config-test-") as directory:
            for index, parsed in enumerate(samples):
                path = Path(directory) / f"config-{index}.json"
                config.write_config(path, config.client_config(parsed["outbound"], 19000 + index))
                ok, diagnostic = config.check_config(binary, path)
                self.assertTrue(ok, diagnostic)


class NormalizationTests(unittest.TestCase):
    def test_dedup_port_filter_and_unsupported(self):
        uri = ss_link("aes-128-gcm", "p", "example.com", 443)
        rows = [
            {"uri": uri, "protocol": "shadowsocks", "source": "a"},
            {"uri": uri + "#duplicate-name", "protocol": "shadowsocks", "source": "b"},
            {"uri": ss_link("aes-128-gcm", "p", "example.com", 8443), "protocol": "shadowsocks", "source": "c"},
            {"uri": "not-a-link", "protocol": "shadowsocks", "source": "d"},
        ]
        nodes, failures, summary = collect.normalize_rows(rows, {443})
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["index"], 0)
        self.assertEqual(nodes[0]["source"], "a")
        self.assertEqual(summary["deduplicated"], 1)
        self.assertEqual(summary["port_filtered"], 1)
        self.assertEqual(summary["conversion_failures"], 1)
        self.assertEqual(len(failures), 1)


class FinalizeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="singbox-finalize-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _candidates(self, nodes):
        payload = {
            "schema": 1,
            "generated_at": "2026-01-01T00:00:00Z",
            "core": {
                "schema": 1,
                "name": "sing-box",
                "repository": "SagerNet/sing-box",
                "version": "1.14.4",
                "revision": "test",
                "binary_sha256": "a" * 64,
                "binary_bytes": 1,
                "source": "test",
            },
            "candidate_total": len(nodes),
            "protocol_counts": {},
            "normalization": {"conversion_failures": 2},
            "conversion_failures": [],
            "source_freshness": {"schema": 2, "sources_checked": 2},
            "sources": [{"name": "fixture", "ok": True, "nodes": len(nodes)}],
            "nodes": nodes,
        }
        path = self.root / "candidates.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path, runner.digest(path)

    @staticmethod
    def _node(index, protocol, identity, country="US"):
        return {
            "index": index,
            "uri": f"{protocol}://fixture-{index}",
            "protocol": protocol,
            "host": "example.com",
            "port": 443,
            "remark": "",
            "source": "fixture",
            "outbound_identity": identity,
        }

    def test_publishes_speed_then_delay_order(self):
        nodes = [
            self._node(0, "vless", "id-0"),
            self._node(1, "vless", "id-1"),
            self._node(2, "trojan", "id-2", "DE"),
            self._node(3, "vmess", "id-3"),
        ]
        candidates, digest = self._candidates(nodes)
        (self.root / "cache").mkdir()
        (self.root / "cache" / "freeproxydb_cache.json").write_text("{}\n", encoding="utf-8")
        core_manifest = json.loads(candidates.read_text(encoding="utf-8"))["core"]
        results = self.root / "results"
        shard0 = results / "shard-0"
        shard1 = results / "shard-1"
        shard0.mkdir(parents=True)
        shard1.mkdir(parents=True)
        working0 = [
            {"index": 0, "protocol": "vless", "shard": 0, "raw": nodes[0]["uri"],
             "outbound_identity": "id-0", "delay_ms": 200, "success_target": "cloudflare",
             "country": "US", "speed": {"status": "MEASURED", "bytes": 1048576, "bits_per_second": 1000.0}},
            {"index": 2, "protocol": "trojan", "shard": 0, "raw": nodes[2]["uri"],
             "outbound_identity": "id-2", "delay_ms": 300, "success_target": "cloudflare",
             "country": "DE", "speed": {"status": "MEASURED", "bytes": 1048576, "bits_per_second": 2000.0}},
        ]
        working1 = [
            {"index": 1, "protocol": "vless", "shard": 1, "raw": nodes[1]["uri"],
             "outbound_identity": "id-1", "delay_ms": 100, "success_target": "google",
             "country": "US", "speed": None},
        ]
        (shard0 / "working.jsonl").write_text("".join(json.dumps(row) + "\n" for row in working0), encoding="utf-8")
        (shard1 / "working.jsonl").write_text("".join(json.dumps(row) + "\n" for row in working1), encoding="utf-8")
        (shard1 / "failed.jsonl").write_text(json.dumps({"index": 3, "protocol": "vmess", "stage": "timeout"}) + "\n", encoding="utf-8")
        (shard0 / "failed.jsonl").write_text("", encoding="utf-8")
        summaries = [
            (0, {"vless": (1, 1), "trojan": (1, 1), "vmess": (0, 0)}, {"vless": {"cloudflare": 1}, "trojan": {"cloudflare": 1}}),
            (1, {"vless": (1, 1), "vmess": (1, 0), "trojan": (0, 0)}, {"vless": {"google": 1}}),
        ]
        for shard, counts, targets in summaries:
            protocols = {}
            for protocol in ("vless", "vmess", "trojan", "shadowsocks"):
                assigned, working = counts.get(protocol, (0, 0))
                protocols[protocol] = {
                    "assigned": assigned,
                    "tested": assigned,
                    "working": working,
                    "failed": assigned - working,
                    "success_targets": targets.get(protocol, {}),
                    "failure_stages": {},
                }
            payload = {
                "schema": 2,
                "shard": shard,
                "shards": 2,
                "workers": 2,
                "candidate_total": 4,
                "candidates_sha256": digest,
                "core": core_manifest,
                "protocols": protocols,
            }
            (results / f"shard-{shard}" / "summary.json").write_text(json.dumps(payload), encoding="utf-8")

        output = self.root / "output"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "singbox_pipeline" / "finalize.py"),
             "--candidates", str(candidates), "--results-root", str(results),
             "--output-root", str(output), "--shards", "2"],
            capture_output=True, text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        us = (output / "countries" / "US.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(us, [nodes[0]["uri"], nodes[1]["uri"]])
        self.assertEqual((output / "countries" / "DE.txt").read_text(encoding="utf-8").splitlines(), [nodes[2]["uri"]])
        self.assertEqual((output / "protocols" / "vless.txt").read_text(encoding="utf-8").splitlines(),
                         [nodes[0]["uri"], nodes[1]["uri"]])
        app_pool = json.loads((output / "metadata" / "app_pool.json").read_text(encoding="utf-8"))
        self.assertEqual(app_pool["mode"], "singbox_https_verified")
        self.assertEqual(app_pool["published_total"], 3)
        self.assertEqual(app_pool["duplicates_removed_after_singbox"], 0)
        self.assertEqual(app_pool["speed_ranking"]["measured"], 2)
        self.assertEqual((output / "country_shards" / "US" / "000.txt").is_file(), True)
        self.assertEqual((output / "metadata" / "freeproxydb_cache.json").read_text(encoding="utf-8"), "{}\n")


@unittest.skipUnless(SINGBOX, "SINGBOX_BINARY is not set")
class IntegrationTests(unittest.TestCase):
    def test_probe_through_local_shadowsocks_server(self):
        binary = Path(SINGBOX)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/speed"):
                    chunk = b"x" * 65536
                    self.send_response(200)
                    self.send_header("Content-Length", str(probe.SAMPLE_BYTES))
                    self.end_headers()
                    for _ in range(probe.SAMPLE_BYTES // len(chunk)):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        time.sleep(0.005)
                    return
                body = b"local-ok\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        http_port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            ss_port = sock.getsockname()[1]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            probe_port = sock.getsockname()[1]

        server_config = {
            "log": {"level": "error"},
            "inbounds": [{"type": "shadowsocks", "tag": "in", "listen": "127.0.0.1",
                          "listen_port": ss_port, "method": "aes-128-gcm", "password": "test-password"}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
        }
        with tempfile.TemporaryDirectory(prefix="singbox-integration-") as directory:
            config_path = Path(directory) / "server.json"
            config.write_config(config_path, server_config)
            server = subprocess.Popen([str(binary), "run", "-c", str(config_path)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", ss_port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                original = probe.TARGETS
                original_speed = probe.SPEED_URL
                probe.TARGETS = (("local", f"http://127.0.0.1:{http_port}/", frozenset({200})),)
                probe.SPEED_URL = f"http://127.0.0.1:{http_port}/speed"
                try:
                    result = probe.probe_link(binary, ss_link("aes-128-gcm", "test-password", "127.0.0.1", ss_port),
                                              probe_port, timeout=15, measure_speed=True)
                finally:
                    probe.TARGETS = original
                    probe.SPEED_URL = original_speed
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["http_status"], 200)
                self.assertEqual(result["success_target"], "local")
                self.assertEqual(result["protocol"], "shadowsocks")
                self.assertEqual(result["speed"]["status"], "MEASURED")
                self.assertGreaterEqual(result["speed"]["bytes"], probe.SAMPLE_BYTES)
                self.assertGreater(result["speed"]["bits_per_second"], 0)
            finally:
                server.terminate()
                server.wait(timeout=5)
                httpd.shutdown()
                httpd.server_close()


class CoreManifestTests(unittest.TestCase):
    @unittest.skipUnless(SINGBOX, "SINGBOX_BINARY is not set")
    def test_manifest_pins_binary_and_version(self):
        manifest = core.read_manifest(Path(SINGBOX))
        self.assertEqual(manifest["name"], "sing-box")
        self.assertRegex(manifest["version"], r"^\d+\.\d+\.\d+")
        self.assertEqual(core.validate_manifest(manifest, Path(SINGBOX)), manifest)
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "fake"
            fake.write_bytes(b"not-sing-box")
            with self.assertRaises(ValueError):
                core.validate_manifest(manifest, fake)


if __name__ == "__main__":
    unittest.main()
