"""Offline collector regression fixtures. No source downloads or node probes."""
import base64
import html
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_sources_candidates as builder
import build_telegram_candidates as telegram
import clashxw_daily_adapter as clashxw
import outlinekeys_adapter as outline
from share_link_extractor import extract_uri_records
import update_catalog as catalog
import v2nodes_adapter as v2nodes

BASE = "vless://11111111-1111-1111-1111-111111111111@example.invalid:443"
OTHER = "trojan://secret@other.invalid:443?security=tls#other"
COMPLEX = BASE + '?type=xhttp&extra={"headers":{"X-Test":"a,b"},"xmux":{"maxConcurrency":4},"downloadSettings":null}&alpn=h2,http/1.1#full'


class ShareLinkTests(unittest.TestCase):
    def uris(self, text, **kwargs):
        return [item.uri for item in extract_uri_records(text, **kwargs)]

    def test_nested_json_commas_and_following_settings_are_complete(self):
        self.assertEqual(self.uris(COMPLEX), [COMPLEX])
        row, = catalog.parse_lines(COMPLEX, "fixture")
        self.assertEqual(row["uri"], COMPLEX)
        self.assertEqual(row["original_uri"], COMPLEX)

    def test_finalmask_and_escaped_quotes_are_not_truncated(self):
        uri = BASE + '?fm={"tcp":[{"type":"fragment","settings":{"note":"a,\\\"b\\\"","size":[1,2]}}]}&security=tls'
        self.assertEqual(self.uris(uri), [uri])

    def test_json_string_wrapper_is_decoded_and_original_is_saved(self):
        wrapped = json.dumps({"url": COMPLEX})
        row, = catalog.parse_lines(wrapped, "json")
        self.assertEqual(row["uri"], COMPLEX)
        self.assertEqual(row["original_uri"], json.dumps(COMPLEX)[1:-1])

    def test_json_escaped_slashes_and_unicode_are_supported(self):
        wrapped = json.dumps(BASE + "?security=tls#اختبار").replace("/", "\\/")
        self.assertEqual(self.uris(wrapped), [BASE + "?security=tls#اختبار"])

    def test_json_wrapper_control_bytes_cannot_create_extra_input_lines(self):
        uri = BASE + "?path=/a\nb&security=tls"
        self.assertEqual(self.uris(json.dumps(uri)), [uri.replace("\n", "%0A")])

    def test_html_attribute_entities_restore_full_json(self):
        escaped = html.escape(COMPLEX, quote=True)
        row, = catalog.parse_lines(f'<a href="{escaped}">copy</a>', "html")
        self.assertEqual(row["uri"], COMPLEX)
        self.assertEqual(row["original_uri"], escaped)

    def test_html_text_entities_restore_full_json(self):
        escaped = html.escape(COMPLEX, quote=True)
        row, = catalog.parse_lines(f"<pre>{escaped}</pre>", "html")
        self.assertEqual(row["uri"], COMPLEX)
        self.assertEqual(row["original_uri"], escaped)

    def test_script_json_is_not_html_entity_decoded(self):
        literal = BASE + "?path=/literal&amp;name&security=tls"
        row, = catalog.parse_lines(f"<script>const link = {json.dumps(literal)};</script>", "js")
        self.assertEqual(row["uri"], literal)

    def test_adjacent_and_comma_separated_nodes_remain_separate(self):
        for text in (BASE + OTHER, BASE + "," + OTHER, COMPLEX + OTHER):
            with self.subTest(text=text):
                self.assertEqual(self.uris(text), [COMPLEX if text.startswith(COMPLEX) else BASE, OTHER])

    def test_unclosed_json_preserves_bytes_without_hiding_next_line(self):
        broken = BASE + '?fm={"tcp":[{"type":"fragment"'
        records = extract_uri_records(broken + "\n" + OTHER)
        self.assertEqual([item.uri for item in records], [broken, OTHER])
        self.assertEqual(records[0].original_uri, broken)

    def test_unclosed_json_does_not_hide_another_node_on_same_line(self):
        broken = BASE + '?fm={"broken":"unterminated '
        self.assertEqual(self.uris(broken + OTHER), [broken, OTHER])

    def test_placeholders_bad_json_and_conflicting_settings_are_not_repaired(self):
        for suffix in ('?fm=tlshello-0-len', '?fm={"x":}', '?security=tls&security=reality', '?x={"a":1]'):
            uri = BASE + suffix
            self.assertEqual(self.uris(uri), [uri])

    def test_all_existing_protocol_shapes_preserve_uri_bytes(self):
        vmess = "vmess://" + base64.b64encode(json.dumps({"add": "vm.invalid", "port": "443", "id": "id"}).encode()).decode()
        uris = [BASE + "?security=tls&type=ws&path=%2Fws#old", OTHER,
                "ss://YWVzLTI1Ni1nY206cGFzcw@ss.invalid:443#ss", vmess,
                "VMESS://id@modern.invalid:443?security=tls&type=ws#modern"]
        # Compare with the previous literal regex on already complete inputs.
        for uri in uris:
            self.assertEqual(catalog.URI_RE.findall(uri), [uri])
            self.assertEqual(self.uris(uri), [uri])
            self.assertEqual([row["uri"] for row in catalog.parse_lines(uri, "old")], [uri])

    def test_base64_subscription_still_preserves_complete_nodes(self):
        text = COMPLEX + "\n" + OTHER
        encoded = base64.b64encode(text.encode()).decode()
        self.assertEqual([row["uri"] for row in catalog.parse_lines(encoded, "base64")], [COMPLEX, OTHER])

    def test_adapter_provenance_is_not_reimported_as_an_extra_node(self):
        escaped = html.escape(COMPLEX, quote=True)
        item, = extract_uri_records(f'<a href="{escaped}">copy</a>')
        rows = builder.normalize_adapter_rows([{"url": item.uri, **item.source_fields()}], "adapter")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["original_uri"], escaped)

    def test_adapter_nested_links_survive_provenance_metadata(self):
        rows = builder.normalize_adapter_rows([{
            "url": COMPLEX, "original_uri": COMPLEX, "uri_encoding": "literal",
            "metadata": {"links": [OTHER]},
        }], "adapter")
        self.assertEqual([row["uri"] for row in rows], [COMPLEX, OTHER])

    def test_same_uri_bytes_with_different_wrapper_meanings_are_not_collapsed(self):
        uri = BASE + "?path=/literal&amp;name&security=tls"
        rows = builder.normalize_adapter_rows([
            {"url": uri, "original_uri": uri, "uri_encoding": "literal"},
            {"url": uri},
        ], "adapter")
        self.assertEqual(len(rows), 2)

    def test_plain_json_containing_markup_is_not_treated_as_html(self):
        uri = BASE + '?extra={"headers":{"X-Label":"<span>value</span>"}}'
        self.assertEqual(self.uris(uri), [uri])

    def test_telegram_actual_collector_does_not_pretruncate(self):
        escaped = html.escape(COMPLEX, quote=True)
        with patch.object(telegram, "telegram_page", return_value=f"<pre>{escaped}</pre>"):
            rows = telegram.collect_channel("fixture", 1, 10)
        self.assertEqual([row["uri"] for row in rows], [COMPLEX])
        self.assertEqual(rows[0]["original_uri"], escaped)

    def test_v2nodes_actual_page_path_preserves_source(self):
        escaped = html.escape(COMPLEX, quote=True)
        with patch.object(v2nodes, "fetch", return_value=f'<a href="{escaped}">copy</a>'):
            _, records, error = v2nodes.process_page("https://fixture.invalid/", 1, 1, True)
        self.assertIsNone(error)
        rows = catalog.parse_uri_records(records, "v2nodes")
        self.assertEqual(rows[0]["uri"], COMPLEX)
        self.assertEqual(rows[0]["original_uri"], escaped)
        self.assertEqual(v2nodes.extract_uris(f"<p>{escaped}</p>"), [COMPLEX])
        self.assertEqual(v2nodes.extract_uris("<p>ssconf://legacy.invalid/key</p>"), ["ssconf://legacy.invalid/key"])
        self.assertEqual(v2nodes.extract_uris(f"<p>{BASE}?security=tls);</p>"), [BASE + "?security=tls"])

    def test_v2nodes_retry_keeps_original_records_and_legacy_return_type(self):
        escaped = html.escape(COMPLEX, quote=True)
        for preserve in (False, True):
            retried = []

            def fetch(url, **kwargs):
                if url == v2nodes.BASE:
                    return "<html>listing</html>"
                if url == "good":
                    return f"<pre>{escaped}</pre>"
                if not retried:
                    retried.append(url)
                    raise v2nodes.requests.Timeout("fixture")
                return f"<pre>{OTHER}</pre>"

            with patch.object(v2nodes, "fetch", side_effect=fetch), patch.object(v2nodes, "discover_server_urls", return_value=["good", "retry"]):
                result = v2nodes.collect(max_pages=2, preserve_original=preserve)
            self.assertEqual([item.uri if preserve else item for item in result], [COMPLEX, OTHER])
            if preserve:
                self.assertEqual(result[0].original_uri, escaped)
            else:
                self.assertTrue(all(isinstance(item, str) for item in result))

    def test_outline_and_clashxw_helpers_keep_complete_data(self):
        self.assertEqual(outline.extract_uri(f"<pre>{html.escape(COMPLEX)}</pre>"), COMPLEX)
        rows = clashxw.extract_nodes(COMPLEX)
        self.assertEqual([row["url"] for row in rows], [COMPLEX])
        normalized = builder.normalize_adapter_rows(rows, "clashxw")
        self.assertEqual(normalized[0]["uri"], COMPLEX)

    def test_source_comments_bad_endpoint_and_port_policy_are_unchanged(self):
        bad = "vless://u@[1.2.3.4]:443"
        text = "# " + BASE + "\n// " + BASE + "\n" + bad + "\n" + BASE.replace(":443", ":8443") + "\n" + OTHER
        self.assertEqual([row["uri"] for row in catalog.parse_lines(text, "mixed")], [OTHER])


if __name__ == "__main__":
    unittest.main()
