"""Extract complete share links without interpreting their connection settings.

Only HTML containers and valid JSON string containers are unwrapped. JSON in a
query value is kept verbatim, including quotes, commas and nested objects. No
missing bytes, settings, or closing braces are supplied for malformed input.
"""
from __future__ import annotations

from dataclasses import dataclass
import html
from html.parser import HTMLParser
import json
import re


START = re.compile(r"(?:vless|vmess|trojan|ss|ssconf):(?:/{2}|\\/\\/)", re.I)
HTML_TAG = re.compile(r"</?(?:html|head|body|a|pre|code|div|span|p|br|textarea|script)\b", re.I)
ENTITY = re.compile(r"&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);")
ENTITY_SOURCE = re.compile(r"&[#A-Za-z0-9]+;?")
DECODER = json.JSONDecoder()


@dataclass(frozen=True)
class ExtractedURI:
    uri: str
    original_uri: str
    literal: bool = False
    structured: bool = False

    def source_fields(self) -> dict:
        result = {"original_uri": self.original_uri}
        if self.literal:
            # Prevent a second HTML decode after a proven wrapper was removed.
            result["uri_encoding"] = "literal"
        return result


def _character(text: str, index: int, html_encoded: bool) -> tuple[str, int]:
    if html_encoded and text[index] == "&":
        match = ENTITY.match(text, index)
        if match:
            decoded = html.unescape(match.group())
            if len(decoded) == 1:
                return decoded, match.end()
    return text[index], index + 1


def _json_end(text: str, start: int, html_encoded: bool) -> int:
    """Keep even malformed JSON intact, but never consume a following line/node."""
    stack: list[str] = []
    quoted = escaped = False
    index = start
    while index < len(text):
        if text[index] in "\r\n" or (not quoted and index > start and START.match(text, index)):
            return index
        char, end = _character(text, index, html_encoded)
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "{[":
            stack.append(char)
        elif char in "}]":
            if not stack or (stack[-1], char) not in (("{", "}"), ("[", "]")):
                return end
            stack.pop()
            if not stack:
                return end
        elif char in "<>" and not html_encoded:
            return index
        index = end
    return index


def _uri_end(text: str, start: int, html_encoded: bool) -> tuple[int, bool]:
    index = START.match(text, start).end()
    query = structured = False
    value_start = False
    while index < len(text):
        if index > start and START.match(text, index):
            break
        char, end = _character(text, index, html_encoded)
        if value_start and char in "{[":
            json_end = _json_end(text, index, html_encoded)
            value = text[index:json_end]
            try:
                json.loads(html.unescape(value) if html_encoded else value)
            except (ValueError, RecursionError):
                # Do not let an unterminated JSON string hide another node on
                # the same line. Complete JSON strings can contain URI text.
                following = START.search(text, index + 1, json_end)
                if following:
                    return following.start(), True
            index = json_end
            structured = True
            value_start = False
            continue
        if text[index].isspace() or text[index] in "\"'<>`":
            break
        # A comma between two concatenated links is a list separator. Commas
        # inside ALPN, paths, credentials and JSON are connection data.
        if char == "," and START.match(text, end):
            break
        if char == "?":
            query = True
        elif char == "#":
            query = False
        value_start = query and char == "="
        index = end
    return index, structured


def _scan(text: str, *, html_encoded: bool = False) -> list[ExtractedURI]:
    found: list[ExtractedURI] = []
    offset = 0
    while match := START.search(text, offset):
        start = match.start()
        # Decode an actual JSON string, never a guessed JavaScript expression.
        if start and text[start - 1] == '"':
            try:
                value, end = DECODER.raw_decode(text, start - 1)
            except (ValueError, RecursionError):
                value = None
            if isinstance(value, str):
                value = value.replace("\r", "%0D").replace("\n", "%0A").replace("\t", "%09")
                nested = _scan(value, html_encoded=html_encoded)
                original = text[start:end - 1]
                found.extend(ExtractedURI(item.uri, original, True, item.structured) for item in nested)
                offset = end
                continue
        end, structured = _uri_end(text, start, html_encoded)
        raw = text[start:end]
        uri = html.unescape(raw) if html_encoded else raw
        # A decoded JSON string may contain escaped control characters. Encode
        # these bytes so one source record remains one nodecheck input line.
        uri = uri.replace("\r", "%0D").replace("\n", "%0A").replace("\t", "%09")
        found.append(ExtractedURI(uri, raw, html_encoded or structured, structured))
        offset = max(end, match.end())
    return found


class _HTMLLinks(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self.source = text
        self.lines = [0]
        self.lines.extend(match.end() for match in re.finditer("\n", text))
        self.pending: list[str] = []
        self.records: list[ExtractedURI] = []
        self.raw_text = False

    def flush(self) -> None:
        self.records.extend(_scan("".join(self.pending), html_encoded=not self.raw_text))
        self.pending.clear()

    def handle_data(self, data: str) -> None:
        self.pending.append(data)

    def _entity(self) -> None:
        line, column = self.getpos()
        start = self.lines[line - 1] + column
        match = ENTITY_SOURCE.match(self.source, start)
        if match:
            self.pending.append(match.group())

    def handle_entityref(self, name: str) -> None:
        self._entity()

    def handle_charref(self, name: str) -> None:
        self._entity()

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self.flush()
        self.records.extend(_scan(self.get_starttag_text(), html_encoded=True))
        self.raw_text = tag in {"script", "style"}

    def handle_startendtag(self, tag: str, attrs: list) -> None:
        self.handle_starttag(tag, attrs)
        self.raw_text = False

    def handle_endtag(self, tag: str) -> None:
        self.flush()
        if tag in {"script", "style"}:
            self.raw_text = False

    def handle_comment(self, data: str) -> None:
        self.flush()
        self.records.extend(_scan(data))


def extract_uri_records(text: str, *, html_source: bool | None = None) -> list[ExtractedURI]:
    if html_source is None:
        tag = HTML_TAG.search(text)
        uri = START.search(text)
        # Markup inside a plain URI/JSON setting is connection data, not proof
        # that the entire subscription is an HTML page.
        html_source = bool(tag and (not uri or tag.start() < uri.start()))
    if not html_source:
        return _scan(text)
    parser = _HTMLLinks(text)
    parser.feed(text)
    parser.close()
    parser.flush()
    return parser.records
