#!/usr/bin/env python3
"""Discover subscription sources on GitHub and merge them into sources/sources.json.

Search repositories for a keyword, ordered by most recently updated, then inspect each
repository tree for subscription files: raw node lists, base64 node lists, Clash YAML,
or files that publish subscription addresses. Every discovered URL is deduplicated
against the existing catalog before it is appended.

Usage:
    GITHUB_TOKEN=... python scripts/discover_github_sources.py --limit 300
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources" / "sources.json"
LEDGER = ROOT / "output" / "metadata" / "source_health.json"
API = "https://api.github.com"

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import source_health  # noqa: E402

NODE_URI = re.compile(r"(?:vmess|vless|trojan|ss)://[^\s\"'<>]+", re.I)
CLASH_MARK = re.compile(r"^proxies:\s*$", re.M)
CLASH_TYPE = re.compile(r"^\s*-\s*\{?\s*type:\s*(vless|vmess|trojan|ss|shadowsocks)\b", re.M | re.I)
CANDIDATE_PATH = re.compile(
    r"(sub|subscribe|subscription|v2ray|vmess|vless|trojan|shadowsocks|ssr?|prox|nodes?|config|urls?|clash|mihomo|mixed|all|free)",
    re.I,
)
CANDIDATE_EXT = {".txt", ".yaml", ".yml", ".json", ".conf", ".md", ".base64", ".b64"}
SKIP_URL = re.compile(
    r"(github\.com/|gist\.github\.com|t\.me/|telegram|youtube|twitter|x\.com/|discord|"
    r"shields\.io|badge|\.png|\.jpg|\.jpeg|\.gif|\.svg|\.ico|licen[cs]e|"
    r"/issues|/pulls|/releases|/stargazers|/network|/blame|/commit/|@)",
    re.I,
)
MAX_BYTES = 2 * 1024 * 1024
PLACEHOLDER_URL = re.compile(
    r"(your[_-]?(username|repo|user|name|token|domain|host)"
    r"|example\.(com|org|net|invalid)|localhost|127\.0\.0\.1|0\.0\.0\.0"
    r"|<[^>]+>|\$\{|\{\{|\.\.\.)",
    re.I,
)
PLACEHOLDER_PATH = re.compile(r"(example|sample|template|placeholder|dummy|fake|skeleton)", re.I)


def fetch(url: str, token: str | None, *, raw: bool = False, timeout: float = 15.0,
          limit: int = MAX_BYTES) -> bytes:
    headers = {"User-Agent": "free-nodes-source-discovery"}
    if token and not raw:
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError(f"response larger than {limit} bytes")
    return body


def retry(call, attempts: int = 4, delay: float = 2.0, label: str = "request"):
    """Run ``call`` with bounded retries; GitHub often drops long responses."""
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return call()
        except Exception as exc:  # noqa: BLE001 - network layer is unreliable
            last = exc
            if attempt < attempts:
                time.sleep(delay * attempt)
    raise last  # type: ignore[misc]


def api_json(url: str, token: str | None, limit: int = 8 * 1024 * 1024,
             attempts: int = 4, delay: float = 2.0) -> dict:
    def call() -> dict:
        body = fetch(url, token, limit=limit)
        return json.loads(body.decode("utf-8", errors="replace"))

    return retry(call, attempts=attempts, delay=delay, label=url)


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url.strip())
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def looks_base64(text: str) -> bool:
    compact = "".join(text.split())
    if len(compact) < 32 or len(compact) % 4:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact))


def decode_base64(text: str) -> str:
    compact = "".join(text.split())
    compact += "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(compact).decode("utf-8", errors="replace")
        except Exception:
            continue
    return ""


def extract_urls(text: str) -> list[str]:
    urls = []
    for candidate in re.findall(r"https?://[^\s\"'<>)\]]+", text):
        candidate = candidate.rstrip(".,;:*")
        if SKIP_URL.search(candidate) or NODE_URI.match(candidate):
            continue
        if PLACEHOLDER_URL.search(candidate):
            continue
        urls.append(candidate)
    return urls


def classify(text: str) -> tuple[str, list[str]]:
    """Return (kind, payload) where kind is nodes, clash, urls or none."""
    body = text.strip()
    if not body:
        return "none", []
    if NODE_URI.search(body):
        return "nodes", NODE_URI.findall(body)
    if looks_base64(body):
        decoded = decode_base64(body)
        if decoded and NODE_URI.search(decoded):
            return "nodes", NODE_URI.findall(decoded)
    if CLASH_MARK.search(body) or CLASH_TYPE.search(body):
        return "clash", []
    urls = extract_urls(body)
    return ("urls", urls) if urls else ("none", [])


PROMISING = ("sub.txt", "sub", "subscribe", "subscription", "v2ray.txt", "vmess.txt",
             "vless.txt", "trojan.txt", "all.txt", "config.txt", "clash.yaml", "clash.yml",
             "node.txt", "nodes.txt", "proxy.txt", "urls.txt")


def score_path(path: str) -> int:
    lowered = path.lower()
    score = sum(3 for token in PROMISING if token in lowered)
    if lowered.endswith(".txt"):
        score += 1
    if lowered.endswith((".yaml", ".yml")):
        score += 1
    return score - lowered.count("/")


def candidate_paths(tree: list[dict], limit: int = 4) -> list[str]:
    scored: list[tuple[int, str]] = []
    for entry in tree:
        if entry.get("type") != "blob":
            continue
        path = str(entry.get("path") or "")
        if Path(path).suffix.lower() not in CANDIDATE_EXT:
            continue
        if int(entry.get("size") or 0) > MAX_BYTES:
            continue
        if not CANDIDATE_PATH.search(path) or PLACEHOLDER_PATH.search(path):
            continue
        scored.append((score_path(path), path))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [path for _, path in scored[:limit]]


def slug(value: str, limit: int = 48) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-")
    return cleaned[:limit] or "source"


def search_repositories(query: str, limit: int, token: str | None) -> list[dict]:
    repos: list[dict] = []
    seen: set[str] = set()
    page = 1
    while len(repos) < limit:
        per_page = min(100, limit - len(repos))
        url = (f"{API}/search/repositories?q={urllib.parse.quote(query)}"
               f"&sort=updated&order=desc&per_page={per_page}&page={page}")
        try:
            payload = api_json(url, token)
        except Exception as exc:
            print(f"WARN search page {page} failed: {exc}")
            break
        items = payload.get("items") or []
        if not items:
            break
        for item in items:
            name = str(item.get("full_name") or "")
            if name and name not in seen:
                seen.add(name)
                repos.append(item)
        page += 1
        if page > 10:
            break
    return repos[:limit]


def discover(repo: dict, token: str | None, raw_timeout: float = 10.0) -> list[dict]:
    full_name = str(repo.get("full_name") or "")
    branch = str(repo.get("default_branch") or "main")
    owner, _, name = full_name.partition("/")
    if not owner or not name:
        return []
    try:
        tree_payload = api_json(f"{API}/repos/{full_name}/git/trees/{branch}?recursive=1", token)
    except urllib.error.HTTPError as exc:
        print(f"SKIP {full_name}: tree {exc.code}")
        return []
    except Exception as exc:
        print(f"SKIP {full_name}: {exc}")
        return []

    found: list[dict] = []
    for path in candidate_paths(tree_payload.get("tree") or []):
        raw_url = (f"https://raw.githubusercontent.com/{full_name}/{branch}/"
                   f"{urllib.parse.quote(path, safe='/')}")
        text = ""
        for attempt in (1, 2):
            try:
                text = fetch(raw_url, token, raw=True, timeout=raw_timeout).decode("utf-8", errors="replace")
                break
            except Exception as exc:
                if attempt == 2:
                    print(f"SKIP {full_name}/{path}: {exc}")
                else:
                    time.sleep(1.0)
        if not text:
            continue
        kind, payload = classify(text)
        if Path(path).suffix.lower() == ".md" and kind != "urls":
            # A README with embedded links is only a pointer, never a node list.
            kind, payload = ("urls", extract_urls(text))
        if kind == "nodes":
            found.append({"name": f"gh-{slug(full_name)}-{slug(Path(path).stem)}", "url": raw_url})
        elif kind == "clash":
            found.append({"name": f"gh-{slug(full_name)}-{slug(Path(path).stem)}",
                          "url": raw_url, "format": "clash_yaml"})
        elif kind == "urls":
            for index, url in enumerate(dict.fromkeys(payload), 1):
                found.append({"name": f"gh-{slug(full_name)}-sub-{index}", "url": url})
    if found:
        print(f"OK   {full_name}: {len(found)} candidate(s)")
    return found


def merge(existing: list[dict], discovered: list[dict], cap: int,
          blocked: set[str] | None = None) -> tuple[list[dict], list[dict]]:
    seen_urls = {normalize_url(str(item.get("url") or "")).lower() for item in existing}
    seen_urls |= {str(url).strip().rstrip("/").lower() for url in blocked or ()}
    seen_names = {str(item.get("name") or "") for item in existing}
    added: list[dict] = []
    for item in discovered:
        if len(added) >= cap:
            break
        url = str(item.get("url") or "").strip()
        if not url or not url.lower().startswith(("http://", "https://")):
            continue
        if PLACEHOLDER_URL.search(url):
            continue
        key = normalize_url(url).lower()
        if key in seen_urls:
            continue
        name = str(item.get("name") or "")
        suffix = 2
        while name in seen_names:
            name = f"{item['name']}-{suffix}"
            suffix += 1
        entry = {"name": name, "url": url}
        if item.get("format"):
            entry["format"] = item["format"]
        seen_urls.add(key)
        seen_names.add(name)
        added.append(entry)
    return existing + added, added


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", default="v2ray")
    parser.add_argument("--limit", type=int, default=300)
    parser.add_argument("--cap", type=int, default=300, help="maximum new sources to add")
    parser.add_argument("--sources", type=Path, default=SOURCES)
    parser.add_argument("--health-ledger", type=Path, default=LEDGER)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--max-seconds", type=int, default=2700, help="wall-clock budget")
    parser.add_argument("--raw-timeout", type=float, default=10.0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    started = time.monotonic()
    token = args.token.strip() or None
    if not token:
        print("WARN no GITHUB_TOKEN: unauthenticated API allows only 60 core requests/hour")

    catalog = json.loads(args.sources.read_text(encoding="utf-8"))
    existing = catalog.get("sources") or []
    repos = search_repositories(args.query, args.limit, token)
    print(f"repos={len(repos)} query={args.query}")

    discovered: list[dict] = []
    for index, repo in enumerate(repos, 1):
        if time.monotonic() - started > args.max_seconds:
            print(f"STOP budget exhausted after {index - 1} repositories")
            break
        discovered.extend(discover(repo, token, args.raw_timeout))
        if index % 10 == 0:
            print(f"progress {index}/{len(repos)} candidates={len(discovered)} "
                  f"elapsed={int(time.monotonic() - started)}s")
        time.sleep(0.2)

    merged, added = merge(existing, discovered, args.cap,
                          blocked=source_health.blocked_urls(source_health.load_ledger(args.health_ledger)))
    print(f"discovered={len(discovered)} new={len(added)} total={len(merged)}")
    for item in added[:20]:
        print(f"  + {item['name']}: {item['url']}")
    if args.dry_run:
        print("dry run: sources.json not written")
        return 0
    if not added:
        print("no change")
        return 0
    catalog["sources"] = merged
    args.sources.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.sources}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
