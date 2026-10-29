#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from share_link_extractor import ExtractedURI, extract_uri_records

BASE = "https://www.v2nodes.com/"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151 Safari/537.36"

URI_RE = re.compile(
    r'(?P<uri>(?:vless|vmess|trojan|ss|ssconf)://[^\s<>"\'`]+)',
    re.IGNORECASE,
)

thread_local = threading.local()


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def get_session() -> requests.Session:
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml",
        })
        # Explicit retry/backoff below owns retry behavior. Keep urllib3 from
        # silently multiplying requests when v2nodes is under load.
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=4,
            pool_maxsize=4,
            max_retries=0,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        thread_local.session = session
    return session


def is_retryable_error(exc: Exception) -> bool:
    if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
        return True
    if isinstance(exc, requests.HTTPError):
        response = exc.response
        status = response.status_code if response is not None else 0
        return status == 429 or 500 <= status < 600
    return False


def fetch(url: str, timeout: float = 25, attempts: int = 3) -> str:
    last_error: Exception | None = None
    backoff = (1.0, 3.0, 6.0)
    for attempt in range(1, max(1, attempts) + 1):
        try:
            r = get_session().get(
                url,
                timeout=timeout,
                headers={"Referer": BASE},
            )
            r.raise_for_status()
            return r.text
        except Exception as exc:
            last_error = exc
            if attempt >= attempts or not is_retryable_error(exc):
                break
            time.sleep(backoff[min(attempt - 1, len(backoff) - 1)])
    assert last_error is not None
    raise last_error


def discover_server_urls(html: str, limit: int, start_url: str) -> list[str]:
    """Collect every /servers/ URL visible in the site's crawled listing pages."""
    seen_servers: set[str] = set()
    servers: list[str] = []
    listings: list[str] = [start_url]
    seen_listings: set[str] = {start_url}

    def add_server(href: str) -> None:
        url = urljoin(BASE, href)
        if "/servers/" in url and url not in seen_servers:
            seen_servers.add(url)
            servers.append(url)

    def add_listing(href: str) -> None:
        url = urljoin(BASE, href)
        if url.startswith(BASE) and "/servers/" not in url and url not in seen_listings:
            seen_listings.add(url)
            listings.append(url)

    soup = BeautifulSoup(html, "html.parser")
    for a in soup.select("a[href]"):
        href = a.get("href")
        if not href:
            continue
        if "/servers/" in href:
            add_server(href)
        else:
            url = urljoin(start_url, href)
            if url.startswith(BASE):
                add_listing(href)
        if len(servers) >= limit:
            return servers[:limit]

    index = 0
    while index < len(listings) and len(servers) < limit:
        listing_url = listings[index]
        index += 1
        if listing_url == start_url:
            page_html = html
        else:
            try:
                page_html = fetch(listing_url)
            except Exception:
                continue

        page_soup = BeautifulSoup(page_html, "html.parser")
        for a in page_soup.select("a[href]"):
            href = a.get("href")
            if not href:
                continue
            if "/servers/" in href:
                add_server(href)
                if len(servers) >= limit:
                    break
            else:
                url = urljoin(listing_url, href)
                if url.startswith(BASE):
                    add_listing(href)

    return servers[:limit]


def extract_uris(html: str) -> list[str]:
    return list(dict.fromkeys(item.uri for item in _page_records(html)))


def _page_records(html: str) -> list[ExtractedURI]:
    records = extract_uri_records(html, html_source=True)
    # Keep the existing page-punctuation cleanup for its original simple-link
    # path. Structured query values must retain their closing braces/brackets.
    return [item if item.structured else ExtractedURI(
        item.uri.rstrip("),.;]}>'\""), item.original_uri, item.literal)
        for item in records]


def process_page(url: str, timeout: float, attempts: int, preserve_original: bool = False):
    try:
        page = fetch(url, timeout=timeout, attempts=attempts)
        found = _page_records(page) if preserve_original else extract_uris(page)
        return url, found, None
    except Exception as exc:
        return url, [], exc


def collect(start_url: str = BASE, max_pages: int = 5000, *, preserve_original: bool = False):
    """Collect proxy URIs while retrying transient v2nodes failures gently."""
    primary_workers = env_int("V2NODES_WORKERS", 80, 1, 150)
    retry_workers = env_int("V2NODES_RETRY_WORKERS", 20, 1, 50)
    primary_timeout = env_float("V2NODES_TIMEOUT", 25.0, 5.0, 60.0)
    retry_timeout = env_float("V2NODES_RETRY_TIMEOUT", 30.0, 5.0, 90.0)

    start_html = fetch(start_url, timeout=primary_timeout, attempts=3)
    pages = discover_server_urls(start_html, max_pages, start_url)

    nodes: list[str | ExtractedURI] = []
    seen: set[str] = set()
    retry_urls: list[str] = []

    def add_found(found) -> int:
        new = 0
        for uri in found:
            identity = uri.uri if isinstance(uri, ExtractedURI) else uri
            if identity not in seen:
                seen.add(identity)
                nodes.append(uri)
                new += 1
        return new

    print(
        f"INFO v2nodes pages={len(pages)} primary_workers={primary_workers} "
        f"retry_workers={retry_workers} primary_timeout_s={primary_timeout} retry_timeout_s={retry_timeout}"
    )

    # First pass: one request per page. Failed transient pages are deferred
    # instead of retrying immediately while the site is already saturated.
    with ThreadPoolExecutor(max_workers=primary_workers) as pool:
        futures = [pool.submit(process_page, url, primary_timeout, 1, preserve_original) for url in pages]

        for completed, future in enumerate(as_completed(futures), 1):
            url, found, error = future.result()

            if error is not None:
                if is_retryable_error(error):
                    retry_urls.append(url)
                    print(f"[{completed}/{len(pages)}] RETRY-LATER {url}: {error}")
                else:
                    print(f"[{completed}/{len(pages)}] ERROR {url}: {error}")
                continue

            new = add_found(found)
            print(f"[{completed}/{len(pages)}] {new} new node(s) <- {url}")

    recovered_pages = 0
    if retry_urls:
        print(f"INFO v2nodes second_pass={len(retry_urls)} workers={retry_workers} attempts=3")
        with ThreadPoolExecutor(max_workers=retry_workers) as pool:
            futures = [pool.submit(process_page, url, retry_timeout, 3, preserve_original) for url in retry_urls]

            for completed, future in enumerate(as_completed(futures), 1):
                url, found, error = future.result()
                if error is not None:
                    print(f"[retry {completed}/{len(retry_urls)}] ERROR {url}: {error}")
                    continue
                recovered_pages += 1
                new = add_found(found)
                print(f"[retry {completed}/{len(retry_urls)}] {new} new node(s) <- {url}")

    print(
        f"INFO v2nodes retry_summary queued={len(retry_urls)} "
        f"recovered_pages={recovered_pages} remaining_failed={len(retry_urls) - recovered_pages}"
    )
    return nodes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-pages", type=int, default=5000)
    parser.add_argument("--output", default="v2nodes_nodes.txt")
    args = parser.parse_args()

    print(f"[+] Fetching {BASE}")
    try:
        nodes = collect(start_url=BASE, max_pages=args.max_pages)
    except Exception as exc:
        print(f"[!] Start page failed: {exc}", file=sys.stderr)
        return 1

    output = Path(args.output)
    output.write_text(
        "\n".join(nodes) + ("\n" if nodes else ""),
        encoding="utf-8",
    )

    print(f"\n[+] Unique nodes: {len(nodes)}")
    print(f"[+] Saved to: {output.resolve()}")

    if not nodes:
        print("[!] No proxy URI found in the pages.")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
