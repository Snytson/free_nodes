from __future__ import annotations

from urllib.parse import urlparse


def gitverse_fallback_urls(item: dict) -> list[str]:
    """Return validated GitVerse raw URLs configured as source fallbacks."""
    raw_urls = item.get("gitverse_fallback_urls", [])
    if raw_urls is None:
        return []
    if not isinstance(raw_urls, list):
        raise ValueError("gitverse_fallback_urls must be a list")

    urls: list[str] = []
    for raw_url in raw_urls:
        if not isinstance(raw_url, str) or not raw_url.strip():
            raise ValueError("GitVerse fallback URL must be a non-empty string")
        url = raw_url.strip()
        parsed = urlparse(url)
        path = parsed.path
        if (
            parsed.scheme != "https"
            or (parsed.hostname or "").lower() != "gitverse.ru"
            or not path.startswith("/api/repos/")
            or "/raw/branch/" not in path
        ):
            raise ValueError(f"unsupported GitVerse raw URL: {url}")
        if url not in urls:
            urls.append(url)
    return urls
