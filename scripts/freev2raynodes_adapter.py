#!/usr/bin/env python3
"""Dynamic resolver for freev2raynodes GitHub Pages subscriptions.

Produces candidate subscription URLs without hard-coding a single date.
"""
from __future__ import annotations

from datetime import datetime, timedelta

BASE = "https://freev2raynodes.github.io"


def candidate_urls(days_back: int = 14):
    now = datetime.utcnow()
    for offset in range(days_back + 1):
        day = now - timedelta(days=offset)
        stamp = day.strftime("%Y%m%d")
        folder = day.strftime("%Y/%m")
        for index in range(5):
            yield f"{BASE}/uploads/{folder}/{index}-{stamp}.txt"
            yield f"{BASE}/uploads/{folder}/{index}-{stamp}.yaml"
        yield f"{BASE}/uploads/{folder}/{stamp}.json"


if __name__ == "__main__":
    for url in candidate_urls():
        print(url)
