"""Validate an owner-requested publication-only recovery, without testing nodes."""
from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

BRANCH = os.environ.get("CATALOG_BRANCH", "main")


def validate(run: dict, jobs: list[dict], repository: str) -> str:
    if (run.get("status") != "completed" or run.get("conclusion") not in {"failure", "success"}
            or run.get("head_branch") != BRANCH or run.get("path") != ".github/workflows/update.yml"
            or (run.get("head_repository") or {}).get("full_name") != repository
            or not re.fullmatch(r"[0-9a-f]{40}", str(run.get("head_sha", "")))):
        raise ValueError(f"Source must be a completed catalog run on this repository's {BRANCH}")
    required = {"Collect candidates and pin sing-box",
                *(f"Probe shard ({i})" for i in range(8))}
    counts = {name: sum(j.get("name") == name and j.get("conclusion") == "success" for j in jobs)
              for name in required}
    if any(count != 1 for count in counts.values()):
        raise ValueError("Source run is missing a successful collection or probe shard")
    return run["head_sha"]


def main() -> None:
    source = os.environ["CATALOG_SOURCE_RUN_ID"]
    if not re.fullmatch(r"[1-9][0-9]*", source) or source == os.environ["GITHUB_RUN_ID"]:
        raise SystemExit("Expected a different, numeric source run ID")
    repository = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GH_TOKEN"]

    def api(path):
        request = urllib.request.Request("https://api.github.com/repos/" + repository + path,
                                         headers={"Authorization": "Bearer " + token,
                                                  "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    run = api(f"/actions/runs/{source}")
    jobs = api(f"/actions/runs/{source}/jobs?filter=latest&per_page=100")
    sha = validate(run, jobs["jobs"], repository)
    repo = Path(__file__).resolve().parents[1]
    subprocess.run(["git", "fetch", "origin", sha], cwd=repo, check=True)
    # Geo updates and publication repairs are allowed. A newer catalog or changed
    # finalizer/signing contract needs explicit review instead of a stale replay.
    for paths in (("output",), ("scripts/singbox_pipeline",
                                "scripts/country_resolver.py", "scripts/sign_catalog.py",
                                "data/catalog_signing_public_key.pem")):
        subprocess.run(["git", "diff", "--quiet", sha, "HEAD", "--", *paths], cwd=repo, check=True)
    print(f"Validated publication-only recovery from run {source}, source {sha}")


if __name__ == "__main__":
    main()
