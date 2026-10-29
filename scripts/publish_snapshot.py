"""Publish one generated payload while preserving the latest default-branch tree.

Catalog and GeoLite2 writers share the same compare-and-swap implementation.
The rolling-output history policy is retained; a rejected lease is never removed.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

MARKER = "[rolling-output]"
BRANCH = os.environ.get("CATALOG_BRANCH", "main")
PATHS = {"catalog": ("output",),
         "geo": ("data/GeoLite2-Country.mmdb", "data/GEOLITE2_SOURCE.md")}


def git(repo: Path, *args: str, env=None, data=None, check=True):
    result = subprocess.run(["git", "-C", str(repo), *args], input=data,
                            capture_output=True, env=env)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace").strip())
    return result


def value(repo: Path, *args: str, **kwargs) -> str:
    return git(repo, *args, **kwargs).stdout.decode().strip()


def selected(repo: Path, tree: str, paths: tuple[str, ...]) -> bytes:
    return git(repo, "ls-tree", "-r", "-z", tree, "--", *paths).stdout


def overlay(repo: Path, base: str, payload: bytes, paths: tuple[str, ...], env) -> str:
    git(repo, "read-tree", base, env=env)
    git(repo, "rm", "-r", "-f", "--cached", "--ignore-unmatch", "--", *paths, env=env)
    if payload:
        git(repo, "update-index", "-z", "--index-info", data=payload, env=env)
    return value(repo, "write-tree", env=env)


def commit(repo: Path, tree: str, message: str, parent: str = "") -> str:
    args = ["commit-tree", tree]
    if parent:
        args += ["-p", parent]
    return value(repo, *args, data=(message + "\n").encode())


def publish(repo: Path, kind: str, attempts: int = 3) -> str:
    paths = PATHS[kind]
    original = value(repo, "rev-parse", "HEAD")
    original_payload = selected(repo, original, paths)
    with tempfile.TemporaryDirectory(prefix="publish-index-") as tmp:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        git(repo, "read-tree", original, env=env)
        git(repo, "add", "-A", "--", *paths, env=env)
        payload = selected(repo, value(repo, "write-tree", env=env), paths)
        if not payload:
            raise RuntimeError("Refusing to publish an empty payload")

        for attempt in range(attempts):
            git(repo, "fetch", "origin", f"+refs/heads/{BRANCH}:refs/remotes/origin/{BRANCH}")
            latest = value(repo, "rev-parse", f"refs/remotes/origin/{BRANCH}")
            if kind == "catalog" and selected(repo, latest, ("data/catalog_signing_public_key.pem",)) != selected(repo, original, ("data/catalog_signing_public_key.pem",)):
                raise RuntimeError(f"Catalog signing key changed on {BRANCH}; refusing incompatible signature")
            remote_payload = selected(repo, latest, paths)
            if remote_payload == payload:
                print(f"{kind}: payload already published at {latest}")
                return latest
            if remote_payload != original_payload:
                raise RuntimeError(f"Newer {kind} payload exists on {BRANCH}; refusing stale replacement")

            tree = overlay(repo, latest, payload, paths, env)
            non_output = overlay(repo, tree, b"", ("output",), env)
            message = value(repo, "log", "-1", "--pretty=%B", latest)
            parent = git(repo, "rev-parse", "--verify", f"{latest}^", check=False)
            base = ""
            if kind == "catalog" and MARKER in message.splitlines() and parent.returncode == 0:
                candidate = parent.stdout.decode().strip()
                if value(repo, "rev-parse", f"{candidate}^{{tree}}") == non_output:
                    base = candidate
            if not base:
                previous = value(repo, "log", "--first-parent", "--format=%H",
                                 "--grep=\\[rolling-output\\]", "-n", "1", latest)
                baseline_parent = ""
                if previous:
                    found = git(repo, "rev-parse", "--verify", f"{previous}^", check=False)
                    if found.returncode == 0:
                        baseline_parent = found.stdout.decode().strip()
                base = commit(repo, non_output, f"chore: refresh {kind} repository baseline", baseline_parent)
            snapshot = commit(repo, tree, f"chore: refresh {kind} snapshot\n\n{MARKER}", base)
            pushed = git(repo, "push", f"--force-with-lease=refs/heads/{BRANCH}:{latest}",
                         "origin", f"{snapshot}:refs/heads/{BRANCH}", check=False)
            if pushed.returncode == 0:
                print(f"Published {kind} snapshot {snapshot}; preserved {BRANCH} {latest}")
                return snapshot
            if attempt + 1 == attempts:
                raise RuntimeError(pushed.stderr.decode(errors="replace").strip())
            print(f"{kind}: push rejected; refreshing {BRANCH} before bounded retry")
    raise RuntimeError("Publication did not complete")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=PATHS)
    args = parser.parse_args()
    if os.environ.get("GITHUB_REF_NAME") != BRANCH:
        raise SystemExit(f"Snapshot publishing is allowed only from {BRANCH}")
    repo = Path(__file__).resolve().parents[1]
    git(repo, "config", "user.name", "github-actions[bot]")
    git(repo, "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    publish(repo, args.kind)


if __name__ == "__main__":
    main()
