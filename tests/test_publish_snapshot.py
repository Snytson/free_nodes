"""Exercise real Git remotes and interleaved catalog/Geo writers; no Internet."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
# The fixture remotes below use `main`; keep an ambient CI branch setting out of them.
os.environ["CATALOG_BRANCH"] = "main"
import publish_snapshot as publishing
from validate_catalog_resume import validate


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="catalog-publication-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.remote = self.root / "remote.git"
        self.repo = self.root / "runner"
        self.writer = self.root / "writer"
        self.git(self.root, "init", "--bare", "--initial-branch=main", str(self.remote))
        self.git(self.root, "init", "--initial-branch=main", str(self.repo))
        self.identity(self.repo)
        self.write(self.repo, {"code.txt": "original code", "data/GeoLite2-Country.mmdb": "old geo",
                               "data/GEOLITE2_SOURCE.md": "provenance",
                               "data/catalog_signing_public_key.pem": "unchanged signing key"})
        self.git(self.repo, "add", ".")
        self.git(self.repo, "commit", "-m", "initial baseline")
        self.write(self.repo, {"output/nodes.txt": "previous nodes", "output/obsolete.txt": "old"})
        self.git(self.repo, "add", ".")
        self.git(self.repo, "commit", "-m", "old catalog\n\n[rolling-output]")
        self.git(self.repo, "remote", "add", "origin", str(self.remote))
        self.git(self.repo, "push", "-u", "origin", "main")
        self.git(self.root, "clone", "--branch=main", str(self.remote), str(self.writer))
        self.identity(self.writer)

    @staticmethod
    def git(repo, *args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def identity(self, repo):
        self.git(repo, "config", "user.name", "fixture")
        self.git(repo, "config", "user.email", "fixture@example.test")
        self.git(repo, "config", "core.autocrlf", "false")

    @staticmethod
    def write(repo, files):
        for name, value in files.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8", newline="\n")

    def advance(self, files):
        self.write(self.writer, files)
        self.git(self.writer, "add", ".")
        self.git(self.writer, "commit", "-m", "concurrent update")
        self.git(self.writer, "push", "origin", "main")
        return self.git(self.writer, "rev-parse", "HEAD")

    def remote_file(self, path):
        return self.git(self.remote, "show", "main:" + path)

    def test_catalog_preserves_concurrent_geo_and_code_and_deletes_obsolete_output(self):
        self.write(self.repo, {"output/nodes.txt": "new nodes", "code.txt": "unrelated local edit"})
        (self.repo / "output/obsolete.txt").unlink()
        self.advance({"data/GeoLite2-Country.mmdb": "new geo", "code.txt": "latest code"})
        publishing.publish(self.repo, "catalog")
        self.assertEqual(self.remote_file("output/nodes.txt"), "new nodes")
        self.assertEqual(self.remote_file("data/GeoLite2-Country.mmdb"), "new geo")
        self.assertEqual(self.remote_file("code.txt"), "latest code")
        self.assertNotIn("obsolete.txt", self.git(self.remote, "ls-tree", "-r", "--name-only", "main"))
        self.assertNotIn("output/", self.git(self.remote, "ls-tree", "-r", "--name-only", "main^"))
        self.assertIn("[rolling-output]", self.git(self.remote, "log", "-1", "--pretty=%B", "main"))

    def test_real_lease_race_retries_preserving_geo(self):
        self.write(self.repo, {"output/nodes.txt": "new nodes"})
        actual_git = publishing.git
        pushes = []

        def race(repo, *args, **kwargs):
            if args[0] == "push":
                pushes.append(args)
                if len(pushes) == 1:
                    self.advance({"data/GeoLite2-Country.mmdb": "geo during push"})
            return actual_git(repo, *args, **kwargs)

        with mock.patch.object(publishing, "git", side_effect=race):
            publishing.publish(self.repo, "catalog")
        self.assertEqual(len(pushes), 2)
        self.assertNotEqual(pushes[0][1], pushes[1][1])
        self.assertEqual(self.remote_file("data/GeoLite2-Country.mmdb"), "geo during push")
        self.assertEqual(self.remote_file("output/nodes.txt"), "new nodes")

    def test_newer_catalog_is_not_overwritten(self):
        self.write(self.repo, {"output/nodes.txt": "stale nodes"})
        latest = self.advance({"output/nodes.txt": "newer nodes"})
        with self.assertRaisesRegex(RuntimeError, "Newer catalog"):
            publishing.publish(self.repo, "catalog")
        self.assertEqual(self.git(self.remote, "rev-parse", "main"), latest)

    def test_catalog_published_during_push_is_not_overwritten_on_retry(self):
        self.write(self.repo, {"output/nodes.txt": "stale nodes"})
        actual_git = publishing.git
        pushes = []

        def race(repo, *args, **kwargs):
            if args[0] == "push":
                pushes.append(args)
                self.advance({"output/nodes.txt": "winning catalog"})
            return actual_git(repo, *args, **kwargs)

        with mock.patch.object(publishing, "git", side_effect=race):
            with self.assertRaisesRegex(RuntimeError, "Newer catalog"):
                publishing.publish(self.repo, "catalog")
        self.assertEqual(len(pushes), 1)
        self.assertEqual(self.remote_file("output/nodes.txt"), "winning catalog")

    def test_geo_preserves_new_catalog_and_local_code_is_not_staged(self):
        self.write(self.repo, {"data/GeoLite2-Country.mmdb": "new geo", "code.txt": "local only"})
        self.advance({"output/nodes.txt": "newer nodes"})
        publishing.publish(self.repo, "geo")
        self.assertEqual(self.remote_file("output/nodes.txt"), "newer nodes")
        self.assertEqual(self.remote_file("data/GeoLite2-Country.mmdb"), "new geo")
        self.assertEqual(self.remote_file("code.txt"), "original code")

    def test_changed_signing_key_blocks_old_signature(self):
        self.write(self.repo, {"output/nodes.txt": "new nodes"})
        self.advance({"data/catalog_signing_public_key.pem": "rotated key"})
        with self.assertRaisesRegex(RuntimeError, "signing key changed"):
            publishing.publish(self.repo, "catalog")
        self.assertEqual(self.remote_file("output/nodes.txt"), "previous nodes")

    def test_unchanged_payload_is_idempotent(self):
        before = self.git(self.remote, "rev-parse", "main")
        self.assertEqual(publishing.publish(self.repo, "catalog"), before)
        self.assertEqual(self.git(self.remote, "rev-parse", "main"), before)

    def test_rejected_pushes_are_bounded_and_never_remove_the_lease(self):
        self.write(self.repo, {"output/nodes.txt": "new nodes"})
        actual_git = publishing.git
        pushes = []

        def reject(repo, *args, **kwargs):
            if args[0] == "push":
                pushes.append(args)
                return subprocess.CompletedProcess(args, 1, b"", b"fixture rejected")
            return actual_git(repo, *args, **kwargs)

        with mock.patch.object(publishing, "git", side_effect=reject):
            with self.assertRaisesRegex(RuntimeError, "fixture rejected"):
                publishing.publish(self.repo, "catalog")
        self.assertEqual(len(pushes), 3)
        self.assertTrue(all(args[1].startswith("--force-with-lease=refs/heads/main:") for args in pushes))
        self.assertEqual(self.remote_file("output/nodes.txt"), "previous nodes")


class BranchTests(unittest.TestCase):
    """The publisher must follow CATALOG_BRANCH, not a hard-coded main."""

    def test_publish_uses_configured_default_branch(self):
        with tempfile.TemporaryDirectory(prefix="catalog-branch-test-") as tmp:
            root = Path(tmp)
            remote = root / "remote.git"
            repo = root / "runner"

            def run(*args, **kwargs):
                return subprocess.run(["git", "-C", str(kwargs.pop("repo", repo)), *args],
                                      check=True, capture_output=True, text=True).stdout.strip()

            run("init", "--bare", "--initial-branch=master", str(remote), repo=root)
            run("init", "--initial-branch=master", str(repo), repo=root)
            run("config", "user.name", "fixture")
            run("config", "user.email", "fixture@example.test")
            run("config", "core.autocrlf", "false")
            (repo / "data").mkdir()
            (repo / "data/catalog_signing_public_key.pem").write_text("key\n", newline="\n")
            run("add", ".")
            run("commit", "-m", "initial baseline")
            run("remote", "add", "origin", str(remote))
            run("push", "-u", "origin", "master")
            (repo / "output").mkdir()
            (repo / "output/nodes.txt").write_text("node\n", newline="\n")

            with mock.patch.object(publishing, "BRANCH", "master"):
                publishing.publish(repo, "catalog")

            shown = run("show", "master:output/nodes.txt", repo=remote)
            self.assertEqual(shown, "node")


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.run = {"status": "completed", "conclusion": "failure", "head_branch": "main",
                    "path": ".github/workflows/update.yml", "head_sha": "a" * 40,
                    "head_repository": {"full_name": "owner/repo"}}
        names = ["Collect candidates and pin sing-box"]
        self.jobs = [{"name": name, "conclusion": "success"}
                     for name in names + [f"Probe shard ({i})" for i in range(8)]]

    def test_completed_failed_publication_can_resume(self):
        self.assertEqual(validate(self.run, self.jobs, "owner/repo"), "a" * 40)

    def test_missing_or_failed_checker_cannot_resume(self):
        with self.assertRaises(ValueError):
            validate(self.run, self.jobs[:-1], "owner/repo")
        self.jobs[-1]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            validate(self.run, self.jobs, "owner/repo")

    def test_configured_branch_is_required(self):
        with mock.patch("validate_catalog_resume.BRANCH", "master"):
            self.assertEqual(validate({**self.run, "head_branch": "master"},
                                      self.jobs, "owner/repo"), "a" * 40)
            with self.assertRaises(ValueError):
                validate(self.run, self.jobs, "owner/repo")

    def test_foreign_running_or_cancelled_run_cannot_resume(self):
        for key, bad in (("head_branch", "feature"), ("status", "in_progress"),
                         ("conclusion", "cancelled"), ("path", ".github/workflows/other.yml")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate({**self.run, key: bad}, self.jobs, "owner/repo")
        with self.assertRaises(ValueError):
            validate(self.run, self.jobs, "different/repo")


if __name__ == "__main__":
    unittest.main()
