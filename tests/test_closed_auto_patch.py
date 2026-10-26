# Copyright 2026 SyncBit Software SRL and the CVELab contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The closed-source resolver reading the fix commit.

A product advisory is written to withhold the endpoint, so a resolver given
only the CVE record declines and is right to. These tests cover the other
input: the patch, and what happens when it cannot be had.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cvelab import closed_auto, sourcegen

URL = "https://gitlab.com/example/product.git"
CVE = "CVE-2026-0002"


def git(repository: Path, *arguments: str) -> str:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    return subprocess.run(
        ["git", *arguments], cwd=repository, check=True, capture_output=True, text=True, env=environment
    ).stdout.strip()


@unittest.skipUnless(shutil.which("git"), "git is required")
class FixPatchTests(unittest.TestCase):
    """fix_patch against a real repository, with the network stubbed out.

    Both retrieval routes are covered. GitHub and gitlab.com each serve a
    full commit id on its own in about a second; the clone is for what they
    cannot serve -- an abbreviated id, a tag, or a server with the
    capability turned off.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        seed = self.root / "seed"
        seed.mkdir(parents=True)
        git(seed, "init", "-q")
        (seed / "app").mkdir()
        (seed / "app" / "notes.rb").write_text("field :discussions, skip_authorization: true\n")
        git(seed, "add", "-A")
        git(seed, "commit", "-qm", "affected")
        (seed / "app" / "notes.rb").write_text("field :discussions\n")
        git(seed, "commit", "-qam", "restore note authorization")
        self.fixed = git(seed, "rev-parse", "HEAD")
        self.parent = git(seed, "rev-parse", "HEAD^")
        self.seed = seed
        self.refused: list[list[str]] = []
        real_git = sourcegen._run_git

        def offline_git(arguments, cwd=None, binary=False):
            if arguments[0] == "clone":
                return ""
            if arguments[0] == "fetch":
                # A server with uploadpack.allowAnySHA1InWant off: it
                # answers "not our ref" for an id it holds.
                if "--depth=2" in arguments:
                    self.refused.append(arguments)
                    raise RuntimeError("couldn't find remote ref")
                return ""
            return real_git(arguments, cwd=cwd, binary=binary)

        self.patcher = mock.patch.object(sourcegen, "_run_git", side_effect=offline_git)
        self.patcher.start()

    def tearDown(self) -> None:
        self.patcher.stop()
        self.temporary.cleanup()

    def place(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.seed, destination)

    def fix_cache(self) -> Path:
        key = hashlib.sha256(f"{URL}@{self.fixed}".encode()).hexdigest()[:16]
        return self.root / ".fix-cache" / key

    def source_cache(self) -> Path:
        return self.root / ".source-cache" / hashlib.sha256(URL.encode()).hexdigest()[:16]

    def test_the_patch_carries_the_change_the_advisory_withheld(self) -> None:
        self.place(self.source_cache())
        fix = sourcegen.fix_patch(URL, self.fixed, self.root, described={"notes"})
        self.assertIn("skip_authorization", fix["patch"])
        self.assertEqual(["app/notes.rb"], fix["changed_files"])
        self.assertEqual(URL, fix["repository"])
        # The cheap route was tried before the clone it fell back to.
        self.assertTrue(self.refused)

    def test_a_fix_already_fetched_is_read_without_the_network(self) -> None:
        self.place(self.fix_cache())
        fix = sourcegen.fix_patch(URL, self.fixed, self.root)
        self.assertIn("skip_authorization", fix["patch"])
        self.assertFalse(self.refused)
        self.assertFalse(self.source_cache().exists())

    def test_the_vulnerable_revision_is_the_fixs_parent(self) -> None:
        # Nothing is built from these revisions; they only say which code the
        # published vulnerable image is running.
        self.place(self.fix_cache())
        fix = sourcegen.fix_patch(URL, self.fixed, self.root)
        self.assertEqual(f"{self.fixed}^", fix["vulnerable_ref"])
        self.assertEqual(
            self.parent, git(self.fix_cache(), "rev-parse", fix["vulnerable_ref"])
        )

    def test_an_abbreviated_id_is_not_asked_of_the_server(self) -> None:
        # The protocol wants the whole id, so asking with eight characters
        # spends a round trip to be told the ref does not exist.
        self.place(self.source_cache())
        fix = sourcegen.fix_patch(URL, self.fixed[:8], self.root)
        self.assertIn("skip_authorization", fix["patch"])
        self.assertFalse(self.refused)

    def test_a_revision_that_is_not_a_revision_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            sourcegen.fix_patch(URL, "--output=/tmp/x", self.root)


class ResolverInputTests(unittest.TestCase):
    """What reaches the model, and what happens when the fix cannot be read."""

    FIX = {
        "repository": URL,
        "vulnerable_ref": "abc123^",
        "fixed_ref": "abc123",
        "changed_files": ["app/notes.rb"],
        "patch": "@@ -1 +1 @@\n-field :discussions, skip_authorization: true\n+field :discussions\n",
    }
    DOSSIER = {"cve": CVE, "descriptions": ["could have allowed an unauthenticated user to read internal notes"]}

    def resolve(self, root: Path, **overrides):
        calls: list[dict] = []

        def model(**kwargs):
            calls.append(kwargs)
            return {"status": "UNSUPPORTED", "reason": "stub", "attack": [], "sources": []}

        patches = [
            mock.patch.object(closed_auto, "collect_cve", return_value=self.DOSSIER),
            mock.patch.object(closed_auto, "structured_response", side_effect=model),
            *overrides.pop("extra", []),
        ]
        for patcher in patches:
            patcher.start()
        try:
            result = closed_auto.run_closed_auto(
                CVE, root, "key", "model", "anthropic", None,
                overrides.get("repo"), overrides.get("fixed_ref"),
            )
        finally:
            for patcher in patches:
                patcher.stop()
        return result, calls

    def test_the_patch_reaches_the_prompt_and_its_provenance_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            result, calls = self.resolve(
                root,
                repo=URL, fixed_ref="abc123",
                extra=[mock.patch.object(closed_auto, "fix_patch", return_value=self.FIX)],
            )
            sent = json.loads(calls[0]["input_text"])
            self.assertEqual(self.FIX["patch"], sent["security_patch"]["patch"])
            resolution = json.loads(
                (root / CVE / "closed" / "resolution.json").read_text(encoding="utf-8")
            )
            # The patch is public and a copy would travel with every uploaded
            # report, so only where it came from is kept.
            self.assertNotIn("patch", resolution["security_patch"])
            self.assertEqual("abc123", resolution["security_patch"]["fixed_ref"])
            self.assertFalse(result["ok"])

    def test_a_fix_the_record_merely_named_may_fail_to_be_read(self) -> None:
        """The resolver then answers from the record alone, as it did before."""
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            _, calls = self.resolve(
                root,
                extra=[
                    mock.patch.object(
                        closed_auto, "resolve_source", return_value=(URL, "abc123"),
                    ),
                    mock.patch.object(
                        closed_auto, "fix_patch",
                        side_effect=RuntimeError("git fetch failed"),
                    ),
                ],
            )
            sent = json.loads(calls[0]["input_text"])
            self.assertIsNone(sent["security_patch"])

    def test_a_fix_the_operator_supplied_must_not_fail_in_silence(self) -> None:
        """--repo with --fixed-ref is the operator saying where the patch is.

        Swallowed, a typo or a revision git rejects left the resolver
        answering from advisory prose while the patch the operator supplied
        was dropped, and nothing in the result or resolution.json said so.
        """
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(RuntimeError):
                self.resolve(
                    Path(name),
                    repo=URL, fixed_ref="abc123",
                    extra=[mock.patch.object(
                        closed_auto, "fix_patch",
                        side_effect=RuntimeError("git fetch failed"),
                    )],
                )

    def test_without_a_fix_the_record_is_still_resolved_alone(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _, calls = self.resolve(
                Path(name),
                extra=[mock.patch.object(closed_auto, "resolve_source", return_value=None)],
            )
            sent = json.loads(calls[0]["input_text"])
            self.assertIsNone(sent["security_patch"])
            self.assertEqual(CVE, sent["cve"])


class ReferenceScanTests(unittest.TestCase):
    """What the resolver takes from a CVE record's reference list."""

    def test_a_self_hosted_commit_link_does_not_abandon_the_list(self) -> None:
        """Only gitlab.com is supported, but the pattern matches any host.

        A reference to a self-hosted instance used to raise from inside the
        scan, so closed-auto died before planning and a usable github.com
        reference further down was never reached.
        """
        dossier = {
            "cve": CVE,
            "references": [
                "https://gitlab.gnome.org/GNOME/glib/-/commit/" + "a" * 40,
                "https://github.com/example/product/commit/" + "b" * 40,
            ],
        }
        self.assertEqual(
            sourcegen.resolve_source(dossier, None, None),
            ("https://github.com/example/product.git", "b" * 40),
        )

    def test_an_unsupported_host_alone_resolves_to_nothing(self) -> None:
        dossier = {
            "cve": CVE,
            "references": ["https://salsa.debian.org/a/b/-/commit/" + "c" * 40],
        }
        with mock.patch.object(sourcegen, "resolve_source_via_osv", return_value=None):
            self.assertIsNone(sourcegen.resolve_source(dossier, None, None))

    def test_an_uppercase_commit_id_still_takes_the_single_commit_path(self) -> None:
        """The id is matched case-insensitively but fetched exactly.

        Left uppercase it failed the full-id check and fell through to a
        blobless clone of the whole repository -- the minutes and gigabytes
        the single-commit fetch exists to avoid.
        """
        dossier = {
            "cve": CVE,
            "references": ["https://github.com/example/product/commit/" + "AB" * 20],
        }
        _, reference = sourcegen.resolve_source(dossier, None, None)
        self.assertEqual(reference, "ab" * 20)
        self.assertTrue(sourcegen.FULL_COMMIT_ID.fullmatch(reference))


class FixCacheTests(unittest.TestCase):
    """A cache entry that exists is one that holds the commit."""

    def test_an_interrupted_fetch_leaves_nothing_to_be_reused(self) -> None:
        """Cleanup ran only on RuntimeError.

        Ctrl-C or a signal left an init-only repository behind, and every
        later run took it as cached, so that fix could never be read again.
        """
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixed = "d" * 40
            calls: list[list[str]] = []

            def git(args, cwd=None, **kwargs):
                calls.append(list(args))
                if args[0] == "fetch":
                    raise KeyboardInterrupt
                return ""

            with mock.patch.object(sourcegen, "_run_git", side_effect=git):
                with self.assertRaises(KeyboardInterrupt):
                    sourcegen._fetch_one_commit(URL, fixed, root)

            cache = root / ".fix-cache"
            left = list(cache.iterdir()) if cache.is_dir() else []
            self.assertEqual(left, [], f"left behind: {left}")

            # And the next run fetches again rather than reusing a shell.
            calls.clear()
            with mock.patch.object(sourcegen, "_run_git", side_effect=git):
                with self.assertRaises(KeyboardInterrupt):
                    sourcegen._fetch_one_commit(URL, fixed, root)
            self.assertIn("fetch", [args[0] for args in calls])

    def test_a_completed_fetch_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixed = "e" * 40

            def git(args, cwd=None, **kwargs):
                if args[0] == "init":
                    (Path(cwd) / ".git").mkdir(exist_ok=True)
                return ""

            with mock.patch.object(sourcegen, "_run_git", side_effect=git):
                first = sourcegen._fetch_one_commit(URL, fixed, root)
                self.assertIsNotNone(first)
                self.assertTrue((first / ".git").is_dir())
                calls: list[str] = []

                def record(args, cwd=None, **kwargs):
                    calls.append(args[0])
                    return ""

                with mock.patch.object(sourcegen, "_run_git", side_effect=record):
                    second = sourcegen._fetch_one_commit(URL, fixed, root)
                self.assertEqual(second, first)
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
