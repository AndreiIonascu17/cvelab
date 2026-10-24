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

    def test_a_fix_that_cannot_be_read_does_not_stop_the_resolver(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            _, calls = self.resolve(
                root,
                repo=URL, fixed_ref="abc123",
                extra=[mock.patch.object(
                    closed_auto, "fix_patch", side_effect=RuntimeError("git fetch failed"),
                )],
            )
            sent = json.loads(calls[0]["input_text"])
            self.assertIsNone(sent["security_patch"])

    def test_without_a_fix_the_record_is_still_resolved_alone(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _, calls = self.resolve(
                Path(name),
                extra=[mock.patch.object(closed_auto, "resolve_source", return_value=None)],
            )
            sent = json.loads(calls[0]["input_text"])
            self.assertIsNone(sent["security_patch"])
            self.assertEqual(CVE, sent["cve"])


if __name__ == "__main__":
    unittest.main()
