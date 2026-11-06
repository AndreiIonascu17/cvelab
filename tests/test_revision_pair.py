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

"""The revision pair is checked before a lab is built from it.

Measured over 40 attempts, `proof_not_verified` was the largest failure
class at 20%, and a share of it was decided before the model saw anything:
the pair could not show the fix, so every repair chased an effect the
inputs forbid.

Every repository here is built in a temp directory, commit by commit, so
the merge, the divergent release line and the prose-only child are real
git objects and the verdict is read from git rather than from a mock of it.
Nothing in this file reaches the network.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from cvelab import cli, revisions, sourcegen


def _git(repository: Path, *arguments: str) -> str:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    return subprocess.run(
        ["git", *arguments], cwd=repository, check=True, capture_output=True, text=True,
        env=environment,
    ).stdout.strip()


#: Every field both adapter contracts audit, in one string, so one answer
#: serves the differential and the vulnerable-only schema alike.
_VALIDATOR = " ".join([
    "attack_executed", "proof_quality", "observable_effect", "evidence_type",
    "vulnerable", "patched", "patched_tested", "fix_status",
    "differential_confirmed", "confirmed", "blocked", "observations",
    "CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "exploit", "verify",
])

_VULNERABLE_ONLY_COMPOSE = """services:
  vulnerable:
    build:
      context: .
      dockerfile: vulnerable/Dockerfile
  validator:
    build:
      context: ./validator
      dockerfile: Dockerfile
networks:
  labnet:
    internal: true
"""

_DIFFERENTIAL_COMPOSE = """services:
  vulnerable:
    build:
      context: .
      dockerfile: vulnerable/Dockerfile
  patched:
    build:
      context: .
      dockerfile: patched/Dockerfile
  validator:
    build:
      context: ./validator
      dockerfile: Dockerfile
networks:
  labnet:
    internal: true
"""


def _generation(vulnerable_only: bool) -> dict:
    answer = {
        "cwe": "CWE-78",
        "confidence": 0.6,
        "rationale": "r",
        "fidelity": {
            "execution_level": "source_component",
            "vendor_product_started": False,
            "exercised_vendor_components": ["app/shellexec.go"],
            "simulated_components": [],
            "rationale": "r",
        },
        "exploit_contract": {
            "attack_summary": "a", "preconditions": [], "observable_effect": "e",
            "evidence_type": "code_execution",
            # One answer serves the differential and the vulnerable-only
            # schema alike, so the predicate has to satisfy the stricter of
            # the two: a vulnerable-only lab has no patched build to show up
            # a status clause standing on its own.
            "effect_predicate": {"body_contains": "shell-ran"},
        },
        "docker_compose": (
            _VULNERABLE_ONLY_COMPOSE if vulnerable_only else _DIFFERENTIAL_COMPOSE
        ),
        "dockerignore": "",
        "vulnerable_dockerfile": "FROM scratch\n",
        "validator_dockerfile": "FROM scratch\n",
        "validator_py": _VALIDATOR,
        "support_services": [],
        "adapter_files": [],
    }
    if not vulnerable_only:
        answer["patched_dockerfile"] = "FROM scratch\n"
    return answer


class _PairLab:
    """A repository holding every pair shape, and a fake model.

    The history, with the advisory naming app/shellexec.go:

        affected (v1.0.0) --- linear_fix (v1.0.1) --- merge
                 |                                   /
                 |--- release_side -----------------/
                 |
                 |--- wrong_parent --- wrong_fix

    `linear_fix` already carries the fix, so the merge's first parent is not
    a before-state and its second parent is: the merge's change set against
    parent 2 is the fix, and against parent 1 it is the release line's own
    three files. `wrong_fix` is the shape a reference resolved to the wrong
    release line leaves, where `fixed^` is on no line the fix ever shipped on.
    """

    URL = "https://github.com/example/widget.git"
    CVE = "CVE-2026-0003"
    DESCRIPTION = "an argument reaches a shell unquoted in app/shellexec.go"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        cache = self.root / ".source-cache" / hashlib.sha256(self.URL.encode()).hexdigest()[:16]
        cache.mkdir(parents=True)
        self.cache = cache
        _git(cache, "init", "-q")
        for path, text in (
            ("app/shellexec.go", "package app\n\nfunc Run(s string) { exec(s) }\n"),
            ("lib/logging.go", "package lib\n\nfunc Log(m string) {}\n"),
            ("README.zh.md", "the old translation\n"),
        ):
            target = cache / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        _git(cache, "add", "-A")
        _git(cache, "commit", "-qm", "affected")
        self.affected = _git(cache, "rev-parse", "HEAD")
        _git(cache, "tag", "v1.0.0")

        (cache / "app" / "shellexec.go").write_text(
            "package app\n\nfunc Run(s string) { exec(quote(s)) }\n"
        )
        _git(cache, "commit", "-qam", "quote the argument")
        self.linear_fix = _git(cache, "rev-parse", "HEAD")
        _git(cache, "tag", "v1.0.1")

        (cache / "README.zh.md").write_text("the new translation\n")
        _git(cache, "commit", "-qam", "translate the README")
        self.prose_fix = _git(cache, "rev-parse", "HEAD")

        # The line the merge brings in: three files the advisory names none of.
        _git(cache, "checkout", "-q", "-b", "release", self.affected)
        (cache / "lib" / "logging.go").write_text("package lib\n\nfunc Log(m string) { out(m) }\n")
        (cache / "lib" / "metrics.go").write_text("package lib\n\nfunc Count() {}\n")
        (cache / "cmd").mkdir()
        (cache / "cmd" / "serve.go").write_text("package main\n\nfunc main() {}\n")
        _git(cache, "add", "-A")
        _git(cache, "commit", "-qm", "the release line moves on")
        self.release_side = _git(cache, "rev-parse", "HEAD")

        _git(cache, "checkout", "-q", self.linear_fix)
        _git(cache, "merge", "--no-ff", "-q", "-m", "merge the release line", "release")
        self.merge = _git(cache, "rev-parse", "HEAD")

        # A second line off the affected revision, tagged by nothing.
        _git(cache, "checkout", "-q", "-b", "wrong", self.affected)
        (cache / "app" / "other.go").write_text("package app\n\nfunc Other() {}\n")
        _git(cache, "add", "-A")
        _git(cache, "commit", "-qm", "an unrelated line")
        self.wrong_parent = _git(cache, "rev-parse", "HEAD")
        (cache / "app" / "other.go").write_text("package app\n\nfunc Other() { safe() }\n")
        _git(cache, "commit", "-qam", "a change on the unrelated line")
        self.wrong_fix = _git(cache, "rev-parse", "HEAD")

        # A sibling of prose_fix: the same program, a different translation.
        # The only pair here that is both prose-only and off one line of
        # history, so it is the only one that can say which of the two
        # reasons an operator is given.
        _git(cache, "checkout", "-q", "-b", "translation", self.linear_fix)
        (cache / "README.zh.md").write_text("another translation\n")
        _git(cache, "commit", "-qam", "translate the README differently")
        self.prose_sibling = _git(cache, "rev-parse", "HEAD")

        self.schemas: list[str] = []
        self.references: list[str] = []
        self.pair: dict | None = None
        revisions.clear_cache()
        real_git = sourcegen._run_git

        def offline_git(arguments, cwd=None, binary=False):
            if arguments[0] in {"clone", "fetch"}:
                return ""
            return real_git(arguments, cwd=cwd, binary=binary)

        patches = [
            mock.patch.object(sourcegen, "_run_git", side_effect=offline_git),
            mock.patch.object(sourcegen, "collect_cve", side_effect=self.dossier),
            mock.patch.object(sourcegen, "resolve_source_via_osv", return_value=None),
            # A vulnerable-only resolution leaves `resolved` empty, which is
            # the one path that asks the model to go looking; this suite is
            # about the pair and not about discovery.
            mock.patch.object(
                sourcegen,
                "discover_source_with_ai",
                return_value={"status": "INSUFFICIENT_DATA", "rationale": "", "evidence_urls": []},
            ),
            mock.patch.object(sourcegen, "_enforce_compose_policy"),
            mock.patch.object(sourcegen.releases, "find_releases", return_value=[]),
            # The advisory and the tag listing, answered from the test rather
            # than from GitHub. The pair itself is a real local tag pair, so
            # the ancestry around it is still decided by git.
            mock.patch.object(
                sourcegen.revisions, "release_pair", side_effect=lambda *_: self.pair
            ),
            mock.patch.object(sourcegen, "structured_response", side_effect=self.model),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def dossier(self, _cve: str) -> dict:
        return {
            "cve": self.CVE,
            "descriptions": [self.DESCRIPTION],
            "references": self.references,
        }

    def model(self, **kwargs) -> dict:
        self.schemas.append(kwargs["schema_name"])
        return _generation(kwargs["schema"] is sourcegen.VULNERABLE_ONLY_SCHEMA)

    def commit_url(self, revision: str) -> str:
        return f"https://github.com/example/widget/commit/{revision}"

    def generate(
        self,
        *,
        repo: str | None = None,
        fixed_ref: str | None = None,
        vulnerable_ref: str | None = None,
        reference: str | None = None,
    ) -> dict:
        """One generation, resolving either from an override or from the record."""
        self.references = [reference] if reference else []
        return sourcegen.generate_source_lab(
            self.CVE, self.root, repo, fixed_ref, vulnerable_ref,
            "key", "model", "anthropic", None, research_mode="off",
        )

    def verdict(self, vulnerable: str, fixed: str | None, **options) -> revisions.Verdict:
        """verify_pair against the real repository, without a generation."""
        self.references = options.pop("references", [])
        return revisions.verify_pair(
            self.cache, vulnerable, fixed, self.dossier(self.CVE), self.CVE, self.URL,
            **options,
        )

    def tags(self, vulnerable: str, fixed: str) -> dict:
        return {
            "repository": self.URL,
            "package": "widget",
            "vulnerable_version": vulnerable.lstrip("v"),
            "fixed_version": fixed.lstrip("v"),
            "vulnerable_tag": vulnerable,
            "fixed_tag": fixed,
        }


@unittest.skipUnless(shutil.which("git"), "git is required")
class TheVulnerableSideIsChosenRatherThanGuessedTests(_PairLab, unittest.TestCase):
    """`fixed^` was the vulnerable side for every fixing reference alike.

    Nothing asked whether the reference was a merge, and a merge has one
    before-state per parent: the fix lies between exactly one of them and
    the merge, and the diff from the other is the line the merge brought in.
    A pair built on the wrong parent cannot show the fix, so every repair
    after it is asked for an effect its own inputs forbid.
    """

    def test_a_linear_pair_still_takes_the_first_parent(self) -> None:
        """One parent, one answer, and the behaviour that was already there."""
        verdict = self.verdict(f"{self.linear_fix}^", self.linear_fix)

        self.assertEqual(verdict.vulnerable, f"{self.linear_fix}^")
        self.assertEqual(verdict.provenance["vulnerable_side"], revisions.FIRST_PARENT)
        self.assertNotIn("merge_parents", verdict.provenance)
        self.assertIsNone(verdict.demotion)

    def test_the_fix_on_the_second_parent_of_a_merge_is_found(self) -> None:
        """The headline case: parent 2 is the before-state and `fixed^` is not.

        The merge's first parent already carries the fix, so its change set
        against the merge is the release line's three files and names nothing
        the advisory does. The second parent's change set is app/shellexec.go,
        which the advisory names, and that is the revision a lab must build.
        """
        verdict = self.verdict(f"{self.merge}^", self.merge)

        self.assertEqual(verdict.vulnerable, self.release_side)
        self.assertNotEqual(verdict.vulnerable, self.linear_fix)
        self.assertNotEqual(verdict.vulnerable, f"{self.merge}^")
        self.assertEqual(verdict.provenance["chosen_parent"], 2)
        self.assertEqual(verdict.provenance["vulnerable_side"], revisions.CHOSEN_PARENT)
        self.assertEqual(
            verdict.provenance["merge_parents"], [self.linear_fix, self.release_side]
        )

    def test_the_chosen_parent_is_the_one_that_gets_snapshotted(self) -> None:
        """End to end, because a verdict nothing acts on is worth nothing.

        The pair is verified before either snapshot is extracted, so the
        revision on disk, the revision in plan.json and the revision the
        diff was taken from are all the chosen parent.
        """
        result = self.generate(reference=self.commit_url(self.merge))
        plan = result["plan"]

        self.assertEqual(plan["revisions"]["vulnerable"], self.release_side)
        self.assertEqual(plan["revisions"]["patched"], self.merge)
        self.assertNotIn("demotion", plan)
        self.assertEqual(
            (self.root / self.CVE / "source" / ".vulnerable.revision").read_text(),
            f"{self.URL} {self.release_side}\n",
        )

    def test_an_explicit_vulnerable_revision_outranks_the_choice(self) -> None:
        """An operator's revision is not a guess, so it is not overruled."""
        verdict = self.verdict(self.linear_fix, self.merge, explicit=True)

        self.assertEqual(verdict.vulnerable, self.linear_fix)
        self.assertEqual(verdict.provenance["vulnerable_side"], revisions.VULNERABLE_EXPLICIT)
        self.assertNotIn("merge_parents", verdict.provenance)

    def test_a_parent_whose_diff_cannot_show_a_fix_is_not_chosen(self) -> None:
        """The rejection reuses `_unusable_pair` rather than a rule of its own.

        A merge of two identical trees has two parents and no before-state,
        and the generator's own classifier is what says so.
        """
        scored = revisions._scored_parents(
            self.cache, self.merge, [self.merge, self.release_side], {"shellexec"}
        )
        self.assertIn("same tree", scored[0]["unusable"] or "")
        self.assertIsNone(scored[1]["unusable"])
        self.assertEqual(revisions._best_parent(scored)["position"], 2)
        self.assertIsNone(revisions._best_parent([scored[0]]))


@unittest.skipUnless(shutil.which("git"), "git is required")
class TheAdvisorysOwnAffectedLineIsConsultedTests(_PairLab, unittest.TestCase):
    """pair_from_advisory and tag_pair ran only when nothing had resolved.

    They were gated behind "no commit resolved AND discovery ran", so a
    commit that resolved badly was never checked against the versions the
    advisory itself states were affected and patched -- the one piece of
    evidence that can tell a reference on the wrong release line from a
    reference on the right one.
    """

    def test_the_tag_pair_wins_when_it_contradicts_the_guess(self) -> None:
        """Both ends replaced, and the pair they replaced kept in the record.

        `wrong_fix` is on a line of its own, so `wrong_fix^` is on no line
        the first patched release was ever cut from. The advisory names its
        two ends, the repository tags them, and those two are a before and
        an after; the rejected pair stays in the provenance because the
        disagreement is the evidence and an artifact that hid it could not
        be argued with afterwards.
        """
        self.pair = self.tags("v1.0.0", "v1.0.1")
        verdict = self.verdict(self.wrong_parent, self.wrong_fix)

        self.assertEqual(verdict.vulnerable, "v1.0.0")
        self.assertEqual(verdict.fixed, "v1.0.1")
        self.assertEqual(verdict.provenance["vulnerable_side"], revisions.RELEASE_TAG)
        self.assertEqual(verdict.provenance["resolver"], revisions.TAG_PAIR)
        self.assertEqual(
            verdict.provenance["rejected"],
            {"vulnerable": self.wrong_parent, "fixed": self.wrong_fix},
        )
        self.assertEqual(verdict.provenance["affected_line"], "v1.0.0 -> v1.0.1")
        self.assertTrue(verdict.verified)
        self.assertIsNone(verdict.demotion)

    def test_the_tag_pair_reaches_the_plan_and_the_snapshots(self) -> None:
        self.pair = self.tags("v1.0.0", "v1.0.1")
        result = self.generate(reference=self.commit_url(self.wrong_fix))
        plan = result["plan"]

        self.assertEqual(plan["revisions"], {"vulnerable": "v1.0.0", "patched": "v1.0.1"})
        self.assertNotIn("demotion", plan)
        # The reference that was going to be used, as it was going to be
        # used: `fixed^` and not what it resolves to, because the literal is
        # what an operator reading the plan has to recognise.
        self.assertEqual(
            plan["source_provenance"]["rejected"],
            {"vulnerable": f"{self.wrong_fix}^", "fixed": self.wrong_fix},
        )

    def test_a_pair_already_on_the_affected_line_is_left_alone(self) -> None:
        """Agreement is recorded, not acted on: this is the common case."""
        self.pair = self.tags("v1.0.0", "v1.0.1")
        verdict = self.verdict(f"{self.linear_fix}^", self.linear_fix)

        self.assertEqual(verdict.vulnerable, f"{self.linear_fix}^")
        self.assertEqual(verdict.fixed, self.linear_fix)
        self.assertEqual(verdict.provenance["affected_line"], "ancestor of v1.0.1")
        self.assertNotIn("rejected", verdict.provenance)
        self.assertTrue(verdict.verified)

    def test_an_unreadable_advisory_means_unknown_and_not_unverifiable(self) -> None:
        """A timeout must never read as evidence against a good pair.

        releases._get and resolve_source_via_osv both answer with nothing
        rather than raising, and a verification that failed a run over an
        unreachable GitHub would be worse than the guessing it replaced.
        """
        self.pair = None
        verdict = self.verdict(f"{self.linear_fix}^", self.linear_fix)

        self.assertEqual(verdict.provenance["affected_line"], revisions.UNKNOWN)
        self.assertEqual(verdict.provenance["ancestry"], "confirmed")
        self.assertFalse(verdict.verified)
        self.assertIsNone(verdict.demotion)


class TheAdvisoryLookupNeverFailsARunTests(unittest.TestCase):
    """The lookup costs network and a 60s timeout, and may answer nothing.

    Verifying every pair means asking for every pair, so what the lookup
    does when it cannot answer is now on the generation path for every run
    rather than only for the ones that had already given up.
    """

    URL = "https://github.com/example/widget.git"
    CVE = "CVE-2026-0004"

    def setUp(self) -> None:
        revisions.clear_cache()
        self.addCleanup(revisions.clear_cache)

    def tags(self, vulnerable: str, fixed: str) -> dict:
        return {
            "repository": self.URL, "package": "widget",
            "vulnerable_version": vulnerable.lstrip("v"),
            "fixed_version": fixed.lstrip("v"),
            "vulnerable_tag": vulnerable, "fixed_tag": fixed,
        }

    def test_a_lookup_that_raises_is_not_fatal(self) -> None:
        """releases._get answers with nothing rather than raising; so does this.

        A verification that failed a run over an unreachable GitHub would be
        worse than the guessing it replaced.
        """
        with mock.patch.object(
            revisions.releases, "pair_from_advisory", side_effect=TimeoutError("slow")
        ):
            self.assertIsNone(revisions.release_pair(self.URL, self.CVE))

    def test_the_tag_listing_is_asked_for_once_per_run(self) -> None:
        """repo_tags has a 60s timeout and lists every tag a project published.

        A generation and its three repairs would otherwise ask four times for
        an answer that cannot change inside one run.
        """
        with mock.patch.object(
            revisions.releases, "pair_from_advisory", return_value=[]
        ) as advisory:
            for _ in range(4):
                revisions.release_pair(self.URL, self.CVE)
        self.assertEqual(advisory.call_count, 1)

    def test_a_tag_name_git_would_read_as_an_option_is_refused(self) -> None:
        """A tag arrives from ls-remote on a public repository: untrusted.

        The resolver that already accepted a tag pair sanitised both ends
        with _safe_revision on its own path, and these two reach `git diff`
        and `git archive` once the pair is preferred over a commit.
        """
        with mock.patch.object(
            revisions.releases,
            "tag_pair",
            return_value=self.tags("--output=/tmp/pwned", "v1.0.1"),
        ), mock.patch.object(revisions.releases, "pair_from_advisory", return_value=[{}]):
            self.assertIsNone(revisions.release_pair(self.URL, self.CVE))

    def test_a_tag_pair_that_is_safe_comes_through(self) -> None:
        pair = self.tags("v1.0.0", "v1.0.1")
        with mock.patch.object(revisions.releases, "tag_pair", return_value=pair), \
                mock.patch.object(revisions.releases, "pair_from_advisory", return_value=[{}]):
            self.assertEqual(revisions.release_pair(self.URL, self.CVE), pair)

    def test_the_documented_off_switch_still_turns_the_lookup_off(self) -> None:
        """CVELAB_PUBLISHED_RELEASES=off, which pair_from_advisory never read.

        find_releases honours it and pair_from_advisory does not, because
        until now it only ran on a path that had already decided to look
        things up. Verifying every pair would otherwise have made a
        documented off switch stop turning the lookup off.
        """
        with mock.patch.dict(os.environ, {"CVELAB_PUBLISHED_RELEASES": "off"}), \
                mock.patch.object(revisions.releases, "pair_from_advisory") as advisory:
            self.assertIsNone(revisions.release_pair(self.URL, self.CVE))
        advisory.assert_not_called()

    def test_no_repository_is_nothing_to_ask_about(self) -> None:
        with mock.patch.object(revisions.releases, "pair_from_advisory") as advisory:
            self.assertIsNone(revisions.release_pair("", self.CVE))
        advisory.assert_not_called()


@unittest.skipUnless(shutil.which("git"), "git is required")
class AnUnverifiablePairUsesTheDemotionThatIsAlreadyThereTests(
    _PairLab, unittest.TestCase
):
    """The verification adds no disposition of its own.

    A pair that cannot be verified goes where an unusable pair has gone
    since that work landed: demoted to a vulnerable-only lab, with the
    reason in plan.json and from there in the report. A second path would be
    a second, contradictory answer to the same input.
    """

    def test_a_byte_identical_pair_keeps_the_reason_it_already_had(self) -> None:
        result = self.generate(
            reference=self.commit_url(self.linear_fix), vulnerable_ref=self.linear_fix
        )
        plan = result["plan"]

        self.assertEqual(self.schemas, ["cvelab_vulnerable_only_adapter"])
        self.assertEqual(plan["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
        self.assertEqual(plan["demotion"]["rejected_fixed"], self.linear_fix)
        self.assertIn("resolve to the same tree", plan["demotion"]["reason"])
        self.assertNotIn("is not an ancestor", plan["demotion"]["reason"])

    def test_a_prose_only_pair_keeps_the_reason_it_already_had(self) -> None:
        result = self.generate(
            reference=self.commit_url(self.prose_fix), vulnerable_ref=self.linear_fix
        )
        plan = result["plan"]

        self.assertEqual(self.schemas, ["cvelab_vulnerable_only_adapter"])
        self.assertEqual(plan["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
        self.assertIn("nothing the program is built from changed", plan["demotion"]["reason"])
        self.assertIn("README.zh.md", plan["demotion"]["reason"])
        self.assertNotIn("is not an ancestor", plan["demotion"]["reason"])

    def test_neither_shape_gets_a_reason_from_the_verification(self) -> None:
        """Both are a before and an after of one history; only the diff is wrong.

        The verification must stay silent about them, or the operator would
        read two reasons for one pair and the existing classifier's more
        specific one would be the one lost.
        """
        for fixed in (self.linear_fix, self.prose_fix):
            with self.subTest(fixed=fixed):
                self.assertIsNone(
                    self.verdict(self.linear_fix, fixed, explicit=True).demotion
                )

    def test_a_pair_with_two_reasons_is_given_the_more_specific_one(self) -> None:
        """Both reasons are true of this pair, and only one is worth printing.

        Two siblings of the fix differing in one translated README are off
        one line of history and prose-only at once. The classifier's reason
        names the file, which is what an operator can check; the
        verification's names two object ids. A reason reaches plan.json and
        from there REPORT.md verbatim, so the order they are tried in is the
        whole of what the operator is told.
        """
        self.assertIn(
            "is not an ancestor",
            self.verdict(self.prose_sibling, self.prose_fix, explicit=True).demotion,
        )
        plan = self.generate(
            reference=self.commit_url(self.prose_fix), vulnerable_ref=self.prose_sibling
        )["plan"]

        self.assertEqual(plan["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
        self.assertIn("nothing the program is built from changed", plan["demotion"]["reason"])
        self.assertIn("README.zh.md", plan["demotion"]["reason"])
        self.assertNotIn("is not an ancestor", plan["demotion"]["reason"])

    def test_two_revisions_on_different_lines_are_demoted_not_aborted(self) -> None:
        """The one thing the verification can say no to on its own.

        No network and no advisory: two revisions that are not on one line of
        history are not a before and an after, and their diff carries the fix
        mixed with everything each side changed alone.
        """
        verdict = self.verdict(self.wrong_parent, self.linear_fix, explicit=True)

        self.assertEqual(verdict.provenance["ancestry"], "not one line of history")
        self.assertIn("is not an ancestor of the fixed revision", verdict.demotion)
        self.assertIn("the fixing reference in hand is not the fix", verdict.demotion)

    def test_that_demotion_travels_through_the_machinery_already_there(self) -> None:
        result = self.generate(
            reference=self.commit_url(self.linear_fix), vulnerable_ref=self.wrong_parent
        )
        plan = result["plan"]

        self.assertEqual(self.schemas, ["cvelab_vulnerable_only_adapter"])
        self.assertEqual(plan["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
        self.assertIsNone(plan["revisions"]["patched"])
        self.assertEqual(plan["demotion"]["rejected_fixed"], self.linear_fix)
        self.assertIn("not an ancestor", plan["demotion"]["reason"])
        self.assertIn(
            "A fixed revision was resolved and then discarded",
            plan["safety"]["limitations"],
        )
        self.assertFalse((self.root / self.CVE / "source" / "patched").exists())

    def test_a_pair_that_verifies_cleanly_changes_nothing(self) -> None:
        """The case that must not move: a differential lab, exactly as before."""
        self.pair = self.tags("v1.0.0", "v1.0.1")
        result = self.generate(reference=self.commit_url(self.linear_fix))
        plan = result["plan"]

        self.assertEqual(self.schemas, ["cvelab_source_adapter"])
        self.assertEqual(plan["lab_type"], "SOURCE_REPRODUCTION")
        self.assertEqual(
            plan["revisions"], {"vulnerable": f"{self.linear_fix}^", "patched": self.linear_fix}
        )
        self.assertNotIn("demotion", plan)
        self.assertTrue(plan["source_provenance"]["verified"])
        self.assertTrue((self.root / self.CVE / "source" / "patched").is_dir())


@unittest.skipUnless(shutil.which("git"), "git is required")
class ProvenanceSaysWhichResolverDecidedTests(_PairLab, unittest.TestCase):
    """plan.json recorded `source_provenance` as a constant string.

    Two sentences, one per lab type, true of every run that reached them, so
    after a bad pair nothing in the artifacts said how it had been chosen.
    README states under Limitations that a guessed repository or commit is
    not accepted as provenance; this is the field that makes the statement
    something to check rather than something asserted.
    """

    def test_two_resolutions_no_longer_produce_the_same_value(self) -> None:
        explicit = self.generate(repo=self.URL, fixed_ref=self.linear_fix)
        from_record = self.generate(reference=self.commit_url(self.linear_fix))

        first = explicit["plan"]["source_provenance"]
        second = from_record["plan"]["source_provenance"]
        self.assertNotEqual(first, second)
        self.assertEqual(first["resolver"], revisions.EXPLICIT)
        self.assertEqual(second["resolver"], revisions.CVE_REFERENCE)
        self.assertEqual(second["reference"], self.commit_url(self.linear_fix))
        self.assertEqual(first["reference"], "")

    def test_a_merge_records_the_parents_it_chose_among(self) -> None:
        plan = self.generate(reference=self.commit_url(self.merge))["plan"]
        provenance = plan["source_provenance"]

        self.assertEqual(provenance["merge_parents"], [self.linear_fix, self.release_side])
        self.assertEqual(provenance["chosen_parent"], 2)
        self.assertEqual(
            [item["position"] for item in provenance["parent_match"]], [1, 2]
        )
        self.assertGreater(provenance["parent_match"][1]["match"], provenance["parent_match"][0]["match"])

    def test_the_provenance_survives_json(self) -> None:
        """It is written to plan.json and to the validator's copy of it."""
        self.generate(reference=self.commit_url(self.linear_fix))
        written = json.loads((self.root / self.CVE / "plan.json").read_text())
        beside = json.loads((self.root / self.CVE / "validator" / "plan.json").read_text())

        self.assertEqual(written["source_provenance"], beside["source_provenance"])
        self.assertEqual(written["source_provenance"]["resolver"], revisions.CVE_REFERENCE)

    def test_a_vulnerable_only_lab_names_its_resolver_too(self) -> None:
        plan = self.generate(repo=self.URL, vulnerable_ref=self.affected)["plan"]

        self.assertEqual(plan["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
        self.assertEqual(plan["source_provenance"]["resolver"], revisions.EXPLICIT)
        self.assertEqual(
            plan["source_provenance"]["vulnerable_side"], revisions.VULNERABLE_EXPLICIT
        )


class RepoAloneIsRefusedRatherThanDroppedTests(unittest.TestCase):
    """`--repo` on its own was accepted and then thrown away.

    resolve_source honours `repo` only together with `fixed_ref`, so a run
    given a repository and nothing else resolved the CVE record's own commit
    instead -- which may belong to a different repository than the one that
    was named, and the operator was told nothing. closed-auto was given a
    guard for exactly this; the three subcommands that build from source
    were not.
    """

    REPO = "https://github.com/example/widget.git"

    def run_cli(self, *arguments: str) -> tuple[int, str]:
        errors = io.StringIO()
        with mock.patch.object(cli, "generate_source_lab") as generate, \
                mock.patch.object(cli, "run_auto_workflow") as auto, \
                redirect_stderr(errors), redirect_stdout(io.StringIO()):
            code = cli.main(list(arguments))
        generate.assert_not_called()
        auto.assert_not_called()
        return code, errors.getvalue()

    def test_every_source_subcommand_refuses_a_repository_with_no_revision(self) -> None:
        for command in ("auto", "source", "source-all"):
            with self.subTest(command=command):
                code, errors = self.run_cli(command, "CVE-2026-0003", "--repo", self.REPO)
                self.assertEqual(code, 1)
                self.assertIn("--repo names a repository to take a revision from", errors)

    def test_a_revision_with_no_repository_is_refused_as_well(self) -> None:
        """The other half of the same silence: `fixed_ref` alone is dropped too."""
        for command in ("auto", "source", "source-all"):
            with self.subTest(command=command):
                code, errors = self.run_cli(command, "CVE-2026-0003", "--fixed-ref", "a" * 40)
                self.assertEqual(code, 1)
                self.assertIn("--fixed-ref names a revision in a repository", errors)

    def test_a_repository_with_a_vulnerable_revision_is_still_accepted(self) -> None:
        """A vulnerable-only lab is `--repo` with `--vulnerable-ref` and no fix.

        The symmetric check closed-auto uses would have refused this, and it
        is a combination generate_source_lab supports on purpose.
        """
        with mock.patch.object(
            cli, "generate_source_lab", return_value={"ok": True}
        ) as generate, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main([
                "source", "CVE-2026-0003", "--repo", self.REPO,
                "--vulnerable-ref", "a" * 40,
            ])
        self.assertEqual(code, 0)
        generate.assert_called_once()

    def test_neither_flag_is_still_the_ordinary_run(self) -> None:
        with mock.patch.object(
            cli, "generate_source_lab", return_value={"ok": True}
        ) as generate, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["source", "CVE-2026-0003"])
        self.assertEqual(code, 0)
        generate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
