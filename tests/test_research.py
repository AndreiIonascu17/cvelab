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

from cvelab import research, sourcegen
from cvelab.research import (
    Budget,
    Workspace,
    file_kind,
    fix_index,
    rank_sections,
    render_brief,
    research_fix,
    select_patch,
    split_diff,
    words,
)


def section(path: str, body: str, function: str = "") -> str:
    lines = "".join(f"+{line}\n" for line in body.splitlines())
    return (
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
        f"@@ -1,1 +1,{len(body.splitlines())} @@ {function}\n{lines}"
    )


class SelectPatchTests(unittest.TestCase):
    def test_a_fix_that_fits_is_shown_whole_and_in_order(self) -> None:
        diff = section("b.c", "x") + section("a.c", "y")
        patch, ordered = select_patch(diff, set(), set(), budget=10000)
        self.assertEqual(patch, diff)
        self.assertEqual(ordered, ["b.c", "a.c"])

    def test_the_half_of_a_shared_fix_the_cve_names_is_shown(self) -> None:
        # The shape of the PHP fix that covered two CVEs: dozens of files
        # under Zend/ come first in path order, and the CVE's own half sits
        # in ext/session/, past any cut made in that order.
        diff = "".join(section(f"Zend/zend_file{n:02}.c", "zend_alloc noise\n" * 40) for n in range(40))
        diff += section("ext/session/session.c", "php_session_reset stale state\n" * 5)
        described = words("A stale session state survives into the next request in php_session_reset")
        patch, ordered = select_patch(diff, described, set(), budget=len(diff) // 4)
        self.assertIn("ext/session/session.c", patch)
        self.assertEqual(ordered[0], "ext/session/session.c")
        self.assertIn("this fix changes 41 files", patch)

    def test_a_hint_outranks_the_cve_text(self) -> None:
        diff = section("src/parser.c", "parser parser\n" * 30) + section("src/cookie.c", "cookie\n" * 30)
        _, ordered = select_patch(diff, words("parser bug"), words("cookie"), budget=200)
        self.assertEqual(ordered[0], "src/cookie.c")

    def test_code_comes_before_tests_and_documentation(self) -> None:
        sections = split_diff(
            section("docs/guide.md", "x") + section("tests/test_a.py", "x") + section("lib/a.py", "x")
        )
        order = rank_sections(sections, set(), set())
        self.assertEqual([sections[index][0] for index in order], ["lib/a.py", "tests/test_a.py", "docs/guide.md"])

    def test_file_kinds(self) -> None:
        self.assertEqual(file_kind("src/main.c"), 0)
        self.assertEqual(file_kind("tests/x.c"), 1)
        self.assertEqual(file_kind("pkg/thing_test.go"), 1)
        self.assertEqual(file_kind("NEWS"), 2)
        self.assertEqual(file_kind("docs/a.txt"), 2)


class FixIndexTests(unittest.TestCase):
    def test_each_file_has_its_kind_size_and_functions(self) -> None:
        sections = split_diff(section("ext/session/session.c", "a\nb", "PHP_FUNCTION(session_start)"))
        index = fix_index(sections, [0], 10000)
        self.assertIn("code +2 -0 ext/session/session.c  in: PHP_FUNCTION(session_start)", index)

    def test_a_long_index_says_what_it_left_out(self) -> None:
        sections = split_diff("".join(section(f"f{n}.c", "x") for n in range(50)))
        index = fix_index(sections, list(range(50)), 200)
        self.assertIn("more changed files", index)
        self.assertLess(len(index), 400)

    def test_a_removed_sql_comment_is_counted_as_a_removed_line(self) -> None:
        text = (
            "diff --git a/a.sql b/a.sql\n--- a/a.sql\n+++ b/a.sql\n@@ -1,1 +0,0 @@\n"
            "--- a comment that started with two dashes\n"
        )
        self.assertIn("+0 -1 a.sql", fix_index(split_diff(text), [0], 1000))


class WorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.vulnerable = base / "vulnerable"
        self.fixed = base / "fixed"
        for root in (self.vulnerable, self.fixed):
            (root / "ext" / "session").mkdir(parents=True)
            (root / "ext" / "session" / "session.c").write_text(
                "".join(f"line {n} session_start\n" if n % 100 == 0 else f"line {n}\n" for n in range(1, 1001))
            )
            (root / "ext" / "session" / "config.m4").write_text("PHP_ARG_ENABLE(session)\n")
            (root / "blob.bin").write_bytes(b"session_start\0binary")
        (base / "secret.txt").write_text("outside the repository\n")
        self.git = mock.Mock(return_value="@@ diff text @@")
        self.workspace = Workspace(
            base / "cache", "aaa^", "aaa",
            {"vulnerable": self.vulnerable, "fixed": self.fixed},
            ["ext/session/session.c"], self.git,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def ask(self, **request) -> str:
        defaults = {"kind": "file", "revision": "fixed", "path": "", "query": None,
                    "start_line": None, "end_line": None}
        return self.workspace.answer({**defaults, **request}, 100000)

    def test_a_file_range_comes_back_numbered(self) -> None:
        text = self.ask(path="ext/session/session.c", start_line=99, end_line=101)
        self.assertIn("lines 99-101 of 1000", text)
        self.assertIn("   100  line 100 session_start", text)
        self.assertNotIn("line 102", text)

    def test_a_file_without_a_range_is_cut_at_400_lines(self) -> None:
        text = self.ask(path="./ext/session/session.c")
        self.assertIn("lines 1-400 of 1000", text)

    def test_reading_outside_the_repository_is_refused(self) -> None:
        self.assertIn("may not contain ..", self.ask(path="../secret.txt"))
        (self.fixed / "escape").symlink_to(Path(self.temporary.name) / "secret.txt")
        self.assertIn("leaves the repository", self.ask(path="escape"))
        # A leading slash is the repository root, not the machine's.
        self.assertIn("no such file", self.ask(path="/etc/passwd"))

    def test_binary_files_and_directories_are_refused(self) -> None:
        self.assertIn("binary file", self.ask(path="blob.bin"))
        self.assertIn("use list", self.ask(path="ext"))

    def test_search_is_literal_and_skips_binary_files(self) -> None:
        text = self.ask(kind="search", query="session_start", path="")
        self.assertIn("10 matching lines in 1 files", text)
        self.assertIn("ext/session/session.c:100: line 100 session_start", text)
        self.assertNotIn("blob.bin", text)
        self.assertIn("0 matching lines", self.ask(kind="search", query="session.start"))

    def test_search_can_be_limited_to_a_directory(self) -> None:
        self.assertIn("1 matching lines", self.ask(kind="search", query="PHP_ARG", path="ext/session"))
        self.assertIn("needs a query", self.ask(kind="search", query=" "))

    def test_list_shows_directories_first(self) -> None:
        text = self.ask(kind="list", path="")
        self.assertLess(text.index("ext/"), text.index("blob.bin"))
        self.assertIn("ext/  (1 entries)", text)

    def test_a_diff_is_asked_of_git_for_changed_files_only(self) -> None:
        self.assertIn("not a file this fix changes", self.ask(kind="diff", path="ext/session/config.m4"))
        self.git.assert_not_called()
        text = self.ask(kind="diff", path="ext/session/session.c")
        self.assertIn("@@ diff text @@", text)
        arguments = self.git.call_args.args[0]
        self.assertEqual(arguments[:2], ["--literal-pathspecs", "diff"])
        self.assertIn("--function-context", arguments)
        self.assertEqual(arguments[-5:], ["--end-of-options", "aaa^", "aaa", "--", "ext/session/session.c"])

    def test_without_a_fix_the_vulnerable_tree_answers(self) -> None:
        workspace = Workspace(Path("."), "v", None, {"vulnerable": self.vulnerable}, [], self.git)
        request = {"kind": "file", "revision": "fixed", "path": "ext/session/config.m4",
                   "query": None, "start_line": None, "end_line": None}
        self.assertIn("this is the vulnerable one", workspace.answer(request, 10000))
        self.assertIn("no diff", workspace.answer({**request, "kind": "diff"}, 10000))

    def test_an_answer_is_cut_to_its_limit(self) -> None:
        request = {"kind": "file", "revision": "fixed", "path": "ext/session/session.c",
                   "query": None, "start_line": None, "end_line": None}
        self.assertLessEqual(len(self.workspace.answer(request, 500)), 500)


def answer(analysis: str = "a", requests: list | None = None, done: bool = True) -> dict:
    return {"analysis": analysis, "build_notes": "b", "requests": requests or [], "done": done}


def file_request(path: str, start: int | None = None) -> dict:
    return {"kind": "file", "revision": "fixed", "path": path, "query": None,
            "start_line": start, "end_line": None}


class ResearchLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = mock.Mock(spec=Workspace)
        self.workspace.vulnerable = "v"
        self.workspace.fixed = "f"
        self.workspace.changed = {"a.c"}
        self.workspace.answer.side_effect = lambda request, limit: f"### {request['path']}\nbody\n"[:limit]

    def run_loop(self, answers: list[dict], **extra) -> tuple[dict, list[dict]]:
        calls = []

        def fake(**kwargs):
            calls.append(kwargs)
            return answers[len(calls) - 1]

        options = {
            "cve": "CVE-2026-0001", "dossier": {"cve": "CVE-2026-0001"}, "hint": None,
            "workspace": self.workspace, "index": "code +1 -0 a.c", "preview": "diff",
            "overview": "### list", "budget": research.HOSTED, "rounds": 3,
            "api_key": "k", "model": "m", "provider": "anthropic", **extra,
        }
        with mock.patch.object(research, "structured_response", side_effect=fake):
            return research_fix(**options), calls

    def test_it_reads_what_was_asked_and_stops_when_done(self) -> None:
        brief, calls = self.run_loop([
            answer("first", [file_request("a.c")], done=False),
            answer("second, having read a.c"),
        ])
        self.assertEqual(len(calls), 2)
        self.assertEqual(brief["rounds"], 2)
        self.assertEqual(brief["analysis"], "second, having read a.c")
        self.assertEqual([item["answer"] for item in brief["material"]], ["### a.c\nbody\n"])
        self.assertIn("### a.c\nbody", calls[1]["input_text"])
        self.assertIn("YOUR BRIEF SO FAR", calls[1]["input_text"])
        self.assertEqual(calls[0]["schema_name"], "cvelab_fix_research")

    def test_the_rounds_are_bounded_and_the_last_requests_still_answered(self) -> None:
        brief, calls = self.run_loop(
            [answer(str(n), [file_request(f"f{n}.c")], done=False) for n in range(3)]
        )
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(brief["material"]), 3)

    def test_a_repeated_request_is_not_read_twice_and_ends_the_loop(self) -> None:
        brief, calls = self.run_loop([
            answer("1", [file_request("a.c")], done=False),
            answer("2", [file_request("a.c")], done=False),
            answer("3"),
        ])
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(brief["material"]), 1)

    def test_requests_beyond_the_round_limit_are_ignored(self) -> None:
        brief, _ = self.run_loop([answer("1", [file_request(f"f{n}.c") for n in range(30)])])
        self.assertEqual(len(brief["material"]), research.HOSTED.requests)

    def test_a_spent_budget_refuses_instead_of_reading(self) -> None:
        tight = Budget(record=100, overview=100, index=100, preview=100, answer=100, round=100,
                       material=10, brief=100, requests=5)
        brief, _ = self.run_loop(
            [answer("1", [file_request("a.c"), file_request("b.c")])], budget=tight
        )
        self.assertIn("research budget is spent", brief["material"][1]["answer"])

    def test_a_repair_extends_the_brief_with_the_failure_in_view(self) -> None:
        prior = {"analysis": "old", "build_notes": "old", "rounds": 2,
                 "material": [{"request": file_request("a.c"), "answer": "### a.c\nold\n"}]}
        brief, calls = self.run_loop(
            [answer("new", [file_request("a.c"), file_request("config.m4")])],
            situation="configure: error: session support missing", prior=prior,
        )
        self.assertEqual(brief["rounds"], 3)
        self.assertEqual([item["request"]["path"] for item in brief["material"]], ["a.c", "config.m4"])
        self.assertIn("--- SITUATION ---\nconfigure: error", calls[0]["input_text"])
        self.assertIn("A lab built from an earlier brief failed", calls[0]["instructions"])


class BriefTests(unittest.TestCase):
    def brief(self) -> dict:
        return {
            "cve": "CVE-2026-0001", "revisions": {"vulnerable": "v", "patched": "f"}, "hint": None,
            "analysis": "The session half.", "build_notes": "--enable-session", "rounds": 2,
            "material": [
                {"request": {}, "answer": "### old\n" + "x" * 3000},
                {"request": {}, "answer": "### new\n" + "y" * 3000},
            ],
        }

    def test_it_renders_within_its_limit_and_keeps_the_newest(self) -> None:
        text = render_brief(self.brief(), 4500)
        self.assertLessEqual(len(text), 4500)
        self.assertIn("The session half.", text)
        self.assertIn("### new", text)
        self.assertNotIn("### old", text)
        self.assertIn("1 earlier answers omitted", text)

    def test_it_is_saved_and_matched_to_its_lab(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            research.save(Path(temporary), self.brief())
            loaded = research.load(Path(temporary))
        self.assertTrue(research.matches(loaded, "CVE-2026-0001", "v", "f", None))
        self.assertFalse(research.matches(loaded, "CVE-2026-0001", "v", "f", "a hint"))
        self.assertFalse(research.matches(loaded, "CVE-2026-0001", "v", "other", None))
        self.assertIsNone(research.load(Path("/nonexistent")))

    def test_settings_are_checked(self) -> None:
        self.assertEqual(research.research_mode(None), "auto")
        self.assertEqual(research.research_mode("OFF"), "off")
        with self.assertRaisesRegex(ValueError, "auto, on, off"):
            research.research_mode("sometimes")
        with mock.patch.dict(os.environ, {"CVELAB_RESEARCH_ROUNDS": "0"}):
            with self.assertRaisesRegex(ValueError, "between 1 and 10"):
                research.research_rounds()
        with mock.patch.dict(os.environ, {"CVELAB_CONTEXT_CHARS": "900000"}):
            self.assertEqual(research.prompt_budget(False), 900000)
        self.assertEqual(research.prompt_budget(True), 60000)


VALIDATOR = " ".join([
    "attack_executed", "proof_quality", "observable_effect", "evidence_type", "vulnerable",
    "patched", "differential_confirmed", "confirmed", "blocked", "CVELAB_MANUAL_ACTION",
    "CVELAB_TARGET", "exploit", "verify",
])
COMPOSE = """services:
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


def generation(adapter: list[dict]) -> dict:
    return {
        "cwe": "CWE-384", "confidence": 0.5, "rationale": "r",
        "fidelity": {
            "execution_level": "source_component", "vendor_product_started": False,
            "exercised_vendor_components": ["session"], "simulated_components": [], "rationale": "r",
        },
        "exploit_contract": {
            "attack_summary": "a", "preconditions": [], "observable_effect": "e",
            "evidence_type": "data_exposure",
        },
        "docker_compose": COMPOSE, "dockerignore": "", "vulnerable_dockerfile": "FROM scratch\n",
        "patched_dockerfile": "FROM scratch\n", "validator_dockerfile": "FROM scratch\n",
        "validator_py": VALIDATOR, "support_services": [], "adapter_files": adapter,
    }


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
class SourceLabResearchTests(unittest.TestCase):
    """generate_source_lab and repair_source_lab with a real repository and a fake model."""

    URL = "https://github.com/example/widget.git"
    CVE = "CVE-2026-0001"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        cache = self.root / ".source-cache" / hashlib.sha256(self.URL.encode()).hexdigest()[:16]
        cache.mkdir(parents=True)
        git(cache, "init", "-q")
        (cache / "ext" / "session").mkdir(parents=True)
        (cache / "ext" / "session" / "session.c").write_text("int session_start(void) { return 0; }\n")
        (cache / "ext" / "session" / "config.m4").write_text("PHP_ARG_ENABLE(session)\n")
        git(cache, "add", "-A")
        git(cache, "commit", "-qm", "affected")
        (cache / "ext" / "session" / "session.c").write_text(
            "int session_start(void) { php_session_reset(); return 0; }\n"
        )
        git(cache, "commit", "-qam", "fix")
        self.fixed = git(cache, "rev-parse", "HEAD")
        self.calls: list[dict] = []
        real_git = sourcegen._run_git

        def offline_git(arguments, cwd=None, binary=False):
            if arguments[0] in {"clone", "fetch"}:
                return ""
            return real_git(arguments, cwd=cwd, binary=binary)

        dossier = {"cve": self.CVE, "descriptions": ["stale session state"], "references": []}
        self.patches = [
            mock.patch.object(sourcegen, "_run_git", side_effect=offline_git),
            mock.patch.object(sourcegen, "collect_cve", return_value=dossier),
            mock.patch.object(sourcegen, "resolve_source", return_value=(self.URL, self.fixed)),
            mock.patch.object(sourcegen, "_enforce_compose_policy"),
            mock.patch.object(sourcegen.releases, "find_releases", return_value=[]),
            mock.patch.object(sourcegen, "structured_response", side_effect=self.model),
            mock.patch.object(research, "structured_response", side_effect=self.model),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in self.patches:
            patcher.stop()
        self.temporary.cleanup()

    def model(self, **kwargs) -> dict:
        self.calls.append(kwargs)
        if kwargs["schema_name"] == "cvelab_fix_research":
            if "SITUATION" in kwargs["input_text"]:
                return answer("The build lacked --enable-session.", [{
                    "kind": "file", "revision": "vulnerable", "path": "ext/session/config.m4",
                    "query": None, "start_line": None, "end_line": None,
                }])
            if "SOURCE YOU ASKED FOR" not in kwargs["input_text"]:
                return answer("Looking for callers.", [{
                    "kind": "search", "revision": "fixed", "path": "", "query": "session_start",
                    "start_line": None, "end_line": None,
                }], done=False)
            return answer("The session half of the fix.")
        return generation([{"path": "adapter/app/main.py", "content": "print('lab')\n"}])

    def generate(self, **options) -> dict:
        return sourcegen.generate_source_lab(
            self.CVE, self.root, None, None, None, "key", "model", "anthropic", None, **options
        )

    def research_calls(self) -> list[dict]:
        return [call for call in self.calls if call["schema_name"] == "cvelab_fix_research"]

    def test_research_feeds_the_generation_and_is_recorded(self) -> None:
        result = self.generate(research_mode="on")
        lab = self.root / self.CVE
        self.assertEqual(len(self.research_calls()), 2)
        brief = json.loads((lab / "research.json").read_text())
        self.assertEqual(brief["analysis"], "The session half of the fix.")
        self.assertIn("ext/session/session.c:1: int session_start", brief["material"][0]["answer"])
        prompt = self.calls[-1]["input_text"]
        self.assertIn("--- RESEARCH BRIEF ---", prompt)
        self.assertIn("The session half of the fix.", prompt)
        self.assertIn("ext/session/session.c:1:", prompt)
        self.assertEqual(result["plan"]["generation"]["research"], {"rounds": 2, "requests": 1, "file": "research.json"})
        self.assertTrue((lab / "adapter" / "app" / "main.py").is_file())
        self.assertTrue((lab / "source" / ".patched.revision").is_file())

    def test_a_retry_reuses_the_brief_and_off_skips_research(self) -> None:
        self.generate(research_mode="on")
        before = len(self.research_calls())
        self.generate(research_mode="on", generation_feedback=["compose was refused"])
        self.assertEqual(len(self.research_calls()), before)
        self.assertIn("--- RESEARCH BRIEF ---", self.calls[-1]["input_text"])
        result = self.generate(research_mode="off")
        self.assertEqual(len(self.research_calls()), before)
        self.assertNotIn("research", result["plan"]["generation"])

    def test_a_small_fix_is_not_researched_by_default(self) -> None:
        self.generate()
        self.assertEqual(self.research_calls(), [])

    def test_a_repair_researches_its_failure(self) -> None:
        self.generate(research_mode="on")
        lab = self.root / self.CVE
        (lab / "adapter" / "old" ).mkdir()
        (lab / "adapter" / "old" / "stale.js").write_text("stale\n")
        failure = {"kind": "runtime_error", "error": "configure: error: session support missing"}
        result = sourcegen.repair_source_lab(self.CVE, self.root, failure, 1, "key", "model", "anthropic", None)
        repair_research = self.research_calls()[-1]
        self.assertIn("session support missing", repair_research["input_text"])
        prompt = self.calls[-1]["input_text"]
        self.assertIn("The build lacked --enable-session.", prompt)
        self.assertIn("PHP_ARG_ENABLE(session)", prompt)
        self.assertIn("adapter/app/main.py", prompt)
        self.assertEqual(result["plan"]["generation"]["research"]["rounds"], 3)
        self.assertFalse((lab / "adapter" / "old").exists())


class AdapterTreeTests(unittest.TestCase):
    def test_repair_material_reads_nested_files_within_its_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary)
            (lab / "adapter" / "app" / "lib").mkdir(parents=True)
            (lab / "adapter" / "app" / "lib" / "a.js").write_text("a" * 100)
            (lab / "adapter" / "app" / "z.js").write_text("z" * 100)
            material = sourcegen._repair_material(lab, limit=150)
        self.assertEqual(material["adapter/app/lib/a.js"], "a" * 100)
        self.assertIn("omitted", material["adapter/app/z.js"])

    def test_stale_files_go_at_any_depth_and_new_ones_stay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary)
            (lab / "adapter" / "old" / "deep").mkdir(parents=True)
            (lab / "adapter" / "old" / "deep" / "x.py").write_text("x")
            (lab / "adapter" / "keep.py").write_text("k")
            sourcegen._remove_stale_adapter_files(lab, {"adapter/keep.py"})
            self.assertFalse((lab / "adapter" / "old").exists())
            self.assertTrue((lab / "adapter" / "keep.py").is_file())


class SourceContextTests(unittest.TestCase):
    def test_build_files_are_sampled_before_a_long_tree(self) -> None:
        tree = [f".github/workflows/w{n}.yml" for n in range(600)] + ["ext/session/config.m4", "configure.ac"]
        sample = sourcegen._tree_sample(tree, ["ext/session/session.c"], limit=50)
        self.assertEqual(len(sample), 50)
        self.assertIn("ext/session/config.m4", sample)
        self.assertIn("configure.ac", sample)

    def test_a_context_under_its_limit_is_not_cut(self) -> None:
        excerpt = "x" * 9000
        diff = section("a.c", "y")
        with mock.patch.object(sourcegen, "_run_git", return_value=excerpt):
            context = sourcegen._source_context(
                Path("."), "v", "f", {}, max_chars=100000, listing=(diff, ["a.c"], ["a.c"])
            )
        self.assertIn(excerpt, context)


if __name__ == "__main__":
    unittest.main()
