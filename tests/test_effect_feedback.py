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

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cvelab import core, sourcegen
from cvelab.autoflow import run_auto_workflow

DIFF = (
    "diff --git a/src/core.c b/src/core.c\n--- a/src/core.c\n+++ b/src/core.c\n"
    "@@ -1 +1 @@\n-    if (alias && !valid)\n+    if (alias && (!valid || changed))\n"
    "diff --git a/tests/test_alias.py b/tests/test_alias.py\n--- /dev/null\n+++ b/tests/test_alias.py\n"
    "@@ -0,0 +1,2 @@\n+def test_rewrite_then_alias():\n+    assert get('/foo/1').status == 500\n"
)


class RegressionTestSectionTests(unittest.TestCase):
    def test_tests_the_fix_changes_get_their_own_section(self) -> None:
        section = sourcegen._regression_tests(DIFF, ["src/core.c", "tests/test_alias.py"])
        self.assertIn("--- UPSTREAM REGRESSION TESTS ---", section)
        self.assertIn("def test_rewrite_then_alias", section)
        self.assertNotIn("src/core.c", section)

    def test_no_section_without_a_test(self) -> None:
        self.assertEqual(sourcegen._regression_tests(DIFF, ["src/core.c"]), "")

    def test_the_section_is_capped(self) -> None:
        big = "diff --git a/tests/test_big.py b/tests/test_big.py\n" + "+x = 1\n" * 5000
        section = sourcegen._regression_tests(big, ["tests/test_big.py"], limit=2000)
        self.assertLess(len(section), 2600)
        self.assertIn("[... cut]", section)

    def test_the_section_comes_before_the_patch_and_survives_a_cut(self) -> None:
        listing = (DIFF, ["src/core.c", "tests/test_alias.py"], ["src/core.c", "tests/test_alias.py"])
        with mock.patch.object(sourcegen, "_run_git", return_value="int main(void) { return 0; }\n" * 400):
            whole = sourcegen._source_context(Path("."), "a", "b", {"cve": "CVE-2026-0001"}, listing=listing)
            cut = sourcegen._source_context(Path("."), "a", "b", {"cve": "CVE-2026-0001"}, max_chars=4000, listing=listing)
        for context in (whole, cut):
            self.assertIn("UPSTREAM REGRESSION TESTS", context)
            self.assertLess(context.index("UPSTREAM REGRESSION TESTS"), context.index("--- SECURITY PATCH ---"))


class ServiceLogTests(unittest.TestCase):
    def test_logs_are_redacted_and_keep_the_end(self) -> None:
        secret = "sk-ant-api03-" + "A" * 90
        core.register_secret(secret)  # a run registers the keys it was given
        self.addCleanup(core._SECRETS.discard, secret)
        output = "early line\n" * 2000 + f"key {secret}\nlast line\n"
        finished = mock.Mock(stdout=output, stderr="")
        with mock.patch("cvelab.core.subprocess.run", return_value=finished):
            logs = core._service_logs(["docker", "compose"], ["vulnerable", "patched"], Path("."), {})
        self.assertLessEqual(len(logs), core.SERVICE_LOG_CHARS)
        self.assertTrue(logs.rstrip().endswith("last line"))
        self.assertNotIn(secret, logs)


def failed(reached: bool) -> dict:
    return {"ok": False, "report": {
        "proof_checks": {"attack_executed": reached, "vulnerable_confirmed": False},
        "validation": {"attack_executed": reached, "vulnerable": {"status": 200, "raw": "x" * 5000}, "patched": {"status": 200}},
        "service_logs": "vulnerable-1 | GET /static/canary.txt 200",
    }}


class EffectRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.generated = {"ok": True, "status": "GENERATED_UNVALIDATED", "lab_dir": str(self.root / "CVE-2026-12345"), "plan": {}}
        self.repaired = {"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}}

    def run_flow(self, outcomes: list, max_attempts: int, limit: str | None = None):
        env = {} if limit is None else {"CVELAB_EFFECT_REPAIRS": limit}
        with (
            mock.patch.dict(os.environ, env),
            mock.patch("cvelab.autoflow.generate_source_lab", return_value=self.generated),
            mock.patch("cvelab.autoflow.run_lab", side_effect=outcomes) as run,
            mock.patch("cvelab.autoflow.repair_source_lab", return_value=self.repaired) as repair,
            mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
        ):
            result = run_auto_workflow(
                "CVE-2026-12345", self.root, None, None, None,
                "key", "model", False, max_attempts=max_attempts, progress=lambda _: None,
            )
        return result, run, repair

    def test_the_repair_gets_the_digest_and_the_hint_first(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        _result, _run, repair = self.run_flow([failed(True), passed], max_attempts=3)
        failure = repair.call_args.args[2]
        self.assertEqual(list(failure)[:3], ["hint", "kind", "digest"])
        digest = failure["digest"]
        self.assertEqual(digest["failed_proof_checks"], ["vulnerable_confirmed"])
        self.assertIn("GET /static/canary.txt", digest["service_logs"])
        self.assertIn("more characters", digest["vulnerable"]["raw"])

    def test_no_hint_when_the_input_never_reached_the_services(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        _result, _run, repair = self.run_flow([failed(False), passed], max_attempts=3)
        self.assertNotIn("hint", repair.call_args.args[2])

    def test_a_lab_that_runs_without_the_effect_gets_extra_repairs(self) -> None:
        result, run, repair = self.run_flow([failed(True)] * 10, max_attempts=2, limit="2")
        self.assertFalse(result["ok"])
        self.assertEqual(run.call_count, 4)
        self.assertEqual(repair.call_count, 3)
        self.assertEqual(result["effect_repairs"], 2)

    def test_extra_repairs_can_be_turned_off_and_are_not_given_without_contact(self) -> None:
        _result, run, repair = self.run_flow([failed(True)] * 10, max_attempts=2, limit="0")
        self.assertEqual((run.call_count, repair.call_count), (2, 1))
        _result, run, repair = self.run_flow([failed(False)] * 10, max_attempts=2, limit="2")
        self.assertEqual((run.call_count, repair.call_count), (2, 1))


if __name__ == "__main__":
    unittest.main()
