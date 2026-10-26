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

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cvelab import core, policy
from cvelab.autoflow import run_auto_workflow

UNHEALTHY = (
    "Validator startup failed: dependency failed to start: container "
    "cve-2026-12345-vulnerable-1 is unhealthy\n\nCompose diagnostics:\n"
    "docker compose logs --no-color --tail 200:\nvulnerable-1  | Error: listen EADDRINUSE"
)


class StartPeriodTests(unittest.TestCase):
    def test_compose_durations_are_read(self) -> None:
        self.assertEqual(policy.duration_seconds("2s"), 2)
        self.assertEqual(policy.duration_seconds("1m30s"), 90)
        self.assertEqual(policy.duration_seconds("500ms"), 0.5)
        self.assertEqual(policy.duration_seconds(2_000_000_000), 2)
        self.assertIsNone(policy.duration_seconds(None))
        self.assertIsNone(policy.duration_seconds("soon"))

    def test_health_checked_services_get_a_start_period(self) -> None:
        model = {"services": {
            "vulnerable": {"healthcheck": {"test": ["CMD-SHELL", "true"], "interval": "2s", "retries": 30}},
            "patched": {"healthcheck": {"test": ["CMD-SHELL", "true"], "start_period": "30s"}},
            "slow": {"healthcheck": {"test": ["CMD-SHELL", "true"], "start_period": "5m"}},
            "validator": {},
            "disabled": {"healthcheck": {"test": ["NONE"]}},
            "off": {"healthcheck": {"test": ["CMD", "true"], "disable": True}},
        }}
        override = policy.startup_grace_override(model, 120)["services"]
        self.assertEqual(override["vulnerable"], {"healthcheck": {"start_period": "120s"}})
        self.assertEqual(override["patched"], {"healthcheck": {"start_period": "120s"}})
        for name in ("slow", "validator", "disabled", "off"):
            self.assertNotIn(name, override)
        self.assertEqual(policy.startup_grace_override(model, 0), {"services": {}})

    def test_the_grace_setting_is_bounded(self) -> None:
        with mock.patch.dict(os.environ, {"CVELAB_STARTUP_GRACE": ""}):
            self.assertEqual(core.startup_grace(), 120)
        with mock.patch.dict(os.environ, {"CVELAB_STARTUP_GRACE": "0"}):
            self.assertEqual(core.startup_grace(), 0)
        for bad in ("1000", "-1", "two minutes"):
            with mock.patch.dict(os.environ, {"CVELAB_STARTUP_GRACE": bad}), self.assertRaises(ValueError):
                core.startup_grace()


class StartupRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = self.root / "CVE-2026-12345"
        self.generated = {"ok": True, "status": "GENERATED_UNVALIDATED", "lab_dir": str(self.lab), "plan": {}}
        self.repaired = {"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}}

    def run_flow(self, outcomes: list, max_attempts: int = 3, limit: str | None = None):
        env = {} if limit is None else {"CVELAB_STARTUP_REPAIRS": limit}
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

    def test_a_startup_failure_is_repaired_without_spending_an_attempt(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, run, repair = self.run_flow([RuntimeError(UNHEALTHY), passed])

        self.assertTrue(result["ok"])
        self.assertEqual(run.call_count, 2)
        repair.assert_called_once()
        failure = repair.call_args.args[2]
        self.assertEqual(failure["kind"], "startup_failure")
        self.assertIn("did not become healthy", failure["hint"])
        self.assertIn("EADDRINUSE", failure["error"])
        self.assertEqual(result["automation"]["validation_attempts"], 1)
        self.assertEqual(result["automation"]["repair_calls"], 0)
        phases = [attempt["phase"] for attempt in result["automation"]["attempts"]]
        self.assertEqual(phases[:3], ["generation", "startup", "startup_repair"])

    def test_startup_repairs_are_capped_and_the_run_still_ends(self) -> None:
        result, run, repair = self.run_flow([RuntimeError(UNHEALTHY)] * 10, max_attempts=2, limit="1")

        self.assertFalse(result["ok"])
        # One free startup repair, then the ordinary path: two validations
        # and the one repair a budget of two allows.
        self.assertEqual(run.call_count, 3)
        self.assertEqual(repair.call_count, 2)
        recorded = json.loads((self.lab / "automation.json").read_text())
        phases = [attempt["phase"] for attempt in recorded["attempts"]]
        self.assertEqual(phases.count("startup_repair"), 1)

    def test_a_proof_failure_is_not_treated_as_a_startup_failure(self) -> None:
        failed = {"ok": False, "report": {"proof_checks": {"vulnerable_confirmed": False}}}
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, _run, repair = self.run_flow([failed, passed])

        self.assertTrue(result["ok"])
        self.assertEqual(repair.call_args.args[2]["kind"], "proof_not_verified")
        self.assertEqual(result["automation"]["repair_calls"], 1)


if __name__ == "__main__":
    unittest.main()
