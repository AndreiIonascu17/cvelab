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

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cvelab.autoflow import _validator_only_failure, run_auto_workflow


class AutonomousWorkflowTests(unittest.TestCase):
    def test_generation_retry_receives_preflight_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lab = root / "CVE-2026-12345"
            generated = {
                "ok": True,
                "status": "GENERATED_UNVALIDATED",
                "lab_dir": str(lab),
                "plan": {},
            }
            passed = {"ok": True, "report": {"proof_checks": {}}}
            with (
                mock.patch(
                    "cvelab.autoflow.generate_source_lab",
                    side_effect=[RuntimeError("Compose network must be internal"), generated],
                ) as generate,
                mock.patch("cvelab.autoflow.run_lab", return_value=passed),
                mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
            ):
                result = run_auto_workflow(
                    "CVE-2026-12345", root, None, None, None,
                    "key", "model", False, max_attempts=3, progress=lambda _: None,
                )

            self.assertTrue(result["ok"])
            self.assertEqual(generate.call_count, 2)
            self.assertEqual(
                generate.call_args_list[1].args[-1],
                ["Compose network must be internal"],
            )

    def test_anthropic_bad_request_is_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch(
                "cvelab.autoflow.generate_source_lab",
                side_effect=RuntimeError("Anthropic API HTTP 400: invalid schema"),
            ) as generate:
                result = run_auto_workflow(
                    "CVE-2026-12345", root, None, None, None,
                    "key", "model", False, max_attempts=4, progress=lambda _: None,
                    provider="anthropic",
                )

            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "AUTO_GENERATION_FAILED")
            self.assertEqual(generate.call_count, 1)
            self.assertEqual(len(result["attempts"]), 1)

    def test_failed_proof_is_repaired_and_revalidated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lab = root / "CVE-2026-12345"
            generated = {
                "ok": True,
                "status": "GENERATED_UNVALIDATED",
                "lab_dir": str(lab),
                "plan": {"fidelity": {"execution_level": "source_component"}},
            }
            failed = {
                "ok": False,
                "report": {
                    "proof_checks": {"vulnerable_confirmed": False},
                    "validation": {"error": "canary was not observed"},
                },
            }
            passed = {
                "ok": True,
                "report": {"proof_checks": {"manual_poc_verified": True}},
            }

            with (
                mock.patch("cvelab.autoflow.generate_source_lab", return_value=generated),
                mock.patch("cvelab.autoflow.run_lab", side_effect=[failed, passed]) as run,
                mock.patch(
                    "cvelab.autoflow.repair_source_lab",
                    return_value={"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": generated["plan"]},
                ) as repair,
                mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
            ):
                result = run_auto_workflow(
                    "CVE-2026-12345", root, None, None, None,
                    "key", "model", False, max_attempts=3, progress=lambda _: None,
                )

            self.assertTrue(result["ok"])
            self.assertEqual(run.call_count, 2)
            repair.assert_called_once()
            self.assertEqual(repair.call_args.args[2]["failed_checks"], ["vulnerable_confirmed"])
            self.assertEqual(result["automation"]["repair_calls"], 1)
            self.assertTrue((lab / "automation.json").is_file())

    def test_docker_infrastructure_error_retries_without_ai_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lab = root / "CVE-2026-12345"
            generated = {
                "ok": True,
                "status": "GENERATED_UNVALIDATED",
                "lab_dir": str(lab),
                "plan": {},
            }
            with (
                mock.patch("cvelab.autoflow.generate_source_lab", return_value=generated),
                mock.patch(
                    "cvelab.autoflow.run_lab",
                    side_effect=RuntimeError("Cannot connect to the Docker daemon"),
                ) as run,
                mock.patch("cvelab.autoflow.repair_source_lab") as repair,
            ):
                result = run_auto_workflow(
                    "CVE-2026-12345", root, None, None, None,
                    "key", "model", False, max_attempts=2, progress=lambda _: None,
                )

            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "AUTO_REPAIR_EXHAUSTED")
            self.assertEqual(run.call_count, 2)
            repair.assert_not_called()

    def test_contradictory_patched_verdict_uses_focused_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lab = root / "CVE-2026-12345"
            generated = {
                "ok": True,
                "status": "GENERATED_UNVALIDATED",
                "lab_dir": str(lab),
                "plan": {},
            }
            failed = {
                "ok": False,
                "report": {
                    "proof_checks": {
                        "source_reproduction": True,
                        "contract_effect_defined": True,
                        "contract_evidence_defined": True,
                        "attack_executed": True,
                        "observable_effect_recorded": True,
                        "evidence_type_matches": True,
                        "security_effect_observed": True,
                        "vulnerable_confirmed": True,
                        "vulnerable_raw_recorded": True,
                        "patched_not_confirmed": False,
                        "patched_blocked": True,
                        "patched_raw_recorded": True,
                        "manual_poc_verified": False,
                    },
                    "validation": {
                        "patched": {"confirmed": True, "blocked": True},
                    },
                },
            }
            passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
            with (
                mock.patch("cvelab.autoflow.generate_source_lab", return_value=generated),
                mock.patch("cvelab.autoflow.run_lab", side_effect=[failed, passed]),
                mock.patch("cvelab.autoflow.repair_validator_verdict", return_value={
                    "ok": True, "status": "VALIDATOR_REPAIRED_UNVALIDATED", "plan": {},
                }) as focused,
                mock.patch("cvelab.autoflow.repair_source_lab") as full,
                mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
            ):
                result = run_auto_workflow(
                    "CVE-2026-12345", root, None, None, None,
                    "key", "model", False, max_attempts=3, progress=lambda _: None,
                )

            self.assertTrue(result["ok"])
            focused.assert_called_once()
            full.assert_not_called()
            self.assertEqual(result["automation"]["repair_calls"], 1)

    def test_missing_raw_evidence_uses_focused_repair(self) -> None:
        failure = {
            "kind": "proof_not_verified",
            "report": {
                "proof_checks": {
                    "source_reproduction": True,
                    "contract_effect_defined": True,
                    "contract_evidence_defined": True,
                    "attack_executed": True,
                    "observable_effect_recorded": True,
                    "evidence_type_matches": True,
                    "security_effect_observed": True,
                    "vulnerable_confirmed": True,
                    "vulnerable_raw_recorded": False,
                    "patched_not_confirmed": False,
                    "patched_blocked": True,
                    "patched_raw_recorded": True,
                },
                "validation": {"patched": {"confirmed": True, "blocked": True}},
            },
        }
        self.assertTrue(_validator_only_failure(failure))

    def test_wrong_proof_quality_uses_focused_repair(self) -> None:
        failure = {
            "kind": "proof_not_verified",
            "report": {
                "proof_checks": {
                    "source_reproduction": True,
                    "contract_effect_defined": True,
                    "contract_evidence_defined": True,
                    "attack_executed": True,
                    "observable_effect_recorded": True,
                    "evidence_type_matches": True,
                    "vulnerable_confirmed": True,
                    "vulnerable_raw_recorded": True,
                    "patched_not_confirmed": True,
                    "patched_blocked": True,
                    "patched_raw_recorded": True,
                    "security_effect_observed": False,
                    "manual_poc_verified": False,
                },
                "manual_poc_checks": {},
            },
        }
        self.assertTrue(_validator_only_failure(failure))
        failure["report"]["proof_checks"]["security_effect_observed"] = True
        failure["report"]["proof_checks"]["differential_confirmed"] = False
        self.assertTrue(_validator_only_failure(failure))

    def test_failed_focused_repair_escalates_to_full_adapter_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lab = root / "CVE-2026-12345"
            generated = {"ok": True, "lab_dir": str(lab), "plan": {}}
            failed = {
                "ok": False,
                "report": {
                    "proof_checks": {
                        "source_reproduction": True,
                        "contract_effect_defined": True,
                        "contract_evidence_defined": True,
                        "attack_executed": True,
                        "observable_effect_recorded": True,
                        "evidence_type_matches": True,
                        "vulnerable_confirmed": True,
                        "vulnerable_raw_recorded": True,
                        "patched_not_confirmed": True,
                        "patched_blocked": True,
                        "patched_raw_recorded": True,
                        "differential_confirmed": True,
                        "security_effect_observed": False,
                        "manual_poc_verified": False,
                    },
                    "manual_poc_checks": {},
                },
            }
            passed = {"ok": True, "report": {"proof_checks": {}}}
            with (
                mock.patch("cvelab.autoflow.generate_source_lab", return_value=generated),
                mock.patch("cvelab.autoflow.run_lab", side_effect=[failed, failed, passed]),
                mock.patch(
                    "cvelab.autoflow.repair_validator_verdict",
                    return_value={"ok": True, "plan": {}},
                ) as focused,
                mock.patch(
                    "cvelab.autoflow.repair_source_lab",
                    return_value={"ok": True, "plan": {}},
                ) as full,
                mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
            ):
                result = run_auto_workflow(
                    "CVE-2026-12345", root, None, None, None,
                    "key", "model", False, max_attempts=3, progress=lambda _: None,
                )

            self.assertTrue(result["ok"])
            focused.assert_called_once()
            full.assert_called_once()


if __name__ == "__main__":
    unittest.main()
