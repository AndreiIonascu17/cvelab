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
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cvelab.autoflow import run_auto_workflow
from cvelab.core import CVERecordNotFound


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

    def test_missing_cve_record_is_not_retried(self) -> None:
        # The record is missing at CVE.org and at GitHub: a second request
        # gets the same answer, so the run stops after one attempt.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch(
                "cvelab.autoflow.generate_source_lab",
                side_effect=CVERecordNotFound("CVE API returned HTTP 404 for CVE-2026-12345"),
            ) as generate:
                result = run_auto_workflow(
                    "CVE-2026-12345", root, None, None, None,
                    "key", "model", False, max_attempts=4, progress=lambda _: None,
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


class AValidatedLabThatShippedNoKitSaysSoTests(unittest.TestCase):
    """The status `create_deliverables` returns, which nothing used to read.

    VALIDATED is written to automation.json before the deliverables are
    attempted, and the call's result was dropped into the returned dict
    without being looked at. So when the deliverables gate took its refusal
    path, the run recorded a validated lab, printed a line reading as
    completion, and returned with nothing in artifacts/ -- measured as 40
    labs in one benchmark tree against 89 with a kit. The gate that caused
    it is fixed; this is about the silence, which would hide the next cause
    just as well.
    """

    CVE = "CVE-2026-12345"

    REFUSED = {
        "ok": False,
        "status": "POC_NOT_VERIFIED",
        "reason": "The real vulnerable source path did not produce a verified security effect.",
    }

    def auto(self, delivered: dict) -> tuple[dict, list[str], dict]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        lab = root / self.CVE
        generated = {
            "ok": True,
            "status": "GENERATED_UNVALIDATED",
            "lab_dir": str(lab),
            "plan": {},
        }
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        lines: list[str] = []
        with (
            mock.patch("cvelab.autoflow.generate_source_lab", return_value=generated),
            mock.patch("cvelab.autoflow.run_lab", return_value=passed),
            mock.patch("cvelab.autoflow.create_deliverables", return_value=delivered),
        ):
            result = run_auto_workflow(
                self.CVE, root, None, None, None,
                "key", "model", False, max_attempts=1, progress=lines.append,
            )
        return result, lines, json.loads((lab / "automation.json").read_text("utf-8"))

    def test_the_operator_is_told_the_kit_is_missing(self) -> None:
        _result, lines, _record = self.auto(self.REFUSED)

        said = "\n".join(lines)
        self.assertIn("validated, but no deliverables were written", said)
        self.assertIn("POC_NOT_VERIFIED", said)
        self.assertIn("no PoC, manual kit, report, or walkthrough", said)

    def test_the_record_keeps_the_contradiction(self) -> None:
        """automation.json is the file a batch operator reads afterwards, and
        the only place the two halves of this can be compared: the status the
        validation earned, and the kit that was not written for it.

        The status stays VALIDATED on purpose. The lab reproduced, which is
        what the word records; what is corrected is the impression that a
        deliverable exists, so that lands in the failure slot beside it.
        """
        _result, _lines, record = self.auto(self.REFUSED)

        self.assertEqual(record["status"], "VALIDATED")
        self.assertEqual(record["failure"]["kind"], "deliverables_not_written")
        self.assertEqual(record["failure"]["status"], "POC_NOT_VERIFIED")
        self.assertIn("verified security effect", record["failure"]["reason"])

    def test_a_run_that_shipped_its_kit_records_no_gap(self) -> None:
        delivered = {"ok": True, "status": "REAL_SOURCE_POC_VALIDATED", "deliverables": {}}

        result, lines, record = self.auto(delivered)

        self.assertTrue(result["ok"])
        self.assertEqual(record["status"], "VALIDATED")
        self.assertNotIn("failure", record)
        self.assertNotIn("no deliverables were written", "\n".join(lines))

    def test_the_verified_line_no_longer_speaks_for_the_kit(self) -> None:
        """It is printed before `create_deliverables` is called -- it cannot
        know -- so it says what the run measured and that the kit is next.
        """
        _result, lines, _record = self.auto(self.REFUSED)

        verified = [line for line in lines if "manual PoC verified" in line]
        self.assertEqual(len(verified), 1, lines)
        self.assertTrue(verified[0].endswith("writing the deliverables"), verified)


if __name__ == "__main__":
    unittest.main()
