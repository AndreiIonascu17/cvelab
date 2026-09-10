from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cvelab.autoflow import run_auto_workflow


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


if __name__ == "__main__":
    unittest.main()
