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
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cvelab import upload
from cvelab.deliverables import create_deliverables


class DeliverableContractTests(unittest.TestCase):
    def test_source_lab_gets_uniform_report_evidence_and_manual_kit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary) / "CVE-2099-1000"
            (lab / "validator").mkdir(parents=True)
            plan = {
                "cve": "CVE-2099-1000",
                "cwe": "CWE-1",
                "lab_type": "SOURCE_REPRODUCTION",
                "repository": "https://example.invalid/vendor/project.git",
                "revisions": {"vulnerable": "a" * 40, "patched": "b" * 40},
                "exploit_contract": {
                    "attack_summary": "Send the local canary request.",
                    "preconditions": ["Docker"],
                    "observable_effect": "Protected canary is returned.",
                    "evidence_type": "unauthorized_read",
                },
                "fidelity": {
                    "execution_level": "source_component",
                    "vendor_product_started": False,
                    "exercised_vendor_components": ["vendor parser"],
                    "simulated_components": ["downstream"],
                    "rationale": "The parser is real and the downstream is simulated.",
                },
                "safety": {"target_scope": "internal_docker_network_only"},
            }
            dossier = {"source": "unit-test", "descriptions": ["Test CVE"]}
            (lab / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
            (lab / "dossier.json").write_text(json.dumps(dossier), encoding="utf-8")
            (lab / "validator" / "validator.py").write_text(
                "# CVELAB_MANUAL_ACTION CVELAB_TARGET exploit verify\n",
                encoding="utf-8",
            )
            validation = {
                "attack_executed": True,
                "proof_quality": "security_effect_observed",
                "observable_effect": "Protected canary is returned.",
                "evidence_type": "unauthorized_read",
                "vulnerable": {
                    "confirmed": True,
                    "raw_observations": {"status": 200, "body": "canary"},
                },
                "patched": {
                    "confirmed": False,
                    "blocked": True,
                    "raw_observations": {"status": 403},
                },
                "differential_confirmed": True,
            }
            result = {
                "ok": True,
                "report": {
                    "validated_at": "2099-01-01T00:00:00Z",
                    "validation": validation,
                    "proof_contract": plan["exploit_contract"],
                    "proof_checks": {"vulnerable_confirmed": True},
                    "real_poc_verified": True,
                    "product_e2e_verified": False,
                },
            }

            delivered = create_deliverables("CVE-2099-1000", lab, result)

            self.assertTrue(delivered["ok"])
            for path in delivered["deliverables"].values():
                self.assertTrue(Path(path).is_file(), path)
            report = (lab / "artifacts" / "REPORT.md").read_text(encoding="utf-8")
            self.assertIn('"status": 200', report)
            self.assertIn("Fidelity level: `source_component`", report)
            self.assertIn("Product E2E verified: `False`", report)
            evidence = json.loads((lab / "artifacts" / "EVIDENCE.json").read_text())
            self.assertEqual(evidence["schema_version"], 1)
            self.assertEqual(evidence["validation"], validation)
            self.assert_valid_bash(lab / "artifacts" / "manual.sh")

    def assert_valid_bash(self, script: Path) -> None:
        # Resolved, never the bare name, matching run_shipyard_script: on
        # Windows CreateProcess searches System32 before PATH, so "bash"
        # reaches the WSL launcher stub, which exits 1 with a UTF-16 complaint
        # about having no installed distribution.
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not installed")
        # Fed on stdin rather than by path, because a native Windows path does
        # not survive the boundary into Git Bash. Bytes, not text: subprocess
        # wraps a text-mode stdin in a TextIOWrapper with newline=None, which
        # would rewrite "\n" to os.linesep and hand bash a CRLF script.
        completed = subprocess.run(
            [bash, "-n"],
            input=script.read_bytes(),
            capture_output=True,
        )
        if completed.returncode != 0:
            payload = script.read_bytes()
            has_crlf = b"\r\n" in payload
            self.fail(
                f"generated {script.name} is not valid bash\n"
                f"  bash: {bash!r}\n"
                f"  rc: {completed.returncode}\n"
                f"  stderr: {completed.stderr.decode('utf-8', 'replace').strip()!r}\n"
                f"  stdout: {completed.stdout.decode('utf-8', 'replace').strip()!r}\n"
                f"  bytes: {len(payload)}\n"
                f"  head: {payload[:120]!r}\n"
                f"  has_crlf: {has_crlf}"
            )


#: The sentences a lab with no public fix at all gets, and the one thing none
#: of them may say about a demoted lab: a fixed revision WAS identified, read,
#: and then discarded as unable to serve as a control. Four of these were
#: printed unconditionally on `lab_type`, so a demoted lab's own report
#: asserted the opposite of its own plan.json four times over -- and the
#: instruction among them told the operator to write it down.
_DENIALS = (
    "No public fixed revision was identified",
    "no public fix was identified",
    "No public fix was identified",
    "no public fixed revision identified",
    "Re-run differential validation when a fix becomes public",
)


class ADemotedLabsReportSaysNothingFalseTests(unittest.TestCase):
    """Rendered REPORT.md and WALKTHROUGH.md, not plan.json.

    plan.json was already truthful, through `safety.limitations`, and the
    tests all looked there. The defect lived in the documents built around
    that field, which no test rendered.
    """

    CVE = "CVE-2099-1001"
    REJECTED = "f" * 40
    REASON = (
        "between the vulnerable and the fixed revision nothing the program is built "
        "from changed (README.zh.md); the fixing reference in hand is not the fix, "
        "so resolve it again"
    )

    def deliver(self, demoted: bool) -> tuple[Path, str, str, dict]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab = Path(temporary.name) / self.CVE
        (lab / "validator").mkdir(parents=True)
        plan = {
            "cve": self.CVE,
            "cwe": "CWE-78",
            "lab_type": "VULNERABLE_ONLY_REPRODUCTION",
            "repository": "https://example.invalid/vendor/project.git",
            "revisions": {"vulnerable": "a" * 40, "patched": None},
            "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
            "patched_tested": False,
            "exploit_contract": {
                "attack_summary": "Send the local canary request.",
                "preconditions": ["Docker"],
                "observable_effect": "Protected canary is returned.",
                "evidence_type": "unauthorized_read",
            },
            "fidelity": {
                "execution_level": "source_component",
                "vendor_product_started": False,
                "exercised_vendor_components": ["vendor parser"],
                "simulated_components": [],
                "rationale": "The parser is real.",
            },
            "safety": {
                "target_scope": "internal_docker_network_only",
                "limitations": (
                    f"A fixed revision was resolved and then discarded: {self.REASON}. "
                    "Remediation behavior was not tested."
                    if demoted
                    else "No public fixed revision was identified; remediation behavior "
                    "was not tested."
                ),
            },
        }
        if demoted:
            plan["demotion"] = {"rejected_fixed": self.REJECTED, "reason": self.REASON}
        (lab / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        (lab / "dossier.json").write_text(
            json.dumps({"source": "unit-test", "descriptions": ["Test CVE"]}),
            encoding="utf-8",
        )
        (lab / "validator" / "validator.py").write_text(
            "# CVELAB_MANUAL_ACTION CVELAB_TARGET exploit verify\n", encoding="utf-8"
        )
        validation = {
            "attack_executed": True,
            "proof_quality": "security_effect_observed",
            "observable_effect": "Protected canary is returned.",
            "evidence_type": "unauthorized_read",
            "vulnerable": {"confirmed": True, "raw_observations": {"status": 200}},
            "patched_tested": False,
            "differential_confirmed": False,
        }
        result = {
            "ok": True,
            "report": {
                "validated_at": "2099-01-01T00:00:00Z",
                "validation": validation,
                "proof_contract": plan["exploit_contract"],
                "proof_checks": {"vulnerable_confirmed": True},
                "real_poc_verified": True,
                "product_e2e_verified": False,
            },
        }

        delivered = create_deliverables(self.CVE, lab, result)
        self.assertTrue(delivered["ok"], delivered)
        artifacts = lab / "artifacts"
        return (
            lab,
            (artifacts / "REPORT.md").read_text(encoding="utf-8"),
            (artifacts / "WALKTHROUGH.md").read_text(encoding="utf-8"),
            json.loads((artifacts / "EVIDENCE.json").read_text(encoding="utf-8")),
        )

    def test_neither_document_denies_the_fix_it_discarded(self) -> None:
        _lab, report, walkthrough, _evidence = self.deliver(demoted=True)

        for name, text in (("REPORT.md", report), ("WALKTHROUGH.md", walkthrough)):
            for denial in _DENIALS:
                with self.subTest(document=name, denial=denial):
                    self.assertNotIn(denial, text)

    def test_both_documents_say_what_happened_instead(self) -> None:
        _lab, report, walkthrough, _evidence = self.deliver(demoted=True)

        for name, text in (("REPORT.md", report), ("WALKTHROUGH.md", walkthrough)):
            with self.subTest(document=name):
                self.assertIn("identified and then discarded", text)
                self.assertIn("nothing the program is built from changed", text)
                # The rejected reference itself, so the remedy can be carried
                # out without opening plan.json -- which --no-poc withholds.
                self.assertIn(self.REJECTED, text)

    def test_the_operator_is_not_told_to_write_down_something_untrue(self) -> None:
        """That step is an instruction to the operator, not a report of a fact."""
        _lab, _report, walkthrough, _evidence = self.deliver(demoted=True)

        self.assertIn("4. Record that no patched control was tested", walkthrough)
        self.assertIn("could not serve as one", walkthrough)

    def test_the_remediation_remedy_is_the_one_that_applies(self) -> None:
        """Waiting for a public fix is useless advice when one already exists."""
        _lab, report, _walkthrough, _evidence = self.deliver(demoted=True)

        self.assertIn(
            "Re-run differential validation once the fixing reference resolves to the "
            "commit that carries the fix",
            report,
        )
        self.assertIn("there is nothing to wait for", report)

    def test_the_demotion_survives_into_the_shared_record(self) -> None:
        """EVIDENCE.json, because that is the copy sharing keeps.

        plan.json is in `upload.EXPLOIT`, so `--no-poc` strips it, and
        `upload.collect` sends `fixed_ref` from `revisions.patched`, which is
        correctly null for a demoted lab. Without this the shared record kept
        no trace of the discarded reference at all.
        """
        _lab, _report, _walkthrough, evidence = self.deliver(demoted=True)

        provenance = evidence["provenance"]
        self.assertEqual(provenance["discarded_fixed_revision"], self.REJECTED)
        self.assertEqual(provenance["demotion_reason"], self.REASON)
        self.assertIsNone(provenance["patched_revision"])
        self.assertNotIn("EVIDENCE.json", upload.EXPLOIT)
        self.assertIn("EVIDENCE.json", upload.ALWAYS)
        self.assertIn("plan.json", upload.EXPLOIT)

    def test_a_no_poc_upload_still_carries_the_reason(self) -> None:
        """What a batch operator filing without the exploit actually sends."""
        lab, _report, _walkthrough, _evidence = self.deliver(demoted=True)
        (lab / "artifacts" / "report.json").write_text("{}\n", encoding="utf-8")

        payload = upload.collect(
            lab,
            {"ok": True, "status": "REAL_VULNERABLE_ONLY_POC_VALIDATED"},
            provider="anthropic",
            model="model",
            include_poc=False,
        )

        sent = {document["name"]: document["text"] for document in payload["documents"]}
        self.assertNotIn("plan.json", sent)
        self.assertIn(self.REJECTED, sent["EVIDENCE.json"])
        self.assertIn("identified and then discarded", sent["REPORT.md"])
        # Correctly null, and left that way: no fixed revision was built or
        # tested, so naming the rejected one here would claim one had been.
        self.assertIsNone(payload["fixed_ref"])

    def test_a_lab_with_no_fix_at_all_still_says_so(self) -> None:
        """The other lab wearing the same lab_type must read exactly as before."""
        _lab, report, walkthrough, evidence = self.deliver(demoted=False)

        self.assertIn("No public fixed revision was identified", report)
        self.assertIn("Re-run differential validation when a fix becomes public", report)
        self.assertIn("because no public fix was identified", walkthrough)
        self.assertNotIn("discarded", report)
        self.assertIsNone(evidence["provenance"]["discarded_fixed_revision"])
        self.assertIsNone(evidence["provenance"]["demotion_reason"])


#: What the line printed for every lab that never had a curated runner, and
#: the one thing it may not say about a run that simply did not reach the
#: handed-over actions: that something curated was involved.
_CURATED = "separate curated runner"


class TheManualPocLineSaysWhatHappenedTests(unittest.TestCase):
    """The rendered REPORT.md line, and the status EVIDENCE.json keeps.

    `core.run_lab` runs the handed-over actions only behind `if
    automatic_proof`, so a run that did not prove never reaches them. That
    non-verdict used to be folded into proof_checks["manual_poc_verified"] as
    False; the key is now absent, and the three states are recorded in
    report.manual_poc_status beside the checks. Reading the old key alone fell
    through to this line's default and printed a curated runner for a lab that
    has none and ran nothing.

    The reports here are built by hand, because that is what the rendering
    takes as input. Which of the four shapes `cvelab run` can hand it is a
    separate question and not this line's job: create_deliverables refuses to
    render anything at all unless the run proved, so "failed" arrives only
    from a report.json loaded by another tool -- the verdict still has to read
    as a failure when it does.
    """

    CVE = "CVE-2099-1002"

    def deliver(
        self,
        report_extra: dict,
        plan_extra: dict | None = None,
        proof_quality: str = "security_effect_observed",
    ) -> tuple[str, dict]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab = Path(temporary.name) / self.CVE
        (lab / "validator").mkdir(parents=True)
        plan = {
            "cve": self.CVE,
            "cwe": "CWE-22",
            "lab_type": "SOURCE_REPRODUCTION",
            "repository": "https://example.invalid/vendor/project.git",
            "revisions": {"vulnerable": "a" * 40, "patched": "b" * 40},
            "exploit_contract": {
                "attack_summary": "Send the local canary request.",
                "preconditions": ["Docker"],
                "observable_effect": "Protected canary is returned.",
                "evidence_type": "unauthorized_read",
            },
            "fidelity": {
                "execution_level": "source_component",
                "vendor_product_started": False,
                "exercised_vendor_components": ["vendor parser"],
                "simulated_components": [],
                "rationale": "The parser is real.",
            },
            "safety": {"target_scope": "internal_docker_network_only"},
        }
        plan.update(plan_extra or {})
        (lab / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        (lab / "dossier.json").write_text(
            json.dumps({"source": "unit-test", "descriptions": ["Test CVE"]}),
            encoding="utf-8",
        )
        (lab / "validator" / "validator.py").write_text(
            "# CVELAB_MANUAL_ACTION CVELAB_TARGET exploit verify\n", encoding="utf-8"
        )
        validation = {
            "attack_executed": True,
            "proof_quality": proof_quality,
            "observable_effect": "Protected canary is returned.",
            "evidence_type": "unauthorized_read",
            "vulnerable": {"confirmed": True, "raw_observations": {"status": 200}},
            "patched": {"confirmed": False, "blocked": True},
            "differential_confirmed": True,
        }
        report = {
            "validated_at": "2099-01-01T00:00:00Z",
            "validation": validation,
            "proof_contract": plan["exploit_contract"],
            "proof_checks": {"vulnerable_confirmed": True},
            "real_poc_verified": True,
            "product_e2e_verified": False,
        }
        report.update(report_extra)

        delivered = create_deliverables(self.CVE, lab, {"ok": True, "report": report})
        self.assertTrue(delivered["ok"], delivered)
        artifacts = lab / "artifacts"
        return (
            (artifacts / "REPORT.md").read_text(encoding="utf-8"),
            json.loads((artifacts / "EVIDENCE.json").read_text(encoding="utf-8")),
        )

    def test_a_run_that_never_reached_the_actions_says_so(self) -> None:
        report, _evidence = self.deliver({
            "manual_poc_status": "not_run",
            "manual_poc_checks": {},
        })

        self.assertIn("- Manual PoC verified: `not run;", report)
        self.assertIn("the handed-over actions were not executed", report)
        self.assertNotIn(_CURATED, report)

    def test_a_proved_run_whose_actions_passed_still_reads_as_verified(self) -> None:
        report, _evidence = self.deliver({
            "manual_poc_status": "verified",
            "proof_checks": {"vulnerable_confirmed": True, "manual_poc_verified": True},
            "manual_poc_checks": {"vulnerable_verify": {"passed": True}},
        })

        self.assertIn("- Manual PoC verified: `True`", report)
        self.assertNotIn(_CURATED, report)

    def test_a_run_whose_actions_failed_still_reads_as_a_failure(self) -> None:
        report, _evidence = self.deliver({
            "manual_poc_status": "failed",
            "proof_checks": {"vulnerable_confirmed": True, "manual_poc_verified": False},
            "manual_poc_checks": {"vulnerable_verify": {"passed": False}},
        })

        self.assertIn("- Manual PoC verified: `False`", report)
        self.assertNotIn(_CURATED, report)

    def test_a_curated_runner_lab_still_gets_the_answer_that_is_true_of_it(self) -> None:
        """A plan.json `runner` lab, which is the shape the default describes.

        `core.run_lab` hands it to `core.run_shipyard_script` and reports it
        with `core.shipyard_report`, whose report carries neither
        manual_poc_status nor proof_checks["manual_poc_verified"] -- the
        actions are not its mechanism, its own script is. The report built
        here is that shape: no manual-PoC key of any kind.
        """
        report, evidence = self.deliver(
            {},
            {
                "lab_type": "END_TO_END_REPRODUCTION",
                "runner": {"type": "shipyard", "script": "e2e/run.sh"},
            },
            proof_quality="end_to_end_security_effect_observed",
        )

        self.assertIn(f"- Manual PoC verified: `{_CURATED}`", report)
        self.assertIsNone(evidence["manual_poc_status"])

    def test_the_shared_record_tells_failed_from_never_ran(self) -> None:
        """Both leave manual_poc_checks empty of a passing entry, so the
        status is the only thing that separates them, and EVIDENCE.json is the
        copy sharing keeps: it is in upload.ALWAYS, in REQUIRED_TO_SHARE, and
        not in upload.EXPLOIT, so --no-poc does not strip it.
        """
        _report, never_ran = self.deliver({
            "manual_poc_status": "not_run", "manual_poc_checks": {},
        })
        _report, failed = self.deliver({
            "manual_poc_status": "failed",
            "proof_checks": {"vulnerable_confirmed": True, "manual_poc_verified": False},
            "manual_poc_checks": {"vulnerable_verify": {"passed": False}},
        })

        self.assertEqual(never_ran["manual_poc_status"], "not_run")
        self.assertEqual(failed["manual_poc_status"], "failed")
        self.assertNotEqual(never_ran["manual_poc_status"], failed["manual_poc_status"])
        self.assertIn("EVIDENCE.json", upload.ALWAYS)
        self.assertIn("EVIDENCE.json", upload.REQUIRED_TO_SHARE)
        self.assertNotIn("EVIDENCE.json", upload.EXPLOIT)


if __name__ == "__main__":
    unittest.main()
