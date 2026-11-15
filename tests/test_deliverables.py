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

import inspect
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cvelab import core, deliverables, field, upload
from cvelab.deliverables import (
    LAB_POC_GUIDE_NAME,
    POC_NAME,
    create_deliverables,
)
from cvelab.field import prompt_standing

#: A spec that was proved, as `report.manual_poc_field` carries one. The
#: three keys `field.poc_standing` reads are the three a half-written record
#: used to be missing, so the tests below carry all of them.
_PROVED_SPEC = {
    "strategy": "direct_observation",
    "observable_effect": "a protected canary returned to an unauthenticated requester",
    "transport": "http",
    "inputs": ["target_path"],
    "checks": [{
        "label": "spec",
        "discover": [],
        "probe": [{"method": "GET", "path": "{{target_path}}"}],
        "expect": {"status": 200},
    }],
    "auth": {},
    "health_timeout": 120,
}


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
                    "trigger_source": "substituted",
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
            # A substituted trigger has to be legible to whoever reads the
            # documents, not only to a step that parses report.json: the two
            # boundary bullets read the same either way.
            walkthrough = (lab / "artifacts" / "WALKTHROUGH.md").read_text(encoding="utf-8")
            for document in (report, walkthrough):
                self.assertIn("- Trigger: **substituted**", document)
                self.assertIn("not the one the evidence names", document)
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


class _DeliveredLabHarness(unittest.TestCase):
    """One validated lab, delivered, for the two classes below to read.

    Holds no tests of its own, so it collects nothing. It is a class rather
    than a module function because both classes below want `self.CVE` and
    `self.addCleanup`, and because the second was briefly a subclass of the
    first -- which ran the first's five tests a second time under the second's
    name for no added coverage.
    """

    CVE = "CVE-2099-1002"

    def deliver(
        self,
        report_extra: dict,
        plan_extra: dict | None = None,
        proof_quality: str = "security_effect_observed",
        legacy_record: dict | None = None,
    ) -> tuple[str, dict]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab = Path(temporary.name) / self.CVE
        (lab / "validator").mkdir(parents=True)
        if legacy_record is not None:
            # Where an archived lab keeps what it proved. Read, never written.
            (lab / "artifacts").mkdir(parents=True, exist_ok=True)
            (lab / "artifacts" / field.LEGACY_MANUAL_POC_RECORD_NAME).write_text(
                json.dumps(legacy_record), encoding="utf-8"
            )
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
        # Kept for the reach tests, which read the other documents this call
        # wrote rather than only the two returned here.
        self.lab = lab
        self.delivered = delivered
        return (
            (artifacts / "REPORT.md").read_text(encoding="utf-8"),
            json.loads((artifacts / "EVIDENCE.json").read_text(encoding="utf-8")),
        )


class TheManualPocLineSaysWhatHappenedTests(_DeliveredLabHarness):
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


class TheLabDocumentStatesItsReachTests(_DeliveredLabHarness):
    """What LAB-POC.md says about how far it reaches, and what it cannot show.

    The defect this covers was never a crash. A reader opened a file called
    "Manual PoC", followed it, watched it work, and learned nothing about
    whether any of it could be pointed at the client's server -- and for most
    labs it cannot, because the single-instance script was refused. The
    drafter's own reason for refusing was already written, and is often the
    best sentence in the whole record, but it lived only in report.json, which
    nobody reads before a client meeting. These tests are about whether the
    document the reader actually opens says it.

    The harness is shared with the class above: the same hand-built reports,
    because report.manual_poc_field is what the rendering takes as input, and
    create_deliverables is handed the very dict core.run_lab returns -- which
    is why none of this needed a change to core.py.
    """

    #: One record per standing, so the tests that have to cover every answer
    #: enumerate the same set. Keyed by what `field.poc_standing` must call
    #: each one, which one of those tests asserts against `POC_STANDINGS` --
    #: a record that stops being read as its key would otherwise quietly test
    #: a different standing twice.
    STANDING_RECORDS = {
        field.POC_SHIPPED: {
            "shipped": True, "container_port": 8080, "spec": _PROVED_SPEC,
        },
        field.POC_REFUSED: {"shipped": False, "reason": "the effect is internal"},
        field.POC_NOT_PROVED: {
            "shipped": False, "reason": "the script did not finish against both builds",
            "proof_checks": {"script_ran_on_both": False}, "runs": {},
        },
        field.POC_NOT_REPRODUCED: {
            "shipped": False, "reason": field.NOT_REPRODUCED_REASON,
        },
        field.POC_NOT_REQUESTED: {
            "shipped": False, "reason": field.NOT_REQUESTED_REASON,
        },
        field.POC_NO_RECORD: {},
    }

    def guide(
        self,
        report_extra: dict,
        plan_extra: dict | None = None,
        legacy_record: dict | None = None,
    ) -> str:
        self.deliver(report_extra, plan_extra, legacy_record=legacy_record)
        return (
            self.lab / "artifacts" / LAB_POC_GUIDE_NAME
        ).read_text(encoding="utf-8")

    @staticmethod
    def flat(text: str) -> str:
        """The document with its line wrapping collapsed.

        The emitted Markdown is hard-wrapped at about 80 columns, so a
        sentence this file asserts on is split across a newline wherever the
        wrap happened to land. The contract is the sentence, not the column
        it broke at; asserting on the wrapped form would make every reflow a
        test failure and tempt the next person to unwrap the document.
        """
        return " ".join(text.split())

    def test_the_document_says_what_it_runs_against_before_anything_else(self) -> None:
        """The reach is the first section, not a closing caveat.

        It was the last line of the file -- "Targets are Docker service names
        only" -- which is true, and was read by nobody, because by the time
        the reader gets there they have already run the thing.
        """
        guide = self.guide({})

        self.assertTrue(guide.startswith(f"# {self.CVE} Lab PoC"), guide[:80])
        head = guide.split("## How the steps work")[0]
        self.assertIn("## What this runs against", head)
        self.assertIn("two Docker builds", self.flat(head))
        self.assertIn("not an address", self.flat(head))
        self.assertIn("be pointed at a client's server", self.flat(head))

    def test_a_refused_single_instance_script_carries_the_drafters_reason(self) -> None:
        """The whole point: the sentence that stops someone overclaiming."""
        reason = (
            "A stock containerd daemon serves no HTTP route that reports its "
            "root directory permissions."
        )
        guide = self.guide({"manual_poc_field": {"shipped": False, "reason": reason}})

        self.assertIn("for this lab it refuses", self.flat(guide))
        self.assertIn("recorded why", self.flat(guide))
        self.assertIn("> " + reason, guide)
        self.assertIn("exits 2 without sending anything", self.flat(guide))
        # And it does not advertise the artifact this one replaced, which 45
        # of the archived labs still hold beside them.
        self.assertNotIn(field.LEGACY_MANUAL_POC_NAME, guide)

    def test_a_multi_line_reason_stays_inside_the_quote(self) -> None:
        """A blank line in the prose would end the blockquote.

        The rest of the drafter's sentence would then render as body text,
        reading as CVELab's own claim rather than as the reason a script was
        refused -- the opposite of what quoting it is for.
        """
        guide = self.guide({"manual_poc_field": {
            "shipped": False,
            "reason": "The effect is internal.\n\nOnly the lab's adapter reports it.",
        }})

        self.assertIn("> The effect is internal.", guide)
        self.assertIn("> Only the lab's adapter reports it.", guide)
        for line in guide.splitlines():
            if "adapter reports it" in line:
                self.assertTrue(line.startswith(">"), line)

    def test_a_step_never_asked_for_is_not_reported_as_a_refusal(self) -> None:
        """"not requested" is core.py's own default, not a drafter's verdict.

        Rendering it as a refusal would attribute to the model a judgement it
        was never asked to make, and would tell the reader the effect cannot
        be shown against a live instance when nobody has yet looked.
        """
        guide = self.guide(
            {"manual_poc_field": {"shipped": False, "reason": "not requested"}}
        )

        self.assertIn("because one was never asked for", self.flat(guide))
        self.assertIn("--manual-poc", self.flat(guide))
        self.assertNotIn("not requested", self.flat(guide))
        self.assertNotIn("could not stand", self.flat(guide))

    def test_a_proved_remote_mode_is_named_so_the_reader_can_find_it(self) -> None:
        guide = self.guide({"manual_poc_field": {
            "shipped": True, "container_port": 8080, "spec": _PROVED_SPEC,
        }})

        self.assertIn("has two modes, and the argument chooses", self.flat(guide))
        self.assertIn(POC_NAME, guide)
        self.assertIn("stayed silent on the fixed one", self.flat(guide))
        # The header of that one file is the handover document now, so the
        # guide sends the reader to it rather than to a document beside it.
        self.assertIn("own header is the handover document", self.flat(guide))

    def test_a_vulnerable_only_lab_claims_no_differential_it_never_had(self) -> None:
        """One build, so nothing can have "stayed silent on the fixed one"."""
        guide = self.guide(
            {"manual_poc_field": {
                "shipped": True, "container_port": 8080, "spec": _PROVED_SPEC,
            }},
            {"lab_type": "VULNERABLE_ONLY_REPRODUCTION",
             "revisions": {"vulnerable": "a" * 40, "patched": None}},
        )

        self.assertIn("The one Docker build in this lab directory", self.flat(guide))
        self.assertIn("no fixed revision to compare against", self.flat(guide))
        self.assertNotIn("stayed silent on the fixed one", self.flat(guide))
        self.assertNotIn("two Docker builds", self.flat(guide))

    def test_a_report_with_no_record_at_all_claims_neither_way(self) -> None:
        """A plan.json `runner` lab never attempts one, and is not a refusal.

        core.shipyard_report carries no manual-PoC key of any kind, so the
        field is absent rather than False. Saying "CVELab tried and refused"
        for one would invent a verdict out of a missing key.
        """
        guide = self.guide({})

        self.assertIn("kept no record of a single-instance script either way", self.flat(guide))
        self.assertNotIn("drafted a single-instance script", self.flat(guide))
        self.assertNotIn("has two modes", self.flat(guide))

    def test_a_script_of_our_own_that_failed_is_not_the_findings_limit(self) -> None:
        """The defect this fixes, in the document that carried it.

        Measured across the 264 archived labs: 11 record a script of CVELab's
        own that was written, emitted and run and did not hold up, and all 11
        ship a kit. Each was handed the refusal note, which calls that
        sentence "the limit of what this lab can show" and "the one to
        repeat" -- a tooling failure described to a client as a fact about
        the vulnerability. `field._spec_complaint` feeds the same sentence
        back to the next draft as OUR problem, with the script's output
        attached, precisely because it says nothing about the finding.

        The reason is still quoted, because it is the only thing that says
        which part of the attempt to look at. What changes is whose failure
        the document says it is.
        """
        reason = "the script did not tell the two builds apart"
        guide = self.guide({"manual_poc_field": {
            "shipped": False, "reason": reason,
            "proof_checks": {"script_ran_on_both": True, "manual_poc_proven": False},
            "runs": {},
        }})
        flat = self.flat(guide)

        self.assertIn("> " + reason, guide)
        self.assertIn("could not make it hold up", flat)
        self.assertIn("CVELab's own script failing, and not a finding about the "
                      "vulnerability", flat)
        self.assertIn("differential proof below is this lab's own", flat)
        # The sentences that were wrong for these 11, each of which is still
        # right for a real refusal and is asserted above for one.
        for forbidden in (
            "the limit of what this lab can show",
            "it is the one to repeat",
            "proved it could not stand",
            "recorded why",
        ):
            self.assertNotIn(forbidden, flat)

    def test_a_colon_that_introduces_the_quote_is_next_to_it(self) -> None:
        """The reason follows the colon that promises it, on every shape.

        Both notes that quote the record lead with a colon, and where the lab
        publishes a port the route paragraph used to be appended to that lead
        -- it opens with a single newline, so it joined the colon's own
        paragraph. The reader got a colon promising the drafter's reason and
        delivering nine lines about the route, with the blockquote after them.
        Measured: 7 archived labs, all refused, none of them a lab whose
        script was drafted and not proved -- none of those 11 declares a port
        yet, and the next one would.

        Both address shapes for both quoting standings, because the shape
        that was wrong is the one that only appears when a port is declared,
        and asserting it on the shape that was always right is how it came
        back.
        """
        quoting = {
            field.POC_REFUSED: {
                "shipped": False, "reason": "the effect is internal to the library",
            },
            field.POC_NOT_PROVED: {
                "shipped": False, "reason": "the script did not tell the two builds apart",
                "proof_checks": {"manual_poc_proven": False}, "runs": {},
            },
        }
        for standing, record in quoting.items():
            for takes_address in (False, True):
                with self.subTest(standing=standing, address=takes_address):
                    note = deliverables._single_instance_note(
                        record, False, takes_address
                    )
                    lines = note.splitlines()
                    quoted = [i for i, line in enumerate(lines) if line.startswith(">")]
                    self.assertTrue(quoted, note)
                    # The lead ends on the colon, the quote opens two lines
                    # later, and the only thing between them is the blank
                    # line a Markdown blockquote needs.
                    opening = quoted[0]
                    self.assertEqual(lines[opening - 1], "")
                    self.assertTrue(lines[opening - 2].endswith(":"), lines[opening - 2])
                    self.assertIn(record["reason"], lines[opening])
                    # And the route paragraph, where there is one, is after
                    # the quote rather than inside the colon's paragraph.
                    route = "That address is yours to choose"
                    if takes_address:
                        self.assertIn(route, note)
                        self.assertGreater(note.index(route), note.index("\n> "))
                        # Its own paragraph, not glued to the sentence above.
                        self.assertIn("\n\n" + route, note)
                    else:
                        self.assertNotIn(route, note)

    def test_no_note_is_wider_than_the_document_around_it(self) -> None:
        """Every shape wraps at the width the rest of the file is wrapped at.

        The companion to the colon: the same class of miss, in the same seam.
        A note splices a standing's own sentence into the middle of its prose,
        each half is hard-wrapped for the half it was written beside, and the
        join lands wherever the two happen to meet. Measured: the
        `not_reproduced` note ran to 107 columns with no address and 101 with
        one, against 79 everywhere else -- in a document read next to a
        client, where an overrun reads as the generator having broken.

        Enumerated from `field.POC_STANDINGS` rather than from the shapes the
        archive happens to hold, because that is exactly what let this
        through: correct in the shape that ships most, ragged in a shape with
        few archived labs or none. Both address shapes and both lab shapes,
        for the same reason.

        Blockquote lines are the one exception and are excluded. The reason
        inside them is the drafter's own prose, prefixed line by line and
        deliberately not re-wrapped -- `_quoted` says why -- so its width is
        the model's and not this module's to fix.
        """
        for standing, record in self.STANDING_RECORDS.items():
            for takes_address in (False, True):
                for vulnerable_only in (False, True):
                    with self.subTest(
                        standing=standing, address=takes_address,
                        vulnerable_only=vulnerable_only,
                    ):
                        note = deliverables._single_instance_note(
                            record, vulnerable_only, takes_address
                        )
                        over = [
                            line for line in note.splitlines()
                            if not line.startswith(">")
                            and len(line) > deliverables._NOTE_WIDTH
                        ]
                        self.assertEqual(over, [], f"{len(over[0]) if over else 0} columns")

    def test_the_route_paragraph_is_never_glued_to_the_sentence_above_it(self) -> None:
        """It is nine lines about the address, and it needs its own paragraph.

        It opens with a single newline of its own, so appending it to a
        standing's sentence put it in that sentence's paragraph. For the two
        notes that quote the record it also landed between the colon and the
        quote; for the other three it ran on from a sentence about something
        else. Asserted for every standing that can carry it, so the next one
        added cannot inherit the glue.
        """
        for standing, record in self.STANDING_RECORDS.items():
            if standing == field.POC_SHIPPED:
                continue  # No address paragraph: the argument is remote mode's.
            with self.subTest(standing=standing):
                note = deliverables._single_instance_note(record, False, True)
                route = deliverables._THE_ROUTE_IS_A_CONSTANT.strip()
                self.assertIn("\n\n" + route.splitlines()[0], note)
                # And it is the last thing in the note, for every standing.
                self.assertTrue(note.endswith(route), note[-200:])
                # Nothing of it reaches a lab that publishes no port.
                self.assertNotIn(
                    route.splitlines()[0],
                    deliverables._single_instance_note(record, False, False),
                )

    def test_the_address_and_the_single_instance_script_are_told_apart(self) -> None:
        """"No" and "that address is yours to choose" are not a contradiction.

        No argument reaches a single-instance script, because there is none;
        the address does reach the lab program. Said as two different things
        in the lead, because as consecutive sentences they read as one claim
        reversing itself -- which is what they were when the route paragraph
        sat directly under the lead.
        """
        for standing, record in (
            (field.POC_REFUSED, {"shipped": False, "reason": "the effect is internal"}),
            (field.POC_NOT_PROVED,
             {"shipped": False, "reason": "the script did not finish against both builds",
              "proof_checks": {}, "runs": {}}),
        ):
            with self.subTest(standing=standing):
                note = deliverables._single_instance_note(record, False, True)
                flat = self.flat(note)
                self.assertIn("does not reach a single-instance script", flat)
                self.assertIn("it is not refused either", flat)
                self.assertIn("it runs the lab program", flat)
                # The lead points forward at the paragraph that explains the
                # address, so that paragraph has to be the last one. Compared
                # against the constant rather than against its closing
                # sentence spelled out here: the emitted text is hard-wrapped,
                # and a reflow of it is not a change in what the note says.
                self.assertIn("the last paragraph here is about", flat)
                self.assertTrue(
                    note.endswith(deliverables._THE_ROUTE_IS_A_CONSTANT.strip()),
                    note[-200:],
                )

    def test_every_standing_has_something_for_both_writers_to_say(self) -> None:
        """A standing with no entry is a KeyError at delivery time.

        Both of the dicts below are keyed by `field.poc_standing`'s answer,
        and they are read while a validated lab's kit is being written -- so
        a missing entry does not fail here or on most labs. It fails on
        exactly the labs that have the new shape, after the run that built
        them, which is the worst place for it. Enumerated from
        `field.POC_STANDINGS` rather than listed, so a standing added later
        cannot be added to one dict and forgotten in the other.
        """
        records = self.STANDING_RECORDS
        self.assertEqual(sorted(records), sorted(field.POC_STANDINGS))
        notes = {}
        for standing, record in records.items():
            with self.subTest(standing=standing):
                self.assertEqual(field.poc_standing(record), standing)
                if standing != field.POC_SHIPPED:
                    self.assertIn(standing, deliverables._ADDRESS_IS_REFUSED)
                    self.assertIn(standing, deliverables._ADDRESS_RUNS_THE_LAB_PROGRAM)
                # Both shapes an address can have, which is the other key the
                # notes are chosen by.
                for takes_address in (False, True):
                    note = deliverables._single_instance_note(
                        record, False, takes_address
                    )
                    self.assertTrue(note.strip(), standing)
                    # Nothing left unsubstituted: a stray field would reach
                    # the reader as a brace.
                    self.assertNotIn("{", note)
                    notes[(standing, takes_address)] = note
        # And no two standings say the same thing, which is what having them
        # as separate standings is for.
        for takes_address in (False, True):
            said = [
                note for (_standing, shape), note in notes.items()
                if shape is takes_address
            ]
            self.assertEqual(len(set(said)), len(field.POC_STANDINGS))

    def test_an_archived_labs_own_record_is_read_when_the_report_has_none(self) -> None:
        """An archived lab re-rendered by `cvelab deliverables` still reads true.

        The proved spec lives in report.manual_poc_field now, and it did not
        carry one before the merge: 45 of the archived labs keep theirs in
        Manual-PoC.json beside the lab, 29 of those with a spec that shipped.
        Reading only this run's report would turn every one of those into a
        refusal on re-render, which is the one direction this document must
        never drift.
        """
        guide = self.guide({}, legacy_record={
            "cve": self.CVE, "shipped": True, "container_port": 8080,
            "spec": _PROVED_SPEC,
        })

        self.assertIn("has two modes, and the argument chooses", self.flat(guide))
        self.assertNotIn("kept no record", self.flat(guide))

    def test_the_walkthrough_points_at_the_document_by_its_new_name(self) -> None:
        """WALKTHROUGH.md is the other document a reader takes to a client."""
        self.deliver({})
        walkthrough = (
            self.lab / "artifacts" / "WALKTHROUGH.md"
        ).read_text(encoding="utf-8")

        self.assertIn(LAB_POC_GUIDE_NAME, walkthrough)
        self.assertNotIn("MANUAL-POC.md", walkthrough)
        self.assertIn("reach this lab's own two builds", self.flat(walkthrough))

    def test_the_returned_deliverables_name_the_renamed_document(self) -> None:
        """autoflow and the CLI print these paths; a stale key would 404."""
        self.deliver({})

        self.assertEqual(
            self.delivered["deliverables"]["manual_guide"],
            str(self.lab / "artifacts" / LAB_POC_GUIDE_NAME),
        )
        self.assertFalse((self.lab / "artifacts" / "MANUAL-POC.md").exists())


class TheGateReadsTheComputedVerdictTests(unittest.TestCase):
    """What decides whether a validated lab gets a kit at all.

    The gate used to require validation["proof_quality"] to be one of two
    literals. That field is free text the model's own validator prints about
    its own run, and `core.effect_observed` exists because CVELab removed
    exactly that string equality from the proof gate -- the thing being
    judged was also the judge -- keeping the field as a claim with a
    non-decisive agreement note beside it. deliverables.py kept enforcing it,
    so a lab that reproduced differentially and then described itself in some
    other words took the early return, which writes nothing: no PoC, no
    manual kit, no report, no walkthrough, no evidence. Measured over one
    benchmark tree, 40 labs recorded VALIDATED hold no artifacts/PoC.py
    against 89 that do.

    Both directions are pinned here. A lab that did not prove must still get
    nothing, or the repair is just a wider hole.
    """

    CVE = "CVE-2099-1003"

    #: Written by validators in the measured tree, none of which the old gate
    #: accepted, and the last of which is a whole sentence: the field is prose
    #: and no list of allowed spellings could have been long enough.
    LABELS = (
        "wrapper_observed",
        "state_observation",
        "behavioral: the published release ran behind an HTTP adapter",
    )

    def lab(self, proof_quality: str = "wrapper_observed") -> Path:
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
        (lab / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        (lab / "dossier.json").write_text(
            json.dumps({"source": "unit-test", "descriptions": ["Test CVE"]}),
            encoding="utf-8",
        )
        (lab / "validator" / "validator.py").write_text(
            "# CVELAB_MANUAL_ACTION CVELAB_TARGET exploit verify\n", encoding="utf-8"
        )
        self.proof_quality = proof_quality
        return lab

    def result(self, **overrides: object) -> dict:
        """The dict core.run_lab returns for a lab that proved.

        Four of the old gate's five conditions, exactly as the measured labs
        carried them, and the fifth -- the label -- is whatever the validator
        wrote.
        """
        report = {
            "validated_at": "2099-01-01T00:00:00Z",
            "validation": {
                "attack_executed": True,
                "proof_quality": self.proof_quality,
                "observable_effect": "Protected canary is returned.",
                "evidence_type": "unauthorized_read",
                "vulnerable": {"confirmed": True, "raw_observations": {"status": 200}},
                "patched": {"confirmed": False, "blocked": True},
                "differential_confirmed": True,
            },
            "proof_contract": {"evidence_type": "unauthorized_read"},
            "proof_checks": {"vulnerable_confirmed": True, "security_effect_observed": True},
            "real_poc_verified": True,
            "product_e2e_verified": False,
        }
        report.update(overrides.pop("report_extra", {}) or {})
        return {"ok": True, "report": report, **overrides}

    #: The whole kit, by the names a reader looks for. The measured labs held
    #: none of these and reported success.
    KIT = ("PoC.py", "manual.sh", LAB_POC_GUIDE_NAME, "REPORT.md", "WALKTHROUGH.md", "EVIDENCE.json")

    def test_a_validated_lab_that_labelled_itself_otherwise_still_ships(self) -> None:
        for label in self.LABELS:
            with self.subTest(proof_quality=label):
                lab = self.lab(label)

                delivered = create_deliverables(self.CVE, lab, self.result())

                self.assertTrue(delivered["ok"], delivered)
                for name in self.KIT:
                    self.assertTrue((lab / "artifacts" / name).is_file(), name)
                # The claim still travels, undecided, where a reader can
                # compare it with what CVELab measured.
                evidence = json.loads(
                    (lab / "artifacts" / "EVIDENCE.json").read_text(encoding="utf-8")
                )
                self.assertEqual(evidence["validation"]["proof_quality"], label)

    def test_a_run_that_did_not_prove_still_gets_nothing(self) -> None:
        """The early return has to keep firing, or this is a wider hole.

        One case per surviving clause, each otherwise a lab that proved.
        """
        failures = {
            "ok": {"ok": False},
            "lab_type": {"report_extra": {}},
            "real_poc_verified": {"report_extra": {"real_poc_verified": False}},
        }
        for clause, overrides in failures.items():
            with self.subTest(clause=clause):
                lab = self.lab()
                if clause == "lab_type":
                    plan = json.loads((lab / "plan.json").read_text(encoding="utf-8"))
                    plan["lab_type"] = "SYNTHETIC_CLASS_LAB"
                    (lab / "plan.json").write_text(json.dumps(plan), encoding="utf-8")

                delivered = create_deliverables(self.CVE, lab, self.result(**overrides))

                self.assertFalse(delivered["ok"], delivered)
                self.assertEqual(delivered["status"], "POC_NOT_VERIFIED")
                for name in self.KIT:
                    self.assertFalse((lab / "artifacts" / name).exists(), name)

    def test_the_kit_offers_the_command_only_where_the_artifact_has_it(
        self,
    ) -> None:
        """What the kit prints is what the file beside it can do.

        The condition here was `_executes(plan)`, the evidence shape the
        plan DECLARES, while the artifact offers the command form on
        `prompt_standing` -- a declared service port and a validator that
        reads the command. Measured across 262 archived labs: 34 declare
        command execution, 2 implement it, and every one of the other 32
        declares no port at all, so `manual.sh` and the guide printed a
        command for a file whose one argument does not reach it.

        Tested here rather than against `_write_generic_manual_assets`,
        which is where the existing test for this line lives: that function
        was always right about the argument it was handed, and no test
        covered what it was handed. The defect was the argument, so the
        argument is what this reads.
        """
        offer = "$POC_AT id"
        fallback = "nothing here may be pointed at that address"

        # Declares command execution, implements nothing of the sort: the
        # default validator reads no command and the plan declares no port.
        lab = self.lab()
        plan = json.loads((lab / "plan.json").read_text(encoding="utf-8"))
        plan["exploit_contract"]["evidence_type"] = "code_execution"
        (lab / "plan.json").write_text(json.dumps(plan), encoding="utf-8")

        self.assertTrue(create_deliverables(self.CVE, lab, self.result())["ok"])

        runner = (lab / "artifacts" / "manual.sh").read_text(encoding="utf-8")
        guide = (lab / "artifacts" / LAB_POC_GUIDE_NAME).read_text(encoding="utf-8")
        self.assertNotIn(offer, runner)
        self.assertIn(fallback, runner)
        self.assertNotIn('python3 PoC.py "$(bash manual.sh address', guide)

        # And the shape that does implement it keeps the line, which is the
        # half of this that a stricter condition could have taken away.
        able = self.lab()
        plan = json.loads((able / "plan.json").read_text(encoding="utf-8"))
        plan["exploit_contract"]["evidence_type"] = "code_execution"
        plan["exploit_contract"]["service_port"] = 8080
        (able / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        (able / "validator" / "validator.py").write_text(
            (Path(__file__).parent / "fixtures" / "operator_validator.py")
            .read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        self.assertTrue(create_deliverables(self.CVE, able, self.result())["ok"])

        runner = (able / "artifacts" / "manual.sh").read_text(encoding="utf-8")
        guide = (able / "artifacts" / LAB_POC_GUIDE_NAME).read_text(encoding="utf-8")
        self.assertIn(offer, runner)
        self.assertNotIn(fallback, runner)
        self.assertIn('python3 PoC.py "$(bash manual.sh address vulnerable)" id', guide)

    def test_the_kit_and_the_artifact_say_the_same_thing(self) -> None:
        """One predicate, read once, so the two cannot come apart.

        They did come apart, and that is the whole finding: the kit printed
        the command on what the plan DECLARED while the artifact offered it
        on what the validator IMPLEMENTS. Two predicates for one question.

        All four shapes, because fixing it with a condition that merely
        agrees on the labs that exist today is how it would come apart
        again. The port decides whether there is an address at all; the
        validator decides whether a command after it is answered. Only both
        together may print a command.
        """
        able = (
            Path(__file__).parent / "fixtures" / "operator_validator.py"
        ).read_text(encoding="utf-8")
        unable = "# CVELAB_MANUAL_ACTION CVELAB_TARGET exploit verify\n"
        shapes = {
            ("port", "implements"): (8080, able, True),
            ("port", "refuses"): (8080, unable, False),
            ("no port", "implements"): (None, able, False),
            ("no port", "refuses"): (None, unable, False),
        }
        for (has_port, reads), (port, validator, expected) in shapes.items():
            with self.subTest(port=has_port, validator=reads):
                lab = self.lab()
                plan = json.loads((lab / "plan.json").read_text(encoding="utf-8"))
                plan["exploit_contract"]["evidence_type"] = "code_execution"
                if port is not None:
                    plan["exploit_contract"]["service_port"] = port
                (lab / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
                (lab / "validator" / "validator.py").write_text(
                    validator, encoding="utf-8"
                )

                self.assertIs(prompt_standing(plan, validator)[0], expected)
                self.assertTrue(create_deliverables(self.CVE, lab, self.result())["ok"])

                runner = (lab / "artifacts" / "manual.sh").read_text(encoding="utf-8")
                poc = (lab / "artifacts" / field.POC_NAME).read_text(encoding="utf-8")
                header = poc.split('"""')[1]
                # The kit's offer and the file's own usage line, read off the
                # two artifacts rather than off the predicate, so this is a
                # comparison and not a restatement.
                # Scoped to LAB MODE, because that is the half an address
                # reaches here: the REMOTE MODE paragraph below it shows an
                # address too, and it is the refusal's.
                lab_mode = header[
                    header.index("LAB MODE"):header.index("REMOTE MODE")
                ]
                kit_offers = "$POC_AT id" in runner
                file_offers = bool(
                    re.search(r"python3 PoC\.py \S+ id\b", lab_mode)
                )
                self.assertIs(kit_offers, expected)
                self.assertIs(file_offers, expected)
                self.assertIs(kit_offers, file_offers)
                # And the address itself, which is the other half of the same
                # discipline and the half the flag's removal added: the
                # runner prints the address exactly where the file takes it,
                # with or without a command after it.
                takes_address = field.takes_lab_address(port, field.poc_record(lab))
                self.assertIs(takes_address, port is not None)
                self.assertIs(
                    'python3 \\"$LAB_ROOT/artifacts/PoC.py\\" $POC_AT' in runner,
                    takes_address,
                )
                self.assertIs("python3 PoC.py 127.0.0.1:32768" in lab_mode,
                              takes_address)

    def test_the_gate_no_longer_reads_the_validators_own_label(self) -> None:
        """Read off the source, because the behaviour above cannot tell a gate
        that ignores the field from one that happens to accept every spelling
        a test thought to try. `proof_quality` is still rendered further down
        the same function, as a claim, which is why only the gate is read.
        """
        source = inspect.getsource(create_deliverables)
        gate = source[
            source.index("real_poc_verified = (") : source.index("if not real_poc_verified:")
        ]

        self.assertNotIn("proof_quality", gate)
        self.assertIn('result.get("ok") is True', gate)
        self.assertIn('report.get("real_poc_verified") is True', gate)
        self.assertIn("proof_quality", source)

    def test_the_implication_the_gate_leans_on_is_still_true_in_core(self) -> None:
        """`ok` is the computed verdict, so the gate does not re-read it.

        That holds only while every proof check is ANDed into `ok` and
        `security_effect_observed` is one of them, in both of core's
        validation paths -- the Docker one and the curated-runner one. If
        either stops being true, the gate in deliverables.py is reading
        something weaker than it claims and this test is the notice.
        """
        source = Path(core.__file__).read_text(encoding="utf-8")

        self.assertIn("real_source_proof = all(proof_checks.values())", source)
        self.assertIn("validated = real_source_proof", source)
        self.assertIn("validated = all(proof_checks.values())", source)
        self.assertEqual(source.count('"security_effect_observed": effect_held'), 2)
        self.assertEqual(
            source.count('"attack_executed": validation.get("attack_executed") is True'), 2
        )


class TheDocumentSaysWhetherThereIsAPromptTests(unittest.TestCase):
    """Whether the delivered document names the prompt, or says why not.

    It did neither, for any lab shape, including the three archived labs that
    have one: the prompt was in the artifact's header and in the artifact's
    own output, and nowhere in the document the operator opens first. The
    closing line counted the invocations the file takes, and counted two.

    Driven through `create_deliverables`, like the two kit tests above and for
    the same reason: the writer was always right about the arguments it was
    handed, and what the document says about the prompt is decided by which
    arguments reach it. The expectation is read off `field.prompt_standing`
    rather than written out, so each assertion is a comparison between the one
    function that decides and a surface that repeats it.

    Enumerated from the shapes, because that is what let this through: the
    shape that matters most -- a proved remote mode beside a prompt -- has no
    archived lab whose report.json records it, so nothing measured over the
    archive's reports would have noticed the document saying nothing.
    """

    CVE = "CVE-2099-1004"

    #: Each shape by what makes it one: the evidence the contract declares,
    #: the port it publishes, whether its validator implements the one-command
    #: form, and whether a remote mode was proved. The middle two are the
    #: refusals that owe a reason; the last is the lab that was never a
    #: candidate and is owed silence.
    SHAPES = {
        "a prompt, at this lab's own published build": (
            "code_execution", 8080, True, False,
        ),
        "a prompt beside a proved remote mode": (
            "code_execution", 8080, True, True,
        ),
        "declared the form, publishes no port": (
            "code_execution", None, True, False,
        ),
        "declared the form, validator reads no command": (
            "code_execution", 8080, False, False,
        ),
        "declared something else entirely": (
            "unauthorized_read", 8080, True, False,
        ),
    }

    HEADING = "## Is there a prompt?"

    @staticmethod
    def flat(text: str) -> str:
        """The text with its line wrapping collapsed, as the class above."""
        return " ".join(text.split())

    def deliver(
        self, evidence: str, port: int | None, implements: bool, proved: bool
    ) -> tuple[str, str, dict, str]:
        """One lab of that shape, delivered: its document and its artifact."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab = Path(temporary.name) / self.CVE
        (lab / "validator").mkdir(parents=True)
        contract = {
            "attack_summary": "Send the local canary request.",
            "preconditions": ["Docker"],
            "observable_effect": "Protected canary is returned.",
            "evidence_type": evidence,
        }
        if port is not None:
            contract["service_port"] = port
        plan = {
            "cve": self.CVE,
            "cwe": "CWE-22",
            "lab_type": "SOURCE_REPRODUCTION",
            "repository": "https://example.invalid/vendor/project.git",
            "revisions": {"vulnerable": "a" * 40, "patched": "b" * 40},
            "exploit_contract": contract,
            "fidelity": {
                "execution_level": "source_component",
                "vendor_product_started": False,
                "exercised_vendor_components": ["vendor parser"],
                "simulated_components": ["the adapter route"],
                "rationale": "The parser is real.",
            },
            "safety": {"target_scope": "internal_docker_network_only"},
        }
        (lab / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        (lab / "dossier.json").write_text(
            json.dumps({"source": "unit-test", "descriptions": ["Test CVE"]}),
            encoding="utf-8",
        )
        # A real validator either way: `prompt_standing` reads the file, so a
        # stand-in that merely claimed to implement the form would make this a
        # test of its own fixture.
        validator = (
            (Path(__file__).parent / "fixtures" / "operator_validator.py")
            .read_text(encoding="utf-8")
            if implements
            else "# CVELAB_MANUAL_ACTION CVELAB_TARGET exploit verify\n"
        )
        (lab / "validator" / "validator.py").write_text(validator, encoding="utf-8")
        report = {
            "validated_at": "2099-01-01T00:00:00Z",
            "validation": {
                "attack_executed": True,
                "proof_quality": "security_effect_observed",
                "observable_effect": "Protected canary is returned.",
                "evidence_type": evidence,
                "vulnerable": {"confirmed": True, "raw_observations": {"status": 200}},
                "patched": {"confirmed": False, "blocked": True},
                "differential_confirmed": True,
            },
            "proof_contract": contract,
            "proof_checks": {"vulnerable_confirmed": True},
            "real_poc_verified": True,
            "product_e2e_verified": False,
        }
        if proved:
            report["manual_poc_field"] = {
                "cve": self.CVE, "shipped": True, "container_port": port or 8080,
                "spec": _PROVED_SPEC,
            }
        delivered = create_deliverables(self.CVE, lab, {"ok": True, "report": report})
        self.assertTrue(delivered["ok"], delivered)
        artifacts = lab / "artifacts"
        return (
            (artifacts / LAB_POC_GUIDE_NAME).read_text(encoding="utf-8"),
            (artifacts / POC_NAME).read_text(encoding="utf-8"),
            plan,
            validator,
        )

    def section(self, guide: str) -> str:
        """The prompt's own section, or "" where the document says nothing."""
        if self.HEADING not in guide:
            return ""
        return guide.split(self.HEADING)[1].split("\n## ")[0]

    def test_each_shape_is_told_what_the_standing_told_the_artifact(self) -> None:
        """The document and the header give one answer, or neither does.

        Three outcomes, and the third is as much the contract as the other
        two: a lab whose declared evidence was never command execution hears
        nothing at all, because a section about a prompt it was never a
        candidate for is noise in a document read next to a client. That is
        229 of the 264 archived labs, and it is the same judgement the
        artifact's own header makes from the same two answers.
        """
        for name, shape in self.SHAPES.items():
            with self.subTest(shape=name):
                guide, poc, plan, validator = self.deliver(*shape)
                offered, reason = prompt_standing(plan, validator)
                header = poc.split('"""')[1]
                if offered:
                    self.assertIn(self.HEADING, guide)
                    self.assertIn(
                        f'{POC_NAME} "$(bash manual.sh address vulnerable)" '
                        "--prompt --allow-prompt",
                        guide,
                    )
                    self.assertIn(
                        "One command per line, and not a session.",
                        self.flat(self.section(guide)),
                    )
                    # And the header names it too, which is what makes the
                    # document a second surface and not a second answer.
                    self.assertIn("--prompt --allow-prompt", header)
                elif field._executes(plan):
                    self.assertIn(self.HEADING, guide)
                    # The reason, as the one function gave it, in both.
                    self.assertIn(self.flat(reason), self.flat(self.section(guide)))
                    self.assertIn(self.flat(reason), self.flat(header))
                    self.assertNotIn("--allow-prompt", guide)
                else:
                    self.assertNotIn(self.HEADING, guide)
                    self.assertNotIn("--allow-prompt", guide)
                    # Nor the reason: it is true of this lab, and it answers a
                    # question nobody holding this lab would ask.
                    self.assertNotIn(self.flat(reason), self.flat(guide))

    def test_what_a_line_that_does_not_run_costs_is_named_before_it_is_paid(
        self
    ) -> None:
        """The probe's cost, where the reader decides whether to run the mode.

        A line the lab program reports as not run is followed by a probe of
        the artifact's own to the same address -- a request the operator did
        not type, going wherever the address points. The session's own costs
        are each named in this document and in the artifact's header for
        exactly this reason: a reader deciding whether to point a mode at a
        client's host decides on what it sends. The prompt's banner says it
        too, but the banner is printed after `--allow-prompt` has already been
        given, so the two surfaces read beforehand are the ones held here.
        """
        for name, shape in self.SHAPES.items():
            with self.subTest(shape=name):
                guide, poc, plan, validator = self.deliver(*shape)
                if not prompt_standing(plan, validator)[0]:
                    continue
                surfaces = {
                    "LAB-POC.md": self.flat(self.section(guide)),
                    "header": self.flat(poc.split('"""')[1]),
                }
                for surface, text in surfaces.items():
                    with self.subTest(surface=surface):
                        # That there is an extra delivery, when it is sent,
                        # and that it goes to the address the operator gave.
                        self.assertIn("costs more than one request", text)
                        self.assertIn("only after a line that did not run", text)
                        self.assertIn("wherever the address points", text)

    def test_the_closing_line_names_every_invocation_the_file_takes(self) -> None:
        """The line a reader quotes, which counted two where there are three.

        `_CLOSING` is keyed by both predicates, so the count is pinned for all
        four shapes rather than for the one that ships most. The prompt is
        named as an invocation and not as a third mode -- it is the lab
        program once per line -- so the sentences elsewhere in this document
        that say the file holds two modes are still true beside it.
        """
        self.assertEqual(len(set(deliverables._CLOSING.values())), 4)
        for name, shape in self.SHAPES.items():
            with self.subTest(shape=name):
                guide, _poc, plan, validator = self.deliver(*shape)
                offered = prompt_standing(plan, validator)[0]
                # Flattened: one of the four shapes wraps the flag pair across
                # a line, and the contract is the sentence rather than the
                # column it broke at.
                closing = self.flat(guide.rstrip().rsplit("`manual.sh` takes", 1)[1])

                self.assertIn("takes no argument", closing)
                self.assertIs("--prompt --allow-prompt" in closing, offered)
                self.assertNotIn("three modes", self.flat(guide))

    def test_no_prompt_section_is_wider_than_the_document_around_it(self) -> None:
        """The same seam as the single-instance notes, measured the same way.

        A substituted reason lands mid-paragraph, so the section that carries
        one is flowed rather than hand-broken, and this is what says the flow
        happened. Nothing unsubstituted either: a stray field would reach the
        reader as a brace in a document they are reading out loud.
        """
        for name, shape in self.SHAPES.items():
            with self.subTest(shape=name):
                guide, _poc, _plan, _validator = self.deliver(*shape)
                section = self.section(guide)
                over = [
                    line for line in section.splitlines()
                    if len(line) > deliverables._NOTE_WIDTH
                ]

                self.assertEqual(over, [], f"{len(over[0]) if over else 0} columns")
                self.assertNotIn("{", section)
                self.assertNotIn("}", section)


if __name__ == "__main__":
    unittest.main()
