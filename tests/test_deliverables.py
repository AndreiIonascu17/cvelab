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
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cvelab import core, field, upload
from cvelab.deliverables import (
    LAB_POC_GUIDE_NAME,
    POC_NAME,
    create_deliverables,
)

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


if __name__ == "__main__":
    unittest.main()
