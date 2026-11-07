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

"""The mandatory effect check, measured by CVELab instead of claimed.

It used to be `validation["proof_quality"] == "security_effect_observed"`:
a string equality on a field the model's own validator writes about itself.
The lab fixture checked in beside this file prints exactly that literal from
its own differential boolean, so the project shipped a demonstration of its
own hole.

Moving the check onto a declared predicate is not on its own enough --
`{"body_contains": ""}` holds against any body at all -- so the decisive
part is the shape of the question: for a lab with a fixed build the effect
is that the predicate held on the vulnerable side and did NOT hold on the
patched side. A vacuous predicate holds on both and fails itself. The tests
below are in that order: the self-certifying validator first, because it is
the soundness regression.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import core, sourcegen

FORKED_VALIDATOR = Path(__file__).parent / "fixtures" / "self_certifying_validator.py"

#: The canary the lab plants, and the value plan.json records as `marker`.
#: The two are the same string here on purpose: a vulnerable-only lab has no
#: patched build, so its predicate has to quote the canary it planted, and a
#: fixture whose plan recorded one canary while its contract named another
#: would be testing the mismatch rather than the rule.
CANARY = "cvelab-e2e-secret"

#: What the contract commits to before anything is built: the owner's note
#: comes back to a caller with no credential. Nothing about a status code,
#: because a status code is how the service behaves on every build.
CONTRACT = {
    "observable_effect": "a note the authorized path withholds",
    "evidence_type": "unauthorized_read",
    "effect_predicate": {"body_contains": CANARY},
}

#: The affected build answers, but with nothing in it. A validator deriving
#: `confirmed` from "a reply arrived" calls this a reproduction.
NO_EFFECT = {
    "vulnerable": {"status": 200, "headers": {"Server": "x"},
                   "body": "nothing interesting happened here"},
    "patched": {"status": 403, "headers": {"Server": "x"}, "body": "forbidden"},
}

#: The same lab, actually reproducing.
REAL_EFFECT = {
    "vulnerable": {"status": 200, "headers": {"Server": "x"},
                   "body": f'{{"note": "{CANARY}"}}'},
    "patched": {"status": 403, "headers": {"Server": "x"}, "body": "forbidden"},
}


def run_forked_validator(responses: dict[str, Any], **environment: str) -> str:
    """The forked validator's real stdout, with no network and no container.

    Executed rather than transcribed: a hand-written JSON document would
    test the assertion instead of the path, and the point of the fixture is
    that a validator written this way is what reaches `run_lab`.
    """
    done = subprocess.run(
        [sys.executable, "-I", str(FORKED_VALIDATOR)],
        capture_output=True, text=True, check=False,
        env={"CVELAB_FAKE_RESPONSES": json.dumps(responses), **environment},
    )
    if not done.stdout.strip():
        raise AssertionError(f"the forked validator printed nothing: {done.stderr}")
    return done.stdout


class _LabRun(unittest.TestCase):
    """`run_lab` against a mocked Docker, as tests/test_manual_poc.py does it."""

    CVE = "CVE-2026-0001"

    def _on_disk(self, root: Path, contract: dict, lab_type: str) -> Path:
        lab = root / self.CVE
        sides = ["vulnerable"] if lab_type == "VULNERABLE_ONLY_REPRODUCTION" else [
            "vulnerable", "patched"
        ]
        for side in sides:
            (lab / side).mkdir(parents=True)
            (lab / side / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (lab / "source" / side).mkdir(parents=True)
        (lab / "validator").mkdir(parents=True)
        (lab / "validator" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (lab / "validator" / "validator.py").write_text("", encoding="utf-8")
        (lab / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        (lab / "plan.json").write_text(
            json.dumps({
                "cve": self.CVE,
                "cwe": "CWE-639",
                "lab_type": lab_type,
                "startup_services": sides,
                # Every source plan CVELab writes carries one, and the
                # vulnerable-only branch of the effect check reads it: with
                # no patched build it is the only thing in the plan that says
                # what the lab itself put into the response.
                "marker": CANARY,
                "exploit_contract": contract,
            }),
            encoding="utf-8",
        )
        return lab

    def report(
        self,
        said: str,
        *,
        contract: dict | None = None,
        lab_type: str = "SOURCE_REPRODUCTION",
    ) -> dict:
        def validator(
            _compose: list[str], _docker: str, _environment: dict[str, str],
            _lab_dir: Path, extra: dict[str, str] | None = None,
            wait_for_services: bool = True,
        ) -> tuple[int, str, str]:
            if not extra:
                return 0, said, ""
            return 0, (
                "REPRODUCED" if extra["CVELAB_TARGET"] == "vulnerable" else "BLOCKED"
            ), ""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._on_disk(root, CONTRACT if contract is None else contract, lab_type)
            scratch = root / "limits"
            scratch.mkdir()
            with mock.patch.object(
                        core, "prepare_compose",
                        return_value=("docker", {}, ["docker", "compose"], scratch),
                    ), \
                    mock.patch.object(core, "run_docker_stage"), \
                    mock.patch.object(core, "run_validator", side_effect=validator), \
                    mock.patch(
                        "subprocess.run",
                        return_value=subprocess.CompletedProcess([], 0, "", ""),
                    ):
                outcome = core.run_lab(self.CVE, root, keep=False)
            return outcome["report"]


class SelfCertifyingValidatorTests(_LabRun):
    """The soundness regression, and the most important test here.

    The forked validator prints `proof_quality: security_effect_observed`
    from a differential it computed honestly from a rule that is not the
    effect -- "a reply arrived". Every other proof check passes, so before
    this change the lab reproduced on the strength of the label alone.
    """

    def test_the_label_no_longer_passes_the_gate(self) -> None:
        report = self.report(run_forked_validator(NO_EFFECT))

        self.assertIs(report["proof_checks"]["security_effect_observed"], False)
        self.assertIs(report["real_poc_verified"], False)
        self.assertIs(report["ok"], False)
        # And the label it claimed is still in the report, and the
        # disagreement is written down rather than swallowed.
        self.assertEqual(
            report["validation"]["proof_quality"], "security_effect_observed"
        )
        self.assertEqual(
            report["proof_quality_agreement"], "claimed_but_not_measured"
        )

    def test_the_effect_check_is_the_only_one_that_failed(self) -> None:
        """Otherwise this would prove something other than what it claims.

        A validator the rest of the contract rejects would fail for other
        reasons, and the test would pass with the defect still in place.
        """
        report = self.report(run_forked_validator(NO_EFFECT))

        self.assertEqual(
            sorted(
                name for name, passed in report["proof_checks"].items()
                if passed is False
            ),
            ["security_effect_observed"],
        )

    def test_the_evidence_says_which_side_failed(self) -> None:
        report = self.report(run_forked_validator(NO_EFFECT))
        evidence = "\n".join(report["effect_evidence"])

        self.assertIn("vulnerable: body_contains", evidence)
        self.assertIn("patched: body_contains", evidence)
        self.assertIn("effect on vulnerable=False", evidence)

    def test_a_real_effect_still_passes(self) -> None:
        """The check has to keep its teeth without losing them."""
        report = self.report(run_forked_validator(REAL_EFFECT))

        self.assertIs(report["proof_checks"]["security_effect_observed"], True)
        self.assertIs(report["real_poc_verified"], True)
        self.assertIs(report["ok"], True)
        self.assertEqual(report["proof_quality_agreement"], "agrees")


class VacuousPredicateTests(_LabRun):
    """A predicate loose enough to pass is what makes it fail.

    This is the part that makes the fix real rather than cosmetic. Executed
    against the evaluator before this change, `{"body_contains": ""}` held
    against a body reading "nothing interesting happened here", as did
    `{"body_regex": ".*"}` and `{"status": [200, 500]}`. Under the
    differential they all hold on the patched side too, so substance is
    enforced by the comparison rather than by a blocklist of degenerate
    patterns -- there is nothing to write around, because the looser the
    predicate the more certainly it fails.
    """

    VACUOUS = (
        {"body_contains": ""},
        {"body_regex": ".*"},
        {"status": [200, 403]},
    )

    def test_a_vacuous_predicate_fails_a_differential_lab(self) -> None:
        for declared in self.VACUOUS:
            with self.subTest(predicate=declared):
                report = self.report(
                    run_forked_validator(REAL_EFFECT),
                    contract={**CONTRACT, "effect_predicate": declared},
                )
                self.assertIs(
                    report["proof_checks"]["security_effect_observed"], False
                )
                self.assertIn(
                    "effect on vulnerable=True effect on patched=True",
                    "\n".join(report["effect_evidence"]),
                )

    def test_an_undeclared_predicate_measures_nothing(self) -> None:
        """A contract from before this field existed reproduces nothing.

        Fail closed and on purpose: such a run was never measured, and the
        archived labs confirm it could not have been -- of 86 passes
        recorded under benchmarks/, not one declared a predicate and not one
        printed response headers.
        """
        report = self.report(
            run_forked_validator(REAL_EFFECT),
            contract={k: v for k, v in CONTRACT.items() if k != "effect_predicate"},
        )

        self.assertIs(report["proof_checks"]["security_effect_observed"], False)
        self.assertIn("declared no effect predicate", report["effect_evidence"][0])

    def test_a_validator_that_prints_no_observations_measures_nothing(self) -> None:
        said = json.loads(run_forked_validator(REAL_EFFECT))
        for side in ("vulnerable", "patched"):
            said[side].pop("observations")

        report = self.report(json.dumps(said))

        self.assertIs(report["proof_checks"]["security_effect_observed"], False)
        self.assertIn(
            "which was not observed", "\n".join(report["effect_evidence"])
        )


class VulnerableOnlyMeasurementTests(_LabRun):
    """With no patched build, the predicate is measured on one side only."""

    CONTRACT = {
        "observable_effect": "a note the authorized path withholds",
        "evidence_type": "unauthorized_read",
        "effect_predicate": {"body_contains": CANARY},
    }

    def _said(self, responses: dict[str, Any]) -> str:
        said = json.loads(run_forked_validator(responses))
        said["patched_tested"] = False
        said["fix_status"] = "PUBLIC_FIX_NOT_IDENTIFIED"
        said["differential_confirmed"] = False
        said.pop("patched")
        return json.dumps(said)

    def test_the_effect_on_the_only_build_decides(self) -> None:
        report = self.report(
            self._said(REAL_EFFECT), contract=self.CONTRACT,
            lab_type="VULNERABLE_ONLY_REPRODUCTION",
        )
        self.assertIs(report["proof_checks"]["security_effect_observed"], True)

        report = self.report(
            self._said(NO_EFFECT), contract=self.CONTRACT,
            lab_type="VULNERABLE_ONLY_REPRODUCTION",
        )
        self.assertIs(report["proof_checks"]["security_effect_observed"], False)

    #: A body that holds the lab's canary and a text the product prints by
    #: itself, so one predicate can be measured against the other with the
    #: observation held fixed. Both clauses hold here; only one of them says
    #: anything about the weakness.
    AMBIGUOUS = {
        "vulnerable": {
            "status": 200, "headers": {"Server": "x"},
            "body": f"Allowed memory size of 8388608 bytes exhausted {CANARY}",
        },
        "patched": {"status": 403, "headers": {"Server": "x"}, "body": "forbidden"},
    }

    def test_a_predicate_the_product_satisfies_by_itself_no_longer_passes(self) -> None:
        """The soundness regression for a lab with nothing to compare against.

        This is 109618 replayed through run_lab: the predicate holds on the
        only build there is, every other proof check passes, and before this
        change the lab reproduced on the strength of a message the runtime
        prints for any script that exceeds its configured limit.
        """
        report = self.report(
            self._said(self.AMBIGUOUS),
            contract={
                **self.CONTRACT,
                "effect_predicate": {
                    "body_regex": r"Allowed memory size of [0-9]+ bytes exhausted"
                },
            },
            lab_type="VULNERABLE_ONLY_REPRODUCTION",
        )

        self.assertIs(report["proof_checks"]["security_effect_observed"], False)
        self.assertIs(report["real_poc_verified"], False)
        self.assertIs(report["ok"], False)
        # And the effect check is the only one that failed, so this proves
        # what it claims rather than passing on an unrelated refusal.
        self.assertEqual(
            sorted(
                name for name, passed in report["proof_checks"].items()
                if passed is False
            ),
            ["security_effect_observed"],
        )

    def test_the_evidence_keeps_the_measurement_and_adds_the_reason(self) -> None:
        """Both lines, because the predicate did hold.

        The refused lab's whole evidence record read "body_regex='Allowed
        memory size of [0-9]+ bytes exhausted' passed=True", which is true
        and left a reader of the report nothing to go on. Dropping that line
        in favour of the refusal would make the same mistake the other way
        round.
        """
        report = self.report(
            self._said(self.AMBIGUOUS),
            contract={
                **self.CONTRACT,
                "effect_predicate": {
                    "body_regex": r"Allowed memory size of [0-9]+ bytes exhausted"
                },
            },
            lab_type="VULNERABLE_ONLY_REPRODUCTION",
        )
        evidence = "\n".join(report["effect_evidence"])

        self.assertIn("vulnerable: body_regex=", evidence)
        self.assertIn("passed=True", evidence)
        self.assertIn(f"no clause quotes the canary {CANARY} this lab planted", evidence)
        self.assertIn("not something the attack introduced", evidence)

    def test_the_same_predicate_still_passes_a_differential_lab(self) -> None:
        """The change is confined to the branch that has no comparison.

        Same contract, same observation on the vulnerable side, a patched
        side that does not produce the effect -- and the lab reproduces. A
        differential lab's predicate is judged by the comparison, which is
        the stronger test and the one that cannot be written around; 43 of
        the 53 archived differential predicates quote no marker and must go
        on being measured that way.
        """
        report = self.report(
            run_forked_validator(self.AMBIGUOUS),
            contract={
                **self.CONTRACT,
                "effect_predicate": {
                    "body_regex": r"Allowed memory size of [0-9]+ bytes exhausted"
                },
            },
        )

        self.assertIs(report["proof_checks"]["security_effect_observed"], True)
        self.assertIs(report["ok"], True)
        self.assertNotIn("canary", "\n".join(report["effect_evidence"]))

    def test_a_plan_with_no_canary_measures_nothing(self) -> None:
        """A vulnerable-only plan that records no marker fails the gate.

        Refused at generation, so reaching run_lab means the plan was
        edited, or was written before the rule existed -- which is how the
        measured case holds a VALIDATED report to this day. Failing closed
        is what makes revalidating such a lab not reproduce it.
        """
        held, evidence = core.effect_observed(
            json.loads(self._said(REAL_EFFECT)), self.CONTRACT, True, None
        )

        self.assertIs(held, False)
        self.assertIn("this plan records no canary", "\n".join(evidence))


class DeclarationRefusedBeforeAnyBuildTests(unittest.TestCase):
    """A predicate that cannot measure is refused for one model call.

    `predicate.evaluate` ignores a key it does not know, which is what the
    closed path has always done, so `{"status": 500, "body_contins": "x"}`
    is decided on the status alone -- weaker than it reads, and a free pass
    on the mandatory check. Nothing validated a predicate's kinds at
    declaration time, which is why a misspelling bought one.
    """

    def declared(self, **predicate: object) -> dict:
        return {
            "attack_summary": "a", "preconditions": [], "observable_effect": "e",
            "evidence_type": "unauthorized_read",
            "effect_predicate": dict(predicate),
        }

    def test_a_misspelled_kind_is_refused(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "body_contins"):
            sourcegen._validate_effect_predicate(
                self.declared(status=[500], body_contins="x")
            )

    def test_an_invented_kind_is_refused(self) -> None:
        """`absent` and `equals` do not exist and must not start existing.

        closed.py embeds a second copy of the evaluator in the PoC script it
        ships to reviewers, which runs in a sidecar with no CVELab to
        import, so a fifth kind would have to be written twice.
        """
        for invented in ("absent", "equals"):
            with self.subTest(kind=invented):
                with self.assertRaisesRegex(RuntimeError, invented):
                    sourcegen._validate_effect_predicate(
                        self.declared(**{"body_contains": "x", invented: "y"})
                    )

    def test_a_declaration_with_no_kind_at_all_is_refused(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "at least one"):
            sourcegen._validate_effect_predicate(self.declared())

    def test_the_nulls_a_strict_schema_forces_are_dropped(self) -> None:
        """Every kind is `required` with a null alternative, so they arrive.

        OpenAI's strict structured output rejects a property that is not
        required, which is why every other object in these schemas requires
        all of its properties. A kind the contract does not declare must not
        reach plan.json, or the evaluator would look for an observation for
        a clause nobody meant to make.
        """
        contract = self.declared(
            status=None, body_contains="x", body_regex=None, header=None
        )
        self.assertEqual(
            sourcegen._validate_effect_predicate(contract), {"body_contains": "x"}
        )
        self.assertEqual(contract["effect_predicate"], {"body_contains": "x"})

    def test_an_uncompilable_pattern_is_refused_on_every_lab_shape(self) -> None:
        for vulnerable_only in (False, True):
            with self.subTest(vulnerable_only=vulnerable_only):
                with self.assertRaisesRegex(RuntimeError, "usable regular expression"):
                    sourcegen._validate_effect_predicate(
                        self.declared(body_regex="note(["),
                        vulnerable_only=vulnerable_only,
                    )

    def test_a_status_clause_must_be_whole_numbers(self) -> None:
        for bad in ([], "200", [200, "500"], [True]):
            with self.subTest(status=bad):
                with self.assertRaisesRegex(RuntimeError, "whole response status"):
                    sourcegen._validate_effect_predicate(self.declared(status=bad))

    def test_a_header_clause_must_name_a_header_and_its_text(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "name and the text"):
            sourcegen._validate_effect_predicate(
                self.declared(header={"name": "X-Tok"})
            )

    def test_the_refusal_costs_one_model_call_and_no_build(self) -> None:
        """Which is the whole reason it belongs in the `_check` path.

        `_answer_until_valid` catches a RuntimeError from check, feeds the
        message back and asks again; a refusal there used to cost a whole
        generation attempt or one of the three repairs. So this asserts the
        shape of the refusal, not only its text: a RuntimeError the retry
        loop recognises, raised with nothing built.
        """
        asked = []

        def ask(refused: str) -> dict:
            asked.append(refused)
            return {"exploit_contract": self.declared(body_contins="x")}

        with mock.patch.dict("os.environ", {"CVELAB_CONTRACT_RETRIES": "2"}):
            with self.assertRaisesRegex(RuntimeError, "body_contins"):
                sourcegen._answer_until_valid(
                    ask,
                    lambda generation: [
                        sourcegen._validate_effect_predicate(
                            generation["exploit_contract"]
                        )
                    ],
                )

        self.assertEqual(len(asked), 3)
        self.assertIn("REFUSED BEFORE ANY BUILD", asked[-1])
        self.assertIn("body_contins", asked[-1])


class VulnerableOnlySubstanceTests(unittest.TestCase):
    """The syntactic minimum, in the one place it is needed.

    A differential lab needs no such rule -- a loose predicate holds on the
    patched build too and fails itself -- and giving it one would be a
    blocklist of degenerate spellings, which is the kind of check a model
    that wants to pass writes around. A vulnerable-only lab has no patched
    build, so the declaration is all there is.
    """

    def declared(self, **predicate: object) -> dict:
        return {
            "attack_summary": "a", "preconditions": [], "observable_effect": "e",
            "evidence_type": "unauthorized_read",
            "effect_predicate": dict(predicate),
        }

    def check(self, **predicate: object) -> dict:
        return sourcegen._validate_effect_predicate(
            self.declared(**predicate), vulnerable_only=True, marker=CANARY
        )

    def test_status_alone_cannot_carry_a_vulnerable_only_proof(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "cannot rest on status alone"):
            self.check(status=[200])
        # However narrow. The rule is about what a status code can mean, not
        # about how many of them are named, which is why it needs no
        # cardinality to pick and defend.
        with self.assertRaisesRegex(RuntimeError, "cannot rest on status alone"):
            self.check(status=[500, 502, 503])

    def test_status_may_narrow_a_proof_it_does_not_carry(self) -> None:
        self.assertEqual(
            self.check(status=[200], body_contains=f"owner-note {CANARY}"),
            {"status": [200], "body_contains": f"owner-note {CANARY}"},
        )

    def test_an_empty_needle_is_refused(self) -> None:
        for empty in ("", " ", "\t\n"):
            with self.subTest(needle=repr(empty)):
                with self.assertRaisesRegex(RuntimeError, "is empty"):
                    self.check(body_contains=empty)

    def test_a_pattern_that_matches_the_empty_string_is_refused(self) -> None:
        """The general form of "no pattern equivalent to `.*`".

        A blocklist of spellings would have caught the first of these and
        missed the rest; all five hold against any response whatever, and
        all five match the empty string.
        """
        for pattern in (".*", ".*?", "(.*)", "x?", "owner|"):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(RuntimeError, "matches the empty string"):
                    self.check(body_regex=pattern)

    def test_a_pattern_that_requires_a_character_is_accepted(self) -> None:
        for pattern in (CANARY, rf"note\":\s*\"{CANARY}", f"{CANARY}-[0-9]+"):
            with self.subTest(pattern=pattern):
                self.assertEqual(self.check(body_regex=pattern), {"body_regex": pattern})

    def test_an_empty_header_clause_is_refused(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "holds against any response"):
            self.check(header={"name": "X-Tok", "contains": ""})
        self.assertEqual(
            self.check(header={"name": "X-Tok", "contains": f"owner-{CANARY}"}),
            {"header": {"name": "X-Tok", "contains": f"owner-{CANARY}"}},
        )

    def test_a_differential_lab_keeps_its_loose_predicates(self) -> None:
        """Deliberately: the differential is what refuses them, at run time.

        Refusing them here as well would read as belt and braces and is
        worse than it looks -- it would make the comparison untested, and
        the comparison is the part that cannot be written around.
        """
        for declared in ({"body_contains": ""}, {"body_regex": ".*"}, {"status": [200, 500]}):
            with self.subTest(predicate=declared):
                sourcegen._validate_effect_predicate(self.declared(**declared))


class VulnerableOnlyAnchorTests(VulnerableOnlySubstanceTests):
    """The declared effect has to be something the attack introduced.

    THE DEFECT THESE PIN, MEASURED

    Looseness was the only thing the substance rules looked at, and a
    predicate can be perfectly tight and still measure nothing. The archived
    lab that showed it declared

        {"body_regex": "Allowed memory size of [0-9]+ bytes exhausted"}

    which names a specific text, is not a status clause and cannot match the
    empty string, so both earlier rules passed it -- and the runtime prints
    that text for any script at all that exceeds its configured limit, on a
    fixed build as readily as on this one. The lab validated, recorded
    PUBLIC_FIX_NOT_IDENTIFIED, and had PoC.py, MANUAL-POC.md, REPORT.md and
    EVIDENCE.json written for it. Only the manual-PoC drafter objected, and
    it objected in prose, to a human, after the automatic path had passed.

    The subclass inherits the earlier rules deliberately: they still have to
    hold, and a refusal must still name the cheapest thing wrong with the
    declaration rather than reaching for this one first.
    """

    #: What the vulnerable-only labs in the archive declared, and the verdict
    #: each must get. Written out rather than described: these three are the
    #: entire measured population, two of them are the reason this rule
    #: exists, and the third is the one lab that must keep passing.
    ARCHIVED = (
        ("quotes its canary", {"status": [200], "body_contains": CANARY}, True),
        ("a runtime's own limit message", {"body_regex": r"Allowed memory size of [0-9]+ bytes exhausted"}, False),
        ("no predicate at all", {}, False),
    )

    def test_the_three_archived_vulnerable_only_predicates(self) -> None:
        """Accept one, refuse two, and refuse them for the right reasons."""
        for description, declared, accepted in self.ARCHIVED:
            with self.subTest(predicate=description):
                if accepted:
                    self.assertEqual(self.check(**declared), declared)
                elif declared:
                    with self.assertRaisesRegex(RuntimeError, "must quote the canary"):
                        self.check(**declared)
                else:
                    # Refused further up, by the rule that a contract
                    # declaring no kind measures nothing, and left there:
                    # the earlier message is the one that tells a repair
                    # what to write.
                    with self.assertRaisesRegex(RuntimeError, "must declare at least one of"):
                        self.check(**declared)

    def test_a_tight_text_that_names_nothing_the_attack_introduced_is_refused(self) -> None:
        """Specificity is not substance, which is what 109618 cost to learn.

        Each of these is non-empty, cannot match the empty string and is not
        a status clause, so every earlier rule accepts it. None of them says
        anything the attack put there.
        """
        for declared in (
            {"body_regex": ".+"},
            {"body_contains": "Internal Server Error"},
            {"body_regex": r"Fatal error: [a-z ]+ exhausted"},
            {"status": [500], "body_contains": "Traceback (most recent call last)"},
            {"header": {"name": "X-Powered-By", "contains": "PHP/"}},
        ):
            with self.subTest(predicate=declared):
                with self.assertRaisesRegex(RuntimeError, "must quote the canary"):
                    self.check(**declared)

    def test_the_canary_may_sit_inside_the_text_the_clause_names(self) -> None:
        """Containment, not equality.

        A clause naming only the canary and nothing else would be the only
        legal shape under equality, and that would be worse rather than
        stricter: the stronger declaration is the one that says where in the
        response the canary has to appear.
        """
        for declared in (
            {"body_contains": f'{{"note": "{CANARY}"}}'},
            {"body_regex": rf'"note":\s*"{CANARY}"'},
            {"header": {"name": "Set-Cookie", "contains": f"session={CANARY}"}},
        ):
            with self.subTest(predicate=declared):
                self.assertEqual(self.check(**declared), declared)

    def test_a_header_name_is_not_a_value(self) -> None:
        """Only what was observed can carry what the attack introduced.

        The name says which header is read. A canary in the name would be a
        canary in the question rather than in the answer, and a lab could
        satisfy it by asking about a header that is never sent.
        """
        with self.assertRaisesRegex(RuntimeError, "must quote the canary"):
            self.check(header={"name": CANARY, "contains": "something"})

    def test_a_placeholder_is_refused_because_nothing_fills_it(self) -> None:
        """`inputs` cannot be what a predicate quotes, and this is why.

        `exploit_contract.inputs` names values an operator supplies to the
        shipped PoC; they are never present in the lab, and no code path
        substitutes {{name}} into a predicate. Accepting one would accept a
        clause that can never hold against any response.
        """
        with self.assertRaisesRegex(RuntimeError, "must quote the canary"):
            self.check(body_contains="{{marker}}")

    def test_a_lab_with_no_canary_is_refused_rather_than_exempted(self) -> None:
        """Otherwise an absent marker would switch the rule off silently.

        Not reachable from a lab CVELab generated -- every source plan it
        writes records a marker, and all three archived vulnerable-only
        plans do -- which is exactly why it must not read as permission.
        """
        for absent in (None, "", "   "):
            with self.subTest(marker=repr(absent)):
                with self.assertRaisesRegex(RuntimeError, "records none"):
                    sourcegen._validate_effect_predicate(
                        self.declared(body_contains=CANARY),
                        vulnerable_only=True,
                        marker=absent,
                    )

    def test_a_differential_lab_is_not_held_to_the_canary(self) -> None:
        """The comparison judges those, and it judges them better.

        Of the 53 predicates the archived differential labs recorded, 43
        name an attacker-supplied value or a field the adapter computes
        rather than the marker -- a spoofed address, a reflected payload, a
        traversal path, a boolean the harness prints. Holding a differential
        lab to this rule would refuse four out of five of them for no gain,
        because a predicate that does not describe the effect already fails
        by holding on the patched side.
        """
        for declared in (
            {"body_contains": '"client_ip":"20.20.20.20"'},
            {"body_contains": "onerror=alert(1)"},
            {"body_regex": r'"name"\s*:\s*"\.\./'},
            {"body_contains": "EVENT_LOOP_BLOCKED"},
            {"header": {"name": "Location", "contains": "%5C@attacker"}},
        ):
            with self.subTest(predicate=declared):
                self.assertEqual(
                    sourcegen._validate_effect_predicate(self.declared(**declared)),
                    declared,
                )


class ContractPlumbingTests(unittest.TestCase):
    """The declaration reaches the schema, the checks and the prompts."""

    SOURCE = Path(sourcegen.__file__).read_text(encoding="utf-8")

    def test_both_schemas_require_the_declaration(self) -> None:
        for schema in (sourcegen.SOURCE_SCHEMA, sourcegen.VULNERABLE_ONLY_SCHEMA):
            contract = schema["properties"]["exploit_contract"]
            self.assertIn("effect_predicate", contract["required"])
            self.assertIn("effect_predicate", contract["properties"])

    def test_the_schema_offers_the_four_kinds_that_exist_and_no_others(self) -> None:
        from cvelab import predicate

        offered = sourcegen.EFFECT_PREDICATE_SCHEMA["properties"]
        self.assertEqual(sorted(offered), sorted(predicate.KINDS))
        self.assertEqual(
            sorted(sourcegen.EFFECT_PREDICATE_SCHEMA["required"]),
            sorted(predicate.KINDS),
        )
        self.assertIs(
            sourcegen.EFFECT_PREDICATE_SCHEMA["additionalProperties"], False
        )

    def test_every_answer_that_writes_the_contract_is_checked(self) -> None:
        """Generation, vulnerable-only generation and repair, all three.

        The repair rewrites plan["exploit_contract"] from its own answer, so
        it can install an unmeasurable predicate exactly as a generation
        can.

        Read off the parsed module rather than off three literal spellings of
        the call. The spellings were what this asserted, and they broke on a
        reformatting that changed nothing about which answers are checked --
        so the test failed where the property it names still held, which is
        the one way a guard like this can mislead.
        """
        checked = [
            node
            for node in ast.walk(ast.parse(self.SOURCE))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_validate_effect_predicate"
        ]
        self.assertEqual(len(checked), 3)
        for call in checked:
            argument = call.args[0] if call.args else None
            self.assertIsInstance(argument, ast.Subscript, ast.dump(call))
            self.assertEqual(argument.value.id, "generation")
        self.assertEqual(self.SOURCE.count('plan["exploit_contract"] = generation'), 1)

    def test_every_vulnerable_only_check_is_given_the_canary(self) -> None:
        """Otherwise the rule would refuse the lab instead of its predicate.

        `_vulnerable_only_substance` holds the declaration to the marker the
        lab planted, and refuses outright when no marker reaches it -- the
        honest answer, since nothing then says what the lab put there. That
        makes a call site which forgets to pass one a refusal of every
        vulnerable-only lab rather than of an unanchored predicate, and the
        failure would read as the rule being wrong.
        """
        for call in [
            node
            for node in ast.walk(ast.parse(self.SOURCE))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_validate_effect_predicate"
        ]:
            named = {keyword.arg for keyword in call.keywords}
            if "vulnerable_only" in named:
                self.assertIn("marker", named, ast.dump(call))

    def test_the_validator_must_print_its_observations(self) -> None:
        validator = " ".join([
            "attack_executed", "proof_quality", "observable_effect", "evidence_type",
            "vulnerable", "patched", "differential_confirmed", "confirmed", "blocked",
            "CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "exploit", "verify", "sys.argv",
        ])
        from tests.test_sourcegen_contract import generated_files

        with self.assertRaisesRegex(RuntimeError, "observations"):
            sourcegen._validate_generated(generated_files(validator))
        sourcegen._validate_generated(generated_files(validator + " observations"))

    def test_proof_quality_is_not_added_to_the_anti_hardcoding_guard(self) -> None:
        """And must not be. The comment above that guard records why.

        Banning the literal `confirmed` "rejected every validator written
        exactly as asked, across two unrelated model families, on all four
        attempts". Once CVELab evaluates the predicate the label is not
        load-bearing, so banning it would cost generations and buy nothing.
        """
        self.assertIn("confirmed|differential_confirmed", self.SOURCE)
        self.assertNotIn("proof_quality|confirmed", self.SOURCE)
        self.assertNotIn("confirmed|differential_confirmed|proof_quality", self.SOURCE)

    def test_all_three_prompts_ask_for_the_declaration_and_the_observations(self) -> None:
        self.assertEqual(self.SOURCE.count("+ _EFFECT_CONTRACT"), 3)
        self.assertIn("exploit_contract.effect_predicate", sourcegen._EFFECT_CONTRACT)
        self.assertIn("under the key observations", sourcegen._EFFECT_CONTRACT)

    def test_the_pinned_sentence_keeps_its_place_in_both_prompt_blocks(self) -> None:
        """The constraint the prompt edit had to be designed around.

        tests/test_sourcegen_contract.py requires "Measure confirmed the
        same way on both sides" inside the first 2000 characters of each
        contract prompt. Measured here: the vulnerable-only block has 1657
        characters of room ahead of it and the differential block 361, so
        the new instruction text is appended after the sentence rather than
        inserted ahead of it. Asserted at a margin, not at the exact offset,
        so that an unrelated edit to the prose ahead of the sentence is free
        to move it a little and is told when it has moved it too far.
        """
        blocks = self.SOURCE.split("the literal keys attack_executed")
        self.assertEqual(len(blocks), 3)
        for number, block in enumerate(blocks[1:], 1):
            with self.subTest(prompt=number):
                self.assertLess(
                    block.index("Measure confirmed the same way on both sides"), 1700
                )


class ShipyardMeasurementTests(unittest.TestCase):
    """The second instance of the same defect, on the end-to-end path.

    `shipyard_report` read `proof_quality` out of e2e/result.json, a file an
    arbitrary script writes, and treated the string
    "end_to_end_security_effect_observed" as a mandatory proof. Nothing in
    CVELab generates a Shipyard runner, so there is no generation step here
    in which a predicate could be declared and refused -- which is why this
    path fails closed rather than being made to pass.
    """

    def report(self, validation: dict, contract: dict) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            lab_dir = Path(temporary)
            (lab_dir / "e2e").mkdir()
            (lab_dir / "e2e" / "result.json").write_text(json.dumps(validation))
            plan = {
                "cwe": "CWE-284",
                "lab_type": "END_TO_END_REPRODUCTION",
                "exploit_contract": contract,
                "fidelity": {"execution_level": "product_end_to_end"},
            }
            return core.shipyard_report("CVE-2026-0001", lab_dir, plan)["report"]

    def _validation(self, body: str) -> dict:
        return {
            "attack_executed": True,
            "proof_quality": "end_to_end_security_effect_observed",
            "observable_effect": "protected object created",
            "evidence_type": "authorization_bypass",
            "differential_confirmed": True,
            "vulnerable": {
                "confirmed": True,
                "observations": {"status": 200, "headers": {}, "body": body},
            },
            "patched": {
                "confirmed": False, "rejection_logged": True,
                "observations": {"status": 403, "headers": {}, "body": "forbidden"},
            },
        }

    CONTRACT = {
        "observable_effect": "protected object created",
        "evidence_type": "authorization_bypass",
        "effect_predicate": {"body_contains": "object-created"},
    }

    def test_a_measured_end_to_end_run_still_passes(self) -> None:
        report = self.report(self._validation("object-created"), self.CONTRACT)

        self.assertIs(report["proof_checks"]["security_effect_observed"], True)
        self.assertIs(report["real_poc_verified"], True)
        self.assertIs(report["product_e2e_verified"], True)
        self.assertEqual(report["proof_quality_agreement"], "agrees")

    def test_the_label_alone_no_longer_passes_the_gate(self) -> None:
        report = self.report(self._validation("nothing happened"), self.CONTRACT)

        self.assertIs(report["proof_checks"]["security_effect_observed"], False)
        self.assertIs(report["real_poc_verified"], False)
        self.assertIs(report["product_e2e_verified"], False)
        self.assertEqual(report["proof_quality_agreement"], "claimed_but_not_measured")

    def test_a_plan_that_declares_no_predicate_fails_closed(self) -> None:
        report = self.report(
            self._validation("object-created"),
            {k: v for k, v in self.CONTRACT.items() if k != "effect_predicate"},
        )

        self.assertIs(report["proof_checks"]["security_effect_observed"], False)
        self.assertIs(report["ok"], False)


class CoreStaysIndependentTests(unittest.TestCase):
    """predicate.py is stdlib-only, which is what makes it safe to import.

    tests/test_manual_poc.py asserts core imports neither field, nor a
    provider, nor structured_response; a lab is built and validated with no
    model configured at all, and that import graph is what keeps the two
    independent.
    """

    def test_the_evaluator_reaches_for_nothing(self) -> None:
        from cvelab import predicate

        source = Path(predicate.__file__).read_text(encoding="utf-8")
        for line in source.splitlines():
            if line.startswith(("import ", "from ")):
                self.assertNotIn("cvelab", line)
                self.assertNotIn("from .", line.replace("from __future__", ""))

    def test_core_still_learns_nothing_about_providers(self) -> None:
        source = Path(core.__file__).read_text(encoding="utf-8")
        self.assertIn("from . import policy, predicate, progress", source)
        self.assertNotIn("from .field import", source)
        self.assertNotIn("structured_response", source)


if __name__ == "__main__":
    unittest.main()
