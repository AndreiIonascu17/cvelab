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

"""The evaluator that decides whether a declared effect actually happened.

The point of the module under test is that the predicate is declared before
the run and decided by CVELab afterwards, so these tests are mostly about the
cases where it must refuse to say the effect happened.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from cvelab import predicate

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

#: An HTTP observation, which on this path is already a plain mapping.
RESPONSE: dict[str, Any] = {
    "status": 200,
    "headers": {"Server": "nginx/1.25", "X-Report-Token": "tok-abc"},
    "body": 'canary 42 {"role":"admin"}',
}


class VocabularyTests(unittest.TestCase):
    """The kinds are the closed-lab contract's, unchanged by the move."""

    def test_the_kinds_are_the_ones_the_contract_declares(self) -> None:
        self.assertEqual(
            predicate.KINDS, ("status", "body_contains", "body_regex", "header")
        )

    def test_every_kind_names_the_observation_it_reads(self) -> None:
        self.assertEqual(sorted(predicate.READS), sorted(predicate.KINDS))
        self.assertEqual(
            {predicate.READS[kind] for kind in predicate.KINDS},
            {"status", "body", "headers"},
        )

    def test_a_key_that_is_not_a_kind_is_reported_rather_than_obeyed(self) -> None:
        """Ignoring it is what the closed path has always done, silently.

        A predicate of status plus a misspelled body check is decided on the
        status alone, which claims less than it looks like it claims. The
        evaluator keeps ignoring it -- changing that is a contract-schema
        decision, not this module's -- but it says which keys it ignored.
        """
        said = {"status": 200, "body_contins": "canary", "note": "typo above"}
        self.assertEqual(predicate.declared_kinds(said), ["status"])
        self.assertEqual(predicate.unknown_kinds(said), ["body_contins", "note"])
        self.assertTrue(predicate.evaluate(RESPONSE, said).held)


class KindTests(unittest.TestCase):
    """Each kind, holding and not holding."""

    def _held(self, **declared: Any) -> bool:
        return predicate.evaluate(RESPONSE, declared).held

    def test_status(self) -> None:
        self.assertTrue(self._held(status=200))
        self.assertTrue(self._held(status=[200, 204]))
        self.assertFalse(self._held(status=404))
        self.assertFalse(self._held(status=[301, 302]))

    def test_body_contains(self) -> None:
        self.assertTrue(self._held(body_contains="canary"))
        self.assertTrue(self._held(body_contains='"role":"admin"'))
        self.assertFalse(self._held(body_contains="not in the body"))

    def test_body_regex(self) -> None:
        self.assertTrue(self._held(body_regex=r"canary\s+\d+"))
        self.assertFalse(self._held(body_regex=r"canary\s+\d+\s+canary"))

    def test_header(self) -> None:
        """The name is matched without case, the value by containment."""
        self.assertTrue(self._held(header={"name": "server", "contains": "nginx"}))
        self.assertTrue(self._held(header={"name": "X-Report-Token", "contains": "tok-"}))
        self.assertFalse(self._held(header={"name": "Server", "contains": "apache"}))
        self.assertFalse(self._held(header={"name": "X-Absent", "contains": "anything"}))

    def test_every_clause_has_to_hold(self) -> None:
        self.assertTrue(self._held(status=200, body_contains="canary"))
        self.assertFalse(self._held(status=200, body_contains="not in the body"))
        self.assertFalse(self._held(status=404, body_contains="canary"))

    def test_the_evidence_names_every_clause_in_a_fixed_order(self) -> None:
        """The lines are quoted into the evidence document, so order is pinned."""
        verdict = predicate.evaluate(
            RESPONSE,
            {
                "header": {"name": "Server", "contains": "nginx"},
                "body_regex": "42",
                "body_contains": "canary",
                "status": 200,
            },
        )
        self.assertEqual(
            verdict.evidence,
            [
                "status=200 allowed=[200] passed=True",
                "body_contains='canary' passed=True",
                "body_regex='42' passed=True",
                "header='Server' contains='nginx' passed=True",
            ],
        )


class UndecidableTests(unittest.TestCase):
    """A predicate nothing can decide must not read as the effect happening.

    `evaluate` refuses to answer, which is how the closed path has always
    failed: the run stops rather than record a verdict it never measured.
    `effect_observed` answers, and the answer is always that the effect was
    not observed.
    """

    CASES: tuple[tuple[str, dict[str, Any], dict[str, Any]], ...] = (
        ("the observation was never made", {"headers": {}, "body": "x"}, {"status": 200}),
        ("no body was observed", {"status": 200, "headers": {}}, {"body_contains": "x"}),
        ("no headers were observed", {"status": 200, "body": "x"},
         {"header": {"name": "a", "contains": "b"}}),
        ("the pattern does not compile", {"status": 200, "headers": {}, "body": "x"},
         {"body_regex": "(unterminated"}),
        ("the header clause is half written", {"status": 200, "headers": {}, "body": "x"},
         {"header": {"name": "a"}}),
        ("the body is not text", {"status": 200, "headers": {}, "body": 7},
         {"body_contains": "7"}),
        ("nothing at all was observed", {}, {"status": 200}),
    )

    def test_the_strict_form_refuses_to_answer(self) -> None:
        for label, observations, declared in self.CASES:
            with self.subTest(label=label):
                with self.assertRaises(predicate.PredicateError):
                    predicate.evaluate(observations, declared)

    def test_refusing_is_still_a_contract_error(self) -> None:
        """Every caller between here and the CLI reads ValueError that way."""
        self.assertTrue(issubclass(predicate.PredicateError, ValueError))

    def test_an_empty_predicate_is_refused(self) -> None:
        for declared in ({}, {"not_a_kind": "x"}):
            with self.subTest(declared=declared):
                with self.assertRaises(predicate.PredicateError) as raised:
                    predicate.evaluate(RESPONSE, declared, where="effect_predicate")
                self.assertIn("effect_predicate", str(raised.exception))

    def test_the_fail_closed_form_answers_not_observed(self) -> None:
        for label, observations, declared in self.CASES:
            with self.subTest(label=label):
                verdict = predicate.effect_observed(observations, declared)
                self.assertFalse(verdict.held)
                self.assertTrue(verdict.evidence, "an undecidable clause still reports")
                for line in verdict.evidence:
                    self.assertIn("passed=False", line)
                    self.assertNotIn("passed=True", line)

    def test_the_fail_closed_form_never_raises(self) -> None:
        for declared in ({}, {"not_a_kind": "x"}):
            with self.subTest(declared=declared):
                verdict = predicate.effect_observed(RESPONSE, declared, where="effect_predicate")
                self.assertFalse(verdict.held)
                self.assertIn("effect_predicate", verdict.evidence[0])
                self.assertIn("passed=False", verdict.evidence[0])

    def test_one_undecidable_clause_does_not_hide_the_others(self) -> None:
        verdict = predicate.effect_observed(
            RESPONSE, {"status": 200, "body_regex": "(unterminated"}
        )
        self.assertFalse(verdict.held)
        self.assertEqual(verdict.evidence[0], "status=200 allowed=[200] passed=True")
        self.assertIn("could not be decided", verdict.evidence[1])

    def test_a_decidable_predicate_answers_the_same_either_way(self) -> None:
        for declared in ({"status": 200}, {"status": 404}, {"body_contains": "canary"}):
            with self.subTest(declared=declared):
                self.assertEqual(
                    predicate.evaluate(RESPONSE, declared),
                    predicate.effect_observed(RESPONSE, declared),
                )

    def test_a_number_is_not_read_as_text(self) -> None:
        """Coercion would let a status code satisfy a claim about a body."""
        verdict = predicate.effect_observed({"body": 200}, {"body_contains": "200"})
        self.assertFalse(verdict.held)


class PlainMappingTests(unittest.TestCase):
    """The next caller observes what a validator printed, not a response.

    No HTTP anywhere here: a flat mapping of strings and integers, which is
    the shape a source lab's validator prints.
    """

    OBSERVATIONS: dict[str, Any] = {
        "status": 403,
        "body": "balance=10 owner=other-tenant",
        "attempts": 3,
    }

    def test_a_flat_mapping_decides_a_predicate(self) -> None:
        self.assertTrue(
            predicate.evaluate(self.OBSERVATIONS, {"status": 403, "body_contains": "other-tenant"}).held
        )
        self.assertFalse(
            predicate.evaluate(self.OBSERVATIONS, {"status": 403, "body_contains": "own-tenant"}).held
        )

    def test_no_observation_is_required_for_a_kind_that_is_not_declared(self) -> None:
        """A caller supplies what its predicate reads, not a whole response."""
        self.assertTrue(predicate.evaluate({"body": "root:x:0:0"}, {"body_contains": "root:x:0:0"}).held)
        self.assertTrue(predicate.evaluate({"status": 500}, {"status": [500, 502]}).held)

    def test_the_evaluator_reads_nothing_and_sends_nothing(self) -> None:
        """It is a decision, not a probe, which is why core can import it."""
        source = Path(predicate.__file__).read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "import urllib", "import socket", "from ."):
            self.assertNotIn(forbidden, source, forbidden)


class ShippedContractTests(unittest.TestCase):
    """The predicates this project publishes as examples still decide."""

    def _published(self) -> list[tuple[str, dict[str, Any]]]:
        found: list[tuple[str, dict[str, Any]]] = []
        for path in sorted(EXAMPLES.rglob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            for entry in [payload, *payload.get("cves", {}).values()]:
                contract = entry.get("contract", entry) if isinstance(entry, dict) else {}
                match = contract.get("observe", {}).get("match") if isinstance(contract, dict) else None
                if isinstance(match, dict):
                    found.append((path.name, match))
        self.assertTrue(found, "no published contract predicate was found")
        return found

    def test_each_published_predicate_uses_only_known_kinds(self) -> None:
        for name, match in self._published():
            with self.subTest(contract=name):
                self.assertEqual(predicate.unknown_kinds(match), [])
                self.assertTrue(predicate.declared_kinds(match))

    def test_a_published_predicate_holds_only_on_the_response_it_describes(self) -> None:
        for name, match in self._published():
            with self.subTest(contract=name):
                effect = {
                    "status": 200,
                    "headers": {},
                    "body": str(match.get("body_contains", "")) + " cvelab-canary",
                }
                self.assertTrue(predicate.evaluate(effect, match).held)
                self.assertFalse(
                    predicate.evaluate({**effect, "status": 404, "body": ""}, match).held
                )


if __name__ == "__main__":
    unittest.main()
