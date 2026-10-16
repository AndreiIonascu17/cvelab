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

import unittest

from cvelab.core import _manual_verdict_matches, source_proof_checks


class SourceProofChecksTests(unittest.TestCase):
    def plan(self, evidence_type: str, vulnerable_only: bool = False) -> dict:
        return {
            "lab_type": "VULNERABLE_ONLY_REPRODUCTION" if vulnerable_only else "SOURCE_REPRODUCTION",
            "exploit_contract": {
                "observable_effect": "A protected effect occurs only in the affected revision",
                "evidence_type": evidence_type,
            },
        }

    def validation(self, evidence_type: str) -> dict:
        return {
            "attack_executed": True,
            "proof_quality": "security_effect_observed",
            "observable_effect": "Observed the stated effect on affected code and rejection on fixed code",
            "evidence_type": evidence_type,
            "vulnerable": {"confirmed": True, "raw": {"effect": "canary"}},
            "patched": {"confirmed": False, "blocked": True, "raw": "rejected"},
            "differential_confirmed": True,
        }

    def test_accepts_raw_differential_evidence_for_distinct_vulnerability_classes(self) -> None:
        for evidence_type in ("code_execution", "authorization_bypass", "unauthorized_read"):
            with self.subTest(evidence_type=evidence_type):
                checks = source_proof_checks(self.plan(evidence_type), self.validation(evidence_type))
                self.assertTrue(all(checks.values()), checks)

    def test_rejects_contradictory_patched_verdict(self) -> None:
        evidence = self.validation("code_execution")
        evidence["patched"]["confirmed"] = True
        checks = source_proof_checks(self.plan("code_execution"), evidence)
        self.assertFalse(checks["patched_not_confirmed"])

    def test_rejects_missing_differential_flag(self) -> None:
        evidence = self.validation("authorization_bypass")
        evidence["differential_confirmed"] = False
        checks = source_proof_checks(self.plan("authorization_bypass"), evidence)
        self.assertFalse(checks["differential_confirmed"])

    def test_rejects_missing_or_blank_raw_observations(self) -> None:
        for raw in (None, "", "   ", {}, []):
            with self.subTest(raw=raw):
                evidence = self.validation("authorization_bypass")
                evidence["vulnerable"]["raw"] = raw
                checks = source_proof_checks(self.plan("authorization_bypass"), evidence)
                self.assertFalse(checks["vulnerable_raw_recorded"])

    def test_vulnerable_only_requires_raw_evidence_without_patched_target(self) -> None:
        evidence = self.validation("unauthorized_read")
        evidence.pop("patched")
        evidence.update({
            "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
            "patched_tested": False,
            "differential_confirmed": False,
        })
        checks = source_proof_checks(self.plan("unauthorized_read", vulnerable_only=True), evidence)
        self.assertTrue(all(checks.values()), checks)
        self.assertNotIn("patched_raw_recorded", checks)

    def test_manual_verdict_requires_exact_word(self) -> None:
        self.assertTrue(_manual_verdict_matches("REPRODUCED\n", "REPRODUCED"))
        self.assertTrue(_manual_verdict_matches(" BLOCKED ", "BLOCKED"))
        self.assertFalse(_manual_verdict_matches("NOT REPRODUCED", "REPRODUCED"))
        self.assertFalse(_manual_verdict_matches("BLOCKED maybe", "BLOCKED"))


if __name__ == "__main__":
    unittest.main()
