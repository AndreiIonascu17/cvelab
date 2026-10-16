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

import re
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "cvelab"

# A real identifier, not the CVE-YYYY-NNNNN shape used in help text and docs.
CVE_LITERAL = re.compile(r"CVE-\d{4}-\d{4,7}")


class NoPerCveLogicTests(unittest.TestCase):
    """The generator must treat every CVE identifier the same way.

    CVELab once shipped a curated lab for CVE-2026-66788: a hardcoded commit
    pair and six handwritten templates, emitted whenever that identifier was
    passed. One CVE reproduced perfectly for reasons no other CVE could share,
    which is indistinguishable from a tool rigged to pass its own demo. The
    assets now live in tests/fixtures/lighthouse.py as a regression fixture.

    These tests fail if per-CVE handling reappears in the shipped package.
    """

    def source_files(self) -> list[Path]:
        files = sorted(PACKAGE.rglob("*.py"))
        self.assertTrue(files, "no package sources found")
        return files

    def test_no_cve_identifier_is_hardcoded_in_the_package(self) -> None:
        offenders = []
        for path in self.source_files():
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                for found in CVE_LITERAL.findall(line):
                    offenders.append(f"{path.name}:{number}: {found}")
        self.assertEqual(
            offenders,
            [],
            "A specific CVE identifier is hardcoded in the package. Per-CVE "
            "handling belongs in tests/fixtures, never on the generation "
            "path:\n  " + "\n  ".join(offenders),
        )

    def test_no_curated_source_table_is_shipped(self) -> None:
        banned = ("CURATED_SOURCES", "_generate_curated", "LIGHTHOUSE_")
        offenders = []
        for path in self.source_files():
            text = path.read_text(encoding="utf-8")
            offenders += [f"{path.name}: {name}" for name in banned if name in text]
        self.assertEqual(
            offenders,
            [],
            "A curated per-CVE table or generator is back in the package:\n  "
            + "\n  ".join(offenders),
        )

    def test_the_fixture_is_still_available_to_tests(self) -> None:
        from tests.fixtures.lighthouse import (
            CURATED_REFERENCE,
            LIGHTHOUSE_E2E_RUN_SH,
        )

        self.assertEqual(CURATED_REFERENCE["cve"], "CVE-2026-66788")
        self.assertEqual(len(CURATED_REFERENCE["fixed_ref"]), 40)
        self.assertIn("#!/usr/bin/env bash", LIGHTHOUSE_E2E_RUN_SH)


if __name__ == "__main__":
    unittest.main()
