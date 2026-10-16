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

from cvelab.core import run_shipyard_script, shipyard_report


class ShipyardRunnerTests(unittest.TestCase):
    @unittest.skipIf(__import__("os").name == "nt", "native Linux runner test")
    def test_native_runner_executes_bash_script(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab_dir = Path(temporary)
            script = lab_dir / "e2e" / "run.sh"
            script.parent.mkdir(parents=True)
            script.write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\nprintf ran > e2e/native.txt\n",
                encoding="utf-8",
            )

            with mock.patch("cvelab.core.ensure_docker"):
                run_shipyard_script(lab_dir, {"script": "e2e/run.sh"})

            self.assertEqual((lab_dir / "e2e" / "native.txt").read_text(), "ran")

    def test_missing_script_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(RuntimeError, "was not found"):
            run_shipyard_script(Path(temporary), {"script": "e2e/missing.sh"})

    @unittest.skipIf(__import__("os").name == "nt", "native Linux runner test")
    def test_failure_hint_does_not_assume_vpn_is_the_cause(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab_dir = Path(temporary)
            script = lab_dir / "e2e" / "run.sh"
            script.parent.mkdir(parents=True)
            script.write_text("#!/usr/bin/env bash\nexit 125\n", encoding="utf-8")

            with mock.patch("cvelab.core.ensure_docker"), self.assertRaisesRegex(
                RuntimeError,
                "exit 125 normally means Docker could not create or start",
            ):
                run_shipyard_script(lab_dir, {"script": "e2e/run.sh"})

    def test_report_requires_differential_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab_dir = Path(temporary)
            evidence_dir = lab_dir / "e2e"
            evidence_dir.mkdir()
            evidence = {
                "attack_executed": True,
                "proof_quality": "end_to_end_security_effect_observed",
                "observable_effect": "protected object created",
                "evidence_type": "authorization_bypass",
                "differential_confirmed": True,
                "vulnerable": {"confirmed": True},
                "patched": {"confirmed": False, "rejection_logged": True},
            }
            (evidence_dir / "result.json").write_text(json.dumps(evidence))
            plan = {
                "cwe": "CWE-284",
                "lab_type": "END_TO_END_REPRODUCTION",
                "exploit_contract": {
                    "observable_effect": "protected object created",
                    "evidence_type": "authorization_bypass",
                },
                "fidelity": {"execution_level": "product_end_to_end"},
            }

            result = shipyard_report("CVE-2026-66788", lab_dir, plan)

            self.assertTrue(result["ok"])
            self.assertTrue(result["report"]["real_poc_verified"])
            self.assertTrue(result["report"]["product_e2e_verified"])
            self.assertTrue((lab_dir / "report.json").is_file())


if __name__ == "__main__":
    unittest.main()
