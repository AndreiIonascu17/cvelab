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


if __name__ == "__main__":
    unittest.main()
