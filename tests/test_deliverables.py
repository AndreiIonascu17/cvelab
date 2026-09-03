from __future__ import annotations

import json
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
            subprocess.run(
                ["bash", "-n", str(lab / "artifacts" / "manual.sh")],
                check=True,
            )


if __name__ == "__main__":
    unittest.main()
