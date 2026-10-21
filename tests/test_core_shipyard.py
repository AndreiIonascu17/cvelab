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

from cvelab.core import HOST_RUNNER_VARIABLE, run_shipyard_script, shipyard_report

ALLOWED = {HOST_RUNNER_VARIABLE: "1"}


class ShipyardRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        # The runner executes the lab's own script on the host, so every
        # test here opts in the way a user has to.
        patcher = mock.patch.dict("os.environ", ALLOWED)
        patcher.start()
        self.addCleanup(patcher.stop)

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


class HostRunnerGuardTests(unittest.TestCase):
    """plan.json is part of the lab, and a runner is a script run on the host.

    No generator writes one. A lab copied from someone else could name any
    script -- an absolute path, or one that climbs out of the lab -- and on
    Windows any WSL distribution to run it in as root.
    """

    def lab(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab_dir = Path(temporary.name) / "lab"
        (lab_dir / "e2e").mkdir(parents=True)
        (lab_dir / "e2e" / "run.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        return lab_dir

    def test_nothing_runs_without_the_opt_in(self) -> None:
        with mock.patch.dict("os.environ", {HOST_RUNNER_VARIABLE: ""}), \
                mock.patch("subprocess.run") as run, \
                self.assertRaisesRegex(RuntimeError, HOST_RUNNER_VARIABLE) as raised:
            run_shipyard_script(self.lab(), {"script": "e2e/run.sh"})
        run.assert_not_called()
        self.assertIn("outside Docker", str(raised.exception))

    def test_an_absolute_script_is_refused(self) -> None:
        lab_dir = self.lab()
        with mock.patch.dict("os.environ", ALLOWED), mock.patch("subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "relative"):
                run_shipyard_script(lab_dir, {"script": str(lab_dir / "e2e" / "run.sh")})
        run.assert_not_called()

    def test_a_script_outside_the_lab_is_refused(self) -> None:
        lab_dir = self.lab()
        (lab_dir.parent / "elsewhere.sh").write_text("exit 0\n", encoding="utf-8")
        with mock.patch.dict("os.environ", ALLOWED), mock.patch("subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "outside the lab"):
                run_shipyard_script(lab_dir, {"script": "../elsewhere.sh"})
        run.assert_not_called()

    @unittest.skipIf(__import__("os").name == "nt", "symlinks need privileges on Windows")
    def test_a_symlink_out_of_the_lab_is_refused(self) -> None:
        lab_dir = self.lab()
        outside = lab_dir.parent / "outside.sh"
        outside.write_text("exit 0\n", encoding="utf-8")
        (lab_dir / "e2e" / "link.sh").symlink_to(outside)
        with mock.patch.dict("os.environ", ALLOWED), mock.patch("subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "outside the lab"):
                run_shipyard_script(lab_dir, {"script": "e2e/link.sh"})
        run.assert_not_called()

    def test_a_wsl_distribution_must_be_a_plain_name(self) -> None:
        from cvelab.core import wsl_distribution

        self.assertEqual(wsl_distribution({}), "kali-linux")
        self.assertEqual(wsl_distribution({"distribution": "Ubuntu-24.04"}), "Ubuntu-24.04")
        for bad in ("-u", "Ubuntu -u root --exec", "../x", "", 7):
            with self.subTest(distribution=bad):
                with self.assertRaisesRegex(RuntimeError, "plain name"):
                    wsl_distribution({"distribution": bad})

    def test_the_windows_path_checks_the_distribution(self) -> None:
        source = (Path(__file__).resolve().parent.parent / "cvelab" / "core.py").read_text(encoding="utf-8")
        self.assertIn("distribution = wsl_distribution(runner)", source)

    def test_run_lab_reaches_the_guard(self) -> None:
        from cvelab.core import run_lab

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab_dir = Path(temporary.name) / "CVE-2026-66788"
        lab_dir.mkdir()
        (lab_dir / "plan.json").write_text(json.dumps({
            "cwe": "CWE-284", "lab_type": "END_TO_END_REPRODUCTION",
            "runner": {"type": "shipyard", "script": "/bin/true"},
        }))
        with mock.patch.dict("os.environ", {HOST_RUNNER_VARIABLE: ""}), \
                mock.patch("subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, HOST_RUNNER_VARIABLE):
                run_lab("CVE-2026-66788", Path(temporary.name), keep=False)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
