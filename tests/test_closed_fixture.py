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

"""The fixture phase: state an attack needs before it can prove anything."""

from __future__ import annotations

import ast
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import closed


def _contract(**extra: Any) -> dict[str, Any]:
    contract: dict[str, Any] = {
        "attack": [{"method": "POST", "path": "/api/graphql", "body": "{}"}],
        "observe": {"request": {"path": "/api/graphql"}, "match": {"status": 200}},
    }
    contract.update(extra)
    return contract


class ContractTests(unittest.TestCase):
    def test_a_contract_without_a_fixture_is_unchanged(self) -> None:
        validated = closed._validate_contract(_contract())
        self.assertIsNone(validated.get("fixture"))
        self.assertEqual(validated["health_timeout"], closed.DEFAULT_HEALTH_TIMEOUT)

    def test_readiness_deadline_is_bounded(self) -> None:
        self.assertEqual(
            closed._validate_contract(_contract(health_timeout=600))["health_timeout"], 600
        )
        for value in (0, -1, closed.MAX_HEALTH_TIMEOUT + 1, "600", True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                closed._validate_contract(_contract(health_timeout=value))

    def test_a_fixture_is_an_argv_list(self) -> None:
        """A shell string would have to be quoted somewhere; an argv list never is."""
        fixture = closed._validate_fixture(
            {"command": ["gitlab-rails", "runner", "/cvelab/fixture/seed.rb"]}
        )
        self.assertEqual(fixture["command"][0], "gitlab-rails")
        self.assertEqual(fixture["timeout"], closed.DEFAULT_FIXTURE_TIMEOUT)
        for command in ([], "seed.sh", ["", "x"], [1, 2], {"a": 1}):
            with self.subTest(command=command), self.assertRaises(ValueError):
                closed._validate_fixture({"command": command})

    def test_a_fixture_file_cannot_name_a_path(self) -> None:
        """The name is joined onto a directory on this host and inside the container."""
        for name in ("../seed.rb", "/etc/passwd", "sub/seed.rb", "", "a" * 65, "seed rb"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                closed._validate_fixture({"command": ["true"], "files": {name: "x"}})

    def test_a_fixture_file_is_bounded_text(self) -> None:
        with self.assertRaises(ValueError):
            closed._validate_fixture(
                {"command": ["true"], "files": {"seed.rb": "x" * (256 * 1024 + 1)}}
            )
        with self.assertRaises(ValueError):
            closed._validate_fixture({"command": ["true"], "files": {"seed.rb": 7}})

    def test_a_fixture_environment_name_is_a_variable_name(self) -> None:
        fixture = closed._validate_fixture(
            {"command": ["true"], "env": {"CVELAB_MARKER": "abc"}}
        )
        self.assertEqual(fixture["env"], {"CVELAB_MARKER": "abc"})
        for key in ("9VAR", "a-b", "a.b", ""):
            with self.subTest(key=key), self.assertRaises(ValueError):
                closed._validate_fixture({"command": ["true"], "env": {key: "v"}})

    def test_a_fixture_deadline_is_bounded(self) -> None:
        for timeout in (0, closed.MAX_FIXTURE_TIMEOUT + 1, "600"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                closed._validate_fixture({"command": ["true"], "timeout": timeout})


class ApplyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = closed._validate_fixture(
            {
                "command": ["gitlab-rails", "runner", "/cvelab/fixture/seed.rb"],
                "files": {"seed.rb": "puts 1\n"},
                "env": {"CVELAB_MARKER": "canary"},
            }
        )

    def test_the_files_arrive_before_the_command_runs(self) -> None:
        calls: list[tuple[str, ...]] = []
        copied: dict[str, str] = {}

        def docker(*args: str, check: bool = True) -> str:
            calls.append(args)
            if args[0] == "cp":
                copied[args[2]] = Path(args[1]).read_text(encoding="utf-8")
            return ""

        completed = subprocess.CompletedProcess(["docker"], 0, '{"ok":true}', "")
        with mock.patch.object(closed, "_docker", side_effect=docker), mock.patch.object(
            closed.subprocess, "run", return_value=completed
        ) as run:
            record = closed._apply_fixture("lab", self.fixture)

        # As uid 0, and only for the directory: a product image declaring a
        # non-root USER cannot create /cvelab, so every fixture on such an
        # image failed here.
        self.assertEqual(calls[0], ("exec", "-u", "0", "lab", "mkdir", "-p", "/cvelab/fixture"))
        self.assertEqual(calls[1], ("exec", "-u", "0", "lab", "chmod", "777", "/cvelab/fixture"))
        self.assertEqual(copied, {"lab:/cvelab/fixture/seed.rb": "puts 1\n"})
        self.assertEqual(
            run.call_args.args[0],
            ["docker", "exec", "-e", "CVELAB_MARKER=canary", "lab",
             "gitlab-rails", "runner", "/cvelab/fixture/seed.rb"],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], closed.DEFAULT_FIXTURE_TIMEOUT)
        self.assertEqual(record["stdout"], '{"ok":true}')
        self.assertEqual(record["files"], ["seed.rb"])

    def test_the_staged_copy_does_not_outlive_the_call(self) -> None:
        staged: list[str] = []

        def docker(*args: str, check: bool = True) -> str:
            if args[0] == "cp":
                staged.append(args[1])
            return ""

        completed = subprocess.CompletedProcess(["docker"], 0, "", "")
        with mock.patch.object(closed, "_docker", side_effect=docker), mock.patch.object(
            closed.subprocess, "run", return_value=completed
        ):
            closed._apply_fixture("lab", self.fixture)
        self.assertTrue(staged)
        self.assertFalse(Path(staged[0]).exists())

    def test_a_failed_fixture_stops_the_run(self) -> None:
        """An unseeded instance answers like a fixed one, so this cannot pass quietly."""
        completed = subprocess.CompletedProcess(["docker"], 1, "", "no root user")
        with mock.patch.object(closed, "_docker", return_value=""), mock.patch.object(
            closed.subprocess, "run", return_value=completed
        ):
            with self.assertRaises(RuntimeError) as raised:
                closed._apply_fixture("lab", self.fixture)
        self.assertIn("no root user", str(raised.exception))
        self.assertIn("exited 1", str(raised.exception))


class VariantTests(unittest.TestCase):
    """What the runner does with and without a fixture."""

    def _run(self, contract: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, ...]]]:
        calls: list[tuple[str, ...]] = []

        def docker(*args: str, check: bool = True) -> str:
            calls.append(args)
            if args[:2] == ("run", "--rm"):
                return json.dumps({"status": 200, "headers": {}, "body": "ok"})
            return "id"

        completed = subprocess.CompletedProcess(["docker"], 0, "seeded", "")
        with mock.patch.object(closed, "_docker", side_effect=docker), mock.patch.object(
            closed.subprocess, "run", return_value=completed
        ):
            result = closed._run_variant(
                "CVE-2026-0001", "vulnerable", "image:tag", 80, "/",
                closed._validate_contract(contract),
            )
        return result, calls

    def test_the_fixture_runs_before_the_attack(self) -> None:
        result, calls = self._run(
            _contract(fixture={"command": ["seed"], "files": {"seed.rb": "x"}})
        )
        kinds = [args[0] for args in calls]
        self.assertLess(kinds.index("cp"), kinds.index("run", kinds.index("cp")))
        self.assertEqual(result["fixture"]["stdout"], "seeded")
        self.assertEqual(result["fixture"]["command"], ["seed"])

    def test_without_a_fixture_nothing_is_executed_in_the_container(self) -> None:
        result, calls = self._run(_contract())
        self.assertIsNone(result["fixture"])
        self.assertEqual([args for args in calls if args[0] in {"exec", "cp"}], [])


class LabTests(unittest.TestCase):
    def test_the_fixture_ships_beside_the_poc(self) -> None:
        """The walkthrough's manual path is only runnable if the files are there."""
        contract = _contract(
            fixture={"command": ["gitlab-rails", "runner", "/cvelab/fixture/seed.rb"],
                     "files": {"seed.rb": "puts 1\n"}}
        )
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            contract_path = output / "contract.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            variant = {"variant": "vulnerable", "image": "image:tag", "confirmed": True,
                       "predicates": ["status=200 passed=True"], "attack_responses": [],
                       "observation": {}, "attack_executed": True,
                       "fixture": {"command": ["seed"]},
                       "shipped_poc": {"expected_verdict": "REPRODUCED", "passed": True,
                                       "exit_code": 0, "output": "REPRODUCED", "stderr": ""}}
            with mock.patch.object(closed, "_run_variant", return_value=variant):
                result = closed.run_closed_lab(
                    "CVE-2026-0001", output, "image:tag", None, 80, "/", contract_path
                )
            artifacts = Path(result["lab_dir"]) / "artifacts"
            self.assertEqual(
                (artifacts / "fixture" / "seed.rb").read_text(encoding="utf-8"), "puts 1\n"
            )
            self.assertTrue(result["fixture_applied"])
            walkthrough = (artifacts / "WALKTHROUGH.md").read_text(encoding="utf-8")
            self.assertIn("gitlab-rails runner /cvelab/fixture/seed.rb", walkthrough)
            self.assertIn(
                "This contract needs its fixture in place first",
                (artifacts / "PoC.py").read_text(encoding="utf-8"),
            )
            manual = (artifacts / "manual.sh").read_text(encoding="utf-8")
            self.assertTrue(manual.startswith("#!"))
            self.assertIn("gitlab-rails runner /cvelab/fixture/seed.rb", manual)
            self.assertIn("-p 127.0.0.1::", manual)


class ShippedPoCTests(unittest.TestCase):
    def _run(self, stdout: str, code: int = 0) -> tuple[dict[str, Any], list[str]]:
        completed = subprocess.CompletedProcess(["docker"], code, stdout, "")
        with mock.patch.object(closed.subprocess, "run", return_value=completed) as run:
            record = closed._run_poc_script("lab", 8080, _contract(), "REPRODUCED")
        return record, list(run.call_args.args[0])

    def test_the_sidecar_borrows_the_lab_network_and_publishes_nothing(self) -> None:
        """127.0.0.1 has to be the product, or the script's own guard refuses it."""
        _, argv = self._run("REPRODUCED")
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "container:lab")
        self.assertNotIn("-p", argv)
        self.assertIn("CVELAB_BASE=http://127.0.0.1:8080", argv)
        self.assertIn("--security-opt", argv)
        self.assertIn("--memory", argv)

    def test_the_verdict_is_the_last_line_the_script_printed(self) -> None:
        self.assertTrue(self._run("attack[1] status=200\nREPRODUCED")[0]["passed"])
        self.assertFalse(self._run("REPRODUCED\nBLOCKED")[0]["passed"])
        self.assertFalse(self._run("REPRODUCED mentioned in a response body")[0]["passed"])
        self.assertFalse(self._run("REPRODUCED", code=1)[0]["passed"])


class MatcherAgreementTests(unittest.TestCase):
    """The script ships with its own matcher; it has to mean the same thing.

    The runner measures inside the lab network and the script measures from
    wherever a reviewer runs it, so the predicate is implemented twice. Two
    verdicts that can disagree would make one of them a lie.
    """

    def setUp(self) -> None:
        tree = ast.parse(closed._POC_SCRIPT)
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "matches"
        )
        module = ast.Module(
            body=[ast.Import(names=[ast.alias(name="re")]), function], type_ignores=[]
        )
        namespace: dict[str, Any] = {}
        exec(compile(ast.fix_missing_locations(module), "<PoC.py>", "exec"), namespace)
        self.script_matches = namespace["matches"]

    def test_both_implementations_agree(self) -> None:
        response = {"status": 200, "headers": {"Server": "nginx"}, "body": "canary 42"}
        cases = [
            {"status": 200},
            {"status": [200, 204]},
            {"status": 404},
            {"body_contains": "canary"},
            {"body_contains": "absent"},
            {"body_regex": "canary[\\s\\S]*42"},
            {"body_regex": "canary.*canary"},
            {"header": {"name": "server", "contains": "nginx"}},
            {"header": {"name": "Server", "contains": "apache"}},
            {"header": {"name": "X-Absent", "contains": "x"}},
            {"status": 200, "body_contains": "canary"},
            {"status": 200, "body_contains": "absent"},
        ]
        for match in cases:
            with self.subTest(match=match):
                self.assertEqual(
                    closed._matches(response, match)[0],
                    self.script_matches(
                        response["status"], response["headers"], response["body"], match
                    )[0],
                )

    def test_both_refuse_an_empty_predicate(self) -> None:
        with self.assertRaises(ValueError):
            closed._matches({"status": 200, "headers": {}, "body": ""}, {})
        with self.assertRaises(SystemExit):
            self.script_matches(200, {}, "", {})


class EvidenceTests(unittest.TestCase):
    """What the control plane reads before a run may join the shared corpus."""

    def _lab(self, *, shipped_passed: bool, patched: bool) -> dict[str, Any]:
        def variant(name: str, confirmed: bool, expected: str) -> dict[str, Any]:
            return {"variant": name, "image": f"image:{name}", "confirmed": confirmed,
                    "predicates": [f"status=200 passed={confirmed}"],
                    "attack_responses": [], "observation": {}, "attack_executed": True,
                    "fixture": None,
                    "shipped_poc": {"expected_verdict": expected, "passed": shipped_passed,
                                    "exit_code": 0, "output": expected, "stderr": ""}}

        variants = iter([variant("vulnerable", True, "REPRODUCED")]
                        + ([variant("patched", False, "BLOCKED")] if patched else []))
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            contract_path = output / "contract.json"
            contract_path.write_text(json.dumps(_contract()), encoding="utf-8")
            with mock.patch.object(closed, "_run_variant", side_effect=lambda *a, **k: next(variants)):
                result = closed.run_closed_lab(
                    "CVE-2026-0001", output, "image:vulnerable",
                    "image:patched" if patched else None, 80, "/", contract_path,
                )
            artifacts = Path(result["lab_dir"]) / "artifacts"
            return {
                "result": result,
                "evidence": json.loads((artifacts / "EVIDENCE.json").read_text()),
                "plan": json.loads((artifacts / "plan.json").read_text()),
                "report": json.loads((artifacts / "report.json").read_text()),
                "root_plan": (Path(result["lab_dir"]) / "plan.json").exists(),
            }

    def test_a_validated_run_records_what_the_gate_checks(self) -> None:
        lab = self._lab(shipped_passed=True, patched=True)
        evidence, report = lab["evidence"], lab["report"]
        self.assertRegex(evidence["status"], r"^REAL_[A-Z_]+_POC_VALIDATED$")
        self.assertEqual(evidence["cve"], "CVE-2026-0001")
        self.assertEqual(evidence["lab_type"], report["lab_type"])
        self.assertTrue(evidence["validation"]["attack_executed"])
        self.assertEqual(evidence["validation"]["proof_quality"], "security_effect_observed")
        self.assertTrue(evidence["validation"]["differential_confirmed"])
        for check in ("attack_executed", "security_effect_observed",
                      "vulnerable_confirmed", "manual_poc_verified", "patched_blocked"):
            self.assertIs(evidence["proof_checks"][check], True, check)
        self.assertIsNone(evidence["provenance"]["repository"])
        self.assertEqual(lab["plan"]["cve"], "CVE-2026-0001")
        self.assertIsNone(lab["plan"]["repository"])
        self.assertTrue(lab["root_plan"])
        self.assertIs(report["ok"], True)
        self.assertIs(report["real_poc_verified"], True)

    def test_a_shipped_poc_that_did_not_run_is_not_a_validated_lab(self) -> None:
        """The runner's own measurement is not evidence that the handover works."""
        lab = self._lab(shipped_passed=False, patched=True)
        self.assertIs(lab["result"]["ok"], False)
        self.assertIs(lab["evidence"]["proof_checks"]["manual_poc_verified"], False)
        self.assertNotRegex(lab["evidence"]["status"], r"^REAL_[A-Z_]+_POC_VALIDATED$")

    def test_without_a_fixed_image_nothing_is_claimed_about_the_patch(self) -> None:
        """No differential to confirm, so the check is not claimed at all.

        Reporting `patched_blocked: false` beside a validated status made the
        status contradict its own rule that every check must pass.
        """
        lab = self._lab(shipped_passed=True, patched=False)
        checks = lab["evidence"]["proof_checks"]
        self.assertNotIn("patched_blocked", checks)
        self.assertIs(checks["differential_not_available"], True)
        self.assertTrue(all(checks.values()))
        self.assertIsNone(lab["evidence"]["validation"]["patched"])
        self.assertIs(lab["result"]["ok"], True)


class ContractArgumentTests(unittest.TestCase):
    """The contract reaches the sidecar as one -e value, which Linux caps."""

    def test_the_fixture_does_not_travel_to_the_poc_script(self) -> None:
        """It already ran inside the container before the first request.

        Carried along it risked the argument limit for nothing and shipped
        the fixture's own markers into the sidecar's environment.
        """
        contract = _contract()
        contract["fixture"] = closed._validate_fixture({
            "command": ["seed"],
            "files": {"seed.rb": "canary marker"},
            "env": {"CVELAB_MARKER": "canary"},
        })
        sent = json.loads(closed._attack_only(contract))
        self.assertNotIn("fixture", sent)
        self.assertNotIn("canary", json.dumps(sent))
        self.assertEqual(sent["attack"], contract["attack"])
        self.assertEqual(sent["observe"], contract["observe"])

    def test_a_contract_too_large_for_one_argument_is_refused_up_front(self) -> None:
        """Raised after the fixture and the attack had both run, with no report.

        A fixture file may be 256 KiB on its own, and one argument carries
        128 KiB, so docker answered "argument list too long" at the very end
        of the run.
        """
        contract = _contract()
        contract["attack"] = [
            {"method": "POST", "path": "/a", "headers": [], "body": "x" * 200_000}
        ]
        with self.assertRaises(RuntimeError) as caught:
            closed._attack_only(contract)
        self.assertIn("argument", str(caught.exception))


class RerunTests(unittest.TestCase):
    """A run that does not finish must not leave the last one's verdict."""

    def test_an_aborted_rerun_drops_the_previous_validated_evidence(self) -> None:
        """`cvelab upload` reads report.json and EVIDENCE.json off the disk.

        The contract, the PoC and the fixture are rewritten at the top of a
        run but the verdict only at the end, so a run that raised partway
        left `ok: true` and a validated status beside the new inputs.
        """
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            lab_dir = output / "CVE-2026-0001"
            artifacts = lab_dir / "artifacts"
            evidence_dir = lab_dir / "closed" / "evidence"
            for directory in (artifacts, evidence_dir):
                directory.mkdir(parents=True, exist_ok=True)
            stale = {"ok": True, "status": "REAL_CLOSED_SOFTWARE_POC_VALIDATED"}
            for path in (
                artifacts / "report.json",
                artifacts / "EVIDENCE.json",
                evidence_dir / "result.json",
            ):
                path.write_text(json.dumps(stale), encoding="utf-8")

            contract_path = output / "contract.json"
            contract_path.write_text(json.dumps(_contract()), encoding="utf-8")
            with mock.patch.object(
                closed, "_run_variant", side_effect=RuntimeError("never became healthy")
            ):
                with self.assertRaises(RuntimeError):
                    closed.run_closed_lab(
                        "CVE-2026-0001", output, "image:vulnerable", None, 80, "/",
                        contract_path,
                    )
            for path in (
                artifacts / "report.json",
                artifacts / "EVIDENCE.json",
                evidence_dir / "result.json",
            ):
                self.assertFalse(path.exists(), f"{path.name} survived the failed run")


class SharedLabTests(unittest.TestCase):
    """A closed lab uploaded as a success must be one someone can run."""

    def test_the_attack_contract_travels_with_the_exploit(self) -> None:
        """PoC.py reads the attack from contract.json beside it.

        Without it the shared lab, downloaded as a validated run, failed
        with FileNotFoundError on the first line that matters.
        """
        from cvelab import upload

        self.assertIn("contract.json", upload.ALWAYS)
        self.assertIn("contract.json", upload.EXPLOIT)
        withheld = tuple(n for n in upload.ALWAYS if n not in upload.EXPLOIT)
        self.assertNotIn("contract.json", withheld)


if __name__ == "__main__":
    unittest.main()
