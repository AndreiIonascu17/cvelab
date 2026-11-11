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

"""The single-target script a source lab hands over beside its own proof."""

from __future__ import annotations

import ast
import contextlib
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from cvelab import (
    autoflow,
    cli,
    closed,
    core,
    deliverables,
    field,
    sidecar,
    sourcegen,
    upload,
)


def _spec(**extra: Any) -> dict[str, Any]:
    spec = {
        "strategy": "inband_differential",
        "observable_effect": "a record the authorized path withholds",
        "probe": [{"method": "GET", "path": "/notes"}],
        "control": [{"method": "GET", "path": "/notes?auth=1"}],
        "extract": {"json_values": "body"},
    }
    spec.update(extra)
    return spec


def _run(observed: bool, ran: bool) -> dict[str, Any]:
    return {
        "observed": observed,
        "ran": ran,
        "verdict": "OBSERVED" if observed else "NOT_OBSERVED",
        "exit_code": 0,
        "observation": {},
        "output": "",
        "stderr": "",
    }


#: The lab program the merged artifact carries underneath remote mode. A real
#: one is model-written and runs a differential between two Compose services;
#: what every test here needs of it is that it is a program, that it is not
#: CVELab's own text, and that `diff` can find it again under the marker.
_LAB_MODE = (
    "#!/usr/bin/env python3\n"
    "# CVELab validator for the lab in this directory.\n"
    "import os, sys\n"
    "def main():\n"
    "    print(os.environ.get('CVELAB_MANUAL_ACTION', 'differential'))\n"
    "    return 0\n"
    "if __name__ == '__main__':\n"
    "    sys.exit(main())\n"
)


def _held(lab_dir: Path) -> dict[str, Any]:
    """The record, where it lives now: report.json's manual_poc_field."""
    report = json.loads((lab_dir / "report.json").read_text(encoding="utf-8"))
    return report.get("manual_poc_field") or {}


@contextlib.contextmanager
def _lab(
    *,
    reproduced: bool = True,
    lab_type: str = "SOURCE_REPRODUCTION",
    spec: dict[str, Any] | None = None,
    record: dict[str, Any] | None = None,
    legacy_record: dict[str, Any] | None = None,
) -> Iterator[Path]:
    """A lab on disk, as `cvelab run` leaves one.

    `record` goes where the proved spec now lives: report.json's
    `manual_poc_field`. `legacy_record` goes in the old file beside the lab,
    which 45 of the archived labs hold and which is still read.
    """
    with tempfile.TemporaryDirectory() as root:
        lab_dir = Path(root) / "CVE-2026-0001"
        (lab_dir / "validator").mkdir(parents=True)
        (lab_dir / "validator" / "validator.py").write_text(_LAB_MODE)
        (lab_dir / "plan.json").write_text(json.dumps({
            "cve": "CVE-2026-0001",
            "lab_type": lab_type,
            "repository": "https://example.invalid/p.git",
            "startup_services": ["vulnerable", "patched"],
        }))
        (lab_dir / "report.json").write_text(json.dumps(
            {"real_poc_verified": reproduced}
            | ({"manual_poc_field": record} if record is not None else {})
        ))
        if spec is not None:
            (lab_dir / "spec.json").write_text(json.dumps(spec))
        if legacy_record is not None:
            (lab_dir / "artifacts").mkdir(exist_ok=True)
            (lab_dir / "artifacts" / field.LEGACY_MANUAL_POC_RECORD_NAME).write_text(
                json.dumps(legacy_record)
            )
        yield lab_dir


class GenerationIsLeftAloneTests(unittest.TestCase):
    """The model is never asked for a spec, and this is why.

    Asking for one inside the generation prompt pushed the whole prompt past
    the provider's cyber threshold: two of three CVEs that had validated
    minutes earlier with the same model came back PROVIDER_DECLINED. That
    costs the lab, not just the extra, so the spec comes from the operator.
    """

    def test_the_schema_does_not_offer_a_spec_field(self) -> None:
        self.assertNotIn("field_spec", sourcegen.SOURCE_SCHEMA["properties"])
        self.assertNotIn("field_spec", sourcegen.VULNERABLE_ONLY_SCHEMA["properties"])

    def test_no_prompt_asks_for_one(self) -> None:
        source = Path(sourcegen.__file__).read_text(encoding="utf-8")
        self.assertNotIn("field_spec", source)
        self.assertNotIn("single-target script", source)
        self.assertNotIn("permission to test", source)

    def test_the_step_cannot_change_the_lab_status(self) -> None:
        """proof_checks is all-ANDed into the status, so the step stays out.

        The guarantee is an ordering too: the verdict is computed before the
        hook is called, so nothing the hook does can reach back into it.
        """
        source = Path(core.__file__).read_text(encoding="utf-8")
        self.assertNotIn('proof_checks["manual_poc_field"]', source)
        self.assertNotIn('proof_checks["manual_poc_proven"]', source)
        self.assertLess(
            source.index("real_source_proof = all(proof_checks.values())"),
            source.index("after_validation("),
        )

    def test_core_learns_nothing_about_providers(self) -> None:
        """A lab is built and validated with no model configured at all.

        The hook is injected, so core imports neither field nor a provider,
        and that import graph is what keeps the two independent.
        """
        source = Path(core.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from .field import", source)
        self.assertNotIn("import field", source)
        self.assertNotIn("structured_response", source)


#: What the lab's contract commits to before anything is built, and so the
#: text the observations have to carry on the affected build and not on the
#: fixed one.
_EFFECT = "the-withheld-record"

#: The affected build as a run that did not reproduce leaves it: the service
#: answered, and the effect is not in what it answered. Used where a test
#: needs a failure somewhere other than in the handed-over actions.
_NOT_REPRODUCED = {
    "confirmed": False,
    "observations": {"status": 200, "headers": {}, "body": "no record here"},
}


def _proving_validator(**extra: Any) -> dict[str, Any]:
    """A validator document that passes every check run_lab makes."""
    said = {
        "attack_executed": True,
        "proof_quality": "security_effect_observed",
        "observable_effect": "the record the authorized path withholds",
        "evidence_type": "http_response_body",
        # The raw responses the booleans were derived from.
        # security_effect_observed is CVELab's own measurement over these
        # against the predicate the plan below declares, rather than a
        # string comparison on proof_quality, which this document writes
        # about itself -- so a document without them passes nothing.
        "vulnerable": {
            "confirmed": True,
            "observations": {"status": 200, "headers": {}, "body": _EFFECT},
        },
        "patched": {
            "confirmed": False, "blocked": True,
            "observations": {"status": 403, "headers": {}, "body": "forbidden"},
        },
        "differential_confirmed": True,
    }
    said.update(extra)
    return said


class ManualPocNeverRanTests(unittest.TestCase):
    """A check that never ran is not a check that failed.

    The in-lab manual actions sit behind `if automatic_proof`, which is
    deliberate: running them against a lab that did not prove is wasted
    container time. Folding their empty result into proof_checks anyway
    reported them as failed on every failed run. The lab left under
    generated-labs has manual_poc_verified false beside manual_poc_checks
    {}, and its automation record shows what that cost: validation attempt 2
    sent the repair model failed_proof_checks ["manual_poc_verified"] and
    nothing else, while the actual cause -- a differential the validator did
    not confirm -- is not a proof check and so appeared nowhere in the list.
    """

    CVE = "CVE-2026-0001"

    def _on_disk(self, root: Path) -> Path:
        """The lab run_lab's preflight asks for, and nothing more."""
        lab = root / self.CVE
        for side in ("vulnerable", "patched"):
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
                "lab_type": "SOURCE_REPRODUCTION",
                "startup_services": ["vulnerable", "patched"],
                "exploit_contract": {
                    "observable_effect": "a record the authorized path withholds",
                    "evidence_type": "http_response_body",
                    "effect_predicate": {"body_contains": _EFFECT},
                },
            }),
            encoding="utf-8",
        )
        return lab

    def _run(self, said: dict[str, Any], *, actions_pass: bool = True) -> dict[str, Any]:
        """run_lab against a mocked Docker, returning the report it writes."""

        def validator(
            _compose: list[str], _docker: str, _environment: dict[str, str],
            _lab_dir: Path, extra: dict[str, str] | None = None,
            wait_for_services: bool = True,
        ) -> tuple[int, str, str]:
            if not extra:
                return 0, json.dumps(said), ""
            if not actions_pass:
                return 1, "", "the handed-over script exited non-zero"
            return 0, (
                "REPRODUCED" if extra["CVELAB_TARGET"] == "vulnerable" else "BLOCKED"
            ), ""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._on_disk(root)
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

    def test_a_run_that_failed_elsewhere_claims_nothing_about_the_actions(self) -> None:
        report = self._run(_proving_validator(vulnerable=_NOT_REPRODUCED))

        self.assertNotIn("manual_poc_verified", report["proof_checks"])
        self.assertEqual(report["manual_poc_status"], "not_run")
        self.assertEqual(report["manual_poc_checks"], {})
        # The checks that really failed, and only those. Two now rather than
        # one, and the second is a measurement rather than a phantom: the
        # affected build answered without the effect in it, so CVELab's own
        # evaluation of the contract's predicate fails alongside the
        # validator's own verdict. The phantom this test exists for is
        # manual_poc_verified, asserted absent above.
        self.assertEqual(
            sorted(
                name for name, passed in report["proof_checks"].items()
                if passed is False
            ),
            ["security_effect_observed", "vulnerable_confirmed"],
        )
        self.assertIs(report["ok"], False)
        self.assertIs(report["real_poc_verified"], False)
        self.assertEqual(report["evidence_label"], "Not reproduced")

    def test_a_proved_run_whose_actions_pass_still_reports_the_check(self) -> None:
        report = self._run(_proving_validator())

        self.assertIs(report["proof_checks"]["manual_poc_verified"], True)
        self.assertEqual(report["manual_poc_status"], "verified")
        self.assertEqual(sorted(report["manual_poc_checks"]), [
            "patched_exploit", "patched_verify",
            "vulnerable_exploit", "vulnerable_verify",
        ])
        self.assertIs(report["ok"], True)
        self.assertIs(report["real_poc_verified"], True)
        self.assertTrue(report["evidence_label"].startswith("Reproduced"))

    def test_a_proved_run_whose_actions_fail_still_fails_the_check(self) -> None:
        """Where the measurement is real the check keeps its teeth."""
        report = self._run(_proving_validator(), actions_pass=False)

        self.assertIs(report["proof_checks"]["manual_poc_verified"], False)
        self.assertEqual(report["manual_poc_status"], "failed")
        self.assertTrue(report["manual_poc_checks"])
        self.assertIs(report["ok"], False)
        self.assertIs(report["real_poc_verified"], False)
        self.assertEqual(report["evidence_label"], "Not reproduced")
        self.assertEqual(
            autoflow._validation_digest(report)["failed_proof_checks"],
            ["manual_poc_verified"],
        )

    def test_the_repair_digest_no_longer_names_what_never_ran(self) -> None:
        """The digest lists the names whose value is False, so absence is enough.

        This is why dropping the key is the whole fix: autoflow needs no
        change, and the model is no longer told to repair the one item on
        the list it cannot reach.
        """
        report = self._run(_proving_validator(vulnerable=_NOT_REPRODUCED))
        digest = autoflow._validation_digest(report)

        self.assertEqual(
            digest["failed_proof_checks"],
            ["security_effect_observed", "vulnerable_confirmed"],
        )
        self.assertNotIn("manual_poc_verified", digest["failed_proof_checks"])

    def test_the_verdict_is_still_folded_from_proof_checks_alone(self) -> None:
        """No third state in proof_checks: every value there is ANDed.

        The assignment is pinned at the gate's indentation, because moving
        it back out is exactly the defect, and both forms read the same from
        a diff of the surrounding lines.
        """
        source = Path(core.__file__).read_text(encoding="utf-8")
        self.assertIn("real_source_proof = all(proof_checks.values())", source)
        self.assertIn('            proof_checks["manual_poc_verified"] = all(', source)

    def test_the_closed_lab_path_folds_its_own_empty_dict_on_purpose(self) -> None:
        """There the checks always run, so no entries means no PoC shipped.

        Nothing gates them, which is what makes False a measurement rather
        than a consequence of another failure. Pinned because the two reads
        are the same expression and unifying them would be wrong.
        """
        source = Path(closed.__file__).read_text(encoding="utf-8")
        self.assertIn(
            "manual_poc_verified = bool(manual_poc_checks) and all(", source
        )
        self.assertNotIn("automatic_proof", source)


class ProofTests(unittest.TestCase):
    """It is handed over only if it tells the lab's two builds apart."""

    def _prove(
        self,
        *,
        vulnerable: tuple[bool, bool],
        patched: tuple[bool, bool],
        containers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        ids = containers if containers is not None else {
            "vulnerable": "cid-v", "patched": "cid-p"
        }
        outcomes = {"cid-v": _run(*vulnerable), "cid-p": _run(*patched)}
        with mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container",
            side_effect=lambda c, name, d, e: ids.get(name, ""),
        ), mock.patch.object(
            field, "_still_serving", return_value="127.0.0.1"
        ), mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given, host=None, disruptive=False:
                outcomes[cid],
        ):
            return field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8000,
                Path("/lab"), ["docker", "compose"], {},
            )

    def test_effect_on_vulnerable_and_silence_on_fixed_earns_the_handover(self) -> None:
        out = self._prove(vulnerable=(True, True), patched=(False, True))
        self.assertIs(out["shipped"], True)
        self.assertIs(out["proof_checks"]["manual_poc_proven"], True)
        self.assertTrue(out["script"].startswith("#!/usr/bin/env python3"))
        self.assertIn("--target", out["script"])

    def test_firing_on_both_builds_is_normal_behaviour_not_the_bug(self) -> None:
        out = self._prove(vulnerable=(True, True), patched=(True, True))
        self.assertIs(out["shipped"], False)
        self.assertNotIn("script", out)
        self.assertIn("tell the two builds apart", out["reason"])

    def test_a_crash_against_the_fixed_build_is_not_silence(self) -> None:
        """A run that never finished observed nothing because it never looked."""
        out = self._prove(vulnerable=(True, True), patched=(False, False))
        self.assertIs(out["shipped"], False)
        self.assertIs(out["proof_checks"]["script_ran_on_both"], False)
        self.assertIs(out["proof_checks"]["silent_on_fixed"], False)
        self.assertNotIn("script", out)

    def test_a_service_that_is_not_running_is_reported_not_raised(self) -> None:
        out = self._prove(
            vulnerable=(True, True), patched=(False, True),
            containers={"vulnerable": "cid-v", "patched": ""},
        )
        self.assertIs(out["shipped"], False)
        self.assertIn("patched", out["reason"])

    def test_a_refusal_carries_the_run_that_refused_it(self) -> None:
        """A generic reason sends the operator back to guessing."""
        out = self._prove(vulnerable=(True, True), patched=(True, True))
        self.assertIn("output", out)
        self.assertEqual(sorted(out["output"]), ["patched", "vulnerable"])

    def test_an_exception_anywhere_becomes_a_reason(self) -> None:
        with mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(field, "emit_poc", side_effect=OSError("disk gone")):
            out = field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8000,
                Path("/lab"), ["docker", "compose"], {},
            )
        self.assertIs(out["shipped"], False)
        self.assertIn("OSError", out["reason"])

    def test_a_lab_with_no_program_of_its_own_is_said_plainly(self) -> None:
        """The proof runs the whole merged file, so it needs both halves.

        Nothing in a generated lab reaches this -- validator/validator.py is
        what the validator image runs -- and a lab directory without one is
        not a lab. Said as a refusal rather than proving half a file, because
        the claim the proof makes is about the bytes the operator receives.
        """
        out = field.prove_manual_poc(
            "CVE-2026-0001", field.validate_spec(_spec()), 8000,
            Path("/lab"), ["docker", "compose"], {},
        )
        self.assertIs(out["shipped"], False)
        self.assertIn("No lab mode to carry", out["reason"])


class OperatorSpecTests(unittest.TestCase):
    """The spec is the operator's, and the lab it is proved against must qualify."""

    def _call(self, lab_dir: Path, spec_name: str = "spec.json", **kwargs: Any) -> dict:
        with mock.patch.object(
            field, "prepare_compose",
            return_value=("docker", {}, ["docker", "compose"], lab_dir.parent / "scratch"),
        ), mock.patch.object(
            field, "_resolved_compose", return_value={}
        ), mock.patch.object(
            field, "_bring_up"
        ), mock.patch.object(
            field.subprocess, "run",
            return_value=subprocess.CompletedProcess(["docker"], 0, "", ""),
        ), mock.patch.object(
            field, "prove_manual_poc",
            return_value=kwargs.pop("outcome", {
                "shipped": True, "strategy": "inband_differential",
                "observable_effect": "a record the authorized path withholds",
                "container_port": 8000, "proof_checks": {}, "runs": {},
                "script": "#!/usr/bin/env python3\n--target\n",
            }),
        ):
            return field.run_manual_poc(lab_dir, lab_dir / spec_name, 8000, **kwargs)

    def test_a_proved_spec_writes_one_artifact_carrying_its_own_guide(self) -> None:
        with _lab(spec=_spec()) as lab_dir:
            result = self._call(lab_dir)
            artifacts = lab_dir / "artifacts"
            self.assertIs(result["ok"], True)
            self.assertTrue((artifacts / field.POC_NAME).is_file())
            # The trio is gone: one script, and the record in report.json.
            for name in field.LEGACY_MANUAL_POC_NAMES:
                self.assertFalse((artifacts / name).exists(), name)
            self.assertEqual(_held(lab_dir)["container_port"], 8000)
            guide = (artifacts / field.POC_NAME).read_text()
            # It must say where it may be pointed, and that a negative result
            # is not a clean bill.
            self.assertIn("keep that permission in writing", guide)
            self.assertIn("not the same", guide)
            self.assertIn("demo-target", guide)

    def test_the_record_keeps_a_refusal_and_remote_mode_refuses(self) -> None:
        with _lab(spec=_spec()) as lab_dir:
            result = self._call(lab_dir, outcome={
                "shipped": False, "reason": "the script did not tell the two builds apart",
                "proof_checks": {}, "runs": {},
            })
            artifacts = lab_dir / "artifacts"
            self.assertIs(result["ok"], False)
            record = _held(lab_dir)
            self.assertIn("did not tell the two builds apart", record["reason"])
            # The artifact is still written, because lab mode is still true.
            poc = (artifacts / field.POC_NAME).read_text()
            self.assertIn("did not tell the two builds apart", poc)
            self.assertIn("raise SystemExit(2)", poc)

    def test_a_lab_that_never_reproduced_is_refused(self) -> None:
        with _lab(spec=_spec(), reproduced=False) as lab_dir:
            with self.assertRaises(RuntimeError) as raised:
                self._call(lab_dir)
            self.assertIn("did not reproduce", str(raised.exception))

    def test_an_unvalidated_lab_is_refused(self) -> None:
        with _lab(spec=_spec()) as lab_dir:
            (lab_dir / "report.json").unlink()
            with self.assertRaises(RuntimeError) as raised:
                self._call(lab_dir)
            self.assertIn("has not been validated", str(raised.exception))

    def test_a_vulnerable_only_lab_is_not_refused_outright(self) -> None:
        """A patched build is a check against self-deception, not what makes a
        vulnerability real. Some projects publish no resolvable fixed build at
        all, and the effect is still worth showing."""
        with _lab(spec=_spec(), lab_type="VULNERABLE_ONLY_REPRODUCTION") as lab_dir:
            result = self._call(lab_dir)
            self.assertIs(result["ok"], True)

    def test_an_unusable_spec_is_refused_before_anything_starts(self) -> None:
        """Here a bad spec is the operator's own input, so it is an error.

        Nothing is built or started first: the refusal costs a JSON parse.
        """
        for name, offered in {
            "unknown strategy": _spec(strategy="guesswork"),
            "no requests": {"strategy": "inband_differential", "observable_effect": "x"},
            "no effect": _spec(observable_effect=""),
        }.items():
            with self.subTest(case=name), _lab(spec=offered) as lab_dir:
                with self.assertRaises((ValueError, TypeError, RuntimeError)):
                    self._call(lab_dir)

    def test_a_spec_that_is_not_json_names_the_file(self) -> None:
        with _lab() as lab_dir:
            (lab_dir / "spec.json").write_text("{not json")
            with self.assertRaises(RuntimeError) as raised:
                self._call(lab_dir)
            self.assertIn("spec.json", str(raised.exception))

    def test_no_lab_at_the_path_is_said_plainly(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(RuntimeError) as raised:
                field.run_manual_poc(Path(root), Path(root) / "spec.json", 8000)
            self.assertIn("plan.json is missing", str(raised.exception))


class DemoTargetTests(unittest.TestCase):
    """A rehearsal target: one reachable vulnerable host, and the way back."""

    def _up(self, lab_dir: Path, **kwargs: Any) -> tuple[dict, mock.Mock]:
        resolved = {"networks": {"lab_internal": {"internal": True}}}
        with mock.patch.object(
            field, "prepare_compose",
            return_value=("docker", {}, ["docker", "compose"], lab_dir.parent / "scratch"),
        ), mock.patch.object(
            field, "_resolved_compose", return_value=resolved
        ), mock.patch.object(
            field, "_bring_up"
        ) as brought_up, mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", return_value="cid-v"
        ), mock.patch.object(
            field, "_container_address", return_value="172.19.0.2"
        ):
            (lab_dir.parent / "scratch").mkdir(exist_ok=True)
            return field.run_demo_target("up", lab_dir, **kwargs), brought_up

    def test_it_prints_a_real_host_and_port_to_point_at(self) -> None:
        with _lab() as lab_dir:
            result, _ = self._up(lab_dir, container_port=8000)
        self.assertEqual(result["target"], "172.19.0.2:8000")
        self.assertIs(result["running"], True)

    def test_the_fixed_build_is_never_started(self) -> None:
        """The differential is the lab's job, already done.

        A demo that reached the fixed build by accident would show nothing,
        so only the vulnerable one comes up.
        """
        with _lab() as lab_dir:
            _, brought_up = self._up(lab_dir, container_port=8000)
        services = brought_up.call_args.args[0]
        self.assertIn("vulnerable", services)
        self.assertNotIn("patched", services)

    def test_the_port_comes_from_the_proved_record_when_not_given(self) -> None:
        with _lab(record={"container_port": 9090}) as lab_dir:
            result, _ = self._up(lab_dir)
        self.assertEqual(result["target"], "172.19.0.2:9090")

    def test_without_a_port_or_a_record_it_says_what_is_missing(self) -> None:
        with _lab() as lab_dir:
            with self.assertRaises(RuntimeError) as raised:
                self._up(lab_dir)
            self.assertIn("--container-port", str(raised.exception))

    def test_the_override_lifts_internal_and_is_not_auto_loaded(self) -> None:
        """docker-compose.override.yml is loaded by name.

        Left behind under that name, or inside the lab, it would quietly
        change every later run of the lab.
        """
        fragment = field._demo_override(["lab_internal", "lab_back"])
        self.assertIn("lab_internal:\n    internal: false", fragment)
        self.assertIn("lab_back:\n    internal: false", fragment)
        self.assertIn("demo-target down", fragment)
        source = Path(field.__file__).read_text(encoding="utf-8")
        self.assertNotIn("docker-compose.override.yml\"", source)
        self.assertNotIn("lab_dir / \"docker-compose.demo.yml\"", source)

    def test_down_restores_the_lab_and_reports_it(self) -> None:
        with _lab() as lab_dir, mock.patch.object(
            field, "prepare_compose",
            return_value=("docker", {}, ["docker", "compose"], lab_dir.parent / "scratch"),
        ), mock.patch.object(
            field.subprocess, "run",
            return_value=subprocess.CompletedProcess(["docker"], 0, "", ""),
        ) as run:
            (lab_dir.parent / "scratch").mkdir(exist_ok=True)
            result = field.run_demo_target("down", lab_dir)
        self.assertIs(result["running"], False)
        self.assertIn("down", run.call_args.args[0])


class ContainerLookupTests(unittest.TestCase):
    def test_the_running_container_id_comes_from_compose(self) -> None:
        completed = subprocess.CompletedProcess(["docker"], 0, "abc123\n", "")
        with mock.patch.object(field.subprocess, "run", return_value=completed) as run:
            found = field._service_container(
                ["docker", "compose"], "vulnerable", Path("/lab"), {}
            )
        self.assertEqual(found, "abc123")
        self.assertEqual(
            run.call_args.args[0], ["docker", "compose", "ps", "-q", "vulnerable"]
        )

    def test_a_service_with_no_container_is_empty_not_an_error(self) -> None:
        for completed in (
            subprocess.CompletedProcess(["docker"], 0, "", ""),
            subprocess.CompletedProcess(["docker"], 1, "", "no such service"),
        ):
            with self.subTest(code=completed.returncode):
                with mock.patch.object(field.subprocess, "run", return_value=completed):
                    self.assertEqual(
                        field._service_container(
                            ["docker", "compose"], "patched", Path("/lab"), {}
                        ),
                        "",
                    )


class OneArtifactTwoModesTests(unittest.TestCase):
    """`PoC.py` is both programs, and each says what it is worth.

    WHAT WAS MEASURED

    A validated lab shipped two scripts. `artifacts/PoC.py` was
    `validator/validator.py` with a six-line docstring prepended and nothing
    else changed -- across 89 archived labs `diff` printed `0a1,6` and
    stopped -- and its own header said it was "designed for the generated
    Docker lab, not remote targets". Beside it, for 26 of 148 validated labs,
    sat the script that did take a target. So three labs in four carried only
    the lab-only program under the name `PoC.py`, and a reader who opened the
    file called PoC found no claim at all; the claim was in a file nobody
    opened.

    WHAT THESE TESTS HOLD

    Lab mode first and hardest, because a regression there breaks validation
    rather than a deliverable: the lower half of the file is this lab's own
    validator, byte for byte, and running the merged file with no argument
    does what running the validator does. Then remote mode's standing: proved
    and usable, or refused in the drafter's own words with nothing sent.
    """

    SPEC = {
        "strategy": "direct_observation",
        "observable_effect": "an admin route answering 200 to an unauthenticated requester",
        "probe": [{"method": "GET", "path": "{{target_path}}"}],
        "expect": {"status": 200},
        "inputs": ["target_path"],
    }
    PLAN = {
        "cve": "CVE-2026-0001",
        "lab_type": "SOURCE_REPRODUCTION",
        "scenario": "default",
        "repository": "https://example.invalid/p.git",
        "revisions": {"vulnerable": "a" * 40, "patched": "b" * 40},
    }

    def artifact(self, record: dict[str, Any], validator: str = _LAB_MODE) -> str:
        return field.emit_poc("CVE-2026-0001", self.PLAN, validator, record)

    def proved(self) -> dict[str, Any]:
        return {
            "shipped": True,
            "container_port": 8080,
            "spec": field.validate_spec(self.SPEC),
            "lab_values": {"target_path": "/admin"},
        }

    def ran(self, text: str, *argv: str) -> subprocess.CompletedProcess:
        """The artifact run as a file, which is how it is run.

        Not with -c: Windows caps a command line at about 32 KB and the
        deliverable is larger, so passing it as an argument fails with
        WinError 206 before Python sees it.
        """
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        path = Path(root.name) / field.POC_NAME
        path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(path), *argv],
            capture_output=True, text=True, timeout=60,
            env={"PATH": os.environ["PATH"]},
        )

    # --- lab mode ---------------------------------------------------------

    def test_the_lower_half_is_the_validator_byte_for_byte(self) -> None:
        for record in (self.proved(), {"shipped": False, "reason": "no"}, {}):
            with self.subTest(standing=field.poc_standing(record)):
                carried = self.artifact(record).partition(
                    field.POC_LAB_MODE_MARKER
                )[2]
                self.assertEqual(carried, _LAB_MODE)

    def test_lab_mode_does_what_the_validator_does(self) -> None:
        """The non-negotiable, measured rather than read.

        Same stdout, same exit code, and the environment the validator takes
        its instructions from still reaches it: `manual.sh exploit` sets
        CVELAB_MANUAL_ACTION, and the merged file must pass it through
        untouched.
        """
        with tempfile.TemporaryDirectory() as root:
            alone = Path(root) / "validator.py"
            alone.write_text(_LAB_MODE, encoding="utf-8")
            merged = Path(root) / field.POC_NAME
            for record in (self.proved(), {"shipped": False, "reason": "no"}):
                for action in ("", "exploit"):
                    with self.subTest(
                        standing=field.poc_standing(record), action=action
                    ):
                        environment = {"PATH": os.environ["PATH"]}
                        if action:
                            environment["CVELAB_MANUAL_ACTION"] = action
                        merged.write_text(self.artifact(record), encoding="utf-8")
                        one = subprocess.run(
                            [sys.executable, str(merged)], capture_output=True,
                            text=True, timeout=60, env=environment,
                        )
                        two = subprocess.run(
                            [sys.executable, str(alone)], capture_output=True,
                            text=True, timeout=60, env=environment,
                        )
                        self.assertEqual(one.stdout, two.stdout)
                        self.assertEqual(one.returncode, two.returncode)
                        self.assertEqual(one.stdout, f"{action or 'differential'}\n")

    def test_a_future_import_in_the_lab_half_is_hoisted(self) -> None:
        """2 of 281 archived validators carry one.

        A future statement must precede every other statement in a file, and
        this file holds two programs, so leaving it where it was is a
        SyntaxError that would reach the operator as a PoC that does not
        parse.
        """
        validator = "from __future__ import annotations\n" + _LAB_MODE
        merged = self.artifact(self.proved(), validator)
        ast.parse(merged)
        upper, _, lower = merged.partition(field.POC_LAB_MODE_MARKER)
        self.assertIn("from __future__ import annotations\n", upper)
        self.assertIn("# from __future__ import annotations", lower)
        self.assertNotIn("\nfrom __future__", lower)

    # --- remote mode ------------------------------------------------------

    def test_a_proved_remote_mode_runs_and_still_demands_the_inputs(self) -> None:
        """The honest part of the old script, kept.

        CVELab does not know where in someone's application the vulnerable
        call receives user input, so the script refuses to start without it
        rather than sending the placeholder literally and reporting a clean
        target.
        """
        text = self.artifact(self.proved())
        refused = self.ran(text, "10.0.0.5:8080")
        self.assertEqual(refused.returncode, 1)
        self.assertIn("needs values it cannot know: target_path", refused.stderr)
        # And the target itself is validated before anything is sent.
        rubbish = self.ran(text, "http://10.0.0.5:8080/some/path")
        self.assertNotEqual(rubbish.returncode, 0)
        self.assertIn("--target", rubbish.stderr)

    def test_a_refused_remote_mode_says_the_drafters_reason_and_sends_nothing(self) -> None:
        """A remote mode that looks available and was never proved is worse
        than two files, because someone presses it at a client."""
        reason = (
            "A stock application that calls the affected helper does not report "
            "that state."
        )
        done = self.ran(
            self.artifact({"shipped": False, "reason": reason}),
            "10.0.0.5:8080",
        )
        self.assertEqual(done.returncode, 2)
        self.assertIn("has no remote mode", done.stderr)
        self.assertIn("does not report", done.stderr)
        self.assertEqual(done.stdout, "")

    def test_the_three_refusals_read_differently(self) -> None:
        """Refused, never asked for, and no record are three answers.

        Rendering "not requested" as a refusal would attribute to the model a
        judgement it was never asked to make.
        """
        said = {
            standing: self.ran(self.artifact(record), "10.0.0.5:8080").stderr
            for standing, record in (
                (field.POC_REFUSED, {"shipped": False, "reason": "the effect is internal"}),
                (field.POC_NOT_REQUESTED,
                 {"shipped": False, "reason": field.NOT_REQUESTED_REASON}),
                (field.POC_NO_RECORD, {}),
            )
        }
        self.assertIn("recorded why", said[field.POC_REFUSED])
        self.assertIn("never asked for", said[field.POC_NOT_REQUESTED])
        self.assertIn("kept no record", said[field.POC_NO_RECORD])
        self.assertEqual(len(set(said.values())), 3)
        self.assertNotIn(
            field.NOT_REQUESTED_REASON, said[field.POC_NOT_REQUESTED]
        )

    def test_a_half_written_record_claims_nothing(self) -> None:
        """`shipped` without a spec and a port is no claim.

        The spec and the port are what remote mode is made of, and the record
        is read back off disk from a lab an older CVELab may have written.
        """
        for record in (
            {"shipped": True},
            {"shipped": True, "spec": field.validate_spec(self.SPEC)},
            {"shipped": True, "spec": field.validate_spec(self.SPEC),
             "container_port": "8080"},
        ):
            with self.subTest(record=sorted(record)):
                self.assertEqual(field.poc_standing(record), field.POC_NO_RECORD)
                self.assertIn(
                    "kept no record",
                    self.ran(self.artifact(record), "10.0.0.5:8080").stderr,
                )

    def test_the_header_states_its_standing_either_way(self) -> None:
        proved = self.artifact(self.proved()).split('"""')[1]
        self.assertIn(
            "Tested        : proven by CVELab against a build of this project", proved
        )
        self.assertIn("Strategy      : direct_observation", proved)
        self.assertIn("Needs         : --input target_path=...", proved)
        header = self.artifact(
            {"shipped": False, "reason": "the effect is internal"}
        ).split('"""')[1]
        self.assertIn("no remote mode", header)
        # And it claims none of what it was not: those four lines are about a
        # run against one instance, and there was none.
        for absent in ("Tested ", "Strategy ", "Transport ", "Needs "):
            self.assertNotIn(absent, header)
        # The facts about the weakness are facts either way.
        self.assertIn("Project       : https://example.invalid/p.git", header)

    def test_a_triple_quote_in_the_drafters_reason_cannot_end_the_docstring(self) -> None:
        """The one text in the artifact CVELab did not write."""
        merged = self.artifact(
            {"shipped": False, "reason": 'the adapter prints """ around it'}
        )
        ast.parse(merged)
        self.assertIn("'" * 3, merged.split('"""')[1])
        self.assertEqual(2, self.ran(merged, "10.0.0.5:8080").returncode)

    # --- the two writers agree --------------------------------------------

    def test_the_proved_artifact_and_the_rendered_one_are_the_same_bytes(self) -> None:
        """Two writers, one file.

        field.write_manual_poc writes it as run_lab's after_validation hook,
        from the record it has just proved; deliverables.create_deliverables
        writes it again for every validated lab, from the record it reads
        back. The claim "the script CVELab proved is byte for byte the one the
        operator receives" rests on those two agreeing.
        """
        with _lab() as lab_dir:
            outcome = {
                "shipped": True, "proof_checks": {}, "runs": {},
                "script": "ignored: write_manual_poc re-emits it",
                "lab_values": {"target_path": "/admin"},
            }
            field.write_manual_poc(
                "CVE-2026-0001", lab_dir, self.PLAN,
                field.validate_spec(self.SPEC), 8080, outcome,
            )
            written = (lab_dir / "artifacts" / field.POC_NAME).read_text()
            rendered = field.emit_poc(
                "CVE-2026-0001", self.PLAN,
                (lab_dir / "validator" / "validator.py").read_text(),
                field.poc_record(lab_dir),
            )
        self.assertEqual(written, rendered)

    def test_an_archived_labs_proved_spec_survives_a_re_render(self) -> None:
        """29 of the 45 archived records carry a spec that shipped.

        That spec was in Manual-PoC.json and nowhere else -- this key did not
        carry one -- so reading only the report would turn every one of those
        labs into a refusal the next time its deliverables were written.
        """
        held = dict(self.proved(), cve="CVE-2026-0001")
        with _lab(legacy_record=held) as lab_dir:
            record = field.poc_record(lab_dir)
            self.assertEqual(field.poc_standing(record), field.POC_SHIPPED)
            self.assertIn(
                "REMOTE MODE -- one instance",
                field.emit_poc("CVE-2026-0001", self.PLAN, _LAB_MODE, record),
            )

    def test_this_runs_refusal_wins_over_an_archived_claim(self) -> None:
        """The report is this run's answer; the old file is a fallback.

        A lab whose remote mode was proved once and refused on a later run
        must not keep advertising the first answer.
        """
        held = dict(self.proved(), cve="CVE-2026-0001")
        with _lab(
            legacy_record=held,
            record={"shipped": False, "reason": "the second run told them apart"},
        ) as lab_dir:
            record = field.poc_record(lab_dir)
        self.assertEqual(field.poc_standing(record), field.POC_REFUSED)
        self.assertIn("told them apart", record["reason"])


class TheLabAddressFlagTests(unittest.TestCase):
    """The command form, kept because showing impact is what it is for.

    WHAT WAS MEASURED

    `PoC.py <addr> id` ran a command through the weakness and printed its
    output -- `uid=10001(app) gid=10001(app) groups=10001(app)` on a freshly
    generated code-execution lab. It was the carried validator's own mode and
    was never proved against anything but this lab's route, which is a
    constant in that validator: aimed at a client it would send that route,
    find it absent and print BLOCKED, a false negative dressed as a test. A
    bare address now means remote mode, which is proved per CVE or refuses.

    The owner's reason for keeping it is that without it they cannot show a
    client what the vulnerability does. That is a job on a lab they brought
    up themselves, so the flag names the lab, refuses an address this lab
    cannot have published, and says in its own help what it cannot check.
    """

    PLAN = {
        "cve": "CVE-2026-0001",
        "lab_type": "SOURCE_REPRODUCTION",
        "scenario": "default",
        "repository": "https://example.invalid/p.git",
        "exploit_contract": {"service_port": 8080, "evidence_type": "code_execution"},
    }
    #: A lab program that reports the argv it was handed, which is the whole
    #: of what this flag does to it: the real one is the lab's validator and
    #: reads `[addr]` or `[addr, command]` by its own generation contract.
    #:
    #: The command is read by INDEX and not by slice, which matters because
    #: `_reads_a_second_positional` is what decides whether the header and
    #: the kit offer the form at all, and it refuses a slice on purpose:
    #: `argv[2:]` is as often `if argv[2:]: usage()` as it is a read. Both
    #: archived validators that implement the form index it, so a fixture
    #: that sliced was testing a shape generation does not produce -- and it
    #: asserted the header promising a command the detector had refused.
    LAB = (
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "def main():\n"
        "    if len(sys.argv) > 1:\n"
        "        argv = sys.argv\n"
        "        command = argv[2] if len(argv) > 2 else None\n"
        "        print('lab program against %s, command=%s'\n"
        "              % (argv[1], command))\n"
        "        return 0\n"
        "    print(os.environ.get('CVELAB_MANUAL_ACTION', 'differential'))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n"
    )

    def artifact(self, record: dict[str, Any] | None = None, plan: dict | None = None) -> str:
        proved = {
            "shipped": True, "container_port": 8080,
            "spec": field.validate_spec(_spec(
                inputs=["target_path"],
                probe=[{"method": "GET", "path": "{{target_path}}"}],
            )),
        }
        return field.emit_poc(
            "CVE-2026-0001", self.PLAN if plan is None else plan, self.LAB,
            proved if record is None else record,
        )

    def ran(self, text: str, *argv: str) -> subprocess.CompletedProcess:
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        path = Path(root.name) / field.POC_NAME
        path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(path), *argv],
            capture_output=True, text=True, timeout=60,
            env={"PATH": os.environ["PATH"]},
        )

    def test_it_reaches_the_lab_program_with_the_address_and_the_command(self) -> None:
        for text in (self.artifact(), self.artifact({"shipped": False, "reason": "no"})):
            with self.subTest(standing=field.poc_standing(
                {"shipped": False, "reason": "no"} if "REMOTE_MODE_REFUSED" in text else {}
            )):
                done = self.ran(text, "--lab-address", "127.0.0.1:32768", "id")
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(
                    done.stdout,
                    "lab program against 127.0.0.1:32768, command=id\n",
                )

    def test_the_equals_spelling_works_too(self) -> None:
        done = self.ran(self.artifact(), "--lab-address=127.0.0.1:32768", "id")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("127.0.0.1:32768", done.stdout)

    def test_the_flag_is_read_only_ahead_of_the_command(self) -> None:
        """A second spelling of the flag must not eat the command.

        Read anywhere in argv, it did: the later spelling overwrote the
        address and left the command list empty, which the operator contract
        defines as "run the lab's own harmless canary command". So the
        command vanished and the file printed the canary's observation and
        REPRODUCED on stdout at exit 0 -- a success status for work nobody
        asked for, from an argument the operator meant as a command, and
        reachable from any caller that passes operator text through to this
        entry point.

        Both directions are checked, because a fix that refused everything
        flag-shaped would break the other one: an argument that merely
        CONTAINS the flag is a word in the command and has to arrive whole.
        """
        text = self.artifact()
        for twice in (["--lab-address", "127.0.0.1:32768", "--lab-address=127.0.0.1:32768"],
                      ["--lab-address", "127.0.0.1:32768", "--lab-address", "127.0.0.1:9999"],
                      ["--lab-address=127.0.0.1:32768", "--lab-address=127.0.0.1:9999"]):
            with self.subTest(argv=twice):
                done = self.ran(text, *twice)
                self.assertEqual(done.returncode, 2, done.stderr)
                self.assertEqual(done.stdout, "", "nothing may be sent or claimed")
                self.assertNotIn("REPRODUCED", done.stdout)
                self.assertIn("given twice", done.stderr)
        carried = "cd /tmp && echo --lab-address=not-a-flag-here"
        done = self.ran(text, "--lab-address", "127.0.0.1:32768", carried)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(carried, done.stdout)

    def test_an_address_this_lab_cannot_have_published_is_refused(self) -> None:
        """The half of the question that can be answered cheaply.

        `manual.sh` publishes 127.0.0.1 with the port left to the kernel, so
        a host that is not loopback is certainly not this lab's. Which
        loopback port is this lab's is knowable only by asking Docker, which
        the artifact does not do -- so that half is said rather than guessed.
        """
        for where in ("10.0.0.5:8080", "app.example.com", "https://app.example.com",
                      "[2001:db8::1]:443", "127.0.0.1.example.com:80"):
            with self.subTest(target=where):
                done = self.ran(self.artifact(), "--lab-address", where, "id")
                self.assertEqual(done.returncode, 2)
                self.assertEqual(done.stdout, "")
                self.assertIn("not an address this lab published", done.stderr)
                self.assertIn("manual.sh address", done.stderr)
        for where in ("127.0.0.1:32768", "127.0.0.1", "localhost:8080", "[::1]:8080"):
            with self.subTest(target=where):
                self.assertEqual(
                    0, self.ran(self.artifact(), "--lab-address", where).returncode
                )

    def test_it_cannot_be_used_without_an_address(self) -> None:
        for argv in (["--lab-address"], ["--lab-address", "--show-bodies"],
                     ["--lab-address="]):
            with self.subTest(argv=argv):
                done = self.ran(self.artifact(), *argv)
                self.assertEqual(done.returncode, 2)
                self.assertIn("takes the address this lab was published on", done.stderr)
                self.assertIn("not optional", done.stderr)

    def test_it_refuses_to_be_mixed_with_remote_mode(self) -> None:
        """Which of the two the person wants decides what is being tested."""
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:1",
            "--input", "target_path=/theirs",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("different jobs", done.stderr)
        self.assertIn("--input belongs to remote", done.stderr)
        self.assertIn("--lab-address runs against this lab's", done.stderr)

    def test_the_help_says_what_it_reaches_and_what_it_cannot_check(self) -> None:
        said = " ".join(self.ran(self.artifact(), "--help").stdout.split())
        self.assertIn("--lab-address ADDRESS [COMMAND]", said)
        self.assertIn("against this lab's own build on ADDRESS", said)
        self.assertIn("shows nothing about any other host", said)
        self.assertIn("is not something this file can check", said)
        # And on a lab with no remote mode there is no argparse to print it,
        # so --help prints the header, which carries the same sentences.
        refused = self.ran(
            self.artifact({"shipped": False, "reason": "the effect is internal"}),
            "--help",
        )
        self.assertEqual(refused.returncode, 0)
        self.assertIn(
            "shows nothing about any other host", " ".join(refused.stdout.split())
        )
        self.assertIn("--lab-address", refused.stdout)

    def test_the_header_says_it_in_the_same_breath_as_lab_mode(self) -> None:
        header = self.artifact().split('"""')[1]
        lab = header[header.index("LAB MODE"):header.index("REMOTE MODE")]
        flat = " ".join(lab.split())
        self.assertIn("--lab-address 127.0.0.1:32768 id", flat)
        self.assertIn("reaches a build CVELab made", flat)
        self.assertIn("shows nothing about any other host", flat)
        self.assertIn("has to be on loopback", flat)
        self.assertIn("not something this file can check", flat)

    def test_a_lab_that_declares_no_port_has_no_such_flag(self) -> None:
        """Its validator reads no argument, so the flag would run the
        differential and call it a demonstration. 89 archived labs are that
        lab.
        """
        plan = dict(self.PLAN)
        plan.pop("exploit_contract")
        text = self.artifact(plan=plan)
        self.assertNotIn("--lab-address", text)
        done = self.ran(text, "--lab-address", "127.0.0.1:32768", "id")
        self.assertEqual(done.returncode, 2)
        self.assertIn("unrecognized arguments", done.stderr)

    def test_a_lab_with_no_command_evidence_is_offered_no_command(self) -> None:
        plan = dict(self.PLAN, exploit_contract={
            "service_port": 8080, "evidence_type": "unauthorized_read",
        })
        header = self.artifact(plan=plan).split('"""')[1]
        self.assertIn("--lab-address 127.0.0.1:32768\n", header)
        self.assertNotIn("--lab-address 127.0.0.1:32768 id", header)
        self.assertNotIn("one command to run", header)

    def test_no_argument_at_all_is_still_untouched(self) -> None:
        """The non-negotiable, with the flag in the file."""
        with tempfile.TemporaryDirectory() as root:
            alone = Path(root) / "validator.py"
            alone.write_text(self.LAB, encoding="utf-8")
            for action in ("", "exploit"):
                with self.subTest(action=action):
                    environment = {"PATH": os.environ["PATH"]}
                    if action:
                        environment["CVELAB_MANUAL_ACTION"] = action
                    merged = Path(root) / field.POC_NAME
                    merged.write_text(self.artifact(), encoding="utf-8")
                    one = subprocess.run(
                        [sys.executable, str(merged)], capture_output=True,
                        text=True, timeout=60, env=environment,
                    )
                    two = subprocess.run(
                        [sys.executable, str(alone)], capture_output=True,
                        text=True, timeout=60, env=environment,
                    )
                    self.assertEqual(one.stdout, two.stdout)
                    self.assertEqual(one.returncode, two.returncode)

    def test_the_kit_prints_the_command_where_the_operator_is_looking(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            lab = Path(root)
            artifacts = lab / "artifacts"
            artifacts.mkdir()
            deliverables._write_generic_manual_assets(
                "CVE-2026-0001", lab, artifacts, False, False, 8080,
                {"shipped": False, "reason": "the effect is internal"}, True,
            )
            runner = (artifacts / "manual.sh").read_text()
            guide = (artifacts / field.LAB_POC_GUIDE_NAME).read_text()
        # Available whether or not remote mode was proved: it is this lab's
        # own build either way.
        self.assertIn("--lab-address $POC_AT id", runner)
        self.assertIn('python3 PoC.py --lab-address "$(bash manual.sh address', guide)
        self.assertIn("shows nothing about any other host", " ".join(guide.split()))


class ThePromptTests(unittest.TestCase):
    """`--shell`: a prompt over the one-command form, and not a session.

    WHY IT IS A PROMPT AND NOT A CHANNEL

    For a lab whose evidence is command execution, one echoed command proves
    execution and a terminal proves control -- and the artifact could only do
    the first: `--lab-address ADDRESS COMMAND` runs one command per
    invocation, imposed, because `_lab_address` rewrites argv into the shape
    the lab program already takes. What the lower half implements is a
    request/response oracle, so the half above it runs that oracle in a loop:
    one process per line, the lab program's own exit status per line, and no
    attack of CVELab's anywhere. `sourcegen` is untouched, and "validator.py
    has two entry points and must have exactly two" stays true.

    WHAT THESE TESTS HOLD

    That each line really does go through `--lab-address` and never as a bare
    address, which would be remote mode -- a different program against a
    different spec. That output is printed and the cosmetic strip of the
    drafter's header line cannot lose any of it. That `cd` is tracked here
    and said to be. That every refusal exits 2 and says why, including the
    flag that has to be asked for. And that a lab which cannot support the
    mode carries no trace of it: the form the prompt drives is asked for in
    the generation contract's prose with no check behind it, so it is read
    out of the validator and the reason is printed where the operator reads
    it when it is missing.
    """

    CONTRACT = {
        "service_port": 8080,
        "evidence_type": "code_execution",
        "attack_summary": "GET /run?cmd= reaches a shell through the adapter",
    }
    PLAN = {
        "cve": "CVE-2026-0001",
        "lab_type": "SOURCE_REPRODUCTION",
        "scenario": "default",
        "repository": "https://example.invalid/p.git",
        "exploit_contract": CONTRACT,
        "fidelity": {
            "simulated_components": [
                "HTTP listener adapter/server.js: the project ships no server, so "
                "the adapter exposes the helper over GET /run",
            ],
        },
    }
    #: A lab program with the one-command form, written the way the two
    #: archived labs that have it are: the command is the second positional,
    #: its output goes under a line of prose saying so, and a command that did
    #: not run exits non-zero with the observation instead.
    LAB = (
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "\n"
        "def main():\n"
        "    argv = sys.argv\n"
        "    if len(argv) == 1:\n"
        "        print(os.environ.get('CVELAB_MANUAL_ACTION', 'differential'))\n"
        "        return 0\n"
        "    if len(argv) > 3:\n"
        "        print('usage: %s [<host>:<port>] [command]'\n"
        "              % os.path.basename(argv[0]), file=sys.stderr)\n"
        "        return 2\n"
        "    print('address in use: ' + argv[1], file=sys.stderr)\n"
        "    if len(argv) == 2:\n"
        "        print('REPRODUCED')\n"
        "        return 0\n"
        "    command = argv[2]\n"
        "    if command.startswith('boom'):\n"
        "        print('observation: the route answered 404')\n"
        "        print('BLOCKED')\n"
        "        return 1\n"
        "    if not command.startswith('quiet'):\n"
        "        print('the following is the command output:')\n"
        "    print('ran %s against %s' % (command, argv[1]))\n"
        "    return 0\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n"
    )
    #: The same program with the second positional refused rather than read,
    #: which is what 32 of the 34 archived command-execution labs do.
    NO_COMMAND = (
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "\n"
        "def main():\n"
        "    argv = sys.argv\n"
        "    if len(argv) > 2:\n"
        "        print('usage: %s [<host>:<port>]'\n"
        "              % os.path.basename(argv[0]), file=sys.stderr)\n"
        "        return 2\n"
        "    if len(argv) == 2:\n"
        "        print('REPRODUCED')\n"
        "        return 0\n"
        "    print(os.environ.get('CVELAB_MANUAL_ACTION', 'differential'))\n"
        "    return 0\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n"
    )
    #: The same form again, with the command's output printed on its own and
    #: no line of prose over it. The contract asks for that line in prose and
    #: checks nothing, so a lab program that prints none is admitted by the
    #: same reading of the validator that admits the two that do -- and what
    #: arrives on stdout is then the command's own first line.
    RAW = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "\n"
        "def main():\n"
        "    argv = sys.argv\n"
        "    if len(argv) == 3:\n"
        "        print(argv[2])\n"
        "        return 0\n"
        "    if len(argv) == 2:\n"
        "        print('REPRODUCED')\n"
        "        return 0\n"
        "    return 0\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n"
    )

    def artifact(
        self,
        record: dict[str, Any] | None = None,
        plan: dict | None = None,
        validator: str | None = None,
    ) -> str:
        proved = {
            "shipped": True, "container_port": 8080,
            "spec": field.validate_spec(_spec()),
        }
        return field.emit_poc(
            "CVE-2026-0001",
            self.PLAN if plan is None else plan,
            self.LAB if validator is None else validator,
            proved if record is None else record,
        )

    def ran(
        self, text: str, *argv: str, typed: str = "", name: str = field.POC_NAME
    ) -> subprocess.CompletedProcess:
        """The artifact run as a file, with lines typed at it."""
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        path = Path(root.name) / name
        path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(path), *argv], input=typed,
            capture_output=True, text=True, timeout=120,
            env={"PATH": os.environ["PATH"]},
        )

    def prompted(self, typed: str, **kept: Any) -> subprocess.CompletedProcess:
        return self.ran(
            self.artifact(**kept), "--lab-address", "127.0.0.1:32768",
            "--shell", "--allow-shell", typed=typed,
        )

    # --- the line it builds -----------------------------------------------

    def test_each_line_is_one_run_of_the_flag_and_never_a_bare_address(self) -> None:
        """The one line in this mode that cannot be written another way.

        `_poc_entry` hands a bare argv[1] to remote mode's `main()`, which is
        a different program drafted against a different spec; `--lab-address`
        is the only branch that falls through to the lab program with the
        address where that program reads it. So the invocation is pinned as
        text, and then measured on a lab with no remote mode, where a bare
        address prints the recorded reason and sends nothing.
        """
        text = self.artifact()
        self.assertIn(
            '[sys.executable, __file__, "--lab-address", address, command]', text
        )
        refused = self.artifact({"shipped": False, "reason": "the effect is internal"})
        done = self.ran(
            refused, "--lab-address", "127.0.0.1:32768", "--shell", "--allow-shell",
            typed="id\n",
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "ran id against 127.0.0.1:32768\n")
        self.assertNotIn("the effect is internal", done.stdout)
        self.assertNotIn("the effect is internal", done.stderr)

    def test_the_address_may_be_given_in_either_spelling(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address=127.0.0.1:32768", "--shell",
            "--allow-shell", typed="id\n",
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "ran id against 127.0.0.1:32768\n")

    def test_the_output_is_printed_with_the_drafters_header_line_dropped(self) -> None:
        done = self.prompted("id\npwd\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(
            done.stdout,
            "ran id against 127.0.0.1:32768\n"
            "ran pwd against 127.0.0.1:32768\n",
        )
        self.assertNotIn("the following is the command output", done.stdout)

    def test_a_first_line_that_is_not_that_header_is_printed_whole(self) -> None:
        """The strip is cosmetic and must never be able to lose output.

        The contract asks for the line in prose and does not spell it, and
        the real validator written to it prints `status: 200` first -- so
        anything that does not read like the header is output and all of it
        is printed.
        """
        done = self.prompted("quiet first\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "ran quiet first against 127.0.0.1:32768\n")

    def test_output_that_reads_like_the_header_is_still_output(self) -> None:
        """The strip is matched as a label, because it can lose output.

        A lab program that prints the output with no line of prose over it --
        which the contract permits, because it asks for that line in prose and
        checks nothing -- puts the command's own first line where the label
        would be. Matched as a phrase, `echo 'command output is here'` lost
        every byte it produced, silently and at exit 0. Matched as a whole
        line ending in the colon both written labels end in, it does not: an
        output line is a line of output and almost never a caption for itself.
        """
        done = self.prompted(
            "command output is here\ncommand output:\n", validator=self.RAW
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "command output is here\n")

    def test_a_line_that_is_the_address_flag_is_refused_before_it_is_sent(self) -> None:
        """The one line this prompt cannot deliver through the form it drives.

        The typed line is one argument of a run of `--lab-address ADDRESS
        COMMAND`, and that run reads the flag wherever it appears -- so a line
        that IS the flag replaces the address and leaves the lab program with
        no command at all. That program then prints its own differential, so
        `--lab-address=127.0.0.1:32768` typed as a command used to put
        `REPRODUCED` on stdout, where the command's output goes, at exit 0.
        Refused here by name, with nothing sent, and a line that merely
        contains the flag is still delivered as typed.
        """
        done = self.prompted(
            "--lab-address=127.0.0.1:32768\n--lab-address\necho --lab-address=x\n"
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "ran echo --lab-address=x against 127.0.0.1:32768\n")
        self.assertNotIn("REPRODUCED", done.stdout)
        self.assertEqual(done.stderr.count("That line is --lab-address itself"), 2)
        self.assertIn("Nothing was sent", done.stderr)

    def test_a_line_that_did_not_run_is_not_printed_as_output(self) -> None:
        """Exit non-zero on this form means the command did not run.

        What the lab program prints then is its own observation -- BLOCKED,
        or the response it got -- and reading that as the command's answer is
        the one mistake a prompt makes easy, so it goes to stderr with a line
        saying what it is.
        """
        done = self.prompted("boom\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "")
        self.assertIn("BLOCKED", done.stderr)
        self.assertIn("the command did not run", done.stderr)

    # --- the directory it tracks ------------------------------------------

    def test_cd_is_tracked_here_and_prefixed_to_every_line(self) -> None:
        done = self.prompted('cd /srv\npwd\ncd app\npwd\ncd "/a b"\npwd\ncd\npwd\n')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(
            [line.partition(" against ")[0] for line in done.stdout.splitlines()],
            [
                "ran cd /srv && pwd",
                "ran cd /srv/app && pwd",
                "ran cd '/a b' && pwd",
                "ran pwd",
            ],
        )

    def test_a_line_that_joins_commands_is_sent_as_it_was_typed(self) -> None:
        """Its `cd` is real and lasts exactly as long as that one command,
        which is what the prompt would be claiming if it tracked it.
        """
        done = self.prompted("cd /srv && pwd\npwd\n")
        self.assertEqual(
            [line.partition(" against ")[0] for line in done.stdout.splitlines()],
            ["ran cd /srv && pwd", "ran pwd"],
        )

    def test_the_prompt_says_the_directory_is_simulated(self) -> None:
        done = self.prompted("cd /srv\n")
        self.assertIn("[cd simulated] .$", done.stderr)
        self.assertIn("[cd simulated] /srv$", done.stderr)

    def test_an_empty_line_sends_nothing_and_exit_leaves(self) -> None:
        for typed in ("exit\n", "quit\n", "\n\n\n", ""):
            with self.subTest(typed=typed):
                done = self.prompted(typed)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout, "")

    # --- what it says before the first line -------------------------------

    def test_it_says_what_it_is_not_before_anything_is_typed(self) -> None:
        said = " ".join(self.prompted("").stderr.split())
        for sentence in (
            "a prompt, not a session",
            "Each line you type is ONE command",
            "no persistent environment",
            "no interactive programs",
            "no job control, no signals",
            "no line editing and no history",
            "`cd` is simulated",
        ):
            with self.subTest(sentence=sentence):
                self.assertIn(sentence, said)

    def test_it_says_where_the_operator_actually_is(self) -> None:
        """The honesty this mode is measured against.

        Of the archived labs whose evidence is command execution, none has
        the vendor's product serving the route the attack goes to. So the
        prompt names the route, quotes the `simulated_components` entry that
        declares it, and says what the effect is not evidence of -- in the
        lab's own words, before the first command is typed and again in the
        header.
        """
        said = " ".join(self.prompted("").stderr.split())
        header = self.artifact().split('"""')[1]
        lab = header[header.index("LAB MODE"):header.index("REMOTE MODE")]
        for text in (said, " ".join(lab.split())):
            with self.subTest(where="prompt" if text is said else "header"):
                self.assertIn("GET /run?cmd= reaches a shell through the adapter", text)
                self.assertIn("declares that route simulated", text)
                self.assertIn("adapter exposes the helper over GET /run", text)
                self.assertIn("adapter CVELab's model wrote", text)
                self.assertIn(
                    "evidence of nothing at all about any other host", text
                )

    def test_a_lab_that_recorded_nothing_is_not_told_the_route_is_genuine(self) -> None:
        """What the silence in the fidelity record is allowed to be read as.

        An empty `simulated_components` is ambiguous, and this file says so
        itself where it hands the same field to a drafter: it can mean nothing
        was simulated, which is the best case, or that the lab said nothing.
        `vendor_product_started` is what tells them apart, and
        `deliverables._fidelity` resolves the same silence the same way --
        assuming an unspecified adapter for a lab that recorded none. So the
        one sentence here that says the route is the product's own is said
        only where the lab recorded that the product started, and the silence
        reads as not recorded rather than as real access.
        """
        plans = {
            "no fidelity at all": {
                key: value for key, value in self.PLAN.items() if key != "fidelity"
            },
            "an empty list and nothing else": dict(
                self.PLAN, fidelity={"simulated_components": []}
            ),
            "an empty list and the product not started": dict(
                self.PLAN,
                fidelity={
                    "simulated_components": [], "vendor_product_started": False,
                },
            ),
        }
        for name, plan in plans.items():
            with self.subTest(plan=name):
                said = " ".join(field._shell_where_you_are(plan).split())
                self.assertIn("does not say what answers this route", said)
                self.assertIn("Read that as not recorded", said)
                self.assertNotIn("the route is the product's own", said)
                self.assertIn(
                    "evidence of nothing at all about any other host", said
                )
        started = dict(
            self.PLAN,
            fidelity={"simulated_components": [], "vendor_product_started": True},
        )
        said = " ".join(field._shell_where_you_are(started).split())
        self.assertIn("records the vendor's own product starting", said)
        self.assertIn("so the route is the product's own", said)

    def test_it_names_the_file_it_was_run_as(self) -> None:
        """The same artifact is delivered under one name and run under another."""
        text = self.artifact()
        for name in (field.POC_NAME, "validator.py"):
            with self.subTest(name=name):
                done = self.ran(
                    text, "--lab-address", "127.0.0.1:32768", "--shell",
                    "--allow-shell", typed="", name=name,
                )
                self.assertIn(f"{name} --lab-address 127.0.0.1:32768 --shell", done.stderr)

    def test_the_header_and_the_help_both_offer_it(self) -> None:
        header = self.artifact().split('"""')[1]
        lab = header[header.index("LAB MODE"):header.index("REMOTE MODE")]
        self.assertIn(
            "python3 PoC.py --lab-address 127.0.0.1:32768 --shell --allow-shell\n",
            lab,
        )
        said = " ".join(self.ran(self.artifact(), "--help").stdout.split())
        self.assertIn("--lab-address ADDRESS --shell --allow-shell", said)
        self.assertIn("--allow-shell is required and not implied", said)

    # --- every refusal ----------------------------------------------------

    def test_it_is_refused_without_the_flag_that_asks_for_it(self) -> None:
        """The precedent is --allow-disruption: every other mode in the file
        asks no more of what it is pointed at than an ordinary request.
        """
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--shell",
            typed="id\n",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("Re-run with --allow-shell", done.stderr)
        self.assertIn("you are permitted to do it", done.stderr)

    def test_it_refuses_a_command_on_the_command_line(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--shell",
            "--allow-shell", "id", typed="",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("different jobs", done.stderr)
        self.assertIn("--lab-address ADDRESS COMMAND", done.stderr)

    def test_it_refuses_to_be_mixed_with_remote_mode(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--shell",
            "--allow-shell", "--input", "target_path=/theirs", typed="",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("different jobs", done.stderr)
        self.assertIn("--input belongs to remote", done.stderr)

    def test_it_cannot_be_used_without_an_address(self) -> None:
        done = self.ran(self.artifact(), "--shell", "--allow-shell", typed="id\n")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("not optional", done.stderr)

    def test_an_address_this_lab_cannot_have_published_is_refused(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "10.0.0.5:8080", "--shell",
            "--allow-shell", typed="id\n",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("not an address this lab published", done.stderr)

    # --- the gate ---------------------------------------------------------

    def test_a_lab_that_declares_no_port_carries_no_trace_of_it(self) -> None:
        plan = dict(self.PLAN)
        plan.pop("exploit_contract")
        text = self.artifact(plan=plan)
        for absent in ("--shell", "--allow-shell", "no prompt in this file"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, text)
        done = self.ran(text, "--shell", "--allow-shell", typed="id\n")
        self.assertEqual(done.returncode, 2)
        self.assertIn("unrecognized arguments", done.stderr)

    def test_a_lab_with_no_command_evidence_carries_no_trace_of_it(self) -> None:
        plan = dict(
            self.PLAN,
            exploit_contract=dict(self.CONTRACT, evidence_type="unauthorized_read"),
        )
        text = self.artifact(plan=plan)
        for absent in ("--shell", "--allow-shell", "no prompt in this file"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, text)
        self.assertEqual(
            field.shell_standing(plan, self.LAB)[0], False
        )
        self.assertIn(
            "declared evidence is unauthorized_read",
            field.shell_standing(plan, self.LAB)[1],
        )

    def test_a_validator_without_the_command_form_gets_no_prompt(self) -> None:
        """The design amendment, and the whole reason for reading the
        validator: nothing in generation enforces the one-command form.

        `sourcegen._validate_generated` checks for the bare token `sys.argv`
        and nothing else, and the second positional is asked for in
        `_OPERATOR_CONTRACT`'s prose with no check behind it. Of the archived
        labs that declare a port and command execution, the ones that
        implement it are the ones generated under the contract. A prompt over
        a form the lab program refuses is a prompt where every line exits 2.
        """
        text = self.artifact(validator=self.NO_COMMAND)
        for absent in ("--shell", "--allow-shell"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, text)
        offered, reason = field.shell_standing(self.PLAN, self.NO_COMMAND)
        self.assertFalse(offered)
        self.assertIn("takes an address and no command", reason)
        # And the reason is printed where the operator reads it, not left in
        # report.json: this lab qualified in every way its own contract
        # states and the mode is missing anyway.
        header = text.split('"""')[1]
        lab = " ".join(
            header[header.index("LAB MODE"):header.index("REMOTE MODE")].split()
        )
        self.assertIn("There is no prompt in this file", lab)
        self.assertIn("takes an address and no command", lab)

    def test_the_command_form_is_read_through_the_spellings_that_exist(self) -> None:
        """Conservative, because the two costs are not symmetric.

        A false negative is a missing mode on a lab that would have
        supported it; a false positive is a shipped shell that cannot work.
        The three positives are the two archived labs that implement the form
        and the fixture written to the contract by hand.
        """
        found = (
            "def main():\n    argv = sys.argv\n    print(argv[2])\n",
            "def main(argv):\n    rest = argv[1:]\n    print(rest[1])\n"
            "main(sys.argv)\n",
            "def address_mode(argv):\n    print(argv[1])\n"
            "address_mode(sys.argv[1:])\n",
            Path(sourcegen.__file__).parent.parent.joinpath(
                "tests", "fixtures", "operator_validator.py"
            ).read_text(encoding="utf-8"),
        )
        for source in found:
            with self.subTest(source=source[:40]):
                self.assertTrue(field._reads_a_second_positional(source))
        missing = (
            "def main():\n    print(sys.argv[1])\n",
            "def main(argv):\n    print(argv[0], argv[1])\nmain(sys.argv)\n",
            # A refusal is not an implementation, and a slice is as often one
            # as the other -- so a slice is never read as an implementation.
            "def main():\n    if sys.argv[2:]:\n        return 2\n",
            "def main():\n    print(sys.argv[1:])\n",
            # Not parseable here is not a reading of the text either.
            "def main(:\n",
        )
        for source in missing:
            with self.subTest(source=source[:40]):
                self.assertFalse(field._reads_a_second_positional(source))

    # --- the structure it may not disturb ---------------------------------

    def test_nothing_of_cvelabs_is_below_the_marker(self) -> None:
        for record in (None, {"shipped": False, "reason": "no"}, {}):
            with self.subTest(record=record):
                text = self.artifact({} if record is None else record)
                self.assertIn("--shell", text)
                self.assertEqual(
                    text.partition(field.POC_LAB_MODE_MARKER)[2], self.LAB
                )

    def test_no_argument_at_all_is_still_untouched(self) -> None:
        """The non-negotiable, with the prompt in the file."""
        with tempfile.TemporaryDirectory() as root:
            alone = Path(root) / "validator.py"
            alone.write_text(self.LAB, encoding="utf-8")
            merged = Path(root) / field.POC_NAME
            merged.write_text(self.artifact(), encoding="utf-8")
            for action in ("", "exploit"):
                with self.subTest(action=action):
                    environment = {"PATH": os.environ["PATH"]}
                    if action:
                        environment["CVELAB_MANUAL_ACTION"] = action
                    one = subprocess.run(
                        [sys.executable, str(merged)], capture_output=True,
                        text=True, timeout=60, env=environment,
                    )
                    two = subprocess.run(
                        [sys.executable, str(alone)], capture_output=True,
                        text=True, timeout=60, env=environment,
                    )
                    self.assertEqual(one.stdout, two.stdout)
                    self.assertEqual(one.returncode, two.returncode)

    def test_the_two_writers_still_agree_byte_for_byte(self) -> None:
        """The prompt is a pure function of the plan and the validator.

        Two modules write this artifact -- `field.write_manual_poc` from the
        record it has just proved, `deliverables.create_deliverables` from the
        record it reads back -- and the claim that the script CVELab proved is
        the one the operator receives rests on them agreeing. A mode that read
        a clock, an environment variable or the filesystem would break that.
        """
        spec = field.validate_spec(_spec())
        with tempfile.TemporaryDirectory() as root:
            lab_dir = Path(root) / "CVE-2026-0001"
            (lab_dir / "validator").mkdir(parents=True)
            (lab_dir / "validator" / "validator.py").write_text(
                self.LAB, encoding="utf-8"
            )
            (lab_dir / "report.json").write_text(
                json.dumps({"real_poc_verified": True}), encoding="utf-8"
            )
            field.write_manual_poc(
                "CVE-2026-0001", lab_dir, self.PLAN, spec, 8080,
                {"shipped": True, "proof_checks": {}, "runs": {},
                 "script": "ignored: write_manual_poc re-emits it"},
            )
            written = (lab_dir / "artifacts" / field.POC_NAME).read_text()
            rendered = field.emit_poc(
                "CVE-2026-0001", self.PLAN,
                (lab_dir / "validator" / "validator.py").read_text(),
                field.poc_record(lab_dir),
            )
        self.assertEqual(written, rendered)
        self.assertIn("--shell", written)


class TheSessionTests(unittest.TestCase):
    """`--reverse-shell`: a connect-back, and a session on the build.

    WHY IT IS NOT THE PROMPT BESIDE IT

    `--shell` is a pseudo-shell over the one-command form: one command per
    line, a new process per line, nothing held open, and a working directory
    the prompt itself remembers because there is nothing on the other end
    that can. This is the other thing. One connect-back command goes out
    through the same weakness, and what connects back is a shell of the
    build's own -- its own working directory, its own environment -- which
    this file then carries bytes for and does not interpret.

    WHAT DECIDES WHETHER THERE IS ONE

    The prompt's three conditions, read by `shell_standing` and not
    re-derived, plus three the owner set and one that is measured at
    generation time: an `END_TO_END_REPRODUCTION` lab, nothing named in
    `fidelity.simulated_components`, a `fidelity.vendor_product_started` of
    True, and a connect-back actually landed against this lab's own
    vulnerable build. The third of the owner's three is not a restatement of
    the second: an empty simulated-components list reads the same whether
    nothing was simulated or the plan said nothing at all, so the record
    saying the product started is the only one of them that attests the
    route. Measured across the archive, of
    the labs whose declared evidence is command execution EVERY one names
    something in `simulated_components` -- so zero labs qualify today, and
    that is the decision rather than an accident: a pseudo-shell on an
    adapter-routed lab is visibly the same thing as one echoed command, and a
    session prompt is the artifact most easily mistaken for real access.

    WHICH IS WHY THESE TESTS BUILD A LAB THAT QUALIFIES

    `QUALIFIES` below is a plan no archived lab matches, and `_Executing` is a
    product that really runs what it is sent. Without them the whole proof
    path -- listener, delivery, relay, exit status -- would never be executed
    anywhere, which is the defect this feature was written against.
    """

    CONTRACT = {
        "service_port": 8080,
        "evidence_type": "code_execution",
        "attack_summary": "GET /run?cmd= reaches a shell in the product itself",
    }
    #: The lab that passes. No archived lab does: this one is an end-to-end
    #: reproduction that names no simulated component and records the
    #: vendor's own product starting.
    QUALIFIES = {
        "cve": "CVE-2026-0001",
        "lab_type": "END_TO_END_REPRODUCTION",
        "scenario": "default",
        "repository": "https://example.invalid/p.git",
        "exploit_contract": CONTRACT,
        "fidelity": {"simulated_components": [], "vendor_product_started": True},
    }
    #: The lab every archived command-execution lab is: an adapter in front
    #: of the vendor's code. A candidate for the prompt and not for a session.
    ADAPTED = {
        **QUALIFIES,
        "lab_type": "SOURCE_REPRODUCTION",
        "fidelity": {
            "simulated_components": [
                "HTTP listener adapter/server.js: the project ships no server, so "
                "the adapter exposes the helper over GET /run",
            ],
        },
    }
    #: END_TO_END and an adapter named anyway: the one case that isolates
    #: the second of the two conditions this mode adds.
    ADAPTED_END_TO_END = {
        **QUALIFIES,
        "fidelity": {
            "simulated_components": [
                "HTTP listener adapter/server.js: the project ships no server, so "
                "the adapter exposes the helper over GET /run",
            ],
        },
    }
    LAB = ThePromptTests.LAB
    NO_COMMAND = ThePromptTests.NO_COMMAND

    def artifact(
        self,
        plan: dict | None = None,
        record: dict[str, Any] | None = None,
        validator: str | None = None,
    ) -> str:
        proved = {
            "shipped": True, "container_port": 8080,
            "spec": field.validate_spec(_spec()),
            "reverse_shell": {"shipped": True, "form": "bash-devtcp"},
        }
        return field.emit_poc(
            "CVE-2026-0001",
            self.QUALIFIES if plan is None else plan,
            self.LAB if validator is None else validator,
            proved if record is None else record,
        )

    @staticmethod
    def complained(done: subprocess.CompletedProcess) -> str:
        """stderr as one line, because the prose in it is wrapped to 78."""
        return " ".join(done.stderr.split())

    def ran(
        self, text: str, *argv: str, typed: str = "", name: str = field.POC_NAME
    ) -> subprocess.CompletedProcess:
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        path = Path(root.name) / name
        path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(path), *argv], input=typed,
            capture_output=True, text=True, timeout=300,
            env={"PATH": os.environ["PATH"]},
        )

    def session(
        self, address: str, *extra: str, typed: str = "", **kept: Any
    ) -> subprocess.CompletedProcess:
        return self.ran(
            self.artifact(**kept), "--lab-address", address, "--reverse-shell",
            "--allow-shell", "--callback-bind", "127.0.0.1:0",
            "--callback-wait", "6", *extra, typed=typed,
        )

    # --- the gate ---------------------------------------------------------

    def test_a_lab_whose_product_serves_its_own_route_qualifies(self) -> None:
        offered, reason = field._reverse_shell_candidate(self.QUALIFIES, self.LAB)
        self.assertTrue(offered, reason)
        self.assertEqual(reason, "")
        self.assertIn("--reverse-shell", self.artifact())

    def test_every_archived_command_execution_lab_fails_the_gate(self) -> None:
        """The measurement the mode ships dormant because of.

        Not a count: the archive can be read three ways and they disagree
        about how many labs there are. The universal survives all three --
        every lab whose declared evidence is command execution names
        something in `fidelity.simulated_components` -- and what is pinned
        here is that such a lab is refused, in the lab's own words.
        """
        offered, reason = field._reverse_shell_candidate(self.ADAPTED, self.LAB)
        self.assertFalse(offered)
        # The lab type is read first, and 88 of the archive's labs are that
        # one, so it is the sentence most artifacts will carry.
        self.assertIn("rather than an END_TO_END_REPRODUCTION", reason)
        # The adapter alone is enough as well, on a lab of the right type.
        offered, reason = field._reverse_shell_candidate(
            self.ADAPTED_END_TO_END, self.LAB
        )
        self.assertFalse(offered)
        self.assertIn("declares the route simulated", reason)
        self.assertIn("adapter/server.js", reason)

    def test_the_prompts_own_conditions_are_read_and_not_re_derived(self) -> None:
        """One detector for the one-command form, and one reason for it.

        A second reading of the validator would be a second thing to keep
        true; a second wording of the refusal would be two answers to one
        question.
        """
        for plan, validator in (
            ({k: v for k, v in self.QUALIFIES.items() if k != "exploit_contract"},
             self.LAB),
            ({**self.QUALIFIES,
              "exploit_contract": dict(self.CONTRACT, evidence_type="unauthorized_read")},
             self.LAB),
            (self.QUALIFIES, self.NO_COMMAND),
        ):
            with self.subTest(validator=validator[:30]):
                self.assertEqual(
                    field._reverse_shell_candidate(plan, validator),
                    field.shell_standing(plan, validator),
                )

    def test_the_standing_is_one_function_the_header_and_the_mode_both_read(
        self,
    ) -> None:
        """`poc_standing`'s discipline, for the third mode in the file.

        The code is in the file if and only if the header says it is, because
        the same call decides both -- so an artifact cannot offer a session
        its own first page denies, which is the failure mode two files had.
        """
        cases = (
            {"shipped": False, "reason": "no", "reverse_shell": {"shipped": True}},
            {"shipped": False, "reason": "no",
             "reverse_shell": {"shipped": False, "reason": "no connect-back landed"}},
            {"shipped": False, "reason": "no"},
        )
        for record in cases:
            with self.subTest(record=record):
                offered, _ = field.reverse_shell_standing(
                    self.QUALIFIES, self.LAB, record
                )
                text = self.artifact(record=record)
                header = text.split('"""')[1]
                lab = " ".join(
                    header[header.index("LAB MODE"):header.index("REMOTE MODE")].split()
                )
                self.assertEqual("--reverse-shell" in text, offered)
                self.assertEqual("A session, and not a prompt." in lab, offered)
                self.assertEqual(
                    "There is no connect-back in this file" in lab, not offered
                )

    def test_a_lab_that_proved_nothing_says_so_rather_than_going_quiet(self) -> None:
        offered, reason = field.reverse_shell_standing(self.QUALIFIES, self.LAB, {})
        self.assertFalse(offered)
        self.assertIn("was ever attempted", reason)
        header = self.artifact(record={"shipped": False, "reason": "no"}).split('"""')[1]
        lab = " ".join(
            header[header.index("LAB MODE"):header.index("REMOTE MODE")].split()
        )
        self.assertIn("was ever attempted", lab)

    def test_a_refusal_the_proof_recorded_is_quoted_in_the_header(self) -> None:
        record = {
            "shipped": False, "reason": "no",
            "reverse_shell": {
                "shipped": False,
                "reason": "no connect-back could be landed on this lab's own "
                          "vulnerable build",
            },
        }
        header = self.artifact(record=record).split('"""')[1]
        lab = " ".join(
            header[header.index("LAB MODE"):header.index("REMOTE MODE")].split()
        )
        self.assertIn("no connect-back could be landed", lab)

    def test_a_candidate_for_the_prompt_is_told_why_it_has_no_session(self) -> None:
        """Said once, in the lab's own terms, the way the prompt's absence is.

        That lab qualified for everything its contract states and has a
        prompt to show for it, so the one sentence about the mode it does not
        have belongs beside the one it does.
        """
        text = self.artifact(plan=self.ADAPTED)
        header = text.split('"""')[1]
        lab = " ".join(
            header[header.index("LAB MODE"):header.index("REMOTE MODE")].split()
        )
        self.assertIn("--shell --allow-shell", lab)
        self.assertIn("There is no connect-back in this file", lab)
        self.assertIn("adapter/server.js", lab)
        self.assertEqual(lab.count("There is no connect-back in this file"), 1)

    def test_the_reason_cannot_end_the_docstring_it_is_written_into(
        self,
    ) -> None:
        """The refusal paragraph carries model-written plan text.

        `reason` is built from `fidelity.simulated_components` and the lab
        type, both of which a model wrote, and it goes into the artifact's
        own docstring. The branch that OFFERS the mode passed its prose
        through `_quotable`; this one interpolated it raw. Three double
        quotes in a component name ended the docstring, `emit_poc`'s own
        `compile` guard then raised, and the lab got no deliverable at all
        -- which is the other half of the failure this mode is written
        against, not a lesser one. Measured: emission failed at line 70 for
        a plan that emitted cleanly at the commit before this mode.

        A trailing backslash as well: `_quotable` strips it for the same
        reason, and the test that does not exercise it is the test that lets
        the next one through.

        NOT covered here, deliberately: `lab_type` and `scenario` reach the
        header by a second route, `_poc_header`'s own `Lab           :`
        line, which interpolates both raw. That one breaks a lab the same
        way and predates this mode -- `212fb59` fails on it at line 14 --
        so it is not this test's to assert and not this diff's to cure.
        """
        shapes = {
            "a component name": {
                **self.QUALIFIES,
                "lab_type": "SOURCE_REPRODUCTION",
                "fidelity": {"simulated_components": ['adapter """ server.js']},
            },
            "a component name ending in a backslash": {
                **self.QUALIFIES,
                "lab_type": "SOURCE_REPRODUCTION",
                "fidelity": {"simulated_components": ["adapter server.js \\"]},
            },
            "several of them, one quoted": {
                **self.QUALIFIES,
                "lab_type": "SOURCE_REPRODUCTION",
                "fidelity": {"simulated_components": [
                    "adapter/server.js", 'shim """ one', "stub two",
                ]},
            },
        }
        for tag, plan in shapes.items():
            with self.subTest(tag=tag):
                # `emit_poc` compiles its own upper half, so this raising is
                # the failure and not the detection of it.
                text = self.artifact(plan=plan)
                compile(text, "PoC.py", "exec")
                header = text.split('"""')[1]
                self.assertIn("LAB MODE", header)
                self.assertIn("There is no connect-back in this file", header)

    def test_a_lab_with_no_prompt_is_not_told_twice(self) -> None:
        """The prompt's reason is this mode's reason, and saying it twice
        says nothing new."""
        text = self.artifact(validator=self.NO_COMMAND)
        header = text.split('"""')[1]
        lab = header[header.index("LAB MODE"):header.index("REMOTE MODE")]
        self.assertIn("There is no prompt in this file", lab)
        self.assertNotIn("There is no connect-back in this file", lab)

    # --- absent when it does not apply ------------------------------------

    def test_a_lab_that_does_not_qualify_carries_no_trace_of_the_flag(self) -> None:
        """The precedent `--lab-address` and `--shell` set.

        A flag named in a file that does not implement it is the flag an
        operator types next, and for this mode what they would be typing is a
        request for a session on something that was never checked.
        """
        for label, kept in (
            ("adapter named", {"plan": self.ADAPTED}),
            ("source lab", {"plan": {**self.QUALIFIES, "lab_type": "SOURCE_REPRODUCTION"}}),
            ("no command form", {"validator": self.NO_COMMAND}),
            ("no port", {"plan": {
                k: v for k, v in self.QUALIFIES.items() if k != "exploit_contract"
            }}),
            ("nothing proved", {"record": {"shipped": False, "reason": "no"}}),
        ):
            with self.subTest(label=label):
                text = self.artifact(**kept)
                for absent in (
                    "--reverse-shell", "_reverse_given", "_reverse_mode",
                    "REVERSE_FORMS", "/dev/tcp", "pty.spawn", "mkfifo",
                ):
                    self.assertNotIn(absent, text, absent)
                # The words may be there -- a lab that is a candidate for the
                # prompt is told in one sentence why it has no session -- and
                # the flag and the code may not.
                self.assertNotIn("--reverse-shell", text)

    def test_the_callback_flags_are_remote_modes_and_are_not_this_modes(self) -> None:
        """Reused spellings, not new ones, which is why they are not on the
        list above.

        `--callback-bind` and `--callback` exist in remote mode for exactly
        the case this mode has -- a listener the target has to be told how to
        reach -- so this mode takes those words and their meaning rather than
        inventing a pair. They are therefore in any artifact whose remote
        mode shipped, with or without a session, and their presence says
        nothing about this mode.
        """
        with_remote = self.artifact(plan=self.ADAPTED)
        self.assertNotIn("--reverse-shell", with_remote)
        for reused in ("--callback-bind", "--callback-wait"):
            with self.subTest(reused=reused):
                self.assertIn(reused, with_remote)
        # And where remote mode was refused as well, they come in with this
        # mode and go out with it.
        refused = {"shipped": False, "reason": "nothing was proved"}
        self.assertNotIn("--callback-bind", self.artifact(record=refused))
        self.assertIn(
            "--callback-bind",
            self.artifact(record=dict(refused, reverse_shell={"shipped": True})),
        )

    def test_a_lab_that_recorded_nothing_is_refused_and_not_described(
        self,
    ) -> None:
        """An empty `simulated_components` is ambiguous, so it refuses.

        It can mean nothing was simulated, which is the best case, or that
        the lab said nothing. `vendor_product_started` is what tells them
        apart, and for the one mode whose entire justification is that no
        adapter CVELab's model wrote is in the path, the ambiguous reading is
        not good enough: silence is not an attestation of fidelity. So the
        record saying the product started is part of the gate rather than a
        sentence in the banner -- which also retires the banner's old claim
        that it already was.
        """
        quiet = {
            **self.QUALIFIES,
            "fidelity": {"simulated_components": []},
        }
        offered, reason = field._reverse_shell_candidate(quiet, self.LAB)
        self.assertFalse(offered)
        self.assertIn(
            "does not record whether the vendor's own product started", reason
        )
        self.assertIn("An empty simulated-components list says nothing", reason)
        # No flag and no code in a file that does not have the mode.
        text = self.artifact(plan=quiet)
        self.assertNotIn("--reverse-shell", text)
        self.assertNotIn("_reverse_mode", text)
        # The banner's own reading of each shape, which is the other half:
        # the sentence has to match what the plan says, including when the
        # plan says no.
        said = " ".join(field._reverse_where_you_are(quiet).split())
        self.assertIn(
            "does not record whether the vendor's own product started", said
        )
        self.assertNotIn("what answers is the product's own route", said)
        recorded = " ".join(field._reverse_where_you_are(self.QUALIFIES).split())
        self.assertIn("records the vendor's own product starting", recorded)
        self.assertIn("the two conditions on the record", recorded)
        self.assertNotIn("not recorded", recorded)
        # Either way, what it is not is said.
        for version in (said, recorded):
            with self.subTest(version=version[:40]):
                self.assertIn("real interactive access", version)
                self.assertIn("not evidence about any host but this one", version)

    def test_an_explicit_false_is_read_as_a_recorded_false(self) -> None:
        """The majority value in the archive, and the opposite of a silence.

        30 of the 34 archived labs whose declared evidence is command
        execution carry `vendor_product_started: False`. The banner used to
        tell every one of them that the lab "does not record the vendor's own
        product starting either -- read that as not recorded", which is not
        what an explicit False is and records the opposite of it.
        """
        denied = {
            **self.QUALIFIES,
            "fidelity": {"simulated_components": [], "vendor_product_started": False},
        }
        offered, reason = field._reverse_shell_candidate(denied, self.LAB)
        self.assertFalse(offered)
        self.assertIn(
            "records the vendor's own product as not having started", reason
        )
        said = " ".join(field._reverse_where_you_are(denied).split())
        self.assertIn("records the vendor's own product as NOT having started", said)
        self.assertIn("a recorded answer and not a silence", said)
        self.assertNotIn("Read that as not recorded", said)

    def test_a_record_that_cannot_be_read_refuses_and_is_never_iterated(
        self,
    ) -> None:
        """Silence and malformation both refuse, and neither is paraphrased.

        `isinstance(fidelity, dict) else {}` and a truthiness test on
        `simulated_components` passed an absent record, a `fidelity` that was
        a string or a list, a `simulated_components` that was None, and -- the
        one that reached the shipped header -- a `simulated_components` that
        was a string, iterated character by character into the prose as
        `"a"; "n"; "H"; "T"; "T"; "P"; ...`.
        """
        shapes = {
            "absent": {k: v for k, v in self.QUALIFIES.items() if k != "fidelity"},
            "null": {**self.QUALIFIES, "fidelity": None},
            "a string": {**self.QUALIFIES, "fidelity": "none"},
            "a list": {**self.QUALIFIES, "fidelity": []},
            "sim null": {**self.QUALIFIES, "fidelity": {"simulated_components": None}},
            "sim a string": {
                **self.QUALIFIES,
                "fidelity": {"simulated_components": "an HTTP adapter stands in"},
            },
            "sim a dict": {
                **self.QUALIFIES,
                "fidelity": {"simulated_components": {"a": "b"}},
            },
            "sim carries a null": {
                **self.QUALIFIES,
                "fidelity": {"simulated_components": [None]},
            },
        }
        for name, plan in shapes.items():
            with self.subTest(shape=name):
                offered, reason = field._reverse_shell_candidate(plan, self.LAB)
                self.assertFalse(offered)
                # Not one character of a non-list quoted as a component, and
                # not the sentence that says the record names nothing.
                self.assertNotIn('"a"; "n"', reason)
                self.assertNotIn('"None"', reason)
                self.assertNotIn("names no simulated component", reason)
                text = self.artifact(plan=plan)
                self.assertNotIn("--reverse-shell", text)
                self.assertNotIn('"a"; "n"', text)
                # And the header says why, in the lab's terms, without
                # naming a flag the file does not have.
                self.assertIn("There is no connect-back in this file", text)
                said = " ".join(field._reverse_where_you_are(plan).split())
                self.assertNotIn('"a"; "n"', said)

    def test_the_flag_is_unrecognised_on_a_lab_that_does_not_qualify(self) -> None:
        done = self.ran(
            self.artifact(plan=self.ADAPTED), "--lab-address", "127.0.0.1:32768",
            "--reverse-shell", "--allow-shell", "--callback-bind", "127.0.0.1:0",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")

    # --- the header and the help ------------------------------------------

    def test_the_header_names_the_form_that_landed_and_calls_it_a_measurement(
        self,
    ) -> None:
        """Which form works is a fact about the image, so the name recorded
        is the measurement and not the mode's setting.

        The mode tries every form in the same order whatever the record
        says, which is what keeps the code the connect-back was proved from
        and the code shipped the same bytes -- so the record can be read in
        the header without the artifact's behaviour depending on it.
        """
        header = self.artifact().split('"""')[1]
        lab = " ".join(
            header[header.index("LAB MODE"):header.index("REMOTE MODE")].split()
        )
        self.assertIn("by the bash-devtcp connect-back", lab)
        self.assertIn("not a constant anyone should trust", lab)
        # Proved with no form named -- which is what the proof emits before
        # it has an answer: the sentence goes and the mode stays.
        named = {"shipped": False, "reason": "no",
                 "reverse_shell": {"shipped": True, "form": "perl"}}
        unnamed = {"shipped": False, "reason": "no",
                   "reverse_shell": {"shipped": True}}
        quiet = " ".join(self.artifact(record=unnamed).split('"""')[1].split())
        self.assertIn("A session, and not a prompt.", quiet)
        self.assertNotIn("connect-back. Which form works", quiet)
        # And the code is the same code either way, which is exactly what
        # lets the proof run the file it is about to ship.
        self.assertEqual(
            self.artifact(record=named).partition("REVERSE_FORMS = ")[2],
            self.artifact(record=unnamed).partition("REVERSE_FORMS = ")[2],
        )
        self.assertIn(
            "by the perl connect-back",
            " ".join(self.artifact(record=named).split()),
        )

    def test_the_header_and_the_help_both_offer_it(self) -> None:
        header = self.artifact().split('"""')[1]
        lab = header[header.index("LAB MODE"):header.index("REMOTE MODE")]
        self.assertIn("--reverse-shell --allow-shell --callback-bind", lab)
        said = " ".join(self.ran(self.artifact(), "--help").stdout.split())
        self.assertIn("--lab-address ADDRESS --reverse-shell --allow-shell", said)
        self.assertIn("--callback-bind is required and not defaulted", said)
        # All three of this mode's valued flags are named where the other
        # two are: a recognised flag that --help does not mention is a flag
        # only a reader of the source finds.
        for flag in field.REVERSE_VALUED_FLAGS:
            with self.subTest(flag=flag):
                self.assertIn(flag, said)
        self.assertIn("--callback-wait SECONDS", said)
        self.assertIn("15 seconds by default", said)

    def test_the_header_says_what_it_is_and_what_it_is_not(self) -> None:
        header = self.artifact().split('"""')[1]
        lab = " ".join(
            header[header.index("LAB MODE"):header.index("REMOTE MODE")].split()
        )
        for sentence in (
            "real interactive access",
            "a Docker container CVELab built",
            "you started on this machine",
            "not a client's instance",
            "not production",
            "not evidence about any host but this one",
        ):
            with self.subTest(sentence=sentence):
                self.assertIn(sentence, lab.replace("It is not", "not"))

    def test_the_banner_is_up_before_the_connect_back_is_sent(self) -> None:
        """The sentences are a reason to stop, and after the delivery there
        is a shell on the build whether they were read or not."""
        done = self.session("127.0.0.1:1", typed="")
        said = self.complained(done)
        self.assertIn("WHAT THIS IS, AND WHAT IT IS NOT", said)
        self.assertLess(
            said.index("real interactive access"),
            said.index("[sending the bash-devtcp connect-back]"),
        )
        self.assertLess(
            said.index("not evidence about any host but this one"),
            said.index("[sending the bash-devtcp connect-back]"),
        )

    def test_it_names_the_file_it_was_run_as(self) -> None:
        for name in (field.POC_NAME, "validator.py"):
            with self.subTest(name=name):
                done = self.ran(
                    self.artifact(), "--lab-address", "127.0.0.1:32768",
                    "--reverse-shell", "--allow-shell", "--callback-bind",
                    "127.0.0.1:0", "--callback-wait", "1", name=name,
                )
                self.assertIn(f"{name} --lab-address 127.0.0.1:32768", done.stderr)

    # --- every refusal ----------------------------------------------------

    def test_it_is_refused_without_the_flag_that_asks_for_it(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--reverse-shell",
            "--callback-bind", "127.0.0.1:0",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("Re-run with --allow-shell", self.complained(done))
        self.assertIn("a session on the target", self.complained(done))

    def test_the_bind_is_required_and_not_defaulted(self) -> None:
        """127.0.0.1:0 is the default everywhere else in this file and a
        container cannot reach it, and on any other host the address the
        target can reach is known only to the operator."""
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--reverse-shell",
            "--allow-shell",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("needs --callback-bind HOST:PORT", self.complained(done))
        self.assertIn("cannot reach that", self.complained(done))
        self.assertNotIn("[sending", done.stderr)

    def test_a_bind_that_is_not_an_address_and_a_port(self) -> None:
        for bad in ("nonsense", "127.0.0.1:not-a-port", ":4444", "127.0.0.1:99999"):
            with self.subTest(bad=bad):
                done = self.ran(
                    self.artifact(), "--lab-address", "127.0.0.1:32768",
                    "--reverse-shell", "--allow-shell", "--callback-bind", bad,
                )
                self.assertEqual(done.returncode, 2)
                self.assertIn(
                    "--callback-bind takes an address", self.complained(done)
                )

    def test_a_wildcard_bind_is_not_an_address_the_build_can_be_told(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--reverse-shell",
            "--allow-shell", "--callback-bind", "0.0.0.0:0",
        )
        self.assertEqual(done.returncode, 2)
        self.assertIn("bound to every interface", self.complained(done))
        self.assertNotIn("[sending", done.stderr)

    def test_an_ipv6_listener_is_refused_by_name_and_not_half_supported(self) -> None:
        """Every form this mode sends is IPv4, so an IPv6 listener listens
        where nothing it sends can be told to reach.

        Measured rather than assumed: Python's `socket.socket()` is AF_INET
        unless told otherwise, Perl's `inet_aton` has no IPv6 at all, and
        `socketserver.ThreadingTCPServer` -- the class `Collector` beside this
        one is built on -- is AF_INET too. Bound anyway, the four deliveries
        would land nothing and the operator would be told the image was
        missing programs it has.
        """
        for argv in (
            ("--callback-bind", "[::1]:4444"),
            ("--callback-bind", "127.0.0.1:0", "--callback", "[2001:db8::1]:4444"),
        ):
            with self.subTest(argv=argv):
                done = self.ran(
                    self.artifact(), "--lab-address", "127.0.0.1:32768",
                    "--reverse-shell", "--allow-shell", *argv,
                )
                self.assertEqual(done.returncode, 2)
                self.assertEqual(done.stdout, "")
                self.assertIn("IPv4", self.complained(done))
                self.assertNotIn("[sending", done.stderr)

    def test_it_refuses_a_command_on_the_command_line(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--reverse-shell",
            "--allow-shell", "--callback-bind", "127.0.0.1:0", "id",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("different jobs", self.complained(done))
        self.assertIn("--lab-address ADDRESS COMMAND", self.complained(done))

    def test_it_refuses_to_be_mixed_with_remote_mode(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--reverse-shell",
            "--allow-shell", "--callback-bind", "127.0.0.1:0",
            "--input", "target_path=/theirs",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("--input belongs to remote", self.complained(done))

    def test_it_refuses_to_be_mixed_with_the_prompt(self) -> None:
        """Two modes in one run, and both of them do something to the build.

        `_POC_OWN_MODES` puts the session first for exactly this: dispatched
        the other way round, naming both flags would have quietly opened the
        smaller of the two.
        """
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--shell",
            "--reverse-shell", "--allow-shell", "--callback-bind", "127.0.0.1:0",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("two modes and this run names both", self.complained(done))
        self.assertNotIn("[sending", done.stderr)

    def test_it_cannot_be_used_without_an_address(self) -> None:
        done = self.ran(
            self.artifact(), "--reverse-shell", "--allow-shell",
            "--callback-bind", "127.0.0.1:0",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("not optional", done.stderr)

    def test_an_address_this_lab_cannot_have_published_is_refused(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "10.0.0.5:8080", "--reverse-shell",
            "--allow-shell", "--callback-bind", "127.0.0.1:0",
        )
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("not an address this lab published", done.stderr)

    def test_a_flag_given_twice_is_refused_rather_than_resolved(self) -> None:
        """`_lab_address`'s correction, applied here from the start.

        Read anywhere with the last one winning, a second spelling of the
        address flag overwrote the first and left the lab program with no
        command -- which it answers by running its own canary and printing
        REPRODUCED at exit 0. The flags here are not that flag, but the shape
        is the shape, and a listener nothing arrives at is the same kind of
        silent wrong answer.
        """
        for flag, first, second in (
            ("--callback-bind", "127.0.0.1:0", "1.2.3.4:5"),
            ("--callback", "127.0.0.1:1", "1.2.3.4:5"),
            ("--callback-wait", "1", "2"),
        ):
            with self.subTest(flag=flag):
                done = self.ran(
                    self.artifact(), "--lab-address", "127.0.0.1:32768",
                    "--reverse-shell", "--allow-shell", "--callback-bind",
                    "127.0.0.1:0", flag, first, flag, second,
                )
                self.assertEqual(done.returncode, 2)
                self.assertIn(f"{flag} was given twice", done.stderr)
                self.assertNotIn("[sending", done.stderr)

    def test_a_switch_given_twice_is_unambiguous_and_is_not_refused(self) -> None:
        """Which is what the docstring beside the refusal now says.

        It claimed "a second spelling of any flag here is ambiguous and
        refused rather than resolved", and a repeated switch was never
        refused -- correctly: `--allow-shell --allow-shell` asks for one
        thing twice and there is no second reading to choose between. The
        refusal next door is for the flags that carry a value, where the two
        spellings say different things. The behaviour is the right one and
        the sentence was the wrong one, so the sentence changed.
        """
        for argv in (
            ("--reverse-shell", "--reverse-shell", "--allow-shell"),
            ("--reverse-shell", "--allow-shell", "--allow-shell"),
        ):
            with self.subTest(argv=argv):
                done = self.ran(
                    self.artifact(), "--lab-address", "127.0.0.1:1", *argv,
                    "--callback-bind", "127.0.0.1:0", "--callback-wait", "1",
                )
                # It ran the mode: delivered, nothing came back, exit 1.
                self.assertEqual(done.returncode, 1, done.stderr)
                self.assertIn("[sending the bash-devtcp connect-back]", done.stderr)
                self.assertNotIn("was given twice", done.stderr)

    def test_a_switch_written_with_a_value_is_the_switch_and_is_refused(self) -> None:
        """The inconsistency this file had with itself, closed on this path.

        `--shell=yes` is not recognised as the flag and is delivered to the
        lab as a command, while `--lab-address=` IS recognised -- so the file
        disagrees with itself about its own spelling. Here both spellings are
        the flag, and the one carrying a value is refused rather than read as
        agreement: `--allow-shell=no` spells out a decision that reading the
        flag alone would have counted as its opposite.
        """
        for argv in (
            ("--reverse-shell=yes",),
            ("--reverse-shell", "--allow-shell=no"),
            ("--reverse-shell", "--allow-shell=yes"),
        ):
            with self.subTest(argv=argv):
                done = self.ran(
                    self.artifact(), "--lab-address", "127.0.0.1:32768", *argv,
                    "--callback-bind", "127.0.0.1:0",
                )
                self.assertEqual(done.returncode, 2)
                self.assertEqual(done.stdout, "")
                self.assertIn(
                    "is a switch and takes no value", self.complained(done)
                )
                self.assertNotIn("[sending", done.stderr)

    def test_a_valued_flag_with_no_value_is_refused(self) -> None:
        done = self.ran(
            self.artifact(), "--lab-address", "127.0.0.1:32768", "--reverse-shell",
            "--allow-shell", "--callback-bind",
        )
        self.assertEqual(done.returncode, 2)
        said = self.complained(done)
        self.assertIn("--callback-bind did not get a value it will read", said)
        self.assertIn("Either nothing followed it", " ".join(said.split()))

    def test_a_valued_flag_given_a_flag_shaped_value_says_which_it_was(
        self,
    ) -> None:
        """The refusal named one case and covered two.

        `--callback-wait -3` was refused as "takes a value and was given
        none" for a run that gave it a value. The behaviour is right -- a
        word beginning with `-` is a flag, and reading one as a value is the
        shape `41bfccb` took out of the address flag -- and only the sentence
        was wrong.
        """
        for argv in (
            ["--callback-wait", "-3"], ["--callback-wait=-3"],
            ["--callback", "--allow-shell"],
        ):
            with self.subTest(argv=argv):
                done = self.ran(
                    self.artifact(), "--lab-address", "127.0.0.1:32768",
                    "--reverse-shell", "--allow-shell",
                    "--callback-bind", "127.0.0.1:0", *argv,
                )
                self.assertEqual(done.returncode, 2)
                said = " ".join(self.complained(done).split())
                self.assertIn("did not get a value it will read", said)
                self.assertIn("begins with a `-` and is read as another flag", said)
                self.assertIn("A negative number is refused by that same rule", said)
                self.assertNotIn("was given none", said)
                self.assertNotIn("[sending", done.stderr)

    # --- the result that is not a refusal ---------------------------------

    def test_nothing_connecting_back_is_a_result_and_exits_one(self) -> None:
        """Against a lab program whose build is not there at all.

        1 and not 2, because this file did not refuse: the forms were
        delivered and nothing came back. And not 0 -- a session that never
        happened must never exit 0, which is the contract's own rule about a
        path that did nothing.
        """
        done = self.session("127.0.0.1:1")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(done.stdout, "")
        for name, _ in field.REVERSE_FORMS:
            with self.subTest(name=name):
                self.assertIn(f"[sending the {name} connect-back]", done.stderr)
                # The name, and beside it which of the two things happened:
                # the lab program refusing the delivery is not the image
                # having nothing to run.
                self.assertIn(f"  {name}: ", done.stderr)
        self.assertRegex(
            self.complained(done),
            "Nothing connected back|Not one of these connect-backs was delivered",
        )

    def test_a_delivery_the_lab_program_refused_is_not_blamed_on_the_image(
        self,
    ) -> None:
        """The two reasons a form lands nothing, told apart.

        `_reverse_said` read the delivery's output and nobody read its exit
        status, so a lab program that refused every delivery -- a second
        positional it will not take, a target it will not accept, BLOCKED --
        was reported to the operator as this build's image having neither
        bash nor perl nor nc. Measured against a real one: the product's log
        was empty, not one command reached it, and every per-form line was
        the lab program's own usage text under a headline blaming the image.

        The prompt beside this one already draws the line, in `_shell_said`:
        "the command did not run: the lab program exited %d".
        """
        # A lower half that refuses every delivery and says so on stdout,
        # which is exactly the shape the measurement found.
        refusing = (
            "import os, sys\n"
            "def main(argv):\n"
            "    rest = argv[1:]\n"
            "    if len(rest) > 1:\n"
            "        print('usage: %s [<host>:<port>]'\n"
            "              % os.path.basename(argv[0]), file=sys.stderr)\n"
            "        return 2\n"
            "    print('REPRODUCED')\n"
            "    return 0\n"
            "if __name__ == '__main__':\n"
            "    sys.exit(main(sys.argv))\n"
        )
        done = self.ran(
            self.artifact(validator=self.LAB).partition(field.POC_LAB_MODE_MARKER)[0]
            + field.POC_LAB_MODE_MARKER + refusing,
            "--lab-address", "127.0.0.1:1", "--reverse-shell", "--allow-shell",
            "--callback-bind", "127.0.0.1:0", "--callback-wait", "2",
        )
        self.assertEqual(done.returncode, 1)
        said = self.complained(done)
        self.assertIn("Not one of these connect-backs was delivered", said)
        self.assertIn("no command got that far", said)
        # And not the sentence that makes it the image's fault.
        self.assertNotIn("a busybox image has no bash", said)
        for name, _ in field.REVERSE_FORMS:
            with self.subTest(name=name):
                self.assertIn(f"{name}: NOT delivered: the lab program exited 2",
                              " ".join(done.stderr.split()))

    # --- the forms --------------------------------------------------------

    def test_each_form_carries_all_three_substitutions_and_is_one_command(
        self,
    ) -> None:
        for name, form in field.REVERSE_FORMS:
            with self.subTest(name=name):
                self.assertIn("@HOST@", form)
                self.assertIn("@PORT@", form)
                # The third, and the one a landing is attributed on. A form
                # that cannot carry it would have to be dropped or landed
                # unattributed, so every form carrying it is the condition
                # the attribution rests on.
                self.assertIn("@NONCE@", form)
                self.assertNotIn("\n", form)
        self.assertEqual(
            [name for name, _ in field.REVERSE_FORMS],
            ["bash-devtcp", "python3-pty", "perl", "nc-fifo"],
        )

    def test_the_nonce_is_generated_by_the_emitted_code_and_never_emitted(
        self,
    ) -> None:
        """The purity constraint, which is what makes the nonce possible.

        The generation-time proof emits the artifact with a provisional
        outcome, runs THAT text's session mode, and then emits again from the
        outcome it recorded. The two texts have to differ in the header only,
        so the session's own code cannot depend on anything the proof
        produced -- and a nonce is exactly such a thing unless it is made at
        run time, inside the artifact, per delivery. A baked-in nonce would
        also be one that every holder of the file knows for every run of it.
        """
        text = self.artifact()
        block = text.partition("def _reverse_given")[2].partition(
            field.POC_LAB_MODE_MARKER
        )[0]
        self.assertIn("secrets.token_hex(REVERSE_NONCE_BYTES)", block)
        self.assertRegex(text, re.compile(r"^import .*\bsecrets\b", re.MULTILINE))
        # The placeholder reaches the file as the placeholder, and no
        # 32-character hex constant is emitted anywhere in it.
        self.assertIn("@NONCE@", block)
        self.assertIsNone(re.search(r"\b[0-9a-f]{32}\b", text))
        # Two emissions of the same inputs are the same bytes, and an
        # outcome carrying a form name changes the header and nothing else.
        self.assertEqual(text, self.artifact())

    def test_the_forms_reach_the_artifact_as_the_forms(self) -> None:
        text = self.artifact()
        for name, form in field.REVERSE_FORMS:
            with self.subTest(name=name):
                self.assertIn(json.dumps(name), text)
                self.assertIn(json.dumps(form), text)

    def test_the_connect_back_goes_through_the_one_command_form(self) -> None:
        """The one line in this mode that cannot be written another way.

        `_poc_entry` hands a bare argv[1] to remote mode's `main()`, which is
        a different program drafted against a different spec, so the flag is
        not optional here either.
        """
        self.assertIn(
            '[sys.executable, __file__, "--lab-address", address, command]',
            self.artifact(),
        )

    # --- the structure it may not disturb ---------------------------------

    def test_nothing_of_cvelabs_is_below_the_marker(self) -> None:
        for record in (
            {"shipped": False, "reason": "no", "reverse_shell": {"shipped": True}},
            {"shipped": False, "reason": "no"},
            {},
        ):
            with self.subTest(record=record):
                text = self.artifact(record=record)
                self.assertEqual(
                    text.partition(field.POC_LAB_MODE_MARKER)[2], self.LAB
                )

    def test_no_argument_at_all_is_still_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            alone = Path(root) / "validator.py"
            alone.write_text(self.LAB, encoding="utf-8")
            merged = Path(root) / field.POC_NAME
            merged.write_text(self.artifact(), encoding="utf-8")
            self.assertIn("_reverse_given(sys.argv)", merged.read_text())
            for action in ("", "exploit"):
                with self.subTest(action=action):
                    environment = {"PATH": os.environ["PATH"]}
                    if action:
                        environment["CVELAB_MANUAL_ACTION"] = action
                    one = subprocess.run(
                        [sys.executable, str(merged)], capture_output=True,
                        text=True, timeout=60, env=environment,
                    )
                    two = subprocess.run(
                        [sys.executable, str(alone)], capture_output=True,
                        text=True, timeout=60, env=environment,
                    )
                    self.assertEqual(one.stdout, two.stdout)
                    self.assertEqual(one.returncode, two.returncode)

    def test_the_two_writers_still_agree_byte_for_byte(self) -> None:
        """The session is a pure function of the plan, the validator and the
        record, with no clock, no environment and no filesystem in it."""
        spec = field.validate_spec(_spec())
        with tempfile.TemporaryDirectory() as root:
            lab_dir = Path(root) / "CVE-2026-0001"
            (lab_dir / "validator").mkdir(parents=True)
            (lab_dir / "validator" / "validator.py").write_text(
                self.LAB, encoding="utf-8"
            )
            (lab_dir / "report.json").write_text(
                json.dumps({"real_poc_verified": True}), encoding="utf-8"
            )
            field.write_manual_poc(
                "CVE-2026-0001", lab_dir, self.QUALIFIES, spec, 8080,
                {"shipped": True, "proof_checks": {}, "runs": {},
                 "reverse_shell": {"shipped": True, "form": "bash-devtcp"},
                 "script": "ignored: write_manual_poc re-emits it"},
            )
            written = (lab_dir / "artifacts" / field.POC_NAME).read_text()
            rendered = field.emit_poc(
                "CVE-2026-0001", self.QUALIFIES,
                (lab_dir / "validator" / "validator.py").read_text(),
                field.poc_record(lab_dir),
            )
        self.assertEqual(written, rendered)
        self.assertIn("--reverse-shell", written)


class TheSessionIsProvedAtGenerationTimeTests(unittest.TestCase):
    """Proved before it is written into the artifact, or refused with a reason.

    The discipline the rest of this file already holds: remote mode is run
    against both of the lab's own builds and recorded as
    `manual_poc_field.shipped` with `reason` and `proof_checks` beside it, and
    a mode that could not be proved is not shipped looking available. The
    session goes through the same gate on the same record, under
    `manual_poc_field.reverse_shell`.

    What makes it cheap is the arrangement `_run_field_script` already uses:
    the sidecar joins the build's network namespace, so the sidecar's
    loopback IS the product's loopback. A connect-back is proved with no
    route from this host, no published port and nothing on the
    `cvelab-manual` network -- which is also why `--callback-bind
    127.0.0.1:0` is the right explicit answer there and refused as a default
    everywhere else.
    """

    CONTRACT = TheSessionTests.CONTRACT
    QUALIFIES = TheSessionTests.QUALIFIES
    ADAPTED = TheSessionTests.ADAPTED
    LAB = TheSessionTests.LAB

    #: The pair `_proof` pins for the duration of a test. The real one is
    #: drawn per run and is deliberately unknowable in advance, which is the
    #: property; a test still has to be able to write the stream, so it
    #: fixes the draw rather than guessing it.
    CHALLENGE = ("echo CVELAB-SHELL-$((11*13))\nid\nexit\n", "CVELAB-SHELL-143")

    @staticmethod
    def _answered(exit_code: int = 0) -> str:
        """A stdout that satisfies the proof, in the order it requires.

        The mark first and the answer after it, which is what the check
        reads. Written through a helper rather than spelled out in each
        test, so that a change to either token cannot leave a test asserting
        against a stream no real run produces.
        """
        return (
            TheSessionIsProvedAtGenerationTimeTests.CHALLENGE[1] + "\n"
            "uid=0(root) gid=0(root)\n"
            f"CVELAB_REVERSE_EXIT={exit_code}\n"
        )

    def _proof(self, stdout: str, stderr: str) -> dict[str, Any]:
        done = subprocess.CompletedProcess(["docker"], 0, stdout, stderr)
        with mock.patch.object(
            field, "_reverse_proof_challenge", return_value=self.CHALLENGE
        ), mock.patch.object(field.subprocess, "run", return_value=done) as asked:
            outcome = field._run_reverse_shell_proof(
                "cid-v", 8080, "SCRIPT", "python:3.13-alpine", "127.0.0.1"
            )
        self.sent = asked.call_args.args[0]
        return outcome

    def test_a_landed_connect_back_that_answered_is_proved(self) -> None:
        outcome = self._proof(
            self.CHALLENGE[1] + "\n"
            "uid=10001(app) gid=10001(app)\nCVELAB_REVERSE_EXIT=0\n",
            "[sending the bash-devtcp connect-back]\n"
            "[connect-back landed: bash-devtcp, from 127.0.0.1]\n",
        )
        self.assertIs(outcome["shipped"], True)
        self.assertEqual(outcome["form"], "bash-devtcp")
        self.assertIs(outcome["proof_checks"]["reverse_shell_proven"], True)
        self.assertEqual(outcome["mode_exit_code"], 0)
        self.assertNotIn("reason", outcome)

    def test_it_runs_in_the_builds_own_network_namespace(self) -> None:
        self._proof("", "")
        self.assertIn("--network", self.sent)
        self.assertEqual(self.sent[self.sent.index("--network") + 1], "container:cid-v")
        said = " ".join(self.sent)
        self.assertIn("--reverse-shell", said)
        self.assertIn("--allow-shell", said)
        self.assertIn("127.0.0.1:0", said)

    def test_a_connect_back_that_carried_nothing_is_not_a_session(self) -> None:
        """A socket is not a shell. A channel that cannot be shown to carry
        one command is not worth offering as one."""
        outcome = self._proof(
            "CVELAB_REVERSE_EXIT=0\n",
            "[sending the nc-fifo connect-back]\n"
            "[connect-back landed: nc-fifo, from 127.0.0.1]\n",
        )
        self.assertIs(outcome["shipped"], False)
        self.assertIs(outcome["proof_checks"]["a_connect_back_arrived"], True)
        self.assertIs(outcome["proof_checks"]["the_build_answered_through_it"], False)
        self.assertIn("nothing came back through it", outcome["reason"])

    def test_nothing_landing_is_recorded_with_what_was_tried(self) -> None:
        outcome = self._proof(
            "CVELAB_REVERSE_EXIT=1\n", "Nothing connected back.\nbash: not found\n"
        )
        self.assertIs(outcome["shipped"], False)
        self.assertEqual(outcome["form"], "")
        self.assertIn("no connect-back could be landed", outcome["reason"])
        for name, _ in field.REVERSE_FORMS:
            with self.subTest(name=name):
                self.assertIn(name, outcome["reason"])
        # And the run that refused it, because a reason alone cannot be acted
        # on: "bash: not found" is what says which form to add.
        self.assertIn("bash: not found", outcome["output"])

    def test_what_is_typed_cannot_be_answered_by_echoing_it(self) -> None:
        """Why the typed lines are what they are, and not a plain marker.

        A connect-back that spawns a pty echoes what is written to it, so a
        marker typed in comes back whether or not anything ran it -- which
        is why the check was `id` and `uid=` to begin with. But `uid=`
        anywhere on the stream was too weak in the other direction: `head`,
        the bytes arriving in the same read as the nonce, is written to
        stdout before a byte has been typed, so a connect-back that
        presented a nonce and immediately said `uid=0(root)` satisfied it
        with nothing behind it. And the nonce travels inside the delivered
        command, so the lab's own product sees it: a product that parsed
        commands rather than running them could have forged the whole check.

        `$((6*7))` is the answer to both. Echoing the line produces the
        line, which does not contain the mark; only arithmetic expansion
        produces it. These assertions are that property, not its spelling:
        the mark must not be derivable from the text that asks for it.
        """
        typed, mark = field._reverse_proof_challenge()
        self.assertIn("$((", typed)
        self.assertEqual(field._REVERSE_PROOF_ANSWER, "uid=")
        # An echo of the typed text carries neither token, which is the half
        # about evaluation.
        self.assertNotIn(mark, typed)
        self.assertNotIn(field._REVERSE_PROOF_ANSWER, typed)
        # And the half about ordering: the pair is drawn per run, so nothing
        # can carry the mark before the typed text has crossed the socket.
        # A fixed pair made `head` -- written to stdout before a byte is
        # typed -- able to satisfy the whole check on its own.
        draws = {field._reverse_proof_challenge() for _ in range(20)}
        self.assertGreater(len(draws), 1)
        # The marks themselves, because two draws sharing a mark would make
        # it precomputable again even where the typed text differed.
        self.assertGreater(len({mark for _, mark in draws}), 1)

    def test_an_answer_that_came_before_anything_was_typed_is_not_a_session(
        self,
    ) -> None:
        """The ordering the old check was missing.

        `head` is written to stdout before the first keystroke reaches the
        socket, so a token in it says nothing about a shell having run
        anything. Three streams here: the answer with no mark at all, the
        answer BEFORE the mark, and the answer after it. Only the last is a
        session, and the middle one is the one that used to pass.
        """
        landing = (
            field._REVERSE_SENDING_PREFIX + "perl connect-back]\n"
            + field._REVERSE_LANDED_PREFIX + "perl, from 127.0.0.1]\n"
        )
        no_mark = self._proof("uid=0(root)\nCVELAB_REVERSE_EXIT=0\n", landing)
        self.assertIs(no_mark["proof_checks"]["the_session_evaluated_a_command"],
                      False)
        self.assertIs(no_mark["shipped"], False)
        # Arrived, and that half is still true: what is refused is the claim
        # that a shell answered through it, not the connection itself.
        self.assertIs(no_mark["proof_checks"]["a_connect_back_arrived"], True)

        before = self._proof(
            "uid=0(root)\n" + self.CHALLENGE[1] + "\n"
            "CVELAB_REVERSE_EXIT=0\n",
            landing,
        )
        self.assertIs(before["proof_checks"]["the_session_evaluated_a_command"],
                      True)
        self.assertIs(before["proof_checks"]["the_build_answered_through_it"],
                      False)
        self.assertIs(before["shipped"], False)

        after = self._proof(self._answered(), landing)
        self.assertIs(after["proof_checks"]["the_build_answered_through_it"], True)
        self.assertIs(after["shipped"], True)

    def test_the_labs_own_output_cannot_forge_the_landing(self) -> None:
        """The check reads a shared stream, so it is anchored.

        stderr carries the mode's own sentences AND, through `_reverse_said`,
        whatever the lab program printed -- which for a product that echoes
        the command back is whatever the product felt like saying. A product
        that prints the landing sentence itself produced
        landed='bash-devtcp' off an unanchored substring match, for a run
        that exited 1 with nothing having connected. The report indents every
        such line by four spaces, so anchoring at the start of the line
        settles it.
        """
        forged = "    " + field._REVERSE_LANDED_PREFIX + "bash-devtcp, from 1.2.3.4]"
        outcome = self._proof(
            self._answered(1),
            field._REVERSE_SENDING_PREFIX + "bash-devtcp connect-back]\n"
            "Nothing connected back\n"
            "  bash-devtcp: delivered; nothing carrying its nonce connected back\n"
            + forged + "\n",
        )
        self.assertEqual(outcome["form"], "")
        self.assertIs(outcome["shipped"], False)
        self.assertIs(outcome["proof_checks"]["a_connect_back_arrived"], False)
        # The real sentence, at the start of a line after a delivery, is read.
        real = self._proof(
            self._answered(),
            field._REVERSE_SENDING_PREFIX + "perl connect-back]\n"
            + field._REVERSE_LANDED_PREFIX + "perl, from 127.0.0.1]\n",
        )
        self.assertEqual(real["form"], "perl")
        self.assertIs(real["shipped"], True)

    def test_the_banner_cannot_forge_the_landing_either(self) -> None:
        """The other half of the same stream, which the anchor did nothing about.

        `_reverse_said`'s four-space indent is true of `_reverse_said`. It is
        false of the banner, which goes onto the same stderr at column 0 and
        is wrapped from model-written plan text -- `plan.repository` and
        `exploit_contract.attack_summary`. A plan that spelled the landing
        sentence out, padded until the wrap put it at the start of a line,
        produced form='perl' and a_connect_back_arrived=True for a run that
        exited 1 with nothing having connected: measured at 8 characters of
        padding in `repository` and 42 in `attack_summary`.

        So the scan is scoped as well as anchored. A landing can only follow
        a delivery, the mode writes `_REVERSE_SENDING_PREFIX` before every
        delivery, and only what follows the LAST of those lines is read. The
        banner is printed before the delivery loop is entered, so the last
        such line is always a real one and the whole banner is behind it --
        including a delivery marker the plan forged, which is why this pins
        both of them.
        """
        forged = field._REVERSE_LANDED_PREFIX + "perl, from 10.9.9.9] prose"
        for tag, stderr in {
            "before any delivery": (
                forged + "\n"
                + field._REVERSE_SENDING_PREFIX + "bash-devtcp connect-back]\n"
                "Nothing connected back\n"
            ),
            "with a forged delivery marker in front of it": (
                field._REVERSE_SENDING_PREFIX + "perl connect-back] prose\n"
                + forged + "\n"
                + field._REVERSE_SENDING_PREFIX + "bash-devtcp connect-back]\n"
                "Nothing connected back\n"
            ),
            "with no delivery marker in the run at all": forged + "\n",
        }.items():
            with self.subTest(tag=tag):
                outcome = self._proof(self._answered(1), stderr)
                self.assertEqual(outcome["form"], "")
                self.assertIs(outcome["shipped"], False)
                self.assertIs(
                    outcome["proof_checks"]["a_connect_back_arrived"], False
                )
        # A real landing after a forged one is still read: the fix narrows
        # what is read and does not refuse a landing the run really had.
        real = self._proof(
            self._answered(),
            forged + "\n"
            + field._REVERSE_SENDING_PREFIX + "bash-devtcp connect-back]\n"
            + field._REVERSE_LANDED_PREFIX + "bash-devtcp, from 127.0.0.1]\n",
        )
        self.assertEqual(real["form"], "bash-devtcp")
        self.assertIs(real["shipped"], True)

    def test_the_banner_puts_no_prose_at_column_zero(self) -> None:
        """Defence in depth, and the reason it is depth and not the fix.

        The parser above is where this is settled. Indenting the prose is the
        second line: a paragraph that cannot begin a line at column 0 cannot
        be mistaken for a status line by anything, this file's own reader or
        a person's eye. Swept over both model-written strings, at every
        padding, against both of the prefixes the proof reads.
        """
        heading = "WHAT THIS IS, AND WHAT IT IS NOT"
        for where in ("repository", "attack_summary"):
            for payload in (
                field._REVERSE_LANDED_PREFIX.strip() + " perl, from 10.9.9.9] more",
                field._REVERSE_SENDING_PREFIX.strip() + " perl connect-back] more",
            ):
                for pad in (0, 7, 8, 41, 42, 43, 77, 100):
                    plan = copy.deepcopy(self.QUALIFIES)
                    plan["exploit_contract"] = dict(plan["exploit_contract"])
                    text = "w" * pad + " " + payload
                    if where == "repository":
                        plan["repository"] = text
                    else:
                        plan["exploit_contract"]["attack_summary"] = text
                    with self.subTest(where=where, pad=pad, payload=payload[:20]):
                        banner = field._reverse_banner(plan)
                        self.assertEqual(
                            [
                                line for line in banner.splitlines()
                                if line and not line.startswith(" ")
                            ],
                            [heading],
                        )

    def test_the_two_checks_read_different_streams_on_purpose(self) -> None:
        """The split that saves the other half of the proof.

        The relay is the only part of the MODE that writes stdout, so
        `answered` cannot be reached by anything the lab program or the
        target printed: a product that answers every request with `uid=`
        cannot make this think a shell replied. The one other thing on that
        stream is this function's own bootstrap line, which carries no
        `uid=`, so the claim is about the mode and not about the stream.

        Both prefixes the stderr check uses are constants shared with the
        emitted code, so neither the sentence nor the scan's start point can
        drift from what is written.
        """
        outcome = self._proof(
            # `uid=` only on stderr, which is where the lab's output lands.
            "CVELAB_REVERSE_EXIT=0\n",
            field._REVERSE_SENDING_PREFIX + "perl connect-back]\n"
            + field._REVERSE_LANDED_PREFIX + "perl, from 127.0.0.1]\n"
            "    uid=0(root) gid=0(root)\n",
        )
        self.assertEqual(outcome["form"], "perl")
        self.assertIs(outcome["proof_checks"]["the_build_answered_through_it"], False)
        self.assertIs(outcome["shipped"], False)
        text = field.emit_poc(
            "CVE-2026-0001", self.QUALIFIES, self.LAB,
            {"shipped": False, "reason": "no",
             "reverse_shell": {"shipped": True}},
        )
        for prefix in (field._REVERSE_LANDED_PREFIX, field._REVERSE_SENDING_PREFIX):
            with self.subTest(prefix=prefix):
                self.assertIn(prefix, text)
                # Substituted raw into the middle of a literal, which is only
                # safe while neither prefix can end one.
                self.assertNotIn('"', prefix)
                self.assertNotIn("\\", prefix)
        # And the bootstrap's own stdout line is this function's, not the
        # mode's: it is what keeps the `answered` claim honest.
        self.assertIn("CVELAB_REVERSE_EXIT=", self.sent[-1])

    # --- where it is attempted at all -------------------------------------

    def _prove(
        self, plan: dict | None, reverse: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], mock.Mock]:
        outcomes = {"cid-v": _run(True, True), "cid-p": _run(False, True)}
        landed = reverse or {"shipped": True, "form": "bash-devtcp", "proof_checks": {}}
        with mock.patch.object(
            field, "_lab_validator", return_value=self.LAB
        ), mock.patch.object(
            field, "_service_container",
            side_effect=lambda c, name, d, e: {
                "vulnerable": "cid-v", "patched": "cid-p"
            }.get(name, ""),
        ), mock.patch.object(
            field, "_still_serving", return_value="127.0.0.1"
        ), mock.patch.object(
            field, "_run_reverse_shell_proof", return_value=landed
        ) as attempted, mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given, host=None,
            disruptive=False: outcomes[cid],
        ):
            return field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8080,
                Path("/lab"), ["docker", "compose"], {}, plan=plan,
            ), attempted

    def test_a_qualifying_lab_is_attempted_and_recorded_beside_the_rest(self) -> None:
        out, attempted = self._prove(self.QUALIFIES)
        self.assertEqual(attempted.call_count, 1)
        self.assertIs(out["reverse_shell"]["shipped"], True)
        self.assertEqual(out["reverse_shell"]["form"], "bash-devtcp")
        # Beside the existing record, not folded into it: remote mode's own
        # standing is untouched by it either way.
        self.assertIs(out["shipped"], True)
        self.assertIn("--reverse-shell", out["script"])

    def test_the_script_remote_mode_is_proved_with_is_the_one_shipped(self) -> None:
        """The claim this function's docstring makes, kept with the mode in.

        The session's own code is a pure function of the plan, so the text
        the connect-back was proved from and the text shipped differ in the
        header's sentence about the outcome and nowhere else -- and the text
        remote mode was proved with is the shipped text exactly.
        """
        out, _ = self._prove(self.QUALIFIES)
        rendered = field.emit_poc(
            "CVE-2026-0001", self.QUALIFIES, self.LAB,
            {key: value for key, value in out.items() if key != "script"}
            | {"shipped": True, "spec": field.validate_spec(_spec()),
               "container_port": 8080},
        )
        self.assertEqual(out["script"], rendered)

    def test_a_refused_session_leaves_the_mode_out_and_the_reason_in(self) -> None:
        out, _ = self._prove(
            self.QUALIFIES,
            reverse={"shipped": False, "reason": "no connect-back could be landed"},
        )
        self.assertIs(out["reverse_shell"]["shipped"], False)
        self.assertNotIn("--reverse-shell", out["script"])
        self.assertIn("no connect-back could be landed", out["script"])

    def test_a_failure_in_the_session_proof_does_not_sink_the_manual_poc(
        self,
    ) -> None:
        """The two standings are independent in both directions.

        The call shells out to `docker` with a 300-second timeout, and inside
        this function's own `except Exception` a docker that hung or was not
        there returned {"shipped": False, "reason": ...} for the ENTIRE
        manual PoC: no `script`, no `reverse_shell` key, and a fully provable
        remote mode reported as refused by a failure in a mode that is
        dormant on every archived lab.
        """
        outcomes = {"cid-v": _run(True, True), "cid-p": _run(False, True)}
        failures = {
            "docker timed out": subprocess.TimeoutExpired(["docker"], 300),
            "docker is not there": OSError("docker: no such file"),
            "something else entirely": ValueError("nonsense"),
        }
        for label, error in failures.items():
            with self.subTest(failure=label), mock.patch.object(
                field, "_lab_validator", return_value=self.LAB
            ), mock.patch.object(
                field, "_service_container",
                side_effect=lambda c, name, d, e: {
                    "vulnerable": "cid-v", "patched": "cid-p"
                }.get(name, ""),
            ), mock.patch.object(
                field, "_still_serving", return_value="127.0.0.1"
            ), mock.patch.object(
                field, "_run_reverse_shell_proof", side_effect=error
            ), mock.patch.object(
                field, "_run_field_script",
                side_effect=lambda cid, port, script, transport, image, given,
                host=None, disruptive=False: outcomes[cid],
            ):
                out = field.prove_manual_poc(
                    "CVE-2026-0001", field.validate_spec(_spec()), 8080,
                    Path("/lab"), ["docker", "compose"], {}, plan=self.QUALIFIES,
                )
            # Remote mode is exactly what it would have been.
            self.assertIs(out["shipped"], True)
            self.assertIn("script", out)
            self.assertNotIn("reason", out)
            self.assertIn("manual_poc_proven", out["proof_checks"])
            # And the session is recorded as not proved, with the cause.
            self.assertIs(out["reverse_shell"]["shipped"], False)
            self.assertIn(
                "the connect-back could not be proved", out["reverse_shell"]["reason"]
            )
            self.assertIn(
                type(error).__name__, out["reverse_shell"]["reason"]
            )
            # A flag that does not apply is absent from the file entirely,
            # and the header says why instead.
            self.assertNotIn("--reverse-shell", out["script"])
            self.assertIn("could not be proved", out["script"])

    def test_a_lab_that_does_not_qualify_is_never_attempted(self) -> None:
        """Which is every archived lab, so this is the ordinary path.

        Nothing is started, nothing is sent, and no key is written: the
        standing then reads the gate's own reason, which is a fact about the
        lab rather than about a run.
        """
        for label, plan in (
            ("adapter named", self.ADAPTED),
            ("no plan at all", None),
        ):
            with self.subTest(label=label):
                out, attempted = self._prove(plan)
                self.assertEqual(attempted.call_count, 0)
                self.assertNotIn("reverse_shell", out)
                self.assertNotIn("--reverse-shell", out["script"])

    def test_a_build_answering_off_loopback_is_said_rather_than_tried(self) -> None:
        """`--lab-address` refuses an address this lab could not have
        published, and the session is driven through that flag."""
        outcomes = {"cid-v": _run(True, True), "cid-p": _run(False, True)}
        with mock.patch.object(
            field, "_lab_validator", return_value=self.LAB
        ), mock.patch.object(
            field, "_service_container",
            side_effect=lambda c, name, d, e: {
                "vulnerable": "cid-v", "patched": "cid-p"
            }.get(name, ""),
        ), mock.patch.object(
            field, "_still_serving", return_value="172.18.0.2"
        ), mock.patch.object(
            field, "_run_reverse_shell_proof"
        ) as attempted, mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given, host=None,
            disruptive=False: outcomes[cid],
        ):
            out = field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8080,
                Path("/lab"), ["docker", "compose"], {}, plan=self.QUALIFIES,
            )
        self.assertEqual(attempted.call_count, 0)
        self.assertIs(out["reverse_shell"]["shipped"], False)
        self.assertIn("172.18.0.2", out["reverse_shell"]["reason"])
        self.assertIn("rather than on loopback", out["reverse_shell"]["reason"])

    def test_the_record_is_read_back_and_the_mode_survives_a_re_render(self) -> None:
        """Asking twice gives the same answer, which is what the record is for."""
        spec = field.validate_spec(_spec())
        with tempfile.TemporaryDirectory() as root:
            lab_dir = Path(root) / "CVE-2026-0001"
            (lab_dir / "validator").mkdir(parents=True)
            (lab_dir / "validator" / "validator.py").write_text(
                self.LAB, encoding="utf-8"
            )
            (lab_dir / "report.json").write_text(
                json.dumps({"real_poc_verified": True}), encoding="utf-8"
            )
            field.write_manual_poc(
                "CVE-2026-0001", lab_dir, self.QUALIFIES, spec, 8080,
                {"shipped": True, "proof_checks": {}, "runs": {},
                 "reverse_shell": {"shipped": True, "form": "perl"}},
            )
            held = field.poc_record(lab_dir)
            self.assertEqual(held["reverse_shell"]["form"], "perl")
            self.assertIs(
                field.reverse_shell_standing(self.QUALIFIES, self.LAB, held)[0], True
            )

    def test_the_record_is_withheld_from_what_a_shared_lab_sends(self) -> None:
        """The form is a recipe, and the allowlist is a denylist by default.

        `upload.DESCRIBED_ONLY` names what travels and withholds the rest,
        which is the safe direction to be wrong in: a connect-back one-liner
        is how to produce the effect and not a description of it.
        """
        allowed = upload.DESCRIBED_ONLY["report.json"]
        self.assertNotIn("manual_poc_field.reverse_shell", allowed)
        self.assertFalse(
            [name for name in allowed if name.startswith("manual_poc_field.reverse")]
        )

#: A product with the weakness the contract declares, for the one test that
#: needs a real container. Not a lab and not a template for one: the smallest
#: HTTP service `tests/fixtures/operator_validator.py` can drive, with the
#: command actually run rather than echoed, because a connect-back that is
#: echoed connects nowhere.
_PRODUCT_WITH_A_SHELL = '''import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def answer(self, status, body):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if urlparse(self.path).path == "/login":
            raw = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=lab-session; Path=/")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.answer(404, "no")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.answer(200, "ok")
            return
        if parsed.path != "/run":
            self.answer(404, "no")
            return
        command = (parse_qs(parsed.query).get("cmd") or [""])[0]
        child = subprocess.Popen(
            ["/bin/sh", "-c", command], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            said = child.communicate(timeout=4)[0].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            said = "(still running)"
        self.answer(200, "shell-ran " + said)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def _docker_works() -> bool:
    if not shutil.which("docker"):
        return False
    done = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, timeout=60, check=False
    )
    return done.returncode == 0


@pytest.mark.docker
@unittest.skipUnless(_docker_works(), "needs a working Docker daemon")
class TheConnectBackIsProvedInAContainerTests(unittest.TestCase):
    """The proof path, run where it actually runs: a container and a sidecar.

    The rest of the suite drives `_run_reverse_shell_proof` with `docker`
    stubbed, which measures what it does with an answer and not that the
    arrangement works. This measures the arrangement, and it is the whole
    reason the proof is affordable: the sidecar joins the product
    container's network namespace, so the listener it binds on loopback IS
    the product's loopback. Nothing is published, no route from this host is
    needed, and the `cvelab-manual` network is not involved.

    Two images, because which connect-back form works is a fact about what is
    in the image and not about this code: `python:3.13-slim` has bash and
    perl and no `nc`, and `python:3.13-alpine` is busybox with neither bash
    nor perl. Measured here rather than assumed, which is also why the
    outcome records which form landed.
    """

    IMAGES = ("python:3.13-slim", "python:3.13-alpine")
    CONTRACT = TheSessionTests.CONTRACT
    QUALIFIES = TheSessionTests.QUALIFIES

    @classmethod
    def validator(cls) -> str:
        return (
            Path(field.__file__).parent.parent
            / "tests" / "fixtures" / "operator_validator.py"
        ).read_text(encoding="utf-8")

    @contextlib.contextmanager
    def product(self, image: str) -> Iterator[str]:
        started = subprocess.run(
            ["docker", "run", "-d", "--rm", image, "python", "-c",
             _PRODUCT_WITH_A_SHELL],
            capture_output=True, text=True, timeout=300, check=True,
        )
        container = started.stdout.strip()
        try:
            for _ in range(120):
                ready = subprocess.run(
                    ["docker", "exec", container, "python", "-c",
                     "import urllib.request;urllib.request.urlopen("
                     "'http://127.0.0.1:8080/health',timeout=2)"],
                    capture_output=True, timeout=60, check=False,
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                self.fail(f"the product in {image} never answered")
            yield container
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container], capture_output=True, timeout=120,
                check=False,
            )

    def test_a_connect_back_is_landed_and_the_build_answers_through_it(self) -> None:
        script = field.emit_poc(
            "CVE-2026-0001", self.QUALIFIES, self.validator(),
            {"shipped": False, "reason": "nothing was proved against one instance",
             "reverse_shell": {"shipped": True}},
        )
        for image in self.IMAGES:
            with self.subTest(image=image), self.product(image) as container:
                outcome = field._run_reverse_shell_proof(
                    container, 8080, script, sidecar.BASE_IMAGE, "127.0.0.1"
                )
                self.assertIs(outcome["shipped"], True, outcome)
                self.assertIn(
                    outcome["form"], [name for name, _ in field.REVERSE_FORMS]
                )
                self.assertIs(
                    outcome["proof_checks"]["reverse_shell_proven"], True, outcome
                )
                self.assertEqual(outcome["mode_exit_code"], 0, outcome)
                # The form named is one this image could actually run, which
                # is the measurement the nonce makes possible: without it the
                # name was whichever delivery was last in flight. Measured
                # per image rather than asserted -- bash and perl in the
                # slim one, busybox `nc` in the alpine one.
                self.assertEqual(
                    outcome["form"],
                    "bash-devtcp" if image.endswith("slim") else "python3-pty",
                    outcome,
                )
                # And no connection reached the listener that it had to
                # close as unattributable.
                self.assertNotIn("carried no nonce", outcome.get("output", ""))

    def test_a_product_that_echoes_the_command_proves_nothing(self) -> None:
        """The refusal, measured the same way, so it is a recorded reason and
        not an exception."""
        echoing = _PRODUCT_WITH_A_SHELL.replace(
            '        child = subprocess.Popen(\n'
            '            ["/bin/sh", "-c", command], stdin=subprocess.DEVNULL,\n'
            '            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,\n'
            '        )\n'
            '        try:\n'
            '            said = child.communicate(timeout=4)[0].decode("utf-8", "replace")\n'
            '        except subprocess.TimeoutExpired:\n'
            '            said = "(still running)"\n',
            '        said = command\n',
        )
        self.assertIn("said = command", echoing)
        script = field.emit_poc(
            "CVE-2026-0001", self.QUALIFIES, self.validator(),
            {"shipped": False, "reason": "no", "reverse_shell": {"shipped": True}},
        )
        started = subprocess.run(
            ["docker", "run", "-d", "--rm", self.IMAGES[0], "python", "-c", echoing],
            capture_output=True, text=True, timeout=300, check=True,
        )
        container = started.stdout.strip()
        try:
            for _ in range(120):
                ready = subprocess.run(
                    ["docker", "exec", container, "python", "-c",
                     "import urllib.request;urllib.request.urlopen("
                     "'http://127.0.0.1:8080/health',timeout=2)"],
                    capture_output=True, timeout=60, check=False,
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.5)
            outcome = field._run_reverse_shell_proof(
                container, 8080, script, sidecar.BASE_IMAGE, "127.0.0.1", seconds=2
            )
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container], capture_output=True, timeout=120,
                check=False,
            )
        self.assertIs(outcome["shipped"], False, outcome)
        self.assertEqual(outcome["form"], "")
        self.assertIn("no connect-back could be landed", outcome["reason"])
        self.assertEqual(outcome["mode_exit_code"], 1, outcome)

class EverythingTravelsTests(unittest.TestCase):
    """The merged script goes to the shared corpus whole, remote mode included.

    This class replaces StaysLocalTests, "The lab travels to the corpus; a
    free-target script does not", which asserted that Manual-PoC.py, its
    guide and its record were absent from both upload allowlists. The project
    owner reversed that decision on 2026-11-08, when the two scripts were
    merged into one `PoC.py`. The consequence, stated plainly because it was
    chosen rather than drifted into: free-target exploit code is distributed
    to everyone who downloads a lab. Where the drafter proved a
    single-instance script, that script is inside the `PoC.py` on
    `upload.ALWAYS`, and anyone with the lab can point it at any host they
    like. `--no-poc` still withholds it, since `PoC.py` is on
    `upload.EXPLOIT` as well -- and the records it cannot withhold are
    redacted, because moving the proved spec into report.json put the
    requests remote mode sends into a document the control plane requires.

    Nothing was added to either list to make this happen, and that is worth
    recording too: `PoC.py` was already on both, as the lab-only script, and
    what changed is what the name contains.
    """

    def test_the_one_artifact_travels_and_is_withheld_by_no_poc(self) -> None:
        self.assertIn(field.POC_NAME, upload.ALWAYS)
        self.assertIn(field.POC_NAME, upload.EXPLOIT)
        self.assertIn(field.POC_NAME, upload.REQUIRED_TO_SHARE)

    def test_the_record_travels_with_it(self) -> None:
        """The proved spec is in report.json now, which is shared.

        `Manual-PoC.json` never left the machine, so `cvelab manual-poc` on a
        downloaded lab had nothing to reuse and drafted afresh -- a model call
        and a sampled answer, so the same lab could get a different verdict on
        a different day.
        """
        self.assertIn("report.json", upload.ALWAYS)
        self.assertIn("report.json", upload.REQUIRED_TO_SHARE)

    def test_a_shipped_lab_sends_remote_mode_in_the_body(self) -> None:
        """Measured on the document that is actually collected, not the list."""
        with _lab() as lab_dir:
            artifacts = lab_dir / "artifacts"
            artifacts.mkdir(exist_ok=True)
            (artifacts / field.POC_NAME).write_text(
                field.emit_poc(
                    "CVE-2026-0001", {}, _LAB_MODE,
                    {"shipped": True, "container_port": 8000,
                     "spec": field.validate_spec(_spec())},
                ),
                encoding="utf-8",
            )
            payload = upload.collect(
                lab_dir, {"ok": True, "cve": "CVE-2026-0001"},
                provider="anthropic", model="m", include_poc=True,
            )
            withheld = upload.collect(
                lab_dir, {"ok": True, "cve": "CVE-2026-0001"},
                provider="anthropic", model="m", include_poc=False,
            )
        sent = {document["name"]: document["text"] for document in payload["documents"]}
        self.assertIn("--target", sent[field.POC_NAME])
        self.assertIn("REMOTE MODE", sent[field.POC_NAME])
        self.assertNotIn(
            field.POC_NAME, {d["name"] for d in withheld["documents"]}
        )

    def test_no_poc_withholds_the_script_and_the_spec_it_sends(self) -> None:
        """The record travels, and `--no-poc` takes the attack out of it.

        Moving the proved spec into report.json put every request remote mode
        sends into a document that `--no-poc` could not withhold, because the
        control plane requires it. Measured when that landed: a `--no-poc`
        upload filed `manual_poc_field.spec` in full, which is the script in
        all but name. It is redacted out now, with the rest of the attack --
        `tests/test_upload.py::WhatNoPocFilesTests` is the measurement, name
        by name.
        """
        with _lab() as lab_dir:
            artifacts = lab_dir / "artifacts"
            artifacts.mkdir(exist_ok=True)
            report = json.loads((lab_dir / "report.json").read_text())
            report["manual_poc_field"] = {
                "shipped": True, "container_port": 8000,
                "spec": field.validate_spec(_spec()),
                "lab_values": {"account": "seeded-user"},
            }
            # The copy upload reads is the one in artifacts/, written by the
            # deliverables pass from the same dict as the lab's own.
            (artifacts / "report.json").write_text(json.dumps(report))
            (artifacts / field.POC_NAME).write_text("# the artifact\n", encoding="utf-8")
            payload = upload.collect(
                lab_dir, {"ok": True, "cve": "CVE-2026-0001"},
                provider="anthropic", model="m", include_poc=False,
            )
        sent = {document["name"]: document["text"] for document in payload["documents"]}
        self.assertNotIn(field.POC_NAME, sent)
        self.assertIn("report.json", sent)
        self.assertNotIn("inband_differential", sent["report.json"])
        self.assertNotIn("seeded-user", sent["report.json"])
        held = json.loads(sent["report.json"])
        self.assertNotIn("spec", held["manual_poc_field"])
        self.assertIn(
            "manual_poc_field.spec", held["withheld_by_no_poc"]["fields"]
        )

    def test_the_names_it_replaced_are_still_absent(self) -> None:
        """Nothing writes them, and an archived lab's copies do not travel."""
        for name in field.LEGACY_MANUAL_POC_NAMES:
            with self.subTest(name=name):
                self.assertNotIn(name, upload.ALWAYS)
                self.assertNotIn(name, upload.EXPLOIT)


class NamesCannotCollideTests(unittest.TestCase):
    """No two artifact names may differ only by case.

    This class replaces a test that claimed to make this guarantee and did
    not. It compared `field.MANUAL_POC_GUIDE_NAME` against the tuple
    `("manual.sh", "MANUAL-POC.md", "PoC.py")` with assertNotIn, which is an
    exact-string membership test: "Manual-PoC.md" is not equal to
    "MANUAL-POC.md", so it passed, while the two names were the same file on
    macOS and on Windows. 13 of the archived labs held both documents, and on
    those platforms one of the two was silently lost to whichever was written
    second. A test whose name promises "does not collide" and compares with
    `==` semantics is worse than no test, because it is read as cover.

    The lab guide was renamed to LAB-POC.md. These tests are the guard that
    should have existed, and they compare the way Windows and macOS do.
    """

    #: Every name CVELab writes into a lab's artifacts/ directory, in the
    #: spelling it writes. Collected from the constants where there are
    #: constants and spelled out where the writer spells it out. Three names
    #: left this list when the two scripts were merged, which is three fewer
    #: chances to collide -- but the merged name has to be checked too, and
    #: `PoC.py` against `PoC.ps1` is the pair that is nearly one.
    ARTIFACT_NAMES = (
        field.POC_NAME,
        field.LAB_POC_GUIDE_NAME,
        "PoC.ps1", "manual.sh",
        "REPORT.md", "WALKTHROUGH.md",
        "EVIDENCE.json", "report.json", "plan.json", "contract.json",
        "analysis.json", "field-poc.py", "field-spec.json",
    )

    def test_no_two_artifact_names_differ_only_by_case(self) -> None:
        folded: dict[str, str] = {}
        for name in self.ARTIFACT_NAMES:
            earlier = folded.setdefault(name.lower(), name)
            with self.subTest(name=name):
                self.assertEqual(
                    earlier, name,
                    f"{name!r} and {earlier!r} are one file on macOS and Windows",
                )

    def test_the_two_manual_documents_are_distinct_without_case(self) -> None:
        """The exact pair that collided, asserted the way the bug happened."""
        self.assertNotEqual(
            field.LAB_POC_GUIDE_NAME.lower(),
            field.LEGACY_MANUAL_POC_GUIDE_NAME.lower(),
        )
        # And the old name really is gone from what gets written. It survives
        # only in upload's allowlists, for archived labs that still hold it.
        self.assertNotEqual(
            field.LAB_POC_GUIDE_NAME, field.LEGACY_LAB_POC_GUIDE_NAME
        )
        self.assertEqual(
            field.LEGACY_LAB_POC_GUIDE_NAME.lower(),
            field.LEGACY_MANUAL_POC_GUIDE_NAME.lower(),
            "the legacy name is kept precisely because it DID collide; if this "
            "stops being true the comments explaining the rename are wrong",
        )

    def test_the_whole_package_declares_no_colliding_file_name(self) -> None:
        """Scanned, not enumerated, so a new name added anywhere is caught.

        The list above is only as good as whoever maintained it, and the bug
        this replaces happened because two modules each declared a name
        without seeing the other's. This reads every quoted file name in the
        package the way test_no_per_cve_logic reads every line, so a third
        module introducing a third spelling fails here even if nobody thinks
        to extend ARTIFACT_NAMES.
        """
        quoted = re.compile(
            r"""["']([A-Za-z0-9][A-Za-z0-9._-]*\.(?:md|json|py|sh|ps1|yml|yaml))["']"""
        )
        # The one name that is allowed to collide, because colliding is the
        # whole of what it records. LEGACY_LAB_POC_GUIDE_NAME is the name the
        # lab guide had when it was one file with Manual-PoC.md on macOS and
        # Windows. Nothing writes it; it stays in upload.py's allowlists so
        # that an archived lab holding it still ships it. A read-only name
        # cannot overwrite anything, so it is exempt here -- and exempt by
        # name, in one place, rather than by loosening the scan.
        # And the three the merge absorbed, for the same reason: nothing
        # writes them, field.py reads one of them off an archived lab, and a
        # name that is only ever read cannot overwrite anything. Exempt by
        # name, in one place, rather than by loosening the scan.
        exempt = {field.LEGACY_LAB_POC_GUIDE_NAME, *field.LEGACY_MANUAL_POC_NAMES}
        found: dict[str, tuple[str, str]] = {}
        for source in sorted(Path(field.__file__).parent.glob("*.py")):
            for name in quoted.findall(source.read_text(encoding="utf-8")):
                if name in exempt:
                    continue
                where = found.setdefault(name.lower(), (name, source.name))
                if where[0] != name:
                    self.fail(
                        f"{source.name} declares {name!r} and {where[1]} declares "
                        f"{where[0]!r}; those are one file on macOS and Windows"
                    )

    def test_the_upload_allowlists_name_the_document_that_is_written(self) -> None:
        """upload.py spells the names out, so something has to tie them here.

        The allowlists are a declarative list of literals and are easier to
        read that way, but a rename that missed them would stop shipping a
        document with no test failing anywhere.
        """
        self.assertIn(field.LAB_POC_GUIDE_NAME, upload.ALWAYS)
        self.assertIn(field.LAB_POC_GUIDE_NAME, upload.EXPLOIT)
        # Both names stay reachable: an archived lab holds the old one.
        self.assertIn(field.LEGACY_LAB_POC_GUIDE_NAME, upload.ALWAYS)
        self.assertIn(field.LEGACY_LAB_POC_GUIDE_NAME, upload.EXPLOIT)

    def test_an_archived_lab_still_ships_its_guide_under_the_old_name(self) -> None:
        """The reason the legacy name is on the allowlist, exercised.

        `cvelab upload` reads a lab directory off disk, and 87 of the archived
        labs were generated when the guide was called MANUAL-POC.md. Dropping
        the old name would have silently stopped shipping a document those
        labs still have -- and silently, because the share gate does not
        require this document, so the upload would have succeeded.
        """
        with tempfile.TemporaryDirectory() as root:
            lab = Path(root) / "CVE-2026-0001"
            artifacts = lab / "artifacts"
            artifacts.mkdir(parents=True)
            (artifacts / field.LEGACY_LAB_POC_GUIDE_NAME).write_text(
                "# an archived lab's guide\n", encoding="utf-8"
            )
            payload = upload.collect(
                lab, {"ok": True, "cve": "CVE-2026-0001"},
                provider="anthropic", model="m", include_poc=True,
            )
        names = {document["name"] for document in payload["documents"]}
        self.assertIn(field.LEGACY_LAB_POC_GUIDE_NAME, names)
        # And only one of the two ever travels, because only one is on disk.
        self.assertNotIn(field.LAB_POC_GUIDE_NAME, names)


class CommandLineTests(unittest.TestCase):
    def test_manual_takes_a_cve_and_where_its_poc_lives(self) -> None:
        """A CVE is what anyone remembers; the path with the CVE in it is not."""
        args = cli.parser().parse_args([
            "manual", "CVE-2026-0001", "--poc", "/labs",
            "--spec", "s.json", "--container-port", "8000",
        ])
        self.assertEqual(args.command, "manual")
        self.assertEqual(args.cve, "CVE-2026-0001")
        self.assertEqual(args.poc, Path("/labs"))
        self.assertEqual(args.container_port, 8000)
        self.assertIs(args.keep, False)

    def test_either_spelling_of_the_location_is_accepted(self) -> None:
        """Both are what gets typed: the directory holding the lab, and the lab."""
        with _lab() as lab_dir:
            self.assertEqual(cli._locate_lab("CVE-2026-0001", lab_dir.parent), lab_dir)
            self.assertEqual(cli._locate_lab("cve-2026-0001", lab_dir), lab_dir)

    def test_a_missing_lab_says_where_it_looked(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(RuntimeError) as raised:
                cli._locate_lab("CVE-2026-0001", Path(root))
            said = str(raised.exception)
            self.assertIn("CVE-2026-0001", said)
            self.assertIn("plan.json", said)
            self.assertIn("cvelab auto", said)

    def test_demo_target_takes_up_or_down(self) -> None:
        for action in ("up", "down"):
            with self.subTest(action=action):
                args = cli.parser().parse_args(["demo-target", action, "/labs/X"])
                self.assertEqual(args.action, action)
        with self.assertRaises(SystemExit):
            cli.parser().parse_args(["demo-target", "sideways", "/labs/X"])


class DraftedSpecTests(unittest.TestCase):
    """The spec is asked for in one separate call, after the lab is finished."""

    def _ask(self, answer: Any = None, error: Exception | None = None) -> dict[str, Any]:
        with mock.patch.object(
            field, "structured_response",
            side_effect=error if error else None,
            return_value=answer,
        ):
            return field.draft_manual_poc_spec(
                "CVE-2026-0001", {"cwe": "CWE-200", "exploit_contract": {}},
                api_key="k", model="m", provider="anthropic", base_url=None,
            )

    def test_a_usable_answer_becomes_a_validated_spec_and_a_port(self) -> None:
        out = self._ask({
            "feasible": True, "reason": "", "container_port": 8000,
            "spec_json": json.dumps(_spec()),
        })
        self.assertEqual(out["container_port"], 8000)
        self.assertEqual(out["spec"]["strategy"], "inband_differential")
        # validate_spec normalises the single check into the checks list.
        self.assertEqual(len(out["spec"]["checks"]), 1)

    def test_not_feasible_is_the_expected_answer_and_keeps_the_reason(self) -> None:
        out = self._ask({
            "feasible": False, "reason": "the effect is a worker crash",
            "container_port": None, "spec_json": None,
        })
        self.assertNotIn("spec", out)
        self.assertIn("worker crash", out["reason"])

    def test_a_provider_decline_is_recorded_and_never_reworded(self) -> None:
        """The same request asked again gets the same answer.

        Rewording it would only be an attempt to get past an answer the
        provider already gave, so the call is made once.
        """
        declined = field.ProviderDeclined("anthropic", "claude-haiku-5-5", "cyber")
        with mock.patch.object(
            field, "structured_response", side_effect=declined
        ) as asked:
            out = field.draft_manual_poc_spec(
                "CVE-2026-0001", {}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )
        self.assertEqual(asked.call_count, 1)
        self.assertNotIn("spec", out)
        self.assertEqual(out["declined"]["provider"], "anthropic")

    def test_a_malformed_answer_names_what_was_wrong(self) -> None:
        """Both DeepSeek drafts were rejected for shape, each differently.

        A bare "not usable" left nothing to correct, so the reason carries
        validate_spec's own message.
        """
        cases = {
            "invented strategy": json.dumps(_spec(strategy="http_differential")),
            "empty probe": json.dumps(_spec(probe=[])),
            "not json": "{not json",
        }
        for name, offered in cases.items():
            with self.subTest(case=name):
                out = self._ask({
                    "feasible": True, "reason": "", "container_port": 8000,
                    "spec_json": offered,
                })
                self.assertNotIn("spec", out)
                self.assertTrue(out["reason"])

    def test_feasible_without_a_port_is_not_usable(self) -> None:
        out = self._ask({
            "feasible": True, "reason": "", "container_port": None,
            "spec_json": json.dumps(_spec()),
        })
        self.assertNotIn("spec", out)
        self.assertIn("port", out["reason"])

    def test_the_schema_carries_the_spec_as_text(self) -> None:
        """Anthropic rejects a schema with additionalProperties: true.

        That rejection killed a whole run before anything was sent, so the
        spec travels as a JSON string and validate_spec checks the shape.
        """
        properties = field.MANUAL_POC_DRAFT_SCHEMA["properties"]
        self.assertEqual(properties["spec_json"]["type"], ["string", "null"])
        self.assertIs(field.MANUAL_POC_DRAFT_SCHEMA["additionalProperties"], False)
        self.assertNotIn("additionalProperties: true", json.dumps(properties))


class AfterValidationHookTests(unittest.TestCase):
    """Nothing the step does can cost the lab anything."""

    def _step(self, **kwargs: Any) -> Any:
        return field.manual_poc_step(
            api_key="k", model="m", provider="anthropic", base_url=None, **kwargs
        )

    def test_a_lab_that_did_not_reproduce_is_not_asked_about(self) -> None:
        with mock.patch.object(field, "draft_manual_poc_spec") as drafted:
            out = self._step()(
                "CVE-2026-0001", Path("/lab"), {}, ["docker"], {}, False
            )
        drafted.assert_not_called()
        self.assertIs(out["shipped"], False)
        self.assertIn("did not reproduce", out["reason"])

    def test_a_vulnerable_only_lab_is_asked_about_too(self) -> None:
        """It used to be skipped. The effect is still worth showing."""
        with mock.patch.object(field, "ai_is_configured", return_value=True), \
             mock.patch.object(
                 field, "draft_manual_poc_spec",
                 return_value={"spec": field.validate_spec(_spec()), "container_port": 8000},
             ) as drafted, \
             mock.patch.object(
                 field, "prove_manual_poc",
                 return_value={"shipped": False, "reason": "x", "proof_checks": {}, "runs": {}},
             ), _lab() as lab_dir:
            self._step()(
                "CVE-2026-0001", lab_dir,
                {"lab_type": "VULNERABLE_ONLY_REPRODUCTION"}, ["docker"], {}, True,
            )
        drafted.assert_called_once()

    def test_no_model_configured_costs_nothing(self) -> None:
        with mock.patch.object(field, "ai_is_configured", return_value=False), \
             mock.patch.object(field, "draft_manual_poc_spec") as drafted:
            out = self._step()("CVE-2026-0001", Path("/lab"), {}, ["docker"], {}, True)
        drafted.assert_not_called()
        self.assertIn("no model configured", out["reason"])

    def test_a_proved_spec_is_written_beside_the_lab(self) -> None:
        with _lab() as lab_dir, \
             mock.patch.object(field, "ai_is_configured", return_value=True), \
             mock.patch.object(
                 field, "draft_manual_poc_spec",
                 return_value={"spec": field.validate_spec(_spec()), "container_port": 8000},
             ), \
             mock.patch.object(
                 field, "prove_manual_poc",
                 return_value={
                     "shipped": True, "proof_checks": {}, "runs": {},
                     "script": "#!/usr/bin/env python3\n",
                 },
             ):
            out = self._step()(
                "CVE-2026-0001", lab_dir, {"repository": "r"}, ["docker"], {}, True
            )
            self.assertIs(out["shipped"], True)
            self.assertTrue((lab_dir / "artifacts" / field.POC_NAME).is_file())

    def test_the_script_never_reaches_the_report(self) -> None:
        """run_lab puts this outcome in report.json verbatim.

        The script is a free-target exploit and the report is uploaded, so it
        is taken out of the outcome when it is written to disk.
        """
        with _lab() as lab_dir:
            outcome = {
                "shipped": True, "proof_checks": {}, "runs": {},
                "script": "#!/usr/bin/env python3\n",
            }
            field.write_manual_poc(
                "CVE-2026-0001", lab_dir, {}, field.validate_spec(_spec()), 8000, outcome
            )
        self.assertNotIn("script", outcome)
        self.assertIn("deliverables", outcome)

    def test_a_refusal_writes_the_record_and_a_refusing_remote_mode(self) -> None:
        with _lab() as lab_dir:
            outcome = {"shipped": False, "reason": "did not tell them apart"}
            field.write_manual_poc(
                "CVE-2026-0001", lab_dir, {}, field.validate_spec(_spec()), 8000, outcome
            )
            record = _held(lab_dir)
            self.assertIn("did not tell them apart", record["reason"])
            poc = (lab_dir / "artifacts" / field.POC_NAME).read_text()
            self.assertIn("did not tell them apart", poc)
            # And no embedded spec: there is nothing to send.
            self.assertNotIn("SPEC = json.loads", poc)


class HookOptionsTests(unittest.TestCase):
    """Generating a lab and demonstrating it on a server are separate jobs."""

    def test_a_lab_run_gives_the_lab_and_its_own_PoC_and_nothing_else(self) -> None:
        """A batch wants the labs. The extra call is asked for, not assumed."""
        for argv in (
            ["run", "CVE-2026-0001"],
            ["auto", "CVE-2026-0001"],
            ["source-all", "CVE-2026-0001"],
            ["all", "CVE-2026-0001"],
        ):
            with self.subTest(command=argv[0]):
                self.assertIs(cli.parser().parse_args(argv).manual_poc, False)

    def test_it_can_be_asked_for_and_pointed_at_another_provider(self) -> None:
        args = cli.parser().parse_args([
            "run", "CVE-2026-0001", "--manual-poc",
            "--manual-poc-provider", "deepseek", "--manual-poc-model", "deepseek-chat",
        ])
        self.assertIs(args.manual_poc, True)
        self.assertEqual(args.manual_poc_provider, "deepseek")
        self.assertEqual(args.manual_poc_model, "deepseek-chat")

    def test_the_dedicated_command_needs_neither_a_spec_nor_a_port(self) -> None:
        """`cvelab manual-poc <lab>` asks for the spec itself."""
        args = cli.parser().parse_args(["manual", "CVE-2026-0001"])
        self.assertIsNone(args.spec)
        self.assertIsNone(args.container_port)

    def test_a_command_that_never_validates_has_no_such_flag(self) -> None:
        """The dispatch reads it with getattr, so absence means skipped."""
        for argv in (["upload", "CVE-2026-0001"], ["demo-target", "up", "/lab"]):
            with self.subTest(command=argv[0]):
                args = cli.parser().parse_args(argv)
                self.assertFalse(hasattr(args, "no_manual_poc"))


class NoFixedBuildTests(unittest.TestCase):
    """A lab with no patched build may still hand over a script.

    The patched build answers one question -- is this the bug, or is it how the
    thing always behaves -- and it is a check against self-deception rather
    than what makes a vulnerability real. Some projects publish no resolvable
    fixed revision at all. What has to replace it is a strategy that carries
    its own control inside the one instance it runs against.
    """

    def _prove(self, strategy: str, observed: bool = True) -> dict[str, Any]:
        spec = {
            "inband_differential": _spec(),
            "marker_roundtrip": {
                "strategy": "marker_roundtrip", "observable_effect": "a stored marker",
                "probe": [{"method": "POST", "path": "/c", "body": "{{marker}}"}],
                "observe": {"method": "GET", "path": "/c"},
            },
            "oob_callback": {
                "strategy": "oob_callback", "observable_effect": "a callback",
                "probe": [{"method": "POST", "path": "/f",
                           "body": "http://{{callback}}/{{marker}}"}],
            },
            "direct_observation": {
                "strategy": "direct_observation", "observable_effect": "a 200",
                "probe": [{"method": "GET", "path": "/a"}], "expect": {"status": 200},
            },
            # Its control is in time: answering before the payload and not
            # after, inside the one instance.
            "service_crash": {
                "strategy": "service_crash",
                "observable_effect": "the service stops answering",
                "baseline": [{"method": "GET", "path": "/health"}],
                "probe": [{"method": "POST", "path": "/render", "body": "boom"}],
            },
            # And its control is the same route with input that does not
            # trigger the blowup.
            "timing_differential": {
                "strategy": "timing_differential",
                "observable_effect": "the pathological input stalls the service",
                "probe": [{"method": "POST", "path": "/match", "body": "aaaaaaaa!"}],
                "control": [{"method": "POST", "path": "/match", "body": "aaaaaaaa"}],
            },
        }[strategy]
        with mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", side_effect=lambda c, n, d, e: f"cid-{n}"
        ), mock.patch.object(
            field, "_still_serving", return_value="127.0.0.1"
        ), mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given, host=None, disruptive=False:
                _run(observed, True),
        ):
            return field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(spec), 8000, Path("/lab"),
                ["docker", "compose"], {},
                {"lab_type": "VULNERABLE_ONLY_REPRODUCTION"},
            )

    def test_a_self_controlled_strategy_earns_the_handover(self) -> None:
        for strategy in field.SELF_CONTROLLED:
            with self.subTest(strategy=strategy):
                out = self._prove(strategy)
                self.assertIs(out["shipped"], True)
                self.assertIs(out["fixed_build_compared"], False)
                self.assertIs(out["proof_checks"]["control_is_in_the_strategy"], True)
                self.assertNotIn("silent_on_fixed", out["proof_checks"])

    def test_direct_observation_is_refused_without_a_fixed_build(self) -> None:
        """Its only check was the fixed build. On its own, "the route answered
        200" is the shape of proof that passed a lab on `existsSync` seeing a
        path with "..", which had to be rejected by hand."""
        out = self._prove("direct_observation")
        self.assertIs(out["shipped"], False)
        self.assertIn("no control of its own", out["reason"])
        self.assertIn("inband_differential", out["reason"])

    def test_the_effect_still_has_to_be_observed(self) -> None:
        out = self._prove("inband_differential", observed=False)
        self.assertIs(out["shipped"], False)
        self.assertIn("did not observe the effect", out["reason"])

    def test_only_the_vulnerable_service_is_asked_for(self) -> None:
        seen: list[str] = []
        with mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container",
            side_effect=lambda c, n, d, e: (seen.append(n), f"cid-{n}")[1],
        ), mock.patch.object(
            field, "_still_serving", return_value="127.0.0.1"
        ), mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given, host=None, disruptive=False:
                _run(True, True),
        ):
            field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8000, Path("/lab"),
                ["docker", "compose"], {},
                {"lab_type": "VULNERABLE_ONLY_REPRODUCTION"},
            )
        self.assertEqual(seen, ["vulnerable"])

    def test_the_guide_says_the_evidence_is_weaker(self) -> None:
        """A report should not read as if a patch was shown to remove it."""
        guide = field._remote_mode_note(
            "CVE-2026-0001", field.validate_spec(_spec()),
            {"lab_type": "VULNERABLE_ONLY_REPRODUCTION", "repository": "r"}, 8000,
        )
        self.assertIn("no fixed revision to compare against", guide)
        self.assertIn("weaker evidence", guide)
        self.assertIn("not that a fix removes it", guide)
        with_fix = field._remote_mode_note(
            "CVE-2026-0001", field.validate_spec(_spec()), {"repository": "r"}, 8000,
        )
        self.assertIn("stayed silent on the fixed one", with_fix)
        self.assertNotIn("weaker evidence", with_fix)

    def test_the_header_says_which_mode_reaches_a_live_server(self) -> None:
        """The one fact a reader taking this to a client needs first.

        The two scripts both opened with the identical line
        `# <CVE> Manual PoC`, so neither the heading, the filename nor the
        first paragraph told the reader which of the two could be pointed at a
        live server. There is one file now, and the first thing in it is which
        of its two modes does.
        """
        header = field._poc_header(
            "CVE-2026-0001",
            {"repository": "r", "lab_type": "SOURCE_REPRODUCTION"},
            {"shipped": True, "container_port": 8000,
             "spec": field.validate_spec(_spec())},
            field.POC_SHIPPED,
        )
        flat = " ".join(header.split())

        self.assertIn("Two modes, and the argument chooses.", flat)
        self.assertLess(flat.index("LAB MODE"), flat.index("REMOTE MODE"))
        self.assertIn("REMOTE MODE -- one instance whose address you supply", flat)
        self.assertIn("by Compose service name -- `vulnerable` and `patched`", flat)
        self.assertIn("shows nothing about any other host", flat)

    def test_the_header_does_not_credit_one_build_with_a_second(self) -> None:
        """A vulnerable-only lab has one build for lab mode to reach.

        Saying "two Docker builds" there would promise a differential that
        the trust section further down explicitly denies, in the same file.
        """
        header = field._poc_header(
            "CVE-2026-0001",
            {"repository": "r", "lab_type": "VULNERABLE_ONLY_REPRODUCTION"},
            {"shipped": True, "container_port": 8000,
             "spec": field.validate_spec(_spec())},
            field.POC_SHIPPED,
        )
        flat = " ".join(header.split())

        self.assertIn("this lab's own one Docker build", flat)
        self.assertIn("by Compose service name -- `vulnerable` --", flat)
        self.assertNotIn("two Docker builds", flat)
        self.assertNotIn("`patched`", flat)


class EvidenceLabelTests(unittest.TestCase):
    """One line a reader can take at face value.

    A fixed build answers what a single observation cannot -- is this the bug
    or is it how the thing always behaves -- so a run with one and a run
    without must not read the same.
    """

    def test_the_four_outcomes_read_differently(self) -> None:
        said = {
            core.evidence_label("SOURCE_REPRODUCTION", True, False),
            core.evidence_label("SOURCE_REPRODUCTION", True, True),
            core.evidence_label("VULNERABLE_ONLY_REPRODUCTION", True, False),
            core.evidence_label("VULNERABLE_ONLY_REPRODUCTION", True, True),
        }
        self.assertEqual(len(said), 4)

    def test_a_missing_fixed_build_is_stated_not_implied(self) -> None:
        for poc in (False, True):
            with self.subTest(manual_poc=poc):
                label = core.evidence_label("VULNERABLE_ONLY_REPRODUCTION", True, poc)
                self.assertIn("no fixed build available", label)
                self.assertNotIn("differential", label)

    def test_a_differential_run_says_so(self) -> None:
        label = core.evidence_label("END_TO_END_REPRODUCTION", True, False)
        self.assertIn("differential against the fixed build", label)
        self.assertNotIn("no fixed build", label)

    def test_the_poc_clause_says_proven_not_provided(self) -> None:
        """The script is only written after it earned it, which is the whole
        difference between it and a script found in the wild."""
        for lab_type in ("SOURCE_REPRODUCTION", "VULNERABLE_ONLY_REPRODUCTION"):
            with self.subTest(lab_type=lab_type):
                self.assertTrue(
                    core.evidence_label(lab_type, True, True).endswith(
                        ", manual PoC proven"
                    )
                )
                self.assertNotIn(
                    "manual PoC", core.evidence_label(lab_type, True, False)
                )

    def test_it_carries_none_of_the_internal_lab_shape_names(self) -> None:
        """A report reader has no idea what VULNERABLE_ONLY means."""
        for lab_type in ("SOURCE_REPRODUCTION", "VULNERABLE_ONLY_REPRODUCTION"):
            for poc in (False, True):
                label = core.evidence_label(lab_type, True, poc).lower()
                self.assertNotIn("vulnerable_only", label)
                self.assertNotIn("reproduction", label)

    def test_a_failed_run_claims_nothing(self) -> None:
        for lab_type in ("SOURCE_REPRODUCTION", "VULNERABLE_ONLY_REPRODUCTION"):
            self.assertEqual(core.evidence_label(lab_type, False, False), "Not reproduced")
            # not even when a PoC somehow exists
            self.assertEqual(core.evidence_label(lab_type, False, True), "Not reproduced")

    def test_the_report_carries_it(self) -> None:
        source = Path(core.__file__).read_text(encoding="utf-8")
        self.assertIn('"evidence_label": evidence_label(', source)


class ProvenSpecIsReusedTests(unittest.TestCase):
    """Asking twice for the same lab gives the same answer.

    A drafted spec is sampled, and nothing remembered the one that earned the
    handover: it existed only embedded in the generated script. So a lab that
    produced a script one day could refuse the next with nothing having
    changed, which is the one piece of this instability that is ours.
    """

    def _record(self, lab_dir: Path, legacy: bool = False, **extra: Any) -> None:
        held = {"cve": "CVE-2026-0001", "shipped": True, "container_port": 8000,
                "spec": field.validate_spec(_spec())}
        held.update(extra)
        if legacy:
            # Where an archived lab kept it. Read, never written.
            artifacts = lab_dir / "artifacts"
            artifacts.mkdir(exist_ok=True)
            (artifacts / field.LEGACY_MANUAL_POC_RECORD_NAME).write_text(
                json.dumps(held)
            )
            return
        report = json.loads((lab_dir / "report.json").read_text())
        report["manual_poc_field"] = held
        (lab_dir / "report.json").write_text(json.dumps(report))

    def test_a_proven_spec_comes_back(self) -> None:
        with _lab() as lab_dir:
            self._record(lab_dir)
            found = field._proven_spec(lab_dir)
        self.assertIsNotNone(found)
        self.assertEqual(found[1], 8000)
        self.assertEqual(found[0]["strategy"], "inband_differential")

    def test_a_refusal_is_not_reused(self) -> None:
        """Only a spec that passed the proof is worth repeating."""
        with _lab() as lab_dir:
            self._record(lab_dir, shipped=False)
            self.assertIsNone(field._proven_spec(lab_dir))

    def test_an_unusable_or_missing_record_is_ignored(self) -> None:
        for extra in ({"spec": {"strategy": "nonsense"}}, {"container_port": "8000"},
                      {"spec": None}):
            with self.subTest(extra=extra), _lab() as lab_dir:
                self._record(lab_dir, **extra)
                self.assertIsNone(field._proven_spec(lab_dir))
        with _lab() as lab_dir:
            (lab_dir / "artifacts").mkdir(exist_ok=True)
            (lab_dir / "artifacts" / field.LEGACY_MANUAL_POC_RECORD_NAME).write_text(
                "{not json"
            )
            self.assertIsNone(field._proven_spec(lab_dir))

    def test_reuse_asks_the_model_nothing(self) -> None:
        with _lab() as lab_dir, mock.patch.object(
            field, "prepare_compose",
            return_value=("docker", {}, ["docker", "compose"], lab_dir.parent / "s"),
        ), mock.patch.object(field, "_resolved_compose", return_value={}), \
             mock.patch.object(field, "_bring_up"), \
             mock.patch.object(field.subprocess, "run",
                               return_value=subprocess.CompletedProcess(["d"], 0, "", "")), \
             mock.patch.object(field, "draft_manual_poc_spec") as drafted, \
             mock.patch.object(
                 field, "prove_manual_poc",
                 return_value={"shipped": True, "proof_checks": {}, "runs": {},
                               "script": "#!/usr/bin/env python3\n"},
             ):
            (lab_dir.parent / "s").mkdir(exist_ok=True)
            self._record(lab_dir)
            result = field.run_manual_poc(lab_dir)
        drafted.assert_not_called()
        self.assertIs(result["ok"], True)

    def test_redraft_asks_again(self) -> None:
        with _lab() as lab_dir, mock.patch.object(
            field, "prepare_compose",
            return_value=("docker", {}, ["docker", "compose"], lab_dir.parent / "s"),
        ), mock.patch.object(field, "_resolved_compose", return_value={}), \
             mock.patch.object(field, "_bring_up"), \
             mock.patch.object(field.subprocess, "run",
                               return_value=subprocess.CompletedProcess(["d"], 0, "", "")), \
             mock.patch.object(field, "ai_is_configured", return_value=True), \
             mock.patch.object(
                 field, "draft_manual_poc_spec",
                 return_value={"spec": field.validate_spec(_spec()), "container_port": 9000},
             ) as drafted, \
             mock.patch.object(
                 field, "prove_manual_poc",
                 return_value={"shipped": False, "reason": "x", "proof_checks": {}, "runs": {}},
             ):
            (lab_dir.parent / "s").mkdir(exist_ok=True)
            self._record(lab_dir)
            field.run_manual_poc(lab_dir, redraft=True)
        drafted.assert_called_once()

    def test_the_spec_is_written_only_when_it_shipped(self) -> None:
        with _lab() as lab_dir:
            outcome = {"shipped": True, "proof_checks": {}, "runs": {},
                       "script": "#!/usr/bin/env python3\n"}
            field.write_manual_poc("CVE-2026-0001", lab_dir, {},
                                   field.validate_spec(_spec()), 8000, outcome)
            held = _held(lab_dir)
            self.assertIn("spec", held)
            self.assertNotIn("attempted_spec", held)
        with _lab() as lab_dir:
            refused = {"shipped": False, "reason": "x"}
            field.write_manual_poc("CVE-2026-0001", lab_dir, {},
                                   field.validate_spec(_spec()), 8000, refused)
            held = _held(lab_dir)
            self.assertNotIn("spec", held)

    def test_a_refused_spec_is_kept_where_it_can_be_read(self) -> None:
        """Centrifugo: "did not tell the two builds apart" and nothing else.

        The lab's own PoC had the forged header working on the vulnerable
        build and rejected on the fixed one, so the finding was real and the
        manual script simply looked in the wrong place -- and the spec that
        looked there was gone, so there was nothing to correct.
        """
        with _lab() as lab_dir:
            refused = {"shipped": False, "reason": "did not tell them apart"}
            field.write_manual_poc("CVE-2026-0001", lab_dir, {},
                                   field.validate_spec(_spec()), 8000, refused)
            held = _held(lab_dir)
            self.assertEqual(held["attempted_spec"]["strategy"], "inband_differential")
            # Kept to be read, not to be repeated.
            self.assertIsNone(field._proven_spec(lab_dir))


class ServiceWentAwayTests(unittest.TestCase):
    """A service that stopped is named, not reported as an absent effect.

    Storybook 10.6.1 answered the readiness probe and then stopped before its
    turn came, twice, while the fixed build served both runs. The proof said
    "did not finish against both builds" -- true, and useless for working out
    what to do about it.
    """

    def _prove(self, serving: dict[str, bool]) -> dict[str, Any]:
        with mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", side_effect=lambda c, n, d, e: f"cid-{n}"
        ), mock.patch.object(
            field, "_still_serving",
            side_effect=lambda cid, port: "127.0.0.1" if serving[cid] else ""
        ), mock.patch.object(
            field, "_container_logs", return_value="killed: out of memory"
        ), mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given, host=None, disruptive=False:
                _run(True, True),
        ):
            return field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8000, Path("/lab"),
                ["docker", "compose"], {},
            )

    def test_the_service_that_stopped_is_named(self) -> None:
        out = self._prove({"cid-vulnerable": False, "cid-patched": True})
        self.assertIs(out["shipped"], False)
        self.assertIn("vulnerable service stopped answering", out["reason"])
        self.assertIn("port 8000", out["reason"])

    def test_its_logs_come_with_it(self) -> None:
        """A stop that needs explaining is explained by what the service said."""
        out = self._prove({"cid-vulnerable": False, "cid-patched": True})
        self.assertIn("out of memory", out["service_logs"]["vulnerable"])

    def test_the_fixed_build_going_away_is_caught_too(self) -> None:
        out = self._prove({"cid-vulnerable": True, "cid-patched": False})
        self.assertIn("patched service stopped answering", out["reason"])

    def test_nothing_is_run_against_a_service_that_went_away(self) -> None:
        """Running it anyway is how a dead target became a clean bill."""
        ran: list[str] = []
        with mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", side_effect=lambda c, n, d, e: f"cid-{n}"
        ), mock.patch.object(
            field, "_still_serving",
            side_effect=lambda cid, port: "" if cid == "cid-vulnerable" else "127.0.0.1"
        ), mock.patch.object(field, "_container_logs", return_value=""), \
             mock.patch.object(
                 field, "_run_field_script",
                 side_effect=lambda cid, *a: ran.append(cid) or _run(True, True),
             ):
            field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8000, Path("/lab"),
                ["docker", "compose"], {},
            )
        self.assertEqual(ran, [])

    def test_both_serving_proceeds_as_before(self) -> None:
        out = self._prove({"cid-vulnerable": True, "cid-patched": True})
        self.assertIn("proof_checks", out)
        self.assertNotIn("service_logs", out)


class ServiceLogsAreReadableTests(unittest.TestCase):
    """A dev server's output is mostly colour. The first time these logs were
    read for a real stop, the one useful line was buried in escape codes."""

    def test_colour_and_cursor_control_are_stripped(self) -> None:
        noisy = (
            "\x1b[38;2;255;71;133m─\x1b[39m\x1b[90m│\x1b[39m\n"
            "\x1b[34m●\x1b[39m  124 ms for manager\n"
            "\x1b[33m▲\x1b[39m  Change detection unavailable: git is not available\n"
        )
        with mock.patch.object(field, "_docker", return_value=noisy):
            said = field._container_logs("cid")
        self.assertNotIn("\x1b", said)
        self.assertIn("124 ms for manager", said)
        self.assertIn("git is not available", said)

    def test_blank_lines_left_by_stripping_are_dropped(self) -> None:
        with mock.patch.object(
            field, "_docker", return_value="\x1b[90m\x1b[39m\n\nreal line\n\x1b[90m\x1b[39m\n"
        ):
            self.assertEqual(field._container_logs("cid"), "real line")

    def test_it_is_bounded(self) -> None:
        with mock.patch.object(field, "_docker", return_value="x" * 10000):
            self.assertLessEqual(len(field._container_logs("cid", limit=500)), 500)


class SampledSpecGetsASecondAskTests(unittest.TestCase):
    """A spec that failed the proof is asked for again, once.

    Centrifugo reproduced a forged-header auth bypass on one build and
    rejected it on the other, and the first spec drawn for it observed
    nothing on either -- it reached ws:// with no path, where the service
    serves /connection/websocket. Asked again, for the same lab and the same
    model, the second spec named the path and proved it. The demonstration
    was there; one sample lost it.
    """

    def _failed(self, **extra: Any) -> dict[str, Any]:
        outcome = {
            "shipped": False,
            "reason": "the script did not tell the two builds apart",
            "proof_checks": {"manual_poc_proven": False},
            "runs": {},
            "spec_at_fault": True,
            "output": {"vulnerable": {"stderr": "0 finding(s)", "tail": "NOT_OBSERVED"}},
        }
        outcome.update(extra)
        return outcome

    def _shipped(self) -> dict[str, Any]:
        return {"shipped": True, "proof_checks": {"manual_poc_proven": True},
                "runs": {}, "script": "#!/usr/bin/env python3\n"}

    def _prove(self, outcomes: list[dict[str, Any]], drafts: Any) -> Any:
        with _lab() as lab_dir, mock.patch.object(
            field, "prove_manual_poc", side_effect=outcomes,
        ) as proved, mock.patch.object(
            field, "draft_manual_poc_spec", side_effect=drafts,
        ) as drafted:
            spec, port, outcome = field._prove_drafted_spec(
                "CVE-2026-0001", {},
                {"spec": field.validate_spec(_spec()), "container_port": 8000,
                 "lab_values": {"account": "seeded-user"}},
                lab_dir, ["docker", "compose"], {}, True, None,
                api_key="k", model="m", provider="anthropic", base_url=None,
            )
        return spec, port, outcome, proved, drafted

    def test_a_second_spec_is_proved_and_can_ship(self) -> None:
        # The spec that worked on centrifugo, in shape: same finding, same
        # transport, the path the service actually serves.
        second = field.validate_spec({
            "strategy": "direct_observation",
            "transport": "ws",
            "observable_effect": "a connect reply whose data has principal admin",
            "ws_path": "/connection/websocket",
            "probe": [{"send": '{"id":1,"connect":{"headers":{"X-Trusted-User":"admin"}}}',
                       "read_until": "\n"}],
            "expect": {"body_contains": "forwarded-header"},
        })
        spec, port, outcome, proved, drafted = self._prove(
            [self._failed(), self._shipped()],
            [{"spec": second, "container_port": 9000}],
        )
        self.assertIs(outcome["shipped"], True)
        self.assertEqual(spec["ws_path"], "/connection/websocket")
        self.assertEqual(port, 9000)
        self.assertEqual(proved.call_count, 2)
        # What the first script printed goes with the request: "did not tell
        # them apart" alone is not enough to write a different spec with.
        complaint = drafted.call_args.kwargs["complaint"]
        self.assertIn("did not tell the two builds apart", complaint)
        self.assertIn("0 finding(s)", complaint)

    def test_what_the_spec_could_not_have_caused_is_not_retried(self) -> None:
        """A stopped service would sample a new answer against the same wall."""
        stopped = {"shipped": False, "runs": {},
                   "reason": "the vulnerable service stopped answering on port 8000"}
        _, _, outcome, proved, drafted = self._prove([stopped], [])
        self.assertEqual(proved.call_count, 1)
        drafted.assert_not_called()
        self.assertIn("stopped answering", outcome["reason"])

    def test_the_measured_failure_is_kept_when_the_second_ask_gives_nothing(self) -> None:
        first = self._failed()
        _, _, outcome, proved, drafted = self._prove(
            [first], [{"reason": "the effect is a worker crash"}],
        )
        # The run that failed used the lab's values, so the record keeps them:
        # without this a refusal came back saying inputs were never filled.
        self.assertEqual(outcome.get("lab_values"), {"account": "seeded-user"})
        self.assertEqual(proved.call_count, 1)
        drafted.assert_called_once()
        # A judgement about the finding does not outrank a run against it.
        self.assertIn("did not tell the two builds apart", outcome["reason"])
        self.assertIn("vulnerable", outcome["output"])

    def test_the_retry_flag_stays_out_of_the_record(self) -> None:
        with _lab() as lab_dir:
            _, _, outcome, _, _ = self._prove([self._failed(), self._failed()], [
                {"spec": field.validate_spec(_spec()), "container_port": 8000},
            ])
            self.assertNotIn("spec_at_fault", outcome)
            field.write_manual_poc("CVE-2026-0001", lab_dir, {},
                                   field.validate_spec(_spec()), 8000, outcome)
            held = _held(lab_dir)
        self.assertNotIn("spec_at_fault", held)

    def test_asking_can_be_switched_off(self) -> None:
        with mock.patch.object(field, "_draft_retries", return_value=0):
            _, _, outcome, proved, drafted = self._prove([self._failed()], [])
        self.assertEqual(proved.call_count, 1)
        drafted.assert_not_called()
        self.assertIs(outcome["shipped"], False)

    def test_a_failed_proof_says_the_spec_was_at_fault(self) -> None:
        """The marker _prove_drafted_spec reads is set where the proof is run."""
        with _lab() as lab_dir, mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", return_value="cid",
        ), mock.patch.object(field, "_still_serving", return_value="127.0.0.1"), \
             mock.patch.object(field.sidecar, "ensure_image", return_value="img"), \
             mock.patch.object(
                 field, "_run_field_script",
                 return_value=_run(observed=False, ran=True),
             ):
            outcome = field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8000, lab_dir,
                ["docker", "compose"], {}, {}, True, None,
            )
        self.assertIs(outcome["shipped"], False)
        self.assertIs(outcome["spec_at_fault"], True)


class ExpectationMustBeAbleToFireTests(unittest.TestCase):
    """An expectation the transport cannot produce is a spec error.

    A socket exchange returns a transcript and no status line. A spec
    expecting a status over tcp would run, read exactly the right bytes and
    report nothing -- which reads as the effect being absent, and sends the
    operator looking for a vulnerability that was there all along.
    """

    def _ws(self, expect: dict[str, Any]) -> dict[str, Any]:
        return {
            "strategy": "direct_observation",
            "transport": "ws",
            "observable_effect": "a reply naming a principal the caller never proved",
            "ws_path": "/connection/websocket",
            "probe": [{"send": '{"id":1}', "read_until": "\n"}],
            "expect": expect,
        }

    def test_a_status_or_header_over_a_socket_is_refused(self) -> None:
        for transport in ("tcp", "tls", "ssh", "smb"):
            for expect in ({"status": 200}, {"header": "X-Who"}):
                spec = self._ws(expect)
                spec["transport"] = transport
                if transport not in field.WS_TRANSPORTS:
                    spec.pop("ws_path")
                if transport == "ssh":
                    spec["probe"] = [{"exec": "id"}]
                elif transport == "smb":
                    spec["probe"] = [{"op": "list_shares"}]
                with self.subTest(transport=transport, expect=expect):
                    with self.assertRaises(ValueError) as refused:
                        field.validate_spec(spec)
                    self.assertIn("http, ws or wss", str(refused.exception))

    def test_an_extractor_hides_nothing(self) -> None:
        """{"extract": {"status": true}} reads the same absent status line."""
        spec = self._ws(expect={"extract": {"status": True}})
        spec["transport"] = "tcp"
        spec.pop("ws_path")
        with self.assertRaises(ValueError) as refused:
            field.validate_spec(spec)
        self.assertIn("http, ws or wss", str(refused.exception))

    def test_the_websocket_handshake_is_a_response_and_keeps_both(self) -> None:
        """An Origin check's whole finding is that the upgrade was accepted."""
        for expect in ({"status": 101}, {"header": "Sec-WebSocket-Accept"}):
            with self.subTest(expect=expect):
                spec = field.validate_spec(self._ws(expect))
                self.assertEqual(spec["checks"][0]["expect"], expect)

    def test_the_bytes_are_what_a_socket_matches_on(self) -> None:
        for expect in ({"body_contains": "forwarded-header"},
                       {"extract": {"json_values": "principal"}}):
            with self.subTest(expect=expect):
                spec = field.validate_spec(self._ws(expect))
                self.assertEqual(spec["checks"][0]["expect"], expect)

    def test_http_still_takes_a_status_and_a_header(self) -> None:
        for expect in ({"status": 401}, {"header": "X-Debug-User"}):
            with self.subTest(expect=expect):
                spec = field.validate_spec({
                    "strategy": "direct_observation",
                    "observable_effect": "a route that answers where it should refuse",
                    "probe": [{"method": "GET", "path": "/admin"}],
                    "expect": expect,
                })
                self.assertEqual(spec["checks"][0]["expect"], expect)


class PromptSaysWhatTheValidatorAcceptsTests(unittest.TestCase):
    """The spec vocabulary and the instructions that ask for it stay together.

    Each absence was paid for. A write was refused as "state-changing" when
    marker_roundtrip is the strategy for exactly that; a discover step's
    binding key had to be guessed, because the prose said "bind it" and never
    named `bind`; a status expectation was describable over a socket, where
    there is no status line to read it from.
    """

    def test_every_key_a_spec_may_carry_is_described(self) -> None:
        for key in (
            "strategy", "transport", "observable_effect", "inputs", "auth",
            "ws_path", "ws_headers", "checks", "label", "discover", "bind",
            "derive", "query", "extract", "probe", "control", "observe",
            "match", "expect", "health_timeout", "send", "send_hex",
            "read_until", "container_port", "body_contains", "json_values",
            # A crafted upload was the one thing a spec could not say, and
            # three labs were refused over it.
            "setup", "upload", "filename", "content_type", "tar_gz", "zip",
            "base64", "lab_values_json",
        ):
            with self.subTest(key=key):
                self.assertIn(key, field._DRAFT_INSTRUCTIONS)

    def test_every_name_the_validator_will_accept_is_offered(self) -> None:
        names = (
            field.STRATEGIES + field.TRANSPORTS + field.SMB_OPS + field.EXPECTATIONS
            # Two refusals in one afternoon said a value could not be pulled
            # out of HTML or out of a URL, because the instructions showed
            # json_values where the validator takes any of the four.
            + field.EXTRACTORS
            + tuple(sorted({f for fields in field.AUTH_FIELDS.values() for f in fields}))
        )
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, field._DRAFT_INSTRUCTIONS)

    def test_the_tokens_a_spec_may_place_are_described(self) -> None:
        for token in (field._MARKER_TOKEN, field._CALLBACK_TOKEN,
                      *(f"{{{{{name}}}}}" for name in field._TARGET_TOKENS)):
            with self.subTest(token=token):
                self.assertIn(token, field._DRAFT_INSTRUCTIONS)

    def test_the_contract_only_key_is_not_offered(self) -> None:
        """A fixture seeds a contract run, and this proof never applies one.

        validate_spec accepts it, because the same validator serves the
        closed-source contract flow. Asking a draft for one would get a spec
        that depends on state nothing seeds, and the proof would read the
        absence as the effect being absent.
        """
        self.assertNotIn("fixture", field._DRAFT_INSTRUCTIONS)


class LabValuesLetAnInputSpecBeProvedTests(unittest.TestCase):
    """A spec that asks the operator for a value can still be proved here.

    Three labs in one afternoon drafted a correct spec and shipped nothing:
    "this spec needs values only you have: protected_id, target_id,
    target_key". Declaring an input is the right answer whenever the effect
    acts on an object or an account the operator owns -- and the lab knows
    its own equivalents, because its validator uses them.
    """

    def _answer(self, values: Any) -> dict[str, Any]:
        spec = _spec(inputs=["account"], probe=[{"method": "GET", "path": "/u/{{account}}"}])
        with mock.patch.object(field, "structured_response", return_value={
            "feasible": True, "reason": "", "container_port": 8000,
            "spec_json": json.dumps(spec), "lab_values_json": values,
        }):
            return field.draft_manual_poc_spec(
                "CVE-2026-0001", {}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )

    def test_the_lab_s_own_values_come_back_with_the_spec(self) -> None:
        out = self._answer(json.dumps({"account": "seeded-user"}))
        self.assertEqual(out["lab_values"], {"account": "seeded-user"})

    def test_only_declared_names_survive_and_only_as_text(self) -> None:
        out = self._answer(json.dumps({
            "account": 41, "tenant": "not-declared", "blank": "", "deep": {"a": 1},
        }))
        self.assertEqual(out["lab_values"], {"account": "41"})

    def test_rubbish_is_no_reason_to_lose_the_spec(self) -> None:
        for offered in (None, "", "not json", json.dumps(["account"])):
            with self.subTest(offered=offered):
                out = self._answer(offered)
                self.assertIn("spec", out)
                self.assertEqual(out["lab_values"], {})

    def test_the_proof_uses_them_and_the_operator_still_wins(self) -> None:
        seen: list[dict[str, str] | None] = []

        def prove(*args: Any, **kwargs: Any) -> dict[str, Any]:
            seen.append(args[8])
            return {"shipped": True, "proof_checks": {}, "runs": {},
                    "script": "#!/usr/bin/env python3\n"}

        with _lab() as lab_dir, mock.patch.object(field, "prove_manual_poc", prove):
            field._prove_drafted_spec(
                "CVE-2026-0001", {},
                {"spec": field.validate_spec(_spec()), "container_port": 8000,
                 "lab_values": {"account": "seeded-user", "token": "lab"}},
                lab_dir, ["docker", "compose"], {}, True, {"token": "mine"},
                api_key="k", model="m", provider="anthropic", base_url=None,
            )
        self.assertEqual(seen[0], {"account": "seeded-user", "token": "mine"})

    def test_they_are_recorded_for_the_next_run_and_kept_out_of_the_report(self) -> None:
        with _lab() as lab_dir:
            spec = field.validate_spec(_spec(
                inputs=["account"], probe=[{"method": "GET", "path": "/u/{{account}}"}]
            ))
            outcome = {"shipped": True, "container_port": 8000, "proof_checks": {},
                       "runs": {}, "script": "#!/usr/bin/env python3\n",
                       "lab_values": {"account": "seeded-user"}}
            field.write_manual_poc("CVE-2026-0001", lab_dir, {}, spec, 8000, outcome)
            # They stay in the record, which is report.json now, because an
            # input spec cannot be re-proved without them -- and they travel
            # with it, which is the cost of the record travelling at all.
            # They are the lab's own: the route its adapter serves, the
            # account its setup created, and plan.json already ships the
            # contract that created them.
            self.assertEqual(_held(lab_dir)["lab_values"], {"account": "seeded-user"})
            # The script is still taken out: it is the one thing a report has
            # no business carrying, and it is on disk beside it.
            self.assertNotIn("script", outcome)
            held = field._proven_spec(lab_dir)
        self.assertIsNotNone(held)
        self.assertEqual(held[2], {"account": "seeded-user"})


class SetupPutsTheLabInTheStateTheEffectNeedsTests(unittest.TestCase):
    """The lab is empty, and a weakness needs something to act on.

    Payload drafted a correct spec -- discover the document its access rule
    protects, reorder it, expect 200 -- and found nothing on either build.
    The document exists only after the lab's own /lab/seed route is called,
    which its validator does and the manual proof did not. The same happened
    to a file-transfer lab whose effect needs an admin filter and a denied
    file. Both were recorded as "the script did not tell the two builds
    apart", which was true and nobody's fault but ours.
    """

    def _spec(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "observable_effect": "an unauthenticated reorder of a protected document",
            "setup": [{"method": "POST", "path": "/lab/seed",
                       "body": {"title": "Fixed position"}}],
            "probe": [{"method": "POST", "path": "/api/reorder"}],
            "expect": {"status": 200},
        }
        spec.update(extra)
        return spec

    def test_it_validates_and_keeps_the_requests(self) -> None:
        spec = field.validate_spec(self._spec())
        self.assertEqual(spec["setup"][0]["path"], "/lab/seed")
        # A JSON body is serialised the same way a probe's is.
        self.assertEqual(spec["setup"][0]["body"], '{"title": "Fixed position"}')

    def test_it_may_use_the_operator_s_inputs_and_nothing_else(self) -> None:
        spec = field.validate_spec(self._spec(
            inputs=["admin_auth"],
            setup=[{"method": "POST", "path": "/lab/seed",
                    "headers": {"Authorization": "{{admin_auth}}"}}],
        ))
        self.assertIn("{{admin_auth}}", json.dumps(spec["setup"]))
        with self.assertRaises(ValueError) as refused:
            field.validate_spec(self._spec(
                setup=[{"method": "POST", "path": "/lab/seed/{{whatever}}"}]
            ))
        self.assertIn("nothing binds", str(refused.exception))

    def test_a_long_list_is_a_workflow_and_not_a_precondition(self) -> None:
        with self.assertRaises(ValueError):
            field.validate_spec(self._spec(
                setup=[{"method": "GET", "path": f"/s/{i}"} for i in range(11)]
            ))
        with self.assertRaises(ValueError):
            field.validate_spec(self._spec(setup=[]))

    def test_the_deliverable_never_carries_it(self) -> None:
        """A script pointed at a real server must not call a seeding route."""
        script = field.emit_field_poc("CVE-2026-0001", field.validate_spec(self._spec()))
        self.assertNotIn("/lab/seed", script)
        self.assertNotIn("setup", json.loads(
            script.split('SPEC = json.loads(r"""', 1)[1].split('""")', 1)[0]
        ))

    def test_it_runs_against_both_builds_before_the_script(self) -> None:
        order: list[str] = []
        spec = field.validate_spec(self._spec())
        with _lab() as lab_dir, mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", side_effect=lambda c, name, d, e: f"cid-{name}",
        ), mock.patch.object(field, "_still_serving", return_value="127.0.0.1"), \
             mock.patch.object(field.sidecar, "ensure_image", return_value="img"), \
             mock.patch.object(
                 field, "_run_setup",
                 side_effect=lambda cid, *a, **k: (
                     order.append(f"setup:{cid}"), {"requests": [{"status": 201}]})[1],
             ), mock.patch.object(
                 field, "_run_field_script",
                 side_effect=lambda cid, *a, **k: (
                     order.append(f"script:{cid}"), _run(observed=cid.endswith("vulnerable"),
                                                         ran=True))[1],
             ):
            outcome = field.prove_manual_poc(
                "CVE-2026-0001", spec, 3000, lab_dir, ["docker", "compose"], {},
                {}, True, None,
            )
        self.assertEqual(order, ["setup:cid-vulnerable", "script:cid-vulnerable",
                                 "setup:cid-patched", "script:cid-patched"])
        self.assertIs(outcome["shipped"], True)
        # Readable in the record: the script was proved against seeded builds.
        self.assertEqual(set(outcome["setup_applied"]), {"vulnerable", "patched"})

    def test_a_setup_that_cannot_run_stops_the_proof(self) -> None:
        """An unseeded instance answers like a fixed one, so silence here lies."""
        with _lab() as lab_dir, mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", return_value="cid",
        ), mock.patch.object(field, "_still_serving", return_value="127.0.0.1"), \
             mock.patch.object(field.sidecar, "ensure_image", return_value="img"), \
             mock.patch.object(
                 field, "_run_setup",
                 side_effect=RuntimeError("setup did not run against this build: refused"),
             ), mock.patch.object(field, "_run_field_script") as ran:
            outcome = field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(self._spec()), 3000, lab_dir,
                ["docker", "compose"], {}, {}, True, None,
            )
        ran.assert_not_called()
        self.assertIs(outcome["shipped"], False)
        self.assertIn("setup did not run", outcome["reason"])

    def test_an_empty_discovery_tells_the_next_draft_what_it_means(self) -> None:
        """Payload's spec was right twice and repeated unchanged twice.

        "check spec: nothing to test on this target" was in front of the
        model both times, and nothing said that it meant the lab was
        unseeded.
        """
        said = field._spec_complaint({
            "reason": "the script did not tell the two builds apart",
            "output": {"vulnerable": {
                "stderr": "check    spec: nothing to test on this target\n0 finding(s)",
                "tail": "NOT_OBSERVED",
            }},
        })
        self.assertIn("the lab is empty", said)
        self.assertIn("setup", said)
        self.assertIn("keep the discovery step", said)
        # Nothing of the sort where the script did reach something.
        plain = field._spec_complaint({
            "reason": "x", "output": {"vulnerable": {"stderr": "0 finding(s)", "tail": ""}},
        })
        self.assertNotIn("the lab is empty", plain)

    def test_the_guide_says_a_silent_run_on_an_empty_target_proves_nothing(self) -> None:
        guide = field._remote_mode_note(
            "CVE-2026-0001", field.validate_spec(self._spec()), {"repository": "r"}, 3000
        )
        self.assertIn("started empty", guide)
        self.assertIn("nothing learned", guide)


class SlowStartIsWaitedForAndNamedTests(unittest.TestCase):
    """A lab that validated can still fail the proof's readiness probe.

    A lab declaring no healthcheck says nothing about how long its
    application takes, and its own validator does not need it to: PoC.py
    retries in a loop of its own. Storybook took more than four minutes to
    serve port 6006, and the proof gave up at 240s with "pass
    --container-port for the port the service listens on" -- which was not
    the problem and sent the next attempt looking in the wrong place.
    """

    def _bring_up(self, ready: bool, running: bool = True) -> str:
        with mock.patch.object(field, "run_docker_stage"), \
             mock.patch.object(field, "_lab_validator", return_value=_LAB_MODE), \
             mock.patch.object(field, "_service_container", return_value="cid"), \
             mock.patch.object(
                 field, "_reachable_address",
                 return_value="127.0.0.1" if ready else "") as waited, \
             mock.patch.object(field, "_is_running", return_value=running), \
             mock.patch.object(field, "_container_logs", return_value="webpack built"):
            try:
                field._bring_up(
                    ["vulnerable"], ["vulnerable"], 6006, 120, Path("/x"),
                    ["docker", "compose"], "docker", {}, {"services": {"vulnerable": {}}},
                )
            except RuntimeError as refused:
                self.waited = waited
                return str(refused)
        self.waited = waited
        return ""

    def test_a_service_with_no_healthcheck_gets_ten_minutes(self) -> None:
        self._bring_up(ready=True)
        self.assertEqual(self.waited.call_args.args[2], field._SLOW_START_TIMEOUT)
        self.assertGreater(field._SLOW_START_TIMEOUT, 240)

    def test_giving_up_names_the_cause_and_shows_the_output(self) -> None:
        said = self._bring_up(ready=False)
        self.assertIn("still running", said)
        self.assertIn("listens on another port", said)
        self.assertIn("webpack built", said)

    def test_a_container_that_died_is_not_called_slow(self) -> None:
        said = self._bring_up(ready=False, running=False)
        self.assertIn("no longer running", said)
        self.assertNotIn("slower than that", said)

    def test_a_spec_may_still_ask_for_longer(self) -> None:
        """health_timeout above the floor is the spec's own business."""
        with mock.patch.object(field, "run_docker_stage"), \
             mock.patch.object(field, "_lab_validator", return_value=_LAB_MODE), \
             mock.patch.object(field, "_service_container", return_value="cid"), \
             mock.patch.object(
                 field, "_reachable_address", return_value="127.0.0.1") as waited:
            field._bring_up(
                ["vulnerable"], ["vulnerable"], 6006, 1200, Path("/x"),
                ["docker", "compose"], "docker", {}, {"services": {"vulnerable": {}}},
            )
        self.assertEqual(waited.call_args.args[2], 1200)


class ServiceOnItsOwnInterfaceIsReachedTests(unittest.TestCase):
    """Not every service binds loopback, and the sidecar has to find it.

    Storybook 10.6.1 printed "Storybook ready! - Local:
    http://localhost:6006/" and listened on 172.18.0.2:6006 only. The probe
    knew one address, waited ten minutes, and reported a running, listening
    service as one that never came up -- then, on the attempt before that, as
    a wrong --container-port.
    """

    def _probe(self, answers: dict[str, bool], addresses: str) -> tuple[str, list[str]]:
        asked: list[str] = []

        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            hosts = argv[argv.index(field._PORT_READY) + 3:]
            asked.extend(hosts)
            found = [host for host in hosts if answers.get(host)]
            return subprocess.CompletedProcess(
                argv, 0 if found else 1, (found[0] + "\n") if found else "", ""
            )

        with mock.patch.object(field, "_container_address", return_value=addresses), \
             mock.patch.object(field, "runtime_flags", return_value=[]), \
             mock.patch.object(field.subprocess, "run", side_effect=run):
            return field._reachable_address("cid", 6006, 30), asked

    def test_loopback_is_tried_first_and_wins_when_it_answers(self) -> None:
        where, asked = self._probe({"127.0.0.1": True, "172.18.0.2": True}, "172.18.0.2")
        self.assertEqual(where, "127.0.0.1")
        self.assertEqual(asked[0], "127.0.0.1")

    def test_the_container_s_own_address_is_tried_too(self) -> None:
        where, asked = self._probe({"172.18.0.2": True}, "172.18.0.2")
        self.assertEqual(where, "172.18.0.2")
        self.assertIn("172.18.0.2", asked)

    def test_every_network_the_container_is_on_is_offered(self) -> None:
        where, asked = self._probe({"10.1.0.9": True}, "172.18.0.2 10.1.0.9")
        self.assertEqual(where, "10.1.0.9")
        self.assertEqual(asked, ["127.0.0.1", "172.18.0.2", "10.1.0.9"])

    def test_nothing_answering_is_an_empty_address(self) -> None:
        where, _ = self._probe({}, "172.18.0.2")
        self.assertEqual(where, "")

    def test_the_script_is_pointed_at_what_answered(self) -> None:
        sent: list[str] = []

        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            sent.extend(a for a in argv if a.startswith("CVELAB_BASE="))
            return subprocess.CompletedProcess(argv, 0, "OBSERVED", "")

        with mock.patch.object(field, "runtime_flags", return_value=[]), \
             mock.patch.object(field.subprocess, "run", side_effect=run):
            field._run_field_script("cid", 6006, "x", "http", "img", None, "172.18.0.2")
            field._run_setup("cid", 6006, [{"method": "POST", "path": "/s"}],
                             "img", None, "172.18.0.2")
        self.assertEqual(sent, ["CVELAB_BASE=http://172.18.0.2:6006"] * 2)


class BlindRunThatHeardNothingSaysSoTests(unittest.TestCase):
    """For a callback strategy, "did not tell them apart" means one thing.

    9router's SSRF was real and the drafted spec was right in principle: a
    region value pointing at the script's listener, with the marker in the
    path. Nothing arrived, because the lab replaced global fetch with an
    in-process recorder and sent no traffic at all -- which it disclosed in
    its own fidelity record. The proof said the script did not tell the two
    builds apart, which was true and told nobody that the lab had no network
    for the callback to come back over.
    """

    def _prove(self, strategy: str, observed: tuple[bool, bool]) -> dict[str, Any]:
        spec = field.validate_spec({
            "strategy": strategy,
            "observable_effect": "the target fetches a URL the caller chose",
            "probe": [{"method": "POST", "path": "/r",
                       "body": {"region": "{{callback}}/{{marker}}"}}],
        } if strategy == "oob_callback" else _spec())
        with _lab() as lab_dir, mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", side_effect=lambda c, name, d, e: f"cid-{name}",
        ), mock.patch.object(field, "_still_serving", return_value="127.0.0.1"), \
             mock.patch.object(field.sidecar, "ensure_image", return_value="img"), \
             mock.patch.object(
                 field, "_run_field_script",
                 side_effect=lambda cid, *a, **k: _run(
                     observed=observed[0] if cid.endswith("vulnerable") else observed[1],
                     ran=True,
                 ),
             ):
            return field.prove_manual_poc(
                "CVE-2026-0001", spec, 3000, lab_dir, ["docker", "compose"], {},
                {}, True, None,
            )

    def test_a_blind_run_with_no_hit_names_the_listener(self) -> None:
        outcome = self._prove("oob_callback", (False, False))
        self.assertIn("nothing reached the script's own listener", outcome["reason"])
        self.assertIn("outbound request", outcome["reason"])

    def test_a_hit_on_both_builds_is_still_ordinary_behaviour(self) -> None:
        outcome = self._prove("oob_callback", (True, True))
        self.assertIn("did not tell the two builds apart", outcome["reason"])

    def test_another_strategy_keeps_the_general_wording(self) -> None:
        outcome = self._prove("inband_differential", (False, False))
        self.assertIn("did not tell the two builds apart", outcome["reason"])


class DraftOnlyTests(unittest.TestCase):
    """One model call against a lab on disk, and nothing else.

    The loop for working on the instructions was a whole `auto` run -- clone,
    research, build, repair, validate, twenty minutes and a dollar -- to see
    what one sentence changed about one answer. Most of what went wrong was
    visible in the drafted spec alone: a name nothing bound, a probe with no
    send, a strategy whose channel the lab had replaced.
    """

    def _draft(self, answer: dict[str, Any]) -> dict[str, Any]:
        with _lab() as lab_dir, mock.patch.object(
            field, "draft_manual_poc_spec", return_value=answer,
        ) as asked, mock.patch.object(field, "ai_is_configured", return_value=True), \
             mock.patch.object(field, "prepare_compose") as prepared, \
             mock.patch.object(field, "prove_manual_poc") as proved:
            out = field.draft_only(lab_dir, api_key="k", model="m", provider="anthropic")
            # Without the lab, the draft is asked with no validator source and
            # no port: the single most informative thing it is ever given, and
            # the first sweep taken with this command ran blind for want of
            # one keyword.
            self.assertEqual(asked.call_args.kwargs["lab_dir"], lab_dir.resolve())
            self.assertEqual(out["lab_dir"], str(lab_dir.resolve()))
            # Nothing is built, started or proved.
            prepared.assert_not_called()
            proved.assert_not_called()
            self.assertFalse((lab_dir / "artifacts" / field.POC_NAME).exists())
            self.assertEqual(_held(lab_dir), {})
        return out

    def test_a_usable_answer_comes_back_normalised(self) -> None:
        out = self._draft({
            "spec": field.validate_spec(_spec()), "container_port": 8000,
            "lab_values": {"account": "seeded"},
        })
        self.assertIs(out["ok"], True)
        self.assertIs(out["proved"], False)
        self.assertEqual(out["strategy"], "inband_differential")
        self.assertEqual(out["transport"], "http")
        self.assertEqual(out["container_port"], 8000)
        self.assertEqual(out["lab_values"], {"account": "seeded"})
        self.assertEqual(len(out["spec"]["checks"]), 1)

    def test_a_refusal_comes_back_with_its_reason(self) -> None:
        out = self._draft({"reason": "the effect is a worker crash"})
        self.assertIs(out["ok"], False)
        self.assertIn("worker crash", out["reason"])

    def test_it_says_nothing_was_proved(self) -> None:
        """So a draft taken this way is never mistaken for one that held up."""
        out = self._draft({"spec": field.validate_spec(_spec()), "container_port": 8000})
        self.assertIn("nothing was run against the lab", out["note"])

    def test_no_model_is_an_error_rather_than_an_empty_answer(self) -> None:
        with _lab() as lab_dir, mock.patch.object(
            field, "ai_is_configured", return_value=False,
        ):
            with self.assertRaises(RuntimeError) as refused:
                field.draft_only(lab_dir)
        self.assertIn("Configure a model", str(refused.exception))


class PortHintReadsTheValidatorTooTests(unittest.TestCase):
    """The validator always states the port, whatever else the lab omits.

    An sftpgo lab declared no healthcheck and no EXPOSE, so the hint was
    None and the draft had to guess a port -- and a spec with no port is
    thrown away. The only mention of 8080 in the whole lab was the
    validator's own SERVICES = {'vulnerable': 'http://vulnerable:8080', ...},
    which is unavoidable: the validator has to reach the service to prove
    anything.
    """

    def _hint(self, files: dict[str, str]) -> int | None:
        with _lab() as lab_dir:
            for name, text in files.items():
                path = lab_dir / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            return field._port_hint(lab_dir)

    def test_a_service_url_in_the_validator_is_enough(self) -> None:
        self.assertEqual(self._hint({
            "validator/validator.py":
                "SERVICES = {'vulnerable': 'http://vulnerable:8080', "
                "'patched': 'http://patched:8080'}\n",
        }), 8080)

    def test_a_port_constant_is_enough(self) -> None:
        self.assertEqual(
            self._hint({"validator/validator.py": "PORT = 6006\nX = 1\n"}), 6006
        )

    def test_the_healthcheck_still_comes_first(self) -> None:
        """It is the lab's own statement of where to reach the application."""
        self.assertEqual(self._hint({
            "docker-compose.yml": "    test: curl http://127.0.0.1:9000/health\n",
            "validator/validator.py": "PORT = 6006\n",
        }), 9000)

    def test_nothing_anywhere_is_still_nothing(self) -> None:
        self.assertIsNone(self._hint({"validator/validator.py": "X = 1\n"}))
        self.assertIsNone(self._hint({}))

    def test_a_nonsense_port_is_not_taken(self) -> None:
        self.assertIsNone(self._hint({"validator/validator.py": "PORT = 99999\n"}))


class RecordedSpecsKeepValidatingTests(unittest.TestCase):
    """Every spec the model has actually written stays valid input.

    A fixture of real answers, not invented ones: validate_spec is the gate
    the drafts have to pass, and a change to it that quietly refuses a shape
    the model already writes costs a demonstration with nothing failing in
    the suite. Twice now a normalised spec stopped being valid input to the
    same function -- auth: {} once, ws_path: "/" the next time -- and only a
    round trip caught it.
    """

    def _recorded(self) -> list[tuple[str, dict[str, Any]]]:
        held = Path(__file__).parent / "fixtures" / "recorded-specs.json"
        return [(row["from"], row["spec"]) for row in json.loads(held.read_text())]

    def test_the_fixture_holds_what_was_actually_written(self) -> None:
        rows = self._recorded()
        self.assertGreaterEqual(len(rows), 8)
        self.assertEqual(
            {spec["strategy"] for _, spec in rows} - set(field.STRATEGIES), set()
        )

    def test_each_one_still_validates(self) -> None:
        for where, spec in self._recorded():
            with self.subTest(spec=where):
                field.validate_spec(spec)

    def test_each_one_survives_a_round_trip(self) -> None:
        for where, spec in self._recorded():
            with self.subTest(spec=where):
                once = field.validate_spec(spec)
                self.assertEqual(field.validate_spec(once), once)

    def test_each_one_emits_a_script_that_parses(self) -> None:
        for where, spec in self._recorded():
            with self.subTest(spec=where):
                script = field.emit_field_poc("CVE-2026-0001", field.validate_spec(spec))
                ast.parse(script)


class WhatTheValidatorObservedTests(unittest.TestCase):
    """The lab wrote down the statuses the draft was guessing.

    MobSF's draft had to pick the status its forged request would get. It
    guessed 302, which was right, and set the new password to the current
    one to avoid changing anything -- and that variant answers 200, so the
    expectation never matched and the proof reported that the script did not
    tell the two builds apart. The validator had recorded attack_status 302
    against 403 before any of it.
    """

    def _lab_with(self, validation: Any) -> dict[str, Any]:
        with _lab() as lab_dir:
            (lab_dir / "report.json").write_text(json.dumps({
                "real_poc_verified": True, "validation": validation,
            }))
            return field._observation(lab_dir)

    def test_each_build_s_observation_comes_through(self) -> None:
        seen = self._lab_with({
            "vulnerable": {"attack_status": 302, "confirmed": True},
            "patched": {"attack_status": 403, "blocked": True},
            "differential_confirmed": True,
        })
        self.assertEqual(seen["vulnerable"]["attack_status"], 302)
        self.assertEqual(seen["patched"]["attack_status"], 403)

    def test_a_page_of_html_is_trimmed_rather_than_carried(self) -> None:
        """A 403 page is two kilobytes of styling; the status beside it is
        the whole point."""
        seen = self._lab_with({
            "vulnerable": {"attack_status": 302},
            "patched": {"attack_status": 403, "attack_body": "<html>" + "x" * 4000},
        })
        self.assertLess(len(json.dumps(seen["patched"])), 1400)
        self.assertEqual(seen["patched"]["attack_status"], 403)

    def test_nothing_recorded_is_an_empty_answer(self) -> None:
        for validation in (None, "not a dict", {}, {"vulnerable": True}):
            with self.subTest(validation=validation):
                self.assertEqual(self._lab_with(validation).get("vulnerable"), None)

    def test_a_lab_with_no_report_is_not_an_error(self) -> None:
        with _lab() as lab_dir:
            (lab_dir / "report.json").unlink()
            self.assertEqual(field._observation(lab_dir), {})

    def test_the_draft_is_told_to_read_it(self) -> None:
        self.assertIn("what_the_validator_observed", field._DRAFT_INSTRUCTIONS)
        self.assertIn("rather than guessed", field._DRAFT_INSTRUCTIONS)

    def test_the_draft_is_told_a_refusal_comes_before_the_view(self) -> None:
        """So the differential survives without completing the action."""
        self.assertIn("accepted at all", field._DRAFT_INSTRUCTIONS)
        self.assertIn("damage you do not need", field._DRAFT_INSTRUCTIONS)


class TheDifferentialIsHandedOverAsAVerdictTests(unittest.TestCase):
    """The draft is told the verdict instead of re-deriving it.

    Twice on the half-seen10-2026-11-07 panel a draft re-read the raw bodies,
    reached the opposite of what the record said, and refused on it.

    CVE-2026-112404 (Pillow): the vulnerable body is a 451-character JSON
    array of six `runs` objects whose first holds `"tail_nonzero": false` and
    whose remaining five hold true. The draft read the first element and said
    "the lab's own recorded observation found tail_nonzero false on both the
    vulnerable and the patched build".

    CVE-2026-6961 (Mattermost): it swapped the builds, quoting the patched
    build's confirmed=false and its stripped basename as the vulnerable
    build's, and refused because "the recorded run does not show the claimed
    effect there" -- having already written that the shape "is not the
    obstacle". That lab simulated nothing, so the record was all there was.

    Both reports carried differential_confirmed true, a predicate naming the
    exact string the vulnerable body holds, and evidence reading passed=True
    against passed=False. Neither body was truncated. The predicate reached
    the draft only as a key of confirmed_attack -- the plan's declaration of
    what would be measured -- differential_confirmed only as a line of Python
    inside the validator listing, and effect_evidence not at all.
    """

    def _handed(self, lab_dir: Path) -> dict[str, Any]:
        """What _ask_for_spec actually puts in front of the model."""
        held: dict[str, Any] = {}

        def answer(**kwargs: Any) -> dict[str, Any]:
            held["text"] = kwargs["input_text"]
            return {"feasible": False, "reason": "not asked here",
                    "container_port": None, "spec_json": None, "lab_values_json": None}

        with mock.patch.object(field, "structured_response", side_effect=answer):
            field._ask_for_spec(
                "CVE-2026-0001", json.loads((lab_dir / "plan.json").read_text()), "",
                api_key="k", model="m", provider="anthropic", base_url=None,
                lab_dir=lab_dir,
            )
        return {"text": held["text"], **json.loads(held["text"])}

    @contextlib.contextmanager
    def _lab_reporting(self, **report: Any) -> Iterator[Path]:
        with _lab() as lab_dir:
            (lab_dir / "report.json").write_text(json.dumps(report))
            yield lab_dir

    def _confirmed(self) -> dict[str, Any]:
        """The shape of CVE-2026-112404's report, bodies and all."""
        body = (
            '{"status": "decoded", "runs": [{"tail_nonzero": false}, '
            '{"tail_nonzero": true}, {"tail_nonzero": true}], "tail_nonzero": true}'
        )
        return {
            "patched_tested": True,
            "proof_contract": {"effect_predicate": {"body_regex": '"tail_nonzero": true'}},
            "effect_evidence": [
                'vulnerable: body_regex=\'"tail_nonzero": true\' passed=True',
                'patched: body_regex=\'"tail_nonzero": true\' passed=False',
                "effect on vulnerable=True effect on patched=False passed=True",
            ],
            "validation": {
                "differential_confirmed": True,
                "vulnerable": {"confirmed": True, "observations": {"body": body}},
                "patched": {"confirmed": False, "observations": {"body": "{}"}},
            },
        }

    def test_a_confirmed_differential_is_handed_over_as_the_verdict(self) -> None:
        """The whole point: the draft is told, not left to work it out."""
        with self._lab_reporting(**self._confirmed()) as lab_dir:
            handed = self._handed(lab_dir)
        verdict = handed["the_differential_is_already_measured"]
        self.assertIs(verdict["differential_confirmed"], True)
        self.assertEqual(
            verdict["effect_predicate"], {"body_regex": '"tail_nonzero": true'}
        )
        self.assertIn("passed=True", verdict["effect_evidence"][0])
        self.assertIn("passed=False", verdict["effect_evidence"][1])

    def test_all_three_names_reach_the_draft_as_values(self) -> None:
        """None of the three did before, which is what the drafts were missing.

        The predicate arrived only inside confirmed_attack, which says what
        was to be measured and not whether it held; differential_confirmed
        only as a variable name in the validator source; effect_evidence not
        at all. A name has to arrive as a value to be read as one.
        """
        with self._lab_reporting(**self._confirmed()) as lab_dir:
            handed = self._handed(lab_dir)
        verdict = handed["the_differential_is_already_measured"]
        for name in ("differential_confirmed", "effect_predicate", "effect_evidence"):
            with self.subTest(name=name):
                self.assertIn(name, verdict)
        # Same three autoflow's repair digest carries, for the same reason.
        digest = autoflow._validation_digest(self._confirmed())
        for name in ("differential_confirmed", "effect_predicate", "effect_evidence"):
            with self.subTest(digest=name):
                self.assertEqual(digest[name], verdict[name])

    def test_the_verdict_cannot_be_what_the_input_limit_cuts(self) -> None:
        """It sits ahead of the validator source, which is 20 KB of the 40.

        The digest records the same hazard from the other side: "the report is
        the last key and the first thing the prompt's limit cuts".
        """
        with self._lab_reporting(**self._confirmed()) as lab_dir:
            (lab_dir / "validator").mkdir(exist_ok=True)
            (lab_dir / "validator" / "validator.py").write_text("#" + "x" * 40_000)
            handed = self._handed(lab_dir)
        text = handed["text"]
        self.assertLessEqual(len(text), field._MAX_DRAFT_INPUT)
        self.assertLess(
            text.index("the_differential_is_already_measured"),
            text.index("validator_that_proved_it"),
        )
        self.assertIs(
            handed["the_differential_is_already_measured"]["differential_confirmed"], True
        )

    def test_a_vulnerable_only_lab_is_not_read_as_a_failed_measurement(self) -> None:
        """false here has two meanings and only this separates them.

        CVE-2026-36045 is the shape: no resolvable patched revision, so no
        second build ran and there was no differential to confirm. Handing
        over a bare false would have manufactured a fresh wrong refusal in
        place of the one being fixed -- and the instructions have always said
        a lab with no fixed build is not a reason to answer feasible=false.
        """
        with self._lab_reporting(
            patched_tested=False,
            proof_contract={"effect_predicate": {"status": [200]}},
            effect_evidence=["vulnerable: status=200 allowed=[200] passed=True"],
            validation={"differential_confirmed": False,
                        "vulnerable": {"confirmed": True}},
        ) as lab_dir:
            verdict = self._handed(lab_dir)["the_differential_is_already_measured"]
        self.assertIs(verdict["differential_confirmed"], False)
        self.assertIs(verdict["a_fixed_build_was_tested"], False)
        self.assertIn("passed=True", verdict["effect_evidence"][0])
        self.assertIn("a_fixed_build_was_tested", field._DRAFT_INSTRUCTIONS)
        self.assertIn("no second build was ever run", field._DRAFT_INSTRUCTIONS)

    def test_a_lab_with_no_report_is_not_an_error(self) -> None:
        with _lab() as lab_dir:
            (lab_dir / "report.json").unlink()
            self.assertEqual(field._measured_differential(lab_dir), {})

    def test_a_report_with_nothing_recorded_says_nothing(self) -> None:
        for report in ({}, {"validation": "not a dict"}, {"effect_evidence": "text"}):
            with self.subTest(report=report), self._lab_reporting(**report) as lab_dir:
                verdict = field._measured_differential(lab_dir)
                self.assertIsNone(verdict["differential_confirmed"])
                self.assertEqual(verdict["effect_evidence"], [])

    def test_the_evidence_is_cut_line_wise_rather_than_mid_clause(self) -> None:
        """Each line is one clause's verdict; half a line is worse than none."""
        with self._lab_reporting(
            effect_evidence=["clause " + "x" * 2000] * 40,
        ) as lab_dir:
            evidence = field._measured_differential(lab_dir)["effect_evidence"]
        self.assertEqual(len(evidence), field._MAX_EVIDENCE_LINES)
        self.assertTrue(evidence[0].startswith("clause "))
        self.assertEqual(len(evidence[0]), field._MAX_EVIDENCE_LINE_CHARS)

    def test_the_draft_is_told_the_differential_is_not_its_question(self) -> None:
        said = field._DRAFT_INSTRUCTIONS
        self.assertIn("the_differential_is_already_measured", said)
        self.assertIn("CVELab's verdict", said)
        self.assertIn("answering a question nobody asked", said)
        # The bodies keep their job -- choosing an expectation -- and lose the
        # one they were being read for.
        self.assertIn("never take the first element of a list as the result", said)

    def test_the_two_standing_refusals_are_still_named_as_refusals(self) -> None:
        """Nothing here lowers the bar, so both stay spelled out."""
        said = field._DRAFT_INSTRUCTIONS
        self.assertIn("effect one instance genuinely cannot express", said)
        self.assertIn("only evidence comes through a route the lab invented", said)


class RefusingIsStillTheAnswerWhenItShouldBeTests(unittest.TestCase):
    """The two correct refusals on that panel, kept correct.

    Two labs had a spec drafted, proved against both builds and refused --
    "the script did not tell the two builds apart" -- which is the prover
    working. Nothing about handing the draft a verdict touches the prover, and
    these pin that: a spec whose script cannot separate the builds must not
    ship however confidently the differential was measured, because the lab's
    own validator separating them says nothing about whether this script does.
    """

    def _prove(self, observed: tuple[bool, bool]) -> dict[str, Any]:
        with _lab() as lab_dir, mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", side_effect=lambda c, name, d, e: f"cid-{name}",
        ), mock.patch.object(field, "_still_serving", return_value="127.0.0.1"), \
             mock.patch.object(field.sidecar, "ensure_image", return_value="img"), \
             mock.patch.object(
                 field, "_run_field_script",
                 side_effect=lambda cid, *a, **k: _run(
                     observed=observed[0] if cid.endswith("vulnerable") else observed[1],
                     ran=True,
                 ),
             ):
            return field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 3000, lab_dir,
                ["docker", "compose"], {}, {}, True, None,
            )

    def test_a_script_that_fires_on_both_builds_does_not_ship(self) -> None:
        outcome = self._prove((True, True))
        self.assertIs(outcome["shipped"], False)
        self.assertIn("did not tell the two builds apart", outcome["reason"])
        self.assertNotIn("script", outcome)

    def test_a_script_silent_on_both_builds_does_not_ship(self) -> None:
        outcome = self._prove((False, False))
        self.assertIs(outcome["shipped"], False)
        self.assertIn("did not tell the two builds apart", outcome["reason"])
        self.assertNotIn("script", outcome)

    def test_a_refusal_on_the_lab_s_own_route_is_still_carried_back(self) -> None:
        """The draft refusing for a harness-only channel is kept as the answer.

        An effect visible only through an endpoint the lab added does not
        exist on a stock instance. The decline is now put back once -- see
        ADeclineIsAskedOnceMoreTests -- and a draft that gives it again has
        its refusal carried back untouched rather than retried into a spec.
        """
        refused = (
            "the only evidence is a flag the lab's own adapter computes, which "
            "no stock instance reports"
        )
        with mock.patch.object(
            field, "structured_response",
            return_value={"feasible": False, "reason": refused,
                          "container_port": None, "spec_json": None,
                          "lab_values_json": None},
        ) as asked:
            out = field.draft_manual_poc_spec(
                "CVE-2026-0001", {"exploit_contract": {}}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )
        self.assertEqual(asked.call_count, 2)
        self.assertNotIn("spec", out)
        self.assertEqual(out["reason"], refused)
        self.assertNotIn("reconsider", out)

    def test_the_channel_refusal_keeps_its_own_bar(self) -> None:
        """Refuse where no response could be a function of the state at all.

        The instruction added for the operator-supplied route must not read as
        permission to aim at the harness's own field, so the refusing half is
        stated beside it.
        """
        said = field._DRAFT_INSTRUCTIONS
        self.assertIn("is not on a stock instance and a spec must not aim at it", said)
        self.assertIn("no route of any kind could carry the effect out", said)


class TheOperatorCanSupplyTheRouteTests(unittest.TestCase):
    """A library CVE's missing piece is a route, and a route is an input.

    Measured over the archive: of 115 labs that reproduced, 24 shipped a PoC,
    12 were drafted and refused by the prover, and 79 were never drafted at
    all -- so a draft declining is by far the most expensive outcome here.

    The path half of this was already instructed and already works:
    CVE-2026-102422 (shell-quote, a library with no listener, execution level
    source_component) shipped a spec whose only input is target_path and
    whose observable_effect says the operator's route "must pass its JSON
    request body to the shell-quote quote() and run the result in sh -c".

    What was missing is the channel. The usual adapter both reaches the
    vulnerable code and computes the value the validator read, and the rule
    against aiming at a harness-reported effect was swallowing the whole
    library case. CVE-2026-112404 refused with "a generic application route
    would have to return raw pixel bytes", CVE-2026-2950 with "a stock
    application that calls _.unset does not report that state", and
    CVE-2026-36045 with "the other strategies would need a stable,
    operator-reachable route that this lab does not supply" -- all three
    reaching for the route idea and then declining on the channel.
    """

    SAID = field._DRAFT_INSTRUCTIONS

    def test_the_route_is_still_declared_as_an_input(self) -> None:
        """The half that already worked, asserted so it cannot be lost."""
        self.assertIn("declare it as an input", self.SAID)
        self.assertIn("target_path", self.SAID)
        self.assertIn("--input target_path=/their/route", self.SAID)

    def test_the_channel_is_settled_separately_from_the_path(self) -> None:
        self.assertIn("The paragraph above settles the path", self.SAID)
        self.assertIn("Settle the channel the same way", self.SAID)
        self.assertIn("reaches the vulnerable code and it also computes", self.SAID)

    def test_the_diagnostic_is_distinguished_from_the_artifact(self) -> None:
        """The distinction the three refusals did not have available."""
        self.assertIn("Separate the harness's diagnostic from the artifact", self.SAID)
        self.assertIn("the effect is in the artifact and not in the diagnostic", self.SAID)
        self.assertIn("Ask what the operator's own route returns", self.SAID)

    def test_the_test_is_what_a_real_application_could_return(self) -> None:
        self.assertIn(
            "whether a real application calling the same function could return anything "
            "that differs",
            " ".join(self.SAID.split()),
        )
        self.assertIn("that is an input, not a refusal", self.SAID)

    def test_the_harness_reporting_rule_points_at_the_channel_paragraph(self) -> None:
        """Left alone it won the reading and refused the library case outright."""
        self.assertIn(
            "a reported result does not by itself mean the effect is out of reach",
            self.SAID,
        )

    def test_the_cost_of_declining_is_recorded_where_it_is_decided(self) -> None:
        self.assertIn("of 115 labs that reproduced", self.SAID)
        self.assertIn("79 were never drafted at all", self.SAID)

    def test_the_route_is_named_as_an_input_where_inputs_are_defined(self) -> None:
        """Not only in the library paragraph, which is read later or not at all.

        inputs was described purely as values -- "a tenant id, the id or title
        of an object they own" -- so the stronger thing every shipped
        component PoC actually does was never said at the point where the
        field is defined. 11 of 12 shipped component PoCs declare an
        operator-supplied input, 9 of them named target_path.
        """
        self.assertIn("An input is not only a value", self.SAID)
        self.assertIn(
            "the route is the input, and it belongs to the operator rather than to the "
            "project",
            " ".join(self.SAID.split()),
        )

    def test_no_listener_is_named_as_the_condition_not_the_obstacle(self) -> None:
        """The same sentence was being used as both.

        19 of 48 declines gave "ships no listener of its own" as the reason
        for declining, which is the exact condition the pattern exists for.
        """
        flat = " ".join(self.SAID.split())
        self.assertIn(
            "\"This project ships no listener of its own\" is therefore the condition "
            "that calls for this pattern, and never a reason to answer feasible=false",
            flat,
        )
        self.assertIn("you have found the pattern rather than an obstacle", flat)

    def test_the_nine_ask_control_experiment_is_recorded(self) -> None:
        """Six scripts and three refusals for one library, on identical input."""
        flat = " ".join(self.SAID.split())
        self.assertIn("asked nine times produced six scripts and three refusals", flat)


class ADeclineIsAskedOnceMoreTests(unittest.TestCase):
    """feasible=false was a single unretried sample of a sampled answer.

    `complaint` already existed for a spec whose shape was refused, and
    `_ask_for_spec` marked only a malformed spec for retry -- so a decline
    returned straight out of the loop and all 48 never-drafted labs in the
    archive audit got exactly one ask. Six labs had shipped on a human asking
    a refused run again by hand. The audit put the recoverable share at 8 to
    12 of those 48.

    The bar is untouched: whatever a second answer offers is still emitted as
    a script and proved against both builds. Of the 11 labs drafted and then
    refused by that proof, 9 ran on both builds and the script fired on
    neither, so no false positive has ever had to be rejected there.
    """

    REFUSED = "a library with no listener cannot be shown on one instance"

    def _answers(self, *answers: dict[str, Any]) -> tuple[dict[str, Any], mock.Mock]:
        """Drive draft_manual_poc_spec through a scripted sequence of answers."""
        asked = mock.Mock(side_effect=list(answers))
        with mock.patch.object(field, "structured_response", asked):
            out = field.draft_manual_poc_spec(
                "CVE-2026-0001", {"exploit_contract": {}}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )
        return out, asked

    def _decline(self, reason: str = "") -> dict[str, Any]:
        return {"feasible": False, "reason": reason or self.REFUSED,
                "container_port": None, "spec_json": None, "lab_values_json": None}

    def _feasible(self) -> dict[str, Any]:
        return {"feasible": True, "reason": "", "container_port": 8000,
                "spec_json": json.dumps(_spec()), "lab_values_json": None}

    def test_a_decline_is_asked_once_more(self) -> None:
        out, asked = self._answers(self._decline(), self._feasible())
        self.assertEqual(asked.call_count, 2)
        self.assertIn("spec", out)
        self.assertEqual(out["container_port"], 8000)

    def test_a_second_decline_is_the_answer_and_is_not_asked_again(self) -> None:
        """Bounded at one, or two declines would ask forever."""
        out, asked = self._answers(self._decline(), self._decline("still no"))
        self.assertEqual(asked.call_count, 2)
        self.assertNotIn("spec", out)
        self.assertEqual(out["reason"], "still no")
        self.assertNotIn("reconsider", out)

    def test_the_decline_text_reaches_the_second_ask(self) -> None:
        """Fed back, not reworded -- the same channel a refused shape uses."""
        sent: list[str] = []

        def answer(**kwargs: Any) -> dict[str, Any]:
            sent.append(kwargs["input_text"])
            return self._decline() if len(sent) == 1 else self._feasible()

        with mock.patch.object(field, "structured_response", side_effect=answer):
            field.draft_manual_poc_spec(
                "CVE-2026-0001", {"exploit_contract": {}}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )
        self.assertNotIn("your_previous_answer_was_rejected", sent[0])
        second = json.loads(sent[1])["your_previous_answer_was_rejected"]
        self.assertIn(self.REFUSED, second)
        self.assertIn("You already answered feasible=false", second)

    def test_a_provider_decline_is_still_never_asked_again(self) -> None:
        """The one thing this must not become.

        A provider answering under its usage policy gives the same answer to
        the same request, so it is recorded and never retried or reworded.
        """
        declined = field.ProviderDeclined("anthropic", "claude-haiku-5-5", "cyber")
        with mock.patch.object(
            field, "structured_response", side_effect=declined
        ) as asked:
            out = field.draft_manual_poc_spec(
                "CVE-2026-0001", {"exploit_contract": {}}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )
        self.assertEqual(asked.call_count, 1)
        self.assertNotIn("spec", out)
        self.assertEqual(out["declined"]["provider"], "anthropic")

    def test_a_failed_call_is_not_a_decline_and_is_not_asked_again(self) -> None:
        with mock.patch.object(
            field, "structured_response", side_effect=RuntimeError("socket closed"),
        ) as asked:
            out = field.draft_manual_poc_spec(
                "CVE-2026-0001", {"exploit_contract": {}}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )
        self.assertEqual(asked.call_count, 1)
        self.assertIn("the spec call failed", out["reason"])

    def test_a_decline_does_not_spend_the_shape_retries(self) -> None:
        """The two budgets are separate, so each keeps its own ask.

        A decline, then a malformed spec, then a usable one: the decline
        spends the single reconsideration and the malformed answer spends a
        shape retry, and the usable spec is still reached.
        """
        out, asked = self._answers(
            self._decline(),
            {"feasible": True, "reason": "", "container_port": 8000,
             "spec_json": "{not json", "lab_values_json": None},
            self._feasible(),
        )
        self.assertEqual(asked.call_count, 3)
        self.assertIn("spec", out)

    def test_a_malformed_spec_does_not_spend_the_reconsideration(self) -> None:
        """And the other way round: shape retries exhaust, then the decline.

        With CVELAB_SPEC_RETRIES at its default of 1 a malformed answer is
        asked once more; that second answer declining still earns its own
        extra ask rather than returning straight out.
        """
        out, asked = self._answers(
            {"feasible": True, "reason": "", "container_port": 8000,
             "spec_json": "{not json", "lab_values_json": None},
            self._decline(),
            self._feasible(),
        )
        self.assertEqual(asked.call_count, 3)
        self.assertIn("spec", out)

    def test_the_reconsideration_names_the_recoverable_shapes(self) -> None:
        said = field._reconsider_complaint(self.REFUSED)
        for shape in (
            "ships no listener of its own",
            "the lab's own adapter",
            "discover enumerates what a real target already holds",
            "oob_callback, service_crash and timing_differential",
        ):
            with self.subTest(shape=shape):
                self.assertIn(shape, said)

    def test_the_reconsideration_does_not_lower_the_bar(self) -> None:
        """Declining again has to stay a real answer, or this becomes pressure.

        24 of the 48 declines in the audit were correct, so the second ask
        says so rather than asking for a spec at any price.
        """
        flat = " ".join(field._reconsider_complaint(self.REFUSED).split())
        self.assertIn("answer feasible=false again and say so", flat)
        self.assertIn("That is a correct answer and it will be recorded as one", flat)
        self.assertIn("Do not offer a spec you do not believe separates the two builds", flat)

    def test_the_second_ask_is_announced(self) -> None:
        """A doubled call on a lab that produced nothing has to be visible."""
        said: list[str] = []
        with mock.patch.object(field.progress, "step", side_effect=said.append):
            self._answers(self._decline(), self._feasible())
        self.assertTrue(any("asking once more" in line for line in said), said)

    def test_a_provider_decline_on_the_second_ask_keeps_the_first_answer(self) -> None:
        """The one way asking twice could leave a worse record than asking once.

        The first ask produced a real verdict and said why. A provider
        declining the second produces no verdict at all, and returning that
        would report the lab as provider-declined and throw the reason away --
        "no manual PoC" is only actionable if it says why.
        """
        asked = mock.Mock(side_effect=[
            self._decline("the effect is a prototype mutation with no response channel"),
            field.ProviderDeclined("anthropic", "claude-haiku-5-5", "cyber"),
        ])
        with mock.patch.object(field, "structured_response", asked):
            out = field.draft_manual_poc_spec(
                "CVE-2026-0001", {"exploit_contract": {}}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )
        self.assertEqual(asked.call_count, 2)
        self.assertNotIn("declined", out)
        self.assertIn("no response channel", out["reason"])
        self.assertIn("the second ask returned no verdict", out["reconsidered"])

    def test_a_failed_second_call_also_keeps_the_first_answer(self) -> None:
        asked = mock.Mock(side_effect=[
            self._decline("it needs two clients driven at once"),
            RuntimeError("socket closed"),
        ])
        with mock.patch.object(field, "structured_response", asked):
            out = field.draft_manual_poc_spec(
                "CVE-2026-0001", {"exploit_contract": {}}, api_key="k", model="m",
                provider="anthropic", base_url=None,
            )
        self.assertIn("two clients", out["reason"])
        self.assertIn("the second ask returned no verdict", out["reconsidered"])

    def test_nothing_internal_leaks_into_the_recorded_answer(self) -> None:
        """report.json carries this dict, so the loop's own keys stay out."""
        for answers in (
            (self._decline(), self._feasible()),
            (self._decline(), self._decline("still no")),
            (self._feasible(),),
        ):
            with self.subTest(answers=len(answers)):
                out, _ = self._answers(*answers)
                self.assertNotIn("reconsider", out)
                self.assertNotIn("retry", out)


class SetupCanBindWhatItReadsTests(unittest.TestCase):
    """A secret the lab makes at boot cannot be a fixed lab value.

    A nebula-mesh lab reproduced end to end and was refused a script for
    exactly this: the effect needs a non-admin API key, the lab could only
    get one using the admin key printed at startup, and "that admin key is
    generated fresh on each run, so no fixed lab value can be recorded for
    it". lab_values answers a stable value; this answers a fresh one.
    """

    def _spec(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "observable_effect": "a non-admin key creates a subscription it may not",
            "inputs": ["admin_key"],
            "setup": [{
                "bind": "admin_key",
                "query": [{"method": "GET", "path": "/lab/admin-key"}],
                "extract": {"json_values": "key"},
            }],
            "probe": [{"method": "POST", "path": "/v1/subs",
                       "headers": {"Authorization": "Bearer {{admin_key}}"}}],
            "expect": {"status": 200},
        }
        spec.update(extra)
        return spec

    def test_a_binding_step_validates_beside_plain_requests(self) -> None:
        spec = field.validate_spec(self._spec(setup=[
            {"method": "POST", "path": "/lab/seed"},
            {"bind": "admin_key", "query": [{"method": "GET", "path": "/lab/admin-key"}],
             "extract": {"json_values": "key"}},
        ]))
        self.assertEqual(spec["setup"][0]["path"], "/lab/seed")
        self.assertEqual(spec["setup"][1]["bind"], "admin_key")

    def test_a_bound_name_has_to_be_an_input_too(self) -> None:
        """The shipped script still asks the operator for their own."""
        with self.assertRaises(ValueError) as refused:
            field.validate_spec(self._spec(
                inputs=[], probe=[{"method": "POST", "path": "/v1/subs"}]
            ))
        self.assertIn("also be declared in inputs", str(refused.exception))

    def test_a_query_may_use_what_an_earlier_step_bound(self) -> None:
        field.validate_spec(self._spec(
            inputs=["admin_key", "user_key"],
            setup=[
                {"bind": "admin_key", "query": [{"method": "GET", "path": "/lab/admin"}],
                 "extract": {"json_values": "key"}},
                {"bind": "user_key",
                 "query": [{"method": "POST", "path": "/v1/keys",
                            "headers": {"Authorization": "Bearer {{admin_key}}"}}],
                 "extract": {"json_values": "key"}},
            ],
            probe=[{"method": "POST", "path": "/v1/subs",
                    "headers": {"Authorization": "Bearer {{user_key}}"}}],
        ))

    def test_an_unbound_name_in_a_query_is_refused(self) -> None:
        with self.assertRaises(ValueError) as refused:
            field.validate_spec(self._spec(setup=[
                {"bind": "admin_key",
                 "query": [{"method": "GET", "path": "/k/{{nothing}}"}],
                 "extract": {"json_values": "key"}},
            ]))
        self.assertIn("nothing binds", str(refused.exception))

    def test_the_proof_is_not_refused_for_a_value_setup_will_read(self) -> None:
        """Without this the spec stops at "needs values only you have"."""
        spec = field.validate_spec(self._spec())
        with _lab() as lab_dir, mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", return_value="cid",
        ), mock.patch.object(field, "_still_serving", return_value="127.0.0.1"), \
             mock.patch.object(field.sidecar, "ensure_image", return_value="img"), \
             mock.patch.object(
                 field, "_run_setup",
                 return_value={"requests": [], "bound": {"admin_key": "fresh-at-boot"}},
             ), mock.patch.object(
                 field, "_run_field_script",
                 side_effect=lambda cid, port, script, transport, image, given, host=None, disruptive=False:
                     (seen.append(given), _run(observed=True, ran=True))[1],
             ):
            seen: list[Any] = []
            outcome = field.prove_manual_poc(
                "CVE-2026-0001", spec, 8000, lab_dir, ["docker", "compose"], {},
                {}, True, None,
            )
        self.assertNotIn("values only you have", str(outcome.get("reason") or ""))
        self.assertEqual(seen[0]["admin_key"], "fresh-at-boot")

    def test_the_operator_s_own_value_still_wins(self) -> None:
        spec = field.validate_spec(self._spec())
        with _lab() as lab_dir, mock.patch.object(
            field, "_lab_validator", return_value=_LAB_MODE
        ), mock.patch.object(
            field, "_service_container", return_value="cid",
        ), mock.patch.object(field, "_still_serving", return_value="127.0.0.1"), \
             mock.patch.object(field.sidecar, "ensure_image", return_value="img"), \
             mock.patch.object(
                 field, "_run_setup",
                 return_value={"requests": [], "bound": {"admin_key": "from-the-lab"}},
             ), mock.patch.object(
                 field, "_run_field_script",
                 side_effect=lambda cid, port, script, transport, image, given, host=None, disruptive=False:
                     (seen.append(given), _run(observed=True, ran=True))[1],
             ):
            seen: list[Any] = []
            field.prove_manual_poc(
                "CVE-2026-0001", spec, 8000, lab_dir, ["docker", "compose"], {},
                {}, True, {"admin_key": "mine"},
            )
        self.assertEqual(seen[0]["admin_key"], "mine")


class ManualActionVerdictTests(unittest.TestCase):
    """The patched side is supposed to block the attack.

    A script that says so by exiting non-zero is using the convention
    CVELab's own shipped Manual-PoC.py documents, and requiring exit zero of
    it as well failed a validator that was right. Measured once, on an
    express lab, where it cost twelve repair attempts on a check no model
    could fix: the output said BLOCKED and the feedback said the check
    failed.
    """

    def test_the_patched_side_may_say_blocked_by_exiting_one(self) -> None:
        self.assertTrue(core._manual_action_passed(
            "verify", "BLOCKED", 1, "status: 302 anchor_present: False\nBLOCKED"))

    def test_and_by_exiting_zero(self) -> None:
        self.assertTrue(core._manual_action_passed("verify", "BLOCKED", 0, "BLOCKED"))

    def test_a_crash_that_printed_the_verdict_does_not_pass(self) -> None:
        # 2 and up is a script that fell over, and a negative code is a
        # signal. Neither is a verdict being reported, which is why this
        # takes exit 1 rather than anything non-zero.
        for code in (2, 127, -9):
            with self.subTest(code=code):
                self.assertFalse(
                    core._manual_action_passed("verify", "BLOCKED", code, "BLOCKED"))

    def test_the_verdict_still_has_to_be_there(self) -> None:
        self.assertFalse(core._manual_action_passed("verify", "BLOCKED", 1, ""))
        self.assertFalse(
            core._manual_action_passed("verify", "BLOCKED", 1, "REPRODUCED"))

    def test_the_vulnerable_side_still_has_to_exit_zero(self) -> None:
        # Nothing is widened here: a reproduction that could not exit zero
        # has not shown the effect, and the exit status is the only part of
        # that claim CVELab did not take from the script's own words.
        self.assertTrue(
            core._manual_action_passed("verify", "REPRODUCED", 0, "REPRODUCED"))
        self.assertFalse(
            core._manual_action_passed("verify", "REPRODUCED", 1, "REPRODUCED"))

    def test_the_exploit_action_is_judged_only_on_its_exit_status(self) -> None:
        # It re-sends the one input and prints what came back; it reports no
        # verdict, so the exit status is all there is to go on.
        self.assertTrue(core._manual_action_passed("exploit", "BLOCKED", 0, "status: 302"))
        self.assertFalse(core._manual_action_passed("exploit", "BLOCKED", 1, "status: 302"))
        self.assertFalse(core._manual_action_passed("exploit", "BLOCKED", 0, ""))


if __name__ == "__main__":
    unittest.main()
