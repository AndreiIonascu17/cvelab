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
import json
import re
import subprocess
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import autoflow, cli, closed, core, field, sourcegen, upload


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


@contextlib.contextmanager
def _lab(
    *,
    reproduced: bool = True,
    lab_type: str = "SOURCE_REPRODUCTION",
    spec: dict[str, Any] | None = None,
    record: dict[str, Any] | None = None,
) -> Iterator[Path]:
    """A lab on disk, as `cvelab run` leaves one."""
    with tempfile.TemporaryDirectory() as root:
        lab_dir = Path(root) / "CVE-2026-0001"
        lab_dir.mkdir(parents=True)
        (lab_dir / "plan.json").write_text(json.dumps({
            "cve": "CVE-2026-0001",
            "lab_type": lab_type,
            "repository": "https://example.invalid/p.git",
            "startup_services": ["vulnerable", "patched"],
        }))
        (lab_dir / "report.json").write_text(json.dumps({
            "real_poc_verified": reproduced
        }))
        if spec is not None:
            (lab_dir / "spec.json").write_text(json.dumps(spec))
        if record is not None:
            (lab_dir / "artifacts").mkdir(exist_ok=True)
            (lab_dir / "artifacts" / field.MANUAL_POC_RECORD_NAME).write_text(
                json.dumps(record)
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
        with mock.patch.object(field, "emit_field_poc", side_effect=OSError("disk gone")):
            out = field.prove_manual_poc(
                "CVE-2026-0001", field.validate_spec(_spec()), 8000,
                Path("/lab"), ["docker", "compose"], {},
            )
        self.assertIs(out["shipped"], False)
        self.assertIn("OSError", out["reason"])


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

    def test_a_proved_spec_writes_the_script_the_guide_and_the_record(self) -> None:
        with _lab(spec=_spec()) as lab_dir:
            result = self._call(lab_dir)
            artifacts = lab_dir / "artifacts"
            self.assertIs(result["ok"], True)
            self.assertTrue((artifacts / field.MANUAL_POC_NAME).is_file())
            self.assertTrue((artifacts / field.MANUAL_POC_GUIDE_NAME).is_file())
            self.assertTrue((artifacts / field.MANUAL_POC_RECORD_NAME).is_file())
            guide = (artifacts / field.MANUAL_POC_GUIDE_NAME).read_text()
            # It must say where it may be pointed, and that a negative result
            # is not a clean bill.
            self.assertIn("keep that permission in writing", guide)
            self.assertIn("not the same as", guide)
            self.assertIn("demo-target", guide)

    def test_the_record_keeps_a_refusal_but_writes_no_script(self) -> None:
        with _lab(spec=_spec()) as lab_dir:
            result = self._call(lab_dir, outcome={
                "shipped": False, "reason": "the script did not tell the two builds apart",
                "proof_checks": {}, "runs": {},
            })
            artifacts = lab_dir / "artifacts"
            self.assertIs(result["ok"], False)
            self.assertFalse((artifacts / field.MANUAL_POC_NAME).exists())
            record = json.loads((artifacts / field.MANUAL_POC_RECORD_NAME).read_text())
            self.assertIn("did not tell the two builds apart", record["reason"])

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


class StaysLocalTests(unittest.TestCase):
    """The lab travels to the corpus; a free-target script does not."""

    def test_the_target_script_is_not_among_the_uploaded_documents(self) -> None:
        for name in (field.MANUAL_POC_NAME, field.MANUAL_POC_GUIDE_NAME,
                     field.MANUAL_POC_RECORD_NAME):
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
    #: constants and spelled out where the writer spells it out.
    ARTIFACT_NAMES = (
        field.MANUAL_POC_NAME,
        field.MANUAL_POC_GUIDE_NAME,
        field.MANUAL_POC_RECORD_NAME,
        field.LAB_POC_GUIDE_NAME,
        "PoC.py", "PoC.ps1", "manual.sh",
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
            field.MANUAL_POC_GUIDE_NAME.lower(),
        )
        # And the old name really is gone from what gets written. It survives
        # only in upload's allowlists, for archived labs that still hold it.
        self.assertNotEqual(
            field.LAB_POC_GUIDE_NAME, field.LEGACY_LAB_POC_GUIDE_NAME
        )
        self.assertEqual(
            field.LEGACY_LAB_POC_GUIDE_NAME.lower(),
            field.MANUAL_POC_GUIDE_NAME.lower(),
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
        exempt = {field.LEGACY_LAB_POC_GUIDE_NAME}
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
            self.assertTrue((lab_dir / "artifacts" / field.MANUAL_POC_NAME).is_file())
            self.assertTrue((lab_dir / "artifacts" / field.MANUAL_POC_GUIDE_NAME).is_file())

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

    def test_a_refusal_writes_the_record_and_no_script(self) -> None:
        with _lab() as lab_dir:
            outcome = {"shipped": False, "reason": "did not tell them apart"}
            field.write_manual_poc(
                "CVE-2026-0001", lab_dir, {}, field.validate_spec(_spec()), 8000, outcome
            )
            artifacts = lab_dir / "artifacts"
            self.assertFalse((artifacts / field.MANUAL_POC_NAME).exists())
            record = json.loads((artifacts / field.MANUAL_POC_RECORD_NAME).read_text())
            self.assertIn("did not tell them apart", record["reason"])


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
        guide = field._manual_poc_guide(
            "CVE-2026-0001", field.validate_spec(_spec()),
            {"lab_type": "VULNERABLE_ONLY_REPRODUCTION", "repository": "r"}, 8000,
        )
        self.assertIn("no fixed revision to compare against", guide)
        self.assertIn("weaker evidence", guide)
        self.assertIn("not that a fix removes it", guide)
        with_fix = field._manual_poc_guide(
            "CVE-2026-0001", field.validate_spec(_spec()), {"repository": "r"}, 8000,
        )
        self.assertIn("stayed silent on the fixed one", with_fix)
        self.assertNotIn("weaker evidence", with_fix)

    def test_the_guide_says_what_it_runs_against_and_names_the_other_one(self) -> None:
        """The one fact a reader taking this to a client needs first.

        This document and the lab's one both opened with the identical line
        `# <CVE> Manual PoC`, so neither the heading, the filename nor the
        first paragraph told the reader which of the two could be pointed at a
        live server. Only this one can.
        """
        guide = field._manual_poc_guide(
            "CVE-2026-0001", field.validate_spec(_spec()), {"repository": "r"}, 8000,
        )
        flat = " ".join(guide.split())

        self.assertTrue(guide.startswith("# CVE-2026-0001 Manual PoC"))
        self.assertIn("## What this runs against", guide)
        self.assertIn("One instance whose address you supply, with `--target`", flat)
        self.assertIn("pointed at a server you did not build yourself", flat)
        # And it names the other document, so the reader can find the one
        # whose reach was only ever this lab's own builds.
        self.assertIn(field.LAB_POC_GUIDE_NAME, guide)
        self.assertIn("and nothing outside them", flat)
        # That document's `PoC.py` now takes an optional address as well, so
        # what separates the two is which was PROVED against a single
        # instance, not which could be aimed at one. Saying otherwise here
        # would be the overclaim this whole section exists to prevent.
        self.assertIn("nothing proved it against one", flat)

    def test_the_guide_does_not_credit_one_build_with_a_second(self) -> None:
        """A vulnerable-only lab has one build for the other document to drive.

        Saying "two Docker builds" there would promise a differential that the
        trust section three paragraphs later explicitly denies, in the same
        document.
        """
        guide = field._manual_poc_guide(
            "CVE-2026-0001", field.validate_spec(_spec()),
            {"lab_type": "VULNERABLE_ONLY_REPRODUCTION", "repository": "r"}, 8000,
        )
        flat = " ".join(guide.split())

        self.assertIn("this lab's own build and nothing outside them", flat)
        self.assertNotIn("two Docker builds", flat)


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

    def _record(self, lab_dir: Path, **extra: Any) -> None:
        held = {"cve": "CVE-2026-0001", "shipped": True, "container_port": 8000,
                "spec": field.validate_spec(_spec())}
        held.update(extra)
        artifacts = lab_dir / "artifacts"
        artifacts.mkdir(exist_ok=True)
        (artifacts / field.MANUAL_POC_RECORD_NAME).write_text(json.dumps(held))

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
            (lab_dir / "artifacts" / field.MANUAL_POC_RECORD_NAME).write_text("{not json")
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
            held = json.loads(
                (lab_dir / "artifacts" / field.MANUAL_POC_RECORD_NAME).read_text())
            self.assertIn("spec", held)
            self.assertNotIn("attempted_spec", held)
        with _lab() as lab_dir:
            refused = {"shipped": False, "reason": "x"}
            field.write_manual_poc("CVE-2026-0001", lab_dir, {},
                                   field.validate_spec(_spec()), 8000, refused)
            held = json.loads(
                (lab_dir / "artifacts" / field.MANUAL_POC_RECORD_NAME).read_text())
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
            held = json.loads(
                (lab_dir / "artifacts" / field.MANUAL_POC_RECORD_NAME).read_text())
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
            held = json.loads(
                (lab_dir / "artifacts" / field.MANUAL_POC_RECORD_NAME).read_text())
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
            # report.json takes this outcome verbatim, and one of these is a
            # credential of the lab's.
            self.assertNotIn("lab_values", outcome)
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
        guide = field._manual_poc_guide(
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
            self.assertFalse((lab_dir / "artifacts" / field.MANUAL_POC_RECORD_NAME).exists())
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
