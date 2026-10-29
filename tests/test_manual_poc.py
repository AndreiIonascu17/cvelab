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

import contextlib
import json
import subprocess
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import cli, core, field, sourcegen, upload


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
            field, "_still_serving", return_value=True
        ), mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given: outcomes[cid],
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

    def test_its_name_does_not_collide_with_the_in_lab_manual_runner(self) -> None:
        """MANUAL-POC.md and manual.sh drive PoC.py inside the lab."""
        self.assertNotIn(
            field.MANUAL_POC_NAME, ("manual.sh", "MANUAL-POC.md", "PoC.py")
        )
        self.assertNotIn(
            field.MANUAL_POC_GUIDE_NAME, ("manual.sh", "MANUAL-POC.md", "PoC.py")
        )


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


if __name__ == "__main__":
    unittest.main()


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
        }[strategy]
        with mock.patch.object(
            field, "_service_container", side_effect=lambda c, n, d, e: f"cid-{n}"
        ), mock.patch.object(
            field, "_still_serving", return_value=True
        ), mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given: _run(observed, True),
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
            field, "_still_serving", return_value=True
        ), mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given: _run(True, True),
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
            field, "_still_serving", side_effect=lambda cid, port: serving[cid]
        ), mock.patch.object(
            field, "_container_logs", return_value="killed: out of memory"
        ), mock.patch.object(
            field, "_run_field_script",
            side_effect=lambda cid, port, script, transport, image, given: _run(True, True),
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
            field, "_still_serving", side_effect=lambda cid, port: cid != "cid-vulnerable"
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
