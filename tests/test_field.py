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

"""Field PoC mode: the single-target exploit the operator runs themselves."""

from __future__ import annotations

import ast
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import field


def _inband(**extra: Any) -> dict[str, Any]:
    spec = {
        "strategy": "inband_differential",
        "observable_effect": "a value disclosed by the vulnerable path",
        "probe": [{"method": "POST", "path": "/api/graphql", "body": '{"query":"a"}'}],
        "control": [{"method": "POST", "path": "/api/graphql", "body": '{"query":"b"}'}],
        "extract": {"json_values": "body"},
    }
    spec.update(extra)
    return spec


def _marker(**extra: Any) -> dict[str, Any]:
    spec = {
        "strategy": "marker_roundtrip",
        "observable_effect": "a reflected marker",
        "probe": [{"method": "GET", "path": "/search?q={{marker}}"}],
        "observe": {"method": "GET", "path": "/search?q={{marker}}"},
    }
    spec.update(extra)
    return spec


class SpecTests(unittest.TestCase):
    def test_a_non_observable_class_is_declined(self) -> None:
        """A memory crash or a race has no field PoC; the mode says so."""
        with self.assertRaises(ValueError):
            field.validate_spec({"strategy": "memory_overread", "observable_effect": "x"})

    def test_a_listener_strategy_is_declined_for_now(self) -> None:
        with self.assertRaises(ValueError) as raised:
            field.validate_spec({"strategy": "oob_callback", "observable_effect": "x"})
        self.assertIn("listener", str(raised.exception))

    def test_an_effect_must_be_described(self) -> None:
        with self.assertRaises(ValueError):
            field.validate_spec(_inband(observable_effect="   "))

    def test_inband_needs_probe_control_and_extractor(self) -> None:
        validated = field.validate_spec(_inband())
        self.assertEqual(validated["checks"][0]["extract"], {"json_values": "body"})
        for drop in ("probe", "control", "extract"):
            spec = _inband()
            del spec[drop]
            with self.subTest(missing=drop), self.assertRaises(ValueError):
                field.validate_spec(spec)

    def test_an_extractor_is_exactly_one_of_two_forms(self) -> None:
        self.assertEqual(
            field.validate_spec(_inband(extract={"regex": "id=(\\d+)"}))["checks"][0]["extract"],
            {"regex": "id=(\\d+)"},
        )
        for bad in ({}, {"json_values": "a", "regex": "b"}, {"other": "x"},
                    {"regex": "("}):
            with self.subTest(extract=bad), self.assertRaises(ValueError):
                field.validate_spec(_inband(extract=bad))

    def test_marker_probe_must_place_the_marker(self) -> None:
        field.validate_spec(_marker())
        with self.assertRaises(ValueError):
            field.validate_spec(_marker(probe=[{"method": "GET", "path": "/search?q=static"}]))

    def test_a_request_path_must_be_relative(self) -> None:
        with self.assertRaises(ValueError):
            field.validate_spec(_inband(probe=[{"path": "http://evil/x"}]))


class DiscoveryTests(unittest.TestCase):
    def _with_discover(self, discover: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "strategy": "inband_differential",
            "observable_effect": "disclosed values",
            "checks": [{
                "label": "c", "discover": discover,
                "probe": [{"method": "POST", "path": "/g", "body": "{{project}}"}],
                "control": [{"method": "POST", "path": "/g", "body": "{{project}}"}],
                "extract": {"json_values": "body"},
            }],
        }

    def test_a_step_may_only_use_names_an_earlier_step_bound(self) -> None:
        good = self._with_discover([
            {"bind": "project", "query": [{"method": "POST", "path": "/g", "body": "list"}],
             "extract": {"json_values": "fullPath"}},
        ])
        field.validate_spec(good)
        bad = self._with_discover([
            {"bind": "issue", "query": [{"method": "POST", "path": "/g", "body": "{{project}}"}],
             "extract": {"json_values": "iid"}},
        ])
        with self.assertRaises(ValueError):
            field.validate_spec(bad)

    def test_a_derive_step_binds_a_computed_value(self) -> None:
        spec = self._with_discover([
            {"bind": "project", "query": [{"method": "POST", "path": "/g", "body": "list"}],
             "extract": {"json_values": "fullPath"}},
            {"bind": "gid", "derive": "gid://x/{{project}}"},
        ])
        validated = field.validate_spec(spec)
        self.assertEqual(validated["checks"][0]["discover"][1],
                         {"bind": "gid", "derive": "gid://x/{{project}}"})

    def test_probe_cannot_reference_an_undiscovered_name(self) -> None:
        spec = self._with_discover([])  # probe uses {{project}} but nothing binds it
        with self.assertRaises(ValueError):
            field.validate_spec(spec)

    def test_the_engine_fans_out_and_reports_per_target(self) -> None:
        """Two discovered projects, each leaking a distinct body, yield two findings."""
        spec = field.validate_spec({
            "strategy": "inband_differential", "observable_effect": "disclosed bodies",
            "checks": [{
                "label": "notes",
                "discover": [
                    {"bind": "project",
                     "query": [{"method": "POST", "path": "/g", "body": "list"}],
                     "extract": {"json_values": "fullPath"}},
                ],
                "probe": [{"method": "POST", "path": "/g", "body": "probe:{{project}}"}],
                "control": [{"method": "POST", "path": "/g", "body": "control:{{project}}"}],
                "extract": {"json_values": "body"},
            }],
        })
        script = field.emit_field_poc("CVE-2026-0001", spec)
        ns: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), ns)

        class FakeTarget:
            base = "http://x"
            def send(self, step):
                body = step.get("body", "")
                if body == "list":
                    return 200, json.dumps({"nodes": [{"fullPath": "a"}, {"fullPath": "b"}]})
                if body.startswith("probe:"):
                    name = body.split(":", 1)[1]
                    return 200, json.dumps({"notes": [{"body": "pub"}, {"body": "secret-" + name}]})
                return 200, json.dumps({"notes": [{"body": "pub"}]})  # control: only public

        check = spec["checks"][0]
        contexts = ns["discover"](FakeTarget(), check["discover"])
        self.assertEqual([c["project"] for c in contexts], ["a", "b"])
        findings: list[dict[str, Any]] = []
        for ctx in contexts:
            ns["_run_inband"](FakeTarget(), check, ctx, False, findings)
        self.assertEqual([f["value"] for f in findings], ["secret-a", "secret-b"])
        self.assertEqual([f["where"]["project"] for f in findings], ["a", "b"])


class EmittedScriptTests(unittest.TestCase):
    def test_both_strategies_emit_valid_python(self) -> None:
        for spec in (field.validate_spec(_inband()), field.validate_spec(_marker())):
            script = field.emit_field_poc("CVE-2026-0001", spec)
            with self.subTest(strategy=spec["strategy"]):
                ast.parse(script)
                self.assertTrue(script.startswith("#!/usr/bin/env python3"))
                self.assertIn(f'"strategy": "{spec["strategy"]}"', script)

    def test_the_spec_is_frozen_into_the_script(self) -> None:
        spec = field.validate_spec(_inband())
        script = field.emit_field_poc("CVE-2026-0001", spec)
        # The embedded SPEC parses back to the same object the lab validated.
        tree = ast.parse(script)
        assign = next(
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(getattr(t, "id", None) == "SPEC" for t in node.targets)
        )
        self.assertEqual(ast.literal_eval(assign.value), spec)

    def test_the_fixture_is_not_baked_into_the_deliverable(self) -> None:
        """The fixture seeds CVELab's own instance; it must not ship in the PoC."""
        spec = field.validate_spec(_inband(fixture={
            "command": ["seed"], "files": {"seed.rb": "secret marker xyz"},
            "env": {"CVELAB_MARKER": "xyz"},
        }))
        self.assertIn("fixture", spec)
        script = field.emit_field_poc("CVE-2026-0001", spec)
        self.assertNotIn("xyz", script)
        self.assertNotIn("seed.rb", script)

    def test_the_script_refuses_without_authorization(self) -> None:
        script = field.emit_field_poc("CVE-2026-0001", field.validate_spec(_inband()))
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "field-poc.py"
            path.write_text(script)
            run = subprocess.run(
                ["python3", str(path), "--target", "http://127.0.0.1:1"],
                capture_output=True, text=True,
            )
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("--authorized", run.stderr)

    def test_the_token_extractor_set_difference_is_the_proof(self) -> None:
        """Run the emitted inband logic over canned responses, no network."""
        spec = field.validate_spec(_inband())
        extractor = spec["checks"][0]["extract"]
        script = field.emit_field_poc("CVE-2026-0001", spec)
        namespace: dict[str, Any] = {}
        exec(compile(script, "<field-poc.py>", "exec"), namespace)
        probe = {"data": {"notes": [{"body": "public"}, {"body": "SECRET"}]}}
        control = {"data": {"notes": [{"body": "public"}]}}
        tokens = namespace["tokens"]
        probe_tokens = tokens(json.dumps(probe), extractor)
        control_tokens = set(tokens(json.dumps(control), extractor))
        disclosed = [t for t in probe_tokens if t not in control_tokens]
        self.assertEqual(disclosed, ["SECRET"])


class ProofTests(unittest.TestCase):
    """The lab hands the script over only if it tells the instances apart."""

    def _lab(self, vulnerable_observed: bool, patched_observed: bool) -> dict[str, Any]:
        outcomes = {
            "vulnerable": {"variant": "vulnerable", "image": "img:v", "fixture": None,
                           "observed": vulnerable_observed, "exit_code": 0,
                           "observation": {}, "output": "", "stderr": ""},
            "patched": {"variant": "patched", "image": "img:p", "fixture": None,
                        "observed": patched_observed, "exit_code": 0,
                        "observation": {}, "output": "", "stderr": ""},
        }
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            spec_path = output / "spec.json"
            spec_path.write_text(json.dumps(_inband()))
            with mock.patch.object(
                field, "_run_variant",
                side_effect=lambda cve, variant, *a, **k: outcomes[variant],
            ):
                result = field.run_field_lab(
                    "CVE-2026-0001", output, "img:v", "img:p", 8080, "/", spec_path
                )
            artifacts = Path(result["lab_dir"]) / "artifacts"
            return {
                "result": result,
                "evidence": json.loads((artifacts / "EVIDENCE.json").read_text()),
                "script": (artifacts / "field-poc.py").read_text(),
            }

    def test_fires_on_vulnerable_and_silent_on_fixed_is_proven(self) -> None:
        lab = self._lab(vulnerable_observed=True, patched_observed=False)
        self.assertIs(lab["result"]["ok"], True)
        self.assertEqual(lab["evidence"]["status"], "REAL_FIELD_POC_VALIDATED")
        self.assertIs(lab["evidence"]["proof_checks"]["field_poc_proven"], True)
        self.assertTrue(lab["script"].startswith("#!/usr/bin/env python3"))

    def test_firing_on_both_is_not_a_field_poc(self) -> None:
        """An effect the fixed build also shows is normal behavior, not the bug."""
        lab = self._lab(vulnerable_observed=True, patched_observed=True)
        self.assertIs(lab["result"]["ok"], False)
        self.assertNotEqual(lab["evidence"]["status"], "REAL_FIELD_POC_VALIDATED")
        self.assertIs(lab["evidence"]["proof_checks"]["silent_on_fixed"], False)

    def test_firing_on_neither_is_not_proven(self) -> None:
        lab = self._lab(vulnerable_observed=False, patched_observed=False)
        self.assertIs(lab["result"]["ok"], False)
        self.assertIs(lab["evidence"]["proof_checks"]["effect_observed_on_vulnerable"], False)

    def test_a_fixed_image_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            spec_path = output / "spec.json"
            spec_path.write_text(json.dumps(_inband()))
            with self.assertRaises(ValueError):
                field.run_field_lab("CVE-2026-0001", output, "img:v", None, 8080, "/", spec_path)


class SidecarTests(unittest.TestCase):
    def test_the_field_script_runs_in_the_lab_network_namespace(self) -> None:
        script = field.emit_field_poc("CVE-2026-0001", field.validate_spec(_inband()))
        completed = subprocess.CompletedProcess(
            ["docker"], 0, '{"observed": true}\nOBSERVED', ""
        )
        with mock.patch.object(field.subprocess, "run", return_value=completed) as run:
            outcome = field._run_field_script("lab", 8080, script, "inband_differential")
        argv = list(run.call_args.args[0])
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "container:lab")
        self.assertNotIn("-p", argv)
        self.assertIn("CVELAB_BASE=http://127.0.0.1:8080", argv)
        self.assertTrue(outcome["observed"])
        self.assertEqual(outcome["observation"], {"observed": True})


if __name__ == "__main__":
    unittest.main()
