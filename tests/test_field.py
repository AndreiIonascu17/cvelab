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
import base64
import contextlib
import io
import json
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import field, releases, sidecar


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

    def test_a_callback_strategy_still_needs_its_requests(self) -> None:
        """It is emitted now, so what it is refused for is an empty spec."""
        with self.assertRaises(ValueError) as raised:
            field.validate_spec({"strategy": "oob_callback", "observable_effect": "x"})
        self.assertIn("probe", str(raised.exception))

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

    def test_a_match_predicate_the_script_cannot_evaluate_is_refused(self) -> None:
        """The script reads body_contains and nothing else.

        Any other key validated and was then ignored, so a spec asking for a
        regex got a bare marker check and reported on something it never
        asked for.
        """
        with self.assertRaises(ValueError):
            field.validate_spec(_marker(match={"body_regex": "<b>{{marker}}"}))
        spec = field.validate_spec(_marker(match={"body_contains": "x{{marker}}"}))
        self.assertEqual(spec["checks"][0]["match"], {"body_contains": "x{{marker}}"})

    def test_a_request_path_must_be_relative(self) -> None:
        with self.assertRaises(ValueError):
            field.validate_spec(_inband(probe=[{"path": "http://evil/x"}]))


class FakeHTTP:
    """A stand-in for the real HTTP target, with the contract it owes.

    A response is (status, body, headers), and fill() merges the operator's
    inputs the way the real target does -- here there are none.
    """

    base = "http://x"
    inputs: dict[str, str] = {}

    @staticmethod
    def subst(obj: Any, ctx: dict[str, Any]) -> Any:
        text = json.dumps(obj)
        for key, value in ctx.items():
            text = text.replace("{{" + key + "}}", json.dumps(str(value))[1:-1])
        return json.loads(text)

    def fill(self, obj: Any, ctx: dict[str, Any]) -> Any:
        return self.subst(obj, dict(self.inputs, **ctx))

    def exchange(
        self, steps: list[dict[str, Any]], ctx: dict[str, Any] | None = None
    ) -> tuple[int, str, dict[str, str]]:
        last = (0, "", {})
        for step in steps:
            last = self.send(step)
        return last

    def discover_exchange(
        self, steps: list[dict[str, Any]]
    ) -> tuple[int, str, dict[str, str]]:
        """What a discovery step runs through, which here is the same thing."""
        return self.exchange(steps)


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

        class FakeTarget(FakeHTTP):
            def send(self, step):
                body = step.get("body", "")
                if body == "list":
                    return 200, json.dumps({"nodes": [{"fullPath": "a"}, {"fullPath": "b"}]}), {}
                if body.startswith("probe:"):
                    name = body.split(":", 1)[1]
                    return 200, json.dumps({"notes": [{"body": "pub"}, {"body": "secret-" + name}]}), {}
                # control: only the public note
                return 200, json.dumps({"notes": [{"body": "pub"}]}), {}

        check = spec["checks"][0]
        contexts = ns["discover"](FakeTarget(), check["discover"])
        self.assertEqual([c["project"] for c in contexts], ["a", "b"])
        findings: list[dict[str, Any]] = []
        for ctx in contexts:
            ns["_run_inband"](FakeTarget(), check, ctx, False, findings)
        self.assertEqual([f["value"] for f in findings], ["secret-a", "secret-b"])
        self.assertEqual([f["where"]["project"] for f in findings], ["a", "b"])

    def _two_step_engine(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """A spec that enumerates projects, then the items inside each."""
        spec = field.validate_spec({
            "strategy": "inband_differential", "observable_effect": "disclosed bodies",
            "checks": [{
                "label": "notes",
                "discover": [
                    {"bind": "project",
                     "query": [{"method": "GET", "path": "/projects"}],
                     "extract": {"json_values": "fullPath"}},
                    {"bind": "item",
                     "query": [{"method": "GET", "path": "/items/{{project}}"}],
                     "extract": {"json_values": "iid"}},
                ],
                "probe": [{"method": "GET", "path": "/n/{{project}}/{{item}}"}],
                "control": [{"method": "GET", "path": "/c/{{project}}/{{item}}"}],
                "extract": {"json_values": "body"},
            }],
        })
        namespace: dict[str, Any] = {"__name__": "not_main"}
        exec(compile(field.emit_field_poc("CVE-2026-0001", spec), "<f>", "exec"), namespace)  # noqa: S102
        return spec, namespace

    def test_the_cap_takes_a_share_from_every_parent(self) -> None:
        """A busy first project must not crowd the others out of the run.

        Truncating a flat list of children let one project's items fill the
        cap, so every later project went untested and the sweep reported a
        clean target.
        """
        spec, namespace = self._two_step_engine()
        cap = namespace["MAX_CONTEXTS"]

        class Crowded(FakeHTTP):
            def send(self, step: dict[str, Any]) -> tuple[int, str, dict[str, str]]:
                path = step["path"]
                if path == "/projects":
                    return 200, json.dumps([{"fullPath": "busy"}, {"fullPath": "quiet"}]), {}
                if path.endswith("/busy"):
                    return 200, json.dumps([{"iid": str(i)} for i in range(cap * 2)]), {}
                return 200, json.dumps([{"iid": "only"}]), {}

        contexts = namespace["discover"](Crowded(), spec["checks"][0]["discover"])
        self.assertEqual(len(contexts), cap)
        projects = {ctx["project"] for ctx in contexts}
        self.assertEqual(projects, {"busy", "quiet"})

    def test_an_empty_discovery_tests_nothing_rather_than_a_literal(self) -> None:
        """Finding nothing to test is its own outcome.

        With no project discovered, the probe was sent anyway, carrying the
        unreplaced {{project}} in its path, and the empty result read as a
        clean target.
        """
        spec, namespace = self._two_step_engine()

        class Empty(FakeHTTP):
            def __init__(self) -> None:
                self.paths: list[str] = []

            def send(self, step: dict[str, Any]) -> tuple[int, str, dict[str, str]]:
                self.paths.append(step["path"])
                return 200, json.dumps([]), {}

        target = Empty()
        contexts = namespace["discover"](target, spec["checks"][0]["discover"])
        self.assertEqual(contexts, [])
        self.assertEqual(target.paths, ["/projects"])
        self.assertFalse(any("{{" in path for path in target.paths))


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
        # It is JSON text rather than a Python literal, because a bodyless
        # request carries null, which is not a Python name.
        tree = ast.parse(script)
        assign = next(
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(getattr(t, "id", None) == "SPEC" for t in node.targets)
        )
        self.assertEqual(json.loads(assign.value.args[0].value), spec)

    def test_a_bodyless_request_still_emits_a_script_that_runs(self) -> None:
        """Every request carries "body": null, which Python cannot name.

        Embedded as a literal, a plain GET probe emitted a script that died
        with NameError on import, against every target, before sending a
        single request. Only the GitLab spec escaped it, by sending a body
        on every request.
        """
        spec = field.validate_spec(_inband(
            probe=[{"method": "GET", "path": "/a"}],
            control=[{"method": "GET", "path": "/b"}],
        ))
        script = field.emit_field_poc("CVE-2026-0001", spec)
        namespace: dict[str, Any] = {"__name__": "not_main"}
        exec(compile(script, "field-poc.py", "exec"), namespace)  # noqa: S102
        self.assertIsNone(namespace["SPEC"]["checks"][0]["probe"][0]["body"])

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

    def test_the_script_names_its_target_before_it_sends_anything(self) -> None:
        """Running it is the operator's own statement that they may test the host.

        There is no gate to pass, so what the script owes is visibility: the
        target and the effect go to stderr before the first request, which
        puts them in the terminal and in whatever captured the output. Port 1
        refuses the connection, so the run cannot get past that point.
        """
        script = field.emit_field_poc("CVE-2026-0001", field.validate_spec(_inband()))
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "field-poc.py"
            path.write_text(script)
            run = subprocess.run(
                ["python3", str(path), "--target", "127.0.0.1:1"],
                capture_output=True, text=True,
            )
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("127.0.0.1:1", run.stderr)
        self.assertIn(_inband()["observable_effect"], run.stderr)
        # stdout carries the verdict and --json output, so it stays clean.
        self.assertNotIn("target ", run.stdout)

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
        probe_tokens = tokens((200, json.dumps(probe), {}), extractor)
        control_tokens = set(tokens((200, json.dumps(control), {}), extractor))
        disclosed = [t for t in probe_tokens if t not in control_tokens]
        self.assertEqual(disclosed, ["SECRET"])


class TargetTests(unittest.TestCase):
    """One target, however the operator wrote it.

    An engagement names a host and a port, so the script takes that shape
    directly rather than requiring a URL to be assembled around it.
    """

    def setUp(self) -> None:
        script = field.emit_field_poc("CVE-2026-0001", field.validate_spec(_inband()))
        namespace: dict[str, Any] = {"__name__": "not_main"}
        exec(compile(script, "<field-poc.py>", "exec"), namespace)  # noqa: S102
        self.normalize = namespace["normalize_target"]

    def test_a_host_and_port_needs_no_scheme(self) -> None:
        for written, expected in [
            ("10.0.0.5:8080", "http://10.0.0.5:8080"),
            ("app.example.com", "http://app.example.com"),
            # A bare 443 means TLS; that is what host:443 means in practice.
            ("app.example.com:443", "https://app.example.com:443"),
            ("[2001:db8::1]:8443", "http://[2001:db8::1]:8443"),
            ("https://app.example.com/", "https://app.example.com"),
            ("  10.0.0.5:8080  ", "http://10.0.0.5:8080"),
        ]:
            with self.subTest(written=written):
                self.assertEqual(self.normalize(written), expected)

    def test_a_target_that_is_not_one_host_is_refused(self) -> None:
        for written in [
            "",
            "   ",
            "ftp://host",
            "http://",
            # The spec supplies every request path, appended to this base, so
            # a path here would prefix none of them.
            "https://host/admin",
            "https://host/?q=1",
            "host:99999",
            "host:not-a-port",
        ]:
            with self.subTest(written=written):
                with self.assertRaises(SystemExit):
                    self.normalize(written)


class SubstitutionTests(unittest.TestCase):
    """A value read off the target is data, never part of the request's syntax."""

    def setUp(self) -> None:
        script = field.emit_field_poc("CVE-2026-0001", field.validate_spec(_inband()))
        namespace: dict[str, Any] = {"__name__": "not_main"}
        exec(compile(script, "<field-poc.py>", "exec"), namespace)  # noqa: S102
        self.subst = namespace["_subst"]

    def test_a_discovered_value_with_a_quote_stays_one_value(self) -> None:
        """Substituted into the JSON text raw, it broke the request.

        The names are filled into the serialized request, so a project named
        `a"b` ended the string early: the script either died in json.loads or
        sent a request whose other fields had moved.
        """
        for value in ['a"b', "a\\b", 'a","method":"DELETE','a\nb', "ünicode"]:
            with self.subTest(value=value):
                out = self.subst({"path": "/p/{{name}}", "method": "GET"}, {"name": value})
                self.assertEqual(out["path"], "/p/" + value)
                self.assertEqual(out["method"], "GET")


class ProofTests(unittest.TestCase):
    """The lab hands the script over only if it tells the instances apart."""

    def _lab(
        self,
        vulnerable_observed: bool,
        patched_observed: bool,
        patched_ran: bool = True,
    ) -> dict[str, Any]:
        outcomes = {
            "vulnerable": {"variant": "vulnerable", "image": "img:v", "fixture": None,
                           "observed": vulnerable_observed, "ran": True,
                           "verdict": "OBSERVED" if vulnerable_observed else "NOT_OBSERVED",
                           "exit_code": 0, "observation": {}, "output": "", "stderr": ""},
            "patched": {"variant": "patched", "image": "img:p", "fixture": None,
                        "observed": patched_observed, "ran": patched_ran,
                        "verdict": ("OBSERVED" if patched_observed else "NOT_OBSERVED")
                        if patched_ran else None,
                        "exit_code": 0 if patched_ran else 1,
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

    def test_a_script_that_crashed_on_the_fixed_image_is_not_silence(self) -> None:
        """A run that never finished observed nothing because it never looked.

        Reading only the last line, an unreachable target, a traceback or a
        killed sidecar on the fixed image read as silence and the lab was
        stored as a validated field PoC.
        """
        lab = self._lab(
            vulnerable_observed=True, patched_observed=False, patched_ran=False
        )
        self.assertIs(lab["result"]["ok"], False)
        self.assertNotEqual(lab["evidence"]["status"], "REAL_FIELD_POC_VALIDATED")
        self.assertIs(lab["evidence"]["proof_checks"]["silent_on_fixed"], False)
        self.assertIs(lab["evidence"]["proof_checks"]["script_ran_on_both"], False)

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
            outcome = field._run_field_script("lab", 8080, script, "http")
        argv = list(run.call_args.args[0])
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "container:lab")
        self.assertNotIn("-p", argv)
        self.assertIn("CVELAB_BASE=http://127.0.0.1:8080", argv)
        self.assertTrue(outcome["observed"])
        self.assertEqual(outcome["observation"], {"observed": True})


if __name__ == "__main__":
    unittest.main()


class SocketTransportTests(unittest.TestCase):
    """A service reachable as a host and a port that does not speak HTTP."""

    def _tcp(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "marker_roundtrip",
            "transport": "tcp",
            "observable_effect": "a value an unauthenticated client stored and read back",
            "probe": [{"send": "SET k {{marker}}\r\n", "read_until": "\r\n"}],
            "observe": [{"send": "GET k\r\n", "read_until": "\r\n"}],
        }
        spec.update(extra)
        return spec

    def test_a_socket_spec_validates_and_keeps_its_transport(self) -> None:
        spec = field.validate_spec(self._tcp())
        self.assertEqual(spec["transport"], "tcp")
        self.assertEqual(spec["checks"][0]["probe"][0]["send"], "SET k {{marker}}\r\n")

    def test_http_stays_the_default_so_existing_specs_are_untouched(self) -> None:
        spec = field.validate_spec({
            "strategy": "marker_roundtrip",
            "observable_effect": "x",
            "probe": [{"method": "POST", "path": "/c", "body": "{{marker}}"}],
            "observe": {"method": "GET", "path": "/c"},
        })
        self.assertEqual(spec["transport"], "http")
        self.assertEqual(spec["checks"][0]["probe"][0]["method"], "POST")

    def test_an_unknown_transport_is_refused(self) -> None:
        for bad in ("ssh", "udp", "", None):
            with self.subTest(transport=bad):
                with self.assertRaises(ValueError):
                    field.validate_spec(self._tcp(transport=bad))

    def test_a_message_sends_text_or_bytes_but_not_both(self) -> None:
        for probe, ok in (
            ([{"send": "A {{marker}}\r\n"}], True),
            ([{"send": "", "read_until": "x"}, {"send": "{{marker}}"}], True),
            ([{"send": "{{marker}}", "send_hex": "2a31"}], False),
            ([{}], False),
        ):
            with self.subTest(probe=probe):
                spec = self._tcp(probe=probe)
                if ok:
                    field.validate_spec(spec)
                else:
                    with self.assertRaises(ValueError):
                        field.validate_spec(spec)

    def test_send_hex_must_be_bytes_and_cannot_carry_the_marker(self) -> None:
        """A marker is text; hex framing is for a protocol that is not."""
        for raw in ("2a3", "zz", "{{marker}}"):
            with self.subTest(send_hex=raw):
                with self.assertRaises(ValueError):
                    field.validate_spec(self._tcp(
                        probe=[{"send": "{{marker}}"}, {"send_hex": raw}]
                    ))
        field.validate_spec(self._tcp(probe=[{"send": "{{marker}}"}, {"send_hex": "2A310D0A"}]))

    def test_discovery_is_refused_rather_than_silently_skipped(self) -> None:
        """Its steps are HTTP requests, so a socket spec has nothing to run them with."""
        with self.assertRaises(ValueError) as raised:
            field.validate_spec(self._tcp(discover=[
                {"bind": "k", "query": [{"method": "GET", "path": "/k"}],
                 "extract": {"json_values": "id"}},
            ]))
        self.assertIn("http, ws and wss", str(raised.exception))
        self.assertIn("not tcp", str(raised.exception))

    def test_the_sidecar_passes_a_host_and_port_not_a_url(self) -> None:
        """The socket script refuses a URL, so the proof has to match it."""
        completed = subprocess.CompletedProcess(["docker"], 0, "OBSERVED\n", "")
        for transport, expected in (
            ("http", "CVELAB_BASE=http://127.0.0.1:6379"),
            ("tcp", "CVELAB_BASE=127.0.0.1:6379"),
            ("tls", "CVELAB_BASE=127.0.0.1:6379"),
        ):
            with self.subTest(transport=transport):
                with mock.patch.object(
                    field.subprocess, "run", return_value=completed
                ) as run:
                    field._run_field_script("lab", 6379, "print()", transport)
                self.assertIn(expected, run.call_args.args[0])

    def test_the_emitted_script_refuses_a_url_for_a_socket_target(self) -> None:
        script = field.emit_field_poc("CVE-2026-0002", field.validate_spec(self._tcp()))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        for bad in ("http://10.0.0.5:6379", "10.0.0.5", "", "10.0.0.5:6379/x"):
            with self.subTest(target=bad):
                with self.assertRaises(SystemExit):
                    namespace["normalize_target"](bad)
        self.assertEqual(namespace["normalize_target"]("10.0.0.5:6379"), ("10.0.0.5", 6379))

    def test_a_socket_sequence_shares_one_connection(self) -> None:
        """A protocol needing a login before a command cannot be independent messages."""
        script = field.emit_field_poc("CVE-2026-0002", field.validate_spec(self._tcp()))
        exchange = script.split("def _socket_exchange", 1)[1].split("\n    def ", 1)[0]
        self.assertEqual(exchange.count("create_connection"), 1)
        self.assertIn("for message in messages", exchange)


class BlindCallbackTests(unittest.TestCase):
    """An effect that sends nothing back: the evidence is the target reaching out."""

    def _oob(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "oob_callback",
            "observable_effect": "the server fetches a URL the caller supplied",
            "probe": [{"method": "POST", "path": "/fetch",
                       "body": '{"url": "http://{{callback}}/{{marker}}"}'}],
        }
        spec.update(extra)
        return spec

    def test_the_strategy_is_emitted_now_and_not_refused(self) -> None:
        spec = field.validate_spec(self._oob())
        self.assertEqual(spec["strategy"], "oob_callback")
        self.assertIn("oob_callback", field.STRATEGIES)

    def test_the_probe_must_place_the_callback(self) -> None:
        with self.assertRaises(ValueError) as raised:
            field.validate_spec(self._oob(
                probe=[{"method": "POST", "path": "/f", "body": "{{marker}}"}]
            ))
        self.assertIn("{{callback}}", str(raised.exception))

    def test_the_probe_must_place_the_marker_too(self) -> None:
        """Without it an unrelated request, or an older payload still firing,
        would read as a result."""
        with self.assertRaises(ValueError) as raised:
            field.validate_spec(self._oob(
                probe=[{"method": "POST", "path": "/f", "body": "http://{{callback}}/"}]
            ))
        self.assertIn("{{marker}}", str(raised.exception))

    def test_it_works_over_a_socket_probe_as_well(self) -> None:
        """The payload may travel over anything; the callback is its own channel."""
        spec = field.validate_spec(self._oob(
            transport="tcp",
            probe=[{"send": "FETCH http://{{callback}}/{{marker}}\r\n", "read_until": "\r\n"}],
        ))
        self.assertEqual(spec["transport"], "tcp")

    def test_only_a_hit_carrying_this_runs_marker_counts(self) -> None:
        script = field.emit_field_poc("CVE-2026-0003", field.validate_spec(self._oob()))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        collector = namespace["Collector"]("127.0.0.1", 0)
        try:
            collector.hits = [{"from": "10.0.0.9", "at": "now", "raw": "GET /other HTTP/1.1"}]
            self.assertIsNone(collector.wait("cvelab-aaaa", 0.3))
            collector.hits.append(
                {"from": "10.0.0.9", "at": "now", "raw": "GET /cvelab-aaaa HTTP/1.1"}
            )
            self.assertIsNotNone(collector.wait("cvelab-aaaa", 0.3))
        finally:
            collector.close()

    def test_the_listener_answers_a_real_fetch_and_records_it(self) -> None:
        script = field.emit_field_poc("CVE-2026-0003", field.validate_spec(self._oob()))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        collector = namespace["Collector"]("127.0.0.1", 0)
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{collector.port}/cvelab-feed", timeout=5
            ) as answer:
                self.assertEqual(answer.status, 200)
            hit = collector.wait("cvelab-feed", 5)
            self.assertIsNotNone(hit)
            self.assertEqual(hit["from"], "127.0.0.1")
        finally:
            collector.close()

    def test_a_non_http_connection_is_recorded_too(self) -> None:
        """A payload may reach out with something that is not HTTP at all."""
        script = field.emit_field_poc("CVE-2026-0003", field.validate_spec(self._oob()))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        collector = namespace["Collector"]("127.0.0.1", 0)
        try:
            with socket.create_connection(("127.0.0.1", collector.port), timeout=5) as sock:
                sock.sendall(b"HELO cvelab-raw\n\n")
            self.assertIsNotNone(collector.wait("cvelab-raw", 5))
        finally:
            collector.close()

    def test_the_bound_address_is_the_default_the_payload_advertises(self) -> None:
        """Across a network the operator has to say how the target reaches them,
        which is what --callback is for; bound is only right when it is direct."""
        script = field.emit_field_poc("CVE-2026-0003", field.validate_spec(self._oob()))
        self.assertIn("--callback", script)
        self.assertIn("args.callback or", script)
        self.assertIn("--callback-wait", script)


class DirectObservationTests(unittest.TestCase):
    """The effect is in the one response the weakness lets you ask for.

    A set difference is the wrong instrument for an authorization finding, and
    this was measured rather than reasoned: asked to compare an unauthenticated
    read against an authorized one, probe-minus-control is empty on the
    vulnerable build, because both see the data, and on the fixed build it
    yields the 401 the probe got and the control did not -- so the proof fired
    on the patched side.
    """

    def _direct(self, expect: dict[str, Any], **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "observable_effect": "a token returned to an unauthenticated requester",
            "probe": [{"method": "GET", "path": "/report"}],
            "expect": expect,
        }
        spec.update(extra)
        return spec

    def test_each_expectation_validates(self) -> None:
        for expect in (
            {"status": 200},
            {"header": "X-Report-Token"},
            {"body_contains": "root:x:0:0"},
            {"extract": {"json_values": "token"}},
        ):
            with self.subTest(expect=expect):
                spec = field.validate_spec(self._direct(expect))
                self.assertEqual(spec["checks"][0]["expect"], expect)

    def test_a_meaningless_expectation_is_refused(self) -> None:
        for expect in (
            {}, {"status": 9999}, {"status": "200"}, {"header": " "},
            {"body_contains": ""}, {"status": 200, "header": "X"}, {"nope": 1},
        ):
            with self.subTest(expect=expect):
                with self.assertRaises(ValueError):
                    field.validate_spec(self._direct(expect))

    def _run(self, expect: dict[str, Any], response: tuple[int, str, dict[str, str]]) -> list:
        script = field.emit_field_poc("CVE-2026-0004", field.validate_spec(self._direct(expect)))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)

        class One(FakeHTTP):
            def exchange(
                self, steps: list[dict[str, Any]], ctx: dict[str, Any] | None = None
            ) -> tuple[int, str, dict[str, str]]:
                return response

        findings: list[dict[str, Any]] = []
        namespace["_run_direct"](One(), namespace["SPEC"]["checks"][0], {}, False, findings)
        return findings

    def test_a_status_the_route_should_not_answer_with_is_the_finding(self) -> None:
        self.assertEqual(
            [f["value"] for f in self._run({"status": 200}, (200, "", {}))], ["200"]
        )
        self.assertEqual(self._run({"status": 200}, (401, "", {})), [])

    def test_evidence_in_a_response_header_is_reachable(self) -> None:
        """One measured lab leaked its token in a header and nowhere else."""
        found = self._run(
            {"header": "X-Report-Token"}, (200, "", {"X-Report-Token": "tok-7f3a91"})
        )
        self.assertEqual([f["value"] for f in found], ["tok-7f3a91"])
        self.assertEqual(self._run({"header": "X-Report-Token"}, (200, "", {})), [])

    def test_the_header_lookup_ignores_case(self) -> None:
        found = self._run({"header": "x-report-token"}, (200, "", {"X-Report-Token": "t"}))
        self.assertEqual([f["value"] for f in found], ["t"])

    def test_body_and_extractor_expectations_both_report(self) -> None:
        self.assertEqual(
            [f["value"] for f in self._run({"body_contains": "root:x:0:0"},
                                           (200, "root:x:0:0:root:/root", {}))],
            ["root:x:0:0"],
        )
        self.assertEqual(
            [f["value"] for f in self._run({"extract": {"json_values": "token"}},
                                           (200, '{"token": "abc"}', {}))],
            ["abc"],
        )


class OperatorInputTests(unittest.TestCase):
    """Values the lab cannot know, which a control request often needs."""

    def _spec(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "observable_effect": "x",
            "inputs": ["credential"],
            "probe": [{"method": "GET", "path": "/r",
                       "headers": {"Authorization": "Bearer {{credential}}"}}],
            "expect": {"status": 200},
        }
        spec.update(extra)
        return spec

    def test_a_declared_input_may_be_used_in_a_request(self) -> None:
        self.assertEqual(field.validate_spec(self._spec())["inputs"], ["credential"])

    def test_an_undeclared_name_is_refused(self) -> None:
        with self.assertRaises(ValueError) as raised:
            field.validate_spec(self._spec(inputs=[]))
        self.assertIn("credential", str(raised.exception))

    def test_an_input_cannot_shadow_the_marker_or_the_callback(self) -> None:
        for name in ("marker", "callback"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    field.validate_spec(self._spec(inputs=[name]))

    def test_the_script_refuses_to_run_without_the_value(self) -> None:
        """Otherwise it sends {{credential}} literally and reports a clean target."""
        script = field.emit_field_poc("CVE-2026-0004", field.validate_spec(self._spec()))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        with self.assertRaises(SystemExit) as raised:
            namespace["_inputs"]([])
        self.assertIn("credential", str(raised.exception))
        with self.assertRaises(SystemExit):
            namespace["_inputs"](["credential"])  # no = sign
        with self.assertRaises(SystemExit):
            namespace["_inputs"](["other=x"])
        self.assertEqual(namespace["_inputs"](["credential=s3cret"]), {"credential": "s3cret"})

    def test_a_credential_never_reaches_the_output_or_a_finding(self) -> None:
        """The context is printed and recorded with every finding; inputs are not."""
        script = field.emit_field_poc("CVE-2026-0004", field.validate_spec(self._spec()))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        target = namespace["Target"].__new__(namespace["Target"])
        target.inputs = {"credential": "s3cret"}
        target.transport = "http"
        target.base = "http://10.0.0.5:8080"
        filled = target.fill([{"path": "/r/{{credential}}"}], {})
        self.assertEqual(filled[0]["path"], "/r/s3cret")
        # the target is filled in alongside, and must not shadow an input
        self.assertEqual(
            target.fill([{"path": "/{{target}}/{{credential}}"}], {})[0]["path"],
            "/10.0.0.5:8080/s3cret",
        )
        self.assertIn("dict(self.inputs, **ctx)", script)
        self.assertIn('"where": ctx', script)


class PublishedPoCShapeTests(unittest.TestCase):
    """The shape a single-file PoC is expected to have when handed over."""

    def _spec(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "observable_effect": "an admin route answering 200 to an unauthenticated requester",
            "probe": [{"method": "GET", "path": "/admin"}],
            "expect": {"status": 200},
        }
        spec.update(extra)
        return spec

    _PLAN = {
        "repository": "https://github.com/django/django.git",
        "revisions": {"vulnerable": "366d9ae^", "patched": "366d9ae"},
        "published_releases": [{"ecosystem": "pip", "package": "django",
                                "last_vulnerable": "6.0.5", "first_patched": "6.0.6"}],
    }

    def test_the_header_names_the_cve_the_versions_and_the_fix(self) -> None:
        """A reader can tell at a glance whether the host is even in range."""
        header = field.emit_field_poc(
            "CVE-2026-8404", field.validate_spec(self._spec()), self._PLAN
        ).split("from __future__")[0]
        self.assertIn("CVE-2026-8404 - an admin route answering 200", header)
        self.assertIn("django <= 6.0.5 (pip), fixed in 6.0.6", header)
        self.assertIn("https://github.com/django/django.git", header)
        self.assertIn("366d9ae", header)
        self.assertIn("Strategy      : direct_observation", header)

    def test_the_usage_lines_name_the_file_it_is_written_as(self) -> None:
        header = field.emit_field_poc(
            "CVE-2026-8404", field.validate_spec(self._spec()), self._PLAN,
            "Manual-PoC.py",
        ).split("from __future__")[0]
        self.assertIn("python3 Manual-PoC.py 10.0.0.5:8080", header)

    def test_a_lab_without_version_metadata_still_emits(self) -> None:
        header = field.emit_field_poc(
            "CVE-2026-8404", field.validate_spec(self._spec()), None
        ).split("from __future__")[0]
        self.assertIn("CVE-2026-8404", header)
        self.assertNotIn("Affected", header)

    def test_an_input_is_announced_in_the_header(self) -> None:
        header = field.emit_field_poc(
            "CVE-2026-8404",
            field.validate_spec(self._spec(
                inputs=["credential"],
                probe=[{"method": "GET", "path": "/admin",
                        "headers": {"Authorization": "Bearer {{credential}}"}}],
            )),
            self._PLAN,
        ).split("from __future__")[0]
        self.assertIn("--input credential=...", header)

    def test_the_footprint_describes_only_the_strategy_in_use(self) -> None:
        """It claimed a marker roundtrip's footprint on a read-only script."""
        read_only = field.emit_field_poc(
            "CVE-2026-8404", field.validate_spec(self._spec()), None
        ).split("from __future__")[0]
        self.assertIn("It leaves nothing behind", read_only)
        self.assertNotIn("cvelab-<16 hex>", read_only)
        marker = field.emit_field_poc("CVE-2026-8404", field.validate_spec({
            "strategy": "marker_roundtrip",
            "observable_effect": "a stored reflection",
            "probe": [{"method": "POST", "path": "/c", "body": "{{marker}}"}],
            "observe": {"method": "GET", "path": "/c"},
        }), None).split("from __future__")[0]
        self.assertIn("cvelab-<16 hex>", marker)
        self.assertNotIn("It leaves nothing behind", marker)

    def test_the_target_is_positional_as_well_as_named(self) -> None:
        script = field.emit_field_poc(
            "CVE-2026-8404", field.validate_spec(self._spec()), None
        )
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        self.assertIn('"target_positional"', script)
        self.assertIn('p.add_argument("--target"', script)

    def test_naming_no_target_or_two_is_refused(self) -> None:
        script = field.emit_field_poc(
            "CVE-2026-8404", field.validate_spec(self._spec()), None
        )
        # Run from a file, not with -c: Windows caps a command line at about
        # 32 KB and the deliverable is larger, so passing it as an argument
        # fails with WinError 206 before Python sees it. A file is also how it
        # is actually run, and how CVELab proves it -- the sidecar passes the
        # script in the environment rather than in argv for the same reason.
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "Manual-PoC.py"
            path.write_text(script, encoding="utf-8")
            for argv in ([], ["a", "--target", "b"]):
                with self.subTest(argv=argv):
                    done = subprocess.run(
                        [sys.executable, str(path), *argv],
                        capture_output=True, text=True, timeout=60,
                    )
                    self.assertEqual(done.returncode, 2)
                    self.assertIn("target", done.stderr.lower())


class HandshakeTransportTests(unittest.TestCase):
    """Protocols whose handshake cannot be written as bytes to send.

    The class these reach is access and post-authentication command
    execution: a file an account should not be able to read, a share that
    should not be exported, a command a restricted session should not run.
    Attacking the handshake itself is not what they are for -- the library
    performs it correctly on purpose.
    """

    def _ssh(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "transport": "ssh",
            "observable_effect": "a payroll file read by an account that should not read it",
            "inputs": ["user", "password"],
            "auth": {"username": "{{user}}", "password": "{{password}}"},
            "probe": [{"exec": "cat /srv/payroll.csv"}],
            "expect": {"body_contains": "INTERNAL-"},
        }
        spec.update(extra)
        return spec

    def _smb(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "transport": "smb",
            "observable_effect": "a share exported to every authenticated account",
            "probe": [{"op": "read", "share": "payroll", "path": "/payroll.csv"}],
            "expect": {"body_contains": "INTERNAL-"},
        }
        spec.update(extra)
        return spec

    def test_both_validate_and_keep_their_operations(self) -> None:
        ssh = field.validate_spec(self._ssh())
        self.assertEqual(ssh["checks"][0]["probe"][0], {"exec": "cat /srv/payroll.csv"})
        self.assertEqual(ssh["auth"]["username"], "{{user}}")
        smb = field.validate_spec(self._smb())
        self.assertEqual(smb["checks"][0]["probe"][0]["share"], "payroll")

    def test_a_command_is_required_and_an_op_must_be_one_of_the_few(self) -> None:
        with self.assertRaises(ValueError):
            field.validate_spec(self._ssh(probe=[{"exec": "  "}]))
        with self.assertRaises(ValueError):
            field.validate_spec(self._smb(probe=[{"op": "delete", "share": "s"}]))

    def test_a_path_cannot_climb_out_of_its_share(self) -> None:
        for path in ("/../etc/shadow", "relative", "/a/../../b"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    field.validate_spec(
                        self._smb(probe=[{"op": "read", "share": "s", "path": path}])
                    )

    def test_a_credential_in_auth_must_come_from_a_declared_input(self) -> None:
        """A spec never carries one; it names an input the operator fills."""
        with self.assertRaises(ValueError) as raised:
            field.validate_spec(self._ssh(inputs=[]))
        self.assertIn("user", str(raised.exception))
        with self.assertRaises(ValueError):
            field.validate_spec(self._ssh(auth={"nonsense": "x"}))

    def test_auth_is_meaningless_without_a_session(self) -> None:
        with self.assertRaises(ValueError) as raised:
            field.validate_spec({
                "strategy": "direct_observation", "transport": "http",
                "observable_effect": "x", "auth": {"username": "a"},
                "probe": [{"method": "GET", "path": "/"}], "expect": {"status": 200},
            })
        self.assertIn("no meaning", str(raised.exception))

    def test_the_conventional_port_is_assumed_from_a_bare_host(self) -> None:
        for spec, port in ((self._ssh(), 22), (self._smb(), 445)):
            with self.subTest(port=port):
                script = field.emit_field_poc("CVE-2026-0002", field.validate_spec(spec))
                namespace: dict[str, Any] = {}
                exec(compile(script, "<f>", "exec"), namespace)
                self.assertEqual(namespace["normalize_target"]("10.0.0.5"), ("10.0.0.5", port))
                self.assertEqual(
                    namespace["normalize_target"]("10.0.0.5:2222"), ("10.0.0.5", 2222)
                )

    def test_a_missing_library_names_the_package_and_the_extra(self) -> None:
        """An ImportError is not a useful way to learn which one is missing."""
        script = field.emit_field_poc("CVE-2026-0002", field.validate_spec(self._ssh()))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        with self.assertRaises(SystemExit) as raised:
            namespace["_require"]("a_module_that_is_not_installed", "ssh")
        said = str(raised.exception)
        self.assertIn("pip install paramiko", said)
        self.assertIn("cvelab[ssh]", said)

    def test_the_library_is_checked_before_the_first_request(self) -> None:
        """Learning halfway through costs the run and reads like a result."""
        script = field.emit_field_poc("CVE-2026-0002", field.validate_spec(self._ssh()))
        main_body = script.split("def main():", 1)[1]
        self.assertLess(main_body.index("_require(needed"), main_body.index("Target("))

    def test_the_footprint_says_a_session_carries_the_credential(self) -> None:
        header = field.emit_field_poc(
            "CVE-2026-0002", field.validate_spec(self._ssh())
        ).split("from __future__")[0]
        self.assertIn("credentials travel", header)
        self.assertIn("--input user=...", header)

    def test_a_protocol_refusal_is_an_answer_and_not_a_broken_run(self) -> None:
        """A share that is gone is what a fixed build says.

        Treating it as a run that never finished refused the handover for the
        one lab where the fix was exactly that the share no longer exists.
        """
        script = field.emit_field_poc("CVE-2026-0003", field.validate_spec(self._smb()))
        exchange = script.split("def _smb_exchange", 1)[1].split("\n    def _smb_op", 1)[0]
        self.assertIn("except smb.SessionError as refused:", exchange)
        self.assertIn("transcript.append", exchange)
        # the session breaking is still fatal, because it answers nothing
        self.assertIn("except OSError as error:", exchange)
        self.assertIn("raise SystemExit", exchange)


class RoundTripTests(unittest.TestCase):
    """A validated spec must validate again.

    validate_spec normalises: it fills in transport, inputs, auth and wraps a
    single check into a list. Saving that output and feeding it back is the
    ordinary thing to do with a spec -- it is what `--spec` takes and what the
    emitted script embeds -- so the output has to be valid input.
    """

    def _specs(self) -> list[dict[str, Any]]:
        return [
            _inband(),
            {"strategy": "direct_observation", "observable_effect": "x",
             "probe": [{"method": "GET", "path": "/a"}], "expect": {"status": 200}},
            {"strategy": "marker_roundtrip", "observable_effect": "x",
             "probe": [{"method": "POST", "path": "/c", "body": "{{marker}}"}],
             "observe": {"method": "GET", "path": "/c"}},
            {"strategy": "oob_callback", "observable_effect": "x",
             "probe": [{"method": "POST", "path": "/f",
                        "body": "http://{{callback}}/{{marker}}"}]},
            {"strategy": "direct_observation", "transport": "tcp",
             "observable_effect": "x", "probe": [{"send": "PING\r\n"}],
             "expect": {"body_contains": "PONG"}},
            {"strategy": "direct_observation", "transport": "ws",
             "ws_path": "/ws", "observable_effect": "x",
             "probe": [{"send": "{\"type\":\"devices/list\"}", "read_until": "}"}],
             "expect": {"body_contains": "requires_auth"}},
            {"strategy": "direct_observation", "transport": "ssh",
             "observable_effect": "x", "inputs": ["user"],
             "auth": {"username": "{{user}}"},
             "probe": [{"exec": "id"}], "expect": {"body_contains": "uid="}},
            {"strategy": "direct_observation", "observable_effect": "x",
             "inputs": ["victimEmail"],
             "discover": [{"bind": "state",
                           "query": [{"method": "POST", "path": "/s",
                                      "body": {"email": "{{victimEmail}}"}}],
                           "extract": {"regex": "state=([a-z]+)"}}],
             "probe": [{"method": "GET", "path": "/v?t={{state}}"}],
             "expect": {"status": 200}},
        ]

    def test_validating_twice_gives_the_same_spec(self) -> None:
        for offered in self._specs():
            with self.subTest(strategy=offered["strategy"],
                              transport=offered.get("transport", "http")):
                once = field.validate_spec(offered)
                twice = field.validate_spec(json.loads(json.dumps(once)))
                self.assertEqual(once, twice)

    def test_an_emitted_spec_can_be_handed_back(self) -> None:
        """The script embeds the normalised spec; `--spec` must accept it."""
        for offered in self._specs():
            with self.subTest(strategy=offered["strategy"]):
                script = field.emit_field_poc("CVE-2026-1", field.validate_spec(offered))
                embedded = json.loads(
                    script.split('json.loads(r"""', 1)[1].split('""")', 1)[0]
                )
                field.validate_spec(embedded)


class ScriptSizeTests(unittest.TestCase):
    """The deliverable is too big to be an argument, and that is a real limit.

    Windows caps a command line at about 32 KB and the emitted script is over
    it, so anything that passed it as an argument failed with WinError 206
    before Python ever saw it. The product never does: the sidecar passes it
    in the environment and the operator runs a file.
    """

    def test_the_script_is_larger_than_a_windows_command_line(self) -> None:
        script = field.emit_field_poc("CVE-2026-1", field.validate_spec(_inband()))
        self.assertGreater(len(script), 32767)

    def test_the_sidecar_passes_it_in_the_environment_not_in_argv(self) -> None:
        completed = subprocess.CompletedProcess(["docker"], 0, "OBSERVED\n", "")
        script = field.emit_field_poc("CVE-2026-1", field.validate_spec(_inband()))
        with mock.patch.object(field.subprocess, "run", return_value=completed) as run:
            field._run_field_script("lab", 8080, script, "http")
        argv = run.call_args.args[0]
        self.assertIn(f"CVELAB_FIELD={script}", argv)
        # Only as the one -e value, never as a bare argument of its own.
        self.assertNotIn(script, argv)


class SidecarImageTests(unittest.TestCase):
    """Nothing is installed without being asked for."""

    def test_a_standard_library_transport_asks_nobody_anything(self) -> None:
        for transport in ("http", "tcp", "tls"):
            with self.subTest(transport=transport):
                self.assertEqual(sidecar.packages_for({transport}), ())
                self.assertEqual(
                    sidecar.ensure_image({transport}), sidecar.BASE_IMAGE
                )

    def test_the_tag_names_what_is_in_it(self) -> None:
        """A changed package list builds a new image rather than reusing one
        that lacks something."""
        self.assertEqual(sidecar.image_tag(("paramiko>=3.4",)),
                         "cvelab/protocol-sidecar:paramiko")
        self.assertNotEqual(
            sidecar.image_tag(("paramiko>=3.4",)),
            sidecar.image_tag(("paramiko>=3.4", "impacket>=0.12")),
        )

    def test_without_a_terminal_and_without_yes_it_stops(self) -> None:
        with mock.patch.object(sidecar.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(sidecar.ConsentRequired) as raised:
                sidecar.ask(("paramiko>=3.4",), "img", assume_yes=False)
        said = str(raised.exception)
        self.assertIn("paramiko>=3.4", said)
        self.assertIn("--yes", said)

    def test_a_no_builds_nothing(self) -> None:
        with mock.patch.object(sidecar.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="n"):
            with self.assertRaises(sidecar.ConsentRequired):
                sidecar.ask(("paramiko>=3.4",), "img", assume_yes=False)

    def test_a_yes_is_the_word_and_nothing_else(self) -> None:
        for answer in ("yes", "YES", " yes "):
            with self.subTest(answer=answer):
                with mock.patch.object(sidecar.sys.stdin, "isatty", return_value=True), \
                     mock.patch("builtins.input", return_value=answer):
                    sidecar.ask(("paramiko>=3.4",), "img", assume_yes=False)
        for answer in ("y", "ok", "", "sure"):
            with self.subTest(answer=answer):
                with mock.patch.object(sidecar.sys.stdin, "isatty", return_value=True), \
                     mock.patch("builtins.input", return_value=answer):
                    with self.assertRaises(sidecar.ConsentRequired):
                        sidecar.ask(("paramiko>=3.4",), "img", assume_yes=False)

    def test_nothing_here_needs_root(self) -> None:
        """A security tool should not ask for privilege it does not use."""
        source = Path(sidecar.__file__).read_text(encoding="utf-8")
        self.assertNotIn("sudo", source)
        self.assertNotIn("setuid", source)


class WebSocketTransportTests(unittest.TestCase):
    """An effect that lives in frames after an upgrade.

    This was the one gap in a measured batch that was the format's fault
    rather than the vulnerability's: a lab whose evidence was in frames after
    a `/ws` upgrade had no way to be expressed, while HTTP and raw sockets
    could not carry the handshake and framing between them.
    """

    def _ws(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "transport": "ws",
            "ws_path": "/ws",
            "observable_effect": "the device list is served to a client that never authenticated",
            "probe": [{"send": '{"type":"devices/list"}', "read_until": "}"}],
            "expect": {"body_contains": "dev-"},
        }
        spec.update(extra)
        return spec

    def test_it_validates_and_keeps_its_upgrade_path(self) -> None:
        spec = field.validate_spec(self._ws())
        self.assertEqual(spec["transport"], "ws")
        self.assertEqual(spec["ws_path"], "/ws")
        self.assertEqual(field.validate_spec(self._ws(transport="wss"))["transport"], "wss")

    def test_the_upgrade_path_must_be_a_path(self) -> None:
        for bad in ("ws", "http://host/ws", ""):
            with self.subTest(ws_path=bad):
                with self.assertRaises(ValueError):
                    field.validate_spec(self._ws(ws_path=bad))

    def test_those_fields_mean_nothing_elsewhere_and_are_not_emitted(self) -> None:
        """Emitting them everywhere broke validating a spec twice."""
        with self.assertRaises(ValueError):
            field.validate_spec({
                "strategy": "direct_observation", "observable_effect": "x",
                "ws_path": "/ws", "probe": [{"method": "GET", "path": "/"}],
                "expect": {"status": 200},
            })
        plain = field.validate_spec({
            "strategy": "direct_observation", "observable_effect": "x",
            "probe": [{"method": "GET", "path": "/"}], "expect": {"status": 200},
        })
        self.assertNotIn("ws_path", plain)
        self.assertNotIn("ws_headers", plain)

    def test_it_needs_nothing_installed(self) -> None:
        """The handshake is HTTP and the framing is documented, so no image."""
        for transport in ("ws", "wss"):
            with self.subTest(transport=transport):
                self.assertEqual(sidecar.packages_for({transport}), ())
                self.assertNotIn(transport, field.HANDSHAKE_TRANSPORTS)

    def test_the_conventional_ports_are_assumed(self) -> None:
        for transport, port in (("ws", 80), ("wss", 443)):
            with self.subTest(transport=transport):
                script = field.emit_field_poc(
                    "CVE-2026-1", field.validate_spec(self._ws(transport=transport))
                )
                namespace: dict[str, Any] = {}
                exec(compile(script, "<f>", "exec"), namespace)
                self.assertEqual(namespace["normalize_target"]("10.0.0.5"), ("10.0.0.5", port))

    def test_a_server_that_does_not_upgrade_is_not_silence(self) -> None:
        """A plain 200 would otherwise read as a successful upgrade, and every
        later read would come back empty -- indistinguishable from the effect
        being absent. This spec reads the frames, so that stays an error."""
        script = field.emit_field_poc("CVE-2026-1", field.validate_spec(self._ws()))
        exchange = script.split("def _ws_exchange", 1)[1].split("\n    def _ws_write", 1)[0]
        self.assertIn("if code != 101:", exchange)
        self.assertIn("did not upgrade to WebSocket", exchange)
        self.assertIn("Sec-WebSocket-Accept", exchange)
        self.assertIn("sha1", exchange)
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)  # noqa: S102
        self.assertFalse(namespace["_handshake_is_the_finding"]())

    def test_the_handshake_itself_can_be_the_finding(self) -> None:
        """Origin checks: 101 to a foreign Origin, 403 on the fixed build.

        Storybook was refused a script three times, the third time for this:
        "the confirmed effect is the HTTP status line of the WebSocket
        upgrade ... over ws the expectation kinds are body_contains or
        extract, so the 101 cannot be matched directly".
        """
        script = field.emit_field_poc("CVE-2026-1", field.validate_spec(
            self._ws(expect={"status": 101}, ws_headers={"Origin": "http://evil.invalid"})
        ))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)  # noqa: S102
        self.assertTrue(namespace["_handshake_is_the_finding"]())

    def test_a_client_frame_is_masked_and_a_ping_is_answered(self) -> None:
        script = field.emit_field_poc("CVE-2026-1", field.validate_spec(self._ws()))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)
        target = namespace["Target"].__new__(namespace["Target"])
        sent: list[bytes] = []
        target._ws_write(type("S", (), {"sendall": lambda _s, b: sent.append(b)})(), b"hi", 1)
        frame = sent[0]
        self.assertEqual(frame[0], 0x81)          # FIN + text
        self.assertTrue(frame[1] & 0x80)          # masked, as a client must
        mask = frame[2:6]
        self.assertEqual(bytes(b ^ mask[i % 4] for i, b in enumerate(frame[6:])), b"hi")
        read = script.split("def _ws_read", 1)[1].split("\n    def _ws_frame", 1)[0]
        self.assertIn("if opcode == 9:", read)    # ping
        self.assertIn("if opcode == 8:", read)    # close ends the read


class WebSocketDiscoveryTests(unittest.TestCase):
    """A value read over HTTP, then used in the frames after the upgrade.

    Storybook reproduced and had no manual script for two runs. Its channel
    token is served in HTML and the effect is in the frames after the
    upgrade, and the draft said so both times: "discover is not available for
    ws, so the token cannot be obtained inside a ws check". A WebSocket
    service is an HTTP server that upgrades on the same host and port, so
    that pairing is the one case where discovery has somewhere to run.
    """

    def _ws(self, **extra: Any) -> dict[str, Any]:
        spec = {
            "strategy": "direct_observation",
            "transport": "ws",
            "ws_path": "/ws",
            "observable_effect": "a channel token from the page is accepted from any origin",
            "discover": [{
                "bind": "token",
                "query": [{"method": "GET", "path": "/iframe.html"}],
                "extract": {"regex": "wsToken[\"']?\\s*[:=]\\s*[\"']([^\"']+)"},
            }],
            "probe": [{"send": '{"token":"{{token}}","type":"devices/list"}',
                       "read_until": "}"}],
            "expect": {"body_contains": "dev-"},
        }
        spec.update(extra)
        return spec

    def test_a_ws_spec_may_discover(self) -> None:
        for transport in ("ws", "wss"):
            with self.subTest(transport=transport):
                spec = field.validate_spec(self._ws(transport=transport))
                step = spec["checks"][0]["discover"][0]
                self.assertEqual(step["bind"], "token")
                self.assertIn("regex", step["extract"])

    def test_a_socket_or_a_session_still_has_nowhere_to_run_one(self) -> None:
        for transport in ("tcp", "tls", "ssh", "smb"):
            spec = self._ws(transport=transport)
            spec.pop("ws_path")
            spec["probe"] = (
                [{"exec": "id"}] if transport == "ssh"
                else [{"op": "list_shares"}] if transport == "smb"
                else [{"send": "PING\r\n", "read_until": "\n"}]
            )
            spec["expect"] = {"body_contains": "dev-"}
            with self.subTest(transport=transport):
                with self.assertRaises(ValueError) as refused:
                    field.validate_spec(spec)
                self.assertIn("http, ws and wss", str(refused.exception))

    def _target(self, transport: str, where: str) -> Any:
        script = field.emit_field_poc(
            "CVE-2026-1", field.validate_spec(self._ws(transport=transport))
        )
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)  # noqa: S102
        return namespace["Target"](where, False, 5)

    def test_the_http_address_is_the_same_host_and_port(self) -> None:
        for transport, scheme in (("ws", "http"), ("wss", "https")):
            with self.subTest(transport=transport):
                target = self._target(transport, "10.0.0.5:6006")
                self.assertEqual(target.base, f"{transport}://10.0.0.5:6006")
                self.assertEqual(target.http_base, f"{scheme}://10.0.0.5:6006")

    def test_a_step_is_an_ordinary_request_and_never_an_upgrade(self) -> None:
        target = self._target("ws", "10.0.0.5:6006")
        seen: list[dict[str, Any]] = []

        def send(message: dict[str, Any]) -> tuple[int, str, dict[str, str]]:
            seen.append(message)
            return 200, '<script>window.wsToken = "tok-9"</script>', {}

        target.send = send
        target._ws_exchange = lambda messages, ctx=None: self.fail(
            "a step must not upgrade")
        status, body, _ = target.discover_exchange([{"method": "GET", "path": "/iframe.html"}])
        self.assertEqual([m["path"] for m in seen], ["/iframe.html"])
        self.assertEqual(status, 200)
        self.assertIn("tok-9", body)

    def test_the_probe_still_speaks_websocket(self) -> None:
        """Only the discovery step is HTTP; the effect is in the frames."""
        target = self._target("ws", "10.0.0.5:6006")
        target.send = lambda message: self.fail("the probe must not go over http")
        target._ws_exchange = lambda messages, ctx=None: (
            101, "dev-1 dev-2", {"Upgrade": "websocket"})
        self.assertEqual(
            target.exchange([{"send": "x"}]),
            (101, "dev-1 dev-2", {"Upgrade": "websocket"}),
        )


class ReleaseTagPairTests(unittest.TestCase):
    """A tagged release pair is a before and an after, with no fix commit.

    A CVE whose fix is a release rather than a commit used to end with
    nothing: discovery will not invent a fixing commit, and it is right not
    to. But an advisory that says "affected through 2.3.34, fixed in 2.3.35"
    names both ends, and where the project tags its releases those two tags
    are immutable refs that give the same differential.
    """

    def test_a_tag_is_matched_exactly_and_never_by_prefix(self) -> None:
        """A repository that tags v2.3.34 often also tags v2.3.34-gae for a
        different build of the same release, and picking that would build the
        wrong thing."""
        tags = {"v2.3.34-gae": "a" * 40, "v2.3.34": "b" * 40, "v2.3.35": "c" * 40}
        with mock.patch.object(releases, "repo_tags", return_value=tags):
            pair = releases.tag_pair("https://example.invalid/p.git", [
                {"last_vulnerable": "2.3.34", "first_patched": "2.3.35"}
            ])
        self.assertEqual(pair["vulnerable_tag"], "v2.3.34")
        self.assertEqual(pair["fixed_tag"], "v2.3.35")

    def test_the_repository_name_is_tried_as_a_prefix(self) -> None:
        """netty tags netty-4.1.127.Final while the advisory names
        io.netty:netty-handler, so the package coordinate alone is not it."""
        candidates = releases.tag_candidates(
            "4.1.127.Final", "io.netty:netty-handler", "https://github.com/netty/netty.git"
        )
        self.assertIn("netty-4.1.127.Final", candidates)
        self.assertIn("netty-handler-4.1.127.Final", candidates)

    def test_common_spellings_are_covered(self) -> None:
        for version, wanted in (
            ("2.3.34", "v2.3.34"), ("5.2.7", "5.2.7"), ("1.0.0", "rel_1_0_0"),
        ):
            with self.subTest(version=version):
                self.assertIn(wanted, releases.tag_candidates(version))

    def test_a_half_resolved_pair_is_no_pair(self) -> None:
        """Returning one end would build a lab comparing a release to nothing."""
        with mock.patch.object(
            releases, "repo_tags", return_value={"v1.0.0": "a" * 40}
        ):
            self.assertIsNone(releases.tag_pair("https://example.invalid/p.git", [
                {"last_vulnerable": "1.0.0", "first_patched": "1.0.1"}
            ]))

    def test_the_versions_come_from_the_advisory_not_a_registry(self) -> None:
        """find_releases asks a registry which versions exist and returns
        nothing when it cannot be read, which is what dropped the measured
        pair. An inclusive upper bound already names the version."""
        advisory = [{"ecosystem": "maven", "package": "org.freemarker:freemarker",
                     "vulnerable_range": ">= 2.2.0, <= 2.3.34", "first_patched": "2.3.35"}]
        with mock.patch.object(releases, "advisory_packages", return_value=advisory), \
             mock.patch.object(releases, "find_releases", return_value=[]):
            entries = releases.pair_from_advisory("CVE-2026-84939")
        self.assertEqual(entries[0]["last_vulnerable"], "2.3.34")
        self.assertEqual(entries[0]["first_patched"], "2.3.35")

    def test_an_exclusive_bound_falls_back_to_the_registry(self) -> None:
        """`< X` does not name the last affected release, so the registry is
        still the only way to learn it."""
        advisory = [{"vulnerable_range": "< 2.3.35", "first_patched": "2.3.35"}]
        with mock.patch.object(releases, "advisory_packages", return_value=advisory), \
             mock.patch.object(
                 releases, "find_releases",
                 return_value=[{"last_vulnerable": "2.3.34", "first_patched": "2.3.35"}]
             ):
            entries = releases.pair_from_advisory("CVE-2026-84939")
        self.assertEqual(entries[0]["last_vulnerable"], "2.3.34")

    def test_an_unreadable_repository_resolves_nothing(self) -> None:
        with mock.patch.object(releases.subprocess, "run", side_effect=OSError("no git")):
            self.assertEqual(releases.repo_tags("https://example.invalid/p.git"), {})


class SendingNothingIsAnExchangeTests(unittest.TestCase):
    """A message with neither key reads without writing.

    The validator demanded one of send or send_hex while its own docstring
    said sending nothing was allowed, and the instructions said so too. It
    cost Storybook a script on the third attempt: an Origin check on a
    WebSocket upgrade sends no frame at all, because the finding is the
    handshake, and the draft came back "spec.probe[0] needs exactly one of
    send or send_hex".
    """

    def _spec(self, transport: str, probe: list[dict[str, Any]]) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "strategy": "direct_observation",
            "transport": transport,
            "observable_effect": "the upgrade is accepted from an origin it should refuse",
            "probe": probe,
            "expect": {"status": 101} if transport == "ws" else {"body_contains": "READY"},
        }
        if transport == "ws":
            spec["ws_path"] = "/ws"
            spec["ws_headers"] = {"Origin": "http://evil.invalid"}
        return spec

    def test_a_handshake_only_probe_validates(self) -> None:
        spec = field.validate_spec(self._spec("ws", [{}]))
        self.assertEqual(spec["checks"][0]["probe"], [{"send": "", "read_bytes": 1024 * 1024}])

    def test_a_banner_read_validates(self) -> None:
        spec = field.validate_spec(self._spec("tcp", [{"read_until": "\\n"}]))
        message = spec["checks"][0]["probe"][0]
        self.assertEqual(message["send"], "")
        self.assertEqual(message["read_until"], "\\n")

    def test_nothing_is_written_for_an_empty_send(self) -> None:
        script = field.emit_field_poc(
            "CVE-2026-1", field.validate_spec(self._spec("ws", [{}]))
        )
        self.assertIn("if payload:", script)

    def test_both_keys_at_once_is_still_wrong(self) -> None:
        with self.assertRaises(ValueError) as refused:
            field.validate_spec(self._spec("tcp", [{"send": "x", "send_hex": "ff"}]))
        self.assertIn("not both", str(refused.exception))


class HandshakeIsFilledLikeARequestTests(unittest.TestCase):
    """A token read over HTTP has to reach the upgrade that uses it.

    Storybook's spec was right in every part: discover the channel token
    from served HTML with a regex, upgrade on
    /storybook-server-channel?token={{token}}&page=preview carrying a
    foreign Origin, expect 101. ws_path was never substituted, so six
    literal characters went on the wire, both builds refused the upgrade,
    and the proof said the script did not tell them apart.
    """

    def _spec(self, **extra: Any) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "strategy": "direct_observation",
            "transport": "ws",
            "observable_effect": "the channel accepts a foreign Origin",
            "ws_path": "/channel?token={{token}}",
            "ws_headers": {"Origin": "http://evil.invalid"},
            "discover": [{
                "bind": "token",
                "query": [{"method": "GET", "path": "/iframe.html"}],
                "extract": {"regex": "wsToken=([a-f0-9-]+)"},
            }],
            "probe": [{}],
            "expect": {"status": 101},
        }
        spec.update(extra)
        return spec

    def _target(self, spec: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        script = field.emit_field_poc("CVE-2026-1", field.validate_spec(spec))
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)  # noqa: S102
        return namespace["Target"]("10.0.0.5:6006", False, 5), namespace

    def test_the_upgrade_carries_the_discovered_value(self) -> None:
        target, namespace = self._target(self._spec())
        target.inputs = {}
        sent: list[bytes] = []

        class Sock:
            def sendall(self, data: bytes) -> None:
                sent.append(data)

            def settimeout(self, _seconds: float) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                return (b"HTTP/1.1 101 Switching Protocols\r\n"
                        b"Sec-WebSocket-Accept: x\r\n\r\n")

            def close(self) -> None:
                pass

        with mock.patch.object(namespace["socket"], "create_connection",
                               return_value=Sock()):
            # The accept header is wrong on purpose: the handshake line is
            # what this is about, and the refusal proves it got that far.
            with contextlib.suppress(SystemExit):
                target._ws_exchange([{"send": ""}], {"token": "abc-123"})
        request = sent[0].decode()
        self.assertIn("GET /channel?token=abc-123 HTTP/1.1", request)
        self.assertNotIn("{{token}}", request)

    def test_the_target_s_own_address_reaches_the_origin_header(self) -> None:
        target, _ = self._target(self._spec(ws_headers={"Origin": "http://{{target}}"}))
        filled = target.fill({"Origin": "http://{{target}}"}, {})
        self.assertEqual(filled, {"Origin": "http://10.0.0.5:6006"})

    def test_a_name_no_check_binds_is_refused(self) -> None:
        with self.assertRaises(ValueError) as refused:
            field.validate_spec(self._spec(discover=[]))
        self.assertIn("does not bind", str(refused.exception))
        self.assertIn("token", str(refused.exception))

    def test_an_input_or_the_target_is_enough(self) -> None:
        field.validate_spec(self._spec(discover=[], inputs=["token"]))
        field.validate_spec(self._spec(
            discover=[], ws_path="/channel", ws_headers={"Origin": "http://{{targetHost}}"}
        ))


class UploadIsExpressibleTests(unittest.TestCase):
    """A crafted upload is the attack for a whole class of weakness.

    Three labs that reproduced were refused a manual PoC over this, the last
    of them outright: "the precondition needs a denied report.dat uploaded
    through the user files API as multipart", and before it "the effect is a
    write of a gzip-compressed tar bundle ... a binary gzip archive cannot be
    expressed faithfully, and the {{marker}} cannot be placed inside the
    bundle's config".
    """

    def _spec(self, upload: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "strategy": "direct_observation",
            "observable_effect": "a bundle the caller may not replace is replaced",
            "probe": [{"method": "PUT", "path": "/v1/agent", "upload": upload}],
            "expect": {"status": 200},
        }
        spec.update(extra)
        return spec

    def _marker_spec(self, upload: list[dict[str, Any]]) -> dict[str, Any]:
        """The shape omnigent needed: the marker goes inside the archive."""
        return {
            "strategy": "marker_roundtrip",
            "observable_effect": "a bundle the caller may not replace is replaced",
            "probe": [{"method": "PUT", "path": "/v1/agent", "upload": upload}],
            "observe": [{"method": "GET", "path": "/v1/agent"}],
            "match": {"body_contains": "{{marker}}"},
        }

    def _parts(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        return field.validate_spec(spec)["checks"][0]["probe"][0]["upload"]

    def test_a_form_field_and_a_text_file_both_validate(self) -> None:
        parts = self._parts(self._spec([
            {"name": "path", "value": "/etc"},
            {"name": "file", "filename": "report.dat", "text": "{{marker}}",
             "content_type": "application/x-dat"},
        ]))
        self.assertEqual(parts[0], {"name": "path", "value": "/etc"})
        self.assertEqual(parts[1]["kind"], "text")
        self.assertEqual(parts[1]["content_type"], "application/x-dat")

    def test_an_archive_is_described_rather_than_pasted(self) -> None:
        parts = self._parts(self._marker_spec([
            {"name": "bundle", "filename": "b.tar.gz",
             "tar_gz": {"config.yaml": "mcpServers:\n  x: {{marker}}"}},
        ]))
        self.assertEqual(parts[0]["kind"], "tar_gz")
        self.assertIn("config.yaml", parts[0]["tar_gz"])

    def test_the_marker_belongs_where_it_can_be_substituted(self) -> None:
        with self.assertRaises(ValueError) as refused:
            self._parts(self._spec([
                {"name": "f", "base64": base64.b64encode(b"{{marker}}").decode()},
                {"name": "g", "base64": "{{marker}}"},
            ]))
        self.assertIn("cannot carry", str(refused.exception))

    def test_rubbish_is_refused_with_the_reason(self) -> None:
        for upload, said in (
            ([], "non-empty"),
            ([{"filename": "x"}], "name must be"),
            ([{"name": "f"}], "exactly one of"),
            ([{"name": "f", "text": "a", "base64": "YQ=="}], "exactly one of"),
            ([{"name": "f", "base64": "not base64!"}], "valid base64"),
            ([{"name": "f", "tar_gz": {}}], "map a file name"),
            ([{"name": "f", "zip": {"a": 1}}], "must be text"),
            ([{"name": f"f{i}"} for i in range(7)], "at most"),
        ):
            with self.subTest(upload=upload):
                with self.assertRaises(ValueError) as refused:
                    self._parts(self._spec(upload))
                self.assertIn(said, str(refused.exception))

    def test_a_body_and_an_upload_are_two_ways_to_say_one_thing(self) -> None:
        with self.assertRaises(ValueError) as refused:
            field.validate_spec(self._spec(
                [{"name": "f", "text": "x"}],
                probe=[{"method": "PUT", "path": "/v1/agent", "body": "{}",
                        "upload": [{"name": "f", "text": "x"}]}],
            ))
        self.assertIn("not both", str(refused.exception))

    def test_the_form_is_encoded_with_the_archive_inside_it(self) -> None:
        spec = field.validate_spec(self._spec([
            {"name": "bundle", "filename": "b.tar.gz",
             "tar_gz": {"config.yaml": "token: cvelab-abc"}},
            {"name": "path", "value": "/opt"},
        ]))
        script = field.emit_field_poc("CVE-2026-1", spec)
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)  # noqa: S102
        body, content_type = namespace["multipart"](spec["checks"][0]["probe"][0]["upload"])
        self.assertTrue(content_type.startswith("multipart/form-data; boundary=cvelab"))
        boundary = content_type.split("boundary=", 1)[1]
        self.assertIn(b'filename="b.tar.gz"', body)
        self.assertIn(b'name="path"', body)
        self.assertIn(b"/opt", body)
        self.assertTrue(body.endswith(f"--{boundary}--\r\n".encode()))
        # The archive in the body is a real one, and holds what the spec said.
        start = body.index(b"application/octet-stream\r\n\r\n") + len(
            b"application/octet-stream\r\n\r\n"
        )
        held = body[start:body.index(f"\r\n--{boundary}".encode(), start)]
        with tarfile.open(fileobj=io.BytesIO(held), mode="r:gz") as archive:
            self.assertEqual(archive.getnames(), ["config.yaml"])
            member = archive.extractfile("config.yaml")
            assert member is not None
            self.assertEqual(member.read(), b"token: cvelab-abc")

    def test_a_zip_is_a_real_zip(self) -> None:
        spec = field.validate_spec(self._spec([
            {"name": "f", "filename": "a.zip", "zip": {"../escape.txt": "out"}},
        ]))
        script = field.emit_field_poc("CVE-2026-1", spec)
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)  # noqa: S102
        raw = namespace["_part_bytes"](spec["checks"][0]["probe"][0]["upload"][0])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(archive.namelist(), ["../escape.txt"])

    def test_the_run_says_it_leaves_a_file_behind(self) -> None:
        """"This run only reads" over a request that writes one would lie."""
        spec = field.validate_spec(self._spec([{"name": "f", "text": "x"}]))
        self.assertIn("uploads a file", field._poc_footprint(spec))
        plain = field.validate_spec({
            "strategy": "direct_observation", "observable_effect": "x",
            "probe": [{"method": "GET", "path": "/"}], "expect": {"status": 200},
        })
        self.assertNotIn("uploads a file", field._poc_footprint(plain))


class SessionIsCarriedAcrossRequestsTests(unittest.TestCase):
    """A login handshake is how most web findings are reached at all.

    MobSF's CSRF finding needs a csrftoken read from the login page, a
    sessionid from the POST that follows, and both carried into the forged
    request. The draft named the obstacle exactly: "The spec format sends
    each HTTP request standalone with no cookie jar". Authorization bypass,
    IDOR and CSRF all look like this.
    """

    def _target(self) -> Any:
        spec = field.validate_spec({
            "strategy": "direct_observation",
            "observable_effect": "a state-changing post is accepted without a token",
            "probe": [{"method": "POST", "path": "/delete_scan/"}],
            "expect": {"status": 200},
        })
        script = field.emit_field_poc("CVE-2026-1", spec)
        namespace: dict[str, Any] = {}
        exec(compile(script, "<f>", "exec"), namespace)  # noqa: S102
        return namespace["Target"]("http://10.0.0.5:8000", False, 5)

    def test_what_the_target_sets_comes_back_on_the_next_request(self) -> None:
        target = self._target()
        target.keep_cookies([
            "csrftoken=abc; Path=/; SameSite=Lax",
            "sessionid=xyz; HttpOnly; Path=/",
        ])
        sent: list[dict[str, str]] = []

        class Answer:
            status = 200
            headers = type("H", (), {"items": lambda _s: [],
                                     "get_all": lambda _s, _n: []})()

            def read(self, _n: int) -> bytes:
                return b""

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_a: Any) -> None:
                return None

        def urlopen(req: Any, **_kw: Any) -> Any:
            sent.append(dict(req.header_items()))
            return Answer()

        with mock.patch.object(urllib.request, "urlopen", urlopen):
            target.send({"method": "GET", "path": "/scans"})
        cookie = next(v for k, v in sent[0].items() if k.lower() == "cookie")
        self.assertEqual(cookie, "csrftoken=abc; sessionid=xyz")

    def test_a_cookie_the_spec_writes_itself_wins(self) -> None:
        """An operator's own session is never overwritten by one picked up."""
        target = self._target()
        target.keep_cookies(["sessionid=picked-up"])
        sent: list[dict[str, str]] = []

        class Answer:
            status = 200
            headers = type("H", (), {"items": lambda _s: [],
                                     "get_all": lambda _s, _n: []})()

            def read(self, _n: int) -> bytes:
                return b""

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_a: Any) -> None:
                return None

        with mock.patch.object(urllib.request, "urlopen",
                               lambda req, **_k: (sent.append(dict(req.header_items())),
                                                  Answer())[1]):
            target.send({"method": "GET", "path": "/x",
                         "headers": {"Cookie": "sessionid=mine"}})
        cookie = next(v for k, v in sent[0].items() if k.lower() == "cookie")
        self.assertEqual(cookie, "sessionid=mine")

    def test_a_cleared_cookie_is_forgotten(self) -> None:
        target = self._target()
        target.keep_cookies(["sessionid=xyz"])
        target.keep_cookies(['sessionid=""; Max-Age=0'])
        self.assertNotIn("sessionid", target.cookies)

    def test_rubbish_in_a_set_cookie_header_is_ignored(self) -> None:
        target = self._target()
        target.keep_cookies(["", "   ", "novalue", "=novalue"])
        self.assertEqual(target.cookies, {})

    def test_the_instructions_say_the_requests_share_a_session(self) -> None:
        self.assertIn("share a session", field._DRAFT_INSTRUCTIONS)
        self.assertIn("login handshake", field._DRAFT_INSTRUCTIONS)
