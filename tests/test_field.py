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
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import field, sidecar


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

    def exchange(self, steps: list[dict[str, Any]]) -> tuple[int, str, dict[str, str]]:
        last = (0, "", {})
        for step in steps:
            last = self.send(step)
        return last


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
        self.assertIn("http only", str(raised.exception))

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
            def exchange(self, steps: list[dict[str, Any]]) -> tuple[int, str, dict[str, str]]:
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
        filled = target.fill([{"path": "/r/{{credential}}"}], {})
        self.assertEqual(filled[0]["path"], "/r/s3cret")
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
