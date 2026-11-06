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

"""Putting a generated lab in the state its attack needs, before the attack.

An unverified proof is the largest measured failure class, and one shape
inside it is a lab that never delivered its attack at all: a mobile security
framework lab reported `victim session not established` against both its
services while the login it had already made answered 200, and recorded
attack_executed false four attempts running. Nothing in the lab could say so.
`exploit_contract.preconditions` had held that sentence in prose since the
beginning and no proof check had ever read it.

So the state is declared in `exploit_contract.setup`, CVELab runs those steps
itself once per build, and a precondition that no step and no input stands
behind is refused before anything is built.

Nothing here needs Docker or a network. The runner is driven in a subprocess
against a loopback server, which is what tests/test_steps.py does with the
single-target runner for the same reason: the program is the thing being
tested and the delivery is not.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock as mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cvelab import autoflow, core, policy, sourcegen, steps
from cvelab.autoflow import run_auto_workflow

from tests.test_compose_policy import LAB, model, service

REPO = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# The service CVELab adds to a lab's own Compose project
# --------------------------------------------------------------------------


def _override(**extra: Any) -> dict:
    return policy.setup_override(
        model(),
        image="python:3.13-alpine",
        program=steps.SETUP_RUNNER,
        environment={steps.SETUP_SPEC_VARIABLE: "[]"},
        **extra,
    )


class TheInjectedServiceTests(unittest.TestCase):
    """CVELab writes one service into a lab, and the policy judges it too.

    `prepare_compose` already appends a JSON Compose file of CVELab's own and
    lets Compose merge it, which is how the runtime limits reach a lab. The
    setup service travels the same way, so it has to be a definition the
    lab's own policy would accept -- there is no second set of rules for
    CVELab's services, and a key that would be refused in a lab is refused
    here.
    """

    def definition(self, **extra: Any) -> dict:
        return _override(**extra)["services"][policy.SETUP_SERVICE]

    def test_the_policy_accepts_it_beside_the_lab_s_own_services(self) -> None:
        merged = model()
        merged["services"][policy.SETUP_SERVICE] = self.definition()
        self.assertEqual(policy.check_model(merged, LAB), [])

    def test_every_key_it_asks_for_is_one_a_lab_may_ask_for(self) -> None:
        """Named key by key, because this is the whole feasibility claim.

        The program travels in `command` precisely because the keys that
        would be easier -- volumes for a file, ports for a route, a build
        context of CVELab's -- are refused to a lab and therefore refused
        here.
        """
        for key in self.definition():
            with self.subTest(key=key):
                self.assertIn(key, policy.SERVICE_KEYS)
        for refused in ("volumes", "ports", "build", "network_mode"):
            with self.subTest(absent=refused):
                self.assertNotIn(refused, self.definition())

    def test_a_lab_declaring_the_same_service_is_refused_not_merged(self) -> None:
        """Compose merges two definitions of one service key rather than
        refusing them, so the lab's build would stay and CVELab's image,
        command and environment would be merged on top of it.
        """
        collision = model()
        collision["services"][policy.SETUP_SERVICE] = service()
        with self.assertRaises(policy.PolicyError) as caught:
            policy.setup_override(
                collision, image="i", program="p", environment={},
            )
        self.assertIn(policy.SETUP_SERVICE, str(caught.exception))
        self.assertIn("merge", str(caught.exception))

    def test_generation_refuses_the_name_as_a_support_service(self) -> None:
        """One model call rather than a whole run, and the same reason."""
        compose = f"services:\n  {policy.SETUP_SERVICE}:\n"
        with self.assertRaisesRegex(RuntimeError, "reserved names"):
            sourcegen._validate_support_services([policy.SETUP_SERVICE], compose)

    def test_it_joins_the_networks_the_validator_joins(self) -> None:
        self.assertEqual(self.definition()["networks"], {"lab": None})

    def test_it_waits_for_health_the_way_the_validator_does(self) -> None:
        """Setup runs before the first thing in a lab that waits for health,
        so it brings the lab's own wait with it rather than inventing one.
        """
        self.assertEqual(
            self.definition()["depends_on"],
            {"vulnerable": {"condition": "service_healthy", "required": True}},
        )

    def test_a_lab_whose_validator_declares_no_wait_gets_no_invented_one(self) -> None:
        bare = model()
        del bare["services"]["validator"]["depends_on"]
        definition = policy.setup_override(
            bare, image="i", program="p", environment={},
        )["services"][policy.SETUP_SERVICE]
        self.assertNotIn("depends_on", definition)

    def test_the_profile_keeps_it_out_of_the_lab_s_own_startup(self) -> None:
        """`up -d <startup services>` must start what it always started."""
        self.assertEqual(self.definition()["profiles"], ["tools"])

    def test_an_endpoint_s_address_or_alias_is_not_copied(self) -> None:
        """A second service claiming a fixed address or an alias is a
        Compose conflict rather than a setup that ran.
        """
        fixed = model()
        fixed["services"]["validator"]["networks"] = {
            "lab": {"ipv4_address": "10.1.0.9", "aliases": ["canary.local"]}
        }
        definition = policy.setup_override(
            fixed, image="i", program="p", environment={},
        )["services"][policy.SETUP_SERVICE]
        self.assertEqual(definition["networks"], {"lab": None})

    def test_the_ceilings_are_applied_here_because_the_other_pass_cannot(self) -> None:
        """limits_override is built from the resolved model, and the resolved
        model cannot hold a service that is being added to it.
        """
        definition = self.definition(limits={"mem_limit": "2g", "pids_limit": 512})
        self.assertEqual(definition["mem_limit"], "2g")
        self.assertEqual(definition["pids_limit"], 512)


# --------------------------------------------------------------------------
# The runner, against a real server
# --------------------------------------------------------------------------


class _Lab(BaseHTTPRequestHandler):
    """A lab that will not create an account without the token it issues.

    Which is the ordinary shape of the thing: the token is fresh per boot,
    so no fixed value can be written down for it, and reading it out of the
    response that issues it is the only way a spec can name it.
    """

    token = "tok-9f2c41"
    seen: list[tuple[str, str, dict[str, str], str]] = []
    created: list[str] = []

    def reply(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def record(self) -> str:
        length = min(int(self.headers.get("Content-Length", "0")), 65536)
        body = self.rfile.read(length).decode() if length else ""
        _Lab.seen.append(
            (self.command, self.path, dict(self.headers.items()), body)
        )
        return body

    def do_GET(self) -> None:
        self.record()
        if self.path == "/admin/login":
            self.reply(
                200, {"form": "login"},
                {"X-CSRF-Token": _Lab.token, "Set-Cookie": "lab_session=abc; Path=/"},
            )
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self) -> None:
        body = self.record()
        if self.headers.get("X-CSRF-Token") != _Lab.token:
            self.reply(403, {"error": "anti-forgery token missing"})
            return
        if self.path == "/admin/login":
            self.reply(200, {"authenticated": True})
            return
        if self.path == "/admin/users":
            try:
                _Lab.created.append(json.loads(body)["username"])
            except (ValueError, KeyError):
                self.reply(400, {"error": "bad body"})
                return
            self.reply(201, {"created": True})
            return
        self.reply(404, {"error": "not found"})

    def log_message(self, format: str, *args: object) -> None:
        return


class _Running:
    """One loopback server, started and stopped by the test that wants it."""

    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server.server_port)

    def stop(self) -> None:
        self.server.shutdown()
        self.thread.join(2)
        self.server.server_close()


#: The sequence the prompt shows, against the server above. Written here as
#: the grammar's own output, so the runner is handed exactly what a validated
#: contract holds.
_WORKED_EXAMPLE = [
    {"bind": "csrfToken",
     "query": [{"method": "GET", "path": "/admin/login"}],
     "extract": {"header": "X-CSRF-Token"}},
    {"method": "POST", "path": "/admin/login",
     "headers": {"X-CSRF-Token": "{{csrfToken}}",
                 "Content-Type": "application/x-www-form-urlencoded"},
     "body": "username=admin&password=labadmin"},
    {"method": "POST", "path": "/admin/users",
     "headers": {"X-CSRF-Token": "{{csrfToken}}",
                 "Content-Type": "application/json"},
     "body": {"username": "victim", "password": "labvictim", "role": "user"}},
]


class TheRunnerTests(unittest.TestCase):
    """The program CVELab's setup service runs, driven for real.

    It cannot be field's: that one is handed a container id and joins its
    network namespace, because a single-target lab is one container. A
    generated lab is a Compose project with an internal network and no such
    container. The route differs; what the steps mean does not.
    """

    def setUp(self) -> None:
        _Lab.seen = []
        _Lab.created = []
        self.lab = _Running()
        self.addCleanup(self.lab.stop)

    def run_setup(
        self, spec: list[dict], port: int | None = None,
        target: str = "127.0.0.1", inputs: str = "{}",
    ) -> tuple[int, dict, str]:
        done = subprocess.run(
            [sys.executable, "-c", steps.SETUP_RUNNER],
            cwd=REPO, capture_output=True, text=True, timeout=120,
            env={
                **os.environ,
                steps.SETUP_SPEC_VARIABLE: json.dumps(spec),
                steps.SETUP_TARGET_VARIABLE: target,
                steps.SETUP_PORT_VARIABLE: str(port if port is not None else self.lab.port),
                steps.SETUP_INPUTS_VARIABLE: inputs,
                # The wait is for a product that has not finished booting;
                # this server is already listening, and a test must not sit
                # on a refusal for two minutes.
                steps.SETUP_WAIT_VARIABLE: "2",
            },
        )
        tail = done.stdout.strip().splitlines()[-1:] or [""]
        try:
            reported = json.loads(tail[0])
        except json.JSONDecodeError:
            reported = {}
        return done.returncode, reported, done.stdout + done.stderr

    def validated(self, spec: list[dict], inputs: list[str]) -> list[dict]:
        """Through the grammar first, so the runner gets what a lab's plan holds."""
        return steps.validate_setup(spec, steps.validate_inputs(inputs))

    def test_the_worked_example_seeds_the_victim_it_claims_to(self) -> None:
        code, reported, output = self.run_setup(
            self.validated(_WORKED_EXAMPLE, ["csrfToken"])
        )
        self.assertEqual(code, 0, output)
        self.assertEqual(reported["bound"], {"csrfToken": _Lab.token})
        self.assertEqual(
            [(row["method"], row["path"], row["status"]) for row in reported["requests"]],
            [("GET", "/admin/login", 200),
             ("POST", "/admin/login", 200),
             ("POST", "/admin/users", 201)],
        )
        # The point of the whole thing: the account exists, created through a
        # route that refuses anything without the token the lab made at boot.
        self.assertEqual(_Lab.created, ["victim"])

    def test_the_token_really_was_read_out_of_the_header(self) -> None:
        """Not guessed and not a fixed value: the server refuses a wrong one,
        so the two POSTs could not have succeeded with anything else.

        Read case-insensitively because urllib capitalises a request header
        name, so what arrives is X-csrf-token. The server compares through
        http.client's own case-insensitive lookup and does not care; a test
        reading the raw mapping has to.
        """
        self.run_setup(self.validated(_WORKED_EXAMPLE, ["csrfToken"]))
        sent = [headers for _, path, headers, _ in _Lab.seen if path == "/admin/users"]
        lowered = {name.lower(): value for name, value in sent[0].items()}
        self.assertEqual(lowered["x-csrf-token"], _Lab.token)

    def test_a_cookie_the_lab_sets_is_carried_to_the_steps_that_follow(self) -> None:
        """A login is the requests it really is, session included."""
        self.run_setup(self.validated(_WORKED_EXAMPLE, ["csrfToken"]))
        later = [headers for _, path, headers, _ in _Lab.seen if path == "/admin/users"]
        self.assertEqual(later[0].get("Cookie"), "lab_session=abc")

    def test_a_substitution_nothing_supplies_is_refused_not_sent(self) -> None:
        """field's runner sends the literal `{{name}}`, which would seed an
        account named `{{adminPassword}}` and report success. CVELab has no
        value for an input whoever reproduces the lab would supply, so the
        step is refused instead.
        """
        spec = self.validated(
            [{"method": "POST", "path": "/admin/users",
              "headers": {"X-CSRF-Token": "x"},
              "body": {"username": "{{adminPassword}}"}}],
            ["adminPassword"],
        )
        code, reported, output = self.run_setup(spec)
        self.assertEqual(code, 1, output)
        self.assertIn("nothing supplies", reported.get("error", ""))
        self.assertIn("{{adminPassword}}", reported.get("error", ""))
        self.assertEqual(_Lab.seen, [])

    def test_a_declared_input_with_a_value_is_filled_in(self) -> None:
        """The same path with the value present, so the refusal above is
        about the missing value and not about the substitution.
        """
        spec = self.validated(
            [{"bind": "csrfToken", "query": [{"path": "/admin/login"}],
              "extract": {"header": "X-CSRF-Token"}},
             {"method": "POST", "path": "/admin/users",
              "headers": {"X-CSRF-Token": "{{csrfToken}}"},
              "body": {"username": "{{who}}"}}],
            ["csrfToken", "who"],
        )
        code, _, output = self.run_setup(spec, inputs=json.dumps({"who": "victim"}))
        self.assertEqual(code, 0, output)
        self.assertEqual(_Lab.created, ["victim"])

    def test_a_header_that_is_not_there_says_so_rather_than_binding_nothing(self) -> None:
        spec = self.validated(
            [{"bind": "csrfToken", "query": [{"path": "/admin/login"}],
              "extract": {"header": "X-Absent"}}],
            ["csrfToken"],
        )
        code, reported, output = self.run_setup(spec)
        self.assertEqual(code, 1, output)
        self.assertEqual(reported.get("bind"), "csrfToken")
        self.assertIn("nothing to bind", reported.get("error", ""))

    def test_a_step_that_cannot_be_reached_at_all_fails_the_run(self) -> None:
        """An unseeded instance answers the attack with nothing to show,
        which is indistinguishable from a fixed one refusing it.
        """
        code, reported, output = self.run_setup(
            self.validated([{"path": "/admin/login"}], []),
            port=_free_port(),
        )
        self.assertEqual(code, 1, output)
        self.assertIn("error", reported)

    def test_the_other_three_extractors_read_what_they_name(self) -> None:
        for extract, expected in (
            ({"status": True}, "200"),
            ({"json_values": "form"}, "login"),
            ({"regex": "\"form\": \"([a-z]+)\""}, "login"),
        ):
            with self.subTest(extract=extract):
                spec = self.validated(
                    [{"bind": "taken", "query": [{"path": "/admin/login"}],
                      "extract": extract}],
                    ["taken"],
                )
                code, reported, output = self.run_setup(spec)
                self.assertEqual(code, 0, output)
                self.assertEqual(reported["bound"], {"taken": expected})

    def test_two_runs_do_not_share_anything(self) -> None:
        """Which is what makes the per-build separation real rather than
        asserted: each build's setup is its own process against its own
        service, and there is nothing for a binding to leak through.
        """
        other = _Running()
        self.addCleanup(other.stop)
        try:
            _Lab.token = "tok-first"
            first = self.run_setup(self.validated(_WORKED_EXAMPLE, ["csrfToken"]))
            _Lab.token = "tok-second"
            second = self.run_setup(
                self.validated(_WORKED_EXAMPLE, ["csrfToken"]), port=other.port
            )
        finally:
            _Lab.token = "tok-9f2c41"
        self.assertEqual(first[1]["bound"], {"csrfToken": "tok-first"})
        self.assertEqual(second[1]["bound"], {"csrfToken": "tok-second"})


def _free_port() -> int:
    import socket

    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        return int(held.getsockname()[1])


class TheExampleInTheTreeTests(unittest.TestCase):
    """Why examples/closed-http-demo/ is not what the runner is proved against.

    It is a real HTTP server in the tree, and it was the obvious candidate.
    Two things rule it out, neither of them Docker. It hard-codes
    `ThreadingHTTPServer(("0.0.0.0", 8080))`, so a test driving it would bind
    a fixed port on every interface rather than an ephemeral one on loopback,
    and would fail or interfere whenever 8080 is in use. And it serves no
    value a step could bind: its only header is Content-Type and its routes
    answer `{"ok": true}`, `{"created": true}` or an error, so the binding
    form -- the part of the grammar that has never appeared in a model's
    answer and therefore the part most worth exercising -- cannot be shown
    against it at all.

    Asserted rather than written in a comment, so that a change to the
    example which removes either obstacle is told that this test is now
    obsolete and the runner can be proved against it directly.
    """

    SOURCE = (REPO / "examples" / "closed-http-demo" / "server.py").read_text(
        encoding="utf-8"
    )

    def test_it_binds_a_fixed_port_on_every_interface(self) -> None:
        self.assertIn('ThreadingHTTPServer(("0.0.0.0", 8080)', self.SOURCE)

    def test_it_sends_no_header_and_no_body_value_worth_binding(self) -> None:
        self.assertNotIn("X-", self.SOURCE)
        # Content-Type and Content-Length, and nothing else: no token, no
        # session, no location, nothing an extract.header could name.
        self.assertEqual(self.SOURCE.count("send_header"), 2)
        self.assertIn('self.send_header("Content-Type"', self.SOURCE)
        self.assertIn('self.send_header("Content-Length"', self.SOURCE)


# --------------------------------------------------------------------------
# The contract, before anything is built
# --------------------------------------------------------------------------


def _contract(**extra: Any) -> dict:
    contract = {
        "attack_summary": "a",
        "preconditions": [],
        "observable_effect": "e",
        "evidence_type": "authorization_bypass",
        "effect_predicate": {"body_contains": "victim"},
        "setup": None,
        "setup_port": None,
        "inputs": None,
    }
    contract.update(extra)
    return contract


class TheContractTests(unittest.TestCase):
    """What is refused for one model call instead of a whole build and run."""

    SOURCE = Path(sourcegen.__file__).read_text(encoding="utf-8")

    def test_both_schemas_offer_the_three_fields(self) -> None:
        for schema in (sourcegen.SOURCE_SCHEMA, sourcegen.VULNERABLE_ONLY_SCHEMA):
            contract = schema["properties"]["exploit_contract"]
            for name in ("setup", "setup_port", "inputs"):
                with self.subTest(schema=schema["properties"]["cwe"], field=name):
                    self.assertIn(name, contract["properties"])
                    # OpenAI's strict structured output rejects a property
                    # that is not required, which is why every object in
                    # these schemas requires all of its properties and every
                    # optional one takes null.
                    self.assertIn(name, contract["required"])
                    self.assertIn(
                        "null", contract["properties"][name]["type"]
                    )

    def test_the_vulnerable_only_schema_is_the_same_object(self) -> None:
        self.assertIs(
            sourcegen.VULNERABLE_ONLY_SCHEMA["properties"]["exploit_contract"],
            sourcegen.SOURCE_SCHEMA["properties"]["exploit_contract"],
        )

    def test_every_answer_that_writes_the_contract_is_checked(self) -> None:
        """Generation, vulnerable-only generation and repair, all three: the
        repair rewrites plan["exploit_contract"] from its own answer, so it
        can install a precondition nothing establishes exactly as a
        generation can.
        """
        self.assertEqual(self.SOURCE.count("_validate_setup_contract("), 4)

    def test_a_lab_with_no_setup_keeps_the_contract_it_had(self) -> None:
        """The regression that matters most: nothing added, nothing recorded,
        and plan.json identical to the one this field did not exist for.
        """
        contract = _contract()
        self.assertEqual(sourcegen._validate_setup_contract(contract), [])
        self.assertEqual(sorted(contract), [
            "attack_summary", "effect_predicate", "evidence_type",
            "observable_effect", "preconditions",
        ])

    def test_a_precondition_naming_lab_state_with_nothing_behind_it_is_refused(self) -> None:
        for precondition in (
            "An authenticated victim session exists on the target.",
            "A victim account must be registered before the request.",
            "A document is seeded in the shared project.",
            "A CSRF token taken from the page that issues it.",
        ):
            with self.subTest(precondition=precondition):
                with self.assertRaisesRegex(RuntimeError, "nothing in this answer"):
                    sourcegen._validate_setup_contract(
                        _contract(preconditions=[precondition])
                    )

    def test_a_precondition_about_the_machine_is_left_alone(self) -> None:
        """A rule that refused these would cost generations and buy nothing:
        no lab can establish them and none should try.
        """
        for precondition in (
            "Docker and docker compose are installed.",
            "The lab's internal network is reachable.",
            "Python 3.11 or newer.",
        ):
            with self.subTest(precondition=precondition):
                contract = _contract(preconditions=[precondition])
                self.assertEqual(sourcegen._validate_setup_contract(contract), [])

    def test_a_declared_input_satisfies_a_precondition_the_lab_cannot_meet(self) -> None:
        """The escape hatch, and the reason it is not a free pass: an input
        is a named value whoever reproduces the lab supplies, which is a
        different statement from prose nothing stands behind.
        """
        contract = _contract(
            preconditions=["A licensed administrator account on the instance."],
            inputs=["adminCredential"],
        )
        self.assertEqual(sourcegen._validate_setup_contract(contract), [])
        self.assertEqual(contract["inputs"], ["adminCredential"])

    def test_setup_satisfies_it_and_is_recorded_as_the_steps_that_will_run(self) -> None:
        contract = _contract(
            preconditions=["An authenticated victim session exists."],
            inputs=["csrfToken"],
            setup=json.dumps(_WORKED_EXAMPLE),
            setup_port=8080,
        )
        parsed = sourcegen._validate_setup_contract(
            contract, "CVELAB_BOUND", "CVELAB_BOUND"
        )
        self.assertEqual(len(parsed), 3)
        # Parsed, not the text it arrived as: plan.json records what runs.
        self.assertEqual(contract["setup"], parsed)
        self.assertEqual(contract["setup_port"], 8080)
        self.assertEqual(steps.bound_names(parsed), ["csrfToken"])

    def test_steps_without_a_port_are_refused(self) -> None:
        for port in (None, 0, "8080", 70000, True):
            with self.subTest(port=port):
                with self.assertRaisesRegex(RuntimeError, "setup_port"):
                    sourcegen._validate_setup_contract(
                        _contract(
                            setup=json.dumps([{"path": "/lab/seed", "method": "POST"}]),
                            setup_port=port,
                        ),
                        "CVELAB_BOUND", "CVELAB_BOUND",
                    )

    def test_setup_that_is_not_json_is_refused_with_the_reason(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "JSON array"):
            sourcegen._validate_setup_contract(
                _contract(setup="[{'path': '/x'}", setup_port=8080)
            )

    def test_the_grammar_s_own_refusals_reach_the_answer(self) -> None:
        """validate_setup does the work; this only has to carry its words."""
        with self.assertRaisesRegex(RuntimeError, "also be declared in inputs"):
            sourcegen._validate_setup_contract(
                _contract(
                    setup=json.dumps([
                        {"bind": "tok", "query": [{"path": "/a"}],
                         "extract": {"status": True}}
                    ]),
                    setup_port=8080, inputs=[],
                ),
                "CVELAB_BOUND", "CVELAB_BOUND",
            )

    def test_a_setup_using_an_input_nothing_binds_is_refused(self) -> None:
        """CVELab has no value for it, and the runner refuses to send its
        spelling; this says so before the build rather than after it.
        """
        with self.assertRaisesRegex(RuntimeError, "which it never binds"):
            sourcegen._validate_setup_contract(
                _contract(
                    setup=json.dumps([
                        {"method": "POST", "path": "/admin/users",
                         "body": {"username": "{{who}}"}}
                    ]),
                    setup_port=8080, inputs=["who"],
                ),
                "CVELAB_BOUND", "CVELAB_BOUND",
            )

    def test_the_target_tokens_need_no_binding(self) -> None:
        contract = _contract(
            setup=json.dumps([
                {"method": "POST", "path": "/admin/users",
                 "headers": {"Origin": "http://{{target}}"}}
            ]),
            setup_port=8080,
        )
        self.assertEqual(
            len(sourcegen._validate_setup_contract(contract, "x", "y")), 1
        )

    def test_an_upload_in_setup_is_refused_before_the_build(self) -> None:
        """The grammar accepts one and this runner does not build one. A
        refusal here costs a model call; the same gap discovered at run time
        cost a lab its spec when field's runner was missing an extractor.
        """
        with self.assertRaisesRegex(RuntimeError, "cannot build"):
            sourcegen._validate_setup_contract(
                _contract(
                    setup=json.dumps([
                        {"method": "POST", "path": "/files",
                         "upload": [{"name": "f", "filename": "a.txt", "text": "x"}]}
                    ]),
                    setup_port=8080,
                ),
                "CVELAB_BOUND", "CVELAB_BOUND",
            )

    def test_a_lab_that_binds_and_cannot_receive_the_bindings_is_refused(self) -> None:
        """A session seeded and never used measures as the attack never
        having been delivered, which is the failure this field exists for.
        """
        for compose, validator in (("", "CVELAB_BOUND"), ("CVELAB_BOUND", "")):
            with self.subTest(compose=bool(compose)):
                with self.assertRaisesRegex(RuntimeError, "CVELAB_BOUND"):
                    sourcegen._validate_setup_contract(
                        _contract(
                            setup=json.dumps(_WORKED_EXAMPLE),
                            setup_port=8080, inputs=["csrfToken"],
                        ),
                        compose or "services: {}", validator or "print(1)",
                    )

    def test_a_setup_with_no_bindings_needs_nothing_received(self) -> None:
        contract = _contract(
            setup=json.dumps([{"method": "POST", "path": "/lab/seed"}]),
            setup_port=8080,
        )
        self.assertEqual(
            len(sourcegen._validate_setup_contract(
                contract, "services: {}", "print(1)"
            )),
            1,
        )


class ThePromptTests(unittest.TestCase):
    """The instruction, and the one example that makes it measurable.

    The binding form has never appeared in a model's answer under `setup`:
    of the nine specs recorded under tests/fixtures/recorded-specs.json
    exactly one declares setup and it is a bare POST to a seeding route.
    `bind` appears only under `discover`, a different field in a different
    mode asked for in different words. A schema entry with no worked example
    would therefore have measured zero and read as "preconditions were not
    the problem".
    """

    SOURCE = Path(sourcegen.__file__).read_text(encoding="utf-8")

    def test_the_recorded_specs_really_do_not_hold_one(self) -> None:
        """The premise, asserted rather than remembered. When a recording
        with a bound setup step lands, this test is how the next person
        learns the example has done its job.
        """
        recorded = json.loads(
            (REPO / "tests" / "fixtures" / "recorded-specs.json").read_text(
                encoding="utf-8"
            )
        )
        with_setup = [
            entry for entry in recorded if entry["spec"].get("setup")
        ]
        self.assertEqual(len(with_setup), 1)
        self.assertEqual(
            [step for step in with_setup[0]["spec"]["setup"] if "bind" in step], []
        )

    def test_all_three_prompts_ask_for_it(self) -> None:
        self.assertEqual(self.SOURCE.count("+ _SETUP_CONTRACT"), 3)
        self.assertEqual(
            self.SOURCE.count("+ _EFFECT_CONTRACT"),
            self.SOURCE.count("+ _SETUP_CONTRACT"),
        )

    def test_the_worked_example_is_a_spec_the_grammar_accepts(self) -> None:
        """Shipping an example that would be refused is worse than shipping
        none: the model copies it, the answer is refused, and the refusal
        names the grammar rather than the instruction that taught it.
        """
        parsed = steps.validate_setup(
            _example_from(sourcegen._SETUP_CONTRACT),
            steps.validate_inputs(["csrfToken"]),
        )
        self.assertEqual(steps.bound_names(parsed), ["csrfToken"])
        self.assertEqual(len(parsed), 3)

    def test_the_example_shows_the_form_that_has_never_arrived(self) -> None:
        shown = _example_from(sourcegen._SETUP_CONTRACT)
        self.assertEqual(shown[0]["extract"], {"header": "X-CSRF-Token"})
        self.assertIn("{{csrfToken}}", json.dumps(shown[1:]))
        self.assertIn("victim", json.dumps(shown[2]))

    def test_it_names_the_declared_input_beside_the_example(self) -> None:
        self.assertIn('inputs is ["csrfToken"]', sourcegen._SETUP_CONTRACT)

    def test_it_says_how_the_bindings_reach_the_validator(self) -> None:
        for said in (
            steps.SETUP_BOUND_VARIABLE,
            "${CVELAB_BOUND:-}",
            "exploit_contract.setup_port",
            "exploit_contract.preconditions",
        ):
            with self.subTest(said=said):
                self.assertIn(said, sourcegen._SETUP_CONTRACT)

    def test_the_pinned_sentence_did_not_move(self) -> None:
        """tests/test_sourcegen_contract.py requires it inside the first 2000
        characters of each contract prompt, and the differential block has
        405 characters of room ahead of it. Appending after it moves no
        offset at all, which is why both contract blocks are appended.
        """
        blocks = self.SOURCE.split("the literal keys attack_executed")
        self.assertEqual(len(blocks), 3)
        for number, block in enumerate(blocks[1:], 1):
            with self.subTest(prompt=number):
                self.assertLess(
                    block.index("Measure confirmed the same way on both sides"), 1700
                )


def _example_from(instruction: str) -> list[dict]:
    """The JSON array the prompt shows, read back out of the prompt itself.

    Decoded rather than sliced to a closing bracket: the first `}]` in it
    closes the binding step's own query.
    """
    start = instruction.index('[{"bind": "csrfToken"')
    shown, _ = json.JSONDecoder().raw_decode(instruction, start)
    return shown


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------


_EFFECT = "victim-record-read"

_PROVING = {
    "attack_executed": True,
    "proof_quality": "security_effect_observed",
    "observable_effect": "the victim's record",
    "evidence_type": "authorization_bypass",
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


class TheRunTests(unittest.TestCase):
    """Where the steps run, and what a lab without them still does.

    The position is the one closed.py has always applied its fixture in:
    after the services are up and before the first attack. A non-zero exit
    aborts, because an unseeded instance answers the attack the way a fixed
    one does.
    """

    CVE = "CVE-2026-0001"

    def _on_disk(self, root: Path, contract: dict) -> Path:
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
                "exploit_contract": contract,
            }),
            encoding="utf-8",
        )
        return lab

    def _run(
        self, contract: dict, *, setup_fails: str | None = None,
    ) -> tuple[dict | None, list[dict], Exception | None]:
        """run_lab with every container call recorded instead of made."""
        calls: list[dict] = []

        def tool(
            _compose: list[str], _docker: str, _environment: dict[str, str],
            _lab_dir: Path, service: str, extra: dict[str, str] | None = None,
            wait_for_services: bool = True, force_recreate: bool = True,
        ) -> tuple[int, str, str]:
            calls.append({
                "service": service, "extra": dict(extra or {}),
                "wait_for_services": wait_for_services,
                "force_recreate": force_recreate,
            })
            if service == policy.SETUP_SERVICE:
                if setup_fails is not None:
                    return 1, json.dumps({"step": 0, "error": setup_fails}), ""
                return 0, json.dumps({
                    "requests": [],
                    "bound": {"csrfToken": "tok-" + extra["CVELAB_SETUP_TARGET"]},
                }), ""
            if not extra or "CVELAB_MANUAL_ACTION" not in extra:
                return 0, json.dumps(_PROVING), ""
            return 0, (
                "REPRODUCED" if extra["CVELAB_TARGET"] == "vulnerable" else "BLOCKED"
            ), ""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._on_disk(root, contract)
            scratch = root / "limits"
            scratch.mkdir()
            with mock.patch.object(
                        core, "prepare_compose",
                        return_value=("docker", {}, ["docker", "compose"], scratch),
                    ) as prepared, \
                    mock.patch.object(core, "run_docker_stage"), \
                    mock.patch.object(core, "_run_tool_service", side_effect=tool), \
                    mock.patch(
                        "subprocess.run",
                        return_value=subprocess.CompletedProcess([], 0, "", ""),
                    ):
                try:
                    outcome = core.run_lab(self.CVE, root, keep=False)
                except Exception as error:  # noqa: BLE001 - the test asserts on it
                    return None, calls, error
                self.prepared = prepared.call_args
            return outcome["report"], calls, None

    # -- a lab with no setup -------------------------------------------------

    def test_a_lab_with_no_setup_runs_exactly_as_it_did(self) -> None:
        """The regression that matters most. No service injected, nothing
        started before the validator, and the validator reached by the same
        call with the same arguments.
        """
        report, calls, error = self._run({
            "observable_effect": "the victim's record",
            "evidence_type": "authorization_bypass",
            "effect_predicate": {"body_contains": _EFFECT},
        })
        self.assertIsNone(error)
        self.assertIsNone(self.prepared.args[1])
        self.assertEqual(
            [call["service"] for call in calls],
            ["validator"] * 5,
        )
        first = calls[0]
        self.assertEqual(first["extra"], {})
        self.assertTrue(first["wait_for_services"])
        self.assertTrue(first["force_recreate"])
        self.assertEqual(report["setup_bindings"], {})
        self.assertTrue(report["ok"])

    # -- a lab with setup ----------------------------------------------------

    def contract(self) -> dict:
        return {
            "observable_effect": "the victim's record",
            "evidence_type": "authorization_bypass",
            "effect_predicate": {"body_contains": _EFFECT},
            "preconditions": ["An authenticated victim session exists."],
            "inputs": ["csrfToken"],
            "setup_port": 8080,
            "setup": steps.validate_setup(
                _WORKED_EXAMPLE, steps.validate_inputs(["csrfToken"])
            ),
        }

    def test_the_steps_run_once_per_build_before_the_validator(self) -> None:
        report, calls, error = self._run(self.contract())
        self.assertIsNone(error)
        self.assertEqual(
            [call["service"] for call in calls[:3]],
            [policy.SETUP_SERVICE, policy.SETUP_SERVICE, "validator"],
        )
        self.assertEqual(
            [call["extra"]["CVELAB_SETUP_TARGET"] for call in calls[:2]],
            ["vulnerable", "patched"],
        )
        self.assertEqual(report["setup_bindings"], {
            "patched": ["csrfToken"], "vulnerable": ["csrfToken"],
        })
        self.assertTrue(report["ok"])

    def test_the_bindings_are_per_build_and_do_not_leak(self) -> None:
        """A session on the affected build is not a session on the fixed one,
        and `_check_variant_parity` cannot catch a collapse here: the setup
        is CVELab's and never passes through it.
        """
        _, calls, error = self._run(self.contract())
        self.assertIsNone(error)
        carried = json.loads(calls[2]["extra"]["CVELAB_BOUND"])
        self.assertEqual(carried, {
            "vulnerable": {"csrfToken": "tok-vulnerable"},
            "patched": {"csrfToken": "tok-patched"},
        })
        self.assertNotEqual(
            carried["vulnerable"]["csrfToken"], carried["patched"]["csrfToken"]
        )

    def test_the_handed_over_actions_get_the_same_bindings(self) -> None:
        """A manual action sends the attack again, so it needs the state the
        automatic proof had; without them a lab whose session came from setup
        would fail its own handed-over script.
        """
        _, calls, error = self._run(self.contract())
        self.assertIsNone(error)
        actions = [call for call in calls if "CVELAB_MANUAL_ACTION" in call["extra"]]
        self.assertEqual(len(actions), 4)
        for action in actions:
            with self.subTest(action=action["extra"]["CVELAB_MANUAL_ACTION"]):
                self.assertIn("CVELAB_BOUND", action["extra"])

    def test_the_second_build_does_not_bring_the_first_one_down(self) -> None:
        """`up --force-recreate` applies to everything it brings up, so the
        setup service never asks for it, and only the first of the two waits
        on the dependencies the lab's validator declares.
        """
        _, calls, error = self._run(self.contract())
        self.assertIsNone(error)
        self.assertEqual(
            [(call["wait_for_services"], call["force_recreate"]) for call in calls[:2]],
            [(True, False), (False, False)],
        )
        # And the validator, for the same reason: recreating it would restart
        # the builds whose state was just established.
        self.assertFalse(calls[2]["wait_for_services"])

    def test_the_declared_steps_reach_the_compose_override(self) -> None:
        report, _, error = self._run(self.contract())
        self.assertIsNone(error)
        declared, port = self.prepared.args[1]
        self.assertEqual(port, 8080)
        self.assertEqual(steps.bound_names(declared), ["csrfToken"])

    def test_a_setup_that_cannot_run_stops_the_run_and_says_which_step(self) -> None:
        report, calls, error = self._run(
            self.contract(), setup_fails="nothing to bind from the response"
        )
        self.assertIsNone(report)
        self.assertIsNotNone(error)
        self.assertIn(core.SETUP_FAILURE_MARKER, str(error))
        self.assertIn("nothing to bind from the response", str(error))
        self.assertIn("vulnerable", str(error))
        # The attack was never delivered, so it must not have been tried:
        # an unseeded instance answers the way a fixed one does.
        self.assertEqual([call["service"] for call in calls], [policy.SETUP_SERVICE])

    def test_the_marker_is_its_own_failure_class(self) -> None:
        """autoflow classifies on the message, so the marker must not read as
        a build that failed or a service that never became healthy. Those
        strings are in autoflow's _STARTUP_MARKERS and must stay out of here.

        Necessary and not sufficient: the marker travels wrapped in the
        compose diagnostics `run_lab` appends, which carry those strings on
        their own. That is what `TheClassAutoflowGivesItTests` below pins;
        the bare marker does not reproduce it.
        """
        lowered = core.SETUP_FAILURE_MARKER.lower()
        for marker in autoflow._STARTUP_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, lowered)
        self.assertIn("setup", lowered)


#: What a setup that could not bind looks like by the time autoflow reads it.
#:
#: The first half is `core.run_setup`'s own f-string, built from core's marker
#: rather than written out again. The second is what `run_lab` wraps every
#: exception it raises in: `docker compose ps -a` and `docker compose logs`
#: for the whole project.
#:
#: Those diagnostics are the hazard, and they are why the bare marker is not
#: a sufficient fixture. They report every service, so a dependency that
#: flapped after the setup had already passed the health gate shows up as
#: `Up (unhealthy)` and `is unhealthy` lands in the text of a failure that
#: happened once the services were up -- and `is unhealthy` is one of
#: autoflow's _STARTUP_MARKERS. The second route is plainer still: any log
#: line that quotes the phrase.
SETUP_DIAGNOSTICS = (
    "\n\nCompose diagnostics:\n"
    "docker compose ps -a:\n"
    "NAME                           STATUS\n"
    "cvelab-vulnerable-1            Up 41 seconds (healthy)\n"
    "cvelab-sessioncache-1          Up 39 seconds (unhealthy)\n\n"
    "docker compose logs --no-color --tail 200:\n"
    "sessioncache-1  | WARNING: replica is unhealthy; serving from primary\n"
)

#: A binding step that found nothing, which is the setup runner's usual
#: report: the route answered, the answer carried no such value, and the
#: status it answered with is recorded beside the name.
SETUP_FAILED = (
    f"{core.SETUP_FAILURE_MARKER} on the vulnerable build: "
    "{'step': 2, 'bind': 'csrfToken', 'status': 403, "
    "'error': 'nothing to bind from the response'}"
)

SETUP_FAILED_AS_AUTOFLOW_SEES_IT = SETUP_FAILED + SETUP_DIAGNOSTICS

#: A startup failure, to prove the class above was not taken at its expense.
STARTUP_FAILED = (
    "Validator startup failed: dependency failed to start: container "
    "cvelab-vulnerable-1 is unhealthy\n\nCompose diagnostics:\n"
    "docker compose logs --no-color --tail 200:\n"
    "vulnerable-1  | Error: listen EADDRINUSE"
)

#: And a build a model can answer, which must stay unhinted and unnamed.
BUILD_FAILED = (
    "Docker stage 'build' failed with exit code 1\nDocker output:\n"
    "#27 40.11 channels/audit/audit.go:43:18: undefined: model.AuditKeyError"
)


class TheClassAutoflowGivesItTests(unittest.TestCase):
    """A setup that did not complete, as the automatic loop classifies it.

    It is the earliest of the repairable classes and the most mechanical: the
    build produced its images, the services passed the health gate the lab's
    own validator declares, and then CVELab's steps stopped on a step whose
    index, route and status are all in the error. The validator never
    started, so nothing was measured and nothing is known about the
    vulnerability yet.

    Nothing here touches Docker or a network: `run_lab`, the generator and
    the repair are all mocked, and the only I/O is automation.json under a
    temporary directory.
    """

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = self.root / "CVE-2026-12345"
        self.generated = {
            "ok": True, "status": "GENERATED_UNVALIDATED",
            "lab_dir": str(self.lab), "plan": {},
        }
        self.repaired = {"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}}
        self.passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}

    def run_flow(
        self,
        outcomes: list,
        max_attempts: int = 3,
        setup_limit: str | None = None,
        startup_limit: str | None = None,
    ):
        env = {}
        if setup_limit is not None:
            env["CVELAB_SETUP_REPAIRS"] = setup_limit
        if startup_limit is not None:
            env["CVELAB_STARTUP_REPAIRS"] = startup_limit
        with (
            mock.patch.dict(os.environ, env),
            mock.patch("cvelab.autoflow.generate_source_lab", return_value=self.generated),
            mock.patch("cvelab.autoflow.run_lab", side_effect=outcomes) as run,
            mock.patch("cvelab.autoflow.repair_source_lab", return_value=self.repaired) as repair,
            mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
        ):
            result = run_auto_workflow(
                "CVE-2026-12345", self.root, None, None, None,
                "key", "model", False, max_attempts=max_attempts, progress=lambda _: None,
            )
        return result, run, repair

    # --- the ordering hazard -------------------------------------------------

    def test_the_diagnostics_do_not_turn_this_into_a_startup_failure(self) -> None:
        """Measured on 2026-11-06, which is why the fixture carries a tail.

        `_startup_failure(marker)` was already False and `_startup_failure(
        marker + diagnostics)` was True, so the wrapped message won the
        startup test, took STARTUP_HINT, and spent the startup budget
        rewriting a build and healthchecks that had both already worked.
        """
        # The fixture has to actually carry the colliding phrase, or every
        # assertion below passes for the wrong reason.
        self.assertIn("is unhealthy", SETUP_FAILED_AS_AUTOFLOW_SEES_IT.lower())
        self.assertNotIn("is unhealthy", SETUP_FAILED.lower())

        for message in (SETUP_FAILED, SETUP_FAILED_AS_AUTOFLOW_SEES_IT):
            with self.subTest(diagnostics="Compose diagnostics" in message):
                self.assertTrue(autoflow._setup_failure(message))
                self.assertFalse(autoflow._startup_failure(message))
                self.assertEqual(
                    autoflow._runtime_failure(message)["kind"], "setup_not_established"
                )

    def test_a_real_startup_failure_is_still_one(self) -> None:
        """The guard is on the marker and on nothing else."""
        self.assertTrue(autoflow._startup_failure(STARTUP_FAILED))
        self.assertFalse(autoflow._setup_failure(STARTUP_FAILED))
        for marker in autoflow._STARTUP_MARKERS:
            with self.subTest(marker=marker):
                self.assertTrue(autoflow._startup_failure(f"Validator failed: {marker}"))

    def test_the_startup_budget_is_not_taken_once_the_setup_budget_is_spent(self) -> None:
        """The case ordering the branches cannot cover.

        Putting the setup branch before the startup branch holds only while
        the setup budget lasts. With it at zero -- or once it has run out --
        the loop falls through to the startup test, and if that test still
        matched the diagnostics the same failure would take the startup
        budget by the back door. So the guard lives in `_startup_failure`,
        and this is the test that says so: revert the guard and keep the
        branch order, and this one fails while every other test here passes.
        """
        _result, _run, repair = self.run_flow(
            [RuntimeError(SETUP_FAILED_AS_AUTOFLOW_SEES_IT), self.passed],
            setup_limit="0",
        )
        failure = repair.call_args.args[2]
        self.assertEqual(failure["hint"], autoflow.SETUP_HINT)
        self.assertNotEqual(failure["hint"], autoflow.STARTUP_HINT)

        result, _run, _repair = self.run_flow(
            [RuntimeError(SETUP_FAILED_AS_AUTOFLOW_SEES_IT)] * 10,
            max_attempts=2, setup_limit="0",
        )
        self.assertEqual(result["startup_repairs"], 0)
        self.assertEqual(result["setup_repairs"], 0)
        recorded = json.loads((self.lab / "automation.json").read_text())
        phases = [attempt["phase"] for attempt in recorded["attempts"]]
        self.assertNotIn("startup", phases)
        self.assertNotIn("startup_repair", phases)

    # --- the hint and the kind -----------------------------------------------

    def test_the_repair_gets_the_setup_hint_and_its_own_kind(self) -> None:
        _result, _run, repair = self.run_flow(
            [RuntimeError(SETUP_FAILED_AS_AUTOFLOW_SEES_IT), self.passed]
        )
        failure = repair.call_args.args[2]
        self.assertEqual(failure["kind"], "setup_not_established")
        # Pinned by identity rather than by a phrase: these hints are a
        # plausible pair to swap, and a swap reads as a passing test.
        self.assertEqual(failure["hint"], autoflow.SETUP_HINT)
        for other in (
            autoflow.PRECONDITION_HINT, autoflow.STARTUP_HINT, autoflow.EFFECT_HINT,
        ):
            self.assertNotEqual(failure["hint"], other)
        self.assertIn("nothing to bind from the response", failure["error"])

    def test_the_hint_comes_before_the_error_it_explains(self) -> None:
        """`repair_source_lab` serialises this dict and cuts it to fit the
        prompt -- 12000 characters on a local provider -- so insertion order
        is the whole retention policy, and an easy thing to lose in an edit.
        """
        failure = autoflow._runtime_failure(SETUP_FAILED + "x" * 20000)
        self.assertEqual(list(failure), ["hint", "kind", "error"])
        serialized = json.dumps(failure, ensure_ascii=True, indent=2)
        self.assertGreater(len(serialized), 20000)
        self.assertIn("exploit_contract.setup", serialized[:12000])
        self.assertLess(
            serialized.index("exploit_contract.setup"), serialized.index('"error"')
        )

    def test_the_hint_says_what_ran_what_did_not_and_what_to_change(self) -> None:
        hint = autoflow.SETUP_HINT
        self.assertIn("became healthy", hint)
        self.assertIn("the validator never ran", hint)
        self.assertIn("Change exploit_contract.setup, and nothing else", hint)
        self.assertIn("exploit_contract.setup_port", hint)

    def test_the_hint_does_not_claim_a_refusal_stops_the_setup(self) -> None:
        """It does not, and saying it did would send the repair hunting.

        `steps.SETUP_RUNNER` catches HTTPError in `send` and returns the
        code, so a 4xx is read as an answer and the next step is sent. The
        only two things that stop the steps are a route that cannot be
        reached and an extractor that bound nothing; a 4xx reaches the error
        as the status recorded beside such a binding, which is exactly how
        SETUP_FAILED above carries its 403.
        """
        self.assertIn("read as an answer", autoflow.SETUP_HINT)
        self.assertIn("before rewriting the extractor", autoflow.SETUP_HINT)
        # The runner's own behaviour, so the hint cannot quietly stop
        # matching it.
        self.assertIn("except urllib.error.HTTPError as refused:", steps.SETUP_RUNNER)
        self.assertIn("return (refused.code,", steps.SETUP_RUNNER)

    # --- the budget ----------------------------------------------------------

    def test_it_is_repaired_without_spending_a_validation_attempt(self) -> None:
        result, run, repair = self.run_flow(
            [RuntimeError(SETUP_FAILED_AS_AUTOFLOW_SEES_IT), self.passed]
        )
        self.assertTrue(result["ok"])
        self.assertEqual(run.call_count, 2)
        repair.assert_called_once()
        # The attempt is given back, as a startup failure's is: the validator
        # never ran, so nothing was learned about the vulnerability.
        self.assertEqual(result["automation"]["validation_attempts"], 1)
        self.assertEqual(result["automation"]["repair_calls"], 0)
        self.assertEqual(result["automation"]["setup_repairs"], 1)
        # And not out of the effect budget, which is for a validator that ran.
        self.assertEqual(result["automation"]["effect_repairs"], 0)
        self.assertEqual(result["automation"]["startup_repairs"], 0)
        phases = [attempt["phase"] for attempt in result["automation"]["attempts"]]
        self.assertEqual(phases[:3], ["generation", "setup", "setup_repair"])

    def test_the_budget_is_capped_and_the_run_still_ends(self) -> None:
        result, run, repair = self.run_flow(
            [RuntimeError(SETUP_FAILED_AS_AUTOFLOW_SEES_IT)] * 10,
            max_attempts=2, setup_limit="1",
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "AUTO_REPAIR_EXHAUSTED")
        # One free setup repair, then the ordinary path: two validations and
        # the one repair a budget of two allows.
        self.assertEqual(run.call_count, 3)
        self.assertEqual(repair.call_count, 2)
        self.assertEqual(result["setup_repairs"], 1)
        self.assertEqual(result["startup_repairs"], 0)
        self.assertEqual(result["failure"]["kind"], "setup_not_established")
        recorded = json.loads((self.lab / "automation.json").read_text())
        phases = [attempt["phase"] for attempt in recorded["attempts"]]
        self.assertEqual(phases.count("setup_repair"), 1)

    def test_the_setting_is_bounded_like_its_neighbours(self) -> None:
        for raw, expected in (("", 2), ("0", 0), ("5", 5), ("99", 5), ("-1", 0), ("two", 2)):
            with (
                self.subTest(raw=raw),
                mock.patch.dict(os.environ, {"CVELAB_SETUP_REPAIRS": raw}),
            ):
                self.assertEqual(autoflow.setup_repair_limit(), expected)
                # Its own setting, so the neighbour's must not move with it.
                self.assertEqual(autoflow.startup_repair_limit(), 2)

    # --- what must not have changed ------------------------------------------

    def test_a_startup_failure_still_gets_its_hint_and_its_own_budget(self) -> None:
        result, run, repair = self.run_flow([RuntimeError(STARTUP_FAILED), self.passed])
        self.assertTrue(result["ok"])
        self.assertEqual(run.call_count, 2)
        failure = repair.call_args.args[2]
        self.assertEqual(list(failure)[:3], ["hint", "kind", "error"])
        self.assertEqual(failure["kind"], "startup_failure")
        self.assertEqual(failure["hint"], autoflow.STARTUP_HINT)
        self.assertNotEqual(failure["hint"], autoflow.SETUP_HINT)
        self.assertEqual(result["automation"]["startup_repairs"], 1)
        self.assertEqual(result["automation"]["setup_repairs"], 0)
        self.assertEqual(result["automation"]["validation_attempts"], 1)
        phases = [attempt["phase"] for attempt in result["automation"]["attempts"]]
        self.assertEqual(phases[:3], ["generation", "startup", "startup_repair"])

    def test_a_precondition_failure_still_gets_the_precondition_hint(self) -> None:
        """The prose half of the same failure, and still the proof's own class.

        It arrives through the other path entirely: the validator ran and
        wrote a report, so it is `proof_not_verified` with a digest, not an
        exception with an error.
        """
        failed = {"ok": False, "report": {
            "proof_checks": {"attack_executed": False},
            "validation": {
                "attack_executed": False,
                "error": "RuntimeError('victim session not established')",
            },
            "setup_bindings": {"patched": ["csrfToken"], "vulnerable": ["csrfToken"]},
        }}
        _result, _run, repair = self.run_flow([failed, self.passed])
        failure = repair.call_args.args[2]
        self.assertEqual(failure["kind"], "proof_not_verified")
        self.assertEqual(failure["hint"], autoflow.PRECONDITION_HINT)
        self.assertNotEqual(failure["hint"], autoflow.SETUP_HINT)

    def test_an_ordinary_build_failure_is_still_unnamed(self) -> None:
        _result, _run, repair = self.run_flow([RuntimeError(BUILD_FAILED), self.passed])
        failure = repair.call_args.args[2]
        self.assertEqual(failure["kind"], "runtime_error")
        self.assertNotIn("hint", failure)

    # --- the digest ----------------------------------------------------------

    def test_what_the_setup_bound_reaches_a_repair_that_can_use_it(self) -> None:
        """Names only, and only where a report exists.

        A setup that failed raises before any report is written, so it never
        reaches this function at all -- which is why SETUP_HINT carries the
        error instead. Where it earns its place is the precondition case
        above: a validator reporting no session while the setup reported
        success is two different labs, one that declares no setup and one
        whose setup bound a name the validator did not use, and the digest is
        what tells them apart once the prompt's limit has cut the report.
        """
        bindings = {"patched": ["csrfToken"], "vulnerable": ["csrfToken"]}
        failed = {"ok": False, "report": {
            "proof_checks": {"attack_executed": False},
            "validation": {
                "attack_executed": False,
                "vulnerable": {"raw": "x" * 40000},
            },
            "setup_bindings": bindings,
        }}
        _result, _run, repair = self.run_flow([failed, self.passed])
        failure = repair.call_args.args[2]
        self.assertEqual(failure["digest"]["setup_bindings"], bindings)
        serialized = json.dumps(failure, ensure_ascii=True, indent=2)
        self.assertGreater(len(serialized), 40000)
        self.assertLess(
            serialized.index('"setup_bindings"'), serialized.index('"report"')
        )

    def test_a_lab_with_no_setup_says_so_rather_than_nothing(self) -> None:
        """core writes {} for a lab that declared no steps, and None is what
        a report from before this field existed has. Neither may become a
        name a repair could mistake for a binding.
        """
        for recorded, expected in (({}, {}), (None, None)):
            with self.subTest(setup_bindings=recorded):
                report: dict[str, Any] = {
                    "proof_checks": {"attack_executed": False},
                    "validation": {"attack_executed": False},
                }
                if recorded is not None:
                    report["setup_bindings"] = recorded
                digest = autoflow._validation_digest(report)
                self.assertEqual(digest["setup_bindings"], expected)


class TheToolServiceTests(unittest.TestCase):
    """The forty lines the validator and the setup service now share.

    They are the same kind of thing: a service behind the `tools` profile,
    brought up once, read from its logs and removed. Started with `up` and
    not `run`, because a one-off `compose run` container does not get the
    aliases its service declares on the network -- the lesson one lab's
    canary cost three runs, and it applies to the setup service for the same
    reason: it reaches the product by service name on that network.
    """

    def argv(self, **extra: Any) -> list[str]:
        seen: list[list[str]] = []

        def ran(arguments, **_kwargs):
            seen.append(list(arguments))
            if "ps" in arguments:
                return subprocess.CompletedProcess(arguments, 0, "abc123\n", "")
            return subprocess.CompletedProcess(arguments, 0, "0\n", "")

        with mock.patch("subprocess.run", side_effect=ran):
            core._run_tool_service(
                ["docker", "compose"], "docker", {}, Path("."), **extra
            )
        return seen[0]

    def test_the_validator_is_brought_up_as_it_always_was(self) -> None:
        self.assertEqual(
            self.argv(service="validator"),
            ["docker", "compose", "--profile", "tools", "up", "-d",
             "--force-recreate", "validator"],
        )

    def test_a_caller_that_says_the_services_are_up_adds_no_deps(self) -> None:
        self.assertIn("--no-deps", self.argv(service="validator", wait_for_services=False))

    def test_the_setup_service_never_asks_to_be_recreated(self) -> None:
        """`up --force-recreate` applies to everything `up` brings up,
        dependencies included, so recreating this container would restart the
        product and discard what the previous run seeded into it.
        """
        argv = self.argv(service=policy.SETUP_SERVICE, force_recreate=False)
        self.assertNotIn("--force-recreate", argv)
        self.assertEqual(argv[-1], policy.SETUP_SERVICE)

    def test_a_service_that_did_not_start_says_which_one(self) -> None:
        def ran(arguments, **_kwargs):
            return subprocess.CompletedProcess(arguments, 1, "", "no such service")

        with mock.patch("subprocess.run", side_effect=ran):
            with self.assertRaisesRegex(RuntimeError, policy.SETUP_SERVICE):
                core._run_tool_service(
                    ["docker", "compose"], "docker", {}, Path("."),
                    policy.SETUP_SERVICE,
                )


class ThePreparedOverrideTests(unittest.TestCase):
    """What `prepare_compose` writes, which is the only thing Compose reads."""

    def _written(self, setup: tuple[list[dict], int] | None) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary)
            (lab / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            with mock.patch.object(core, "docker_executable", return_value="docker"), \
                    mock.patch.object(core, "docker_environment", return_value={}), \
                    mock.patch.object(core, "ensure_docker"), \
                    mock.patch.object(
                        core, "compose_command",
                        return_value=["docker", "compose", "-p", "p"],
                    ), \
                    mock.patch.object(policy, "enforce", return_value=model()):
                _, _, compose, scratch = core.prepare_compose(lab, setup)
            try:
                return json.loads(Path(compose[-1]).read_text(encoding="utf-8"))
            finally:
                for leftover in scratch.iterdir():
                    leftover.unlink()
                scratch.rmdir()

    def test_a_lab_with_no_setup_gets_the_file_it_always_got(self) -> None:
        written = self._written(None)
        self.assertNotIn(policy.SETUP_SERVICE, written["services"])
        self.assertEqual(
            sorted(written["services"]), ["patched", "validator", "vulnerable"]
        )

    def test_the_steps_and_the_port_travel_in_the_environment(self) -> None:
        declared = steps.validate_setup(
            _WORKED_EXAMPLE, steps.validate_inputs(["csrfToken"])
        )
        injected = self._written((declared, 8080))["services"][policy.SETUP_SERVICE]
        environment = injected["environment"]
        self.assertEqual(json.loads(environment[steps.SETUP_SPEC_VARIABLE]), declared)
        self.assertEqual(environment[steps.SETUP_PORT_VARIABLE], "8080")
        self.assertEqual(environment[steps.SETUP_INPUTS_VARIABLE], "{}")
        # Interpolated, because one override file serves both runs and `up`
        # has no equivalent of -e.
        self.assertEqual(
            environment[steps.SETUP_TARGET_VARIABLE], "${CVELAB_SETUP_TARGET:-}"
        )

    def test_the_program_travels_in_the_command(self) -> None:
        declared = [{"method": "POST", "path": "/lab/seed", "headers": {}, "body": None}]
        injected = self._written((declared, 8080))["services"][policy.SETUP_SERVICE]
        self.assertEqual(injected["command"][:2], ["python", "-c"])
        self.assertEqual(injected["command"][2], steps.SETUP_RUNNER)
        self.assertEqual(injected["image"], "python:3.13-alpine")

    def test_the_lab_s_own_services_keep_their_limits(self) -> None:
        declared = [{"method": "POST", "path": "/lab/seed", "headers": {}, "body": None}]
        written = self._written((declared, 8080))
        self.assertIn("mem_limit", written["services"]["vulnerable"])
        self.assertIn("mem_limit", written["services"][policy.SETUP_SERVICE])

    def test_steps_without_a_usable_port_are_refused_before_anything_starts(self) -> None:
        for contract in (
            {"setup": [{"path": "/x"}], "setup_port": None},
            {"setup": [{"path": "/x"}], "setup_port": "8080"},
        ):
            with self.subTest(port=contract["setup_port"]):
                with self.assertRaisesRegex(RuntimeError, "setup_port"):
                    core.setup_contract({"exploit_contract": contract})

    def test_a_plan_from_before_this_existed_reads_as_no_setup(self) -> None:
        for plan in ({}, {"exploit_contract": {}}, {"exploit_contract": {"setup": []}}):
            with self.subTest(plan=plan):
                self.assertIsNone(core.setup_contract(plan))


@pytest.mark.docker
@unittest.skipUnless(shutil.which("docker"), "needs the Docker CLI")
class AgainstTheInstalledComposeTests(unittest.TestCase):
    """The two things no amount of unit testing can settle.

    Whether Compose merges a JSON override's new service into a lab's
    project, and whether it interpolates `${...}` inside a JSON compose file
    the way it does inside a YAML one. The whole per-build design rests on
    the second: one override file serves both runs, and `up` has no
    equivalent of -e, so the build being seeded travels as an interpolated
    variable exactly as the manual actions do.

    Marked docker and skipped without the CLI, like the resolution tests in
    tests/test_compose_policy.py. It starts no container -- `compose config`
    needs the CLI and not the engine -- but it does need Compose installed,
    and the default test run must not.
    """

    LAB = (
        "services:\n"
        "  vulnerable:\n    image: busybox\n    networks: [lab]\n    mem_limit: 128m\n"
        "    healthcheck:\n      test: [\"CMD\", \"true\"]\n"
        "  validator:\n    image: busybox\n    profiles: [\"tools\"]\n"
        "    networks: [lab]\n"
        "    depends_on:\n      vulnerable:\n        condition: service_healthy\n"
        "networks:\n  lab:\n    internal: true\n"
    )

    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.lab = Path(holder.name) / "CVE-2026-0001"
        self.lab.mkdir()
        (self.lab / "docker-compose.yml").write_text(self.LAB, encoding="utf-8")
        self.base = [
            shutil.which("docker") or "docker", "compose", "-p", "probe",
            "-f", "docker-compose.yml",
        ]
        declared = [{"method": "POST", "path": "/lab/seed", "headers": {}, "body": None}]
        merged = policy.setup_override(
            self._config(self.base, "--no-env-resolution"),
            image="python:3.13-alpine",
            program=steps.SETUP_RUNNER,
            environment={
                steps.SETUP_SPEC_VARIABLE: json.dumps(declared),
                steps.SETUP_PORT_VARIABLE: "8080",
                steps.SETUP_TARGET_VARIABLE:
                    "${" + steps.SETUP_TARGET_VARIABLE + ":-}",
            },
            limits={"mem_limit": "2g"},
        )
        (self.lab / "override.json").write_text(json.dumps(merged), encoding="utf-8")
        self.full = [*self.base, "-f", "override.json"]

    def _config(self, command: list[str], *options: str, **environment: str) -> dict:
        done = subprocess.run(
            [*command, "--profile", "*", "config", "--format", "json", *options],
            cwd=self.lab, capture_output=True, text=True,
            env={**os.environ, **environment},
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    def test_the_override_s_new_service_is_merged_in(self) -> None:
        resolved = self._config(self.full)
        self.assertIn(policy.SETUP_SERVICE, resolved["services"])
        injected = resolved["services"][policy.SETUP_SERVICE]
        self.assertEqual(injected["command"][:2], ["python", "-c"])
        self.assertEqual(injected["command"][2], steps.SETUP_RUNNER)
        self.assertEqual(injected["networks"], {"lab": None})
        self.assertEqual(
            injected["depends_on"],
            {"vulnerable": {"condition": "service_healthy", "required": True}},
        )

    def test_the_build_being_seeded_interpolates_from_the_environment(self) -> None:
        """The manual actions' own mechanism, in a JSON file rather than YAML."""
        for named in ("vulnerable", "patched"):
            with self.subTest(build=named):
                resolved = self._config(self.full, CVELAB_SETUP_TARGET=named)
                self.assertEqual(
                    resolved["services"][policy.SETUP_SERVICE]["environment"][
                        steps.SETUP_TARGET_VARIABLE
                    ],
                    named,
                )

    def test_an_unset_build_resolves_to_empty_rather_than_failing(self) -> None:
        """`up -d <startup services>` loads the same file with nothing set."""
        resolved = self._config(self.full, CVELAB_SETUP_TARGET="")
        self.assertEqual(
            resolved["services"][policy.SETUP_SERVICE]["environment"][
                steps.SETUP_TARGET_VARIABLE
            ],
            "",
        )

    def test_the_policy_accepts_what_compose_actually_resolved(self) -> None:
        self.assertEqual(
            policy.check_model(self._config(self.full, "--no-env-resolution"), self.lab),
            [],
        )

    def test_the_profile_keeps_it_out_of_the_lab_s_own_startup(self) -> None:
        def services(*options: str) -> list[str]:
            done = subprocess.run(
                [*self.full, *options, "config", "--services"],
                cwd=self.lab, capture_output=True, text=True, env=os.environ.copy(),
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            return sorted(done.stdout.split())

        self.assertEqual(services(), ["vulnerable"])
        self.assertEqual(
            services("--profile", "tools"),
            sorted([policy.SETUP_SERVICE, "validator", "vulnerable"]),
        )

    def test_the_lab_s_own_ceilings_are_not_overwritten(self) -> None:
        resolved = self._config(self.full)
        # Compose resolves a size to bytes, and reports it as text in this
        # pass, so the comparison is on the number rather than the spelling.
        self.assertEqual(
            int(resolved["services"]["vulnerable"]["mem_limit"]), 128 * 1024**2
        )
        self.assertEqual(
            int(resolved["services"][policy.SETUP_SERVICE]["mem_limit"]), 2 * 1024**3
        )


if __name__ == "__main__":
    unittest.main()
