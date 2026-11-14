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

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
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

    def test_a_script_that_only_names_itself_is_refused_for_that(self) -> None:
        """The one way the token can be present and the address still ignored.

        sys.argv[0] is the name the script was invoked as -- which the usage
        line above is asked for by name -- so a validator can carry the
        token for that alone and read no argument. The lab would declare a
        port, the artifact would offer an address, and the program handed
        one would drop it. The refusal has to name this mistake rather than
        the other, because the text is what the next attempt is given.
        """
        from tests.test_sourcegen_contract import generated_files

        named = fixture_source().replace(
            "sys.exit(main(sys.argv))", "sys.exit(main([sys.argv[0]]))"
        )
        self.assertIn("sys.argv[0]", named)
        with self.assertRaisesRegex(RuntimeError, r"only as sys\.argv\[0\]"):
            sourcegen._validate_generated(generated_files(named))

    def test_naming_itself_and_reading_an_argument_is_accepted(self) -> None:
        """Both uses in one script, the shape the archive is written in.

        Of 269 archived validators 17 mention sys.argv and only 3 spell
        sys.argv[1]; the rest reach the address as sys.argv[1:],
        main(sys.argv) or len(sys.argv), and 11 of the 17 carry a
        sys.argv[0] use as well, for the usage line. A check that read the
        first use and stopped, or that pinned a subscript, would refuse
        those for being written correctly.
        """
        from tests.test_sourcegen_contract import generated_files

        for spelling in (
            "sys.exit(main([sys.argv[0], *sys.argv[1:]]))",
            "sys.exit(main([sys.argv[0]] if len(sys.argv) > 9 else sys.argv))",
        ):
            with self.subTest(spelling=spelling):
                sourcegen._validate_generated(generated_files(
                    fixture_source().replace("sys.exit(main(sys.argv))", spelling)
                ))


class ThePromptDrivesTheSecondEntryPointTests(unittest.TestCase):
    """`--prompt`, measured against the script the contract is satisfiable by.

    The fixture beside these tests is the smallest validator
    `_OPERATOR_CONTRACT` admits, and it implements the one-command form the
    contract asks for in prose. So the prompt can be measured here the way
    nothing else in the suite can: a real two-entry-point validator, a real
    product on a real socket, and a line typed at a prompt arriving as a
    request.

    What is held: that a typed line reaches the lab program's own address
    path and nowhere else, that each line is one invocation and therefore one
    session -- the session the contract makes that path build for itself --
    that it still arrives on a lab whose one address argument belongs to a
    proved remote mode, where the child is named through the environment
    rather than reached by that argument, and that none of this is reachable
    with no argument at all, which is the path the automatic differential
    takes.
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

    def artifact(self, record: dict | None = None, **extra: object) -> str:
        return field.emit_poc(
            "CVE-2026-0001", self.plan(**extra),
            FIXTURE.read_text(encoding="utf-8"),
            record
            or {"shipped": False, "reason": "nothing was proved against one instance"},
        )

    def proved(self) -> dict:
        """A record that makes this lab's one address argument remote mode's.

        The shape no test here covered, which is how the prompt came to be
        withheld from it. The spec is the smallest one `validate_spec`
        accepts and is never sent: `main()` is the program the prompt does
        not reach, and what these runs measure is the one it does.
        """
        return {
            "shipped": True,
            "container_port": 8080,
            "spec": field.validate_spec({
                "strategy": "inband_differential",
                "observable_effect": "the supplied command ran",
                "probe": [{"method": "GET", "path": "/run?cmd=id"}],
                "control": [{"method": "GET", "path": "/run"}],
                "extract": {"json_values": "body"},
            }),
        }

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
        offered, reason = field.prompt_standing(
            self.plan(), FIXTURE.read_text(encoding="utf-8")
        )
        self.assertTrue(offered, reason)
        self.assertIn("--prompt", self.artifact())

    def test_a_typed_line_arrives_at_the_product_as_one_command(self) -> None:
        with stub(seeded=False) as (address, asked):
            said, complained, code = self.ran(
                self.artifact(), address, "--prompt", "--allow-prompt",
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

    def test_a_typed_line_arrives_for_a_lab_that_proved_a_remote_mode_too(self) -> None:
        """The shape the mode was withheld from, measured the same way.

        A declared port, command execution, a validator that implements the
        one-command form -- the three the prompt is gated on -- and a proved
        remote mode, which used to be a fourth gate: one address is remote
        mode's on such a lab, so a child run with the address and the line
        would have landed in argparse and had every line refused. The prompt
        names its own child in the environment instead, and the question that
        matters is whether the line still arrives at the product. So it is
        asked here, against a real socket, and not only of the emitted text.

        Nothing an operator types changed: the same address with no prompt is
        still remote mode's, which `TheOneAddressArgumentTests` holds.
        """
        with stub(seeded=False) as (address, asked):
            said, complained, code = self.ran(
                self.artifact(self.proved()), address, "--prompt", "--allow-prompt",
                typed="id\n", port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(code, 0, complained)
        # The address path's own session, built for that line and used by it.
        self.assertEqual([path for path, _ in asked], ["/login", "/run"])
        self.assertEqual(
            [query.get("cmd") for path, query in asked if path == "/run"], [["id"]]
        )
        self.assertIn("uid=0(root)", said)
        self.assertIn("REPRODUCED", said)

    def test_each_line_is_its_own_invocation_and_its_own_session(self) -> None:
        with stub(seeded=False) as (address, asked):
            said, complained, code = self.ran(
                self.artifact(), address, "--prompt", "--allow-prompt",
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
                self.artifact(), address, "--prompt", "--allow-prompt",
                typed="cd /srv\nls\n", port=address.rsplit(":", 1)[1],
            )
        cmds = [query.get("cmd") for path, query in asked if path == "/run"]
        # `cd /srv` now probes the target before tracking -- `cd /srv && printf
        # <token>` -- and the stub echoes the token back, so the move takes; the
        # typed `ls` then rides the tracked prefix.
        self.assertEqual(len(cmds), 2, cmds)
        self.assertTrue(cmds[0][0].startswith("cd /srv && printf "), cmds[0])
        self.assertEqual(cmds[1], ["cd /srv && ls"])

    def test_the_no_argument_path_is_unchanged_with_the_prompt_in_the_file(self) -> None:
        """The path every proof rests on, measured with the mode present."""
        text = self.artifact()
        self.assertIn("_prompt_given(sys.argv)", text)
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
        self.assertNotIn("--prompt", text)
        self.assertNotIn("--allow-prompt", text)
        _, complained, code = self.ran(text, "--prompt", "--allow-prompt")
        self.assertEqual(code, 2)
        self.assertIn("no remote mode", complained)

    def test_a_cd_that_is_not_there_is_caught_and_not_tracked(self) -> None:
        """A cd to a directory the target does not have is said, not tracked.

        Against a product that answers a failing command with an empty block --
        `executing_stub` runs the line and hands back whatever it printed, which
        is nothing when the directory is not there -- the old code advanced the
        tracked cwd blindly and every later line went out `cd <gone> && ...` and
        came back empty, silently. Now a cd is probed first: `cd /tmp` takes, so
        `pwd` reads /tmp; `cd /nowhere...` does not, so it is said and the tracked
        directory is left at /tmp, which the `pwd` after it proves by still
        reading /tmp rather than an empty block.
        """
        with executing_stub() as (address, _):
            said, err, code = self.ran(
                self.artifact(), address, "--prompt", "--allow-prompt",
                typed="cd /tmp\npwd\ncd /nowhere-zzz-404\npwd\nexit\n",
                port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(code, 0, err)
        self.assertGreaterEqual(said.count("/tmp"), 2, said)
        self.assertIn("cd did not take", err)
        self.assertIn("/nowhere-zzz-404 is not a directory on the target", err)

    def test_asking_for_both_the_prompt_and_the_session_names_the_conflict(self) -> None:
        """The mirror of the session's own check, reached when --shell is absent.

        `--allow-shell` without `--shell` does not win the dispatch, so it lands
        here in the prompt; the real conflict is two modes, not a command, and
        the refusal says so rather than talking about a command on the line.
        """
        _, complained, code = self.ran(
            self.artifact(), "127.0.0.1:1", "--prompt", "--allow-prompt", "--allow-shell",
        )
        self.assertEqual(code, 2)
        self.assertIn("two different modes", complained)
        self.assertNotIn("command on the command line", complained)


class TheSessionHoldsStateTests(unittest.TestCase):
    """`--shell`, measured against a target that really runs what it is sent.

    The session rides the one-command form the prompt rides and is gated the
    same way by `field.prompt_standing`, so the shapes held here are the ones
    that would let it drift from the prompt or from what it claims: it is
    offered on exactly the labs the prompt is and never without the prompt, it
    refuses on the same flag discipline, the marker that tells the held shell's
    answer from the product's echo is made at runtime and never in the file,
    and -- the part that is its own, and the whole reason it was built rather
    than a connect-back -- a shell is held open on the target whose state is
    real and torn down when the session ends.

    The prompt's stub echoes a canned line, which is all the prompt needs; the
    session needs a target that really runs what it is sent, because a held
    shell is a real process reading a real fifo. So these run against
    `executing_stub`, whose command route runs the delivered command in a
    `/bin/sh` on the test host -- which is where the held shell then lives, and
    where teardown is checked to have removed it.
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
        self, text: str, *argv: str, typed: str = "", port: str = "", env: dict | None = None
    ) -> tuple[str, str, int]:
        environment = dict(os.environ)
        for name in ("CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "CVELAB_BOUND"):
            environment.pop(name, None)
        if port:
            environment["CVELAB_FIXTURE_PORT"] = port
        if env:
            environment.update(env)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / field.POC_NAME
            path.write_text(text, encoding="utf-8")
            finished = subprocess.run(
                [sys.executable, str(path), *argv], input=typed,
                capture_output=True, text=True, timeout=120, env=environment,
            )
        return finished.stdout, finished.stderr, finished.returncode

    def test_the_session_is_offered_wherever_the_prompt_is(self) -> None:
        """Offered on exactly the labs the prompt is, and never without it.

        All four shapes the prompt's own gate turns on -- a port and a validator
        that reads the command -- because the session shares that gate, so fixing
        either to a smaller set of labs than the other is how the two would come
        apart. The session is checked to appear with the prompt's two flags and
        with neither on its own.
        """
        able = FIXTURE.read_text(encoding="utf-8")
        unable = "# CVELAB_MANUAL_ACTION CVELAB_TARGET exploit verify\n"
        shapes = {
            ("port", "implements"): (8080, able, True),
            ("port", "refuses"): (8080, unable, False),
            ("no port", "implements"): (None, able, False),
            ("no port", "refuses"): (None, unable, False),
        }
        for (has_port, reads), (port, validator, expected) in shapes.items():
            with self.subTest(port=has_port, validator=reads):
                plan = self.plan(
                    exploit_contract=contract(service_port=port) if port else None
                )
                self.assertIs(field.prompt_standing(plan, validator)[0], expected)
                text = field.emit_poc("CVE-2026-0001", plan, validator, None)
                self.assertIs("--shell" in text, expected)
                self.assertIs("--allow-shell" in text, expected)
                # Never one without the other: the session cannot reach a lab
                # the prompt did not, because one function gates both.
                self.assertIs("--shell" in text, "--prompt" in text)

    def _shell_namespace(self) -> dict:
        """The mode's own functions, exec'd from the emitted upper half.

        So the bytes asserted on are the ones a delivery really puts on the
        wire, built by the emitted `_shell_start`/`_shell_line`/`_shell_teardown`
        -- not a restatement of how they are spelled. `_prompt_run` and
        `_shell_marker` are the two seams a test replaces: one to capture the
        command without running it, the other to make the markers known.
        """
        upper = self.artifact().split(field.POC_LAB_MODE_MARKER, 1)[0]
        namespace: dict = {}
        exec(compile(upper, field.POC_NAME, "exec"), namespace)  # noqa: S102
        return namespace

    def test_the_emission_is_pure(self) -> None:
        """20 emissions are one text: the marker is made at runtime, not here, so
        the two writers can still agree byte for byte."""
        texts = {self.artifact() for _ in range(20)}
        self.assertEqual(len(texts), 1)
        self.assertIn("secrets.token_hex", texts.pop())

    def test_no_delivery_line_carries_the_marker_join(self) -> None:
        """The property the marker exists for, asserted over the actual bytes.

        Every line the mode writes -- the holder from `_shell_start`, the typed
        line from `_shell_line`, the teardown -- is captured, and the JOIN of
        each marker pair is shown to be absent from all of them while each half
        is present. A hex half holds nothing `shlex.quote` quotes, so the halves
        are single-quoted by hand; if that regressed to `shlex.quote(a) +
        shlex.quote(b)` the bare join would ride every line and this would fail.
        A product that only reflects the line it was handed is then fed back
        through `_shell_cut`, which finds no join and cuts to nothing -- so an
        echo cannot forge a landing, which is the whole point.
        """
        namespace = self._shell_namespace()
        pairs = {
            "holder-start": ("1111aaaa", "2222bbbb"),
            "holder-end": ("3333cccc", "4444dddd"),
            "line-start": ("5555eeee", "6666ffff"),
            "line-end": ("7777aaaa", "8888bbbb"),
        }
        halves = iter([pairs["holder-start"], pairs["holder-end"],
                       pairs["line-start"], pairs["line-end"]])
        namespace["_shell_marker"] = lambda: next(halves)
        captured: list[str] = []

        def answer(address: str, command: str):
            # Reply just enough for each step to proceed to the next, so every
            # wire line the mode builds is captured: the write (carries the line
            # markers), the read (carries the end half), the holder and the
            # teardown. The JOINS appear only in these replies, never in the
            # commands -- which is exactly what is asserted below.
            captured.append(command)
            hs, he = ("".join(pairs["holder-start"]), "".join(pairs["holder-end"]))
            ls, le = ("".join(pairs["line-start"]), "".join(pairs["line-end"]))
            out = ""
            if "CVELAB_HELD" in command:
                out = f"x {hs}\nCVELAB_HELD 4321\n{he} y"
            elif "CVELAB_SENT" in command:
                out = "CVELAB_SENT\n"
            elif "grep -q" in command:
                out = f"p {ls}\nuid=0(root)\n{le} q"
            return type("_D", (), {"returncode": 0, "stdout": out, "stderr": ""})()

        namespace["_prompt_run"] = answer
        standing, pgid, _ = namespace["_shell_start"]("10.0.0.9:8080", "deadbeef")
        self.assertEqual((standing, pgid), ("held", "4321"))
        namespace["_shell_line"]("10.0.0.9:8080", "deadbeef", "whoami", False)
        namespace["_shell_teardown"]("10.0.0.9:8080", "deadbeef", pgid)

        # Every captured wire line: no marker JOIN anywhere.
        for command in captured:
            for name, (first, second) in pairs.items():
                self.assertNotIn(
                    first + second, command,
                    f"{name} join rode the wire in: {command}",
                )
            # And a pure reflection of each line cuts to nothing under every pair.
            for first, second in pairs.values():
                self.assertIsNone(
                    namespace["_shell_cut"](command, first + second, first + second)
                )
        joined = "\n".join(captured)
        for first, second in pairs.values():  # the halves are present somewhere
            self.assertIn(first, joined)
            self.assertIn(second, joined)
        self.assertTrue(any("deadbeef" in c and "kill -KILL" in c for c in captured))

    def test_the_cut_still_finds_genuinely_executed_output(self) -> None:
        """The other half of the pin: a real response, where the held shell did
        run the echoes, cuts to the command's own output between the joins."""
        namespace = self._shell_namespace()
        start, end = "aaaabbbbccccdddd", "eeeeffff00001111"
        response = (
            '{"body": "<pre>' + start + "\\nuid=0(root)\\n" + end + '</pre>"}\n'
            "the following is the command's output:\n"
            + start + "\nuid=0(root)\n" + end + "\nREPRODUCED\n"
        )
        self.assertEqual(namespace["_shell_cut"](response, start, end), "uid=0(root)")

    def test_a_held_shell_is_one_process_whose_state_survives(self) -> None:
        """One shell across lines, an export that lasts, a `cd` that is real.

        The three claims the word "session" makes, against a target that really
        runs the lines: the process id is the same on every line, a variable
        exported on one line is read on a later one, and `cd` changes the
        directory on the target rather than being tracked here -- which `pwd`
        on the next line proves.
        """
        with executing_stub() as (address, _):
            said, err, code = self.ran(
                self.artifact(), address, "--shell", "--allow-shell",
                typed=(
                    "echo PID=$$\n"
                    "export HELD=survives_the_line\n"
                    "echo HELD=$HELD again_PID=$$\n"
                    "cd /\n"
                    "pwd; echo last_PID=$$\n"
                    "exit\n"
                ),
                port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(code, 0, err)
        pids = re.findall(r"PID=(\d+)", said)
        self.assertTrue(pids, said)
        self.assertEqual(len(set(pids)), 1, "the shell was not one process: " + said)
        self.assertIn("HELD=survives_the_line", said)
        # `cd /` was real: pwd on the next line is the root, not the directory
        # the first line ran in.
        self.assertIn("/\n", said.split("last_PID=")[0][-4:] or said)
        self.assertIn("torn down", err)
        # The per-line prompt is chrome for a terminal: on this pipe it is
        # withheld, the way the prompt mode's is, so the captured transcript is
        # not one line of repeated `shell$`. The held and teardown lines, which
        # are evidence, are still there.
        self.assertNotIn("shell$", err)
        self.assertIn("held: a detached shell is running", err)

    def test_leaving_removes_the_files_and_kills_the_process(self) -> None:
        """Teardown shown rather than asserted: the files and the held shell are
        gone from the test host, where `executing_stub` ran them."""
        with executing_stub() as (address, _):
            _, err, code = self.ran(
                self.artifact(), address, "--shell", "--allow-shell",
                typed="echo up\nexit\n", port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(code, 0, err)
        found = re.search(r"/tmp/([0-9a-f]+)_in", err)
        self.assertIsNotNone(found, err)
        run = found.group(1)
        self.assertFalse(Path(f"/tmp/{run}_in").exists())
        self.assertFalse(Path(f"/tmp/{run}_out").exists())
        live = subprocess.run(
            ["pgrep", "-f", f"tail -n +1 -f /tmp/{run}_in"],
            capture_output=True, text=True,
        )
        self.assertEqual(live.stdout.strip(), "", "a holder process was left running")

    def test_a_session_without_its_flag_starts_nothing(self) -> None:
        text = self.artifact()
        _, complained, code = self.ran(text, "127.0.0.1:1", "--shell")
        self.assertEqual(code, 2)
        self.assertIn("--allow-shell", complained)
        self.assertNotIn("held:", complained)

    def test_a_session_and_a_command_on_the_line_are_different_jobs(self) -> None:
        _, complained, code = self.ran(
            self.artifact(), "127.0.0.1:1", "id", "--shell", "--allow-shell"
        )
        self.assertEqual(code, 2)
        self.assertIn("different jobs", complained)

    def test_asking_for_both_the_session_and_the_prompt_names_the_conflict(self) -> None:
        """Both mode flags is two modes, not a command on the line.

        The session wins the dispatch, so `--prompt --allow-prompt` survive in
        what is left; the old `len(rest) > 1` told the operator their command
        conflicts when there was no command. The refusal now names the real
        thing -- two modes -- and not a command on the line.
        """
        _, complained, code = self.ran(
            self.artifact(), "127.0.0.1:1",
            "--shell", "--allow-shell", "--prompt", "--allow-prompt",
        )
        self.assertEqual(code, 2)
        self.assertIn("two different modes", complained)
        self.assertNotIn("different jobs", complained)

    def test_a_lab_that_declares_no_port_is_offered_no_session(self) -> None:
        text = self.artifact(exploit_contract=None)
        self.assertNotIn("--shell", text)
        self.assertNotIn("--allow-shell", text)

    def test_the_cause_is_named_when_the_shell_cannot_be_held(self) -> None:
        """A failure the mode tells apart from the weakness not running.

        Two kinds, both proved here. A target whose image cannot hold the shell
        -- here a `/bin/sh` with no `tail` on its PATH -- is told from the
        weakness by name, and nothing is left running. A route that does not
        answer at all -- a port nothing serves -- is told as the delivery not
        running, because that is a fact about the route and not about whether
        a shell could be held.
        """
        with executing_stub(env={"PATH": "/nonexistent"}) as (address, _):
            _, err, code = self.ran(
                self.artifact(), address, "--shell", "--allow-shell",
                typed="echo hi\nexit\n", port=address.rsplit(":", 1)[1],
            )
        self.assertEqual(code, 2)
        self.assertIn("no `tail`", err)
        self.assertIn("Nothing was left running", err)

        _, dead, gone = self.ran(
            self.artifact(), "127.0.0.1:1", "--shell", "--allow-shell",
            typed="echo hi\nexit\n", port="1",
        )
        self.assertEqual(gone, 2)
        self.assertIn("the delivery that would have started the shell did not run", dead)

    def test_a_reflecting_product_is_not_reported_as_a_missing_tail(self) -> None:
        """The holder command names the causes (`CVELAB_NO_TAIL` and the rest),
        so a product that only reflects the line it was sent would, if the join
        rode the wire, cut clean and hand back a cause it never ran. With the
        halves quoted apart the cut finds no join, so a reflection is the honest
        "the delivery did not run" and never a false fact about the target's
        image.
        """
        namespace = self._shell_namespace()

        class _Echo:
            returncode = 0

            def __init__(self, command: str) -> None:
                self.stdout = command
                self.stderr = ""

        namespace["_prompt_run"] = lambda address, command: _Echo(command)
        standing, detail, _ = namespace["_shell_start"]("10.0.0.9:8080", "deadbeef")
        self.assertEqual(standing, "failed")
        self.assertIsNone(detail)


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

    def test_a_lab_with_no_proved_remote_mode_is_offered_the_lab_program(self) -> None:
        """One echo line per thing that can actually be pointed at it.

        A printed command that exits 2 reads as a broken kit, which is why
        this line is per lab. For a lab that publishes a port and has no
        proved remote mode there IS something to point at the address now:
        the lab program takes it, at the place that program reads it. The
        fallback was printed here anyway, so the runner said "nothing here
        may be pointed at that address" while the document written by the
        same call printed the command that does -- the disagreement between
        the kit and the file that `takes_lab_address` exists to make
        impossible. Measured: 12 archived labs are this shape.

        No command after the address, because the validator this kit is
        written beside reads none. That half is `prompt_standing`'s and is
        pinned where the two artifacts are compared.
        """
        runner = written_kit(port=8080)["manual.sh"]
        self.assertIn('echo "This build is reachable on $POC_AT"', runner)
        self.assertIn(
            'echo "  python3 \\"$LAB_ROOT/artifacts/PoC.py\\" $POC_AT"', runner
        )
        self.assertNotIn("nothing here may be pointed at that address", runner)
        self.assertNotIn("$POC_AT id", runner)
        self.assertNotIn("--input", runner)

    def test_a_lab_with_neither_is_offered_nothing_and_says_so(self) -> None:
        """The fallback's own lab: it publishes no port, so no address
        reaches either program and there is nothing to print. 247 of the 264
        archived labs are that lab.
        """
        runner = written_kit(port=None)["manual.sh"]
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

    def test_a_refused_lab_is_shown_the_lab_program_for_the_address(self) -> None:
        """The address is real, and so is what may be pointed at it.

        Remote mode was refused for three labs in four, so this is the
        common case. The section used to say that nothing could be pointed
        at this address -- the refusal printed the recorded reason and exited
        2 -- and for a lab that publishes a port that is no longer what
        happens: the one argument reaches the lab program. So the section
        shows that command, and owes the reader the sentence the verdict
        cannot carry on its own, because the route that program sends is a
        constant in it.
        """
        guide = " ".join(written_kit(port=8080)["LAB-POC.md"].split())
        self.assertIn("## The address this lab publishes", guide)
        self.assertIn('python3 PoC.py "$(bash manual.sh address vulnerable)"', guide)
        self.assertIn(
            "the one target whose result means what it looks like it means", guide
        )
        self.assertIn("What it cannot choose is the route", guide)
        self.assertIn("says nothing about whether the host is affected", guide)
        # The refusal is still named, as the thing this lab has none of
        # rather than as what an argument meets.
        self.assertIn("was refused for this lab, and no argument reaches one", guide)
        self.assertIn("the address above goes to the lab program", guide)
        self.assertIn(
            "Lab mode with no argument, which is what `exploit` runs inside the "
            "lab, is unaffected",
            guide,
        )
        self.assertNotIn("exits 2 without sending anything", guide)
        # And the closing summary names the same mode the section does.
        self.assertIn(
            "`PoC.py` takes no argument for lab mode and one address, which runs "
            "that same lab program against a host instead of the Compose network",
            guide,
        )

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


class _Target(BaseHTTPRequestHandler):
    """A product whose command route actually runs the command it is sent.

    The prompt's `_Product` echoes a canned line, which is all the prompt needs.
    The session needs a target that really runs what it is handed, because a
    held shell is a real process reading a real fifo: the holder, the `tail`,
    the `sh -i` and the two files all live on the test host, which is where the
    session's own claims and its teardown are then measured. `env` lets a test
    run the delivered command in a stripped environment -- a PATH without `tail`
    -- to drive the mode's own "cannot be held" report.
    """

    env: dict | None = None

    def log_message(self, *_: object) -> None:
        pass

    def _ok(self, body: str, status: int = 200, cookie: bool = False) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        if cookie:
            self.send_header("Set-Cookie", "sid=lab-session; Path=/")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._ok("ok", cookie=True)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/run":
            self._ok("not found", status=404)
            return
        command = (parse_qs(parsed.query).get("cmd") or [""])[0]
        done = subprocess.run(
            ["/bin/sh", "-c", command], capture_output=True, text=True,
            timeout=30, env=(type(self).env or None),
        )
        # "shell-ran" is what the fixture's one-command form reads as the
        # weakness having run, so the session's delivery gets a zero exit and
        # its stdout back; the command's real output rides after it.
        self._ok("shell-ran " + done.stdout)


class _ServingTarget:
    def __init__(self, env: dict | None) -> None:
        self.env = env

    def __enter__(self) -> tuple[str, list]:
        handler = type("_BoundTarget", (_Target,), {"env": self.env})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        return f"{host}:{port}", []

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def executing_stub(env: dict | None = None) -> _ServingTarget:
    return _ServingTarget(env)


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


if __name__ == "__main__":
    unittest.main()
