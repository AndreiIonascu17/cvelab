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

"""The pipeline against real Docker, on a lab checked in beside this file.

It also holds the one claim the merged `PoC.py` makes that no stub can
settle: that with no argument it is still the lab's own validator, reaching
`vulnerable` and `patched` by Compose service name inside a network nothing
on the host can route to. The default suite compares the two programs
against a stub; here they are both run in the lab.

Every other test mocks the runtime, so nothing covered what the Docker
commands actually mean. Two regressions in one week lived exactly there:
a validator run as a one-off container silently lost the network aliases
its service declared, and then the same call, fixed for aliases, was given
--no-deps and stopped waiting for the services it depends on -- which the
validator reported as "targets not ready", indistinguishable from a lab
that failed to reproduce.

Neither could fail a unit test: the argv was what the code intended. So
this builds and runs a real lab, two services and a validator, and asserts
the differential comes back. It needs Docker and is skipped without it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pytest
from cvelab import closed, core, field, sidecar

FIXTURE = Path(__file__).parent / "fixtures" / "e2e-lab"


def _docker_works() -> bool:
    if os.getenv("CVELAB_SKIP_DOCKER_TESTS"):
        return False
    if not shutil.which("docker"):
        return False
    done = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, timeout=60, check=False
    )
    return done.returncode == 0


@pytest.mark.docker
@unittest.skipUnless(_docker_works(), "needs a working Docker daemon")
class EndToEndLabTests(unittest.TestCase):
    """One lab, built and run the way `cvelab run` runs one."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.docker, cls.environment, cls.compose, cls.scratch = core.prepare_compose(
            FIXTURE
        )
        subprocess.run(
            cls.compose + ["build", "vulnerable", "patched", "validator"],
            cwd=FIXTURE, capture_output=True, text=True, env=cls.environment,
            timeout=600, check=True,
        )
        subprocess.run(
            cls.compose + ["up", "-d", "--wait", "vulnerable", "patched"],
            cwd=FIXTURE, capture_output=True, text=True, env=cls.environment,
            timeout=300, check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        subprocess.run(
            cls.compose + ["down", "--volumes", "--remove-orphans"],
            cwd=FIXTURE, capture_output=True, env=cls.environment, timeout=300,
            check=False,
        )
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def test_the_validator_reports_the_differential(self) -> None:
        code, out, err = core.run_validator(
            self.compose, self.docker, self.environment, FIXTURE
        )
        self.assertEqual(code, 0, f"validator exited {code}: {err or out}")
        said = json.loads(out)
        self.assertIs(said["attack_executed"], True, said)
        self.assertIs(said["differential_confirmed"], True, said)
        self.assertIs(said["vulnerable"]["confirmed"], True, said)
        self.assertIs(said["patched"]["blocked"], True, said)

    def test_the_proof_checks_read_it_as_reproduced(self) -> None:
        """The same reading run_lab does, on the same output."""
        _code, out, _err = core.run_validator(
            self.compose, self.docker, self.environment, FIXTURE
        )
        said = json.loads(out)
        self.assertIs(core._validator_said(said, "vulnerable", "confirmed"), True)
        self.assertIs(core._validator_said(said, "patched", "blocked"), True)
        self.assertIs(core._validator_said(said, "patched", "confirmed"), False)

    def test_the_validator_waits_for_the_services_it_needs(self) -> None:
        """Started against stopped services, it has to wait rather than fail.

        This is the regression: with --no-deps the validator started first
        and said "targets not ready", which reads as a lab that did not
        reproduce.
        """
        subprocess.run(
            self.compose + ["stop", "vulnerable"],
            cwd=FIXTURE, capture_output=True, env=self.environment, timeout=120,
            check=True,
        )
        try:
            code, out, _err = core.run_validator(
                self.compose, self.docker, self.environment, FIXTURE
            )
        finally:
            # --wait, so the next test starts from a healthy service. Without
            # it the manual check that follows read a product still in its
            # boot sleep as BLOCKED -- the same confusion this test is about.
            subprocess.run(
                self.compose + ["up", "-d", "--wait", "vulnerable"],
                cwd=FIXTURE, capture_output=True, env=self.environment, timeout=300,
                check=True,
            )
        self.assertEqual(code, 0, out)
        self.assertIs(json.loads(out)["differential_confirmed"], True)

    def test_the_manual_interface_answers_for_each_build(self) -> None:
        for target, wanted in (("vulnerable", "REPRODUCED"), ("patched", "BLOCKED")):
            with self.subTest(target=target):
                code, out, err = core.run_validator(
                    self.compose, self.docker, self.environment, FIXTURE,
                    {"CVELAB_MANUAL_ACTION": "verify", "CVELAB_TARGET": target},
                    wait_for_services=False,
                )
                self.assertEqual(code, 0, err or out)
                self.assertIn(wanted, out)

    def test_a_service_alias_resolves_from_the_validator(self) -> None:
        """The other regression: a one-off container had no service aliases."""
        code, out, err = core.run_validator(
            self.compose, self.docker, self.environment, FIXTURE,
            {"CVELAB_MANUAL_ACTION": "alias", "CVELAB_TARGET": "vulnerable"},
            wait_for_services=False,
        )
        self.assertEqual(code, 0, err or out)
        self.assertIn("alias-ok", out)

    #: The one program a sidecar runs here: whatever text it was handed, with
    #: the argv and the environment lab mode is driven by. Lab mode takes its
    #: instructions from the environment and reads no command line, so the
    #: argv is the program name and nothing else.
    BOOTSTRAP = (
        "import os, pathlib, runpy, sys\n"
        "home = pathlib.Path('/tmp/cvelab'); home.mkdir(parents=True, exist_ok=True)\n"
        "held = home / os.environ['CVELAB_AS']\n"
        "held.write_text(os.environ['CVELAB_PROGRAM'])\n"
        "sys.argv = [os.environ['CVELAB_AS']]\n"
        "runpy.run_path(str(held), run_name='__main__')\n"
    )

    @staticmethod
    def without_the_clock(said: tuple) -> tuple:
        """The same run, with the one field that cannot repeat taken out.

        Both programs print the response headers they got, and `Date` is the
        second the product answered in. Two runs a second apart differ there
        and nowhere else, which is the measurement this test wants to make.
        """
        code, out, err = said
        return (
            code,
            re.sub(r'"Date": "[^"]*"', '"Date": "<clock>"', out),
            re.sub(r'"Date": "[^"]*"', '"Date": "<clock>"', err),
        )

    def in_the_lab(self, program: str, name: str, **environment: str) -> tuple:
        """One program, run where `vulnerable` and `patched` resolve.

        From a sidecar joined to the vulnerable container's network
        namespace, which is how `field` proves a script: the lab's network is
        internal, so nothing on the host can reach the builds by name, and
        the names are the whole of what lab mode addresses.
        """
        container = subprocess.run(
            self.compose + ["ps", "-q", "vulnerable"],
            cwd=FIXTURE, capture_output=True, text=True, env=self.environment,
            timeout=60, check=True,
        ).stdout.strip().splitlines()[-1]
        done = subprocess.run(
            ["docker", *closed.sidecar_argv(
                f"container:{container}",
                image=sidecar.BASE_IMAGE,
                program=self.BOOTSTRAP,
                flags=core.runtime_flags(),
                environment={
                    "CVELAB_PROGRAM": program, "CVELAB_AS": name, **environment,
                },
            )],
            capture_output=True, text=True, timeout=300, check=False,
        )
        return self.without_the_clock(
            (done.returncode, done.stdout, done.stderr)
        )

    def test_the_merged_poc_is_the_validator_inside_the_lab(self) -> None:
        """The non-negotiable, measured where it matters.

        Lab mode is pinned against a stub in the default suite, which cannot
        say whether the merged file still reaches `vulnerable` and `patched`
        by name and still reports the differential the same way. This runs
        both programs in the lab's own network namespace, with the same
        environment, and compares what they printed and what they returned.

        Both states of the artifact, because the upper half differs between
        them and the claim is about the lower: a lab whose remote mode was
        proved carries 1200 lines above the marker, and one whose drafter
        refused carries 20.
        """
        validator = (FIXTURE / "validator" / "validator.py").read_text(encoding="utf-8")
        plan = json.loads((FIXTURE / "plan.json").read_text(encoding="utf-8")) \
            if (FIXTURE / "plan.json").is_file() else {
                "cve": "CVE-2026-0001", "lab_type": "SOURCE_REPRODUCTION",
                "exploit_contract": {"service_port": 8000},
            }
        records = {
            "shipped": {
                "shipped": True, "container_port": 8000,
                "spec": field.validate_spec({
                    "strategy": "direct_observation",
                    "observable_effect": "a note returned to an unauthenticated reader",
                    "probe": [{"method": "GET", "path": "{{target_path}}"}],
                    "expect": {"status": 200},
                    "inputs": ["target_path"],
                }),
            },
            "refused": {"shipped": False, "reason": "the effect is internal"},
        }
        alone = self.in_the_lab(validator, "validator.py")
        self.assertEqual(alone[0], 0, f"the fixture's own validator failed: {alone}")
        for standing, record in records.items():
            merged = field.emit_poc("CVE-2026-0001", plan, validator, record)
            with self.subTest(standing=standing):
                self.assertEqual(
                    merged.partition(field.POC_LAB_MODE_MARKER)[2], validator
                )
                self.assertEqual(self.in_the_lab(merged, "PoC.py"), alone)

    def test_the_manual_actions_still_reach_the_lower_half(self) -> None:
        """What `manual.sh exploit` and `manual.sh verify` drive.

        The environment is the whole interface: the merged file must pass
        CVELAB_MANUAL_ACTION and CVELAB_TARGET through untouched, from a
        dispatch that reads argv instead.
        """
        validator = (FIXTURE / "validator" / "validator.py").read_text(encoding="utf-8")
        merged = field.emit_poc(
            "CVE-2026-0001",
            {"lab_type": "SOURCE_REPRODUCTION",
             "exploit_contract": {"service_port": 8000}},
            validator, {"shipped": False, "reason": "the effect is internal"},
        )
        for action, expected in (("exploit", None), ("verify", "REPRODUCED")):
            with self.subTest(action=action):
                environment = {
                    "CVELAB_MANUAL_ACTION": action, "CVELAB_TARGET": "vulnerable",
                }
                one = self.in_the_lab(merged, "PoC.py", **environment)
                two = self.in_the_lab(validator, "validator.py", **environment)
                self.assertEqual(one, two)
                if expected:
                    self.assertIn(expected, one[1])

    def test_remote_mode_reaches_the_build_the_differential_proved(self) -> None:
        """And the other half of the file, against the same lab.

        Remote mode is proved from a sidecar exactly like this one, so this
        is the shape that claim rests on: the merged artifact, pointed at the
        vulnerable build by address, with the route the operator has to
        supply.
        """
        validator = (FIXTURE / "validator" / "validator.py").read_text(encoding="utf-8")
        merged = field.emit_poc(
            "CVE-2026-0001",
            {"lab_type": "SOURCE_REPRODUCTION",
             "exploit_contract": {"service_port": 8000}},
            validator,
            {"shipped": True, "container_port": 8000,
             "spec": field.validate_spec({
                 "strategy": "direct_observation",
                 "observable_effect": "a note returned to an unauthenticated reader",
                 "probe": [{"method": "GET", "path": "{{target_path}}"}],
                 "expect": {"body_contains": "cvelab-e2e-secret"},
                 "inputs": ["target_path"],
             })},
        )
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "PoC.py"
            path.write_text(merged, encoding="utf-8")
            outcome = field._run_field_script(
                subprocess.run(
                    self.compose + ["ps", "-q", "vulnerable"],
                    cwd=FIXTURE, capture_output=True, text=True,
                    env=self.environment, timeout=60, check=True,
                ).stdout.strip().splitlines()[-1],
                8000, merged, inputs={"target_path": "/notes/1"},
            )
        self.assertIs(outcome["observed"], True, outcome)
        self.assertIs(outcome["ran"], True, outcome)
