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
import shutil
import subprocess
import unittest
from pathlib import Path

import pytest
from cvelab import core

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
