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

from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from cvelab import doctor
from cvelab.doctor import FAIL, OK, WARN, Check, Report, format_report

KEY = "sk-doctorTESTkey00000000000000000000000000"  # pragma: allowlist secret


class ChecksTests(unittest.TestCase):
    def test_python_version_passes_on_a_supported_interpreter(self) -> None:
        self.assertEqual(doctor.check_python().status, OK)

    def test_missing_required_executable_fails(self) -> None:
        with mock.patch("shutil.which", return_value=None):
            check = doctor.check_executable("git", ["--version"])
        self.assertEqual(check.status, FAIL)
        self.assertIn("PATH", check.fix)

    def test_missing_optional_executable_only_warns(self) -> None:
        with mock.patch("shutil.which", return_value=None):
            check = doctor.check_executable("make", ["--version"], required=False)
        self.assertEqual(check.status, WARN)

    def test_unwritable_output_root_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("os.access", return_value=False):
                check = doctor.check_output_root(Path(temporary) / "labs")
        self.assertEqual(check.status, FAIL)

    def test_low_disk_space_warns_rather_than_fails(self) -> None:
        usage = mock.Mock(free=1 * 1024**3)
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("shutil.disk_usage", return_value=usage):
                check = doctor.check_output_root(Path(temporary))
        self.assertEqual(check.status, WARN)
        self.assertIn("GiB free", check.detail)

    def test_docker_permission_denied_suggests_the_group(self) -> None:
        completed = mock.Mock(returncode=1, stdout="", stderr="permission denied while connecting")
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), \
             mock.patch.object(doctor, "_run", return_value=completed):
            check = doctor.check_docker_daemon()
        self.assertEqual(check.status, FAIL)
        self.assertIn("usermod -aG docker", check.fix)


class ProviderTests(unittest.TestCase):
    def test_missing_model_fails(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            check = doctor.check_provider_config("openai", None, KEY, None)
        self.assertEqual(check.status, FAIL)
        self.assertIn("no model", check.detail)

    def test_missing_key_fails_and_names_the_variable(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            check = doctor.check_provider_config("anthropic", "a-model", None, None)
        self.assertEqual(check.status, FAIL)
        self.assertIn("ANTHROPIC_API_KEY", check.fix)

    def test_configured_provider_passes_without_echoing_the_key(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            check = doctor.check_provider_config("openai", "a-model", KEY, None)
        self.assertEqual(check.status, OK)
        self.assertNotIn(KEY, check.detail + check.fix)

    def test_local_provider_needs_no_key(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            check = doctor.check_provider_config(
                "local", "a-model", None, "http://127.0.0.1:11434/v1"
            )
        self.assertEqual(check.status, OK)

    def test_rejected_key_is_reported_as_a_failure(self) -> None:
        error = urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=error):
            check = doctor.check_provider_reachable("openai", KEY, None)
        self.assertEqual(check.status, FAIL)
        self.assertIn("401", check.detail)

    def test_unreachable_provider_is_a_failure(self) -> None:
        with mock.patch("urllib.request.urlopen",
                        side_effect=urllib.error.URLError("no route")):
            check = doctor.check_provider_reachable("openai", KEY, None)
        self.assertEqual(check.status, FAIL)
        self.assertIn("could not reach", check.detail)

    def test_reachable_provider_passes(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"{"
        with mock.patch("urllib.request.urlopen", return_value=response):
            check = doctor.check_provider_reachable("openai", KEY, None)
        self.assertEqual(check.status, OK)


class ReportTests(unittest.TestCase):
    def test_a_failure_sets_a_nonzero_exit_code(self) -> None:
        report = Report([Check("a", OK, "fine"), Check("b", FAIL, "broken")])
        self.assertEqual(report.as_dict()["ok"], False)
        self.assertEqual(len(report.failed), 1)

    def test_warnings_alone_keep_the_report_ok(self) -> None:
        report = Report([Check("a", WARN, "slow disk")])
        self.assertEqual(report.as_dict()["ok"], True)
        self.assertEqual(len(report.warned), 1)

    def test_the_report_states_readiness(self) -> None:
        self.assertIn("Ready.", format_report(Report([Check("a", OK, "fine")])))
        self.assertIn("would not get far",
                      format_report(Report([Check("a", FAIL, "broken")])))

    def test_fix_hints_only_appear_for_problems(self) -> None:
        text = format_report(Report([Check("a", OK, "fine", "do not show this")]))
        self.assertNotIn("do not show this", text)

    def test_offline_skips_the_network_check(self) -> None:
        with mock.patch.object(doctor, "check_provider_reachable") as reachable:
            with tempfile.TemporaryDirectory() as temporary:
                doctor.run_doctor(Path(temporary), "openai", "a-model", KEY, None,
                                  offline=True)
        reachable.assert_not_called()

    def test_json_output_is_parseable_and_omits_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = doctor.run_doctor(Path(temporary), "openai", "a-model", KEY, None,
                                       offline=True)
        encoded = json.dumps(report.as_dict())
        self.assertNotIn(KEY, encoded)
        self.assertIn("checks", json.loads(encoded))


if __name__ == "__main__":
    unittest.main()
