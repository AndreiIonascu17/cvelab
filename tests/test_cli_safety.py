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

"""What the command line does around a run: signals, keys, containers."""

from __future__ import annotations

import io
import json
import signal
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from cvelab import cli

POSIX = hasattr(signal, "SIGHUP")


@unittest.skipUnless(POSIX, "POSIX signals")
class TerminationTests(unittest.TestCase):
    """SIGTERM and SIGHUP used to end the process without its teardown.

    A closed terminal, systemd stopping a unit or a parent's timeout left
    the lab's containers running, because only a `finally` stopped them.
    """

    def run_with(self, fake_run_lab) -> int:
        with mock.patch.object(cli, "run_lab", side_effect=fake_run_lab), \
                mock.patch.object(cli, "create_deliverables") as deliver, \
                redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            code = cli.main(["run", "CVE-2026-0001", "--no-upload"])
        deliver.assert_not_called()
        return code

    def test_sigterm_runs_the_teardown_and_exits_143(self) -> None:
        events = []

        def fake_run_lab(*_args):
            try:
                try:
                    signal.raise_signal(signal.SIGTERM)
                    time.sleep(5)
                except Exception:
                    # A retry loop must not mistake the signal for a failure.
                    events.append("swallowed")
            finally:
                events.append("teardown")

        self.assertEqual(self.run_with(fake_run_lab), 128 + signal.SIGTERM)
        self.assertEqual(events, ["teardown"])

    def test_sighup_exits_129(self) -> None:
        def fake_run_lab(*_args):
            signal.raise_signal(signal.SIGHUP)
            time.sleep(5)

        self.assertEqual(self.run_with(fake_run_lab), 128 + signal.SIGHUP)

    def test_a_second_signal_does_not_interrupt_the_teardown(self) -> None:
        events = []

        def fake_run_lab(*_args):
            try:
                signal.raise_signal(signal.SIGTERM)
                time.sleep(5)
            finally:
                signal.raise_signal(signal.SIGTERM)
                events.append("teardown finished")

        self.assertEqual(self.run_with(fake_run_lab), 128 + signal.SIGTERM)
        self.assertEqual(events, ["teardown finished"])

    def test_an_ignored_hangup_stays_ignored(self) -> None:
        # nohup ignores SIGHUP so a run survives the terminal closing.
        previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
        self.addCleanup(signal.signal, signal.SIGHUP, previous)
        observed = []

        def fake_run_lab(*_args):
            observed.append(signal.getsignal(signal.SIGHUP))
            return {"ok": True}

        with mock.patch.object(cli, "run_lab", side_effect=fake_run_lab), \
                mock.patch.object(cli, "create_deliverables", return_value={"ok": True}), \
                redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            cli.main(["run", "CVE-2026-0001", "--no-upload"])
        self.assertEqual(observed, [signal.SIG_IGN])

    def test_the_previous_handlers_are_restored(self) -> None:
        before = signal.getsignal(signal.SIGTERM)
        with mock.patch.object(cli, "doctor_command", return_value=0), redirect_stdout(io.StringIO()):
            cli.main(["doctor", "--offline"])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)


class KeyOnCommandLineTests(unittest.TestCase):
    def run_doctor(self, argv: list[str]) -> str:
        stderr = io.StringIO()
        with mock.patch.object(cli, "doctor_command", return_value=0), \
                mock.patch("getpass.getpass", return_value="sk-typed-0000000000"), \
                redirect_stderr(stderr):
            cli.main(argv)
        return stderr.getvalue()

    def test_a_key_value_on_the_command_line_is_warned_about(self) -> None:
        warning = self.run_doctor(
            ["doctor", "--offline", "--provider", "anthropic", "--model", "m", "--key", "sk-visible-0000000000"]
        )
        self.assertIn("process list", warning)
        self.assertIn("ANTHROPIC_API_KEY", warning)
        self.assertNotIn("sk-visible", warning)

    def test_the_prompt_is_not_warned_about(self) -> None:
        self.assertEqual(self.run_doctor(["doctor", "--offline", "--model", "m", "--key"]), "")


class ClosedContainerLimitTests(unittest.TestCase):
    """The closed workflow runs a user's or a model's image: it gets the same ceilings."""

    def test_every_container_is_bounded(self) -> None:
        from cvelab import closed

        calls = []

        def docker(*args, check=True):
            calls.append(args)
            if args[:2] == ("run", "--rm"):
                return json.dumps({"status": 200, "headers": {}, "body": "ok"})
            return "id"

        contract = {"attack": [{"path": "/"}], "observe": {"request": {"path": "/"}, "match": {"status": 200}}}
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch.object(closed, "_docker", side_effect=docker):
            closed._run_variant("CVE-2026-0001", "vulnerable", "image:tag", 80, "/", contract)
        runs = [args for args in calls if args[0] == "run"]
        self.assertGreaterEqual(len(runs), 2)
        for args in runs:
            with self.subTest(args=args[:3]):
                self.assertIn("no-new-privileges:true", args)
                self.assertIn("--memory", args)
                self.assertIn("--pids-limit", args)
                self.assertIn("--cpu-quota", args)


if __name__ == "__main__":
    unittest.main()
