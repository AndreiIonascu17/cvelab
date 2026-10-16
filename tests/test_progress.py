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

import io
import unittest
import unittest.mock
from contextlib import redirect_stderr

from cvelab import progress


class ProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = progress._reporter
        self.seen: list[str] = []
        progress.set_reporter(self.seen.append)

    def tearDown(self) -> None:
        progress.set_reporter(self._saved)

    def test_step_reaches_the_reporter(self) -> None:
        progress.step("cloning")
        self.assertEqual(self.seen, ["cloning"])

    def test_silence_stops_reporting(self) -> None:
        progress.silence()
        progress.step("should not appear")
        self.assertEqual(self.seen, [])

    def test_stage_announces_its_start(self) -> None:
        with progress.stage("building lab images"):
            pass
        self.assertEqual(self.seen[0], "building lab images...")

    def test_fast_stage_does_not_report_a_duration(self) -> None:
        # A duration on an instant operation is noise, not information.
        with progress.stage("quick"):
            pass
        self.assertEqual(self.seen, ["quick..."])

    def test_slow_stage_reports_its_duration(self) -> None:
        with unittest.mock.patch.object(progress.stage, "REPORT_AFTER_SECONDS", -1):
            with progress.stage("slow"):
                pass
        self.assertEqual(len(self.seen), 2)
        self.assertIn("done in", self.seen[1])

    def test_failure_is_reported_and_the_exception_propagates(self) -> None:
        with self.assertRaises(RuntimeError):
            with progress.stage("cloning"):
                raise RuntimeError("network down")
        self.assertIn("failed after", self.seen[1])

    def test_default_reporter_writes_to_stderr(self) -> None:
        progress.set_reporter(progress._write)
        stream = io.StringIO()
        with redirect_stderr(stream):
            progress.step("on stderr")
        self.assertEqual(stream.getvalue().strip(), "[cvelab] on stderr")


if __name__ == "__main__":
    unittest.main()
