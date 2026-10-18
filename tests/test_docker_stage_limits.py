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

"""Bounds on the part of a run that executes untrusted code.

The lab runtime is capped in the Compose file. The build was not, and it
is the phase that runs `npm install`, `cargo build` and `pip install`
against whatever the upstream dependency tree says. A Docker stage also
had no deadline at all, so a hung build held a serial queue forever.
"""

from __future__ import annotations

import subprocess
import unittest
import unittest.mock as mock
from pathlib import Path

from cvelab.core import (
    DEFAULT_BUILD_MEMORY,
    DEFAULT_STAGE_TIMEOUT,
    build_limits,
    run_docker_stage,
    stage_timeout,
)


class StageTimeoutTests(unittest.TestCase):
    def test_there_is_a_default_ceiling(self) -> None:
        self.assertGreater(DEFAULT_STAGE_TIMEOUT, 0)
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(stage_timeout(), DEFAULT_STAGE_TIMEOUT)

    def test_it_is_generous_enough_to_compile_something(self) -> None:
        # Two source trees and a Rust harness are real work; a tight
        # default would fail honest labs rather than bound broken ones.
        self.assertGreaterEqual(DEFAULT_STAGE_TIMEOUT, 600)

    def test_the_environment_overrides_it(self) -> None:
        with mock.patch.dict("os.environ", {"CVELAB_STAGE_TIMEOUT": "90"}):
            self.assertEqual(stage_timeout(), 90)

    def test_nonsense_is_refused_rather_than_ignored(self) -> None:
        for bad in ("soon", "0", "-5"):
            with self.subTest(value=bad):
                with mock.patch.dict("os.environ", {"CVELAB_STAGE_TIMEOUT": bad}):
                    with self.assertRaises(ValueError):
                        stage_timeout()

    def test_a_stage_that_overruns_is_stopped_and_says_so(self) -> None:
        with mock.patch.dict("os.environ", {"CVELAB_STAGE_TIMEOUT": "1"}):
            with self.assertRaises(RuntimeError) as raised:
                run_docker_stage(
                    ["sleep", "30"],
                    stage="build",
                    docker="docker",
                    environment={},
                    cwd=Path.cwd(),
                )
        message = str(raised.exception)
        self.assertIn("exceeded 1s", message)
        self.assertIn("CVELAB_STAGE_TIMEOUT", message)

    def test_the_timeout_is_passed_to_the_subprocess(self) -> None:
        completed = subprocess.CompletedProcess(["x"], 0, "", "")
        with mock.patch.dict("os.environ", {"CVELAB_STAGE_TIMEOUT": "123"}):
            with mock.patch("subprocess.run", return_value=completed) as run:
                run_docker_stage(
                    ["true"], stage="build", docker="docker",
                    environment={}, cwd=Path.cwd(),
                )
        self.assertEqual(run.call_args.kwargs["timeout"], 123)


class BuildLimitTests(unittest.TestCase):
    def test_memory_is_bounded_by_default(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(build_limits(), ["--memory", DEFAULT_BUILD_MEMORY])

    def test_the_environment_overrides_it(self) -> None:
        with mock.patch.dict("os.environ", {"CVELAB_BUILD_MEMORY": "8g"}):
            self.assertEqual(build_limits(), ["--memory", "8g"])

    def test_an_empty_value_removes_the_limit(self) -> None:
        with mock.patch.dict("os.environ", {"CVELAB_BUILD_MEMORY": ""}):
            self.assertEqual(build_limits(), [])

    def test_no_cpus_flag_is_passed(self) -> None:
        # `docker compose build` has -m/--memory and no --cpus. Passing it
        # fails every build with "unknown flag", which was checked against
        # the installed Compose rather than assumed.
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertNotIn("--cpus", build_limits())

    def test_the_build_call_site_uses_them(self) -> None:
        source = (
            Path(__file__).resolve().parent.parent / "cvelab" / "core.py"
        ).read_text(encoding="utf-8")
        self.assertRegex(source, r'compose \+ \["build", \*build_limits\(\)')


class ComposeVersionTests(unittest.TestCase):
    """Compose v2 ignores a top-level `version:` and warns about it.

    That warning is the first line of every error the file produces,
    including the ones a repair attempt has to read.
    """

    def without_version(self, content: str) -> str:
        from cvelab.sourcegen import _without_compose_version

        return _without_compose_version(content)

    def test_the_obsolete_key_is_dropped(self) -> None:
        self.assertEqual(
            self.without_version('version: "3.9"\nservices:\n  x:\n    build: .\n'),
            "services:\n  x:\n    build: .\n",
        )

    def test_an_unquoted_version_is_dropped_too(self) -> None:
        self.assertNotIn("version", self.without_version("version: 3\nservices:\n"))

    def test_nothing_else_is_touched(self) -> None:
        kept = "services:\n  x:\n    environment:\n      VERSION: 3\n"
        self.assertEqual(self.without_version(kept), kept)

    def test_a_nested_version_key_survives(self) -> None:
        kept = "services:\n  x:\n    labels:\n      version: 2\n"
        self.assertEqual(self.without_version(kept), kept)


class PathRemedyTests(unittest.TestCase):
    """Refusing a path without saying where the file belongs cost attempts.

    server.js twice, exploit.py, server.rb and harness/Cargo.toml -- three
    ecosystems, two models, and once the fifth reproduction of a benchmark
    run, because the repair had nothing to aim at.
    """

    def remedy(self, path: str) -> str:
        from cvelab.sourcegen import _path_remedy

        return _path_remedy(path)

    def test_a_root_file_is_pointed_at_the_adapter(self) -> None:
        for path in ("server.js", "exploit.py", "server.rb"):
            with self.subTest(path=path):
                self.assertIn(f"adapter/{path}", self.remedy(path))

    def test_a_root_directory_is_pointed_at_the_adapter(self) -> None:
        self.assertIn("adapter/harness/Cargo.toml", self.remedy("harness/Cargo.toml"))

    def test_escaping_is_named_as_escaping(self) -> None:
        self.assertIn("climb out", self.remedy("../etc/passwd"))
        self.assertIn("relative", self.remedy("/etc/passwd"))

    def test_the_refusal_lists_what_is_writable(self) -> None:
        source = (
            Path(__file__).resolve().parent.parent / "cvelab" / "sourcegen.py"
        ).read_text(encoding="utf-8")
        self.assertIn("The only writable paths are", source)
        self.assertNotIn("Unsafe generated path rejected", source)


if __name__ == "__main__":
    unittest.main()
