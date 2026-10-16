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
from pathlib import Path
from unittest import mock

from cvelab import core
from cvelab.core import (
    MINIMUM_SECRET_LENGTH,
    redact,
    register_environment_secrets,
    register_secret,
    write_text,
)
from cvelab.providers import PROVIDERS

SENTINEL = "sk-cvelabTESTkey0000000000000000000000000000"  # pragma: allowlist secret


class SecretRedactionTests(unittest.TestCase):
    """A provider key must never reach a file or a stream.

    Generated lab directories are what users attach to bug reports, and
    automation.json stores provider errors verbatim so a failed run can be
    diagnosed. A gateway that echoes the request in its error body would
    otherwise write the key straight into that file.
    """

    def setUp(self) -> None:
        self._saved = set(core._SECRETS)
        core._SECRETS.clear()

    def tearDown(self) -> None:
        core._SECRETS.clear()
        core._SECRETS.update(self._saved)

    def test_registered_key_is_removed_from_written_files(self) -> None:
        register_secret(SENTINEL)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "nested" / "automation.json"
            write_text(
                target,
                json.dumps(
                    {
                        "kind": "generation_error",
                        "error": f"401 from provider: Authorization: Bearer {SENTINEL}",
                    }
                ),
            )
            written = target.read_text(encoding="utf-8")
        self.assertNotIn(SENTINEL, written)
        self.assertIn("[REDACTED]", written)
        # Still parseable: a redacted file must stay useful for diagnosis.
        self.assertEqual(json.loads(written)["kind"], "generation_error")

    def test_every_generated_artifact_is_scanned(self) -> None:
        register_secret(SENTINEL)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (
                "automation.json",
                "report.json",
                "artifacts/EVIDENCE.json",
                "artifacts/REPORT.md",
                "artifacts/WALKTHROUGH.md",
                "artifacts/manual.sh",
                "validator/validator.py",
                "docker-compose.yml",
            ):
                write_text(root / name, f"before {SENTINEL} after\n")
            leaked = [
                str(path.relative_to(root))
                for path in root.rglob("*")
                if path.is_file() and SENTINEL in path.read_text(encoding="utf-8")
            ]
        self.assertEqual(leaked, [], f"the key reached disk in: {leaked}")

    def test_environment_keys_are_registered(self) -> None:
        # Derived from the registry, not listed here: this test named three
        # variables by hand and so agreed with the bug it was meant to catch
        # when DeepSeek was added and its key variable went unregistered.
        for variable in sorted(p.key_variable for p in PROVIDERS.values()):
            with self.subTest(variable=variable):
                core._SECRETS.clear()
                with mock.patch.dict("os.environ", {variable: SENTINEL}, clear=False):
                    register_environment_secrets()
                self.assertNotIn(SENTINEL, redact(f"leaked {SENTINEL}"))

    def test_short_values_are_not_registered(self) -> None:
        # Redacting a short string would mangle ordinary text instead of
        # protecting anything.
        register_secret("abc")
        register_secret("x" * (MINIMUM_SECRET_LENGTH - 1))
        self.assertEqual(redact("abc and xxxxxxxxxxx stay"), "abc and xxxxxxxxxxx stay")

    def test_none_and_empty_are_ignored(self) -> None:
        register_secret(None)
        register_secret("")
        self.assertEqual(redact("unchanged text"), "unchanged text")

    def test_redaction_is_not_vacuous(self) -> None:
        # Without registration the sentinel survives, so the assertions above
        # are testing the mechanism rather than an empty search.
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "unregistered.json"
            write_text(target, f"value {SENTINEL}")
            self.assertIn(SENTINEL, target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
