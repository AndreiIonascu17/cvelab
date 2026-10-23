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

"""A lab that reads the fix out of the source instead of running it is refused."""

from __future__ import annotations

import unittest

from cvelab.sourcegen import _source_text_reads, _validate_fidelity, _validate_generated

DOCKERFILE = """FROM node:22-bookworm-slim
WORKDIR /opt
COPY source/{side} /opt/source
COPY adapter/harness/server.js /opt/harness/server.js
ENV CVELAB_REVISION={side} SOURCE_ROOT=/opt/source NODE_ENV=production
CMD ["node", "/opt/harness/server.js"]
"""
# The shape of the Electron lab that passed without running Electron.
ELECTRON_HARNESS = """const fs = require('fs');
const path = require('path');
const SOURCE_ROOT = process.env.SOURCE_ROOT || '/opt/source';
function linkInitiatorPreserved() {
  const file = path.join(SOURCE_ROOT, 'lib', 'browser', 'guest-window-manager.ts');
  return fs.readFileSync(file, 'utf8').includes('if (navigate) {');
}
"""


def lab(harness: str, dockerfile: str = DOCKERFILE, harness_path: str = "adapter/harness/server.js") -> list[dict]:
    return [
        {"path": "vulnerable/Dockerfile", "content": dockerfile.format(side="vulnerable")},
        {"path": "patched/Dockerfile", "content": dockerfile.format(side="patched")},
        {"path": harness_path, "content": harness},
    ]


class SourceTextReadTests(unittest.TestCase):
    def test_the_electron_shape_is_found(self) -> None:
        reads = _source_text_reads(lab(ELECTRON_HARNESS))
        self.assertEqual(len(reads), 1)
        self.assertIn("adapter/harness/server.js:6:", reads[0])

    def test_validation_refuses_it_and_says_why(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "reads the vendor source as text instead of running it"):
            _validate_generated(lab(ELECTRON_HARNESS) + REQUIRED)

    def test_a_python_text_read_of_a_literal_source_path_is_found(self) -> None:
        dockerfile = "FROM python:3.13\nCOPY source/{side} /src\nCOPY adapter/app.py /harness/app.py\n"
        harness = "def fixed():\n    return 'escape(' in open('/src/lib/render.py').read()\n"
        self.assertTrue(_source_text_reads(lab(harness, dockerfile, "adapter/app.py")))

    def test_a_shell_grep_of_the_source_is_found(self) -> None:
        dockerfile = "FROM debian\nWORKDIR /work\nCOPY source/{side} src\nCOPY adapter/check.sh /usr/local/bin/check\n"
        harness = "#!/bin/sh\ngrep -q 'bounds check' /work/src/parser.c && echo patched\n"
        self.assertTrue(_source_text_reads(lab(harness, dockerfile, "adapter/check.sh")))

    def test_running_the_source_is_not_a_read(self) -> None:
        harness = (
            "const path = require('path');\n"
            "const lib = require(path.join(process.env.SOURCE_ROOT, 'lib', 'index.js'));\n"
            "lib.render(input);\n"
        )
        self.assertEqual(_source_text_reads(lab(harness)), [])

    def test_an_upstream_fixture_read_as_bytes_is_an_input(self) -> None:
        dockerfile = "FROM python:3.13\nCOPY source/{side} /src\nCOPY adapter/probe.py /probe.py\n"
        harness = "payload = open('/src/tests/resources/crash.pdf', 'rb').read()\nsend(payload)\n"
        self.assertEqual(_source_text_reads(lab(harness, dockerfile, "adapter/probe.py")), [])
        js = "const pdf = fs.readFileSync(path.join(SOURCE_ROOT, 'test', 'x.pdf'));\nsend(pdf);\n"
        self.assertEqual(_source_text_reads(lab(js)), [])

    def test_reading_the_adapters_own_files_beside_the_source_is_fine(self) -> None:
        dockerfile = "FROM node:22\nCOPY source/{side} /app\nCOPY adapter/harness/ /app/harness/\n"
        harness = "const config = JSON.parse(fs.readFileSync('/app/harness/config.json', 'utf8'));\n"
        self.assertEqual(_source_text_reads(lab(harness, dockerfile)), [])

    def test_a_lab_without_a_source_copy_is_not_examined(self) -> None:
        self.assertEqual(_source_text_reads(lab(ELECTRON_HARNESS, "FROM scratch\n")), [])


class FidelityReadNotRunTests(unittest.TestCase):
    def fidelity(self, component: str) -> dict:
        return {
            "execution_level": "source_component", "vendor_product_started": False,
            "exercised_vendor_components": [component], "simulated_components": [], "rationale": "r",
        }

    def test_a_component_read_as_text_is_refused(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "read, not run"):
            _validate_fidelity(self.fidelity(
                "lib/browser/guest-window-manager.ts (read as raw source text to test for the navigate callback)"
            ))

    def test_an_executed_component_is_accepted(self) -> None:
        _validate_fidelity(self.fidelity("pypdf/_doc_common.py PdfDocCommon.get_fields and _check_kids"))


COMPOSE = """services:
  vulnerable:
    build:
      context: .
      dockerfile: vulnerable/Dockerfile
  patched:
    build:
      context: .
      dockerfile: patched/Dockerfile
  validator:
    build:
      context: ./validator
      dockerfile: Dockerfile
networks:
  labnet:
    internal: true
"""
VALIDATOR = " ".join([
    "attack_executed", "proof_quality", "observable_effect", "evidence_type", "vulnerable",
    "patched", "differential_confirmed", "confirmed", "blocked", "CVELAB_MANUAL_ACTION",
    "CVELAB_TARGET", "exploit", "verify",
])
REQUIRED = [
    {"path": "docker-compose.yml", "content": COMPOSE},
    {"path": "validator/Dockerfile", "content": "FROM scratch\n"},
    {"path": "validator/validator.py", "content": VALIDATOR},
]


if __name__ == "__main__":
    unittest.main()
