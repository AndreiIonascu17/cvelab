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

import tempfile
import unittest
from pathlib import Path

from cvelab.sourcegen import _check_build_inputs

COMPOSE = """services:
  vulnerable:
    build:
      context: .
      dockerfile: vulnerable/Dockerfile
    image: lab-vulnerable:local
    networks: [lab]
  patched:
    build:
      context: .
      dockerfile: patched/Dockerfile
    image: lab-patched:local
    networks: [lab]
  validator:
    build:
      context: ./validator
      dockerfile: Dockerfile
    networks: [lab]
networks:
  lab:
    internal: true
"""

TARGET = """FROM python:3.12-slim AS build
COPY source/{variant}/ /opt/vendor/
RUN pip install /opt/vendor
FROM python:3.12-slim
COPY --from=build /usr/local /usr/local
COPY ["adapter/app/server.py", "/opt/app/server.py"]
COPY adapter/app/*.py /opt/app/
ENV CVELAB_REVISION={variant}
CMD ["python", "/opt/app/server.py"]
"""

VALIDATOR = "FROM python:3.12-slim\nCOPY validator.py /opt/validator.py\nCMD [\"python\", \"/opt/validator.py\"]\n"


class LabPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.lab = Path(temporary.name) / "CVE-2026-0001"
        for variant in ("vulnerable", "patched"):
            (self.lab / "source" / variant).mkdir(parents=True)
            (self.lab / "source" / variant / "setup.py").write_text("")

    def files(self, **overrides: str) -> list[dict]:
        files = {
            "docker-compose.yml": COMPOSE,
            "vulnerable/Dockerfile": TARGET.format(variant="vulnerable"),
            "patched/Dockerfile": TARGET.format(variant="patched"),
            "validator/Dockerfile": VALIDATOR,
            "validator/validator.py": "print('probe')\n",
            "adapter/app/server.py": "import os\nREVISION = os.environ.get('CVELAB_REVISION')\nprint({'revision': REVISION})\n",
        }
        files.update(overrides)
        return [{"path": path, "content": content} for path, content in files.items() if content is not None]

    def refused(self, files: list[dict], vulnerable_only: bool = False) -> str:
        with self.assertRaises(RuntimeError) as caught:
            _check_build_inputs(files, self.lab, vulnerable_only=vulnerable_only)
        return str(caught.exception)

    def test_a_well_formed_lab_passes(self) -> None:
        # Snapshot copies, a JSON-form COPY, a glob, --from and a revision label.
        _check_build_inputs(self.files(), self.lab)

    def test_validator_copying_the_adapter_is_refused_with_its_context(self) -> None:
        message = self.refused(self.files(**{
            "validator/Dockerfile": VALIDATOR + "COPY adapter/probe.ts /opt/probe.ts\n",
        }))
        self.assertIn("validator/Dockerfile copies adapter/probe.ts", message)
        self.assertIn("built from validator/ alone", message)

    def test_copy_of_a_file_the_answer_lacks_names_the_closest_one(self) -> None:
        target = TARGET.replace("adapter/app/server.py", "adapter/app/serve.py")
        message = self.refused(self.files(**{
            "vulnerable/Dockerfile": target.format(variant="vulnerable"),
            "patched/Dockerfile": target.format(variant="patched"),
        }))
        self.assertIn("vulnerable/Dockerfile copies adapter/app/serve.py, which does not exist", message)
        self.assertIn("closest file in this answer is adapter/app/server.py", message)

    def test_a_stale_adapter_file_on_disk_does_not_count(self) -> None:
        (self.lab / "adapter" / "old").mkdir(parents=True)
        (self.lab / "adapter" / "old" / "helper.js").write_text("")
        target = TARGET + "COPY adapter/old/helper.js /opt/app/\n"
        message = self.refused(self.files(**{
            "vulnerable/Dockerfile": target.format(variant="vulnerable"),
            "patched/Dockerfile": target.format(variant="patched"),
        }))
        self.assertIn("adapter/old/helper.js", message)

    def test_a_missing_snapshot_path_is_refused(self) -> None:
        target = TARGET.replace("COPY source/{variant}/ ", "COPY source/{variant}/pnpm-lock.yaml ")
        message = self.refused(self.files(**{
            "vulnerable/Dockerfile": target.format(variant="vulnerable"),
            "patched/Dockerfile": target.format(variant="patched"),
        }))
        self.assertIn("source/vulnerable/pnpm-lock.yaml", message)

    def test_copying_the_whole_lab_into_a_target_is_refused(self) -> None:
        target = TARGET.replace("COPY source/{variant}/ /opt/vendor/", "COPY . /src")
        message = self.refused(self.files(**{
            "vulnerable/Dockerfile": target.format(variant="vulnerable"),
            "patched/Dockerfile": target.format(variant="patched"),
        }))
        self.assertIn("vulnerable/Dockerfile copies ., the whole lab directory", message)
        self.assertIn("Copy source/vulnerable/", message)

    def test_variants_configured_differently_are_refused(self) -> None:
        message = self.refused(self.files(**{
            "vulnerable/Dockerfile": TARGET.format(variant="vulnerable") + "ENV MODE=unsafe\n",
            "patched/Dockerfile": TARGET.format(variant="patched") + "ENV MODE=safe\n",
        }))
        self.assertIn("may differ only in the source snapshot", message)
        self.assertIn("MODE=unsafe", message)

    def test_compose_environment_that_differs_is_refused(self) -> None:
        compose = COMPOSE.replace(
            "    image: lab-patched:local\n",
            "    image: lab-patched:local\n    environment:\n      CHECK_FIX: \"1\"\n",
        ).replace(
            "    image: lab-vulnerable:local\n",
            "    image: lab-vulnerable:local\n    environment:\n      CHECK_FIX: \"0\"\n",
        )
        message = self.refused(self.files(**{"docker-compose.yml": compose}))
        self.assertIn("Compose services may differ only", message)

    def test_versions_and_the_fix_parent_are_allowed(self) -> None:
        def target(spec: str) -> str:
            return (
                "FROM node:22-alpine\n"
                f"RUN npm install lodash@{spec} && git checkout \"$REF\"{'~1' if spec.endswith('21') else ''}\n"
                "COPY adapter/app/server.py /opt/app/server.py\n"
            )
        _check_build_inputs(self.files(**{
            "vulnerable/Dockerfile": target("4.17.21"),
            "patched/Dockerfile": target("4.17.23"),
        }), self.lab)

    def test_an_adapter_that_branches_on_the_variant_is_refused(self) -> None:
        message = self.refused(self.files(**{
            "adapter/app/server.py": "import os\nif os.environ['CVELAB_REVISION'] == 'vulnerable':\n    leak()\n",
        }))
        self.assertIn("adapter/app/server.py compares against the variant name 'vulnerable'", message)

    def test_a_javascript_role_switch_is_refused(self) -> None:
        message = self.refused(self.files(**{
            "adapter/app/server.py": "const ROLE = process.env.ROLE\nif (ROLE === 'vulnerable') { leak() }\n",
        }))
        self.assertIn("compares against the variant name", message)

    def test_a_vulnerable_only_lab_skips_the_parity_check(self) -> None:
        files = [item for item in self.files(**{
            "vulnerable/Dockerfile": TARGET.format(variant="vulnerable") + "ENV MODE=unsafe\n",
        }) if item["path"] != "patched/Dockerfile"]
        _check_build_inputs(files, self.lab, vulnerable_only=True)


if __name__ == "__main__":
    unittest.main()
