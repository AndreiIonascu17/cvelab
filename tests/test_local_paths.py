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

from cvelab import deliverables, upload

CVE = "CVE-2026-0001"


class LocalPathTests(unittest.TestCase):
    """A shared lab must not show where, or as whom, it was generated."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name) / "home" / "alice"
        self.lab = self.home / "labs" / CVE
        (self.lab / "artifacts").mkdir(parents=True)
        patcher = mock.patch("cvelab.upload.Path.home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_manual_guide_names_no_absolute_path(self) -> None:
        deliverables._write_generic_manual_assets(CVE, self.lab, self.lab / "artifacts", False)
        guide = (self.lab / "artifacts" / "MANUAL-POC.md").read_text(encoding="utf-8")
        self.assertIn(f"cd {CVE}/artifacts", guide)
        self.assertNotIn(str(self.home), guide)
        self.assertNotIn("alice", guide)

    def test_lab_directory_becomes_its_name_and_home_becomes_tilde(self) -> None:
        text = (
            f'cd "{self.lab}/artifacts"\n'
            f"validating {self.lab}/docker-compose.yml: services.patched\n"
            f"cache at {self.home}/.cache/pip\n"
        )
        stripped = upload.strip_local_paths(text, self.lab)
        self.assertIn(f'cd "{CVE}/artifacts"', stripped)
        self.assertIn(f"validating {CVE}/docker-compose.yml", stripped)
        self.assertIn("cache at ~/.cache/pip", stripped)
        self.assertNotIn("alice", stripped)

    def test_windows_home_inside_json_text_is_stripped(self) -> None:
        home = "C:\\Users\\alice"
        document = json.dumps({"error": home + "\\labs\\build failed"})
        with mock.patch("cvelab.upload.Path.home", return_value=home):
            stripped = upload.strip_local_paths(document, self.lab)
        self.assertNotIn("alice", stripped)
        self.assertEqual(json.loads(stripped)["error"], "~\\labs\\build failed")

    def test_uploaded_payload_carries_no_local_path(self) -> None:
        artifacts = self.lab / "artifacts"
        (self.lab / "plan.json").write_text(json.dumps({"repository": "https://github.com/acme/widget"}))
        (artifacts / "MANUAL-POC.md").write_text(f'cd "{artifacts}"\nbash manual.sh setup vulnerable\n')
        (artifacts / "EVIDENCE.json").write_text(json.dumps({
            "automation": {"attempts": [{"error": f"Compose preflight failed: validating {self.lab}/docker-compose.yml"}]},
        }))
        (artifacts / "REPORT.md").write_text(f"Built in {self.home}/work\n")
        result = {"ok": False, "cve": CVE, "status": "AUTO_REPAIR_EXHAUSTED",
                  "error": f"Docker stage 'build' failed in {self.lab}"}

        payload = upload.collect(self.lab, result, provider="anthropic", model="m", include_poc=True)

        names = {document["name"] for document in payload["documents"]}
        self.assertTrue({"MANUAL-POC.md", "EVIDENCE.json", "REPORT.md"} <= names)
        serialized = json.dumps(payload)
        self.assertNotIn(str(self.home), serialized)
        self.assertNotIn("alice", serialized)
        self.assertIn(f"validating {CVE}/docker-compose.yml", serialized)
        self.assertEqual(payload["error"], f"Docker stage 'build' failed in {CVE}")


if __name__ == "__main__":
    unittest.main()
