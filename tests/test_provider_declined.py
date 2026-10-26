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

from cvelab import upload
from cvelab.ai import ProviderDeclined, structured_response
from cvelab.autoflow import run_auto_workflow

SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False}


def ask(provider: str, model: str):
    return structured_response(
        api_key="secret-key-for-tests", model=model, provider=provider,
        instructions="test", input_text="input", schema=SCHEMA,
        schema_name="test_schema", max_output_tokens=100,
    )


class DetectionTests(unittest.TestCase):
    def test_anthropic_refusal_is_a_provider_decline(self) -> None:
        payload = {
            "stop_reason": "refusal",
            "stop_details": {"type": "refusal", "category": "cyber", "explanation": "declined by policy"},
            "content": [{"type": "refusal"}],
        }
        with mock.patch("cvelab.ai._request_json", return_value=payload):
            with self.assertRaises(ProviderDeclined) as caught:
                ask("anthropic", "claude-haiku-5-5")
        self.assertEqual(caught.exception.provider, "Anthropic")
        self.assertEqual(caught.exception.model, "claude-haiku-5-5")
        self.assertEqual(caught.exception.detail["category"], "cyber")

    def test_a_chat_completions_refusal_is_a_provider_decline(self) -> None:
        payload = {"choices": [{"message": {"content": None, "refusal": "I can't help with that."}, "finish_reason": "stop"}]}
        with mock.patch("cvelab.ai._request_json", return_value=payload):
            with self.assertRaises(ProviderDeclined) as caught:
                ask("deepseek", "deepseek-flash")
        self.assertIn("can't help", str(caught.exception.detail))

    def test_a_content_filter_stop_is_a_provider_decline(self) -> None:
        payload = {"choices": [{"message": {"content": ""}, "finish_reason": "content_filter"}]}
        with mock.patch("cvelab.ai._request_json", return_value=payload):
            with self.assertRaises(ProviderDeclined):
                ask("deepseek", "deepseek-flash")


class OutcomeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.decline = ProviderDeclined("Anthropic", "claude-haiku-5-5", {"category": "cyber", "explanation": "declined by policy"})

    def run_flow(self, **patches):
        generated = {"ok": True, "status": "GENERATED_UNVALIDATED", "lab_dir": str(self.root / "CVE-2026-12345"), "plan": {}}
        defaults = {
            "generate_source_lab": mock.Mock(return_value=generated),
            "run_lab": mock.Mock(return_value={"ok": False, "report": {"proof_checks": {"vulnerable_confirmed": False}}}),
            "repair_source_lab": mock.Mock(return_value={"ok": True, "plan": {}}),
        }
        defaults.update(patches)
        with (
            mock.patch("cvelab.autoflow.generate_source_lab", defaults["generate_source_lab"]),
            mock.patch("cvelab.autoflow.run_lab", defaults["run_lab"]),
            mock.patch("cvelab.autoflow.repair_source_lab", defaults["repair_source_lab"]),
            mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
        ):
            return run_auto_workflow(
                "CVE-2026-12345", self.root, None, None, None,
                "key", "model", False, max_attempts=4, progress=lambda _: None,
            ), defaults

    def test_a_decline_at_generation_stops_at_once_with_its_own_status(self) -> None:
        result, mocks = self.run_flow(generate_source_lab=mock.Mock(side_effect=self.decline))
        self.assertEqual(result["status"], "PROVIDER_DECLINED")
        self.assertEqual(mocks["generate_source_lab"].call_count, 1)
        self.assertEqual(result["declined"]["provider"], "Anthropic")
        self.assertEqual(result["declined"]["category"], "cyber")
        self.assertIn("does not retry or reword", result["message"])
        recorded = json.loads((self.root / "CVE-2026-12345" / "automation.json").read_text())
        self.assertEqual(recorded["status"], "PROVIDER_DECLINED")

    def test_a_decline_during_a_repair_ends_the_run_the_same_way(self) -> None:
        result, mocks = self.run_flow(repair_source_lab=mock.Mock(side_effect=self.decline))
        self.assertEqual(result["status"], "PROVIDER_DECLINED")
        self.assertEqual(mocks["repair_source_lab"].call_count, 1)
        self.assertEqual(mocks["run_lab"].call_count, 1)

    def test_a_declined_run_uploads_as_declined_not_failed(self) -> None:
        self.assertEqual(upload.STATUS["PROVIDER_DECLINED"], "declined")


if __name__ == "__main__":
    unittest.main()
