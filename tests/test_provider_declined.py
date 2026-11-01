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
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import ai, upload, usage
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


class FallbackModelTests(unittest.TestCase):
    """A declined request may be asked again on another model, never reworded.

    Every decline CVELab has recorded -- seven -- came back under the
    category "cyber", which the provider documents as one that "benign
    cybersecurity work can also trigger". Its guidance for integrators is
    that the same request sent to another model usually gets an answer, and
    Claude Haiku has no server-side fallback, so the retry is the client's
    to make. It stays off unless a model is named, because a decline a
    fallback answered is not the same measurement as a run never declined.
    """

    def setUp(self) -> None:
        usage.reset()

    def _ask(self, answers: list[object], fallback: str | None) -> tuple[Any, list[str]]:
        asked: list[str] = []

        def anthropic(key, model, instructions, text, schema, budget, tools, seconds):
            asked.append(model)
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        environment = {"CVELAB_FALLBACK_MODEL": fallback} if fallback else {}
        with mock.patch.dict(os.environ, environment, clear=False), \
             mock.patch.object(ai, "_anthropic_response", anthropic):
            if not fallback:
                os.environ.pop("CVELAB_FALLBACK_MODEL", None)
            try:
                return ai.structured_response(
                    api_key="k", model="claude-haiku-5-5", provider="anthropic",
                    instructions="i", input_text="t",
                    schema={"type": "object", "properties": {}, "required": []},
                    schema_name="s", max_output_tokens=100,
                ), asked
            except ai.ProviderDeclined:
                return None, asked

    def _declined(self) -> ai.ProviderDeclined:
        return ai.ProviderDeclined(
            "Anthropic", "claude-haiku-5-5",
            {"type": "refusal", "category": "cyber", "explanation": "..."},
        )

    def test_without_one_configured_the_decline_stands(self) -> None:
        answered, asked = self._ask([self._declined()], fallback=None)
        self.assertIsNone(answered)
        self.assertEqual(asked, ["claude-haiku-5-5"])

    def test_with_one_configured_the_same_request_goes_to_it(self) -> None:
        answered, asked = self._ask(
            [self._declined(), {}], fallback="claude-sonnet-5-5"
        )
        self.assertEqual(answered, {})
        self.assertEqual(asked, ["claude-haiku-5-5", "claude-sonnet-5-5"])

    def test_a_fallback_that_also_declines_is_the_answer(self) -> None:
        answered, asked = self._ask(
            [self._declined(), self._declined()], fallback="claude-sonnet-5-5"
        )
        self.assertIsNone(answered)
        self.assertEqual(len(asked), 2)

    def test_the_same_model_is_not_asked_twice(self) -> None:
        answered, asked = self._ask([self._declined()], fallback="claude-haiku-5-5")
        self.assertIsNone(answered)
        self.assertEqual(asked, ["claude-haiku-5-5"])

    def test_the_decline_is_counted_whether_or_not_it_was_answered(self) -> None:
        self._ask([self._declined(), {}], fallback="claude-sonnet-5-5")
        self.assertEqual(usage.as_dict()["declines"], ["cyber"])

    def test_the_category_travels_with_the_refusal(self) -> None:
        self.assertEqual(self._declined().category, "cyber")
        self.assertIsNone(
            ai.ProviderDeclined("Anthropic", "m", "a string instead").category
        )

    def test_a_run_with_no_decline_says_nothing_about_declines(self) -> None:
        self._ask([{}], fallback=None)
        self.assertNotIn("declines", usage.as_dict())
