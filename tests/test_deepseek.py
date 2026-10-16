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
import unittest
from unittest import mock

from cvelab import usage
from cvelab.ai import (
    _chat_completions_response,
    provider_supports_web_search,
    resolve_provider,
    structured_response,
)
from cvelab.providers import PROVIDERS, endpoint_for

PROVIDER_KEY_VARIABLE = {p.name: p.key_variable for p in PROVIDERS.values()}

SCHEMA = {"type": "object", "required": ["ok"], "properties": {"ok": {"type": "boolean"}}}


def completion(content: str, **extra) -> dict:
    return {"choices": [{"message": {"content": content}, "finish_reason": "stop"}, ], **extra}


class SelectionTests(unittest.TestCase):
    def test_deepseek_is_a_supported_choice(self) -> None:
        self.assertEqual(resolve_provider("deepseek"), "deepseek")

    def test_its_own_key_variable(self) -> None:
        self.assertEqual(PROVIDER_KEY_VARIABLE["deepseek"], "DEEPSEEK_API_KEY")

    def test_auto_selects_it_when_only_its_key_is_set(self) -> None:
        with mock.patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-x"}, clear=True):
            self.assertEqual(resolve_provider(), "deepseek")

    def test_openai_still_wins_when_both_are_set(self) -> None:
        # Changing which provider an existing setup picks would be a surprise.
        with mock.patch.dict(
            "os.environ", {"DEEPSEEK_API_KEY": "sk-x", "OPENAI_API_KEY": "sk-y"},
            clear=True,
        ):
            self.assertEqual(resolve_provider(), "openai")

    def test_no_web_search(self) -> None:
        # DeepSeek has no web search tool, so source discovery cannot fall
        # back to the model. The OSV resolver covers almost all of that.
        self.assertFalse(provider_supports_web_search("deepseek"))


class RequestTests(unittest.TestCase):
    def setUp(self) -> None:
        usage.reset()

    def call(self, payload: dict, base_url: str | None = None):
        captured = {}

        def fake(provider, url, body, headers, timeout_seconds=180):
            captured.update(provider=provider, url=url, body=body, headers=headers,
                            timeout=timeout_seconds)
            return payload

        with mock.patch("cvelab.ai._request_json", side_effect=fake):
            result = _chat_completions_response(
                "deepseek", "sk-test", base_url, "deepseek-flash",
                "Do the thing.", "the context", SCHEMA, "s", 4096,
            )
        return result, captured

    def test_it_posts_to_the_documented_endpoint(self) -> None:
        _, sent = self.call(completion('{"ok": true}'))
        # Derived, so the test cannot disagree with the registry.
        self.assertEqual(sent["url"], endpoint_for("deepseek"))
        self.assertEqual(sent["headers"]["Authorization"], "Bearer sk-test")

    def test_a_custom_base_url_is_honoured(self) -> None:
        _, sent = self.call(completion('{"ok": true}'),
                            base_url="https://gateway.example/proxy")
        self.assertEqual(sent["url"], "https://gateway.example/proxy/chat/completions")

    def test_it_asks_for_json_object_not_json_schema(self) -> None:
        # DeepSeek documents json_object only. Asking for json_schema first
        # and falling back would spend a rejected request on every call.
        _, sent = self.call(completion('{"ok": true}'))
        self.assertEqual(sent["body"]["response_format"], {"type": "json_object"})

    def test_the_schema_travels_in_the_instructions(self) -> None:
        _, sent = self.call(completion('{"ok": true}'))
        system = sent["body"]["messages"][0]["content"]
        self.assertIn("Do the thing.", system)
        self.assertIn(json.dumps(SCHEMA, ensure_ascii=True), system)

    def test_a_fenced_response_is_still_parsed(self) -> None:
        result, _ = self.call(completion('```json\n{"ok": true}\n```'))
        self.assertEqual(result, {"ok": True})

    def test_an_empty_response_names_the_likely_cause(self) -> None:
        payload = {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}
        with self.assertRaises(RuntimeError) as raised:
            self.call(payload)
        self.assertIn("max_tokens", str(raised.exception))

    def test_no_choices_is_an_error(self) -> None:
        with self.assertRaises(RuntimeError):
            self.call({"choices": []})

    def test_usage_is_recorded_from_the_chat_completions_shape(self) -> None:
        self.call(completion('{"ok": true}', usage={
            "prompt_tokens": 1200, "completion_tokens": 300,
            "prompt_cache_hit_tokens": 900,
        }))
        totals = usage.snapshot()
        self.assertEqual(
            (totals.input_tokens, totals.output_tokens, totals.cached_input_tokens),
            (1200, 300, 900),
        )

    def test_the_model_is_priced(self) -> None:
        self.call(completion('{"ok": true}', usage={
            "prompt_tokens": 1_000_000, "completion_tokens": 1_000_000,
        }))
        # Off-peak: $0.15 in, $0.60 out.
        self.assertAlmostEqual(usage.estimate_cost(), 0.75, places=4)


class RoutingTests(unittest.TestCase):
    def test_structured_response_routes_to_deepseek(self) -> None:
        with mock.patch("cvelab.ai._chat_completions_response",
                        return_value={"ok": True}) as handler:
            structured_response(
                api_key="sk-x", model="deepseek-flash", instructions="i",
                input_text="t", schema=SCHEMA, schema_name="s",
                max_output_tokens=100, provider="deepseek",
            )
        handler.assert_called_once()

    def test_a_missing_key_names_the_right_variable(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(RuntimeError) as raised:
                structured_response(
                    api_key=None, model="deepseek-flash", instructions="i",
                    input_text="t", schema=SCHEMA, schema_name="s",
                    max_output_tokens=100, provider="deepseek",
                )
        self.assertIn("DEEPSEEK_API_KEY", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
