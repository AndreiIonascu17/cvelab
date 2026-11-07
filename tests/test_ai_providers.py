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
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from cvelab.ai import (
    AIHTTPError,
    _anthropic_compatible_schema,
    resolve_provider,
    structured_response,
)

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok"],
    "properties": {"ok": {"type": "boolean"}},
}


class AIProviderTests(unittest.TestCase):
    def test_local_provider_over_real_loopback_http(self) -> None:
        observed = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                observed["path"] = self.path
                observed["body"] = json.loads(self.rfile.read(length))
                response = json.dumps({
                    "choices": [{"message": {"content": '{"ok":true}'}}]
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = structured_response(
                api_key=None,
                model="loopback-model",
                provider="local",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                instructions="test",
                input_text="input",
                schema=SCHEMA,
                schema_name="test_schema",
                max_output_tokens=100,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result, {"ok": True})
        self.assertEqual(observed["path"], "/v1/chat/completions")
        self.assertEqual(observed["body"]["model"], "loopback-model")

    def test_openai_uses_responses_structured_output(self) -> None:
        payload = {
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": '{"ok":true}'}],
            }]
        }
        with mock.patch("cvelab.ai._request_json", return_value=payload) as request:
            result = structured_response(
                api_key="secret",
                model="test-model",
                provider="openai",
                instructions="test",
                input_text="input",
                schema=SCHEMA,
                schema_name="test_schema",
                max_output_tokens=100,
            )

        self.assertEqual(result, {"ok": True})
        provider, url, body, headers = request.call_args.args
        self.assertEqual(provider, "OpenAI")
        self.assertEqual(url, "https://api.openai.com/v1/responses")
        self.assertEqual(body["text"]["format"]["schema"], SCHEMA)
        self.assertEqual(headers["Authorization"], "Bearer secret")

    def test_anthropic_uses_messages_output_config_and_web_search(self) -> None:
        payload = {"content": [{"type": "text", "text": '{"ok":true}'}]}
        with mock.patch("cvelab.ai._request_json", return_value=payload) as request:
            result = structured_response(
                api_key="secret",
                model="claude-test",
                provider="anthropic",
                instructions="test",
                input_text="input",
                schema=SCHEMA,
                schema_name="test_schema",
                max_output_tokens=100,
                tools=[{"type": "web_search"}],
            )

        self.assertEqual(result, {"ok": True})
        provider, url, body, headers = request.call_args.args
        self.assertEqual(provider, "Anthropic")
        self.assertEqual(url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(body["output_config"]["format"]["schema"], SCHEMA)
        self.assertEqual(body["output_config"]["effort"], "low")
        self.assertEqual(body["tools"][0]["type"], "web_search_20250305")
        self.assertEqual(headers["x-api-key"], "secret")

    def test_anthropic_reports_max_tokens_with_diagnostics(self) -> None:
        payload = {
            "stop_reason": "max_tokens",
            "usage": {"output_tokens": 100},
            "content": [{"type": "thinking", "thinking": ""}],
        }
        with mock.patch("cvelab.ai._request_json", return_value=payload):
            with self.assertRaisesRegex(RuntimeError, "output_tokens=100"):
                structured_response(
                    api_key="secret",
                    model="claude-opus-5",
                    provider="anthropic",
                    instructions="test",
                    input_text="input",
                    schema=SCHEMA,
                    schema_name="test_schema",
                    max_output_tokens=100,
                )

    def test_anthropic_reports_refusal_without_exposing_thinking(self) -> None:
        payload = {
            "stop_reason": "refusal",
            "stop_details": {"type": "refusal", "category": "cyber"},
            "content": [{"type": "refusal", "explanation": "Request declined"}],
        }
        with mock.patch("cvelab.ai._request_json", return_value=payload):
            with self.assertRaisesRegex(RuntimeError, "category.*cyber"):
                structured_response(
                    api_key="secret",
                    model="claude-opus-5",
                    provider="anthropic",
                    instructions="test",
                    input_text="input",
                    schema=SCHEMA,
                    schema_name="test_schema",
                    max_output_tokens=100,
                )

    def test_anthropic_schema_removes_unsupported_constraints(self) -> None:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["confidence", "names"],
            "properties": {
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "names": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 5,
                    "items": {"type": "string", "minLength": 1},
                },
            },
        }

        compatible = _anthropic_compatible_schema(schema)

        confidence = compatible["properties"]["confidence"]
        names = compatible["properties"]["names"]
        self.assertNotIn("minimum", confidence)
        self.assertNotIn("maximum", confidence)
        self.assertNotIn("minItems", names)
        self.assertNotIn("maxItems", names)
        self.assertNotIn("minLength", names["items"])
        self.assertIn("minimum=0", confidence["description"])
        self.assertEqual(schema["properties"]["confidence"]["minimum"], 0)

    def test_local_uses_openai_compatible_endpoint_without_key(self) -> None:
        payload = {"choices": [{"message": {"content": '{"ok":true}'}}]}
        with mock.patch("cvelab.ai._request_json", return_value=payload) as request:
            result = structured_response(
                api_key=None,
                model="qwen-local",
                provider="local",
                base_url="http://127.0.0.1:8000/v1",
                instructions="test",
                input_text="input",
                schema=SCHEMA,
                schema_name="test_schema",
                max_output_tokens=100,
            )

        self.assertEqual(result, {"ok": True})
        provider, url, body, headers = request.call_args.args
        self.assertEqual(provider, "Local")
        self.assertEqual(url, "http://127.0.0.1:8000/v1/chat/completions")
        self.assertEqual(body["response_format"]["type"], "json_schema")
        self.assertEqual(headers, {})
        self.assertEqual(request.call_args.kwargs["timeout_seconds"], 1800)

    def test_local_timeout_can_be_configured(self) -> None:
        payload = {"choices": [{"message": {"content": '{"ok":true}'}}]}
        with mock.patch.dict("os.environ", {"CVELAB_LOCAL_TIMEOUT": "600"}):
            with mock.patch("cvelab.ai._request_json", return_value=payload) as request:
                structured_response(
                    api_key=None,
                    model="local-model",
                    provider="local",
                    instructions="test",
                    input_text="input",
                    schema=SCHEMA,
                    schema_name="test_schema",
                    max_output_tokens=100,
                )

        self.assertEqual(request.call_args.kwargs["timeout_seconds"], 600)

    def test_local_falls_back_to_json_object(self) -> None:
        payload = {"choices": [{"message": {"content": '{"ok":true}'}}]}
        with mock.patch(
            "cvelab.ai._request_json",
            side_effect=[AIHTTPError("Local", 400, "unsupported format"), payload],
        ) as request:
            result = structured_response(
                api_key=None,
                model="local-model",
                provider="local",
                instructions="test",
                input_text="input",
                schema=SCHEMA,
                schema_name="test_schema",
                max_output_tokens=100,
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(request.call_count, 2)
        fallback_body = request.call_args.args[2]
        self.assertEqual(fallback_body["response_format"], {"type": "json_object"})

    def test_schema_is_validated_for_local_models(self) -> None:
        payload = {"choices": [{"message": {"content": '{"ok":"yes"}'}}]}
        with mock.patch("cvelab.ai._request_json", return_value=payload):
            with self.assertRaisesRegex(RuntimeError, "invalid type"):
                structured_response(
                    api_key=None,
                    model="local-model",
                    provider="local",
                    instructions="test",
                    input_text="input",
                    schema=SCHEMA,
                    schema_name="test_schema",
                    max_output_tokens=100,
                )

    def test_auto_provider_prefers_anthropic_when_it_is_the_only_key(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"ANTHROPIC_API_KEY": "secret", "OPENAI_API_KEY": "", "CVELAB_BASE_URL": ""},
        ):
            self.assertEqual(resolve_provider("auto"), "anthropic")


class AFieldNameIsNotAConstraintTests(unittest.TestCase):
    """The constraint keywords and the answer's own field names share one
    namespace in JSON Schema; only position tells them apart.

    Measured: the header form of an effect predicate declares a property
    called "contains", which is also a keyword the shim strips. The property
    was deleted and a description string was left in the properties map in
    its place, so the API refused the whole request -- a property's schema is
    not a string -- and every generation on the Anthropic path failed before
    a single model call. The smoke entry caught it in five seconds.
    """

    def test_a_property_named_like_a_keyword_survives(self) -> None:
        schema = {
            "type": "object",
            "properties": {"contains": {"type": "string"}, "name": {"type": "string"}},
        }
        out = _anthropic_compatible_schema(schema)
        self.assertEqual(out["properties"], schema["properties"])

    def test_nothing_is_added_to_a_properties_map(self) -> None:
        """The corruption was an injected key, not only a deleted one."""
        out = _anthropic_compatible_schema(
            {"type": "object", "properties": {"contains": {"type": "string"}}}
        )
        self.assertEqual(set(out["properties"]), {"contains"})
        self.assertNotIn("description", out["properties"])

    def test_a_real_constraint_is_still_stripped_and_noted(self) -> None:
        out = _anthropic_compatible_schema({"type": "string", "minLength": 4})
        self.assertNotIn("minLength", out)
        self.assertIn("minLength=4", out["description"])

    def test_a_constraint_inside_a_property_is_still_stripped(self) -> None:
        out = _anthropic_compatible_schema(
            {"type": "object", "properties": {"a": {"type": "array", "maxItems": 3}}}
        )
        self.assertNotIn("maxItems", out["properties"]["a"])
        self.assertIn("maxItems=3", out["properties"]["a"]["description"])

    def test_the_effect_predicate_schema_survives_the_shim(self) -> None:
        """The schema that found the defect, end to end."""
        from cvelab.sourcegen import EFFECT_PREDICATE_SCHEMA

        out = _anthropic_compatible_schema(EFFECT_PREDICATE_SCHEMA)
        for name in out["properties"]["header"]["required"]:
            self.assertIn(name, out["properties"]["header"]["properties"])


class TemperatureReachesEveryDialectTests(unittest.TestCase):
    """One setting, three dialects, and nothing sent unless it is asked for.

    Before this, the messages dialect (Anthropic) and the responses dialect
    (OpenAI) named no temperature while chat-completions (DeepSeek, local)
    pinned 0, so the same CVE asked of two providers was sampled under two
    regimes and nothing recorded that.
    """

    PAYLOADS = {
        "openai": {"output": [{"type": "message",
                               "content": [{"type": "output_text", "text": '{"ok":true}'}]}]},
        "anthropic": {"content": [{"type": "text", "text": '{"ok":true}'}],
                      "stop_reason": "end_turn"},
        "deepseek": {"choices": [{"message": {"content": '{"ok":true}'}}]},
    }

    def body(self, provider: str, **extra) -> dict:
        with mock.patch("cvelab.ai._request_json",
                        return_value=self.PAYLOADS[provider]) as request:
            structured_response(
                api_key="secret", model="test-model", provider=provider,
                instructions="test", input_text="input", schema=SCHEMA,
                schema_name="test_schema", max_output_tokens=100, **extra,
            )
        return request.call_args.args[2] if len(request.call_args.args) > 2 \
            else request.call_args.kwargs["body"]

    def test_each_dialect_sends_what_was_asked_for(self) -> None:
        for provider in ("openai", "anthropic", "deepseek"):
            with self.subTest(provider=provider):
                self.assertEqual(self.body(provider, temperature=0.25)["temperature"], 0.25)

    def test_the_two_that_never_named_one_still_do_not(self) -> None:
        # The default request stays byte-identical to the one these dialects
        # have always sent, so turning the knob is a deliberate act.
        for provider in ("openai", "anthropic"):
            with self.subTest(provider=provider):
                self.assertNotIn("temperature", self.body(provider))

    def test_chat_completions_keeps_the_zero_it_always_pinned(self) -> None:
        self.assertEqual(self.body("deepseek")["temperature"], 0)

    def test_the_environment_reaches_a_caller_that_asked_for_nothing(self) -> None:
        with mock.patch.dict("os.environ", {"CVELAB_TEMPERATURE": "0.7"}):
            self.assertEqual(self.body("anthropic")["temperature"], 0.7)

    def test_an_unreadable_setting_is_ignored_rather_than_raised(self) -> None:
        # A run is worth more than a complaint about a stray environment
        # variable, and the provider's default is a defined behaviour.
        with mock.patch.dict("os.environ", {"CVELAB_TEMPERATURE": "warm"}):
            self.assertNotIn("temperature", self.body("anthropic"))

    def test_out_of_range_is_clamped_not_sent(self) -> None:
        # The endpoint would refuse it, which is a worse way to find out.
        with mock.patch.dict("os.environ", {"CVELAB_TEMPERATURE": "11"}):
            self.assertEqual(self.body("anthropic")["temperature"], 2.0)


if __name__ == "__main__":
    unittest.main()
