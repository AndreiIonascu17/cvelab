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


if __name__ == "__main__":
    unittest.main()
