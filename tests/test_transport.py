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

"""A key or a token is never sent in clear text to another machine.

`--base-url http://...` was accepted for every provider. Plain HTTP stays
allowed where it is normal and carries nothing secret: a local server on
loopback, or Ollama on the LAN with no key.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cvelab import upload
from cvelab.ai import _chat_completions_response
from cvelab.providers import is_loopback, require_private_transport

from tests.test_upload import RESULT, make_lab

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok"],
    "properties": {"ok": {"type": "boolean"}},
}
ANSWER = {"choices": [{"message": {"content": '{"ok": true}'}}]}


class TransportRuleTests(unittest.TestCase):
    def test_loopback_is_recognised(self) -> None:
        for url in ("http://localhost:11434/v1", "http://127.0.0.1/v1", "http://127.8.0.1",
                    "http://[::1]:8000"):
            with self.subTest(url=url):
                self.assertTrue(is_loopback(url))
        for url in ("http://localhost.example", "http://192.168.1.5", "http://10.0.0.1", "http://ollama"):
            with self.subTest(url=url):
                self.assertFalse(is_loopback(url))

    def test_a_key_over_plain_http_to_another_host_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "plain HTTP"):
            require_private_transport("http://gateway.example/v1/chat/completions", "sk-x")

    def test_what_stays_allowed(self) -> None:
        require_private_transport("https://gateway.example/v1", "sk-x")
        require_private_transport("http://127.0.0.1:11434/v1", "sk-x")
        require_private_transport("http://192.168.1.5:11434/v1", None)
        require_private_transport("http://192.168.1.5:11434/v1", "")


class ProviderRequestTests(unittest.TestCase):
    def call(self, provider: str, key: str | None, base_url: str):
        with mock.patch("cvelab.ai._request_json", return_value=ANSWER) as request:
            result = _chat_completions_response(
                provider, key, base_url, "m", "do it", "input", SCHEMA, "s", 100
            )
        return result, request

    def test_deepseek_through_an_http_gateway_is_refused_before_sending(self) -> None:
        with mock.patch("cvelab.ai._request_json") as request:
            with self.assertRaisesRegex(ValueError, "plain HTTP"):
                _chat_completions_response(
                    "deepseek", "sk-x", "http://gateway.example", "m", "i", "t", SCHEMA, "s", 10
                )
        request.assert_not_called()

    def test_a_local_server_with_a_key_on_the_lan_is_refused(self) -> None:
        with mock.patch("cvelab.ai._request_json") as request:
            with self.assertRaisesRegex(ValueError, "plain HTTP"):
                _chat_completions_response(
                    "local", "secret-key", "http://192.168.1.5:11434/v1", "m", "i", "t", SCHEMA, "s", 10
                )
        request.assert_not_called()

    def test_ollama_on_the_lan_without_a_key_keeps_working(self) -> None:
        result, request = self.call("local", None, "http://192.168.1.5:11434/v1")
        self.assertEqual(result, {"ok": True})
        request.assert_called_once()

    def test_the_hosted_providers_are_checked_too(self) -> None:
        source = (Path(__file__).resolve().parent.parent / "cvelab" / "ai.py").read_text(encoding="utf-8")
        self.assertIn('require_private_transport(endpoint_for("openai"), api_key)', source)
        self.assertIn('require_private_transport(endpoint_for("anthropic"), api_key)', source)

    def test_the_preflight_refuses_it_without_sending(self) -> None:
        from cvelab.doctor import FAIL, check_provider_reachable

        with mock.patch("urllib.request.urlopen") as urlopen:
            check = check_provider_reachable("deepseek", "sk-x", "http://gateway.example")
        self.assertEqual(check.status, FAIL)
        self.assertIn("plain HTTP", check.detail)
        urlopen.assert_not_called()


class EndpointTransportTests(unittest.TestCase):
    """The token is a header and the exploit is the body: no clear text off-machine."""

    def test_plain_http_to_another_host_is_refused_before_sending(self) -> None:
        with mock.patch.dict("os.environ", {"CVELAB_ENDPOINT": "http://cvelab.example"}), \
                mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(upload.UploadError, "https"):
                upload.send({"cve": "CVE-2024-12345"}, "cvelab_token")
        urlopen.assert_not_called()

    def test_loopback_http_is_allowed_for_local_development(self) -> None:
        for url in ("http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"):
            with self.subTest(url=url):
                with mock.patch.dict("os.environ", {"CVELAB_ENDPOINT": url}):
                    self.assertIsNone(upload.insecure_endpoint())

    def test_https_is_allowed(self) -> None:
        with mock.patch.dict("os.environ", {"CVELAB_ENDPOINT": "https://self.hosted"}):
            self.assertIsNone(upload.insecure_endpoint())
        for url in ("http://localhost.evil.example", "ftp://cvelab.tech", "http://10.0.0.1"):
            with self.subTest(url=url):
                with mock.patch.dict("os.environ", {"CVELAB_ENDPOINT": url}):
                    self.assertIsNotNone(upload.insecure_endpoint())

    def test_a_refused_endpoint_does_not_fail_the_run(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab = make_lab(Path(temporary.name))
        with mock.patch.dict("os.environ", {"CVELAB_ENDPOINT": "http://cvelab.example"}):
            answer = upload.upload_result(lab, RESULT, token="cvelab_x")
        self.assertEqual(answer["ok"], False)
        self.assertIn("https", answer["error"])

    def test_the_preflight_flags_it(self) -> None:
        from cvelab.doctor import FAIL, check_report_upload

        with mock.patch.dict("os.environ", {"CVELAB_ENDPOINT": "http://cvelab.example"}), \
                mock.patch.object(upload, "find_token", return_value="cvelab_x"):
            check = check_report_upload()
        self.assertEqual(check.status, FAIL)
        self.assertIn("https", check.detail)


if __name__ == "__main__":
    unittest.main()
