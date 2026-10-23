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

"""An answer cut off at its output budget is asked for again, larger."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from cvelab import usage
from cvelab.ai import OutputBudgetExhausted, structured_response

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok"],
    "properties": {"ok": {"type": "boolean"}},
}
ANTHROPIC_CUT = {"stop_reason": "max_tokens", "usage": {"output_tokens": 9}, "content": []}
ANTHROPIC_DONE = {"stop_reason": "end_turn", "content": [{"type": "text", "text": '{"ok": true}'}]}


def ask(provider: str, model: str = "m") -> dict:
    return structured_response(
        api_key="secret", model=model, provider=provider, instructions="test",
        input_text="input", schema=SCHEMA, schema_name="test_schema", max_output_tokens=1000,
        base_url="http://127.0.0.1:11434/v1" if provider == "local" else None,
    )


class OutputEscalationTests(unittest.TestCase):
    def setUp(self) -> None:
        usage.reset()

    def test_a_cut_answer_is_asked_for_again_with_twice_the_budget_and_time(self) -> None:
        with mock.patch("cvelab.ai._request_json", side_effect=[ANTHROPIC_CUT, ANTHROPIC_DONE]) as request:
            self.assertEqual(ask("anthropic"), {"ok": True})
        first, second = request.call_args_list
        # Anthropic's scale of four makes 1000 into 4000, then 8000.
        self.assertEqual(first.args[2]["max_tokens"], 4000)
        self.assertEqual(second.args[2]["max_tokens"], 8000)
        self.assertEqual(second.kwargs["timeout_seconds"], first.kwargs["timeout_seconds"] * 2)

    def test_it_gives_up_at_the_ceiling(self) -> None:
        with mock.patch.dict(os.environ, {"CVELAB_ANTHROPIC_MAX_OUTPUT": "6000"}), \
                mock.patch("cvelab.ai._request_json", return_value=ANTHROPIC_CUT) as request:
            with self.assertRaisesRegex(OutputBudgetExhausted, "max_tokens"):
                ask("anthropic")
        self.assertEqual([call.args[2]["max_tokens"] for call in request.call_args_list], [4000, 6000])

    def test_it_escalates_at_most_twice(self) -> None:
        with mock.patch("cvelab.ai._request_json", return_value=ANTHROPIC_CUT) as request:
            with self.assertRaises(OutputBudgetExhausted):
                ask("anthropic")
        self.assertEqual(request.call_count, 3)

    def test_a_local_model_with_no_known_ceiling_is_not_retried(self) -> None:
        cut = {"choices": [{"message": {"content": '{"ok": tr'}, "finish_reason": "length"}]}
        with mock.patch("cvelab.ai._request_json", return_value=cut) as request:
            with self.assertRaisesRegex(OutputBudgetExhausted, "before its JSON was complete"):
                ask("local")
        self.assertEqual(request.call_count, 1)

    def test_a_partial_chat_completion_is_a_cut_not_bad_json(self) -> None:
        cut = {"choices": [{"message": {"content": '{"ok": tr'}, "finish_reason": "length"}]}
        done = {"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}]}
        with mock.patch("cvelab.ai._request_json", side_effect=[cut, done]) as request:
            self.assertEqual(ask("deepseek", "deepseek-flash"), {"ok": True})
        self.assertEqual(request.call_args_list[1].args[2]["max_tokens"], 8000)

    def test_an_incomplete_openai_response_is_retried(self) -> None:
        cut = {"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}, "output": []}
        done = {"output": [{"type": "message", "content": [{"type": "output_text", "text": '{"ok": true}'}]}]}
        with mock.patch("cvelab.ai._request_json", side_effect=[cut, done]) as request:
            self.assertEqual(ask("openai"), {"ok": True})
        self.assertEqual(request.call_args_list[1].args[2]["max_output_tokens"], 2000)


if __name__ == "__main__":
    unittest.main()
