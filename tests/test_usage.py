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

import unittest
from unittest import mock

from cvelab import usage


class ExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        usage.reset()

    def test_openai_shape(self) -> None:
        usage.record("openai", "gpt-5.6-sol", {
            "usage": {
                "input_tokens": 1200,
                "output_tokens": 300,
                "input_tokens_details": {"cached_tokens": 800},
            }
        })
        totals = usage.snapshot()
        self.assertEqual(
            (totals.input_tokens, totals.output_tokens, totals.cached_input_tokens),
            (1200, 300, 800),
        )

    def test_anthropic_shape(self) -> None:
        usage.record("anthropic", "claude-opus-5-5", {
            "usage": {
                "input_tokens": 500,
                "output_tokens": 100,
                "cache_read_input_tokens": 400,
            }
        })
        totals = usage.snapshot()
        self.assertEqual(
            (totals.input_tokens, totals.output_tokens, totals.cached_input_tokens),
            (500, 100, 400),
        )

    def test_local_chat_completions_shape(self) -> None:
        usage.record("local", "qwen", {
            "usage": {"prompt_tokens": 42, "completion_tokens": 7}
        })
        totals = usage.snapshot()
        self.assertEqual((totals.input_tokens, totals.output_tokens), (42, 7))

    def test_a_provider_that_reports_nothing_is_not_an_error(self) -> None:
        # Many local servers omit usage entirely.
        usage.record("local", "qwen", {})
        totals = usage.snapshot()
        self.assertEqual(totals.calls, 1)
        self.assertEqual(totals.total_tokens, 0)

    def test_calls_accumulate_across_attempts(self) -> None:
        for _ in range(4):
            usage.record("openai", "gpt-5.6-sol",
                         {"usage": {"input_tokens": 100, "output_tokens": 10}})
        totals = usage.snapshot()
        self.assertEqual(totals.calls, 4)
        self.assertEqual(totals.input_tokens, 400)
        self.assertEqual(totals.total_tokens, 440)

    def test_reset_clears_a_previous_run(self) -> None:
        usage.record("openai", "gpt-5.6-sol",
                     {"usage": {"input_tokens": 100, "output_tokens": 10}})
        usage.reset()
        self.assertEqual(usage.snapshot().calls, 0)


class CostTests(unittest.TestCase):
    def setUp(self) -> None:
        usage.reset()

    def test_a_known_model_is_priced(self) -> None:
        # 1M in at $4.00 and 1M out at $20.00.
        usage.record("openai", "gpt-5.6-sol",
                     {"usage": {"input_tokens": 1_000_000, "output_tokens": 1_000_000}})
        self.assertAlmostEqual(usage.estimate_cost(), 24.00, places=4)

    def test_an_unknown_model_reports_tokens_without_a_price(self) -> None:
        usage.record("local", "some-local-build",
                     {"usage": {"prompt_tokens": 1000, "completion_tokens": 100}})
        self.assertIsNone(usage.estimate_cost())
        report = usage.as_dict()
        self.assertEqual(report["total_tokens"], 1100)
        self.assertIsNone(report["estimated_cost_usd"])
        self.assertIn("CVELAB_PRICE_INPUT", report["cost_note"])

    def test_mixed_models_refuse_to_guess_a_single_number(self) -> None:
        usage.record("openai", "gpt-5.6-sol",
                     {"usage": {"input_tokens": 100, "output_tokens": 10}})
        usage.record("anthropic", "claude-opus-5-5",
                     {"usage": {"input_tokens": 100, "output_tokens": 10}})
        self.assertIsNone(usage.estimate_cost())

    def test_environment_override_wins_over_the_table(self) -> None:
        usage.record("openai", "gpt-5.6-sol",
                     {"usage": {"input_tokens": 1_000_000, "output_tokens": 0}})
        with mock.patch.dict("os.environ",
                             {"CVELAB_PRICE_INPUT": "1.0", "CVELAB_PRICE_OUTPUT": "2.0"}):
            self.assertAlmostEqual(usage.estimate_cost(), 1.00, places=4)

    def test_an_override_prices_an_otherwise_unknown_model(self) -> None:
        usage.record("local", "some-local-build",
                     {"usage": {"prompt_tokens": 2_000_000, "completion_tokens": 0}})
        with mock.patch.dict("os.environ",
                             {"CVELAB_PRICE_INPUT": "0.5", "CVELAB_PRICE_OUTPUT": "0"}):
            self.assertAlmostEqual(usage.estimate_cost(), 1.00, places=4)

    def test_a_malformed_override_is_rejected_rather_than_ignored(self) -> None:
        usage.record("openai", "gpt-5.6-sol",
                     {"usage": {"input_tokens": 1, "output_tokens": 1}})
        with mock.patch.dict("os.environ", {"CVELAB_PRICE_INPUT": "free"}):
            with self.assertRaises(ValueError):
                usage.estimate_cost()

    def test_the_report_dates_its_price_table(self) -> None:
        usage.record("openai", "gpt-5.6-sol",
                     {"usage": {"input_tokens": 10, "output_tokens": 1}})
        self.assertIn(usage.PRICES_CHECKED, usage.as_dict()["cost_note"])

    def test_the_summary_is_empty_before_any_call(self) -> None:
        self.assertEqual(usage.format_summary(), "")

    def test_the_summary_names_calls_tokens_and_cost(self) -> None:
        usage.record("openai", "gpt-5.6-sol",
                     {"usage": {"input_tokens": 1_000_000, "output_tokens": 0}})
        summary = usage.format_summary()
        self.assertIn("1 model call(s)", summary)
        self.assertIn("1,000,000 in", summary)
        self.assertIn("$4.00", summary)


if __name__ == "__main__":
    unittest.main()
