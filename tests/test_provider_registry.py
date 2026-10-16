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

"""The registry is the only place a provider is declared.

Adding DeepSeek meant editing eight places, and one of them was missed in a
way that raised KeyError for the first user who tried it. These tests fail if
provider knowledge starts accumulating outside cvelab/providers.py again.
"""

from __future__ import annotations

import re
import unittest
import unittest.mock
from pathlib import Path

from cvelab import cli, usage
from cvelab.ai import SUPPORTED_PROVIDERS, provider_supports_web_search, resolve_provider
from cvelab.providers import (
    DIALECT_PATH,
    PROVIDERS,
    SELECTABLE,
    base_url_for,
    endpoint_for,
    output_budget_for,
    price_for,
)
from cvelab.providers import get as get_provider

PACKAGE = Path(__file__).resolve().parent.parent / "cvelab"


class RegistryShapeTests(unittest.TestCase):
    def test_every_provider_is_complete(self) -> None:
        for name, provider in PROVIDERS.items():
            with self.subTest(provider=name):
                self.assertEqual(provider.name, name)
                self.assertTrue(provider.label)
                self.assertIn(provider.dialect, DIALECT_PATH)
                self.assertTrue(provider.base_url)
                self.assertTrue(provider.key_variable)

    def test_endpoints_derive_from_the_base_url(self) -> None:
        for name in PROVIDERS:
            with self.subTest(provider=name):
                self.assertTrue(endpoint_for(name).startswith(base_url_for(name)))

    def test_a_base_url_can_be_overridden_by_environment(self) -> None:
        with unittest.mock.patch.dict(
            "os.environ", {"CVELAB_OPENAI_BASE_URL": "https://proxy.example/v1"}
        ):
            self.assertEqual(base_url_for("openai"), "https://proxy.example/v1")

    def test_an_explicit_argument_beats_the_environment(self) -> None:
        with unittest.mock.patch.dict(
            "os.environ", {"CVELAB_OPENAI_BASE_URL": "https://proxy.example/v1"}
        ):
            self.assertEqual(
                base_url_for("openai", "https://direct.example/v1"),
                "https://direct.example/v1",
            )

    def test_an_unknown_provider_names_the_known_ones(self) -> None:
        with self.assertRaises(ValueError) as raised:
            get_provider("nonesuch")
        for name in PROVIDERS:
            self.assertIn(name, str(raised.exception))


class NothingIsDeclaredTwiceTests(unittest.TestCase):
    def test_the_package_spells_no_provider_endpoint(self) -> None:
        offenders = []
        for path in sorted(PACKAGE.rglob("*.py")):
            if path.name == "providers.py":
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"https://api\.(openai|anthropic|deepseek)\.com", line):
                    offenders.append(f"{path.name}:{number}")
        self.assertEqual(
            offenders, [],
            "A provider endpoint is written outside the registry: " + ", ".join(offenders),
        )

    def test_the_supported_set_is_derived(self) -> None:
        self.assertEqual(SUPPORTED_PROVIDERS, set(SELECTABLE))
        self.assertEqual(set(SELECTABLE), {"auto", *PROVIDERS})

    def test_the_cli_offers_exactly_the_registry(self) -> None:
        action = next(
            a for a in cli.parser()._subparsers._group_actions[0]
            .choices["auto"]._actions if a.dest == "provider"
        )
        self.assertEqual(tuple(action.choices), SELECTABLE)

    def test_prices_come_from_the_registry(self) -> None:
        for provider in PROVIDERS.values():
            for model, price in provider.prices.items():
                with self.subTest(model=model):
                    self.assertEqual(usage.PRICES[model], price)
                    self.assertEqual(price_for(model), price)

    def test_web_search_is_read_not_listed(self) -> None:
        for name, provider in PROVIDERS.items():
            with self.subTest(provider=name):
                self.assertEqual(provider_supports_web_search(name), provider.web_search)

    def test_every_provider_resolves(self) -> None:
        for name in PROVIDERS:
            self.assertEqual(resolve_provider(name), name)


class OutputBudgetTests(unittest.TestCase):
    """A reasoning model spends the budget before it writes anything.

    deepseek-v4-pro returned finish_reason='length' with no content at the
    budgets that work elsewhere, and the response carried reasoning_tokens.
    The ceiling is a property of the model, so it is declared once.
    """

    def test_a_plain_provider_is_unscaled(self) -> None:
        self.assertEqual(output_budget_for("openai", 14000), 14000)

    def test_a_reasoning_provider_gets_room(self) -> None:
        self.assertGreater(output_budget_for("deepseek", 14000), 14000)

    def test_the_scale_can_be_overridden(self) -> None:
        with unittest.mock.patch.dict(
            "os.environ", {"CVELAB_DEEPSEEK_OUTPUT_SCALE": "2"}
        ):
            self.assertEqual(output_budget_for("deepseek", 1000), 2000)

    def test_a_nonsense_override_is_refused(self) -> None:
        with unittest.mock.patch.dict(
            "os.environ", {"CVELAB_OPENAI_OUTPUT_SCALE": "plenty"}
        ):
            with self.assertRaises(ValueError):
                output_budget_for("openai", 1000)

    def test_every_provider_declares_a_usable_scale(self) -> None:
        for name, provider in PROVIDERS.items():
            with self.subTest(provider=name):
                self.assertGreater(provider.output_budget_scale, 0)
                self.assertEqual(
                    output_budget_for(name, 1000),
                    int(1000 * provider.output_budget_scale),
                )



if __name__ == "__main__":
    import unittest.mock  # noqa: F401  (used above via unittest.mock)

    unittest.main()
