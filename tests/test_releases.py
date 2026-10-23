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

import os
import unittest
from unittest import mock

from cvelab import releases

CVE = "CVE-2026-0001"


def advisory(*vulnerabilities: dict) -> list[dict]:
    return [{"cve_id": CVE, "withdrawn_at": None, "vulnerabilities": list(vulnerabilities)}]


def entry(name: str, vulnerable_range: str, patched: str, ecosystem: str = "npm") -> dict:
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "vulnerable_version_range": vulnerable_range,
        "first_patched_version": patched,
    }


class VersionTests(unittest.TestCase):
    def test_final_releases_compare_numerically(self) -> None:
        self.assertLess(releases.version_key("1.9.0"), releases.version_key("1.10.0"))
        self.assertEqual(releases.version_key("2.0"), releases.version_key("2.0.0"))
        self.assertIsNone(releases.version_key("2.0.0-beta.1"))
        self.assertIsNone(releases.version_key("2.0.0rc1"))

    def test_advisory_ranges(self) -> None:
        self.assertTrue(releases.in_range("1.150.0", ">= 1.143.12, < 1.169.39"))
        self.assertFalse(releases.in_range("1.143.11", ">= 1.143.12, < 1.169.39"))
        self.assertFalse(releases.in_range("1.169.39", ">= 1.143.12, < 1.169.39"))
        self.assertTrue(releases.in_range("19.2.25", "<= 19.2.25"))
        self.assertFalse(releases.in_range("1.0.0", ""))
        self.assertTrue(releases.in_range("10.75.1", ">= 10.0.0-alpha.0, < 10.75.2"))
        self.assertFalse(releases.in_range("11.0.0", ">= 11.0.0-alpha.0, < 11.0.0-rc.1"))


class PickTests(unittest.TestCase):
    def test_the_highest_vulnerable_release_below_the_fix_is_chosen(self) -> None:
        versions = ["4.13.9", "4.13.10", "4.13.11", "4.13.12", "4.14.0-beta.1", "4.12.3"]
        picked = releases.pick_release(
            {"ecosystem": "npm", "package": "hono", "vulnerable_range": ">= 4.12.4, < 4.13.11",
             "first_patched": "4.13.11"},
            versions,
        )
        self.assertEqual(picked["last_vulnerable"], "4.13.10")
        self.assertEqual(picked["first_patched"], "4.13.11")

    def test_a_fix_the_registry_does_not_list_gives_no_pair(self) -> None:
        self.assertIsNone(releases.pick_release(
            {"ecosystem": "npm", "package": "x", "vulnerable_range": "< 2.0.0", "first_patched": "2.0.0"},
            ["1.9.0"],
        ))


class FindTests(unittest.TestCase):
    def fake_get(self, documents: dict):
        def get(url: str, headers: dict):
            for prefix, document in documents.items():
                if url.startswith(prefix):
                    return document
            return None
        return get

    def test_the_newest_release_line_wins_per_package(self) -> None:
        documents = {
            "https://api.github.com/advisories": advisory(
                entry("@acme/widget", ">= 21.0.0, < 21.0.3", "21.0.3"),
                entry("@acme/widget", ">= 20.0.0, < 20.3.34", "20.3.34"),
                entry("acme-py", "< 1.2.0", "1.2.0", ecosystem="pip"),
                entry("acme-go", "< 1.0.1", "1.0.1", ecosystem="go"),
            ),
            "https://registry.npmjs.org/@acme%2Fwidget": {
                "versions": {v: {} for v in ("20.3.33", "20.3.34", "21.0.2", "21.0.3")},
            },
            "https://pypi.org/pypi/acme-py/json": {"releases": {"1.1.9": [], "1.2.0": []}},
        }
        with mock.patch.object(releases, "_get", side_effect=self.fake_get(documents)), \
                mock.patch.dict(os.environ, {"CVELAB_PUBLISHED_RELEASES": ""}):
            found = releases.find_releases(CVE)
        self.assertIn(
            {"ecosystem": "npm", "package": "@acme/widget", "last_vulnerable": "21.0.2", "first_patched": "21.0.3"},
            found,
        )
        self.assertIn(
            {"ecosystem": "pip", "package": "acme-py", "last_vulnerable": "1.1.9", "first_patched": "1.2.0"},
            found,
        )
        self.assertEqual(len(found), 2)  # go has no registry here

    def test_nothing_is_looked_up_when_turned_off(self) -> None:
        with mock.patch.object(releases, "_get") as get, \
                mock.patch.dict(os.environ, {"CVELAB_PUBLISHED_RELEASES": "off"}):
            self.assertEqual(releases.find_releases(CVE), [])
        get.assert_not_called()

    def test_an_unreachable_advisory_gives_no_releases(self) -> None:
        with mock.patch.object(releases, "_get", return_value=None):
            self.assertEqual(releases.find_releases(CVE), [])


class RenderTests(unittest.TestCase):
    def test_render_offers_the_pair_and_keeps_the_snapshots_as_reference(self) -> None:
        text = releases.render([
            {"ecosystem": "npm", "package": "next", "last_vulnerable": "16.3.7", "first_patched": "16.3.8"},
        ])
        self.assertIn("npm next: last vulnerable 16.3.7, first patched 16.3.8", text)
        self.assertIn("vulnerable/Dockerfile installs the last vulnerable version", text)
        self.assertEqual(releases.render([]), "")


if __name__ == "__main__":
    unittest.main()
