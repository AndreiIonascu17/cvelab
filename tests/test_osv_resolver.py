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

import io
import json
import unittest
import urllib.error
from unittest import mock

from cvelab.sourcegen import resolve_source, resolve_source_via_osv


def osv(payload: dict):
    """Patch urlopen to answer with one OSV record."""
    response = mock.MagicMock()
    response.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
    return mock.patch("urllib.request.urlopen", return_value=response)


def git_range(repo: str, fixed: str) -> dict:
    return {
        "affected": [
            {"ranges": [{"type": "GIT", "repo": repo,
                         "events": [{"introduced": "0"}, {"fixed": fixed}]}]}
        ]
    }


COMMIT = "f2e7063ee409ff40a60b14370c58dceee1a2efd4"


class OsvResolverTests(unittest.TestCase):
    """A CVE record often names no commit; OSV usually does.

    Measured over the 40-CVE benchmark suite, the CVE record alone resolved
    22. OSV resolved 17 of the remaining 18. Without this the generator falls
    back to asking a model to find the source with web search, which costs
    money for an answer OSV gives free.
    """

    def test_a_git_range_yields_the_repository_and_fix(self) -> None:
        with osv(git_range("https://github.com/lodash/lodash", COMMIT)):
            self.assertEqual(
                resolve_source_via_osv("CVE-2020-8203"),
                ("https://github.com/lodash/lodash.git", COMMIT),
            )

    def test_a_record_without_a_git_range_resolves_to_nothing(self) -> None:
        with osv({"affected": [{"ranges": [{"type": "ECOSYSTEM",
                                            "events": [{"fixed": "4.17.20"}]}]}]}):
            self.assertIsNone(resolve_source_via_osv("CVE-2020-8203"))

    def test_a_version_string_is_not_accepted_as_a_commit(self) -> None:
        # A lab pinned to a tag is not reproducible; only a commit id is.
        with osv(git_range("https://github.com/o/p", "4.17.20")):
            self.assertIsNone(resolve_source_via_osv("CVE-2020-8203"))

    def test_an_unreachable_osv_is_not_an_error(self) -> None:
        # The caller still has its own fallback, so this must not raise.
        with mock.patch("urllib.request.urlopen",
                        side_effect=urllib.error.URLError("down")):
            self.assertIsNone(resolve_source_via_osv("CVE-2020-8203"))

    def test_malformed_json_is_not_an_error(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value = io.BytesIO(b"<html>not json</html>")
        with mock.patch("urllib.request.urlopen", return_value=response):
            self.assertIsNone(resolve_source_via_osv("CVE-2020-8203"))

    def test_an_invalid_identifier_makes_no_request(self) -> None:
        with mock.patch("urllib.request.urlopen") as urlopen:
            self.assertIsNone(resolve_source_via_osv("../../etc/passwd"))
            self.assertIsNone(resolve_source_via_osv(""))
        urlopen.assert_not_called()

    def test_a_repository_url_from_osv_is_validated(self) -> None:
        # The URL comes from a third party and is checked like user input.
        with osv(git_range("file:///etc", COMMIT)):
            self.assertIsNone(resolve_source_via_osv("CVE-2020-8203"))


class ResolutionOrderTests(unittest.TestCase):
    def test_an_explicit_override_skips_osv_entirely(self) -> None:
        with mock.patch("urllib.request.urlopen") as urlopen:
            self.assertEqual(
                resolve_source({"cve": "CVE-2020-8203"},
                               "https://github.com/o/p.git", COMMIT),
                ("https://github.com/o/p.git", COMMIT),
            )
        urlopen.assert_not_called()

    def test_a_commit_in_the_cve_record_skips_osv(self) -> None:
        dossier = {
            "cve": "CVE-2020-8203",
            "references": [f"https://github.com/lodash/lodash/commit/{COMMIT}"],
        }
        with mock.patch("urllib.request.urlopen") as urlopen:
            repo, ref = resolve_source(dossier, None, None)
        urlopen.assert_not_called()
        self.assertEqual(repo, "https://github.com/lodash/lodash.git")
        self.assertEqual(ref, COMMIT)

    def test_osv_is_consulted_when_the_record_names_no_commit(self) -> None:
        dossier = {"cve": "CVE-2020-8203",
                   "references": ["https://example.invalid/advisory"]}
        with osv(git_range("https://github.com/lodash/lodash", COMMIT)):
            self.assertEqual(
                resolve_source(dossier, None, None),
                ("https://github.com/lodash/lodash.git", COMMIT),
            )

    def test_nothing_anywhere_resolves_to_nothing(self) -> None:
        with osv({"affected": []}):
            self.assertIsNone(
                resolve_source({"cve": "CVE-2020-8203", "references": []}, None, None)
            )


if __name__ == "__main__":
    unittest.main()
