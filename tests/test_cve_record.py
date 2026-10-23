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

from cvelab import core, sourcegen
from cvelab.core import CVERecordNotFound, collect_cve

CVE = "CVE-2026-0001"
CVE_ORG = core.CVE_RECORD_URL.format(cve=CVE)
GITHUB = core.GITHUB_ADVISORY_URL.format(cve=CVE)

RECORD = {
    "cveMetadata": {"state": "PUBLISHED", "datePublished": "2026-10-20T00:00:00Z"},
    "containers": {"cna": {
        "descriptions": [{"value": "From CVE.org."}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
        "references": [{"url": "https://github.com/acme/widget/commit/" + "a" * 40}],
    }},
}

ADVISORY = {
    "ghsa_id": "GHSA-aaaa-bbbb-cccc",
    "cve_id": CVE,
    "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
    "summary": "Widget leaks the session token",
    "description": "The token is sent to any host named in the URL.",
    "published_at": "2026-10-20T20:37:57Z",
    "withdrawn_at": None,
    "cwes": [{"cwe_id": "CWE-201", "name": "Insertion of Sensitive Information Into Sent Data"}],
    "source_code_location": "https://github.com/acme/widget",
    "references": [
        "https://github.com/acme/widget/security/advisories/GHSA-aaaa-bbbb-cccc",
        "https://github.com/acme/widget/pull/12",
        "https://github.com/acme/widget/commit/" + "b" * 40,
    ],
    "vulnerabilities": [{
        "package": {"ecosystem": "npm", "name": "widget"},
        "vulnerable_version_range": "< 2.0.3",
        "first_patched_version": "2.0.3",
    }],
}


def http_error(url: str, code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "error", {}, io.BytesIO(b"{}"))


def network(answers: dict[str, object]):
    """Stand in for urlopen: each URL answers with a document or an HTTP code."""
    calls: list[str] = []

    def urlopen(request, timeout=None):
        url = request.full_url
        calls.append(url)
        answer = answers[url]
        if isinstance(answer, int):
            raise http_error(url, answer)
        return io.BytesIO(json.dumps(answer).encode())

    return urlopen, calls


class CveRecordTests(unittest.TestCase):
    def collect(self, answers: dict[str, object]) -> tuple[dict, list[str]]:
        urlopen, calls = network(answers)
        with mock.patch("cvelab.core.urllib.request.urlopen", side_effect=urlopen):
            return collect_cve(CVE), calls

    def test_cve_org_record_is_used_when_published(self) -> None:
        dossier, calls = self.collect({CVE_ORG: RECORD})
        self.assertEqual(calls, [CVE_ORG])
        self.assertEqual(dossier["descriptions"], ["From CVE.org."])
        self.assertEqual(dossier["source"], CVE_ORG)
        self.assertNotIn("record", dossier)

    def test_reserved_identifier_falls_back_to_the_github_advisory(self) -> None:
        dossier, calls = self.collect({CVE_ORG: 404, GITHUB: [ADVISORY]})
        self.assertEqual(calls, [CVE_ORG, GITHUB])
        self.assertEqual(dossier["cve"], CVE)
        self.assertEqual(dossier["source"], ADVISORY["html_url"])
        self.assertEqual(dossier["record"]["kind"], "github_advisory")
        self.assertEqual(dossier["record"]["id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(dossier["cwes"], ["CWE-201"])
        self.assertIn("Widget leaks the session token", dossier["descriptions"][0])
        self.assertIn("any host named in the URL", dossier["descriptions"][0])
        self.assertEqual(dossier["affected"][0]["product"], "widget")
        self.assertIn("https://github.com/acme/widget", dossier["references"])

    def test_fallback_dossier_resolves_the_fix_commit(self) -> None:
        dossier, _ = self.collect({CVE_ORG: 404, GITHUB: [ADVISORY]})
        self.assertEqual(
            sourcegen.resolve_source(dossier, None, None),
            ("https://github.com/acme/widget.git", "b" * 40),
        )

    def test_missing_everywhere_is_a_permanent_error(self) -> None:
        with self.assertRaises(CVERecordNotFound) as caught:
            self.collect({CVE_ORG: 404, GITHUB: []})
        self.assertIn("reserved", str(caught.exception))

    def test_withdrawn_or_unrelated_advisories_are_ignored(self) -> None:
        withdrawn = dict(ADVISORY, withdrawn_at="2026-10-21T00:00:00Z")
        unrelated = dict(ADVISORY, cve_id="CVE-2026-0002")
        with self.assertRaises(CVERecordNotFound):
            self.collect({CVE_ORG: 404, GITHUB: [withdrawn, unrelated]})

    def test_cve_org_server_error_stays_retryable(self) -> None:
        urlopen, calls = network({CVE_ORG: 503})
        with mock.patch("cvelab.core.urllib.request.urlopen", side_effect=urlopen):
            with self.assertRaises(RuntimeError) as caught:
                collect_cve(CVE)
        self.assertNotIsInstance(caught.exception, CVERecordNotFound)
        self.assertEqual(calls, [CVE_ORG])

    def test_github_rate_limit_stays_retryable(self) -> None:
        urlopen, _ = network({CVE_ORG: 404, GITHUB: 403})
        with mock.patch("cvelab.core.urllib.request.urlopen", side_effect=urlopen):
            with self.assertRaises(RuntimeError) as caught:
                collect_cve(CVE)
        self.assertNotIsInstance(caught.exception, CVERecordNotFound)
        self.assertIn("GitHub advisory API returned HTTP 403", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
