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

"""A local run may send its report to a control plane; it must send nothing else.

The point of the BYOC (bring your own credits) tier is that the provider key stays on the machine that
ran the lab. These tests fail if uploading ever starts carrying more than the
run produced, or if it happens without being asked for.
"""

from __future__ import annotations

import json
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from cvelab import core, upload

SENTINEL = "sk-not-a-real-key-0123456789"


def make_lab(root: Path, *, report: str = "# Report\n") -> Path:
    lab = root / "CVE-2024-12345"
    (lab / "artifacts").mkdir(parents=True)
    (lab / "plan.json").write_text(
        json.dumps(
            {
                "repository": "https://github.com/example/widget",
                "revisions": {"vulnerable": "aaa", "patched": "bbb"},
            }
        )
    )
    (lab / "artifacts" / "REPORT.md").write_text(report)
    (lab / "artifacts" / "PoC.py").write_text("print('exploit')\n")
    (lab / "artifacts" / "WALKTHROUGH.md").write_text("# Walkthrough\n")
    (lab / "artifacts" / "report.json").write_text("{}")
    return lab


RESULT = {"ok": True, "cve": "CVE-2024-12345", "status": "VALIDATED"}


class CollectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def collect(self, lab: Path, **kwargs) -> dict:
        options = {"provider": "openai", "model": "gpt-5.6-sol", "include_poc": True}
        options.update(kwargs)
        return upload.collect(lab, RESULT, **options)

    def test_the_whole_lab_leaves_by_default(self) -> None:
        # The corpus is what the service sells, and an entry nobody can run
        # is a description of a lab rather than a lab.
        names = [d["name"] for d in self.collect(make_lab(self.root))["documents"]]
        self.assertIn("PoC.py", names)
        self.assertIn("REPORT.md", names)
        self.assertIn("WALKTHROUGH.md", names)

    def test_no_poc_withholds_what_makes_it_runnable(self) -> None:
        payload = self.collect(make_lab(self.root), include_poc=False)
        names = [d["name"] for d in payload["documents"]]
        self.assertNotIn("PoC.py", names)
        self.assertIn("REPORT.md", names)
        for withheld in upload.EXPLOIT:
            self.assertNotIn(withheld, names)

    def test_the_upload_says_whether_the_exploit_is_included(self) -> None:
        lab = make_lab(self.root)
        self.assertIn("the exploit is included", upload.describe(self.collect(lab)))
        self.assertIn(
            "the exploit is withheld",
            upload.describe(self.collect(lab, include_poc=False)),
        )

    def test_metadata_comes_from_the_plan(self) -> None:
        payload = self.collect(make_lab(self.root))
        self.assertEqual(payload["repo"], "https://github.com/example/widget")
        self.assertEqual(payload["fixed_ref"], "bbb")

    def test_a_registered_key_is_redacted(self) -> None:
        core.register_secret(SENTINEL)
        self.addCleanup(core._SECRETS.discard, SENTINEL)
        lab = make_lab(self.root, report=f"key was {SENTINEL}\n")
        payload = self.collect(lab)
        serialised = json.dumps(payload)
        self.assertNotIn(SENTINEL, serialised)
        self.assertIn("[REDACTED]", serialised)

    def test_an_oversized_document_is_trimmed_and_marked(self) -> None:
        lab = make_lab(self.root, report="A" * (upload.MAX_DOCUMENT_BYTES + 5000))
        document = self.collect(lab)["documents"][0]
        self.assertTrue(document["truncated"])
        self.assertLessEqual(
            len(document["text"].encode("utf-8")), upload.MAX_DOCUMENT_BYTES
        )

    def test_an_unknown_outcome_is_not_called_a_success(self) -> None:
        payload = upload.collect(
            make_lab(self.root),
            {"ok": False, "cve": "CVE-2024-12345", "status": "SOMETHING_NEW"},
            provider=None,
            model=None,
            include_poc=True,
        )
        self.assertEqual(payload["status"], "failed")

    def test_every_known_outcome_maps_to_a_stored_status(self) -> None:
        allowed = {"queued", "running", "succeeded", "declined", "failed", "cancelled"}
        self.assertTrue(set(upload.STATUS.values()) <= allowed)

    def test_the_payload_never_carries_a_key_field(self) -> None:
        payload = self.collect(make_lab(self.root))
        for field in ("api_key", "key", "token", "authorization"):
            self.assertNotIn(field, payload)


    def test_a_validated_run_says_it_will_be_shared(self) -> None:
        # Enrolling people in a corpus without saying so is the one thing
        # this feature must not do.
        payload = self.collect(make_lab(self.root))
        self.assertIn("shared database", upload.describe(payload))

    def test_a_failed_run_does_not_claim_to_be_shared(self) -> None:
        payload = upload.collect(
            make_lab(self.root),
            {"ok": False, "cve": "CVE-2024-12345", "status": "AUTO_REPAIR_EXHAUSTED"},
            provider=None, model=None, include_poc=True,
        )
        self.assertNotIn("shared database", upload.describe(payload))


class PayloadBudgetTests(unittest.TestCase):
    """Ten documents at the per-document cap exceed what one upload takes.

    The server refuses a body over 1 MiB with a 413, which loses the whole
    entry rather than part of it. ALWAYS is in priority order, so trimming
    from the end sheds the analysis before the report and the report before
    the exploit. Real labs are 50 to 140 KiB, so this only bites a
    pathological one -- but the cliff was introduced the moment the payload
    went from one document to ten.
    """

    def test_a_normal_lab_is_never_trimmed(self) -> None:
        documents = [{"name": "REPORT.md", "text": "x" * 50_000}]
        kept, dropped = upload.fit_payload(documents)
        self.assertEqual(kept, documents)
        self.assertEqual(dropped, [])

    def test_an_oversized_payload_is_trimmed_not_refused(self) -> None:
        documents = [
            {"name": f"d{i}.md", "text": "A" * upload.MAX_DOCUMENT_BYTES}
            for i in range(10)
        ]
        kept, dropped = upload.fit_payload(documents)
        self.assertTrue(kept)
        self.assertTrue(dropped)
        total = sum(len(d["text"].encode("utf-8")) for d in kept)
        self.assertLessEqual(total, upload.MAX_PAYLOAD_BYTES)

    def test_what_was_left_out_is_named(self) -> None:
        documents = [
            {"name": f"d{i}.md", "text": "A" * upload.MAX_DOCUMENT_BYTES}
            for i in range(10)
        ]
        _, dropped = upload.fit_payload(documents)
        payload = {"cve": "CVE-2024-1", "status": "failed", "outcome": None,
                   "documents": [], "dropped_documents": dropped}
        self.assertIn("left out", upload.describe(payload))
        self.assertIn(dropped[0], upload.describe(payload))

    def test_the_budget_stays_under_what_the_worker_accepts(self) -> None:
        # site/worker/index.js refuses a body over 1 MiB.
        self.assertLess(upload.MAX_PAYLOAD_BYTES, 1024 * 1024)


class TokenTests(unittest.TestCase):
    def test_no_token_means_nothing_is_sent(self) -> None:
        with mock.patch.object(upload, "find_token", return_value=None):
            with mock.patch.object(upload, "send") as send:
                answer = upload.upload_result(Path("/nonexistent"), RESULT)
        self.assertIsNone(answer)
        send.assert_not_called()

    def test_the_environment_wins_over_the_file(self) -> None:
        with mock.patch.dict("os.environ", {upload.TOKEN_VARIABLE: "cvelab_env"}):
            self.assertEqual(upload.find_token(), "cvelab_env")

    def test_a_missing_token_file_is_not_an_error(self) -> None:
        with mock.patch.dict("os.environ", {upload.TOKEN_VARIABLE: ""}):
            with mock.patch.object(upload, "TOKEN_FILE", Path("/nonexistent/token")):
                self.assertIsNone(upload.find_token())

    def test_a_failed_upload_does_not_fail_the_run(self) -> None:
        # The lab is the deliverable. An unreachable control plane must not
        # turn a validated reproduction into a non-zero exit.
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab = make_lab(Path(temporary.name))
        with mock.patch.object(upload, "send", side_effect=upload.UploadError("down")):
            answer = upload.upload_result(lab, RESULT, token="cvelab_x")
        self.assertEqual(answer["ok"], False)


class EndpointTests(unittest.TestCase):
    def test_the_endpoint_is_a_default_not_a_constant(self) -> None:
        with mock.patch.dict("os.environ", {"CVELAB_ENDPOINT": "https://self.hosted/"}):
            self.assertEqual(upload.endpoint(), "https://self.hosted")

    def test_the_default_is_the_public_service(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(upload.endpoint(), "https://cvelab.tech")


class PreflightTests(unittest.TestCase):
    """Uploading is opt-out, so the preflight has to say which way it is set."""

    def test_the_preflight_says_nothing_is_kept_on_our_side(self) -> None:
        # "reports stay on this machine" said where they stay without
        # saying that we keep no copy, or what a token would change.
        from cvelab.doctor import check_report_upload

        with mock.patch.object(upload, "find_token", return_value=None):
            detail = check_report_upload().detail
        self.assertIn("off", detail)
        self.assertIn("we keep no copy", detail)
        self.assertIn("token", detail)
        self.assertIn("your account", detail)

    def test_the_preflight_names_where_reports_go(self) -> None:
        from cvelab.doctor import check_report_upload

        with mock.patch.object(upload, "find_token", return_value="cvelab_x"):
            detail = check_report_upload().detail
        self.assertIn("on", detail)
        self.assertIn(upload.endpoint(), detail)
        self.assertIn("--no-upload", detail)
        # The exploit travels by default now, so the line that announces
        # the upload has to say so.
        self.assertIn("exploit included", detail)
        self.assertIn("--no-poc", detail)


if __name__ == "__main__":
    unittest.main()


def http_error(code: int, body: object, headers: dict | None = None):
    import email.message
    import io
    import urllib.error

    message = email.message.Message()
    for key, value in (headers or {}).items():
        message[key] = value
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return urllib.error.HTTPError(
        "https://cvelab.tech/api/runs", code, "error", message, io.BytesIO(raw)
    )


class ControlPlaneAnswerTests(unittest.TestCase):
    """What the CLI says when the control plane refuses, limits or keeps a run."""

    def send_with(self, error) -> upload.UploadError:
        with mock.patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(upload.UploadError) as caught:
                upload.send({"cve": "CVE-2024-12345"}, "cvelab_token")
        return caught.exception

    def test_a_refused_run_names_every_failed_check(self) -> None:
        failures = ["EVIDENCE.json is missing", "the attack was not executed"]
        error = self.send_with(http_error(422, {"error": "x", "failures": failures}))
        self.assertEqual(error.failures, failures)
        for failure in failures:
            self.assertIn(failure, str(error))

    def test_a_rate_limit_says_how_long_to_wait(self) -> None:
        error = self.send_with(
            http_error(429, {"error": "At most 20 runs an hour per account.",
                             "retry_after": 600}, {"Retry-After": "600"})
        )
        self.assertEqual(error.retry_after, 600)
        self.assertIn("20 runs an hour", str(error))
        self.assertIn("10 minutes", str(error))

    def test_a_non_json_error_still_reports_its_status(self) -> None:
        error = self.send_with(http_error(502, b"<html>bad gateway</html>"))
        self.assertIn("502", str(error))

    def test_a_shared_run_says_so(self) -> None:
        self.assertIn("unverified", upload.sharing({"ok": True, "shared": True}))

    def test_every_reason_for_keeping_a_run_private_is_explained(self) -> None:
        for reason in ("exploit_withheld", "duplicate", "review_queue_full"):
            note = upload.sharing({"ok": True, "shared": False, "not_shared": reason})
            self.assertTrue(note.startswith("kept private: "))
            self.assertNotIn(reason, note)

    def test_an_unknown_reason_is_shown_rather_than_dropped(self) -> None:
        note = upload.sharing({"shared": False, "not_shared": "something_new"})
        self.assertIn("something_new", note)

    def test_a_run_that_was_never_a_candidate_says_nothing(self) -> None:
        self.assertIsNone(upload.sharing({"ok": True, "shared": False}))


class SharingRequirementTests(unittest.TestCase):
    def test_what_sharing_requires_survives_trimming(self) -> None:
        big = "x" * (upload.MAX_PAYLOAD_BYTES // 2)
        documents = [{"name": "analysis.json", "text": big, "truncated": False},
                     {"name": "PoC.ps1", "text": big, "truncated": False}]
        documents += [{"name": name, "text": "y" * 1000, "truncated": False}
                      for name in upload.REQUIRED_TO_SHARE]
        kept, dropped = upload.fit_payload(documents)
        names = [d["name"] for d in kept]
        for name in upload.REQUIRED_TO_SHARE:
            self.assertIn(name, names)
        self.assertTrue(dropped)
        self.assertEqual(names, [d["name"] for d in documents if d["name"] in names])

    def test_a_validated_run_missing_evidence_is_warned_before_sending(self) -> None:
        payload = {
            "cve": "CVE-2024-12345", "status": "succeeded", "outcome": "VALIDATED",
            "documents": [{"name": "PoC.py", "text": "print(1)", "truncated": False}],
        }
        self.assertIn("will be refused", upload.describe(payload))
