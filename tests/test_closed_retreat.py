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

"""The one retreat `auto` makes when there is no public source to build from.

`generate_source_lab` returns ARTIFACT_REQUIRED and VENDOR_ARTIFACT_REQUIRED
rather than raising them, so each one used to end the run where it was
recorded: no second generation, no repair, not one model call for an adapter.
Measured over 40 attempts, 7.5% ended that way, byte-identically from run to
run, while the closed-software path -- which needs only a CVE and asks a
different question, about a published image rather than a repository -- sat
unused.

These tests pin the retreat's shape rather than its yield: that it fires for
exactly those two statuses, only where the configured provider can search the
web, that it is one call and not a loop, that it cannot touch the source
budget, and that a decline from it leaves the honest stop honest.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import autoflow
from cvelab.autoflow import run_auto_workflow

CVE = "CVE-2026-12345"

#: A provider with a web-search tool, and one without. Real registry entries
#: rather than a patched predicate, so these exercise the same two functions
#: `generate_source_lab` composes for source discovery.
SEARCHING = "openai"
BLIND = "deepseek"


def _stop(status: str) -> dict[str, Any]:
    """What `generate_source_lab` returns when it has no source to build from."""
    return {
        "ok": False,
        "status": status,
        "cve": CVE,
        "reason": "No public source repository and fixed commit were found.",
        "required": ["Verified public repository and immutable affected revision"],
        "evidence_urls": [],
    }


def _closed_lab(lab: Path) -> dict[str, Any]:
    """What `run_closed_lab` returns for a reproduction it proved.

    Note the absence of a "status" key: the closed path reports success
    through `ok`, and `upload` reads that as VALIDATED.
    """
    return {
        "ok": True,
        "cve": CVE,
        "lab_type": "CLOSED_SOFTWARE_HTTP_REPRODUCTION",
        "lab_dir": str(lab),
        "real_poc_verified": True,
        "manual_poc_verified": True,
        "proof_checks": {"attack_executed": True, "vulnerable_confirmed": True},
        "differential_confirmed": True,
    }


class ClosedRetreatTests(unittest.TestCase):
    def _run(
        self,
        *,
        generated: Any,
        closed: Any = None,
        provider: str = SEARCHING,
        max_attempts: int = 4,
    ) -> tuple[dict, Path, dict[str, mock.Mock]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = {
                "generate": mock.Mock(
                    side_effect=generated
                    if isinstance(generated, list)
                    else [generated] * max_attempts
                ),
                "retreat": mock.Mock(
                    side_effect=closed if isinstance(closed, list) else [closed]
                ),
                "run_lab": mock.Mock(return_value={"ok": True, "report": {}}),
                "repair": mock.Mock(
                    return_value={"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}}
                ),
            }
            with (
                mock.patch("cvelab.autoflow.generate_source_lab", calls["generate"]),
                mock.patch("cvelab.autoflow.run_closed_auto", calls["retreat"]),
                mock.patch("cvelab.autoflow.run_lab", calls["run_lab"]),
                mock.patch("cvelab.autoflow.repair_source_lab", calls["repair"]),
                mock.patch(
                    "cvelab.autoflow.create_deliverables", side_effect=lambda *a: a[2]
                ),
            ):
                result = run_auto_workflow(
                    CVE, root, None, None, None,
                    "key", "model", False,
                    max_attempts=max_attempts,
                    progress=lambda _: None,
                    provider=provider,
                )
            record = json.loads((root / CVE / "automation.json").read_text(encoding="utf-8"))
            return result, root / CVE, calls | {"record": record}

    def test_artifact_required_retreats_and_returns_the_closed_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary) / CVE
        result, lab_dir, calls = self._run(
            generated=_stop("ARTIFACT_REQUIRED"), closed=_closed_lab(lab)
        )

        calls["retreat"].assert_called_once()
        self.assertTrue(result["ok"])
        self.assertEqual(result["lab_type"], "CLOSED_SOFTWARE_HTTP_REPRODUCTION")
        self.assertEqual(
            result["automation"]["mode"], "closed_retreat_after_artifact_required"
        )
        self.assertEqual(result["automation"]["generation_status"], "ARTIFACT_REQUIRED")
        # The CVE is all the closed path needs, and it is given the operator's
        # own repo and fixed ref when there are any to pass on.
        self.assertEqual(calls["retreat"].call_args.args[0], CVE)

    def test_vendor_artifact_required_behaves_the_same_way(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary) / CVE
        result, _, calls = self._run(
            generated=_stop("VENDOR_ARTIFACT_REQUIRED"), closed=_closed_lab(lab)
        )

        calls["retreat"].assert_called_once()
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["automation"]["generation_status"], "VENDOR_ARTIFACT_REQUIRED"
        )

    def test_a_provider_that_cannot_search_the_web_does_not_retreat(self) -> None:
        """The honest stop stands, unchanged and un-annotated.

        The closed path drafts its request plan by asking a model to find a
        published image tag, port and endpoint. An endpoint with no
        web-search tool is told to return insufficient data instead, so the
        retreat would buy a model call and no answer.
        """
        result, _, calls = self._run(
            generated=_stop("ARTIFACT_REQUIRED"),
            closed=_closed_lab(Path("/nowhere")),
            provider=BLIND,
        )

        calls["retreat"].assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "ARTIFACT_REQUIRED")
        self.assertNotIn("closed_retreat", result)
        self.assertEqual(calls["record"]["status"], "ARTIFACT_REQUIRED")
        self.assertNotIn("closed_retreat", calls["record"]["failure"])

    def test_a_declining_retreat_leaves_an_honest_declined_outcome(self) -> None:
        """The population the retreat is least likely to serve answers here.

        A product with no public source usually has no public image either,
        so the resolver declines. That is the same honest "an artifact is
        required" the run already had -- it must not become a status that
        reads as a crash, and it must not become a new kind of failure for
        `upload` to file as one.
        """
        declined = {
            "ok": False,
            "status": "ARTIFACT_REQUIRED",
            "cve": CVE,
            "reason": "no publicly accessible vulnerable image tag is documented",
            "required": "A licensed local image can be registered once in closed-catalog.json",
        }
        result, _, calls = self._run(
            generated=_stop("ARTIFACT_REQUIRED"), closed=declined
        )

        calls["retreat"].assert_called_once()
        self.assertFalse(result["ok"])
        # Unchanged, and in `upload.STATUS` -- which files it "declined".
        self.assertEqual(result["status"], "ARTIFACT_REQUIRED")
        self.assertEqual(result["closed_retreat"]["status"], "ARTIFACT_REQUIRED")
        self.assertFalse(result["closed_retreat"]["ok"])
        self.assertIn("image tag", result["closed_retreat"]["reason"])

    def test_a_retreat_that_raises_is_not_a_crash(self) -> None:
        """`_ensure_image` hard-fails on a pull, which is the common ending.

        An image tag the resolver named and no registry has takes
        `docker pull` down with it, and an incomplete READY plan raises
        outright. Neither says anything new about the CVE.
        """
        result, _, calls = self._run(
            generated=_stop("ARTIFACT_REQUIRED"),
            closed=RuntimeError("docker pull failed: manifest unknown"),
        )

        calls["retreat"].assert_called_once()
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "ARTIFACT_REQUIRED")
        self.assertFalse(result["closed_retreat"]["ok"])
        self.assertIn("manifest unknown", result["closed_retreat"]["error"])

    def test_the_retreat_is_visible_in_the_record(self) -> None:
        """A second strategy nobody can tell fired is a second strategy nobody trusts."""
        declined = {"ok": False, "status": "UNSUPPORTED", "reason": "no HTTP surface"}
        _, _, calls = self._run(generated=_stop("ARTIFACT_REQUIRED"), closed=declined)

        record = calls["record"]
        phases = [attempt["phase"] for attempt in record["attempts"]]
        self.assertIn("closed_retreat", phases)
        retreat = next(a for a in record["attempts"] if a["phase"] == "closed_retreat")
        self.assertFalse(retreat["ok"])
        self.assertEqual(retreat["status"], "UNSUPPORTED")
        self.assertEqual(retreat["reason"], "no HTTP surface")
        # And in the failure block, beside the generation result it followed.
        self.assertEqual(record["failure"]["kind"], "generation_result")
        self.assertEqual(record["failure"]["closed_retreat"]["status"], "UNSUPPORTED")

    def test_the_retreat_is_visible_in_the_record_when_it_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary) / CVE
        _, _, calls = self._run(
            generated=_stop("ARTIFACT_REQUIRED"), closed=_closed_lab(lab)
        )

        record = calls["record"]
        self.assertEqual(record["status"], "VALIDATED")
        retreat = next(a for a in record["attempts"] if a["phase"] == "closed_retreat")
        self.assertTrue(retreat["ok"])

    def test_the_retreat_does_not_spend_the_source_budget(self) -> None:
        """One call, outside `max_attempts`, with no repair loop around it.

        `run_closed_auto` resolves once and runs once; it has no repair of its
        own, and the generation and repair budgets it sits beside are for a
        different lab.
        """
        result, _, calls = self._run(
            generated=_stop("ARTIFACT_REQUIRED"),
            closed={"ok": False, "status": "ARTIFACT_REQUIRED", "reason": "no image"},
            max_attempts=4,
        )

        self.assertEqual(calls["generate"].call_count, 1)
        calls["repair"].assert_not_called()
        calls["run_lab"].assert_not_called()
        calls["retreat"].assert_called_once()
        self.assertEqual(result["automation"]["max_attempts"], 4)
        # One generation attempt and one retreat: nothing else was spent.
        self.assertEqual(
            [a["phase"] for a in calls["record"]["attempts"]], ["closed_retreat"]
        )

    def test_the_other_returned_generation_stop_is_untouched(self) -> None:
        result, _, calls = self._run(generated=_stop("GENERATION_NOT_AVAILABLE"))

        calls["retreat"].assert_not_called()
        self.assertEqual(result["status"], "GENERATION_NOT_AVAILABLE")
        self.assertNotIn("closed_retreat", result)

    def test_a_source_that_cannot_be_cloned_does_not_retreat(self) -> None:
        """A different stop with a different cause: the repository is gone.

        This one is raised, not returned, and it stops the run after one
        attempt. The retreat is for a CVE that never had a public repository,
        not for one whose repository was taken away.
        """
        result, _, calls = self._run(
            generated=[RuntimeError("remote: Repository not found.")]
        )

        calls["retreat"].assert_not_called()
        self.assertEqual(result["status"], "AUTO_GENERATION_FAILED")
        self.assertEqual(calls["record"]["failure"]["kind"], "source_unavailable")

    def test_an_infrastructure_failure_does_not_retreat(self) -> None:
        result, _, calls = self._run(
            generated=[RuntimeError("ANTHROPIC_API_KEY is not set")]
        )

        calls["retreat"].assert_not_called()
        self.assertEqual(result["status"], "AUTO_GENERATION_FAILED")

    def test_exhausted_generation_attempts_do_not_retreat(self) -> None:
        result, _, calls = self._run(
            generated=[RuntimeError("compose file is not valid")] * 3, max_attempts=3
        )

        calls["retreat"].assert_not_called()
        self.assertEqual(result["status"], "AUTO_GENERATION_FAILED")
        self.assertEqual(calls["generate"].call_count, 3)

    def test_an_exhausted_repair_budget_does_not_retreat(self) -> None:
        """The retreat hangs off the generation stop and nothing else.

        A lab that generated and then could not be validated has a source
        repository; the closed path has nothing to add to it.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = {
                "ok": True,
                "status": "GENERATED_UNVALIDATED",
                "lab_dir": str(root / CVE),
                "plan": {},
            }
            with (
                mock.patch("cvelab.autoflow.generate_source_lab", return_value=generated),
                mock.patch(
                    "cvelab.autoflow.run_lab",
                    side_effect=RuntimeError("Cannot connect to the Docker daemon"),
                ),
                mock.patch("cvelab.autoflow.run_closed_auto") as retreat,
                mock.patch("cvelab.autoflow.repair_source_lab"),
            ):
                result = run_auto_workflow(
                    CVE, root, None, None, None,
                    "key", "model", False, max_attempts=2, progress=lambda _: None,
                    provider=SEARCHING,
                )

            retreat.assert_not_called()
            self.assertEqual(result["status"], "AUTO_REPAIR_EXHAUSTED")


class RetreatPredicateTests(unittest.TestCase):
    """The gate itself, apart from the workflow that calls it."""

    def test_only_the_two_no_public_source_statuses_qualify(self) -> None:
        for status in autoflow._ARTIFACT_REQUIRED_STATUSES:
            with self.subTest(status=status):
                self.assertTrue(
                    autoflow._closed_retreat_possible(status, "key", "model", SEARCHING)
                )
        for status in (
            "GENERATION_NOT_AVAILABLE",
            "AUTO_GENERATION_FAILED",
            "PROVIDER_DECLINED",
            "VALIDATED",
            "",
        ):
            with self.subTest(status=status):
                self.assertFalse(
                    autoflow._closed_retreat_possible(status, "key", "model", SEARCHING)
                )

    def test_the_provider_must_be_configured_and_able_to_search(self) -> None:
        self.assertFalse(
            autoflow._closed_retreat_possible("ARTIFACT_REQUIRED", "key", "model", BLIND)
        )
        # Configured is the other half: no model, no request to draft a plan.
        with mock.patch.dict("os.environ", {"CVELAB_MODEL": ""}, clear=False):
            self.assertFalse(
                autoflow._closed_retreat_possible(
                    "ARTIFACT_REQUIRED", "key", None, SEARCHING
                )
            )


if __name__ == "__main__":
    unittest.main()
