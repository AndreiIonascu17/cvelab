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

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from cvelab import autoflow, core, policy, sourcegen
from cvelab.ai import ProviderDeclined
from cvelab.autoflow import run_auto_workflow

UNHEALTHY = (
    "Validator startup failed: dependency failed to start: container "
    "cve-2026-12345-vulnerable-1 is unhealthy\n\nCompose diagnostics:\n"
    "docker compose logs --no-color --tail 200:\nvulnerable-1  | Error: listen EADDRINUSE"
)


class StartPeriodTests(unittest.TestCase):
    def test_compose_durations_are_read(self) -> None:
        self.assertEqual(policy.duration_seconds("2s"), 2)
        self.assertEqual(policy.duration_seconds("1m30s"), 90)
        self.assertEqual(policy.duration_seconds("500ms"), 0.5)
        self.assertEqual(policy.duration_seconds(2_000_000_000), 2)
        self.assertIsNone(policy.duration_seconds(None))
        self.assertIsNone(policy.duration_seconds("soon"))

    def test_health_checked_services_get_a_start_period(self) -> None:
        model = {"services": {
            "vulnerable": {"healthcheck": {"test": ["CMD-SHELL", "true"], "interval": "2s", "retries": 30}},
            "patched": {"healthcheck": {"test": ["CMD-SHELL", "true"], "start_period": "30s"}},
            "slow": {"healthcheck": {"test": ["CMD-SHELL", "true"], "start_period": "5m"}},
            "validator": {},
            "disabled": {"healthcheck": {"test": ["NONE"]}},
            "off": {"healthcheck": {"test": ["CMD", "true"], "disable": True}},
        }}
        override = policy.startup_grace_override(model, 120)["services"]
        self.assertEqual(override["vulnerable"], {"healthcheck": {"start_period": "120s"}})
        self.assertEqual(override["patched"], {"healthcheck": {"start_period": "120s"}})
        for name in ("slow", "validator", "disabled", "off"):
            self.assertNotIn(name, override)
        self.assertEqual(policy.startup_grace_override(model, 0), {"services": {}})

    def test_the_grace_setting_is_bounded(self) -> None:
        with mock.patch.dict(os.environ, {"CVELAB_STARTUP_GRACE": ""}):
            self.assertEqual(core.startup_grace(), 120)
        with mock.patch.dict(os.environ, {"CVELAB_STARTUP_GRACE": "0"}):
            self.assertEqual(core.startup_grace(), 0)
        for bad in ("1000", "-1", "two minutes"):
            with mock.patch.dict(os.environ, {"CVELAB_STARTUP_GRACE": bad}), self.assertRaises(ValueError):
                core.startup_grace()


class StartupRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = self.root / "CVE-2026-12345"
        self.generated = {"ok": True, "status": "GENERATED_UNVALIDATED", "lab_dir": str(self.lab), "plan": {}}
        self.repaired = {"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}}

    def run_flow(self, outcomes: list, max_attempts: int = 3, limit: str | None = None):
        env = {} if limit is None else {"CVELAB_STARTUP_REPAIRS": limit}
        with (
            mock.patch.dict(os.environ, env),
            mock.patch("cvelab.autoflow.generate_source_lab", return_value=self.generated),
            mock.patch("cvelab.autoflow.run_lab", side_effect=outcomes) as run,
            mock.patch("cvelab.autoflow.repair_source_lab", return_value=self.repaired) as repair,
            mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
        ):
            result = run_auto_workflow(
                "CVE-2026-12345", self.root, None, None, None,
                "key", "model", False, max_attempts=max_attempts, progress=lambda _: None,
            )
        return result, run, repair

    def test_a_startup_failure_is_repaired_without_spending_an_attempt(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, run, repair = self.run_flow([RuntimeError(UNHEALTHY), passed])

        self.assertTrue(result["ok"])
        self.assertEqual(run.call_count, 2)
        repair.assert_called_once()
        failure = repair.call_args.args[2]
        self.assertEqual(failure["kind"], "startup_failure")
        self.assertIn("did not become healthy", failure["hint"])
        self.assertIn("EADDRINUSE", failure["error"])
        self.assertEqual(result["automation"]["validation_attempts"], 1)
        self.assertEqual(result["automation"]["repair_calls"], 0)
        phases = [attempt["phase"] for attempt in result["automation"]["attempts"]]
        self.assertEqual(phases[:3], ["generation", "startup", "startup_repair"])

    def test_startup_repairs_are_capped_and_the_run_still_ends(self) -> None:
        result, run, repair = self.run_flow([RuntimeError(UNHEALTHY)] * 10, max_attempts=2, limit="1")

        self.assertFalse(result["ok"])
        # One free startup repair, then the ordinary path: two validations
        # and the one repair a budget of two allows.
        self.assertEqual(run.call_count, 3)
        self.assertEqual(repair.call_count, 2)
        recorded = json.loads((self.lab / "automation.json").read_text())
        phases = [attempt["phase"] for attempt in recorded["attempts"]]
        self.assertEqual(phases.count("startup_repair"), 1)

    def test_a_proof_failure_is_not_treated_as_a_startup_failure(self) -> None:
        failed = {"ok": False, "report": {"proof_checks": {"vulnerable_confirmed": False}}}
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, _run, repair = self.run_flow([failed, passed])

        self.assertTrue(result["ok"])
        self.assertEqual(repair.call_args.args[2]["kind"], "proof_not_verified")
        self.assertEqual(result["automation"]["repair_calls"], 1)


#: What a mirror that 404s a package its own index lists looks like by the
#: time it reaches the loop. Trimmed from the sentry run in
#: selected10c-2026-11-03, which spent the lab's whole repair budget
#: rewriting a Dockerfile whose apt line was already correct.
#:
#: Reproduced on 2026-11-04 in python:3.8-slim-bullseye, the lab's own base:
#: still failing a day later, so retrying is not the answer -- the pool has
#: moved to archive.debian.org and only the index stayed behind.
ARCHIVED_POOL = (
    "Docker stage 'build' failed with exit code 1\nDocker output:\n"
    "#19 3.393 Err:54 http://deb.debian.org/debian-security bullseye-security/main "
    "amd64 libnghttp2-14 amd64 1.43.0-1+deb11u3\n#19 3.393   404  Not Found "
    "[IP: 146.75.118.132 80]\n"
    "#19 3.915 E: Failed to fetch http://deb.debian.org/debian-security/pool/updates/"
    "main/p/postgresql-13/libpq5_13.23-0%2bdeb11u4_amd64.deb  404  Not Found\n"
    "#19 ERROR: process \"/bin/sh -c apt-get update && apt-get install -y "
    "--no-install-recommends -o Acquire::Retries=3 build-essential curl libpq-dev\""
)

#: The same stage failing for something that really does pass on its own:
#: a module proxy that stopped answering mid-download. The mattermost runs
#: in selected10c and selected10d both died among `go: downloading` lines.
MODULE_TIMEOUT = (
    "Docker stage 'build' failed with exit code 1\nDocker output:\n"
    "#30 1.974 go: downloading github.com/goccy/go-json v0.10.5\n"
    "#30 35.21 go: github.com/mattermost/mattermost/server/public@v0.1.13: Get "
    "\"https://proxy.golang.org/github.com/...\": dial tcp 142.250.185.17:443: "
    "i/o timeout\n"
    "#30 ERROR: process \"/bin/sh -c CGO_ENABLED=0 go build -o /out/mattermost "
    "./cmd/mattermost\" did not complete successfully: exit code: 1"
)

#: The same stage failing for a reason a model can actually answer: the
#: mattermost run in selected10d-2026-11-03, where server/ and
#: server/public/ sat at different commits in one go workspace.
VERSION_SKEW = (
    "Docker stage 'build' failed with exit code 1\nDocker output:\n"
    "#27 40.11 channels/audit/audit.go:43:18: undefined: model.AuditKeyError\n"
    "#27 40.22 einterfaces/pap.go:24:64: undefined: model.CELExpressionError\n"
    "#27 ERROR: process \"/bin/sh -c CGO_ENABLED=0 go build -o /out/mattermost "
    "./cmd/mattermost\" did not complete successfully: exit code: 1"
)


class _LoopFixture:
    """One generated lab, a scripted sequence of run_lab outcomes.

    Held apart from any TestCase so that inheriting it does not re-run
    another class's tests.
    """

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = self.root / "CVE-2026-12345"
        self.generated = {
            "ok": True, "status": "GENERATED_UNVALIDATED",
            "lab_dir": str(self.lab), "plan": {},
        }

    def run_flow(
        self,
        outcomes: list,
        max_attempts: int = 3,
        limit: str | None = None,
        repair_outcomes: list | None = None,
    ):
        """Run the loop over scripted run_lab results, and scripted repairs.

        `repair_outcomes` lets a test make the repair call itself fail, which
        is how a busy provider arrives: not as a verdict on the lab, but as
        an exception where an answer was expected.
        """
        env = {"CVELAB_TRANSIENT_PAUSE": "0"}
        if limit is not None:
            env["CVELAB_TRANSIENT_RETRIES"] = limit
        repaired = {"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}}
        repair_patch = mock.patch(
            "cvelab.autoflow.repair_source_lab",
            **(
                {"side_effect": repair_outcomes}
                if repair_outcomes is not None
                else {"return_value": repaired}
            ),
        )
        with (
            mock.patch.dict(os.environ, env),
            mock.patch("cvelab.autoflow.generate_source_lab", return_value=self.generated),
            mock.patch("cvelab.autoflow.run_lab", side_effect=outcomes) as run,
            repair_patch as repair,
            mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *args: args[2]),
        ):
            result = run_auto_workflow(
                "CVE-2026-12345", self.root, None, None, None,
                "key", "model", False, max_attempts=max_attempts, progress=lambda _: None,
            )
        return result, run, repair


class FetchFailureIsRetriedRatherThanRepairedTests(_LoopFixture, unittest.TestCase):
    """A build that never ran says nothing about the PoC.

    Three of thirty attempts over selected10b/c/d ended on a fetch the
    build needed and could not get. None was answerable by a model, and all
    three were handed to `repair_source_lab` anyway, which rewrote correct
    Dockerfiles until the budget ran out and the run was recorded
    AUTO_REPAIR_EXHAUSTED.
    """

    def test_it_is_retried_unchanged_without_spending_an_attempt(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, run, repair = self.run_flow([RuntimeError(MODULE_TIMEOUT), passed])

        self.assertTrue(result["ok"])
        self.assertEqual(run.call_count, 2)
        repair.assert_not_called()
        self.assertEqual(result["automation"]["validation_attempts"], 1)
        self.assertEqual(result["automation"]["transient_retries"], 1)
        phases = [attempt["phase"] for attempt in result["automation"]["attempts"]]
        self.assertEqual(phases, ["generation", "transient", "validation"])

    def test_the_retries_are_capped_and_the_run_still_ends(self) -> None:
        result, run, repair = self.run_flow(
            [RuntimeError(MODULE_TIMEOUT)] * 10, max_attempts=2, limit="1"
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "AUTO_REPAIR_EXHAUSTED")
        # One free retry, then the ordinary path: two validations and the
        # one repair a budget of two allows.
        self.assertEqual(run.call_count, 3)
        self.assertEqual(repair.call_count, 1)
        recorded = json.loads((self.lab / "automation.json").read_text())
        self.assertEqual(
            [a["phase"] for a in recorded["attempts"]].count("transient"), 1
        )

    def test_a_build_a_model_can_answer_still_reaches_a_repair(self) -> None:
        """The guard that keeps this from swallowing real build failures.

        Both halves of the classifier matter: this one failed in the build
        stage too, and must still be repaired.
        """
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, run, repair = self.run_flow([RuntimeError(VERSION_SKEW), passed])

        self.assertTrue(result["ok"])
        self.assertEqual(run.call_count, 2)
        repair.assert_called_once()
        self.assertEqual(repair.call_args.args[2]["kind"], "runtime_error")
        self.assertEqual(result["automation"]["transient_retries"], 0)
        self.assertEqual(result["automation"]["repair_calls"], 1)

    def test_turning_the_retries_off_restores_the_old_path(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        _result, _run, repair = self.run_flow(
            [RuntimeError(MODULE_TIMEOUT), passed], limit="0"
        )

        repair.assert_called_once()
        self.assertEqual(repair.call_args.args[2]["kind"], "runtime_error")


class AnArchivedPoolIsToldTheRemedyTests(_LoopFixture, unittest.TestCase):
    """A 404 is not worth retrying, and is not the package list's fault.

    The sentry lab failed this way in every one of the three runs and still
    fails today, so the retry above would only have delayed it. What it
    needs is the one thing the symptom does not point at: the release's
    pool has moved to archive.debian.org and only its index stayed behind.
    """

    def test_it_is_not_retried(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, _run, _repair = self.run_flow([RuntimeError(ARCHIVED_POOL), passed])

        self.assertEqual(result["automation"]["transient_retries"], 0)
        phases = [attempt["phase"] for attempt in result["automation"]["attempts"]]
        self.assertNotIn("transient", phases)

    def test_the_repair_is_told_where_the_packages_went(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        _result, _run, repair = self.run_flow([RuntimeError(ARCHIVED_POOL), passed])

        repair.assert_called_once()
        failure = repair.call_args.args[2]
        self.assertEqual(failure["kind"], "archived_suite")
        self.assertIn("archive.debian.org", failure["hint"])
        self.assertIn("index", failure["hint"])
        self.assertIn("libpq5", failure["error"])

    def test_the_hint_does_not_send_the_repair_after_the_package_list(self) -> None:
        """The whole point: the symptom is a package that cannot be found."""
        self.assertIn("Nothing in the package list is wrong", autoflow.ARCHIVE_HINT)
        self.assertIn("retrying cannot help", autoflow.ARCHIVE_HINT)


class WhatCountsAsAFailedFetchTests(unittest.TestCase):
    def test_the_three_measured_build_failures_are_told_apart(self) -> None:
        self.assertTrue(autoflow._transient_failure(MODULE_TIMEOUT))
        self.assertFalse(autoflow._archived_suite_failure(MODULE_TIMEOUT))

        self.assertTrue(autoflow._archived_suite_failure(ARCHIVED_POOL))
        self.assertFalse(autoflow._transient_failure(ARCHIVED_POOL))

        self.assertFalse(autoflow._transient_failure(VERSION_SKEW))
        self.assertFalse(autoflow._archived_suite_failure(VERSION_SKEW))

    def test_a_404_outside_a_build_is_not_an_archived_pool(self) -> None:
        self.assertFalse(autoflow._archived_suite_failure(
            "Validator failed: failed to fetch /report  404  Not Found"
        ))

    def test_only_an_archived_pool_carries_a_hint(self) -> None:
        self.assertEqual(autoflow._runtime_failure(MODULE_TIMEOUT)["kind"], "runtime_error")
        self.assertNotIn("hint", autoflow._runtime_failure(VERSION_SKEW))
        self.assertIn("hint", autoflow._runtime_failure(ARCHIVED_POOL))

    def test_the_hint_comes_before_the_output_it_explains(self) -> None:
        """`repair_source_lab` cuts the serialized failure to fit the prompt.

        The sentry run's own build output was 16170 characters against a
        12000 limit on a local provider, so a hint placed after it would be
        cut off and the repair would be back to guessing. Insertion order
        is what keeps it, which is easy to lose in a later edit.
        """
        failure = autoflow._runtime_failure(ARCHIVED_POOL + "x" * 20000)
        serialized = json.dumps(failure, ensure_ascii=True, indent=2)
        self.assertIn("archive.debian.org", serialized[:12000])
        self.assertLess(serialized.index("archive.debian.org"), serialized.index("Err:54"))

    def test_a_fetch_marker_outside_a_build_is_not_one(self) -> None:
        """A validator that cannot reach the product is a real failure.

        Without the stage half of the classifier these would be retried
        silently until the budget ran out, and the lab's own bug would
        never be put to a model.
        """
        for message in (
            "Validator failed: connection reset by peer",
            "Docker stage 'startup' failed with exit code 1: i/o timeout",
            "lab service did not become healthy: connection timed out",
        ):
            with self.subTest(message=message):
                self.assertFalse(autoflow._transient_failure(message))

    def test_a_build_that_failed_for_its_own_reasons_is_not_one(self) -> None:
        self.assertFalse(autoflow._transient_failure(
            "Docker stage 'build' failed with exit code 1: npm ERR! missing script"
        ))

    def test_the_settings_are_bounded(self) -> None:
        for raw, expected in (("", 2), ("0", 0), ("5", 5), ("99", 5), ("-1", 0), ("two", 2)):
            with mock.patch.dict(os.environ, {"CVELAB_TRANSIENT_RETRIES": raw}):
                self.assertEqual(autoflow.transient_retry_limit(), expected)
        for raw, expected in (("", 15.0), ("0", 0.0), ("300", 120.0), ("soon", 15.0)):
            with mock.patch.dict(os.environ, {"CVELAB_TRANSIENT_PAUSE": raw}):
                self.assertEqual(autoflow.transient_retry_pause(), expected)


if __name__ == "__main__":
    unittest.main()


class ValidatorKeepsItsNetworkAliasesTests(unittest.TestCase):
    """A one-off `compose run` container has no service aliases.

    9router's lab put an HTTPS canary in the validator and gave it the alias
    codewhisperer.canary.local, so the product's forged outbound request
    could be received without leaving the internal network. Run as a one-off
    container the name did not resolve -- "gaierror: Temporary failure in
    name resolution" -- and the lab was recorded Not reproduced three runs
    running. The same lab started with `up` reports
    differential_confirmed. Every lab built around a named stand-in was
    failing this way.
    """

    def _calls(self, extra: dict[str, str] | None = None) -> list[list[str]]:
        seen: list[list[str]] = []

        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            seen.append(argv)
            if "wait" in argv:
                return subprocess.CompletedProcess(argv, 0, "0\n", "")
            if "logs" in argv:
                return subprocess.CompletedProcess(argv, 0, '{"ok": true}', "noise")
            if "ps" in argv:
                return subprocess.CompletedProcess(argv, 0, "cid123\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(core.subprocess, "run", side_effect=run):
            self.outcome = core.run_validator(
                ["docker", "compose"], "docker", {"PATH": "/usr/bin"},
                Path("/lab"), extra,
            )
        return seen

    def test_it_is_started_with_up_and_recreated(self) -> None:
        argv = self._calls()[0]
        self.assertIn("up", argv)
        self.assertNotIn("run", argv)
        self.assertIn("--force-recreate", argv)
        self.assertIn("--profile", argv)

    def test_the_services_it_depends_on_are_waited_for(self) -> None:
        """A validator declares depends_on service_healthy, and that wait is
        the only thing between it and a product still booting. Skipping it
        cost a batch: "targets not ready", which reads as a lab that failed
        to reproduce."""
        self.assertNotIn("--no-deps", self._calls()[0])

    def test_the_wait_is_skipped_only_when_the_caller_knows_better(self) -> None:
        seen: list[list[str]] = []

        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            seen.append(argv)
            if "wait" in argv:
                return subprocess.CompletedProcess(argv, 0, "0", "")
            if "ps" in argv:
                return subprocess.CompletedProcess(argv, 0, "cid123", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(core.subprocess, "run", side_effect=run):
            core.run_validator(
                ["docker", "compose"], "docker", {}, Path("/lab"), None,
                wait_for_services=False,
            )
        self.assertIn("--no-deps", seen[0])

    def test_the_exit_code_and_both_streams_come_back(self) -> None:
        self._calls()
        self.assertEqual(self.outcome, (0, '{"ok": true}', "noise"))

    def test_the_manual_interface_travels_in_the_environment(self) -> None:
        """`up` has no -e, and the compose file declares both as ${...}."""
        passed: list[dict[str, str]] = []

        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "up" in argv:
                passed.append(dict(kwargs.get("env") or {}))
            if "wait" in argv:
                return subprocess.CompletedProcess(argv, 0, "0", "")
            if "ps" in argv:
                return subprocess.CompletedProcess(argv, 0, "cid123", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(core.subprocess, "run", side_effect=run):
            core.run_validator(
                ["docker", "compose"], "docker", {"PATH": "/usr/bin"}, Path("/lab"),
                {"CVELAB_MANUAL_ACTION": "verify", "CVELAB_TARGET": "patched"},
            )
        self.assertEqual(passed[0]["CVELAB_MANUAL_ACTION"], "verify")
        self.assertEqual(passed[0]["CVELAB_TARGET"], "patched")
        self.assertEqual(passed[0]["PATH"], "/usr/bin")

    def test_no_container_id_is_an_error_rather_than_a_silent_pass(self) -> None:
        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "ps" in argv:
                return subprocess.CompletedProcess(argv, 0, "\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(core.subprocess, "run", side_effect=run):
            with self.assertRaises(RuntimeError) as refused:
                core.run_validator(
                    ["docker", "compose"], "docker", {}, Path("/lab"), None
                )
        self.assertIn("no container id", str(refused.exception))


class HarnessIsVisibleInTheLabelTests(unittest.TestCase):
    """Whether the product's own server ran is the reader's business.

    Measured over 62 reproduced labs: of the 27 that started the product, 3
    handed over a manual PoC; of the 35 that stood in for it with an
    adapter, 1 did. A lab that reaches the weakness through a harness proves
    the CVE through a route the product does not serve, so the finding
    cannot be shown on anyone's deployment -- and the differential passes
    all the same, which is why the label has to say it.
    """

    def test_a_harness_lab_says_so(self) -> None:
        said = core.evidence_label(
            "SOURCE_REPRODUCTION", True, False, through_harness=True
        )
        self.assertIn("through a lab harness", said)
        self.assertIn("product's own server", said)

    def test_the_product_s_own_server_adds_nothing_to_read(self) -> None:
        said = core.evidence_label("SOURCE_REPRODUCTION", True, False)
        self.assertEqual(said, "Reproduced, differential against the fixed build")

    def test_it_sits_before_the_manual_poc_clause(self) -> None:
        said = core.evidence_label(
            "SOURCE_REPRODUCTION", True, True, through_harness=True
        )
        self.assertTrue(said.endswith("manual PoC proven"))
        self.assertIn("through a lab harness", said)

    def test_a_run_that_did_not_reproduce_says_only_that(self) -> None:
        self.assertEqual(
            core.evidence_label("SOURCE_REPRODUCTION", False, False, True),
            "Not reproduced",
        )

    def test_a_lab_with_no_fixed_build_keeps_both_clauses(self) -> None:
        said = core.evidence_label(
            "VULNERABLE_ONLY_REPRODUCTION", True, False, through_harness=True
        )
        self.assertIn("no fixed build available", said)
        self.assertIn("through a lab harness", said)


#: What git says when the repository is not there. Taken verbatim from
#: CVE-2026-28795 in the run of 2026-11-04, whose upstream had been removed.
SOURCE_GONE = (
    "git clone --filter=blob:none --no-checkout failed: Cloning into "
    "'/labs/.source-cache/3aa6e4f8c344d098'...\n"
    "remote: Repository not found.\n"
    "fatal: repository 'https://github.com/zhongyu09/openchatbi.git/' not found"
)


class ADeletedUpstreamIsNotRetriedTests(unittest.TestCase):
    """A source that is gone stops generation instead of using up its budget.

    The measured cost was four seconds, so this is not about time. It is
    that four identical attempts put the cause four records back and leave
    the artifact saying only `generation_error`, which reads like the model
    failing when nothing was ever asked of it.
    """

    def test_a_missing_repository_is_recognised(self) -> None:
        self.assertTrue(autoflow._source_unavailable_failure(SOURCE_GONE))

    def test_it_is_named_rather_than_lumped_in(self) -> None:
        failure = autoflow._generation_failure(SOURCE_GONE)
        self.assertEqual(failure["kind"], "source_unavailable")
        self.assertIn("openchatbi", failure["error"])

    def test_a_private_repository_reads_the_same_way(self) -> None:
        """GitHub hides a private repository behind the same words.

        Whether it was deleted or merely closed to this run does not change
        what asking again achieves.
        """
        self.assertTrue(
            autoflow._source_unavailable_failure("remote: Repository not found.")
        )

    def test_an_ordinary_generation_failure_keeps_its_kind(self) -> None:
        failure = autoflow._generation_failure("the model returned no plan.json")
        self.assertEqual(failure["kind"], "generation_error")

    def test_a_network_blip_on_the_clone_is_not_this(self) -> None:
        """A name server having a bad minute is a different problem.

        It is worth retrying, so it must not reach the branch that stops.
        """
        self.assertFalse(autoflow._source_unavailable_failure(
            "git clone failed: fatal: unable to access "
            "'https://github.com/x/y.git/': Could not resolve host: github.com"
        ))

    def test_a_missing_file_inside_a_clone_is_not_this(self) -> None:
        """`not found` is a common word; the repository has to be the subject."""
        self.assertFalse(autoflow._source_unavailable_failure(
            "setup.py not found in the checkout"
        ))


class TheArchiveHintDoesNotSendTheBuildToAnInventedTagTests(unittest.TestCase):
    """The hint's own advice cost a lab, which is why this is pinned.

    Written on 2026-11-03, the hint offered moving to a base image on a
    supported release as the better alternative. CVE-2023-39349 took it on
    2026-11-04 and reached for python:3.8.16-bookworm, which has never
    existed, because python 3.8 went end of life before bookworm shipped.
    The build died on the tag instead of on the archive, so the advice was
    not merely useless for this population -- it is the population where it
    cannot work.

    The paragraph explaining the analogy has since moved to BASE_IMAGE_HINT,
    which is shown to the run that did invent a tag; here it was shown only
    to the run that had not yet. ARCHIVE_HINT keeps the refusal, so both
    halves stay pinned: the refusal below, the mechanism where it now lives.
    """

    def test_it_no_longer_recommends_changing_the_base_image(self) -> None:
        hint = autoflow.ARCHIVE_HINT
        self.assertIn("Do not reach for a newer base image", hint)

    def test_it_says_why_the_analogy_fails(self) -> None:
        hint = autoflow.BASE_IMAGE_HINT
        self.assertIn("python:3.8.16-bookworm", hint)
        self.assertIn("never had a bookworm image", hint)

    def test_the_remedy_is_still_the_first_thing_said(self) -> None:
        """The archive redirect is the fix; the warning must not bury it."""
        hint = autoflow.ARCHIVE_HINT
        self.assertLess(
            hint.index("archive.debian.org"),
            hint.index("Do not reach for a newer base image"),
        )


#: What the provider returns when it is too busy, verbatim from the run of
#: 2026-11-04, where it cost one CVE two of its four repair attempts.
PROVIDER_OVERLOADED = (
    'Anthropic API HTTP 503: {"type":"error","error":{"type":"overloaded_error",'
    '"message":"Service temporarily unavailable. Please try again later."},'
    '"request_id":"req_011Cgi1WbfPjtj533d3m78At"}'
)


class ABusyProviderIsNotAFailedRepairTests(_LoopFixture, unittest.TestCase):
    """A provider that could not answer has said nothing about the lab.

    It used to cost a repair attempt and, worse, become the next prompt's
    `previous_failure`, pushing the real evidence a level deeper for a
    message that describes the API rather than the lab.
    """

    def test_the_attempt_is_given_back(self) -> None:
        unproven = {
            "ok": False,
            "report": {"proof_checks": {"manual_poc_verified": False}},
            "error": "the effect did not show",
        }
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, _run, repair = self.run_flow(
            [unproven, passed],
            repair_outcomes=[
                RuntimeError(PROVIDER_OVERLOADED),
                {"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}},
            ],
        )

        self.assertTrue(result["ok"])
        # Asked twice, but only the answering call counted against the budget.
        self.assertEqual(repair.call_count, 2)
        self.assertEqual(result["automation"]["repair_calls"], 1)
        self.assertEqual(result["automation"]["provider_stalls"], 1)

    def test_the_real_failure_is_what_the_next_prompt_still_carries(self) -> None:
        """The API's complaint must not displace the evidence.

        The second repair call has to receive the lab's own failure, not a
        wrapper whose `repair_error` is an HTTP status.
        """
        unproven = {
            "ok": False,
            "report": {"proof_checks": {"manual_poc_verified": False}},
            "error": "the effect did not show",
        }
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        _result, _run, repair = self.run_flow(
            [unproven, passed],
            repair_outcomes=[
                RuntimeError(PROVIDER_OVERLOADED),
                {"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}},
            ],
        )

        handed = repair.call_args_list[1].args[2]
        self.assertNotEqual(handed.get("kind"), "repair_generation_error")
        self.assertNotIn("overloaded_error", json.dumps(handed))

    def test_a_stall_is_recorded_under_its_own_phase(self) -> None:
        unproven = {
            "ok": False,
            "report": {"proof_checks": {"manual_poc_verified": False}},
            "error": "the effect did not show",
        }
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        self.run_flow(
            [unproven, passed],
            repair_outcomes=[
                RuntimeError(PROVIDER_OVERLOADED),
                {"ok": True, "status": "REPAIRED_UNVALIDATED", "plan": {}},
            ],
        )
        written = json.loads((self.lab / "automation.json").read_text())
        phases = [entry.get("phase") for entry in written["attempts"]]
        self.assertIn("provider_busy", phases)

    def test_a_refused_key_still_stops_the_run(self) -> None:
        """401 and 404 are not this: the request is wrong, so asking again is too."""
        self.assertFalse(
            autoflow._provider_unavailable_failure("Anthropic API HTTP 401: invalid key")
        )
        self.assertFalse(
            autoflow._provider_unavailable_failure("Anthropic API HTTP 404: no such model")
        )

    def test_the_statuses_that_mean_ask_again_are_recognised(self) -> None:
        for status in (429, 500, 502, 503, 504, 529):
            with self.subTest(status=status):
                self.assertTrue(
                    autoflow._provider_unavailable_failure(
                        f"Anthropic API HTTP {status}: busy"
                    )
                )


class AnUnusableRevisionPairIsRecognisedBeforeGeneratingTests(unittest.TestCase):
    """Two snapshots of the same program cannot show a fix.

    Measured on 2026-11-04: one pair's only difference was README.zh.md, so
    the file the advisory names was byte-identical in both. The attack ran,
    the effect appeared on both services, and five repairs were spent asking
    for a differential the inputs forbade. The check is deterministic and
    needs no model, so it belongs before the first token is spent.

    What such a pair then costs is settled in the class below: it is demoted,
    not refused. These are the two predicates that decide which pair it is.
    """

    def test_the_measured_pair_is_recognised(self) -> None:
        self.assertTrue(sourcegen._only_prose_changed(["README.zh.md"]))

    def test_documentation_and_a_changelog_are_prose(self) -> None:
        self.assertTrue(
            sourcegen._only_prose_changed(["docs/security.rst", "CHANGELOG", "NOTICE"])
        )

    def test_a_translation_cannot_carry_a_fix(self) -> None:
        self.assertTrue(sourcegen._only_prose_changed(["locale/ro.po"]))

    def test_code_is_not_prose(self) -> None:
        self.assertFalse(sourcegen._only_prose_changed(["pkg/tools/shell.go"]))

    def test_prose_beside_code_is_still_a_real_fix(self) -> None:
        self.assertFalse(
            sourcegen._only_prose_changed(["README.md", "pkg/tools/shell.go"])
        )

    def test_a_dependency_bump_is_a_real_fix(self) -> None:
        """The commonest fix of all must never be mistaken for prose."""
        for files in (["go.mod", "go.sum"], ["package.json"], ["requirements.txt"]):
            with self.subTest(files=files):
                self.assertFalse(sourcegen._only_prose_changed(files))

    def test_a_policy_or_template_change_is_a_real_fix(self) -> None:
        self.assertFalse(sourcegen._only_prose_changed(["config/policy.yaml"]))

    def test_the_extension_decides_and_a_directory_prefix_does_not(self) -> None:
        """A prefix rule read everything under docs/ and .github/ as prose.

        Each of these is a program, and a fix confined to one is a real fix:
        a workflow whose command injection is a vulnerability shape in its
        own right, a Sphinx configuration that is executed Python, a release
        script, a documented example server, and a Dockerfile. Measured on
        this project's own corpus, the prefix rule demoted one pair for a
        change confined to a single workflow file.
        """
        for path in (
            ".github/workflows/release.yml",
            ".github/workflows/ci.yml",
            ".github/scripts/release.py",
            ".github/dependabot.yml",
            "docs/conf.py",
            "docs/Dockerfile",
            "doc/examples/server.py",
        ):
            with self.subTest(path=path):
                self.assertFalse(sourcegen._only_prose_changed([path]))

    def test_a_prose_stem_under_a_code_extension_is_code(self) -> None:
        """Taking the text before the FIRST dot made these prose.

        A license check is where a license-activation auth bypass lives, a
        migration is where a permission change lands, and a template is
        where output encoding lives. The comment above the stem list says a
        template, policy or migration change is a real fix; the split
        contradicted it.
        """
        for path in (
            "src/license.php",
            "db/changes.sql",
            "templates/notice.html",
            "pkg/changes.go",
            "src/notice.ts",
            "lib/authors.rb",
            "app/contributors.jsx",
        ):
            with self.subTest(path=path):
                self.assertFalse(sourcegen._only_prose_changed([path]))

    def test_a_prose_stem_with_no_extension_or_a_plain_text_one_is_prose(self) -> None:
        """What the stem list is actually for, and all it is for."""
        for path in ("LICENSE", "NOTICE", "AUTHORS", "CHANGES", "LICENSE.txt"):
            with self.subTest(path=path):
                self.assertTrue(sourcegen._only_prose_changed([path]))

    def test_the_kinds_of_fix_that_must_keep_their_differential(self) -> None:
        """Over-triggering turns a success into a weaker lab, which costs more.

        Under-triggering costs one run's budget on a pair that was already
        lost; over-triggering costs a differential that would have worked.
        Test-only, lockfile-only and vendored-bump-only fixes are the three
        shapes nearest the boundary.
        """
        for files in (
            ["tests/test_parser.py"],
            ["src/parser_test.go"],
            ["package-lock.json"],
            ["yarn.lock"],
            ["Cargo.lock"],
            ["vendor/github.com/x/y/parse.go"],
            ["go.mod", "go.sum", "vendor/modules.txt"],
        ):
            with self.subTest(files=files):
                self.assertFalse(sourcegen._only_prose_changed(files))

    def test_the_reason_says_what_the_classifier_can_actually_know(self) -> None:
        """It reads names, never contents, so it cannot speak about compiling.

        The old sentence said "both snapshots compile the same program". For
        the corpus pair demoted over a workflow file the verdict was right --
        that pair did burn its budget twice -- and the sentence was untrue of
        the file it was about. What the names do establish is that nothing
        the program is built from changed.
        """
        reason = sourcegen._unusable_pair(["README.zh.md", "docs/security.rst"]) or ""
        self.assertIn("nothing the program is built from changed", reason)
        self.assertNotIn("compile", reason)
        self.assertIn("README.zh.md", reason)
        self.assertIn("docs/security.rst", reason)

    def test_a_long_list_of_changed_files_says_how_many_it_left_out(self) -> None:
        """The cut was silent, so a sixty-file pair read as a ten-file one.

        These are repository paths out of an untrusted diff and they reach
        the prompt, plan.json and REPORT.md, where understating what was
        looked at is the one thing the sentence must not do.
        """
        reason = sourcegen._unusable_pair([f"docs/page{n}.md" for n in range(60)]) or ""
        self.assertIn("docs/page9.md", reason)
        self.assertNotIn("docs/page10.md", reason)
        self.assertIn("and 50 more", reason)
        # Ten exactly is not a cut, so it must not claim one.
        self.assertNotIn(
            "more", sourcegen._unusable_pair([f"p{n}.md" for n in range(10)]) or ""
        )

    def test_nothing_changed_is_not_prose(self) -> None:
        """Zero changed files is the other condition, and must not borrow this one.

        `_only_prose_changed` has no data to judge, so it says no, and an
        identical pair used to pass the guard untouched because of it.
        """
        self.assertFalse(sourcegen._only_prose_changed([]))
        self.assertTrue(sourcegen._pair_is_identical([]))

    def test_an_identical_pair_and_a_prose_pair_are_told_apart(self) -> None:
        """Different mistakes, so different sentences for the operator to act on."""
        identical = sourcegen._unusable_pair([])
        prose = sourcegen._unusable_pair(["README.zh.md"])
        self.assertIn("resolve to the same tree", identical or "")
        self.assertIn("nothing the program is built from changed", prose or "")
        self.assertIn("README.zh.md", prose or "")
        self.assertFalse(sourcegen._pair_is_identical(["README.zh.md"]))

    def test_either_reason_ends_with_the_one_thing_to_do_about_it(self) -> None:
        """The whole of the abort message this replaced, and it went missing.

        A reason that explains the cause and names no remedy leaves a batch
        operator reading a corpus of them with nothing to act on, and for
        both kinds of unusable pair the action is the same.
        """
        for files in ([], ["README.zh.md"]):
            with self.subTest(files=files):
                self.assertIn(
                    "the fixing reference in hand is not the fix, so resolve it again",
                    sourcegen._unusable_pair(files) or "",
                )

    def test_a_usable_pair_has_no_reason_to_give(self) -> None:
        self.assertIsNone(sourcegen._unusable_pair(["pkg/tools/shell.go"]))

    def test_no_abort_path_is_left_for_a_pair_that_is_now_demoted(self) -> None:
        """The disposition moved, so the classifier that stopped the run is gone.

        Generation and repair both demote such a pair, so nothing raises the
        message this used to recognise; a surviving abort kind for it would
        be a second, contradictory answer to the same input.
        """
        self.assertFalse(hasattr(autoflow, "_revision_pair_failure"))
        self.assertEqual(
            autoflow._generation_failure(
                "The revision pair cannot show this fix: only prose changed"
            )["kind"],
            "generation_error",
        )


def _git(repository: Path, *arguments: str) -> str:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    return subprocess.run(
        ["git", *arguments], cwd=repository, check=True, capture_output=True, text=True,
        env=environment,
    ).stdout.strip()


#: Every field both adapter contracts audit, in one string: the differential
#: side wants blocked, the vulnerable-only side wants patched_tested and
#: fix_status, and naming all of them keeps one answer usable for both.
_VALIDATOR = " ".join([
    "attack_executed", "proof_quality", "observable_effect", "evidence_type",
    "vulnerable", "patched", "patched_tested", "fix_status",
    "differential_confirmed", "confirmed", "blocked", "observations",
    "CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "exploit", "verify",
])

_VULNERABLE_ONLY_COMPOSE = """services:
  vulnerable:
    build:
      context: .
      dockerfile: vulnerable/Dockerfile
  validator:
    build:
      context: ./validator
      dockerfile: Dockerfile
networks:
  labnet:
    internal: true
"""

_DIFFERENTIAL_COMPOSE = """services:
  vulnerable:
    build:
      context: .
      dockerfile: vulnerable/Dockerfile
  patched:
    build:
      context: .
      dockerfile: patched/Dockerfile
  validator:
    build:
      context: ./validator
      dockerfile: Dockerfile
networks:
  labnet:
    internal: true
"""


def _generation(vulnerable_only: bool) -> dict:
    answer = {
        "cwe": "CWE-88",
        "confidence": 0.6,
        "rationale": "r",
        "fidelity": {
            "execution_level": "source_component",
            "vendor_product_started": False,
            "exercised_vendor_components": ["app/main.go"],
            "simulated_components": [],
            "rationale": "r",
        },
        "exploit_contract": {
            "attack_summary": "a", "preconditions": [], "observable_effect": "e",
            "evidence_type": "code_execution",
            # As above: usable for both schemas, so it meets the
            # vulnerable-only substance rule rather than only the
            # differential one.
            "effect_predicate": {"body_contains": "shell-ran"},
        },
        "docker_compose": (
            _VULNERABLE_ONLY_COMPOSE if vulnerable_only else _DIFFERENTIAL_COMPOSE
        ),
        "dockerignore": "",
        "vulnerable_dockerfile": "FROM scratch\n",
        "validator_dockerfile": "FROM scratch\n",
        "validator_py": _VALIDATOR,
        "support_services": [],
        "adapter_files": [],
    }
    if not vulnerable_only:
        answer["patched_dockerfile"] = "FROM scratch\n"
    return answer


class _PreflightPassed(RuntimeError):
    """Stands in for prepare_compose: reaching it means the preflight passed."""


#: One commit per shape the taxonomy has to tell apart, each touching exactly
#: one file so that the diff between neighbouring commits is that file alone.
#: Three of the four are programs the prefix rule read as prose: a workflow, a
#: Sphinx configuration that is executed Python, and a license check beside a
#: migration whose stems the first-dot split read as prose.
_SHAPES = (
    ("workflow_fix", ".github/workflows/release.yml", "run: echo ${{ inputs.name | quote }}\n"),
    ("license_fix", "src/license.php", "<?php verify_signature($key); ?>\n"),
    ("migration_fix", "db/changes.sql", "REVOKE ALL ON secrets FROM public;\n"),
    ("docs_conf_fix", "docs/conf.py", "extensions = ['safe_ext']\n"),
    ("doc_prose_fix", "docs/security.rst", "Report issues privately.\n"),
)


class _UnusablePairLab:
    """A real repository and a fake model, shared by the classes below.

    Driven through generate_source_lab rather than the predicate, because the
    demotion is not one branch: it is the fixing reference, the schema, the
    prompt, the plan and the patched snapshot on disk, and a test of the
    predicate alone would pass for every arrangement of those.
    """

    URL = "https://github.com/example/widget.git"
    CVE = "CVE-2026-0002"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        cache = self.root / ".source-cache" / hashlib.sha256(self.URL.encode()).hexdigest()[:16]
        cache.mkdir(parents=True)
        _git(cache, "init", "-q")
        (cache / "app").mkdir()
        (cache / "app" / "main.go").write_text("package main\n\nfunc shell(s string) {}\n")
        (cache / "README.zh.md").write_text("the old translation\n")
        for _name, path, _fixed in _SHAPES:
            target = cache / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("the affected revision\n")
        _git(cache, "add", "-A")
        _git(cache, "commit", "-qm", "affected")
        self.affected = _git(cache, "rev-parse", "HEAD")
        (cache / "README.zh.md").write_text("the new translation\n")
        _git(cache, "commit", "-qam", "translate the README")
        self.prose_only = _git(cache, "rev-parse", "HEAD")
        (cache / "app" / "main.go").write_text(
            "package main\n\nfunc shell(s string) { quote(s) }\n"
        )
        _git(cache, "commit", "-qam", "quote the argument")
        self.real_fix = _git(cache, "rev-parse", "HEAD")
        # Each shape's commit, and the revision just before it, so a test can
        # ask for a pair whose only difference is that one file.
        self.shapes: dict[str, tuple[str, str]] = {}
        previous = self.real_fix
        for name, path, fixed in _SHAPES:
            (cache / path).write_text(fixed)
            _git(cache, "commit", "-qam", f"change {path}")
            revision = _git(cache, "rev-parse", "HEAD")
            self.shapes[name] = (previous, revision)
            previous = revision

        self.schemas: list[str] = []
        self.prompts: list[str] = []
        real_git = sourcegen._run_git

        def offline_git(arguments, cwd=None, binary=False):
            if arguments[0] in {"clone", "fetch"}:
                return ""
            return real_git(arguments, cwd=cwd, binary=binary)

        self.resolve = mock.Mock(return_value=(self.URL, self.prose_only))
        patches = [
            mock.patch.object(sourcegen, "_run_git", side_effect=offline_git),
            mock.patch.object(
                sourcegen,
                "collect_cve",
                return_value={
                    "cve": self.CVE,
                    "descriptions": ["an argument reaches a shell unquoted"],
                    "references": [],
                },
            ),
            mock.patch.object(sourcegen, "resolve_source", self.resolve),
            mock.patch.object(sourcegen, "_enforce_compose_policy"),
            mock.patch.object(sourcegen.releases, "find_releases", return_value=[]),
            # Every pair is verified now, and the affected-version half of
            # that reads GitHub's advisory and lists the repository's tags.
            # The repository here is a temp directory, so there is nothing to
            # ask the network about and nothing to wait on when it is absent.
            mock.patch.object(sourcegen.revisions, "release_pair", return_value=None),
            mock.patch.object(sourcegen, "structured_response", side_effect=self.model),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def model(self, **kwargs) -> dict:
        self.schemas.append(kwargs["schema_name"])
        self.prompts.append(kwargs["input_text"])
        return _generation(kwargs["schema"] is sourcegen.VULNERABLE_ONLY_SCHEMA)

    def generate(self, fixed: str, vulnerable: str) -> dict:
        self.resolve.return_value = (self.URL, fixed)
        return sourcegen.generate_source_lab(
            self.CVE, self.root, None, fixed, vulnerable, "key", "model", "anthropic", None,
            research_mode="off",
        )


@unittest.skipUnless(shutil.which("git"), "git is required")
class AnUnusableRevisionPairBecomesAVulnerableOnlyLabTests(
    _UnusablePairLab, unittest.TestCase
):
    """A pair that cannot show the fix is demoted, not refused.

    README says the principle under Limitations: the absence of a public fix
    does not prevent a PoC against the vulnerable version, but it prevents
    differential validation of remediation. A pair whose diff is prose, or
    empty, leaves precisely that situation, so the run goes on as a
    vulnerable-only lab rather than ending with nothing to show.
    """

    def test_which_shapes_keep_their_differential_end_to_end(self) -> None:
        """The taxonomy decided by generation, not by the predicate alone.

        A prefix rule read everything under `.github/` and `docs/` as prose,
        and a first-dot split read `src/license.php` and `db/changes.sql` as
        prose, so all four of these were demoted. Each is a place a real fix
        lands -- workflow command injection, a license-activation auth
        bypass, a permission migration, an executed Sphinx configuration --
        and over-triggering is the expensive direction, because it turns a
        lab that would have proved a difference into one that cannot.
        """
        for name, kept in (
            ("workflow_fix", True),
            ("license_fix", True),
            ("migration_fix", True),
            ("docs_conf_fix", True),
            ("doc_prose_fix", False),
        ):
            with self.subTest(shape=name):
                vulnerable, fixed = self.shapes[name]
                self.schemas.clear()
                result = self.generate(fixed, vulnerable)
                plan = result["plan"]
                if kept:
                    self.assertEqual(self.schemas, ["cvelab_source_adapter"])
                    self.assertEqual(plan["lab_type"], "SOURCE_REPRODUCTION")
                    self.assertEqual(plan["revisions"]["patched"], fixed)
                    self.assertNotIn("demotion", plan)
                else:
                    self.assertEqual(self.schemas, ["cvelab_vulnerable_only_adapter"])
                    self.assertEqual(plan["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
                    reason = plan["demotion"]["reason"]
                    # Accurate for this shape: the one changed file is an
                    # .rst, and the claim is about what the program is built
                    # from rather than about compiling anything.
                    self.assertIn("docs/security.rst", reason)
                    self.assertIn("nothing the program is built from changed", reason)
                    self.assertNotIn("compile", reason)
                    self.assertIn("resolve it again", reason)

    def test_a_byte_identical_pair_no_longer_slips_through(self) -> None:
        """The same reference twice: zero changed files, and today a differential.

        `_only_prose_changed` returns False for an empty list, on purpose, so
        the guard that refused the prose pair never looked at this one and it
        reached generation as a pair of identical snapshots.
        """
        result = self.generate(self.prose_only, self.prose_only)

        self.assertEqual(self.schemas, ["cvelab_vulnerable_only_adapter"])
        plan = result["plan"]
        self.assertTrue(result["ok"])
        self.assertEqual(plan["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
        self.assertIsNone(plan["revisions"]["patched"])
        self.assertEqual(plan["demotion"]["rejected_fixed"], self.prose_only)
        self.assertIn("resolve to the same tree", plan["demotion"]["reason"])

    def test_a_prose_only_pair_is_demoted_rather_than_aborted(self) -> None:
        result = self.generate(self.prose_only, self.affected)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "GENERATED_UNVALIDATED")
        self.assertEqual(result["fix_status"], "PUBLIC_FIX_NOT_IDENTIFIED")
        self.assertIn("README.zh.md", result["plan"]["demotion"]["reason"])
        self.assertEqual(result["plan"]["patched_tested"], False)

    def test_a_demoted_lab_asks_for_the_vulnerable_only_contract(self) -> None:
        """Not only the schema: the prompt must stop describing a differential."""
        self.generate(self.prose_only, self.affected)

        self.assertEqual(self.schemas, ["cvelab_vulnerable_only_adapter"])
        self.assertNotIn("cvelab_source_adapter", self.schemas)
        self.assertIn("--- FIX STATUS ---", self.prompts[-1])
        self.assertIn("resolved and then discarded", self.prompts[-1])

    def test_the_demotion_reason_is_where_the_report_reads_it(self) -> None:
        """plan.json, and in the field deliverables prints verbatim.

        A demoted lab that said only "no public fixed revision was
        identified" would report the one thing that did not happen: the fix
        was identified, and then found unable to show itself.
        """
        result = self.generate(self.prose_only, self.affected)
        lab = self.root / self.CVE
        written = json.loads((lab / "plan.json").read_text())

        self.assertEqual(written["demotion"], result["plan"]["demotion"])
        self.assertEqual(written["fix_status"], "PUBLIC_FIX_NOT_IDENTIFIED")
        self.assertIn(
            "nothing the program is built from changed", written["safety"]["limitations"]
        )
        self.assertIn("resolved and then discarded", written["safety"]["limitations"])
        # The validator reads its own copy, and the two must not disagree.
        beside = json.loads((lab / "validator" / "plan.json").read_text())
        self.assertEqual(beside["demotion"], written["demotion"])

    def test_a_real_code_change_is_left_alone(self) -> None:
        """The guard against over-triggering: one changed .go file is a fix."""
        result = self.generate(self.real_fix, self.prose_only)
        plan = result["plan"]
        lab = self.root / self.CVE

        self.assertEqual(self.schemas, ["cvelab_source_adapter"])
        self.assertEqual(plan["lab_type"], "SOURCE_REPRODUCTION")
        self.assertEqual(plan["revisions"]["patched"], self.real_fix)
        self.assertNotIn("demotion", plan)
        self.assertTrue((lab / "source" / "patched").is_dir())
        self.assertTrue((lab / "source" / ".patched.revision").is_file())
        self.assertTrue((lab / "patched" / "Dockerfile").is_file())

    def test_the_disk_a_demotion_leaves_is_the_lab_the_plan_describes(self) -> None:
        """The patched snapshot is extracted before the pair is judged.

        core.run_lab does not ask a vulnerable-only lab for it, so a stale
        source/patched would never be complained about -- it would simply sit
        there contradicting plan.json, and its .patched.revision stamp would
        make the next run with a real fixing commit skip the extraction.
        """
        self.generate(self.prose_only, self.affected)
        lab = self.root / self.CVE

        self.assertFalse((lab / "source" / "patched").exists())
        self.assertFalse((lab / "source" / ".patched.revision").exists())
        self.assertFalse((lab / "patched").exists())
        self.assertTrue((lab / "source" / "vulnerable").is_dir())
        self.assertTrue((lab / "source" / ".vulnerable.revision").is_file())
        with mock.patch.object(core, "prepare_compose", side_effect=_PreflightPassed):
            with self.assertRaises(_PreflightPassed):
                core.run_lab(self.CVE, self.root, keep=False)

    def test_a_repair_demotes_too_rather_than_asking_again_forever(self) -> None:
        """Generation no longer writes such a plan, but an older run did.

        Raising here instead would be the worst of both: generation demotes
        this very pair, and autoflow turns a repair exception into
        `repair_generation_error` and asks again, so every remaining repair
        would go on an answer that cannot change. The plan is rewritten
        whole, which is what makes demoting here honest rather than partial.
        """
        self.generate(self.real_fix, self.prose_only)
        lab = self.root / self.CVE
        plan_path = lab / "plan.json"
        stale = json.loads(plan_path.read_text())
        stale["revisions"] = {"vulnerable": self.affected, "patched": self.prose_only}
        plan_path.write_text(json.dumps(stale, indent=2) + "\n")

        repaired = sourcegen.repair_source_lab(
            self.CVE, self.root, {"kind": "effect_not_observed"}, 1, "key", "model",
            "anthropic", None, research_mode="off",
        )

        plan = repaired["plan"]
        self.assertEqual(plan["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
        self.assertIsNone(plan["revisions"]["patched"])
        self.assertEqual(plan["fix_status"], "PUBLIC_FIX_NOT_IDENTIFIED")
        self.assertEqual(plan["patched_tested"], False)
        self.assertIn("README.zh.md", plan["demotion"]["reason"])
        self.assertEqual(plan["demotion"]["rejected_fixed"], self.prose_only)
        self.assertIn("resolved and then discarded", plan["safety"]["limitations"])
        self.assertEqual(plan["startup_services"], ["vulnerable"])
        self.assertFalse((lab / "source" / "patched").exists())
        self.assertFalse((lab / "patched").exists())
        self.assertEqual(json.loads(plan_path.read_text())["demotion"], plan["demotion"])
        with mock.patch.object(core, "prepare_compose", side_effect=_PreflightPassed):
            with self.assertRaises(_PreflightPassed):
                core.run_lab(self.CVE, self.root, keep=False)


class ADemotionIsVisibleToABatchTests(unittest.TestCase):
    """automation.json is the file a batch operator reads, so it has to say.

    A demoted generation returns ok and GENERATED_UNVALIDATED, exactly like
    one that kept its differential, and the record held nothing else: the one
    line announcing the demotion goes to stderr through progress.step, which
    CVELAB_QUIET silences. On a corpus of 190 pairs that left no
    machine-readable trace of which labs lost their differential or why.
    """

    CVE = "CVE-2026-12345"
    DEMOTION = {
        "rejected_fixed": "c" * 40,
        "reason": "between the vulnerable and the fixed revision nothing the program "
        "is built from changed (README.zh.md); the fixing reference in hand is not "
        "the fix, so resolve it again",
    }

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = self.root / self.CVE

    def run_flow(self, plan: dict) -> dict:
        generated = {
            "ok": True,
            "status": "GENERATED_UNVALIDATED",
            "lab_dir": str(self.lab),
            "plan": plan,
        }
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        with (
            mock.patch("cvelab.autoflow.generate_source_lab", return_value=generated),
            mock.patch("cvelab.autoflow.run_lab", return_value=passed),
            mock.patch("cvelab.autoflow.create_deliverables", side_effect=lambda *a: a[2]),
        ):
            return run_auto_workflow(
                self.CVE, self.root, None, None, None, "key", "model", False,
                max_attempts=3, progress=lambda _: None,
            )

    def test_the_generation_attempt_records_the_demotion(self) -> None:
        result = self.run_flow({
            "lab_type": "VULNERABLE_ONLY_REPRODUCTION", "demotion": self.DEMOTION,
        })

        generation = result["automation"]["attempts"][0]
        self.assertEqual(generation["phase"], "generation")
        self.assertTrue(generation["ok"])
        self.assertEqual(generation["demotion"], self.DEMOTION)
        # And on disk, which is what a batch reads rather than the return.
        recorded = json.loads((self.lab / "automation.json").read_text())
        self.assertEqual(recorded["attempts"][0]["demotion"], self.DEMOTION)
        self.assertIn("resolve it again", recorded["attempts"][0]["demotion"]["reason"])

    def test_a_lab_that_kept_its_differential_records_no_demotion(self) -> None:
        """The key is absent rather than null, so its presence is the signal."""
        result = self.run_flow({"lab_type": "SOURCE_REPRODUCTION"})

        self.assertNotIn("demotion", result["automation"]["attempts"][0])
        recorded = json.loads((self.lab / "automation.json").read_text())
        self.assertNotIn("demotion", recorded["attempts"][0])


def _tree_state(lab: Path) -> dict[str, str]:
    """Every file under the lab, by path, with the hash of its contents."""
    return {
        path.relative_to(lab).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(lab.rglob("*"))
        if path.is_file()
    }


@unittest.skipUnless(shutil.which("git"), "git is required")
class ADemotionThatIsNeverWrittenChangesNothingOnDiskTests(
    _UnusablePairLab, unittest.TestCase
):
    """A model call that fails after the demotion was decided must cost nothing.

    The demotion is decided from the diff, long before the model is asked,
    and the patched half used to be deleted at that moment. Everything
    between is a place to fail: `ProviderDeclined`, which autoflow returns on
    without regenerating; an interrupt; or `cvelab source`, which has no
    retry at all. The lab was then left with plan.json still claiming
    SOURCE_REPRODUCTION and revisions.patched set, while source/patched, its
    stamp and patched/ were gone -- so `cvelab run` failed its preflight on a
    lab that had built a minute earlier. The decision is in memory; only the
    deletion waits for the plan that describes it.
    """

    def _differential_lab(self) -> Path:
        """A real differential lab over the pair the predicate now rejects.

        Generated with the predicate held back, which is the one lab that can
        still reach the repair-side demotion: one made before the check
        existed. It also puts the disk in exactly the state the next
        generation finds, so the comparison below is about the demotion and
        not about a re-extracted snapshot.
        """
        with mock.patch.object(sourcegen, "_unusable_pair", return_value=None):
            result = self.generate(self.prose_only, self.affected)
        self.assertEqual(result["plan"]["lab_type"], "SOURCE_REPRODUCTION")
        self.assertEqual(result["plan"]["revisions"]["patched"], self.prose_only)
        self.schemas.clear()
        self.prompts.clear()
        return self.root / self.CVE

    def _assert_preflight_passes(self) -> None:
        with mock.patch.object(core, "prepare_compose", side_effect=_PreflightPassed):
            with self.assertRaises(_PreflightPassed):
                core.run_lab(self.CVE, self.root, keep=False)

    def test_a_declined_generation_leaves_the_lab_exactly_as_it_was(self) -> None:
        lab = self._differential_lab()
        self._assert_preflight_passes()
        before = _tree_state(lab)

        declined = ProviderDeclined("anthropic", "model", "declined")
        with mock.patch.object(sourcegen, "structured_response", side_effect=declined):
            with self.assertRaises(ProviderDeclined):
                self.generate(self.prose_only, self.affected)

        # Byte for byte, plan.json included: the demotion was decided and
        # then never written, so nothing it implies may be on disk.
        self.assertEqual(_tree_state(lab), before)
        plan = json.loads((lab / "plan.json").read_text())
        self.assertEqual(plan["lab_type"], "SOURCE_REPRODUCTION")
        self.assertEqual(plan["revisions"]["patched"], self.prose_only)
        self.assertNotIn("demotion", plan)
        self.assertTrue((lab / "source" / "patched").is_dir())
        self.assertTrue((lab / "source" / ".patched.revision").is_file())
        self.assertTrue((lab / "patched" / "Dockerfile").is_file())
        # The regression that matters: this used to fail on patched/Dockerfile
        # and source/patched, for a lab that passed a moment earlier.
        self._assert_preflight_passes()

    def test_a_declined_repair_leaves_the_lab_exactly_as_it_was(self) -> None:
        """The repair site demotes too, so it has the same obligation."""
        lab = self._differential_lab()
        before = _tree_state(lab)

        declined = ProviderDeclined("anthropic", "model", "declined")
        with mock.patch.object(sourcegen, "structured_response", side_effect=declined):
            with self.assertRaises(ProviderDeclined):
                sourcegen.repair_source_lab(
                    self.CVE, self.root, {"kind": "effect_not_observed"}, 1, "key",
                    "model", "anthropic", None, research_mode="off",
                )

        self.assertEqual(_tree_state(lab), before)
        self.assertTrue((lab / "source" / "patched").is_dir())
        self._assert_preflight_passes()

    def test_an_answer_refused_before_the_build_is_not_the_end_either(self) -> None:
        """A contract refusal is retried, so the half must still be there.

        `_answer_until_valid` asks again on a refusal and gives up only when
        the retries run out. Deleting the snapshot before the first call made
        the exhausted case destructive for the same reason a decline was.
        """
        lab = self._differential_lab()
        before = _tree_state(lab)

        def unusable(**kwargs: Any) -> dict:
            answer = _generation(kwargs["schema"] is sourcegen.VULNERABLE_ONLY_SCHEMA)
            answer["docker_compose"] = "services: {}\n"
            return answer

        with mock.patch.object(sourcegen, "structured_response", side_effect=unusable):
            with self.assertRaises(RuntimeError):
                self.generate(self.prose_only, self.affected)

        self.assertEqual(_tree_state(lab), before)
        self._assert_preflight_passes()

    def test_a_demotion_that_does_get_written_still_clears_the_patched_half(self) -> None:
        """The deletion moved; it did not stop happening."""
        lab = self._differential_lab()

        result = self.generate(self.prose_only, self.affected)

        self.assertEqual(result["plan"]["lab_type"], "VULNERABLE_ONLY_REPRODUCTION")
        self.assertFalse((lab / "source" / "patched").exists())
        self.assertFalse((lab / "source" / ".patched.revision").exists())
        self.assertFalse((lab / "patched").exists())
        self._assert_preflight_passes()

    @property
    def cache(self) -> Path:
        return (
            self.root / ".source-cache"
            / hashlib.sha256(self.URL.encode()).hexdigest()[:16]
        )

    def test_which_half_deleted_state_snapshot_once_would_trust(self) -> None:
        """The hazard the order has to avoid, and the one it was said to avoid.

        The docstring claimed a lone stamp would make a later run skip the
        extraction it needs. It does not: _snapshot_once requires the
        directory, the stamp and its contents all to agree, so a stamp with
        no tree re-extracts. The real hazard is the mirror image -- a
        truncated tree under an intact stamp is skipped, and the lab then
        builds from whatever files the rmtree had not reached. Both halves
        verified here, because the order below is chosen from them.
        """
        lab = self._differential_lab()
        snapshot = lab / "source" / "patched"

        # A stamp with no tree: re-extracted, so the old claim was false.
        shutil.rmtree(snapshot)
        self.assertTrue((lab / "source" / ".patched.revision").is_file())
        sourcegen._snapshot_once(self.cache, self.prose_only, snapshot, self.URL)
        self.assertTrue((snapshot / "app" / "main.go").is_file())

        # A truncated tree under an intact stamp: skipped. This is the state
        # the old order could leave, and the lab would build from it.
        (snapshot / "app" / "main.go").unlink()
        sourcegen._snapshot_once(self.cache, self.prose_only, snapshot, self.URL)
        self.assertFalse((snapshot / "app" / "main.go").is_file())

    def test_an_interrupt_inside_the_delete_leaves_a_state_that_re_extracts(self) -> None:
        """Which is what unlinking the stamp first buys, and all it buys.

        An interrupt lands inside the rmtree of a large vendor snapshot, not
        between the calls, and `ignore_errors` does not catch it. With the
        tree removed first, the stamp was still vouching for a directory
        being emptied; with the stamp removed first, every interrupt from
        here on leaves a state the next run re-extracts.
        """
        lab = self._differential_lab()

        with mock.patch.object(shutil, "rmtree", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                sourcegen._discard_patched_half(lab)

        self.assertFalse((lab / "source" / ".patched.revision").exists())
        # The tree is untouched, and that is fine: with no stamp beside it,
        # the next extraction happens.
        self.assertTrue((lab / "source" / "patched" / "app" / "main.go").is_file())
        sourcegen._snapshot_once(
            self.cache, self.real_fix, lab / "source" / "patched", self.URL
        )
        self.assertIn(
            "quote(s)",
            (lab / "source" / "patched" / "app" / "main.go").read_text(),
        )

    def test_a_stamp_that_cannot_be_removed_keeps_its_tree_and_does_not_raise(self) -> None:
        """One coherent policy: nothing here aborts, and the stamp never leads.

        Both rmtree calls already ignored their errors while the unlink did
        not, so a read-only source/ raised an uncaught PermissionError --
        reintroducing the abort this whole mechanism exists to remove. The
        tree stays with the stamp rather than under it, because a stale pair
        that agrees with itself is what _snapshot_once handles correctly.
        """
        lab = self._differential_lab()

        with mock.patch.object(Path, "unlink", side_effect=PermissionError("read-only")):
            sourcegen._discard_patched_half(lab)

        self.assertTrue((lab / "source" / "patched").is_dir())
        self.assertTrue((lab / "source" / ".patched.revision").is_file())


#: What an unpublished base image tag looks like by the time it reaches the
#: loop. Trimmed from the sentry run in selected10e-2026-11-04, whose
#: `failure.error` is this text: the lab had been told to escape an archived
#: pool, moved its interpreter onto a newer Debian release, and the pairing
#: was never built. Recorded `runtime_error` with no hint.
#:
#: Note what buildkit actually says. There is no "manifest unknown" anywhere
#: in it -- that is the older distribution wording -- and the only phrase
#: common to every unresolvable reference is "failed to resolve source
#: metadata". Confirmed on 2026-11-05 against docker 29.9.2 and buildx
#: 0.38.1 for all three cases: an unpublished tag ("not found"), a missing
#: repository ("pull access denied, repository does not exist"), and a tag
#: with no image for the platform ("no match for platform in manifest").
UNPUBLISHED_TAG = (
    "Docker stage 'build' failed with exit code 1\nDocker output:\n"
    "#4 [patched internal] load metadata for docker.io/library/python:3.8.16-bookworm\n"
    "#4 ...\n"
    "#4 [vulnerable internal] load metadata for docker.io/library/python:3.8.16-bookworm\n"
    "#4 ERROR: docker.io/library/python:3.8.16-bookworm: not found\n"
    "#6 [validator internal] load metadata for "
    "docker.io/library/python:3.8.16-slim-bookworm\n"
    "#6 ERROR: docker.io/library/python:3.8.16-slim-bookworm: not found\n"
    "Dockerfile:1\n   1 | >>> FROM python:3.8.16-bookworm\n"
    "target vulnerable: failed to solve: python:3.8.16-bookworm: failed to resolve "
    "source metadata for docker.io/library/python:3.8.16-bookworm: "
    "docker.io/library/python:3.8.16-bookworm: not found\n"
)

#: The same class from a different language and a different registry: a
#: compound tag pairing a JDK build, an sbt version and a Scala version, each
#: of which exists and whose combination does not. Trimmed from
#: batch10-2026-10-28/CVE-2026-69204, attempt 1. Kept because it is the
#: evidence that this is not one lab's mistake with one interpreter.
COMPOUND_TAG = (
    "Docker stage 'build' failed with exit code 1\nDocker output:\n"
    "#5 ERROR: docker.io/sbtscala/scala-sbt:"
    "eclipse-temurin-17.0.11_9_1.10.0_3.4.2: not found\n"
    "#11 [validator 3/4] WORKDIR /app\n#11 CANCELED\n"
    "target vulnerable: failed to solve: sbtscala/scala-sbt:"
    "eclipse-temurin-17.0.11_9_1.10.0_3.4.2: failed to resolve source metadata for "
    "docker.io/sbtscala/scala-sbt:eclipse-temurin-17.0.11_9_1.10.0_3.4.2: "
    "docker.io/sbtscala/scala-sbt:eclipse-temurin-17.0.11_9_1.10.0_3.4.2: not found\n"
)

#: A pin no published version satisfies. Trimmed from
#: test5-2026-10-29/CVE-2026-62674, attempt 1, whose build output is the
#: 16170-character one the truncation test above is written around. pip names
#: the requirement and every version that does exist, which is exactly what
#: makes this answerable -- and it went to a repair with no hint at all.
PIP_PIN = (
    "Docker stage 'build' failed with exit code 1\nDocker output:\n"
    "#15 7.224 ERROR: Could not find a version that satisfies the requirement "
    "opentelemetry-instrumentation-fastapi<1,>=0 (from omnigent) (from versions: "
    "0.11b0, 0.12b0, 0.13b0, 0.14b0, 0.15b0, 0.16b0, 0.16b1, 0.17b0, 0.18b0)\n"
    "#15 7.441 ERROR: No matching distribution found for "
    "opentelemetry-instrumentation-fastapi<1,>=0\n"
    "#15 ERROR: process \"/bin/sh -c pip install --no-cache-dir "
    "omnigent==${OMNIGENT_VERSION}\" did not complete successfully: exit code: 1\n"
)

#: Go's answer when the recorded sum and the served module disagree. No run
#: in the archive has produced one, so unlike every fixture above this is
#: written from the tool's documented output rather than from a measurement,
#: and it is here because the condition is deterministic: the proxy will
#: serve the same bytes to the next attempt. apt's "hash sum mismatch" stays
#: in the retry markers, because a mirror caught mid-sync really does settle.
GO_SUM_MISMATCH = (
    "Docker stage 'build' failed with exit code 1\nDocker output:\n"
    "#30 4.118 go: downloading github.com/example/widget v1.4.2\n"
    "#30 5.002 go: github.com/example/widget@v1.4.2: verifying module: "
    "checksum mismatch\n"
    "#30 5.002 \tdownloaded: h1:3ps1Ok1bPR0rLgQzSKpGhKTRkNi0QhGBHT+N0UxkFRA=\n"
    "#30 5.002 \tgo.sum:     h1:kyhCBVPQBhjsHMKMqHMUEfD3b2YkA8QDLGCUPIQJv0A=\n"
    "#30 5.002 SECURITY ERROR\n"
    "#30 ERROR: process \"/bin/sh -c go build -o /out/app ./cmd/app\" did not "
    "complete successfully: exit code: 1\n"
)


class AnUnpublishedTagIsNotAnUnhintedRepairTests(_LoopFixture, unittest.TestCase):
    """The failure the archived-pool warning was written for, finally hearing it.

    Of forty measured attempts, four ended in `runtime_error` and every one
    was a build failure. Two whole classes fell through all three buckets --
    an invented base image tag and an unfetchable dependency pin -- and
    reached a repair as a bare `{"kind": "runtime_error", "error": <log>}`.
    A repair handed a long Docker log and nothing else reaches for another
    tag the same way it reached for the first.
    """

    def test_an_unpublished_tag_is_named_and_hinted(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        _result, _run, repair = self.run_flow([RuntimeError(UNPUBLISHED_TAG), passed])

        repair.assert_called_once()
        failure = repair.call_args.args[2]
        self.assertEqual(failure["kind"], "unknown_base_image")
        self.assertIn("does not exist", failure["hint"])
        self.assertIn("3.8.16-bookworm", failure["error"])

    def test_it_is_not_retried_unchanged(self) -> None:
        """The registry's answer is the same next minute, so a retry is waste."""
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        result, _run, _repair = self.run_flow([RuntimeError(UNPUBLISHED_TAG), passed])

        self.assertEqual(result["automation"]["transient_retries"], 0)
        phases = [attempt["phase"] for attempt in result["automation"]["attempts"]]
        self.assertNotIn("transient", phases)

    def test_a_dependency_pin_is_named_and_hinted(self) -> None:
        passed = {"ok": True, "report": {"proof_checks": {"manual_poc_verified": True}}}
        _result, _run, repair = self.run_flow([RuntimeError(PIP_PIN), passed])

        repair.assert_called_once()
        failure = repair.call_args.args[2]
        self.assertEqual(failure["kind"], "dependency_pin")
        self.assertIn("pin", failure["hint"])
        self.assertIn("No matching distribution found", failure["error"])


class WhichBuildFailureGetsWhichHintTests(unittest.TestCase):
    """One case per class, from the recorded text of real runs.

    Table-driven on purpose: the classifiers share a stage guard and overlap
    in vocabulary, so the thing worth pinning is not that each one fires but
    that exactly one does, for text nobody wrote to suit it.
    """

    #: message, the kind it must become, and the hint that must not reach it.
    CASES = (
        ("archived pool", ARCHIVED_POOL, "archived_suite"),
        ("unpublished tag", UNPUBLISHED_TAG, "unknown_base_image"),
        ("compound tag", COMPOUND_TAG, "unknown_base_image"),
        ("pip pin", PIP_PIN, "dependency_pin"),
        ("go sum", GO_SUM_MISMATCH, "dependency_pin"),
        # Still unhinted, and correctly so: a model can read these.
        ("version skew", VERSION_SKEW, "runtime_error"),
        ("module proxy away", MODULE_TIMEOUT, "runtime_error"),
    )

    def test_each_measured_failure_becomes_exactly_one_kind(self) -> None:
        for name, message, kind in self.CASES:
            with self.subTest(case=name):
                self.assertEqual(autoflow._runtime_failure(message)["kind"], kind)

    def test_exactly_one_classifier_claims_each_of_them(self) -> None:
        """No case may match two, which is what makes the order safe to rely on."""
        classifiers = (
            autoflow._archived_suite_failure,
            autoflow._unknown_base_image,
            autoflow._dependency_pin_failure,
        )
        for name, message, kind in self.CASES:
            with self.subTest(case=name):
                matched = [c.__name__ for c in classifiers if c(message)]
                self.assertEqual(len(matched), 0 if kind == "runtime_error" else 1, matched)

    def test_the_archived_pool_wins_when_one_log_carries_both(self) -> None:
        """The order, and the reason it is this way round.

        A compose build solves every target in one go, so one log really can
        carry an archived pool from one target and an unresolvable tag from
        another -- the sentry lab produced both, one attempt apart, in the
        same run. If the base-image branch went first, an archived pool would
        be told to change its tag, which is the advice that invented the
        tag in the first place and the thing ARCHIVE_HINT exists to forbid.
        """
        both = ARCHIVED_POOL + "\n" + UNPUBLISHED_TAG

        self.assertTrue(autoflow._archived_suite_failure(both))
        self.assertTrue(autoflow._unknown_base_image(both))

        failure = autoflow._runtime_failure(both)
        self.assertEqual(failure["kind"], "archived_suite")
        self.assertIn("archive.debian.org", failure["hint"])
        self.assertIn("Do not reach for a newer base image", failure["hint"])

    def test_a_marker_outside_a_build_is_not_one(self) -> None:
        """Both new classifiers keep the stage guard the other two have.

        A validator that cannot pull its own image, or a startup that fails
        on one, is a real failure and must keep reaching a repair with its
        own text rather than being relabelled.
        """
        for message in (
            "Validator failed: pull access denied for the report service",
            "Docker stage 'startup' failed with exit code 1: manifest unknown",
            "lab service did not become healthy: no matching distribution found",
            "Validator failed: checksum mismatch",
        ):
            with self.subTest(message=message):
                self.assertFalse(autoflow._unknown_base_image(message))
                self.assertFalse(autoflow._dependency_pin_failure(message))

    def test_manifest_for_is_not_a_marker(self) -> None:
        """It was proposed and rejected; this is what rejecting it buys.

        buildkit never says "manifest for" in any of the three cases -- the
        platform one says "in manifest" -- while the phrase occurs over a
        thousand times in the source trees the benchmark labs check out, and
        a build log carries source lines whenever a compiler or a traceback
        quotes one. As a marker it would have relabelled ordinary build
        failures as an unresolvable base image.
        """
        self.assertFalse(autoflow._unknown_base_image(
            "Docker stage 'build' failed with exit code 1\nDocker output:\n"
            "#14 2.01 src/loader.ts:88:7 - error TS2345: Argument of type "
            "'string' is not assignable; see the manifest for the expected shape\n"
        ))

    def test_the_hint_comes_before_the_log_for_the_new_branches_too(self) -> None:
        """Same reason as the archived pool, measured on the same ceiling.

        `repair_source_lab` serialises this dict and cuts it to 12000
        characters on a local provider. The pip run's own build output was
        16170, so a hint placed after it would be gone and the repair would
        be back to reading a log. Insertion order is the whole retention
        policy, and it is easy to lose in a later edit.
        """
        for name, message, phrase in (
            ("unknown_base_image", UNPUBLISHED_TAG, "Name only a tag you know to be published"),
            ("dependency_pin", PIP_PIN, "Change the pin the output names"),
        ):
            with self.subTest(case=name):
                failure = autoflow._runtime_failure(message + "x" * 20000)
                serialized = json.dumps(failure, ensure_ascii=True, indent=2)
                self.assertIn(phrase, serialized[:12000])
                self.assertLess(
                    serialized.index(phrase), serialized.index("Docker output")
                )


class TheInventedTagWarningIsOnTheRightFailureTests(unittest.TestCase):
    """The warning moved to the failure it describes.

    It used to end ARCHIVE_HINT: advice about inventing base image tags,
    shown only to a run that had escaped the archived pool and not yet
    invented one. The run that did invent one got no hint at all.
    """

    def test_the_mechanism_is_now_in_the_base_image_hint(self) -> None:
        hint = autoflow.BASE_IMAGE_HINT
        self.assertIn("reaches end of life", hint)
        self.assertIn("never had a bookworm image", hint)
        self.assertIn("Name only a tag you know to be published", hint)

    def test_the_archive_hint_keeps_only_the_cross_reference(self) -> None:
        hint = autoflow.ARCHIVE_HINT
        self.assertIn("Do not reach for a newer base image", hint)
        self.assertNotIn("never had a bookworm image", hint)

    def test_the_remedy_is_still_the_first_thing_each_hint_says(self) -> None:
        """What to change comes before what not to change, in both."""
        for name, hint, remedy, fence in (
            (
                "archive",
                autoflow.ARCHIVE_HINT,
                "archive.debian.org",
                "Change nothing else",
            ),
            (
                "base image",
                autoflow.BASE_IMAGE_HINT,
                "Name only a tag you know to be published",
                "Change nothing else",
            ),
            (
                "dependency",
                autoflow.DEPENDENCY_HINT,
                "Change the pin the output names",
                "Change nothing else",
            ),
        ):
            with self.subTest(hint=name):
                self.assertLess(hint.index(remedy), hint.index(fence))

    def test_each_hint_fences_off_what_is_not_the_cause(self) -> None:
        """The house shape: name the mechanism, state the remedy, then fence."""
        for name, hint in (
            ("base image", autoflow.BASE_IMAGE_HINT),
            ("dependency", autoflow.DEPENDENCY_HINT),
        ):
            with self.subTest(hint=name):
                self.assertIn("the regression input and the validator's", hint)
                self.assertIn("are not the cause", hint)

    def test_the_dependency_hint_protects_the_revision_pair(self) -> None:
        """The one way a model could make this build pass and the lab useless."""
        hint = autoflow.DEPENDENCY_HINT
        self.assertIn("Leave the vulnerable and patched revisions", hint)
        self.assertIn("removes the fix", hint)


class ADeterministicFailureIsNotRetried(unittest.TestCase):
    """Neither new class belongs in the retry markers, and neither is in them.

    A retry is right for a fetch that was briefly away. An unpublished tag
    and a bad pin are answers that will not change, so a retry spends the
    pause and the attempt for nothing and then arrives where it would have
    arrived anyway, two minutes later.
    """

    def test_the_retry_markers_were_not_widened(self) -> None:
        for message in (UNPUBLISHED_TAG, COMPOUND_TAG, PIP_PIN, GO_SUM_MISMATCH):
            with self.subTest(message=message[:60]):
                self.assertFalse(autoflow._transient_failure(message))

    def test_a_mirror_mid_sync_is_still_retried(self) -> None:
        """The distinction the two mismatch wordings carry.

        apt's "Hash Sum mismatch" is a mirror caught between index and pool
        and really does settle; Go's "checksum mismatch" is a recorded sum
        disagreeing with the bytes served, and will not.
        """
        apt_mid_sync = (
            "Docker stage 'build' failed with exit code 1\nDocker output:\n"
            "#8 12.4 E: Failed to fetch http://deb.debian.org/debian/pool/main/"
            "libc6_2.36-9+deb12u7_amd64.deb  Hash Sum mismatch\n"
        )
        self.assertTrue(autoflow._transient_failure(apt_mid_sync))
        self.assertFalse(autoflow._dependency_pin_failure(apt_mid_sync))
        self.assertTrue(autoflow._dependency_pin_failure(GO_SUM_MISMATCH))
        self.assertFalse(autoflow._transient_failure(GO_SUM_MISMATCH))
