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


#: A validated lab as the deliverables pass leaves one, for the documents
#: `--no-poc` cannot withhold. Spelled out rather than generated, because
#: what is under test is which of these fields leaves the machine.
ATTACK_BEARING = {
    "canary": "CVELAB-0123456789abcdef0123456789abcdef",
    "route": "/render",
    "payload": "){ return 'pwned' }; with(obj",
    "credential": "seeded-admin-password",
    # One needle carrying characters json.dumps escapes -- a quote, a
    # backslash, a newline -- because the scrub ran over serialized text
    # while the needles are decoded strings, so for 30 needles in the
    # archive it could not match. Mostly body_regex predicates, like this.
    "escaped": 'root:x:0:0:[^"]*\n(\\S+)',
    # And one the ensure_ascii pass escapes to \uXXXX for the same reason.
    "nonascii": "p\u00e2t\u00e9-\u00dfecret-token",
    # A marker in a spelling no predicate names, so only the canary pattern
    # can find it. Two archived labs' predicates are the bare prefix.
    "loose_canary": "CVELAB-EXEC-9f9f9f9f9f9f9f9f9f9f",
}

#: Needles that must NOT be replaced wherever they appear, and why. Four in
#: the archive are ordinary words at or above the floor -- `Location`,
#: `accepted`, `UnidentifiedImageError` -- and replacing one in prose turned
#: REPORT.md's own finding into "`<withheld by --no-poc>` header
#: percent-encodes the backslash": the sentence saying what was found stopped
#: naming the header that leaked, while the attack URL in the same document
#: survived. A header name is never the secret either, so it is not a needle
#: at all.
KEPT_IN_PROSE = {
    "word": "accepted",
    "header_name": "Location",
}

#: Where the attack leaks into fields the allowlist keeps, which is what
#: happens in real labs: the model weaves the route and the canary into the
#: fidelity rationale, the simulated components and the analysis prose, and
#: only the scrub takes them out. A fixture whose attack strings sit only in
#: withheld fields passes with the scrub deleted, which is how three
#: mutations of it went unnoticed.
def _allowed_prose() -> str:
    return (
        f"The adapter exposes the sink over POST {ATTACK_BEARING['route']}, the "
        f"canary {ATTACK_BEARING['loose_canary']} is what the run looks for, the "
        f"pattern {ATTACK_BEARING['escaped']} matched, and the seeded account "
        f"{ATTACK_BEARING['nonascii']} was used. The {KEPT_IN_PROSE['header_name']} "
        f"header was {KEPT_IN_PROSE['word']} by both builds."
    )


def described_lab(root: Path) -> Path:
    """A lab whose records carry the attack, in every place they carry it."""
    lab = root / "CVE-2024-12345"
    artifacts = lab / "artifacts"
    artifacts.mkdir(parents=True)
    contract = {
        "attack_summary": f"POST the payload to {ATTACK_BEARING['route']}",
        "observable_effect": f"the response contains {ATTACK_BEARING['canary']}",
        "effect_predicate": {
            "body_contains": ATTACK_BEARING["canary"],
            "body_regex": ATTACK_BEARING["escaped"],
            # A header name is never the secret, and it is the one part of a
            # predicate a reader needs to understand the finding.
            "header": {
                "name": KEPT_IN_PROSE["header_name"],
                "contains": KEPT_IN_PROSE["word"],
            },
        },
        "service_port": 8080,
        "evidence_type": "code_execution",
    }
    validation = {
        "attack_executed": True,
        "proof_quality": "security_effect_observed",
        "observable_effect": f"the injected {ATTACK_BEARING['payload']} runs",
        "evidence_type": "code_execution",
        "differential_confirmed": True,
        "vulnerable": {
            "confirmed": True, "blocked": False,
            "observations": {"status": 200, "body": ATTACK_BEARING["canary"]},
        },
        "patched": {
            "confirmed": False, "blocked": True,
            "observations": {"status": 500, "body": "rejected"},
        },
    }
    record = {
        "shipped": True,
        "strategy": "direct_observation",
        "container_port": 8080,
        "observable_effect": f"the response contains {ATTACK_BEARING['canary']}",
        "proof_checks": {"manual_poc_proven": True},
        "runs": {"vulnerable": {"verdict": "OBSERVED"}},
        "lab_values": {
            "target_path": ATTACK_BEARING["route"],
            "credential": ATTACK_BEARING["credential"],
            "account": ATTACK_BEARING["nonascii"],
        },
        "spec": {
            "strategy": "direct_observation",
            "transport": "http",
            "observable_effect": "a canary in the response",
            "inputs": ["target_path"],
            "auth": {},
            "checks": [{
                "label": "spec",
                "discover": [],
                "probe": [{"method": "POST", "path": "{{target_path}}",
                           "body": ATTACK_BEARING["payload"]}],
                "expect": {"body_contains": ATTACK_BEARING["canary"]},
            }],
            "health_timeout": 120,
        },
    }
    report = {
        "cve": "CVE-2024-12345", "cwe": "CWE-94", "lab_type": "SOURCE_REPRODUCTION",
        "validated_at": "2099-01-01T00:00:00Z",
        "validation": validation,
        "proof_contract": contract,
        "effect_evidence": [f"body_contains {ATTACK_BEARING['canary']}: matched"],
        "fidelity": {
            "execution_level": "source_component",
            "rationale": _allowed_prose(),
            "simulated_components": [
                f"an HTTP listener exposing the sink over POST {ATTACK_BEARING['route']}"
            ],
        },
        "proof_checks": {"attack_executed": True, "security_effect_observed": True,
                         "vulnerable_confirmed": True, "manual_poc_verified": True,
                         "patched_blocked": True},
        "manual_poc_field": record,
        "manual_poc_status": "verified",
        # What the manual runner printed: allowed wholesale until it was
        # measured, and carrying every response header and both builds'
        # bodies -- the material validation.*.observations is dropped for.
        "manual_poc_checks": {
            "vulnerable_verify": {
                "passed": True, "exit_code": 0, "expected_verdict": "REPRODUCED",
                "output": f"status: 200\nbody: {ATTACK_BEARING['canary']}\n"
                          f"headers: Location: {ATTACK_BEARING['route']}",
                "stderr": f"sent {ATTACK_BEARING['payload']}",
            },
        },
        "setup_bindings": {"vulnerable": ["session"]},
        "real_poc_verified": True, "ok": True,
        "differential_confirmed": True, "patched_tested": True,
        "fix_status": "PUBLIC_FIX_AVAILABLE",
    }
    evidence = {
        "schema_version": 2, "cve": "CVE-2024-12345",
        "status": "REAL_SOURCE_POC_VALIDATED", "lab_type": "SOURCE_REPRODUCTION",
        "validation": validation, "proof_contract": contract,
        "proof_checks": report["proof_checks"],
        "fidelity": report["fidelity"],
        "manual_poc_checks": report["manual_poc_checks"],
        "manual_poc_status": "verified",
        "provenance": {"repository": "https://github.com/example/widget"},
    }
    analysis = {
        "executive_summary": "A code injection in the template helper.",
        "mechanism": f"The payload {ATTACK_BEARING['payload']} reaches Function().",
        "prerequisites": [f"a route like {ATTACK_BEARING['route']} must exist"],
        "attack_path": [f"POST {ATTACK_BEARING['route']} with the payload"],
        "impact": ["code runs in the server process"],
        "affected_components": ["the template helper"],
        "evidence_interpretation": _allowed_prose(),
        "fidelity": "source_component",
        "limitations": ["not a product end-to-end test"],
        "remediation_status": "fixed upstream",
        "confidence_statement": "high for the lab, limited for the wider CVE",
    }
    (lab / "plan.json").write_text(json.dumps({
        "cve": "CVE-2024-12345",
        "repository": "https://github.com/example/widget",
        "revisions": {"vulnerable": "aaa", "patched": "bbb"},
        "exploit_contract": contract,
    }))
    (artifacts / "report.json").write_text(json.dumps(report, indent=2))
    (artifacts / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2))
    (artifacts / "analysis.json").write_text(json.dumps(analysis, indent=2))
    (artifacts / "PoC.py").write_text("print('exploit')\n")
    (artifacts / "manual.sh").write_text("#!/usr/bin/env bash\necho lab\n")
    (artifacts / "plan.json").write_text((lab / "plan.json").read_text())
    (artifacts / "REPORT.md").write_text(
        "# CVE-2024-12345 Validation Report\n"
        "\n## Result\n\n- Status: `REAL_SOURCE_POC_VALIDATED`\n"
        f"\n## Vulnerability mechanism\n\nThe payload {ATTACK_BEARING['payload']} "
        "reaches Function().\n"
        f"\n## Preconditions\n\n- a route like {ATTACK_BEARING['route']}\n"
        f"\n## Evidence\n\n```json\n{{\"body\": \"{ATTACK_BEARING['canary']}\"}}\n```\n"
        "\n## Potential impact\n\n- code runs in the server process\n"
        "\n## Interpretation\n\nThe fixed revision blocked it.\n"
    )
    (artifacts / "WALKTHROUGH.md").write_text(
        "# CVE-2024-12345 Walkthrough\n"
        "\n## Scope\n\nA vendor-source reproduction.\n"
        f"\n## Modeled attack path\n\nThe payload {ATTACK_BEARING['payload']}.\n"
        f"\n## Validation steps\n\n1. POST to {ATTACK_BEARING['route']}, which "
        f"returns {ATTACK_BEARING['canary']}.\n"
        "\n## Revisions\n\n- Repository: `https://github.com/example/widget`\n"
    )
    return lab


class WhatNoPocFilesTests(unittest.TestCase):
    """`--no-poc` promised a non-runnable entry. This is what it files.

    WHAT WAS MEASURED

    The flag withheld four names and filed five: REPORT.md, WALKTHROUGH.md,
    EVIDENCE.json, report.json and analysis.json. Between them they carried
    the route and method the attack used, the payload's construction in
    prose, the canary the effect is recognised by, the raw observations of
    both builds, and -- once the PoC merge moved the proven spec into
    report.json -- every request the single-instance script sends, verbatim.
    A reader with that does not need the script, so "non-runnable" was not
    true.

    None of those five can simply be withheld. `site/worker/gate.js` requires
    EVIDENCE.json, report.json, REPORT.md and WALKTHROUGH.md even of a
    withheld run, and refuses one that arrives without them: measured, moving
    WALKTHROUGH.md to `upload.EXPLOIT` turns `{"share": false, "reason":
    "exploit_withheld"}` into `{"reason": "evidence_incomplete", "failures":
    ["WALKTHROUGH.md is missing"]}`. So they are redacted instead, by an
    allowlist, and each one says what was taken out of it.

    WHAT THESE TESTS HOLD

    One test per name that still travels, asserting what it may and may not
    contain. A field added to report.json is withheld by DESCRIBED_ONLY until
    someone names it, and the test that notices is
    `test_a_field_nobody_classified_does_not_travel`.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.lab = described_lab(Path(self.temporary.name))

    def filed(self, *, include_poc: bool = False) -> dict[str, str]:
        payload = upload.collect(
            self.lab, RESULT, provider="anthropic", model="m",
            include_poc=include_poc,
        )
        return {d["name"]: d["text"] for d in payload["documents"]}

    def test_the_default_path_is_unchanged(self) -> None:
        """No --no-poc sends the files as they are on disk. Pinned.

        The redaction runs on the payload, so the way to say "unchanged" is
        that every document equals what `read_document` reads off the lab --
        which is the whole of what collect did before this existed.
        """
        sent = self.filed(include_poc=True)
        for name, text in sent.items():
            with self.subTest(name=name):
                on_disk = upload.read_document(
                    self.lab / "artifacts" / name, self.lab
                )
                self.assertEqual(text, on_disk["text"])
        self.assertIn("PoC.py", sent)
        self.assertIn(ATTACK_BEARING["canary"], sent["report.json"])

    def test_the_lab_on_disk_is_never_touched(self) -> None:
        before = {
            path.name: path.read_bytes()
            for path in (self.lab / "artifacts").iterdir() if path.is_file()
        }
        self.filed()
        after = {
            path.name: path.read_bytes()
            for path in (self.lab / "artifacts").iterdir() if path.is_file()
        }
        self.assertEqual(before, after)

    def test_what_travels_is_the_description(self) -> None:
        sent = self.filed()
        self.assertEqual(
            sorted(sent),
            ["EVIDENCE.json", "REPORT.md", "WALKTHROUGH.md", "analysis.json",
             "report.json"],
        )
        # And the four the control plane requires of a withheld run are all
        # there, so the entry is still accepted.
        for name in ("EVIDENCE.json", "report.json", "REPORT.md", "WALKTHROUGH.md"):
            self.assertIn(name, sent)

    def test_no_document_carries_the_attack(self) -> None:
        """The strings a copycat needs, in every surviving document."""
        for name, text in self.filed().items():
            for what, needle in ATTACK_BEARING.items():
                with self.subTest(name=name, carries=what):
                    self.assertNotIn(needle, text)

    def test_report_json_keeps_the_verdict_and_loses_the_recipe(self) -> None:
        held = json.loads(self.filed()["report.json"])
        # What the gate reads, and what a reader needs to know what was found.
        self.assertEqual(held["cve"], "CVE-2024-12345")
        self.assertIs(held["ok"], True)
        self.assertIs(held["real_poc_verified"], True)
        self.assertEqual(held["lab_type"], "SOURCE_REPRODUCTION")
        self.assertIs(held["validation"]["attack_executed"], True)
        self.assertEqual(held["validation"]["proof_quality"], "security_effect_observed")
        self.assertIs(held["validation"]["differential_confirmed"], True)
        self.assertIs(held["validation"]["vulnerable"]["confirmed"], True)
        self.assertIs(held["proof_checks"]["patched_blocked"], True)
        self.assertEqual(held["manual_poc_field"]["shipped"], True)
        # And the recipe, every part of it.
        self.assertNotIn("proof_contract", held)
        self.assertNotIn("effect_evidence", held)
        self.assertNotIn("observations", held["validation"]["vulnerable"])
        self.assertNotIn("observations", held["validation"]["patched"])
        self.assertNotIn("observable_effect", held["validation"])
        for gone in ("spec", "lab_values", "runs", "container_port",
                     "observable_effect"):
            self.assertNotIn(gone, held["manual_poc_field"])

    def test_evidence_json_keeps_what_the_gate_reads(self) -> None:
        held = json.loads(self.filed()["EVIDENCE.json"])
        self.assertEqual(held["status"], "REAL_SOURCE_POC_VALIDATED")
        self.assertEqual(held["cve"], "CVE-2024-12345")
        self.assertEqual(held["lab_type"], "SOURCE_REPRODUCTION")
        self.assertIs(held["validation"]["attack_executed"], True)
        self.assertEqual(held["validation"]["proof_quality"], "security_effect_observed")
        self.assertIs(held["validation"]["differential_confirmed"], True)
        self.assertIs(held["proof_checks"]["manual_poc_verified"], True)
        self.assertEqual(
            held["provenance"]["repository"], "https://github.com/example/widget"
        )
        self.assertEqual(held["schema_version"], 2)
        self.assertNotIn("proof_contract", held)
        self.assertNotIn("observations", held["validation"]["vulnerable"])

    def test_analysis_json_keeps_the_findings_and_loses_the_path(self) -> None:
        held = json.loads(self.filed()["analysis.json"])
        for kept in ("executive_summary", "impact", "limitations",
                     "remediation_status", "confidence_statement",
                     "evidence_interpretation", "affected_components"):
            self.assertIn(kept, held)
        for gone in ("mechanism", "attack_path", "prerequisites"):
            self.assertNotIn(gone, held)

    def test_the_documents_lose_the_sections_that_are_the_reproduction(self) -> None:
        sent = self.filed()
        walkthrough = sent["WALKTHROUGH.md"]
        self.assertIn("## Scope", walkthrough)
        self.assertIn("A vendor-source reproduction.", walkthrough)
        self.assertIn("## Modeled attack path", walkthrough)
        self.assertIn("## Validation steps", walkthrough)
        # The headings stay and the bodies go, so the document says where the
        # cut is rather than closing the gap over it.
        self.assertNotIn("1. POST to", walkthrough)
        report = sent["REPORT.md"]
        self.assertIn("REAL_SOURCE_POC_VALIDATED", report)
        self.assertIn("code runs in the server process", report)
        self.assertIn("## Vulnerability mechanism", report)
        self.assertNotIn("reaches Function().", report)

    def test_every_redacted_document_says_so(self) -> None:
        """An entry that silently lacks fields a reader expects is a lie."""
        for name, text in self.filed().items():
            with self.subTest(name=name):
                if name.endswith(".json"):
                    held = json.loads(text)
                    said = held["withheld_by_no_poc"]
                    self.assertTrue(said["fields"], name)
                    self.assertIn("--no-poc", said["why"])
                    self.assertIn("not the same as", said["why"])
                else:
                    self.assertIn("## Withheld", text)
                    self.assertIn("Withheld by `--no-poc`", text)
                    self.assertIn("not the same as", text)

    def test_it_claims_nothing_about_being_unreproducible(self) -> None:
        """The honest part, and the reason the flag was nearly deleted.

        Withholding the artifacts and redacting the records is not the same
        as a reader being unable to reproduce the finding: the repository,
        the vulnerable and fixed revisions and the CVE all still travel, by
        design, because an entry without them describes nothing.
        """
        sent = self.filed()
        self.assertIn("github.com/example/widget", sent["WALKTHROUGH.md"])
        said = json.loads(sent["report.json"])["withheld_by_no_poc"]["why"]
        self.assertIn("repository", said)
        self.assertIn("fix commit", said)
        for text in sent.values():
            self.assertNotIn("non-runnable", text)

    def test_the_scrub_is_what_removes_what_the_allowlist_keeps(self) -> None:
        """The attack in fields that travel, which only the scrub can take out.

        This is the test that was missing. Every attack string in the first
        fixture sat in a field the allowlist removes, so three mutations of
        the scrub -- returning the text unchanged, breaking the canary
        pattern, raising the path floor from 4 to 40 -- all passed. Real labs
        are the other way round: the route and the canary leak into
        `fidelity.rationale`, `simulated_components`, `manual_poc_checks` and
        the analysis prose, and the scrub is the only thing between them and
        the corpus. Each assertion here names a field that is allowed.
        """
        sent = self.filed()
        for name in ("report.json", "EVIDENCE.json"):
            held = json.loads(sent[name])
            with self.subTest(name=name, field="fidelity.rationale"):
                # Allowed, and so is everything under it.
                self.assertIn("rationale", held["fidelity"])
                rationale = held["fidelity"]["rationale"]
                self.assertNotIn(ATTACK_BEARING["route"], rationale)
                self.assertNotIn(ATTACK_BEARING["loose_canary"], rationale)
                self.assertNotIn(ATTACK_BEARING["escaped"], rationale)
                self.assertNotIn(ATTACK_BEARING["nonascii"], rationale)
            with self.subTest(name=name, field="fidelity.simulated_components"):
                self.assertNotIn(
                    ATTACK_BEARING["route"],
                    json.dumps(held["fidelity"]["simulated_components"]),
                )
        with self.subTest(field="analysis.evidence_interpretation"):
            held = json.loads(sent["analysis.json"])
            said = held["evidence_interpretation"]
            self.assertNotIn(ATTACK_BEARING["route"], said)
            self.assertNotIn(ATTACK_BEARING["loose_canary"], said)

    def test_a_needle_json_escapes_is_still_found(self) -> None:
        """The leak this closed, asserted where it happened.

        `_scrubbed` ran over the re-serialized document while the needles are
        decoded strings, so a needle holding a quote, a backslash or a
        non-ASCII character could not match -- `needle in decoded` true,
        `needle in text` false. Measured on one archived lab, the `--no-poc`
        report.json still carried the traversal filename, which is the
        payload. 30 needles in the archive carry such a character.
        """
        sent = self.filed()
        for name, text in sent.items():
            if not name.endswith(".json"):
                continue
            with self.subTest(name=name):
                # The decoded form, which is what the needle is.
                self.assertNotIn(ATTACK_BEARING["escaped"], json.dumps(json.loads(text)))
                self.assertNotIn(ATTACK_BEARING["nonascii"], text)
                # And the escaped form, which is what the document holds.
                self.assertNotIn(
                    json.dumps(ATTACK_BEARING["escaped"])[1:-1], text
                )
                self.assertNotIn(
                    json.dumps(ATTACK_BEARING["nonascii"], ensure_ascii=True)[1:-1],
                    text,
                )

    def test_a_marker_no_predicate_names_is_still_found(self) -> None:
        """Only the canary pattern can catch this one.

        Its spellings are the ones the archive holds: `CVELAB-<hex>`,
        `CVELAB-EXEC-<hex>`, `CVELAB-<hex>-42`. A lab can print a marker the
        predicate does not quote, and one archived predicate is the bare
        prefix `CVELAB-`, which is below the needle floor.
        """
        for name, text in self.filed().items():
            with self.subTest(name=name):
                self.assertNotIn(ATTACK_BEARING["loose_canary"], text)

    def test_a_needle_that_is_also_a_word_survives_a_sentence(self) -> None:
        """What fix 4 is for: the finding keeps saying what was found.

        `{"header": {"name": "Location"}}` is a predicate, and replacing
        "Location" wherever it occurred left REPORT.md reading "`<withheld by
        --no-poc>` header percent-encodes the backslash" while the attack URL
        in the same document survived. A header name is not a needle at all
        now, and a word-shaped needle is replaced only where a string is
        nothing but the needle.
        """
        sent = self.filed()
        rationale = json.loads(sent["report.json"])["fidelity"]["rationale"]
        self.assertIn(KEPT_IN_PROSE["header_name"], rationale)
        self.assertIn(KEPT_IN_PROSE["word"], rationale)
        self.assertIn("header was accepted by both builds", rationale)

    def test_a_word_shaped_needle_is_still_taken_where_it_is_the_value(self) -> None:
        """A value is not a sentence, so there the whole string goes."""
        artifacts = self.lab / "artifacts"
        held = json.loads((artifacts / "report.json").read_text())
        held["fidelity"]["execution_level"] = KEPT_IN_PROSE["word"]
        (artifacts / "report.json").write_text(json.dumps(held))

        filed = json.loads(self.filed()["report.json"])

        self.assertEqual(filed["fidelity"]["execution_level"], "<withheld by --no-poc>")

    def test_what_the_manual_runner_printed_does_not_travel(self) -> None:
        """Allowed wholesale until it was measured.

        `manual_poc_checks` is keyed `<build>_<action>` and each entry's
        `output` is what the runner printed: status, every response header
        and the full body of both builds. That is the material
        `validation.*.observations` is dropped for and REPORT.md's Evidence
        section is blanked for, one key away from both. Measured elsewhere in
        the archive: a lab shipping 6 KB of a 404 page with internal static
        paths, and one shipping both builds' bodies with their build hashes.
        """
        for name in ("report.json", "EVIDENCE.json"):
            held = json.loads(self.filed()[name])
            with self.subTest(name=name):
                checks = held["manual_poc_checks"]
                self.assertEqual(sorted(checks), ["vulnerable_verify"])
                entry = checks["vulnerable_verify"]
                self.assertIs(entry["passed"], True)
                self.assertEqual(entry["exit_code"], 0)
                self.assertEqual(entry["expected_verdict"], "REPRODUCED")
                self.assertNotIn("output", entry)
                self.assertNotIn("stderr", entry)
                self.assertIn(
                    "manual_poc_checks.vulnerable_verify.output",
                    held["withheld_by_no_poc"]["fields"],
                )

    def test_a_path_shorter_than_the_route_allows_nothing(self) -> None:
        """The direction a wildcard path must not fail in.

        `_reaches` compares a dotted path against a route segment by segment,
        and the length check in front of the zip is what stops a path from
        matching a prefix of a deeper route: `manual_poc_checks.*.passed`
        must not allow `manual_poc_checks.<action>.passed.<anything>`, and
        `validation.vulnerable` must not allow `validation.vulnerable.*`. In
        an allowlist a prefix match is a field nobody named travelling, which
        is why the zip is `strict=True` there -- if that guard is ever
        dropped, it raises rather than saying yes.
        """
        value = {
            "manual_poc_checks": {
                "vulnerable_verify": {
                    "passed": {"nested": ATTACK_BEARING["payload"]},
                    "output": ATTACK_BEARING["canary"],
                },
            },
        }
        kept, withheld = upload._allowed(
            value, ("manual_poc_checks.*.passed",)
        )
        # `passed` is named, so its subtree travels -- that is what naming a
        # key means -- and nothing one level deeper is reached by a shorter
        # path.
        self.assertEqual(sorted(withheld), ["manual_poc_checks.vulnerable_verify.output"])
        self.assertNotIn(
            "output", kept["manual_poc_checks"]["vulnerable_verify"]
        )
        self.assertIs(
            upload._reaches(["validation", "vulnerable", "observations"], "validation.vulnerable"),
            False,
        )
        self.assertIs(
            upload._passes_through(["validation", "vulnerable"], "validation.vulnerable"),
            False,
        )

    def test_a_document_this_pass_cannot_classify_is_dropped(self) -> None:
        """The `allowed is None` branch, which nothing else reaches.

        The list invariant above keeps it unreachable today, which is the
        point of the invariant -- but the branch is what makes "withheld by
        default" true, so it is exercised rather than asserted about.
        """
        shrunk = {
            name: paths for name, paths in upload.DESCRIBED_ONLY.items()
            if name != "analysis.json"
        }
        with mock.patch.object(upload, "DESCRIBED_ONLY", shrunk):
            sent = self.filed()
        self.assertNotIn("analysis.json", sent)
        self.assertIn("report.json", sent)

    def test_a_field_nobody_classified_does_not_travel(self) -> None:
        """The allowlist is the point: new fields are withheld by default.

        A denylist would file whatever the next person adds to report.json,
        and the next person is adding it because a run produced it -- which
        is where an attack-bearing field comes from.
        """
        artifacts = self.lab / "artifacts"
        held = json.loads((artifacts / "report.json").read_text())
        held["new_field_from_a_later_cvelab"] = ATTACK_BEARING["payload"]
        (artifacts / "report.json").write_text(json.dumps(held))

        filed = json.loads(self.filed()["report.json"])

        self.assertNotIn("new_field_from_a_later_cvelab", filed)
        self.assertIn(
            "new_field_from_a_later_cvelab", filed["withheld_by_no_poc"]["fields"]
        )

    def test_a_document_nobody_classified_does_not_travel(self) -> None:
        """The same rule one level up, for a name added to ALWAYS."""
        self.assertEqual(
            sorted(
                name for name in upload.ALWAYS
                if name not in upload.EXPLOIT
                and name not in upload.DESCRIBED_ONLY
            ),
            [],
            "a name in ALWAYS that --no-poc neither withholds nor knows how to "
            "redact would be filed whole, or dropped in silence",
        )

    def test_the_description_says_what_was_done_and_what_was_not(self) -> None:
        payload = upload.collect(
            self.lab, RESULT, provider="anthropic", model="m", include_poc=False,
        )
        said = upload.describe(payload)
        self.assertIn("the exploit, the plan and the reproduction steps are withheld", said)
        self.assertIn("redacted out of them", said)
        self.assertIn("not the same as nobody being able to reproduce it", said)
        self.assertNotIn("will not be runnable", said)


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
        # What this line used to say was "the entry will not be runnable".
        # WhatNoPocFilesTests above is why it does not say that any more.
        self.assertIn(
            "the exploit, the plan and the reproduction steps are withheld",
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

    def test_an_oversized_json_document_still_parses(self) -> None:
        # A run on CVE-2026-109618 wrote a 395 KB validator transcript into
        # EVIDENCE.json; a byte cut left JSON that nothing could read.
        raw = "HTTP/1.1 200 OK\n" + "x" * (3 * upload.MAX_DOCUMENT_BYTES)
        evidence = {
            "cve": "CVE-2024-12345",
            "status": "REAL_SOURCE_POC_VALIDATED",
            "validation": {"vulnerable": {"raw": raw}, "patched": {"raw": "403"}},
            "automation": {"attempts": [{"error": "e" * 16000}]},
        }
        lab = make_lab(self.root)
        (lab / "artifacts" / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2))
        document = upload.read_document(lab / "artifacts" / "EVIDENCE.json")

        self.assertTrue(document["truncated"])
        self.assertLessEqual(
            len(document["text"].encode("utf-8")), upload.MAX_DOCUMENT_BYTES
        )
        kept = json.loads(document["text"])
        self.assertEqual(kept["cve"], evidence["cve"])
        self.assertEqual(kept["status"], evidence["status"])
        self.assertEqual(kept["validation"]["patched"], {"raw": "403"})
        self.assertEqual(kept["automation"], evidence["automation"])
        trimmed = kept["validation"]["vulnerable"]["raw"]
        self.assertTrue(trimmed.startswith("HTTP/1.1 200 OK\n"))
        self.assertTrue(trimmed.endswith("bytes trimmed]"))

    def test_json_that_cannot_be_shortened_inside_is_still_cut(self) -> None:
        # Many short strings: no single field can give way.
        crowd = json.dumps(["y" * 100] * 2000)
        self.assertIsNone(upload.fit_json(crowd, upload.MAX_DOCUMENT_BYTES))
        self.assertIsNone(upload.fit_json("{not json", upload.MAX_DOCUMENT_BYTES))
        lab = make_lab(self.root)
        (lab / "artifacts" / "report.json").write_text(crowd)
        document = upload.read_document(lab / "artifacts" / "report.json")
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
        self.assertIn("awaiting review", upload.sharing({"ok": True, "shared": True}))

    def test_every_reason_for_keeping_a_run_private_is_explained(self) -> None:
        for reason in (
            "exploit_withheld", "duplicate", "review_queue_full",
            "script_not_generated", "poc_rejected", "earlier_entry_rejected",
        ):
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


class ADeclineIsNotAFailureTests(unittest.TestCase):
    """What the control plane stores for a CVE that needs a vendor artifact.

    `sourcegen` answers VENDOR_ARTIFACT_REQUIRED beside ARTIFACT_REQUIRED, for
    the narrower reason that the affected product is proprietary -- an
    appliance, an operating system, a licensed binary. Both say the same
    thing: there is no public source to build a lab from, and nothing about
    the request can change that. Absent from STATUS, the narrower one fell
    through the default to "failed" while the broader one was filed as the
    decline it is, so a batch's failure rate counted every proprietary product
    in it as something that had gone wrong.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # One lab for the whole class: make_lab() creates its directories, so
        # calling it twice under one root fails before anything is collected.
        self.lab = make_lab(self.root)

    def filed_as(self, outcome: str) -> str:
        payload = upload.collect(
            self.lab,
            {"ok": False, "cve": "CVE-2024-12345", "status": outcome},
            provider=None,
            model=None,
            include_poc=True,
        )
        self.assertEqual(payload["outcome"], outcome)
        return payload["status"]

    def test_a_vendor_artifact_is_filed_as_a_decline(self) -> None:
        self.assertEqual(self.filed_as("VENDOR_ARTIFACT_REQUIRED"), "declined")

    def test_it_is_filed_the_same_way_as_the_status_beside_it(self) -> None:
        self.assertEqual(
            self.filed_as("VENDOR_ARTIFACT_REQUIRED"),
            self.filed_as("ARTIFACT_REQUIRED"),
        )

    def test_the_map_is_exactly_what_the_package_can_produce(self) -> None:
        """Pinned whole, because the defect was an omission and the comment
        above STATUS says an unknown status is reported as failed rather than
        guessed at. The same rule applies to additions: a status belongs here
        only once it has been read at the place that returns it.

        POC_NOT_VERIFIED, from deliverables.create_deliverables, is the other
        status that reaches collect() without being listed. It is left out on
        purpose: it means the lab did not prove, so the default is the right
        answer for it.

        UNSUPPORTED was added under this rule rather than against it: it is in
        the closed-image planner's status enum and is returned verbatim from
        the branch that fires whenever the plan is not READY, so it reaches
        collect() the same way ARTIFACT_REQUIRED does from that planner.

        A closed lab that ran and whose predicate did not hold is deliberately
        NOT listed. Its result carries no status key at all, so it takes the
        default, and "failed" is the truthful answer there: real images were
        started and the effect did not appear. That is a failure to reproduce,
        not a judgement that it could not be tried.
        """
        self.assertEqual(
            upload.STATUS,
            {
                "VALIDATED": "succeeded",
                "ARTIFACT_REQUIRED": "declined",
                "VENDOR_ARTIFACT_REQUIRED": "declined",
                "UNSUPPORTED": "declined",
                "GENERATION_NOT_AVAILABLE": "declined",
                "PROVIDER_DECLINED": "declined",
                "AUTO_GENERATION_FAILED": "failed",
                "AUTO_REPAIR_EXHAUSTED": "failed",
            },
        )

    def test_a_plan_that_cannot_be_reproduced_is_declined_not_failed(self) -> None:
        """The closed-image planner judging a product unreproducible is an
        answer, not a crash. Filed as a failure it would read as the tool
        having broken on a CVE it actually assessed and reported on.
        """
        self.assertEqual(self.filed_as("UNSUPPORTED"), "declined")
        self.assertEqual(self.filed_as("UNSUPPORTED"), self.filed_as("ARTIFACT_REQUIRED"))

    def test_a_declined_run_does_not_claim_to_be_shared(self) -> None:
        payload = upload.collect(
            self.lab,
            {"ok": False, "cve": "CVE-2024-12345",
             "status": "VENDOR_ARTIFACT_REQUIRED"},
            provider=None, model=None, include_poc=True,
        )
        self.assertNotIn("shared database", upload.describe(payload))
