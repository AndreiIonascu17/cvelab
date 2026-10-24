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

import re
import unittest
from pathlib import Path

from cvelab.sourcegen import (
    _canonicalize_validator_dockerfile,
    _validate_fidelity,
    _validate_generated,
    _validate_support_services,
)


def generated_files(validator: str) -> list[dict[str, str]]:
    return [
        {
            "path": "docker-compose.yml",
            "content": """services:
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
""",
        },
        {"path": "vulnerable/Dockerfile", "content": "FROM scratch\n"},
        {"path": "patched/Dockerfile", "content": "FROM scratch\n"},
        {"path": "validator/Dockerfile", "content": "FROM scratch\n"},
        {"path": "validator/validator.py", "content": validator},
    ]


class GeneratedValidatorContractTests(unittest.TestCase):
    def test_validator_copy_is_made_relative_to_isolated_context(self) -> None:
        dockerfile = "FROM python:3.13-alpine\nCOPY validator/validator.py /validator/validator.py\n"
        normalized = _canonicalize_validator_dockerfile(dockerfile)
        self.assertIn("COPY validator.py /validator/validator.py", normalized)

    def test_manual_contract_is_required(self) -> None:
        validator = " ".join([
            "attack_executed", "proof_quality", "observable_effect", "evidence_type",
            "vulnerable", "patched", "differential_confirmed", "confirmed", "blocked",
        ])
        with self.assertRaisesRegex(RuntimeError, "manual PoC contract"):
            _validate_generated(generated_files(validator))

    def test_manual_contract_is_accepted(self) -> None:
        validator = " ".join([
            "attack_executed", "proof_quality", "observable_effect", "evidence_type",
            "vulnerable", "patched", "differential_confirmed", "confirmed", "blocked",
            "CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "exploit", "verify",
        ])
        _validate_generated(generated_files(validator))

    def test_fidelity_cannot_promote_component_adapter_to_product(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "cannot claim"):
            _validate_fidelity({
                "execution_level": "source_component",
                "vendor_product_started": True,
                "exercised_vendor_components": ["parser"],
                "simulated_components": ["server"],
            })

    def test_vendor_service_fidelity_is_accepted_when_product_starts(self) -> None:
        _validate_fidelity({
            "execution_level": "vendor_service",
            "vendor_product_started": True,
            "exercised_vendor_components": ["vendor server"],
            "simulated_components": ["local backend"],
        })

    def test_product_end_to_end_requires_product_to_start(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "requires the actual vendor product"):
            _validate_fidelity({
                "execution_level": "product_end_to_end",
                "vendor_product_started": False,
                "exercised_vendor_components": ["request path"],
                "simulated_components": [],
            })

    def test_support_services_must_exist_in_compose(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "support service is missing"):
            _validate_support_services(["upstream"], "services:\n  vulnerable:\n")

        _validate_support_services(
            ["upstream"],
            "services:\n  upstream:\n    image: example.invalid/upstream\n",
        )


if __name__ == "__main__":
    unittest.main()


class ValidatorVerdictGuardTests(unittest.TestCase):
    """The guard must reject a faked verdict and accept an honest one.

    Banning a literal `"attack_executed": True` rejected every validator
    written exactly as the instruction asks, across two unrelated model
    families, on all four attempts each. The contract defines that field as
    "the regression input was actually delivered" -- a fact the code knows
    once it has sent it. Only `confirmed` and `differential_confirmed` have
    to be computed.
    """

    PATTERN = re.compile(
        r"['\"](?:confirmed|differential_confirmed)['\"]\s*:\s*True\b"
    )

    HONEST = """
    sent = deliver(payload)
    observed = MARKER in sent.text
    result = {
        "attack_executed": True,
        "vulnerable": {"confirmed": observed},
        "differential_confirmed": observed and not patched_observed,
    }
    """

    FAKED = """
    result = {
        "attack_executed": True,
        "vulnerable": {"confirmed": True},
        "differential_confirmed": True,
    }
    """

    def test_an_honest_validator_is_accepted(self) -> None:
        self.assertIsNone(self.PATTERN.search(self.HONEST))

    def test_a_faked_verdict_is_rejected(self) -> None:
        self.assertIsNotNone(self.PATTERN.search(self.FAKED))

    def test_the_shipped_guard_is_this_one(self) -> None:
        source = (
            Path(__file__).resolve().parent.parent / "cvelab" / "sourcegen.py"
        ).read_text(encoding="utf-8")
        self.assertIn("confirmed|differential_confirmed", source)
        self.assertNotIn("attack_executed|confirmed|differential_confirmed", source)


class ExternalTargetGuardTests(unittest.TestCase):
    """An interpolated host is a variable, not a destination.

    The contract requires the validator to honour CVELAB_TARGET, which
    forces f"http://{target}/...". Reading that placeholder as an external
    host made two rules of the same contract unsatisfiable together: a
    validator that supported the manual interface was rejected for reaching
    outside, and one that avoided the f-string was rejected for missing the
    manual interface.
    """

    HOSTS = re.compile(r"https?://([^/'\"\s:]+)")
    ALLOWED = {"vulnerable", "patched", "127.0.0.1", "localhost"}

    def rejected(self, source: str) -> list[str]:
        return [
            host
            for host in self.HOSTS.findall(source.lower())
            if "{" not in host and "%" not in host and host not in self.ALLOWED
        ]

    def test_an_interpolated_target_is_allowed(self) -> None:
        self.assertEqual(self.rejected('url = f"http://{target}/read"'), [])

    def test_a_printf_interpolated_target_is_allowed(self) -> None:
        self.assertEqual(self.rejected('url = "http://%s:%d/read" % (target, PORT)'), [])
        self.assertEqual(self.rejected('url = "http://%(host)s/read" % values'), [])

    def test_a_real_external_host_is_still_rejected(self) -> None:
        self.assertEqual(
            self.rejected('get("http://evil.example.com/x")'), ["evil.example.com"]
        )

    def test_the_lab_network_hosts_are_allowed(self) -> None:
        self.assertEqual(self.rejected('get("http://vulnerable:8080/health")'), [])

    def test_the_shipped_guard_skips_placeholders(self) -> None:
        source = (
            Path(__file__).resolve().parent.parent / "cvelab" / "sourcegen.py"
        ).read_text(encoding="utf-8")
        self.assertIn('if "{" in url or "%" in url:', source)


class AdapterTreeTests(unittest.TestCase):
    """adapter/ holds a project, not a flat list of files.

    Exercising a library usually means a real one: package.json beside its
    source, go.mod beside a main. Allowing a single level under adapter/
    refused a lodash lab three times over
    adapter/vulnerable/package.json, and the repair budget ran out on a
    structural rule rather than on anything about the vulnerability.
    """

    def allowed(self, path: str) -> bool:
        from pathlib import PurePosixPath

        from cvelab.sourcegen import ALLOWED_GENERATED

        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts:
            return False
        return bool(ALLOWED_GENERATED.fullmatch(path))

    def test_a_nested_project_is_allowed(self) -> None:
        self.assertTrue(self.allowed("adapter/vulnerable/package.json"))
        self.assertTrue(self.allowed("adapter/a/b/c/index.js"))

    def test_the_flat_files_still_work(self) -> None:
        for path in (
            "adapter/server.js",
            "docker-compose.yml",
            "validator/validator.py",
            "vulnerable/Dockerfile",
        ):
            with self.subTest(path=path):
                self.assertTrue(self.allowed(path))

    def test_file_based_routes_are_allowed(self) -> None:
        for path in (
            "adapter/fixture/app/pages/admin/[slug].vue",
            "adapter/site/src/pages/[...all].astro",
            "adapter/app/(group)/@modal/[[...rest]]/page.tsx",
            "adapter/kit/src/routes/+page.svelte",
            "adapter/remix/app/routes/posts.$id.tsx",
            "adapter/kit/src/routes/[id=int]/+page.ts",
        ):
            with self.subTest(path=path):
                self.assertTrue(self.allowed(path))

    def test_names_no_platform_can_hold_are_still_refused(self) -> None:
        for path in ("adapter/a b.js", "adapter/a:b.js", "adapter/a*b", "adapter/a?b", "adapter/a|b",
                     'adapter/a"b', "adapter/a<b>", "adapter/a\\b.js"):
            with self.subTest(path=path):
                self.assertFalse(self.allowed(path))

    def test_escaping_the_directory_is_still_refused(self) -> None:
        for path in ("../etc/passwd", "/etc/passwd", "adapter/../../x", "adapter/"):
            with self.subTest(path=path):
                self.assertFalse(self.allowed(path))

    def test_a_file_outside_the_allowed_roots_is_still_refused(self) -> None:
        # Depth is not what makes a path unsafe; writing outside the
        # adapter is.
        self.assertFalse(self.allowed("server.js"))
        self.assertFalse(self.allowed("source/vulnerable/x.py"))


class ConfirmedSemanticsTests(unittest.TestCase):
    """The contract has to say what confirmed means, on both sides.

    Two DeepSeek runs, two CVEs, two ecosystems, the same two checks
    failing. Its validator used a different rule per side:

        vulnerable_confirmed = vuln_canary               # the effect
        patched_confirmed    = patch_status is not None  # a reply arrived

    A patched build that refuses the input still answers, so the second
    rule calls a successful defence a successful exploit and inverts the
    proof. Opus called one observe() for both sides and passed. Nothing in
    the contract asked for that, so the model that guessed differently was
    not contradicting anything written down.

    manual_poc_verified failed alongside it, but only as a consequence:
    those checks sit behind `if automatic_proof`, so they never ran.
    """

    SOURCE = (
        Path(__file__).resolve().parent.parent / "cvelab" / "sourcegen.py"
    ).read_text(encoding="utf-8")
    SENTENCE = "Measure confirmed the same way on both sides"

    def test_a_rejection_is_not_a_confirmation(self) -> None:
        # Fragments that sit on one source line: the sentence itself is
        # split across string literals, so the assembled prompt is what
        # carries it, not any single line of the file.
        self.assertIn("confirmed=false and blocked=true", self.SOURCE)
        self.assertIn("the security effect was observed", self.SOURCE)
        self.assertIn("recording that as a confirmation", self.SOURCE)

    def test_every_prompt_that_names_the_keys_also_defines_confirmed(self) -> None:
        # Two prompt blocks build a validator contract -- the differential
        # one and the vulnerable-only one. A clarification added to one of
        # them is half a fix, and counting occurrences would not notice:
        # the first attempt at this landed twice in the same block.
        blocks = self.SOURCE.split("the literal keys attack_executed")
        self.assertEqual(len(blocks), 3, "expected exactly two contract prompts")
        for number, block in enumerate(blocks[1:], 1):
            with self.subTest(prompt=number):
                head = block[:2000]
                self.assertIn(self.SENTENCE, head)


class AdapterFilesTests(unittest.TestCase):
    """adapter_files are written last, so they must not replace a canonical file.

    One named docker-compose.yml or validator/Dockerfile overwrote the copy
    the canonicalisers had just pinned, and every later check with it.
    """

    def test_a_canonical_name_is_refused(self) -> None:
        from cvelab.sourcegen import _adapter_files

        for path in ("docker-compose.yml", "./docker-compose.yml", "validator/Dockerfile",
                     "Validator/Dockerfile", "validator\\validator.py", ".dockerignore",
                     "vulnerable/Dockerfile", "patched/Dockerfile"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(RuntimeError, "field of its own"):
                    _adapter_files([{"path": path, "content": "x"}])

    def test_the_adapter_tree_and_validator_requirements_are_fine(self) -> None:
        from cvelab.sourcegen import _adapter_files

        files = [{"path": "adapter/server.js", "content": "x"},
                 {"path": "validator/requirements.txt", "content": "requests\n"}]
        self.assertEqual(_adapter_files(files), files)

    def test_every_generation_path_uses_it(self) -> None:
        source = (Path(__file__).resolve().parent.parent / "cvelab" / "sourcegen.py").read_text(encoding="utf-8")
        self.assertEqual(source.count('_adapter_files(generation["adapter_files"])'), 3)
        self.assertNotIn('*generation["adapter_files"]', source.replace('*_adapter_files(generation["adapter_files"])', ""))
        # And the written lab is checked against what Docker would run.
        self.assertEqual(source.count("_enforce_compose_policy(lab_dir)"), 3)


class ComposePolicyAtGenerationTests(unittest.TestCase):
    def test_it_is_skipped_without_docker(self) -> None:
        from unittest import mock

        from cvelab import sourcegen

        with mock.patch.object(sourcegen, "docker_executable", side_effect=RuntimeError("Docker CLI was not found")), \
                mock.patch.object(sourcegen.policy, "enforce") as enforce:
            sourcegen._enforce_compose_policy(Path("/labs/CVE-2026-0001"))
        enforce.assert_not_called()

    def test_it_uses_the_command_and_environment_a_run_uses(self) -> None:
        from unittest import mock

        from cvelab import sourcegen

        with mock.patch.object(sourcegen, "docker_executable", return_value="/usr/bin/docker"), \
                mock.patch.object(sourcegen.policy, "enforce") as enforce:
            sourcegen._enforce_compose_policy(Path("/labs/CVE-2026-0001"))
        compose, lab, environment = enforce.call_args.args
        self.assertEqual(compose[:4], ["/usr/bin/docker", "compose", "-p", "cve-2026-0001"])
        self.assertEqual(environment["COMPOSE_DISABLE_ENV_FILE"], "1")


class GitRevisionTests(unittest.TestCase):
    """A revision from a model, plan.json or the command line reaches git.

    `--output=/path` as a revision is an option to `git diff`, which writes
    the file. A model answering from web search is not a trusted source.
    """

    def test_commits_tags_and_branches_are_accepted(self) -> None:
        from cvelab.sourcegen import _safe_revision

        for value in ("a" * 40, "deadbee", "v1.2.3", "release/1.0", "refs/tags/v2.0.0-rc1",
                      "1.2.3+build", f"{'a' * 40}^", "abc1234~2"):
            with self.subTest(value=value):
                self.assertEqual(_safe_revision(value, "revision"), value)

    def test_options_and_odd_syntax_are_refused(self) -> None:
        from cvelab.sourcegen import _safe_revision

        for value in ("--output=/tmp/x", "-n", "a..b", "HEAD@{1}", "main:path", "x y",
                      "refs//x", "x.lock", "x/", "", None, "../x", "a\nb"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "not a commit id"):
                    _safe_revision(value, "revision")

    def test_every_git_call_ends_its_options(self) -> None:
        source = (Path(__file__).resolve().parent.parent / "cvelab" / "sourcegen.py").read_text(encoding="utf-8")
        for call in ('"archive", "--format=tar", "--end-of-options"',
                     '"diff", "--no-ext-diff", "--unified=80", "--end-of-options"',
                     '"diff", "--name-only", "--end-of-options"',
                     '"ls-tree", "-r", "--name-only", "--end-of-options"',
                     '"show", "--end-of-options"',
                     '"--no-checkout", "--end-of-options"',
                     '"fetch", "--depth=2", "--no-tags", "--end-of-options"'):
            with self.subTest(call=call):
                self.assertIn(call, source)
        # An inventory of the call sites that pass a revision from outside, so
        # a new one has to be reviewed rather than inherited: two forced
        # fetches in the generator, and three verifications once the
        # closed-source resolver checks a fix it only reads.
        self.assertEqual(source.count('"fetch", "--force", "--end-of-options", "origin"'), 2)
        self.assertEqual(source.count('"rev-parse", "--verify", "--end-of-options"'), 3)

    def test_a_discovered_revision_is_validated(self) -> None:
        from unittest import mock

        from cvelab import sourcegen

        discovery = {
            "status": "SOURCE_READY", "artifact_type": "library",
            "repository_url": "https://github.com/example/widget", "fixed_ref": "--output=/tmp/pwned",
            "vulnerable_ref": None, "vendor_artifact": None, "rationale": "", "evidence_urls": [],
        }
        with mock.patch.object(sourcegen, "collect_cve", return_value={"cve": "CVE-2026-0001", "references": []}), \
                mock.patch.object(sourcegen, "resolve_source_via_osv", return_value=None), \
                mock.patch.object(sourcegen, "ai_is_configured", return_value=True), \
                mock.patch.object(sourcegen, "provider_supports_web_search", return_value=True), \
                mock.patch.object(sourcegen, "discover_source_with_ai", return_value=discovery), \
                mock.patch.object(sourcegen, "_run_git") as git:
            with self.assertRaisesRegex(ValueError, "source discovery returned"):
                sourcegen.generate_source_lab(
                    "CVE-2026-0001", Path("/nonexistent"), None, None, None, "k", "m", "openai"
                )
        git.assert_not_called()
