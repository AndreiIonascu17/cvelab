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

import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from cvelab import baseimages, sourcegen

ACCEPTED = "application/vnd.oci.image.index.v1+json"
CHALLENGE = 'Bearer realm="https://auth.example.test/token",service="registry.test"'


class _Headers(dict):
    """Just enough of an HTTPMessage: a case-insensitive get of one header."""

    def get(self, name, default=None):  # type: ignore[override]
        for key, value in self.items():
            if key.lower() == str(name).lower():
                return value
        return default


class _Response:
    def __init__(self, status: int, headers: dict | None = None, body: bytes = b"") -> None:
        self.status = status
        self.headers = _Headers(headers or {})
        self._body = body

    def read(self, _size: int | None = None) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_exception) -> bool:
        return False


def _registry(answers: dict[str, object], token: str | None = "tok"):
    """A urlopen that answers manifest URLs from a table and issues one token.

    The table is keyed on the manifest reference, so a test says what the
    registry thinks and nothing else. A reference the table does not mention is
    a programming error in the test, not a 404.
    """
    calls: list[str] = []

    def urlopen(request, timeout=None):  # noqa: ARG001
        url = request.full_url
        calls.append(url)
        if "/token" in url:
            if token is None:
                raise urllib.error.HTTPError(url, 403, "denied", _Headers(), None)
            return _Response(200, body=json.dumps({"token": token}).encode())
        for reference, answer in answers.items():
            if url.endswith("/manifests/" + reference):
                if isinstance(answer, Exception):
                    raise answer
                if request.headers.get("Authorization"):
                    if answer == 200:
                        return _Response(200, {"Docker-Content-Digest": "sha256:a"})
                    raise urllib.error.HTTPError(url, int(answer), "no", _Headers(), None)
                raise urllib.error.HTTPError(
                    url, 401, "unauthorized", _Headers({"WWW-Authenticate": CHALLENGE}), None
                )
        raise AssertionError(f"the test registry was asked about {url}")

    return urlopen, calls


class TagStateTests(unittest.TestCase):
    """A registry answer becomes one of three words, and only one of them refuses."""

    def setUp(self) -> None:
        baseimages._STATE_CACHE.clear()
        baseimages._TOKEN_CACHE.clear()
        self.addCleanup(baseimages._STATE_CACHE.clear)
        self.addCleanup(baseimages._TOKEN_CACHE.clear)

    def test_the_three_answers(self) -> None:
        # One published tag, one that provably never existed, and a registry
        # that cannot be reached at all. The absent tag is the measured shape:
        # a real repository asked for a tag it never published.
        urlopen, _calls = _registry({
            "3.12-bookworm": 200,
            "3.8.16-bookworm": 404,
            "3.11-trixie": urllib.error.URLError("timed out"),
        })
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            self.assertEqual(baseimages.tag_state("python:3.12-bookworm"), "published")
            self.assertEqual(baseimages.tag_state("python:3.8.16-bookworm"), "absent")
            self.assertEqual(baseimages.tag_state("python:3.11-trixie"), "unknown")

    def test_a_repository_that_does_not_exist_is_unknown_not_absent(self) -> None:
        """Docker Hub answers 401, never 404, for a repository it does not have.

        It will not confirm that a name is free, because that would enumerate
        private repositories. From here a 401 and a private repository are the
        same observation, so this cannot refuse -- the build still catches it,
        and `autoflow._unknown_base_image` classifies `pull access denied`.
        """
        urlopen, _calls = _registry({"latest": 401})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            self.assertEqual(baseimages.tag_state("nosuchorg/nosuchimage"), "unknown")

    def test_a_token_that_cannot_be_had_is_unknown(self) -> None:
        urlopen, _calls = _registry({"3.12-bookworm": 200}, token=None)
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            self.assertEqual(baseimages.tag_state("python:3.12-bookworm"), "unknown")

    def test_an_official_image_is_asked_about_under_library(self) -> None:
        urlopen, calls = _registry({"3.12-bookworm": 200})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            baseimages.tag_state("python:3.12-bookworm")
        self.assertTrue(any("/v2/library/python/manifests/" in url for url in calls), calls)

    def test_another_registry_keeps_its_own_host_and_repository(self) -> None:
        urlopen, calls = _registry({"0.5.11": 200})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            self.assertEqual(baseimages.tag_state("ghcr.io/astral-sh/uv:0.5.11"), "published")
        self.assertTrue(any(url.startswith("https://ghcr.io/v2/astral-sh/uv/") for url in calls), calls)

    def test_a_namespace_is_not_mistaken_for_a_registry(self) -> None:
        # The measured second case was a namespaced image, not an official one.
        urlopen, calls = _registry({"eclipse-temurin-17.0.11_9_1.10.0_3.4.2": 404})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            self.assertEqual(
                baseimages.tag_state("sbtscala/scala-sbt:eclipse-temurin-17.0.11_9_1.10.0_3.4.2"),
                "absent",
            )
        self.assertTrue(
            any(url.startswith("https://registry-1.docker.io/v2/sbtscala/scala-sbt/") for url in calls),
            calls,
        )

    def test_the_answer_is_cached_for_the_process(self) -> None:
        # One round trip per FROM per generation, and the same tags recur across
        # the three Dockerfiles of one lab and across every contract retry.
        urlopen, calls = _registry({"3.12-bookworm": 200})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            for _ in range(4):
                baseimages.tag_state("python:3.12-bookworm")
        self.assertEqual(len([url for url in calls if "/manifests/" in url]), 2, calls)

    def test_nothing_that_cannot_be_asked_about_is_asked_about(self) -> None:
        def urlopen(_request, timeout=None):  # noqa: ARG001
            raise AssertionError("the registry must not be asked")

        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            for reference in ("scratch", "SCRATCH", "${BASE_IMAGE}", "python:$TAG", ""):
                with self.subTest(reference=reference):
                    self.assertEqual(baseimages.tag_state(reference), "unknown")

    def test_the_off_switch_asks_nothing(self) -> None:
        def urlopen(_request, timeout=None):  # noqa: ARG001
            raise AssertionError("the registry must not be asked")

        with mock.patch.dict(baseimages.os.environ, {"CVELAB_BASE_IMAGES": "off"}), \
                mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            self.assertEqual(baseimages.tag_state("python:3.8.16-bookworm"), "unknown")
            self.assertEqual(baseimages.refusals({"vulnerable/Dockerfile": "FROM python:3.8.16-bookworm"}), [])

    def test_a_digest_pin_is_split_correctly(self) -> None:
        self.assertEqual(
            baseimages.split_reference("python@sha256:" + "a" * 64),
            ("registry-1.docker.io", "library/python", "sha256:" + "a" * 64),
        )

    def test_a_port_in_the_host_is_a_registry(self) -> None:
        self.assertEqual(
            baseimages.split_reference("localhost:5000/team/app:1.2"),
            ("localhost:5000", "team/app", "1.2"),
        )


class FromTagsTests(unittest.TestCase):
    """What a Dockerfile really pulls, as opposed to what its FROM lines say."""

    def test_platform_aliases_and_stage_references(self) -> None:
        dockerfile = (
            "# a comment naming FROM nothing:real\n"
            "FROM --platform=linux/amd64 golang:1.21-bookworm AS build\n"
            "RUN <<EOF\n"
            "FROM inside-a-heredoc:1\n"
            "EOF\n"
            "FROM debian:bookworm-slim \\\n"
            "    AS runtime\n"
            "COPY --from=build /app /app\n"
            "FROM build AS final\n"
            "FROM BUILD\n"
        )
        self.assertEqual(
            baseimages.from_tags(dockerfile),
            ["golang:1.21-bookworm", "debian:bookworm-slim"],
        )

    def test_an_untagged_image_is_latest(self) -> None:
        self.assertEqual(baseimages.from_tags("FROM debian\n"), ["debian"])
        self.assertEqual(
            baseimages.split_reference("debian"), ("registry-1.docker.io", "library/debian", "latest")
        )

    def test_a_repeated_from_is_listed_once(self) -> None:
        self.assertEqual(
            baseimages.from_tags("FROM python:3.12-bookworm AS a\nFROM python:3.12-bookworm AS b\n"),
            ["python:3.12-bookworm"],
        )

    def test_it_shares_the_instruction_reader_with_the_copy_check(self) -> None:
        # Not a second parser: line continuations, comments and heredoc bodies
        # are handled in one place, and a copy of that logic would drift.
        self.assertIn("_dockerfile_instructions", Path(baseimages.__file__).read_text(encoding="utf-8"))


class CheckPathTests(unittest.TestCase):
    """What `_check_base_images` does with each of the three answers."""

    def setUp(self) -> None:
        baseimages._STATE_CACHE.clear()
        baseimages._TOKEN_CACHE.clear()
        self.addCleanup(baseimages._STATE_CACHE.clear)
        self.addCleanup(baseimages._TOKEN_CACHE.clear)

    def files(self, reference: str) -> list[dict]:
        return [
            {"path": "docker-compose.yml", "content": "services: {}"},
            {"path": "vulnerable/Dockerfile", "content": f"FROM {reference}\nRUN true\n"},
            {"path": "patched/Dockerfile", "content": f"FROM {reference}\nRUN true\n"},
            {"path": "validator/Dockerfile", "content": "FROM python:3.13-alpine\n"},
            {"path": "adapter/Dockerfile", "content": "FROM never-asked-about:1\n"},
        ]

    def test_an_absent_tag_is_refused_before_any_build(self) -> None:
        urlopen, _calls = _registry({"3.8.16-bookworm": 404, "3.13-alpine": 200})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            with self.assertRaises(RuntimeError) as refused:
                sourcegen._check_base_images(self.files("python:3.8.16-bookworm"))
        message = str(refused.exception)
        self.assertIn("vulnerable/Dockerfile", message)
        self.assertIn("python:3.8.16-bookworm", message)
        self.assertIn("publishes no such tag", message)
        # Say what to do instead, from the confirmed table: a repair told only
        # that a tag is wrong reaches for another tag the same way.
        self.assertIn("python:3.13-bookworm", message)

    def test_an_unknown_tag_never_raises(self) -> None:
        """The test that protects the rate.

        If a registry that could not be reached refused, every network hiccup
        would become a refused generation spending the contract-retry budget on
        a tag that was fine. Each of these is "I could not check".
        """
        for answer in (
            urllib.error.URLError("timed out"),
            OSError("connection reset"),
            401,
            429,
            500,
        ):
            with self.subTest(answer=answer):
                baseimages._STATE_CACHE.clear()
                baseimages._TOKEN_CACHE.clear()
                urlopen, _calls = _registry({"3.11-sid": answer, "3.13-alpine": 200})
                with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
                    sourcegen._check_base_images(self.files("python:3.11-sid"))

    def test_a_published_tag_passes(self) -> None:
        urlopen, _calls = _registry({"3.12-bookworm": 200, "3.13-alpine": 200})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            sourcegen._check_base_images(self.files("python:3.12-bookworm"))

    def test_only_the_three_built_dockerfiles_are_asked_about(self) -> None:
        # Compose pins every build to vulnerable/, patched/ and validator/, so
        # a Dockerfile the answer returns under adapter/ is never pulled and a
        # round trip for it would be spent on nothing.
        urlopen, calls = _registry({"3.12-bookworm": 200, "3.13-alpine": 200})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            sourcegen._check_base_images(self.files("python:3.12-bookworm"))
        self.assertFalse([url for url in calls if "never-asked-about" in url], calls)

    def test_it_is_mounted_in_every_check_beside_the_copy_check(self) -> None:
        source = Path(sourcegen.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count("_check_base_images(generated_files)"), 3)
        self.assertEqual(source.count("_check_build_inputs(generated_files"), 3)


class ToolchainSectionTests(unittest.TestCase):
    """The deterministic half: what the snapshot declares, and nothing it does not."""

    def snapshot(self, files: dict[str, str]) -> Path:
        """A lab directory with a vendor snapshot under source/vulnerable."""
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        root = Path(holder.name) / "source" / "vulnerable"
        root.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return Path(holder.name)

    def offered(self, section: str) -> list[str]:
        """The tags the section offers, as opposed to the declarations it lists."""
        after = section.partition("confirmed are published:\n")[2]
        return [
            line[2:] for line in after.splitlines()
            if line.startswith("- ")
        ]

    def test_it_carries_what_the_snapshot_declares(self) -> None:
        lab = self.snapshot({
            "go.mod": "module example.com/widget\n\ngo 1.21\n\nrequire (\n)\n",
            "package.json": json.dumps({"name": "w", "engines": {"node": ">=18.0.0"}}),
            ".python-version": "3.9.18\n",
            "pom.xml": "<project><properties>"
                       "<maven.compiler.release>17</maven.compiler.release>"
                       "</properties></project>",
            "Gemfile": "source 'https://rubygems.org'\nruby '3.1.4'\n",
        })
        section = baseimages.toolchain_section(lab / "source" / "vulnerable")
        self.assertIn("--- TOOLCHAIN ---", section)
        for declaration in ("go.mod: go 1.21", "package.json: node 18",
                            ".python-version: python 3.9.18", "pom.xml: java 17",
                            "Gemfile: ruby 3.1.4"):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, section)
        # The declared version's own tag, and the right distribution release
        # for it rather than the newest one.
        self.assertIn("golang:1.21-bookworm", section)

    def test_it_is_absent_rather_than_wrong_when_the_snapshot_declares_nothing(self) -> None:
        lab = self.snapshot({"README.md": "a project with no declared toolchain\n"})
        self.assertEqual(baseimages.toolchain_section(lab / "source" / "vulnerable"), "")
        # An ecosystem alone does not conjure one. The advisory says which
        # registry shipped the fix, not which interpreter the snapshot builds
        # with, and a section built from it would be a guess dressed as a
        # finding while the model already has the tree.
        self.assertEqual(baseimages.toolchain_section(lab / "source" / "vulnerable", ["npm"]), "")
        self.assertEqual(baseimages.toolchain_section(lab / "source" / "nonexistent"), "")

    def test_the_ecosystem_adds_tags_once_the_snapshot_has_spoken(self) -> None:
        lab = self.snapshot({"go.mod": "module x\n\ngo 1.21\n"})
        plain = baseimages.toolchain_section(lab / "source" / "vulnerable")
        widened = baseimages.toolchain_section(lab / "source" / "vulnerable", ["npm"])
        self.assertIn("golang:1.21-bookworm", plain)
        self.assertNotIn("node:", plain)
        self.assertIn("node:", widened)

    def test_a_module_one_level_down_is_found(self) -> None:
        # A monorepo keeps go.mod in a module directory, and those are exactly
        # the repositories where guessing a base image goes wrong.
        lab = self.snapshot({"cmd/server/README": "x", "service/go.mod": "module x\n\ngo 1.19\n"})
        section = baseimages.toolchain_section(lab / "source" / "vulnerable")
        self.assertIn("service/go.mod: go 1.19", section)
        self.assertIn("golang:1.19-bullseye", section)

    def test_it_costs_no_network_call(self) -> None:
        # Trap: a section that confirmed its own tags would be a dozen round
        # trips on every prompt build, including every repair. The table was
        # confirmed once, at authoring time, by the same tag_state path.
        def urlopen(_request, timeout=None):  # noqa: ARG001
            raise AssertionError("assembling the toolchain section must not use the network")

        lab = self.snapshot({"go.mod": "module x\n\ngo 1.21\n"})
        with mock.patch.object(baseimages.urllib.request, "urlopen", urlopen):
            self.assertIn("golang:1.21-bookworm", baseimages.toolchain_section(lab / "source" / "vulnerable"))

    def test_every_declared_language_gets_a_tag_within_the_cap(self) -> None:
        """Four toolchains, five slots, and none of them left to invention.

        Walking one language at a time instead would spend every slot on the
        first, and the language with no tag is the one the model then guesses
        at -- which is the whole failure this section exists to remove.
        """
        lab = self.snapshot({
            "go.mod": "module x\n\ngo 1.21\n",
            ".python-version": "3.9\n",
            "Gemfile": "ruby '3.1.4'\n",
            "Cargo.toml": '[package]\nrust-version = "1.75"\n',
        })
        offered = self.offered(baseimages.toolchain_section(lab / "source" / "vulnerable"))
        self.assertEqual(len(offered), baseimages.MAX_OFFERED_TAGS)
        for prefix in ("golang:", "python:", "ruby:", "rust:"):
            with self.subTest(prefix=prefix):
                self.assertTrue([tag for tag in offered if tag.startswith(prefix)], offered)

    def test_the_prompt_builder_mounts_it(self) -> None:
        import ast

        source = Path(sourcegen.__file__).read_text(encoding="utf-8")
        self.assertIn('baseimages.toolchain_section(lab_dir / "source" / "vulnerable"', source)
        # All three prompts -- the differential generation, the vulnerable-only
        # generation and the repair -- go through _prompt_context, so one mount
        # reaches every one of them. An inventory of its call sites, so a
        # fourth prompt has to say here whether it wants the section.
        calls = [
            node for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_prompt_context"
        ]
        self.assertEqual(len(calls), 3)
        for call in calls:
            with self.subTest(line=call.lineno):
                self.assertIn("lab_dir", [keyword.arg for keyword in call.keywords])

    def test_a_declaration_file_that_is_nonsense_is_skipped_not_fatal(self) -> None:
        lab = self.snapshot({
            "package.json": "{not json at all",
            "go.mod": "module x\n\ngo 1.21\n",
        })
        section = baseimages.toolchain_section(lab / "source" / "vulnerable")
        self.assertIn("go.mod: go 1.21", section)
        self.assertNotIn("package.json", section)


class NetworkInventoryTests(unittest.TestCase):
    """Every request this module can make, listed so a new one is reviewed here.

    The same guarantee `sourcegen` and `revisions` keep for git calls, for the
    thing this module adds instead: outbound requests. Both of these must stay
    behind the off switch and behind the "every failure is unknown" handling,
    because a request that raises past `_request` would turn an unreachable
    registry into a failed generation.
    """

    def test_there_are_exactly_two_request_sites(self) -> None:
        source = Path(baseimages.__file__).read_text(encoding="utf-8")
        # One in _request, for the manifest; one in _bearer_token, for the
        # token exchange that a registry's challenge asks for.
        self.assertEqual(source.count("urllib.request.urlopen("), 2)
        self.assertEqual(source.count("def _request("), 1)
        self.assertEqual(source.count("def _bearer_token("), 1)

    def test_no_request_is_made_outside_tag_state(self) -> None:
        # The toolchain half is deterministic, so only the check reaches out.
        import ast

        source = Path(baseimages.__file__).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.FunctionDef):
                continue
            reaches_out = any(
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id in ("_request", "_bearer_token")
                for inner in ast.walk(node)
            )
            if reaches_out:
                self.assertIn(node.name, ("tag_state", "_bearer_token"), node.name)

    def test_the_module_runs_no_subprocess(self) -> None:
        # Nothing here shells out, so the git end-of-options inventories that
        # cover sourcegen and revisions have nothing to cover here. If that
        # changes, this is where it gets noticed.
        source = Path(baseimages.__file__).read_text(encoding="utf-8")
        for banned in ("subprocess", "os.system", "os.popen"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)


class ConfirmedTableTests(unittest.TestCase):
    """The table is the deterministic artifact, so its shape is pinned here.

    Its contents were confirmed against the live registry by the same
    `tag_state` path this module uses; a test cannot re-confirm them, because no
    test may reach the network.
    """

    def test_every_entry_is_a_reference_that_can_be_asked_about(self) -> None:
        for language, table in baseimages._TOOLCHAIN_IMAGES.items():
            for key, tag in table:
                with self.subTest(language=language, tag=tag):
                    self.assertIsNotNone(baseimages.split_reference(tag))
                    self.assertIn(":", tag)
                    self.assertTrue(tag.split(":")[1].startswith(key), tag)

    def test_a_version_picks_its_own_release_and_not_the_newest(self) -> None:
        # The measured failure class in one line: an old interpreter must not
        # be paired with a new distribution release by analogy.
        self.assertEqual(baseimages._tags_for("python", "3.8")[0], "python:3.8-buster")
        self.assertEqual(baseimages._tags_for("node", "14")[0], "node:14-buster")
        self.assertEqual(baseimages._tags_for("java", "8")[0], "eclipse-temurin:8-jdk-focal")

    def test_a_patch_version_resolves_to_its_minor_line(self) -> None:
        self.assertEqual(baseimages._tags_for("python", "3.8.16")[0], "python:3.8-buster")


if __name__ == "__main__":
    unittest.main()
