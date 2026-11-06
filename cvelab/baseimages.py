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

"""Base images: what the snapshot's own toolchain is, and whether a FROM resolves.

The model writes every byte of every Dockerfile, including every `FROM`, and
until this module nothing in the package ever asked a registry whether the tag
it named exists. One measured run paired a Python version with a Debian release
that never had an image for it; the build died resolving metadata, before a
single layer ran, and the recorded Docker text said only that the tag was `not
found`. A repair handed that log reached for another tag the same way.

Two things live here, and the first matters more:

* `toolchain_section` reads what the vendor snapshot declares about its own
  toolchain -- the `go` directive, `engines`, `.python-version`, the Maven
  compiler release -- and names base image tags that were confirmed published.
  It costs no model call, no build and, deliberately, no network: it removes
  the invention instead of catching it.
* `tag_state` asks a registry. It is the catch, mounted as a pre-generation
  check so a bad tag costs one model call and zero builds rather than a build
  that fails after the images before it succeeded.

`tag_state` is tri-state on purpose and that is load-bearing. An unreachable
registry means "I could not check", never "it does not exist": collapsing the
two would turn every network hiccup into a refused generation that spends the
contract-retry budget on a tag that was fine. Only `"absent"` ever refuses.

Everything here is best effort and never raises, as in `releases._get` and
`resolve_source_via_osv`. CVELAB_BASE_IMAGES=off turns the registry lookup off.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

#: Docker Hub when a reference names no registry.
DEFAULT_REGISTRY = "registry-1.docker.io"

#: Short. This runs before a generation, so an unreachable registry must cost
#: seconds and then yield "unknown", not stall the run: the answer it would
#: have given is advisory, and the build is still there to catch the tag.
TIMEOUT_SECONDS = 15

#: Ask for every manifest shape a base image can have. A registry that is
#: offered only the v2 schema answers 404 for a multi-platform image whose
#: index is the only thing published under that tag, which would read as
#: `absent` for a perfectly good tag.
_MANIFEST_ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))

_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')

#: Per process, keyed on the normalised reference. Confirming a tag costs a
#: network round trip per FROM, the same handful of tags recur across the three
#: Dockerfiles of one lab, and every contract retry re-checks the answer it
#: just refused.
_STATE_CACHE: dict[str, str] = {}
_TOKEN_CACHE: dict[tuple[str, tuple[tuple[str, str], ...]], str | None] = {}


def enabled() -> bool:
    """Whether the registry lookup runs (CVELAB_BASE_IMAGES)."""
    return os.getenv("CVELAB_BASE_IMAGES", "").strip().lower() not in {"0", "off", "false", "no"}


def _is_registry_host(candidate: str) -> bool:
    """Whether the first path segment of a reference is a registry and not a namespace.

    `sbtscala/scala-sbt` is a Docker Hub namespace; `ghcr.io/astral-sh/uv` and
    `localhost:5000/x` name a registry. A dot or a port tells them apart, which
    is the same rule the Docker CLI uses.
    """
    return "." in candidate or ":" in candidate or candidate == "localhost"


def split_reference(reference: str) -> tuple[str, str, str] | None:
    """A reference as registry, repository and tag-or-digest; None if it cannot be asked about.

    None for `scratch`, which no registry serves, and for anything carrying a
    build argument: `FROM ${BASE}` is not a tag until the build expands it, and
    guessing would be the invention this module exists to remove.
    """
    reference = (reference or "").strip()
    if not reference or reference.lower() == "scratch":
        return None
    if "$" in reference or any(character.isspace() for character in reference):
        return None
    registry = DEFAULT_REGISTRY
    body = reference
    head, separator, rest = reference.partition("/")
    if separator and _is_registry_host(head):
        registry, body = head, rest
    if "@" in body:
        repository, _, digest = body.partition("@")
        reference_part = digest
    elif ":" in body.rsplit("/", 1)[-1]:
        repository, _, reference_part = body.rpartition(":")
    else:
        repository, reference_part = body, "latest"
    if not repository or not reference_part:
        return None
    # An official image is `library/<name>` in the registry API even though
    # nobody writes it that way in a Dockerfile.
    if registry == DEFAULT_REGISTRY and "/" not in repository:
        repository = "library/" + repository
    return registry, repository, reference_part


def _request(url: str, headers: dict[str, str], method: str) -> tuple[int | None, object]:
    """A status and its headers, with every failure reported as no status at all."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "cvelab", **headers}, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, response.headers
    except urllib.error.HTTPError as error:
        # A status is an answer, including 401 and 404; only the transport
        # failing below is "I could not check".
        return error.code, error.headers
    except (urllib.error.URLError, OSError, ValueError):
        return None, {}


def _bearer_token(challenge: str, repository: str) -> str | None:
    """The anonymous pull token a `WWW-Authenticate` challenge asks for.

    Docker Hub and ghcr.io both answer the first manifest request with a
    challenge naming the realm, the service and the scope, so the scope is read
    from the challenge rather than assembled; a registry that omits it gets the
    pull scope for this repository.
    """
    parameters = dict(_CHALLENGE.findall(challenge or ""))
    realm = parameters.pop("realm", "")
    if not realm.startswith("https://"):
        return None
    parameters.pop("error", None)
    parameters.setdefault("scope", f"repository:{repository}:pull")
    key = (realm, tuple(sorted(parameters.items())))
    if key in _TOKEN_CACHE:
        return _TOKEN_CACHE[key]
    url = realm + "?" + urllib.parse.urlencode(parameters)
    request = urllib.request.Request(url, headers={"User-Agent": "cvelab"})
    token = None
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            document = json.loads(response.read(1 << 20))
        if isinstance(document, dict):
            value = document.get("token") or document.get("access_token")
            token = str(value) if value else None
    except (urllib.error.URLError, OSError, ValueError):
        token = None
    _TOKEN_CACHE[key] = token
    return token


def tag_state(reference: str) -> str:
    """Whether a registry serves this reference: "published", "absent" or "unknown".

    "absent" only on a 404, which is the registry saying the repository is there
    and this tag is not. That is the whole measured class: both recorded cases
    were a real repository asked for a tag it never published.

    Everything else is "unknown", and the 401 case is why this is tri-state and
    not a boolean. Docker Hub answers 401, never 404, for a repository that does
    not exist, so that it cannot be used to enumerate private repositories --
    verified against the live registry while this was written. From here a 401
    and a private repository are the same observation, so an invented
    *repository* name is not refused; a build failure says `pull access denied`
    and `autoflow._unknown_base_image` still classifies it.
    """
    if not enabled():
        return "unknown"
    parts = split_reference(reference)
    if parts is None:
        return "unknown"
    registry, repository, wanted = parts
    cache_key = f"{registry}/{repository}:{wanted}"
    if cache_key in _STATE_CACHE:
        return _STATE_CACHE[cache_key]
    url = (
        f"https://{registry}/v2/{urllib.parse.quote(repository)}"
        f"/manifests/{urllib.parse.quote(wanted, safe=':')}"
    )
    headers = {"Accept": _MANIFEST_ACCEPT}
    status, response_headers = _request(url, headers, "HEAD")
    if status == 401:
        challenge = ""
        if hasattr(response_headers, "get"):
            challenge = response_headers.get("WWW-Authenticate") or ""
        token = _bearer_token(challenge, repository)
        if token:
            status, _ = _request(url, {**headers, "Authorization": f"Bearer {token}"}, "HEAD")
    if status == 200:
        state = "published"
    elif status == 404:
        state = "absent"
    else:
        # A registry that refuses HEAD, rate-limits, or is simply down lands
        # here, and so does the 401 above. Never a refusal.
        state = "unknown"
    _STATE_CACHE[cache_key] = state
    return state


_FROM = re.compile(r"(?i)^FROM\s+(.*)$")


def from_tags(text: str) -> list[str]:
    """The base images a Dockerfile really pulls, in order and without repeats.

    Stage aliases are dropped both ways: the `AS <alias>` a stage declares, and
    a later `FROM <alias>` that refers to one, which is a name inside this file
    and not a tag any registry has heard of.
    """
    # Imported here and not at module scope: sourcegen imports this module, so
    # a module-level import back would be a cycle. _dockerfile_instructions is
    # the one piece worth sharing -- it joins line continuations and drops
    # comments and heredoc bodies, and a second copy of that would drift.
    from .sourcegen import _dockerfile_instructions

    references: list[str] = []
    aliases: set[str] = set()
    for instruction in _dockerfile_instructions(text or ""):
        match = _FROM.match(instruction)
        if not match:
            continue
        words = match.group(1).split()
        words = [word for word in words if not word.lower().startswith("--platform=")]
        if not words:
            continue
        reference = words[0]
        if len(words) >= 3 and words[1].lower() == "as":
            # Stage names are case-insensitive, so the alias is recorded folded.
            aliases.add(words[2].lower())
        if reference.lower() in aliases:
            continue
        if reference not in references:
            references.append(reference)
    return references


#: Version-to-tag pairs confirmed published against the live registry on
#: 2026-11-06, by the same `tag_state` path this module uses. The pairing is
#: the whole point: an interpreter reaches end of life at about the time the
#: distribution release under it reaches the archive, so the newest release is
#: wrong for an old version and there is no image for the combination. Tags
#: that look just as reasonable and are not published, confirmed the same way:
#: `eclipse-temurin:21-jdk-focal`, `eclipse-temurin:24-jdk-jammy`,
#: `ruby:2.6-jessie`, and every tag of `openjdk`, a deprecated official image
#: whose repository still answers and whose tags were removed.
#:
#: Minor-level tags, not patch-level. The measured failure was a patch version
#: pinned against a release, and a patch-level tag is also the one that stops
#: existing: the floating minor tag is maintained for as long as the line is.
_TOOLCHAIN_IMAGES: dict[str, list[tuple[str, str]]] = {
    "python": [
        ("3.13", "python:3.13-bookworm"), ("3.12", "python:3.12-bookworm"),
        ("3.11", "python:3.11-bookworm"), ("3.10", "python:3.10-bullseye"),
        ("3.9", "python:3.9-bullseye"), ("3.8", "python:3.8-buster"),
        ("3.7", "python:3.7-buster"), ("3.6", "python:3.6-stretch"),
        ("2.7", "python:2.7-buster"),
    ],
    "node": [
        ("24", "node:24-bookworm"), ("22", "node:22-bookworm"),
        ("20", "node:20-bookworm"), ("18", "node:18-bullseye"),
        ("16", "node:16-bullseye"), ("14", "node:14-buster"),
        ("12", "node:12-buster"), ("10", "node:10-buster"), ("8", "node:8-jessie"),
    ],
    "go": [
        ("1.24", "golang:1.24-bookworm"), ("1.23", "golang:1.23-bookworm"),
        ("1.22", "golang:1.22-bookworm"), ("1.21", "golang:1.21-bookworm"),
        ("1.20", "golang:1.20-bullseye"), ("1.19", "golang:1.19-bullseye"),
        ("1.18", "golang:1.18-bullseye"), ("1.17", "golang:1.17-buster"),
        ("1.16", "golang:1.16-buster"),
    ],
    "java": [
        ("24", "eclipse-temurin:24-jdk-noble"), ("21", "eclipse-temurin:21-jdk-jammy"),
        ("17", "eclipse-temurin:17-jdk-jammy"), ("11", "eclipse-temurin:11-jdk-focal"),
        ("8", "eclipse-temurin:8-jdk-focal"),
    ],
    "ruby": [
        ("3.4", "ruby:3.4-bookworm"), ("3.3", "ruby:3.3-bookworm"),
        ("3.2", "ruby:3.2-bookworm"), ("3.1", "ruby:3.1-bullseye"),
        ("3.0", "ruby:3.0-buster"), ("2.7", "ruby:2.7-buster"),
    ],
    "php": [
        ("8.4", "php:8.4-cli-bookworm"), ("8.3", "php:8.3-cli-bookworm"),
        ("8.2", "php:8.2-cli-bookworm"), ("8.1", "php:8.1-cli-bullseye"),
        ("8.0", "php:8.0-cli-bullseye"), ("7.4", "php:7.4-cli-buster"),
        ("7.2", "php:7.2-cli-stretch"),
    ],
    "rust": [
        ("1.86", "rust:1.86-bookworm"), ("1.82", "rust:1.82-bookworm"),
        ("1.79", "rust:1.79-bookworm"), ("1.75", "rust:1.75-bookworm"),
        ("1.70", "rust:1.70-bookworm"),
    ],
}

#: The advisory ecosystem names a language family when the snapshot's own
#: declarations do not. Taken from what the caller already resolved, never by
#: calling `releases.advisory_packages` again: that is a second network round
#: trip, and it would be paid on every prompt build.
ECOSYSTEM_LANGUAGES = {
    "npm": "node", "pip": "python", "maven": "java", "go": "go",
    "rubygems": "ruby", "composer": "php", "rust": "rust", "cargo": "rust",
}

#: How many tags the section offers. Enough to cover the snapshot's own version
#: and the releases either side of it, few enough to stay a hint.
MAX_OFFERED_TAGS = 5

#: Read from the snapshot root and one level down. A monorepo keeps its go.mod
#: or package.json in a module directory, and a pass over the root alone
#: produced no toolchain section at all for exactly the repositories -- the
#: large ones -- where guessing a base image goes wrong. One level and no
#: deeper: this runs on every prompt build, and a recursive walk of a tree with
#: twenty thousand files to find a `go` directive would not pay for itself.
_MAX_SUBDIRECTORIES = 48
_MAX_READ_BYTES = 256 * 1024


def _read(path: Path) -> str:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_READ_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _version(text: str) -> str:
    """The first version-looking token of a declaration, or "" if there is none."""
    match = re.search(r"\d+(?:\.\d+)*", text or "")
    return match.group(0) if match else ""


def _declare_go_mod(text: str) -> tuple[str, str] | None:
    match = re.search(r"(?m)^\s*go\s+(\d+(?:\.\d+)+)\s*$", text)
    return ("go", match.group(1)) if match else None


def _declare_package_json(text: str) -> tuple[str, str] | None:
    try:
        document = json.loads(text)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    engines = document.get("engines")
    if not isinstance(engines, dict):
        return None
    declared = engines.get("node")
    version = _version(str(declared)) if declared else ""
    return ("node", version) if version else None


def _declare_python_version(text: str) -> tuple[str, str] | None:
    # .python-version may list several interpreters, one per line; the first is
    # the one the project builds against.
    for line in text.splitlines():
        version = _version(line.strip())
        if version:
            return ("python", version)
    return None


def _declare_pyproject(text: str) -> tuple[str, str] | None:
    match = re.search(r"""(?m)^\s*requires-python\s*=\s*["']([^"']+)["']""", text)
    return ("python", _version(match.group(1))) if match and _version(match.group(1)) else None


def _declare_pom(text: str) -> tuple[str, str] | None:
    for pattern in (
        r"<maven\.compiler\.release>\s*([^<\s]+)\s*</maven\.compiler\.release>",
        r"<maven\.compiler\.target>\s*([^<\s]+)\s*</maven\.compiler\.target>",
        r"<maven\.compiler\.source>\s*([^<\s]+)\s*</maven\.compiler\.source>",
        r"<java\.version>\s*([^<\s]+)\s*</java\.version>",
        r"<release>\s*([^<\s]+)\s*</release>",
    ):
        match = re.search(pattern, text)
        if match:
            # Java 8 is written 1.8 in every one of these elements.
            declared = match.group(1).strip()
            return ("java", "8" if declared in ("1.8", "8") else _version(declared))
    return None


def _declare_gradle(text: str) -> tuple[str, str] | None:
    match = re.search(
        r"(?:sourceCompatibility|targetCompatibility|languageVersion[^\n]*?of)"
        r"[^\n]*?(?:VERSION_)?(\d+(?:[._]\d+)?)",
        text,
    )
    if not match:
        return None
    declared = match.group(1).replace("_", ".")
    return ("java", "8" if declared in ("1.8", "8") else _version(declared))


def _declare_gemfile(text: str) -> tuple[str, str] | None:
    match = re.search(r"""(?m)^\s*ruby\s+["']([^"']+)["']""", text)
    return ("ruby", _version(match.group(1))) if match and _version(match.group(1)) else None


def _declare_composer(text: str) -> tuple[str, str] | None:
    try:
        document = json.loads(text)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    require = document.get("require")
    if not isinstance(require, dict):
        return None
    version = _version(str(require.get("php") or ""))
    return ("php", version) if version else None


def _declare_cargo(text: str) -> tuple[str, str] | None:
    match = re.search(r"""(?m)^\s*rust-version\s*=\s*["']([^"']+)["']""", text)
    return ("rust", _version(match.group(1))) if match and _version(match.group(1)) else None


def _declare_plain(language: str):
    def reader(text: str) -> tuple[str, str] | None:
        version = _version(text.strip().splitlines()[0] if text.strip() else "")
        return (language, version) if version else None
    return reader


def _declare_tool_versions(text: str) -> tuple[str, str] | None:
    # asdf and mise: `<tool> <version>` per line, so take the first tool this
    # module knows how to offer an image for.
    for line in text.splitlines():
        words = line.split()
        if len(words) < 2:
            continue
        language = {"nodejs": "node", "node": "node", "python": "python", "golang": "go",
                    "go": "go", "ruby": "ruby", "java": "java", "php": "php",
                    "rust": "rust"}.get(words[0].lower())
        version = _version(words[1])
        if language and version:
            return (language, version)
    return None


#: Each declaration file and how to read a toolchain version out of it, in the
#: order the section lists them. A project that declares the same language
#: twice is reported once, from the first file here that says so.
_DECLARATIONS: tuple[tuple[str, object], ...] = (
    ("go.mod", _declare_go_mod),
    (".python-version", _declare_python_version),
    ("pyproject.toml", _declare_pyproject),
    (".nvmrc", _declare_plain("node")),
    ("package.json", _declare_package_json),
    ("pom.xml", _declare_pom),
    ("build.gradle", _declare_gradle),
    ("build.gradle.kts", _declare_gradle),
    (".ruby-version", _declare_plain("ruby")),
    ("Gemfile", _declare_gemfile),
    ("composer.json", _declare_composer),
    ("Cargo.toml", _declare_cargo),
    (".tool-versions", _declare_tool_versions),
)


def declarations(root: Path) -> list[tuple[str, str, str]]:
    """What the snapshot says about its own toolchain, as (file, language, version).

    The file is relative to the snapshot root, so the prompt can say where the
    version came from: a model told "go 1.21" argues with it, and a model told
    "go.mod declares go 1.21" has nowhere to argue.
    """
    try:
        if not root.is_dir():
            return []
    except OSError:
        return []
    found: list[tuple[str, str, str]] = []
    seen_languages: set[str] = set()
    directories = [root]
    try:
        directories += sorted(
            child for child in root.iterdir()
            if child.is_dir() and not child.name.startswith(".")
        )[:_MAX_SUBDIRECTORIES]
    except OSError:
        pass
    for directory in directories:
        for name, reader in _DECLARATIONS:
            text = _read(directory / name)
            if not text:
                continue
            declared = reader(text)
            if not declared:
                continue
            language, version = declared
            if language in seen_languages:
                continue
            seen_languages.add(language)
            try:
                relative = (directory / name).relative_to(root).as_posix()
            except ValueError:  # pragma: no cover - directories come from root
                relative = name
            found.append((relative, language, version))
    return found


def _tags_for(language: str, version: str) -> list[str]:
    """Confirmed tags for a language, the declared version's own first.

    Not the declared version alone: `engines.node: ">=18"` and a `go` directive
    are both floors rather than pins, and the neighbours either side are what a
    build that needs one more release can reach for without inventing a tag.
    """
    table = _TOOLCHAIN_IMAGES.get(language) or []
    if not table:
        return []
    if not version:
        return [tag for _key, tag in table[:2]]
    wanted = tuple(int(part) for part in version.split(".") if part.isdigit())
    def distance(entry: tuple[str, str]) -> tuple[int, ...]:
        key = tuple(int(part) for part in entry[0].split(".") if part.isdigit())
        width = max(len(key), len(wanted))
        padded_key = key + (0,) * (width - len(key))
        padded_wanted = wanted + (0,) * (width - len(wanted))
        return (sum(abs(a - b) for a, b in zip(padded_key, padded_wanted)), *padded_key)
    return [tag for _key, tag in sorted(table, key=distance)][:3]


def toolchain_section(root: Path, ecosystems: object = ()) -> str:
    """The prompt section naming the snapshot's toolchain and tags known to exist.

    Empty when the snapshot declares nothing: a section assembled from an
    advisory ecosystem alone would say "this is a Node project, here are some
    Node tags", which is a guess dressed as a finding, and the model already
    has the tree. The snapshot's own files are the only authority here.
    """
    declared = declarations(Path(root))
    if not declared:
        return ""
    languages = [language for _file, language, _version in declared]
    for ecosystem in ecosystems or ():
        language = ECOSYSTEM_LANGUAGES.get(str(ecosystem or "").strip().lower())
        if language and language not in languages:
            languages.append(language)
    versions = {language: version for _file, language, version in declared}
    # Round-robin and not language by language. A cap reached while walking one
    # language at a time spends every slot on the first one, and a snapshot
    # declaring three toolchains then gets no tag at all for the third -- which
    # is the one the model is then left to invent.
    per_language = [_tags_for(language, versions.get(language, "")) for language in languages]
    offered: list[str] = []
    for rank in range(max((len(tags) for tags in per_language), default=0)):
        for tags in per_language:
            if rank < len(tags) and tags[rank] not in offered:
                offered.append(tags[rank])
    lines = [
        f"- {file}: {language} {version}" if version else f"- {file}: {language}"
        for file, language, version in declared
    ]
    section = (
        "\n\n--- TOOLCHAIN ---\n"
        "Read out of the vendor snapshot itself, from source/vulnerable:\n"
        + "\n".join(lines)
        + "\nBuild with the toolchain the snapshot declares. A newer one is a different "
        "lab: it changes what compiles and what the affected code path does.\n"
    )
    if offered:
        section += (
            "Base image tags CVELab has confirmed are published:\n"
            + "\n".join(f"- {tag}" for tag in offered[:MAX_OFFERED_TAGS])
            + "\nA FROM naming a tag that was never published fails the build while it resolves "
            "metadata, before one layer runs, and the log then says nothing about this lab. "
            "Pair a language version with a distribution release only where an image for that "
            "combination exists: a release reaches the archive at about the time the interpreter "
            "pinned on top of it reaches end of life, so for an old version there is usually no "
            "image on a supported release, and pairing it with a newer one by analogy produces a "
            "tag nobody ever built -- one measured run lost its whole build to a Python version "
            "paired with a Debian release that never had an image for it. Where that is the "
            "situation the answer is the older release with apt pointed at archive.debian.org. "
            "Prefer a minor-version tag over a patch-version one; a tag from the list above is "
            "checked already.\n"
        )
    return section


def refusals(dockerfiles: dict[str, str]) -> list[str]:
    """One sentence per FROM a registry says does not exist; empty when none do.

    Only `"absent"`. A tag the registry could not be asked about is left to the
    build, which is where it was caught before this check existed.
    """
    if not enabled():
        return []
    problems = []
    for path in sorted(dockerfiles):
        for reference in from_tags(dockerfiles[path]):
            if tag_state(reference) != "absent":
                continue
            repository = reference.rpartition(":")[0] or reference
            language = next(
                (name for name, table in _TOOLCHAIN_IMAGES.items()
                 if any(tag.startswith(repository.rsplit("/", 1)[-1] + ":") for _key, tag in table)),
                "",
            )
            alternatives = [tag for _key, tag in _TOOLCHAIN_IMAGES.get(language, [])][:4]
            hint = (
                " Tags of this image that are published: " + ", ".join(alternatives) + "."
                if alternatives
                else ""
            )
            problems.append(
                f"{path} starts FROM {reference}, and the registry answers that this repository "
                f"publishes no such tag. The build would die resolving metadata before any layer "
                f"ran. This is not transient: the registry's answer will not change." + hint
            )
    return problems
