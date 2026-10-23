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

import difflib
import fnmatch
import hashlib
import io
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from . import policy, progress, research
from .ai import (
    ai_is_configured,
    provider_supports_web_search,
    resolve_provider,
    structured_response,
)
from .core import (
    CVE_PATTERN,
    collect_cve,
    compose_command,
    docker_environment,
    docker_executable,
    normalize_cve,
    redact,
    write_text,
)
from .research import clip_section as _clip_context_section

SOURCE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "cwe", "confidence", "rationale", "fidelity", "exploit_contract", "docker_compose",
        "dockerignore", "vulnerable_dockerfile", "patched_dockerfile",
        "validator_dockerfile", "validator_py", "support_services", "adapter_files",
    ],
    "properties": {
        "cwe": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
        "fidelity": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "execution_level", "vendor_product_started",
                "exercised_vendor_components", "simulated_components", "rationale",
            ],
            "properties": {
                "execution_level": {
                    "type": "string",
                    "enum": ["source_component", "vendor_service", "product_end_to_end"],
                },
                "vendor_product_started": {"type": "boolean"},
                # _validate_fidelity refuses an empty list; saying so here
                # lets a provider with constrained decoding never produce one,
                # instead of spending a generation attempt on it.
                "exercised_vendor_components": {
                    "type": "array", "minItems": 1, "items": {"type": "string"},
                },
                "simulated_components": {
                    "type": "array", "items": {"type": "string"},
                },
                "rationale": {"type": "string"},
            },
        },
        "exploit_contract": {
            "type": "object",
            "additionalProperties": False,
            "required": ["attack_summary", "preconditions", "observable_effect", "evidence_type"],
            "properties": {
                "attack_summary": {"type": "string"},
                "preconditions": {"type": "array", "items": {"type": "string"}},
                "observable_effect": {"type": "string"},
                "evidence_type": {
                    "type": "string",
                    "enum": [
                        "authorization_bypass", "unauthorized_read", "unauthorized_write",
                        "code_execution", "request_forgery", "data_exposure",
                        "integrity_violation", "security_boundary_violation"
                    ],
                },
            },
        },
        "docker_compose": {"type": "string", "minLength": 1},
        "dockerignore": {"type": "string"},
        "vulnerable_dockerfile": {"type": "string", "minLength": 1},
        "patched_dockerfile": {"type": "string", "minLength": 1},
        "validator_dockerfile": {"type": "string", "minLength": 1},
        "validator_py": {"type": "string", "minLength": 1},
        # A product end to end can need a database, a cache, a queue, a mail
        # catcher and an identity provider; ten files did not hold a real
        # project beside its harness. The ceilings are sanity bounds only.
        "support_services": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"},
        },
        "adapter_files": {
            "type": "array",
            "maxItems": 80,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "content"],
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        },
    },
}

VULNERABLE_ONLY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "cwe", "confidence", "rationale", "fidelity", "exploit_contract", "docker_compose",
        "dockerignore", "vulnerable_dockerfile", "validator_dockerfile",
        "validator_py", "support_services", "adapter_files",
    ],
    "properties": {
        key: SOURCE_SCHEMA["properties"][key]
        for key in (
            "cwe", "confidence", "rationale", "fidelity", "exploit_contract", "docker_compose",
            "dockerignore", "vulnerable_dockerfile", "validator_dockerfile",
            "validator_py", "support_services", "adapter_files",
        )
    },
}

DISCOVERY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "status", "artifact_type", "repository_url", "vulnerable_ref", "fixed_ref",
        "vendor_artifact", "rationale", "evidence_urls",
    ],
    "properties": {
        "status": {
            "type": "string",
            "enum": ["SOURCE_READY", "VULNERABLE_ONLY", "VENDOR_ARTIFACT_REQUIRED", "INSUFFICIENT_DATA"],
        },
        "artifact_type": {"type": "string"},
        "repository_url": {"type": ["string", "null"]},
        "vulnerable_ref": {"type": ["string", "null"]},
        "fixed_ref": {"type": ["string", "null"]},
        "vendor_artifact": {"type": ["string", "null"]},
        "rationale": {"type": "string"},
        "evidence_urls": {"type": "array", "items": {"type": "string"}},
    },
}

GITHUB_COMMIT = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})(?:[?#].*)?$",
    re.IGNORECASE,
)
GITLAB_COMMIT = re.compile(
    r"^(https://[^/]+/[^/]+/[^/]+?)/-/commit/([0-9a-f]{7,40})(?:[?#].*)?$",
    re.IGNORECASE,
)
# adapter/ takes a tree, not a flat list of files. Exercising a library
# usually means a real project -- package.json beside its source, a go.mod
# beside a main -- and allowing only one level under adapter/ left no way
# to express that: a lodash lab was refused three times for writing
# adapter/vulnerable/package.json. Depth is not what makes a path unsafe;
# escaping the directory is, and that is still refused by the absolute and
# ".." checks at the call site.
#
# A name may also carry the characters file-based routers give meaning to:
# [slug].vue and [...all].astro, (group)/@modal/page.tsx, +page.svelte,
# posts.$id.tsx, [id=int]. A Nuxt lab was refused for
# adapter/fixture/app/pages/admin/[slug].vue, which is the only way Nuxt
# spells that route. All of them are valid file names on Windows too.
ALLOWED_GENERATED = re.compile(
    r"^(docker-compose\.yml|\.dockerignore|(?:vulnerable|patched)/Dockerfile|"
    r"validator/(?:Dockerfile|validator\.py|requirements\.txt)|"
    r"adapter/[A-Za-z0-9_.\-\[\]()@+$=~]+(?:/[A-Za-z0-9_.\-\[\]()@+$=~]+)*)$"
)
FORBIDDEN = {
    "privileged:": "privileged containers",
    "network_mode: host": "host networking",
    "/var/run/docker.sock": "Docker socket mounting",
    "cap_add:": "additional Linux capabilities",
    "pid: host": "host PID namespace",
    "ipc: host": "host IPC namespace",
    "nc -e": "reverse-shell tooling",
    "netcat -e": "reverse-shell tooling",
    "/dev/tcp/": "shell network callbacks",
    "authorized_keys": "SSH persistence",
    "mimikatz": "credential theft tooling",
}




SOURCE_HEALTH_PY = r'''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        body = b'{"ok":true}' if self.path == "/health" else b'not found'
        self.send_response(200 if self.path == "/health" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''






def _run_git(arguments: list[str], cwd: Path | None = None, binary: bool = False):
    git = shutil.which("git")
    if not git:
        raise RuntimeError("Git was not found")
    text_options = (
        {"text": False}
        if binary
        else {"text": True, "encoding": "utf-8", "errors": "replace"}
    )
    completed = subprocess.run(
        [git, *arguments],
        cwd=cwd,
        capture_output=True,
        **text_options,
    )
    if completed.returncode:
        error = (
            completed.stderr or ""
            if not binary
            else (completed.stderr or b"").decode("utf-8", errors="replace")
        )
        raise RuntimeError(f"git {' '.join(arguments[:3])} failed: {error.strip()}")
    if completed.stdout is not None:
        return completed.stdout
    return b"" if binary else ""


def _safe_repo_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Only public HTTPS repository URLs are accepted")
    if parsed.hostname.lower() not in {"github.com", "gitlab.com"}:
        raise ValueError("Automatic source retrieval currently supports GitHub and GitLab")
    return value.rstrip("/")


OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{cve}"
OSV_TIMEOUT_SECONDS = 20
# A hexadecimal commit id, not a tag or a branch: the lab must be reproducible.
COMMIT_ID = re.compile(r"[0-9a-f]{7,40}")
# A revision that arrives from outside -- the command line, plan.json, or a
# model's answer from web search -- before it reaches git: a commit id or a
# plain tag or branch name, optionally followed by ^ or ~N. It cannot start
# with "-", so git cannot read it as an option such as --output=<file>; every
# git call that takes one passes --end-of-options as well, which needs Git
# 2.30 or newer.
GIT_REVISION = re.compile(r"([A-Za-z0-9_][A-Za-z0-9._/+-]{0,199})((?:[~^][0-9]{0,3})*)")


def _safe_revision(value: object, label: str) -> str:
    text = str(value or "").strip()
    match = GIT_REVISION.fullmatch(text)
    name = match.group(1) if match else ""
    if not match or ".." in name or "//" in name or name.endswith((".", "/", ".lock")):
        raise ValueError(f"The {label} is not a commit id or a plain tag or branch name: {text!r}")
    return text


def resolve_source_via_osv(cve: str, timeout: int = OSV_TIMEOUT_SECONDS) -> tuple[str, str] | None:
    """Look up the repository and fix commit in OSV.

    A CVE record frequently names no commit. OSV usually does, and in a
    structured form rather than a URL to be parsed: an affected range of type
    GIT carries the repository and a `fixed` event. Measured over a 40-CVE
    sample, the CVE record alone resolved 22; OSV resolved 17 of the
    remaining 18.

    This matters beyond coverage. Without it CVELab falls back to asking the
    model to find the source with web search, which costs money for an answer
    OSV gives free and deterministically.

    Returns None on any failure, including an unreachable OSV, so the caller
    keeps whatever fallback it had.
    """
    if not CVE_PATTERN.fullmatch(cve or ""):
        return None
    request = urllib.request.Request(
        OSV_VULN_URL.format(cve=cve),
        headers={"Accept": "application/json", "User-Agent": "cvelab"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            record = json.load(response)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None

    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for entry in affected.get("ranges") or []:
            if not isinstance(entry, dict) or entry.get("type") != "GIT":
                continue
            repository = entry.get("repo")
            if not repository:
                continue
            for event in entry.get("events") or []:
                commit = isinstance(event, dict) and event.get("fixed")
                if not commit or not COMMIT_ID.fullmatch(str(commit)):
                    continue
                try:
                    # The URL comes from a third party, so it is validated
                    # exactly like one a user passed on the command line.
                    url = _safe_repo_url(str(repository).removesuffix("/") + ".git")
                except (ValueError, RuntimeError):
                    continue
                return url, str(commit)
    return None


def resolve_source(dossier: dict, repo: str | None, fixed_ref: str | None) -> tuple[str, str] | None:
    if repo and fixed_ref:
        return _safe_repo_url(repo), fixed_ref
    for reference in dossier.get("references", []):
        github = GITHUB_COMMIT.match(reference)
        if github:
            return f"https://github.com/{github.group(1)}/{github.group(2)}.git", github.group(3)
        gitlab = GITLAB_COMMIT.match(reference)
        if gitlab:
            return _safe_repo_url(gitlab.group(1) + ".git"), gitlab.group(2)
    # Free and deterministic, so it is tried before the paid AI discovery.
    return resolve_source_via_osv(dossier.get("cve", ""))


def discover_source_with_ai(
    dossier: dict,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    return structured_response(
        api_key=api_key,
        model=model,
        schema=DISCOVERY_SCHEMA,
        schema_name="cvelab_source_discovery",
        max_output_tokens=5000,
        tools=[{"type": "web_search"}],
        include=["web_search_call.action.sources"],
        instructions=(
            "Research public provenance for an authorized local CVE reproduction. Search primary sources: the "
            "vendor advisory, upstream repository, GitHub/GitLab advisory, release notes, package registry, and "
            "exact fixing commits. SOURCE_READY requires a public HTTPS GitHub or GitLab repository and an exact "
            "immutable fixing commit supported by evidence; provide its parent or an evidenced affected commit as "
            "vulnerable_ref. VULNERABLE_ONLY requires an exact evidenced affected tag or commit but no exact public "
            "fix. If an affected revision is evidenced but the fixing commit is absent or ambiguous, you MUST return "
            "VULNERABLE_ONLY even when an advisory names a patched release. "
            "Use VENDOR_ARTIFACT_REQUIRED for proprietary products, appliances, operating systems, licensed "
            "installers, or authenticated downloads. Never invent URLs, versions, repositories, commit hashes, "
            "patches, or runtime-test details. If provenance is ambiguous, return INSUFFICIENT_DATA. This step is "
            "provenance research only; do not design or expand a reproduction procedure."
        ),
        input_text=json.dumps(dossier, ensure_ascii=True),
        provider=provider,
        base_url=base_url,
    )


def _snapshot(repository: Path, revision: str, destination: Path) -> None:
    archive = _run_git(["archive", "--format=tar", "--end-of-options", revision], cwd=repository, binary=True)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        bundle.extractall(destination, filter="data")


#: Files whose opening lines are shown beside the fix: they say how the
#: project is built and what it depends on.
MANIFEST_NAMES = frozenset({
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Cargo.toml", "composer.json",
    "Makefile", "README.md", "README", "Gemfile",
})
#: What else marks a build: the tree sample keeps these ahead of everything
#: but the fix's own neighbours. A path-ordered sample of php-src's 20,000
#: files ended inside .github/ and Zend/, before a single config.m4.
BUILD_NAMES = MANIFEST_NAMES | frozenset({
    "configure.ac", "configure.in", "config.m4", "config.w32", "CMakeLists.txt", "meson.build",
    "meson_options.txt", "Makefile.am", "GNUmakefile", "build.sbt", "build.xml", "Dockerfile",
    "docker-compose.yml", "compose.yaml", "tox.ini", "WORKSPACE", "BUILD.bazel", "mix.exs",
    "Package.swift", "SConstruct",
})
TREE_SAMPLE = 500
EXCERPT_FILES = 24


def _tree_sample(tree: list[str], changed: list[str], limit: int = TREE_SAMPLE) -> list[str]:
    """Up to limit paths of the tree, in its own order.

    Shallow build files first, then the directories the fix touches, then
    deeper build files, then shallow paths, then the rest.
    """
    if len(tree) <= limit:
        return tree
    changed_dirs = {PurePosixPath(path).parent for path in changed}

    def rank(item: tuple[int, str]) -> tuple[int, int]:
        index, path = item
        pure = PurePosixPath(path)
        if pure.name in BUILD_NAMES or pure.suffix in {".gemspec", ".csproj", ".cabal"}:
            group = 0 if len(pure.parts) <= 3 else 2
        elif pure.parent in changed_dirs:
            group = 1
        elif len(pure.parts) <= 2:
            group = 3
        else:
            group = 4
        return group, index

    chosen = sorted(enumerate(tree), key=rank)[:limit]
    return [path for _, path in sorted(chosen)]


def _fix_listing(
    repository: Path, vulnerable_ref: str, fixed_ref: str
) -> tuple[str, list[str], list[str]]:
    """The fix's diff, the files it changes, and the fixed revision's tree."""
    diff = _run_git(
        ["diff", "--no-ext-diff", "--unified=80", "--end-of-options", vulnerable_ref, fixed_ref],
        cwd=repository,
    )
    files = _run_git(
        ["diff", "--name-only", "--end-of-options", vulnerable_ref, fixed_ref], cwd=repository
    ).splitlines()
    tree = _run_git(
        ["ls-tree", "-r", "--name-only", "--end-of-options", fixed_ref], cwd=repository
    ).splitlines()
    return diff, files, tree


def _source_context(
    repository: Path,
    vulnerable_ref: str,
    fixed_ref: str,
    dossier: dict,
    max_chars: int | None = None,
    hint: str | None = None,
    listing: tuple[str, list[str], list[str]] | None = None,
) -> str:
    diff, files, tree = listing or _fix_listing(repository, vulnerable_ref, fixed_ref)
    if len(diff) <= research.PATCH_BUDGET:
        patch, ordered = diff, files
    else:
        described = research.words(" ".join(str(text) for text in dossier.get("descriptions") or []))
        patch, ordered = research.select_patch(diff, described, research.words(hint or ""))
    excerpts = []
    manifests = [item for item in tree if PurePosixPath(item).name in MANIFEST_NAMES]
    for path in list(dict.fromkeys(ordered + manifests))[:EXCERPT_FILES]:
        try:
            content = _run_git(["show", "--end-of-options", f"{fixed_ref}:{path}"], cwd=repository)
        except RuntimeError:
            continue
        excerpts.append(f"\n--- FILE {path} (fixed revision) ---\n{content[:12000]}")
    material = {
        "dossier": dossier,
        "vulnerable_ref": vulnerable_ref,
        "fixed_ref": fixed_ref,
        "changed_files": files,
        "repository_files": len(tree),
        "repository_tree_sample": _tree_sample(tree, files),
    }
    metadata = json.dumps(material, ensure_ascii=True, indent=2)
    guidance = ""
    if hint:
        guidance = (
            "\n\n--- OPERATOR HINT ---\n" + hint
            + "\nThe person running CVELab wrote this to say which part of the fix, or which behaviour, "
            "to reproduce. Follow it where the supplied source supports it. It does not change the lab "
            "contract or any safety rule."
        )
    patch_header = "\n\n--- SECURITY PATCH ---\n"
    whole = metadata + guidance + patch_header + patch + "".join(excerpts)
    # Cut only what does not fit: a context under the budget used to lose
    # half of every excerpt all the same.
    if max_chars is None or len(whole) <= max_chars:
        return whole

    prefix = _clip_context_section(metadata, min(len(metadata), max_chars // 4)) + guidance
    remaining = max_chars - len(prefix) - len(patch_header)
    excerpt_reserve = min(14000, max(0, remaining // 3))
    patch = _clip_context_section(patch, max(0, remaining - excerpt_reserve))
    result = prefix + patch_header + patch
    for excerpt in excerpts:
        available = max_chars - len(result)
        if available <= 0:
            break
        result += _clip_context_section(excerpt, min(6000, available))
    return result[:max_chars]


def _canonicalize_compose_builds(content: str, vulnerable_only: bool = False) -> str:
    """Pin AI-generated Compose builds to the generated adapter layout."""
    layouts = {
        "vulnerable": (".", "vulnerable/Dockerfile"),
        "validator": ("./validator", "Dockerfile"),
    }
    if not vulnerable_only:
        layouts["patched"] = (".", "patched/Dockerfile")
    for service, (context, dockerfile) in layouts.items():
        service_pattern = re.compile(
            rf"(?ms)(^  {re.escape(service)}:\s*\n)(.*?)(?=^  [A-Za-z0-9_.-]+:\s*$|^networks:\s*$|\Z)"
        )
        service_match = service_pattern.search(content)
        if not service_match:
            raise RuntimeError(f"Compose service is missing: {service}")
        block = service_match.group(2)
        build_pattern = re.compile(r"(?m)^(    build:\s*\n)((?:      .*\n)*)")
        build_match = build_pattern.search(block)
        if not build_match:
            raise RuntimeError(f"Compose build block is missing for service: {service}")
        body = build_match.group(2)
        if re.search(r"(?m)^      context\s*:", body):
            body = re.sub(r"(?m)^      context\s*:.*$", f"      context: {context}", body, count=1)
        else:
            body = f"      context: {context}\n" + body
        if re.search(r"(?m)^      dockerfile\s*:", body):
            body = re.sub(
                r"(?m)^      dockerfile\s*:.*$",
                f"      dockerfile: {dockerfile}",
                body,
                count=1,
            )
        else:
            body = f"      dockerfile: {dockerfile}\n" + body
        canonical_build = build_match.group(1) + body
        block = block[:build_match.start()] + canonical_build + block[build_match.end():]
        content = content[:service_match.start(2)] + block + content[service_match.end(2):]
    return content


def _canonicalize_validator_dockerfile(content: str) -> str:
    """Make validator COPY sources relative to its isolated ./validator context."""
    replacements = {
        "COPY validator/validator.py ": "COPY validator.py ",
        "COPY ./validator/validator.py ": "COPY validator.py ",
        "COPY adapter/validator.py ": "COPY validator.py ",
        '"validator/validator.py"': '"validator.py"',
        '"./validator/validator.py"': '"validator.py"',
        '"adapter/validator.py"': '"validator.py"',
    }
    for source, target in replacements.items():
        content = content.replace(source, target)
    return content


#: Where each image is built from, as _canonicalize_compose_builds pins it.
BUILD_CONTEXTS = {
    "vulnerable/Dockerfile": "",
    "patched/Dockerfile": "",
    "validator/Dockerfile": "validator/",
}

#: What the CLI itself puts in the validator's context, besides the answer.
VALIDATOR_CONTEXT_EXTRAS = ("plan.json",)

_HEREDOC = re.compile(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")


def _dockerfile_instructions(content: str) -> list[str]:
    """Instructions with continuations joined, comments and heredoc bodies dropped."""
    instructions: list[str] = []
    pending = ""
    terminator = None
    for raw in content.splitlines():
        stripped = raw.strip()
        if terminator is not None:
            if stripped == terminator:
                terminator = None
            continue
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        instruction = (pending + stripped).strip()
        pending = ""
        instructions.append(instruction)
        heredoc = _HEREDOC.search(instruction)
        if heredoc:
            terminator = heredoc.group(1)
    if pending.strip():
        instructions.append(pending.strip())
    return instructions


def _copy_sources(instruction: str) -> list[str]:
    """The context paths a COPY or ADD reads; empty for any other instruction."""
    match = re.match(r"(?i)^(COPY|ADD)\s+(.*)$", instruction)
    if not match:
        return []
    rest = match.group(2).strip()
    if "<<" in rest:
        return []  # a heredoc writes the file inline
    if rest.startswith("["):
        try:
            args = json.loads(rest)
        except ValueError:
            return []
        if not isinstance(args, list):
            return []
        args = [str(arg) for arg in args]
    else:
        try:
            args = shlex.split(rest)
        except ValueError:
            args = rest.split()
    flags = [arg for arg in args if arg.startswith("--")]
    if any(flag.startswith("--from") for flag in flags):
        return []  # copies from another stage, not from the context
    args = [arg for arg in args if not arg.startswith("--")]
    if len(args) < 2:
        return []
    return [
        source for source in args[:-1]
        if "://" not in source and "$" not in source
    ]


def _in_context(source: str, context: str, generated: set[str], lab_dir: Path) -> bool:
    relative = posixpath.normpath(source.replace("\\", "/")).lstrip("/")
    if relative in ("", "."):
        return True
    entries = {path[len(context):] for path in generated if path.startswith(context)}
    if context == "validator/":
        entries.update(VALIDATOR_CONTEXT_EXTRAS)
    glob = any(char in relative for char in "*?[")
    if glob:
        if any(fnmatch.fnmatch(entry, relative) for entry in entries):
            return True
    elif relative in entries or any(entry.startswith(relative + "/") for entry in entries):
        return True
    if context or relative.split("/", 1)[0] == "adapter" or relative in generated:
        # The answer is the only source of adapter files and of the
        # validator's context: a stale file from an earlier attempt is
        # removed before the build, so the disk does not count.
        return False
    # Inputs the CLI prepared itself, such as source/vulnerable.
    if glob:
        return any(lab_dir.glob(relative))
    return (lab_dir / relative).exists()


def _check_build_inputs(files: list[dict], lab_dir: Path, vulnerable_only: bool = False) -> None:
    """Refuse a Dockerfile that copies something its build context does not hold.

    Docker reports that as a checksum failure deep in a long log, after the
    images before it were built, and a repair given the log tends to repeat
    the mistake: in one series of benchmark runs this was 15 of 27 failed
    builds. Checked here, it costs nothing and says exactly what is wrong.
    """
    generated = {item["path"].replace("\\", "/") for item in files}
    contents = {item["path"].replace("\\", "/"): item["content"] for item in files}
    problems = []
    for dockerfile, context in BUILD_CONTEXTS.items():
        if dockerfile not in contents:
            continue
        for instruction in _dockerfile_instructions(contents[dockerfile]):
            for source in _copy_sources(instruction):
                whole = posixpath.normpath(source.replace("\\", "/")).lstrip("/") in ("", ".")
                if whole and not context:
                    variant = dockerfile.split("/", 1)[0]
                    problems.append(
                        f"{dockerfile} copies {source}, the whole lab directory: both snapshots, the "
                        "adapter and the other variant's files land in one image, and the vendor tree "
                        f"is under source/{variant}/ rather than at the destination. Copy "
                        f"source/{variant}/ and the adapter files it needs instead."
                    )
                    continue
                if _in_context(source, context, generated, lab_dir):
                    continue
                relative = posixpath.normpath(source.replace("\\", "/")).lstrip("/")
                if relative.startswith("../"):
                    problems.append(f"{dockerfile} copies {source}, which is outside its build context.")
                elif context == "validator/":
                    problems.append(
                        f"{dockerfile} copies {source}, but the validator image is built from "
                        "validator/ alone, which holds validator.py, requirements.txt and plan.json. "
                        "Nothing under adapter/ or source/ reaches it: put what the probe needs in "
                        "validator.py, or run it from the target service."
                    )
                else:
                    candidates = [path for path in generated if not path.startswith("validator/")]
                    close = difflib.get_close_matches(relative, candidates, n=1)
                    hint = f" The closest file in this answer is {close[0]}." if close else ""
                    problems.append(
                        f"{dockerfile} copies {source}, which does not exist. Its build context is "
                        "the lab directory: the vendor snapshots are source/vulnerable and "
                        "source/patched, and adapter/ holds only the adapter files in this answer."
                        + hint
                    )
    if problems:
        raise RuntimeError("A Dockerfile COPY cannot work as written:\n- " + "\n- ".join(problems))
    if not vulnerable_only:
        _check_variant_parity(contents)


_HEX_RUN = re.compile(r"\b[0-9a-f]{7,40}\b")
_PARENT_REF = re.compile(r"(?:~\d*|\^\d*)(?=[\"']?$|[\"'\s;&|)])")
_VERSIONED = re.compile(r"^(.*?(?:@|==|=|:|-))v?(\d+(?:\.\d+)*[\w.+-]*)$")
_VARIANT_SWITCH = re.compile(
    r"""(?:[!=]==?|\bis\b|\bin\b|\bcase\b)\s*[\(\[]?\s*['"`](vulnerable|patched)['"`]"""
    r"""|['"`](vulnerable|patched)['"`]\s*[!=]==?"""
)


def _benign_token_pair(vulnerable: str, patched: str) -> bool:
    """Whether two tokens differ in a way that cannot switch behaviour by itself.

    Allowed: the variant's own name inside a label (an image tag, a database
    name, `CVELAB_REVISION=vulnerable`), two versions of the same package
    (`lodash@4.17.21` and `lodash@4.17.23`), two commit ids, and the fix's
    parent written as `REF~1` against `REF`. Whether the
    adapter then branches on a label is checked separately.
    """
    if vulnerable.replace("vulnerable", "<variant>") == patched.replace("patched", "<variant>"):
        return True
    if _HEX_RUN.sub("<commit>", vulnerable) == _HEX_RUN.sub("<commit>", patched):
        return True
    # The fix's parent, written as `REF~1` or `REF^`, against the fix itself.
    if _PARENT_REF.sub("", vulnerable) == patched:
        return True
    left, right = _VERSIONED.match(vulnerable), _VERSIONED.match(patched)
    return bool(left and right and left.group(1) == right.group(1))


def _same_but_for_variant(vulnerable: str, patched: str) -> bool:
    if vulnerable == patched:
        return True
    left, right = vulnerable.split(), patched.split()
    if len(left) != len(right):
        return False
    return all(a == b or _benign_token_pair(a, b) for a, b in zip(left, right, strict=True))


def _compose_service_lines(compose: str, service: str) -> list[str]:
    match = re.search(
        rf"(?ms)^  {re.escape(service)}:\s*\n(.*?)(?=^  [A-Za-z0-9_.-]+:\s*$|^[A-Za-z]|\Z)",
        compose,
    )
    if not match:
        return []
    return [
        line.rstrip() for line in match.group(1).splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _check_variant_parity(contents: dict[str, str]) -> None:
    """Refuse a lab whose two variants differ in anything that could stand in for the fix.

    A harness that reads `ROLE=vulnerable` and branches on it, or a command
    that differs between the two services, produces a differential without
    running the vendor code at all. The two images may differ in the
    snapshot they copy, in labels carrying their own name, in the version of
    a package they install and in the commit they check out; the adapter,
    which runs unchanged in both, must not compare against the variant name.
    """
    pairs = []
    vulnerable_file = contents.get("vulnerable/Dockerfile")
    patched_file = contents.get("patched/Dockerfile")
    if vulnerable_file is not None and patched_file is not None:
        pairs.append((
            "vulnerable/Dockerfile and patched/Dockerfile",
            _dockerfile_instructions(vulnerable_file),
            _dockerfile_instructions(patched_file),
        ))
    compose = contents.get("docker-compose.yml")
    if compose:
        pairs.append((
            "The vulnerable and patched Compose services",
            _compose_service_lines(compose, "vulnerable"),
            _compose_service_lines(compose, "patched"),
        ))
    for where, vulnerable, patched in pairs:
        mismatch = None
        if len(vulnerable) != len(patched):
            longer, shorter = (vulnerable, patched) if len(vulnerable) > len(patched) else (patched, vulnerable)
            extra = next((line for line in longer if line not in shorter), longer[-1])
            mismatch = (extra, "(nothing)") if longer is vulnerable else ("(nothing)", extra)
        else:
            for a, b in zip(vulnerable, patched, strict=True):
                if not _same_but_for_variant(a, b):
                    mismatch = (a, b)
                    break
        if mismatch:
            raise RuntimeError(
                f"{where} may differ only in the source snapshot they copy, in labels that "
                "carry their own name, in package versions and in commit ids, so that any "
                "difference in behaviour comes from the vendor code. The vulnerable side has "
                f"`{mismatch[0].strip()}` where the patched side has `{mismatch[1].strip()}`. "
                "A lab whose variants are configured or started differently demonstrates that "
                "difference, not the vulnerability."
            )
    for path, content in sorted(contents.items()):
        if not path.startswith("adapter/"):
            continue
        switch = _VARIANT_SWITCH.search(content)
        if switch:
            word = switch.group(1) or switch.group(2)
            raise RuntimeError(
                f"{path} compares against the variant name '{word}'. The adapter runs unchanged "
                "in both images and must not decide what to do by which one it is in: a lab "
                "that branches on the variant demonstrates that branch, not the vulnerability. "
                "Run the vendor code from the snapshot and let the fix make the difference."
            )


def _validate_generated(files: list[dict], vulnerable_only: bool = False) -> None:
    paths = {item["path"].replace("\\", "/") for item in files}
    required = {
        "docker-compose.yml", "vulnerable/Dockerfile",
        "validator/Dockerfile", "validator/validator.py",
    }
    if not vulnerable_only:
        required.add("patched/Dockerfile")
    missing = required - paths
    if missing:
        raise RuntimeError(f"Generated adapter is missing: {', '.join(sorted(missing))}")
    for item in files:
        path = item["path"].replace("\\", "/")
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not ALLOWED_GENERATED.fullmatch(path):
            raise RuntimeError(
                f"Generated path not allowed: {path}. "
                f"{_path_remedy(path)} "
                "The only writable paths are docker-compose.yml, "
                ".dockerignore, vulnerable/Dockerfile, patched/Dockerfile, "
                "validator/Dockerfile, validator/validator.py, "
                "validator/requirements.txt, and anything under adapter/."
            )
        lowered = item["content"].lower()
        for needle, reason in FORBIDDEN.items():
            if needle in lowered:
                raise RuntimeError(f"Generated adapter rejected: {reason} in {path}")
        if path in {"vulnerable/Dockerfile", "patched/Dockerfile"}:
            if "./gradlew" in item["content"] and not (
                "sed -i" in lowered and "\\r$" in item["content"]
            ):
                raise RuntimeError(
                    f"Generated Gradle Dockerfile must normalize Windows CRLF before execution: {path}"
                )
        if path == "validator/Dockerfile" and re.search(
            r"(?mi)^\s*COPY\s+(?:\./)?(?:validator|adapter)/validator\.py\s+",
            item["content"],
        ):
            raise RuntimeError(
                "Validator Dockerfile COPY source must be relative to the ./validator build context"
            )
        if path == "docker-compose.yml":
            if "internal: true" not in lowered:
                raise RuntimeError("Compose network must be internal")
            if re.search(r"(?m)^\s*ports\s*:", lowered) or re.search(r"(?m)^\s*volumes\s*:", lowered):
                raise RuntimeError("Compose ports and volume mounts are not allowed in source labs")
            required_builds = ["dockerfile: vulnerable/dockerfile", "context: ./validator"]
            if not vulnerable_only:
                required_builds.append("dockerfile: patched/dockerfile")
            for required_build in required_builds:
                if required_build not in lowered:
                    raise RuntimeError(f"Compose build layout is invalid: missing {required_build}")
        if path == "validator/validator.py":
            required_contract = {
                "attack_executed", "proof_quality", "observable_effect", "evidence_type",
                "vulnerable", "differential_confirmed",
            }
            if vulnerable_only:
                required_contract.update({"patched_tested", "fix_status"})
            else:
                required_contract.add("patched")
            missing_contract = {field for field in required_contract if field not in item["content"]}
            if missing_contract:
                raise RuntimeError(
                    "Validator is missing real-PoC evidence fields: "
                    + ", ".join(sorted(missing_contract))
                )
            if "confirmed" not in item["content"] or (
                not vulnerable_only and "blocked" not in item["content"]
            ):
                raise RuntimeError(
                    "Validator must emit nested vulnerable/patched evidence with confirmed and blocked fields"
                )
            manual_contract = {
                "CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "exploit", "verify",
            }
            missing_manual = {
                field for field in manual_contract if field not in item["content"]
            }
            if missing_manual:
                raise RuntimeError(
                    "Validator is missing the manual PoC contract: "
                    + ", ".join(sorted(missing_manual))
                )
            # Only the fields the contract says must be computed. The same
            # instruction defines attack_executed as "the regression input
            # was actually delivered", which the validator knows for a fact
            # once it has sent it -- banning that literal rejected every
            # validator written exactly as asked, across two unrelated model
            # families, on all four attempts.
            if re.search(
                r"['\"](?:confirmed|differential_confirmed)['\"]\s*:\s*True\b",
                item["content"],
            ):
                raise RuntimeError(
                    "Validator hard-codes a success verdict; confirmed and "
                    "differential_confirmed must be computed from observations"
                )
            for url in re.findall(r"https?://([^/'\"\s:]+)", lowered):
                # An interpolated host is a variable, not a destination. The
                # same contract requires the validator to honour CVELAB_TARGET,
                # which forces exactly this shape -- so reading f"http://{target}"
                # as an external host made the two rules unsatisfiable together.
                # Where the variable may point is bounded at run time instead,
                # by the Compose network this file is checked to declare
                # internal.
                if "{" in url:
                    continue
                allowed_hosts = {"vulnerable", "127.0.0.1", "localhost"}
                if not vulnerable_only:
                    allowed_hosts.add("patched")
                if url not in allowed_hosts:
                    raise RuntimeError(f"Validator external target rejected: {url}")
    reads = _source_text_reads(files)
    if reads:
        raise RuntimeError(
            "The lab reads the vendor source as text instead of running it: "
            + "; ".join(reads[:3])
            + ". A verdict must come from executing the affected code with the regression input: "
            "build, install or import the source and send the input to it."
        )


# A harness that reads the vendor source as text and looks for the fix in
# it passes the differential without running anything: an Electron lab
# returned readFileSync(guest-window-manager.ts).includes('if (navigate) {')
# as its verdict and simulated the browser, the cookie jar and the request.
# What follows finds a text read, in an adapter file or the validator, of a
# path the Dockerfiles copied the source to. Calibrated on the twenty labs
# validated by 2026-10-23: it flags that one and none of the others.
_COPY_SOURCE = re.compile(
    r"^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*(?:\./)?source/(?:vulnerable|patched)/?\s+(\S+)\s*$", re.I
)
_COPY_ANY = re.compile(r"^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*(.+?)\s+(\S+)\s*$", re.I)
_WORKDIR = re.compile(r"^\s*WORKDIR\s+(\S+)", re.I)
_ENV_PAIR = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(\"?)([^\s\"]+)\2")
_ENV_LEGACY = re.compile(r"^\s*ENV\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\S+)\s*$", re.I)
_TEXT_READ = re.compile(
    r"readFileSync\s*\(|\breadFile\s*\(|\.read_text\s*\(|(?<![\w.])open\s*\(|file_get_contents\s*\(|"
    r"File\.read\s*\(|IO\.read\s*\(|os\.ReadFile\s*\(|ioutil\.ReadFile\s*\(|read_to_string\s*\(|"
    r"Files\.readString\s*\(|(?<![\w-])grep\s"
)
# Reading an upstream fixture as bytes and sending it is a real input.
_BINARY_MODE = re.compile(r"""['"](?:rb|br|r\+b)['"]""")
_JS_READ = re.compile(r"readFileSync\s*\(|\breadFile\s*\(")
_JS_TEXT = re.compile(r"""['"](?:utf-?8|latin1|ascii|utf16le)['"]|encoding\s*:|\.toString\s*\(""", re.I)


def _source_locations(files: list[dict]) -> tuple[set[str], set[str], set[str]]:
    """Where the Dockerfiles put the source, the ENV names pointing there, and adapter destinations."""
    contents = {item["path"].replace("\\", "/"): item["content"] for item in files}
    roots: set[str] = set()
    names: set[str] = set()
    adapter_destinations: set[str] = set()
    for path in ("vulnerable/Dockerfile", "patched/Dockerfile"):
        lines = contents.get(path, "").splitlines()
        workdir = "/"
        for line in lines:
            if match := _WORKDIR.match(line):
                workdir = posixpath.normpath(posixpath.join(workdir, match.group(1)))
            if match := _COPY_SOURCE.match(line):
                roots.add(posixpath.normpath(posixpath.join(workdir, match.group(1))))
            elif (match := _COPY_ANY.match(line)) and "adapter/" in match.group(1):
                adapter_destinations.add(posixpath.normpath(posixpath.join(workdir, match.group(2))))
        for line in lines:
            if not re.match(r"^\s*ENV\s", line, re.I):
                continue
            legacy = _ENV_LEGACY.match(line)
            pairs = _ENV_PAIR.findall(line) or ([(legacy.group(1), "", legacy.group(2))] if legacy else [])
            for name, _quote, value in pairs:
                value = posixpath.normpath(value) if value.startswith("/") else value
                if any(value == root or value.startswith(root + "/") for root in roots):
                    names.add(name)
    roots.discard("/")
    return roots, names, adapter_destinations


def _source_text_reads(files: list[dict]) -> list[str]:
    """Lines in adapter files or the validator that read the vendor source as text."""
    roots, names, adapter_destinations = _source_locations(files)
    if not roots:
        return []

    def mentions(window: str, path: str) -> bool:
        return re.search(re.escape(path) + r"(?:/|['\"`\s)]|$)", window) is not None

    found = []
    for item in files:
        path = item["path"].replace("\\", "/")
        if not (path.startswith("adapter/") or path == "validator/validator.py"):
            continue
        lines = item["content"].splitlines()
        for index, line in enumerate(lines):
            if not _TEXT_READ.search(line) or _BINARY_MODE.search(line):
                continue
            if _JS_READ.search(line) and not _JS_TEXT.search("\n".join(lines[index:index + 3])):
                continue
            # The path is often built a line or two above the read.
            window = "\n".join(lines[max(0, index - 3):index + 2])
            literal = any(
                mentions(window, root)
                and not any(dest.startswith(root) and mentions(window, dest) for dest in adapter_destinations)
                for root in roots
            )
            named = any(re.search(rf"\b{re.escape(name)}\b", window) for name in names)
            if literal or named:
                found.append(f"{path}:{index + 1}: {line.strip()[:160]}")
    return found


def _without_compose_version(content: str) -> str:
    """Drop the top-level `version:` key from a generated Compose file.

    Compose v2 ignores it and warns, and that warning is the first line of
    every error message the file ever produces -- including the ones a
    repair attempt has to read. Models write it from habit; removing it
    changes nothing about the lab.
    """
    lines = content.splitlines(keepends=True)
    kept = [
        line
        for line in lines
        if not re.match(r"^version\s*:\s*['\"]?[0-9.]+['\"]?\s*$", line)
    ]
    return "".join(kept)


def _path_remedy(path: str) -> str:
    """Name where the file should have gone.

    Refusing a path without saying what was wanted burned a generation
    attempt five times across three ecosystems and two models, and once
    cost a reproduction outright: every time, the model had written the
    adapter's entry point at the root -- server.js, exploit.py, server.rb,
    harness/Cargo.toml -- and the next attempt guessed again.
    """
    pure = PurePosixPath(path)
    if pure.is_absolute():
        return "Paths are relative to the lab directory."
    if ".." in pure.parts:
        return "A path may not climb out of the lab directory."
    if len(pure.parts) == 1 and pure.suffix:
        return f"Did you mean adapter/{pure.name}?"
    if pure.parts and pure.parts[0] not in {"adapter", "validator", "vulnerable", "patched"}:
        return f"Did you mean adapter/{path}?"
    return "Put anything the adapter needs under adapter/."


def _validate_fidelity(fidelity: dict) -> None:
    level = fidelity.get("execution_level")
    product_started = fidelity.get("vendor_product_started")
    exercised = fidelity.get("exercised_vendor_components")
    simulated = fidelity.get("simulated_components")
    if level == "source_component" and product_started is not False:
        raise RuntimeError("source_component fidelity cannot claim that the vendor product started")
    if level == "vendor_service" and product_started is not True:
        raise RuntimeError("vendor_service fidelity requires the actual vendor product to start")
    if level == "product_end_to_end" and product_started is not True:
        raise RuntimeError("product_end_to_end fidelity requires the actual vendor product to start")
    if not isinstance(exercised, list) or not exercised:
        raise RuntimeError("Fidelity must name at least one exercised vendor component")
    if not isinstance(simulated, list):
        raise RuntimeError("Fidelity simulated_components must be a list")
    # A model that reads the source instead of running it tends to say so
    # here, as the Electron lab did: "read as raw source text".
    read_not_run = [str(item) for item in exercised if _READ_NOT_RUN.search(str(item))]
    if read_not_run:
        raise RuntimeError(
            "Fidelity says the vendor code is read, not run: " + "; ".join(read_not_run[:3])
            + ". An exercised component is code the regression input executes."
        )


_READ_NOT_RUN = re.compile(
    r"source text|raw source|read as (?:raw )?text|as raw text|\bgrep|string match|text search"
    r"|reads? the (?:vendor )?source",
    re.I,
)


def _validate_support_services(services: list[str], compose: str) -> None:
    reserved = {"vulnerable", "patched", "validator"}
    if len(services) != len(set(services)) or reserved.intersection(services):
        raise RuntimeError("Support service names must be unique and cannot use reserved names")
    for service in services:
        if not re.search(rf"(?m)^  {re.escape(service)}:\s*$", compose):
            raise RuntimeError(f"Compose support service is missing: {service}")


#: The files a generation answer carries in fields of their own.
CANONICAL_FILES = frozenset({
    "docker-compose.yml", ".dockerignore", "vulnerable/Dockerfile",
    "patched/Dockerfile", "validator/Dockerfile", "validator/validator.py",
})


def _adapter_files(files: list[dict]) -> list[dict]:
    """Refuse an adapter file that would replace one with a field of its own.

    Adapter files are written after the canonical ones, so one named
    docker-compose.yml or validator/Dockerfile replaced the copy that
    _canonicalize_compose_builds or _canonicalize_validator_dockerfile had
    just pinned, and the layout every later check assumes went with it.
    Compared case-insensitively, as the file system on Windows and macOS
    compares names.
    """
    canonical = {name.lower() for name in CANONICAL_FILES}
    for item in files:
        path = PurePosixPath(str(item.get("path", "")).replace("\\", "/")).as_posix()
        if path.lower() in canonical:
            raise RuntimeError(
                f"Adapter file not allowed: {path}. It has a field of its own in the answer; "
                "adapter_files is for anything else, under adapter/."
            )
    return files


def _enforce_compose_policy(lab_dir: Path) -> None:
    """Check a written lab the way run_lab will, when Docker is installed.

    run_lab enforces this before every build, so nothing here is the last
    line. Finding out now turns a refusal into feedback for the next
    generation instead of a spent validation attempt. `docker compose config`
    needs the CLI and not the engine.
    """
    try:
        docker = docker_executable()
    except RuntimeError:
        return
    policy.enforce(compose_command(docker, lab_dir), lab_dir, docker_environment(docker))


def _snapshot_once(repository: Path, revision: str, destination: Path, repo_url: str) -> None:
    """Extract a revision unless this exact one is already there.

    Research reads the snapshots, so they are made before the model is asked
    anything; a generation retry then finds them in place instead of
    extracting php-src again. An extraction over a tree from another revision
    kept that revision's deleted files, so a mismatch starts from empty. The
    marker sits beside the tree, not in it, because the tree is what the lab
    builds.
    """
    marker = destination.parent / f".{destination.name}.revision"
    stamp = f"{repo_url} {revision}\n"
    if destination.is_dir() and marker.is_file() and marker.read_text(encoding="utf-8") == stamp:
        return
    if destination.exists():
        shutil.rmtree(destination)
    _snapshot(repository, revision, destination)
    write_text(marker, stamp)


def _wants_research(mode: str, listing: tuple[str, list[str], list[str]]) -> bool:
    """Research before generating when the fix does not fit, or when asked to."""
    if mode == "off":
        return False
    if mode == "on":
        return True
    diff, files, _tree = listing
    return len(diff) > research.PATCH_BUDGET or len(files) > EXCERPT_FILES


def _research(
    *,
    cve: str,
    dossier: dict,
    hint: str | None,
    repository: Path,
    vulnerable: str,
    fixed: str | None,
    lab_dir: Path,
    listing: tuple[str, list[str], list[str]],
    api_key: str | None,
    model: str | None,
    provider: str | None,
    base_url: str | None,
    rounds: int,
    situation: str | None = None,
    prior: dict | None = None,
) -> dict | None:
    """Run the research phase over this lab's snapshots and save the brief."""
    roots = {"vulnerable": lab_dir / "source" / "vulnerable"}
    if fixed:
        roots["fixed"] = lab_dir / "source" / "patched"
    if not all(root.is_dir() for root in roots.values()):
        return prior
    diff, files, _tree = listing
    budget = research.LOCAL if resolve_provider(provider) == "local" else research.HOSTED
    described = research.words(" ".join(str(text) for text in dossier.get("descriptions") or []))
    hinted = research.words(hint or "")
    sections = research.split_diff(diff)
    workspace = research.Workspace(repository, vulnerable, fixed, roots, files, _run_git)
    brief = research.research_fix(
        cve=cve,
        dossier=dossier,
        hint=hint,
        workspace=workspace,
        index=research.fix_index(
            sections, research.rank_sections(sections, described, hinted), budget.index
        ),
        preview=research.select_patch(diff, described, hinted, budget.preview)[0],
        overview=workspace.answer(
            {"kind": "list", "revision": "fixed" if fixed else "vulnerable", "path": ""},
            budget.overview,
        ),
        budget=budget,
        rounds=rounds,
        api_key=api_key,
        model=model,
        provider=provider,
        base_url=base_url,
        situation=situation,
        prior=prior,
    )
    research.save(lab_dir, brief)
    return brief


def _prompt_context(
    repository: Path,
    vulnerable: str,
    fixed: str,
    dossier: dict,
    hint: str | None,
    listing: tuple[str, list[str], list[str]],
    brief: dict | None,
    limit: int,
) -> str:
    """The source context and the research brief, together within limit."""
    brief_text = research.render_brief(brief, limit * 2 // 5) if brief else ""
    return _source_context(
        repository, vulnerable, fixed, dossier,
        max_chars=limit - len(brief_text), hint=hint, listing=listing,
    ) + brief_text


def generate_source_lab(
    cve_value: str,
    output_root: Path,
    repo: str | None,
    fixed_ref: str | None,
    vulnerable_ref: str | None,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    generation_feedback: list[str] | None = None,
    hint: str | None = None,
    research_mode: str | None = None,
) -> dict:
    cve = normalize_cve(cve_value)
    hint = research.normalize_hint(hint)
    mode = research.research_mode(research_mode)
    dossier = collect_cve(cve)
    resolved = resolve_source(dossier, repo, fixed_ref)
    vulnerable_only_resolved = None
    if repo and vulnerable_ref and not fixed_ref:
        vulnerable_only_resolved = (_safe_repo_url(repo), vulnerable_ref)
    discovery = None
    if (
        not resolved
        and ai_is_configured(api_key, model, provider)
        and provider_supports_web_search(provider)
    ):
        discovery = discover_source_with_ai(
            dossier, api_key, model, provider, base_url
        )
        if discovery["status"] == "SOURCE_READY":
            candidate_repo = discovery.get("repository_url")
            candidate_fixed = discovery.get("fixed_ref")
            if candidate_repo and candidate_fixed:
                resolved = (
                    _safe_repo_url(candidate_repo),
                    _safe_revision(candidate_fixed, "fixed revision source discovery returned"),
                )
                if not vulnerable_ref and discovery.get("vulnerable_ref"):
                    vulnerable_ref = _safe_revision(
                        discovery["vulnerable_ref"], "vulnerable revision source discovery returned"
                    )
        elif discovery["status"] == "VULNERABLE_ONLY":
            candidate_repo = discovery.get("repository_url")
            candidate_vulnerable = discovery.get("vulnerable_ref")
            if candidate_repo and candidate_vulnerable:
                vulnerable_only_resolved = (
                    _safe_repo_url(candidate_repo),
                    _safe_revision(candidate_vulnerable, "vulnerable revision source discovery returned"),
                )
    if not resolved and not vulnerable_only_resolved:
        status = discovery.get("status") if discovery else "INSUFFICIENT_DATA"
        if status == "VENDOR_ARTIFACT_REQUIRED":
            return {
                "ok": False,
                "status": "VENDOR_ARTIFACT_REQUIRED",
                "cve": cve,
                "reason": discovery["rationale"],
                "required": [discovery.get("vendor_artifact") or "Authorized affected vendor artifact"],
                "evidence_urls": discovery.get("evidence_urls", []),
            }
        return {
            "ok": False,
            "status": "ARTIFACT_REQUIRED",
            "cve": cve,
            "reason": discovery["rationale"] if discovery else "No public source repository and fixed commit were found.",
            "required": [
                "Verified public repository and immutable affected revision; fixed revision when available"
            ],
            "evidence_urls": discovery.get("evidence_urls", []) if discovery else [],
        }
    vulnerable_only = resolved is None
    if vulnerable_only:
        repo_url, vulnerable = vulnerable_only_resolved
        vulnerable = _safe_revision(vulnerable, "vulnerable revision")
        fixed = None
    else:
        repo_url, fixed = resolved
        fixed = _safe_revision(fixed, "fixed revision")
    cache_key = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
    repository = output_root.resolve() / ".source-cache" / cache_key
    repository.parent.mkdir(parents=True, exist_ok=True)
    if not repository.exists():
        with progress.stage(f"cloning {repo_url}"):
            _run_git([
                "clone", "--filter=blob:none", "--no-checkout", "--end-of-options",
                repo_url, str(repository),
            ])
    else:
        with progress.stage("fetching updates"):
            _run_git(["fetch", "--force", "origin"], cwd=repository)
    if fixed:
        _run_git(["fetch", "--force", "--end-of-options", "origin", fixed], cwd=repository)
        _run_git(["rev-parse", "--verify", "--end-of-options", f"{fixed}^{{commit}}"], cwd=repository)
        vulnerable = _safe_revision(vulnerable_ref, "vulnerable revision") if vulnerable_ref else f"{fixed}^"
    else:
        _run_git(["fetch", "--force", "--end-of-options", "origin", vulnerable], cwd=repository)
    _run_git(["rev-parse", "--verify", "--end-of-options", f"{vulnerable}^{{commit}}"], cwd=repository)

    lab_dir = output_root.resolve() / cve
    _snapshot_once(repository, vulnerable, lab_dir / "source" / "vulnerable", repo_url)
    if fixed:
        _snapshot_once(repository, fixed, lab_dir / "source" / "patched", repo_url)
    listing = _fix_listing(repository, vulnerable, fixed or vulnerable)
    brief = None
    if _wants_research(mode, listing):
        # A retry in the same run reuses the brief; a fresh run reads anew.
        saved = research.load(lab_dir) if generation_feedback else None
        if research.matches(saved, cve, vulnerable, fixed, hint):
            brief = saved
        else:
            brief = _research(
                cve=cve, dossier=dossier, hint=hint, repository=repository,
                vulnerable=vulnerable, fixed=fixed, lab_dir=lab_dir, listing=listing,
                api_key=api_key, model=model, provider=provider, base_url=base_url,
                rounds=research.research_rounds(),
            )
    research_record = {"research": research.summary(brief)} if brief else {}
    context_limit = research.prompt_budget(resolve_provider(provider) == "local")

    marker = "CVELAB-" + uuid.uuid4().hex
    feedback_suffix = ""
    if generation_feedback:
        feedback_suffix = (
            "\n\n--- PREVIOUS CVELAB PREFLIGHT FAILURES ---\n"
            + redact(json.dumps(generation_feedback[-3:], ensure_ascii=True, indent=2))[:6000]
            + "\nReturn a complete replacement adapter that specifically corrects every listed failure."
        )
    if vulnerable_only:
        context = _prompt_context(
            repository, vulnerable, vulnerable, dossier, hint, listing, brief, context_limit
        )
        context += (
            "\n\n--- FIX STATUS ---\nNo public fixed revision was identified at generation time. "
            "Generate and validate only the authentic vulnerable source. Do not invent a patched service."
        )
        generation = structured_response(
            api_key=api_key,
            model=model,
            schema=VULNERABLE_ONLY_SCHEMA,
            schema_name="cvelab_vulnerable_only_adapter",
            max_output_tokens=12000,
            instructions=(
                "This is an authorized defensive software-regression task using an immutable public source revision. "
                "Create a reproducible, vulnerable-only Docker test fixture from the supplied source evidence. "
                "Populate every required field and put additional files only under adapter/. Do not invent a fix or "
                "any patched artifact. Compose must contain only the required vulnerable and validator services on an "
                "internal network, without published host ports or host mounts. Build source/vulnerable, run it as a "
                "non-root user, and expose only the application route required for the regression check. The validator "
                "must exercise the patch-relevant input against the real affected code path and derive a concrete, "
                "non-destructive security-boundary observation from the response or container state. A reflected value "
                "alone is insufficient. Reading, searching or comparing the vendor source text is not evidence either: the verdict must come from executing the affected code. Preserve the required JSON field names: attack_executed means the regression "
                "input was actually delivered; vulnerable.confirmed must be computed from raw observations; set "
                "proof_quality to security_effect_observed, patched_tested and differential_confirmed to false, and "
                "fix_status to PUBLIC_FIX_NOT_IDENTIFIED. Exit zero only when the stated observation is reproduced. "
                "Support the required local manual interface selected by CVELAB_MANUAL_ACTION and CVELAB_TARGET: the "
                "legacy action name exploit sends only that same regression input and prints raw output, while verify "
                "independently evaluates a fresh observation and prints REPRODUCED only when confirmed. With neither "
                "variable set, retain automatic JSON validation. Report fidelity honestly and list every simulated "
                "policy, peer, backend, or downstream component plus every extra Compose service. "
                "The Compose network definition must literally contain internal: true. In validator.py, construct the "
                "final result with the literal keys attack_executed, proof_quality, observable_effect, evidence_type, "
                "vulnerable, patched_tested, differential_confirmed, and fix_status so CVELab can audit the source "
                "before execution; derive all success booleans from the current raw observations. "
                "Measure confirmed the same way on both sides: one function that decides whether "
                "the exploit succeeded, called once for vulnerable and once for patched, so the two "
                "verdicts are comparable. confirmed means the security effect was observed, not that "
                "the service answered. A rejection, an error status, a thrown exception or any "
                "response without the effect is confirmed=false and blocked=true. A patched build "
                "that refuses the input is the expected outcome; recording that as a confirmation "
                "inverts the proof. "
                f"Use only harmless canary data ({marker}) inside the isolated containers. Do not add arbitrary target "
                "selection, external connectivity, host integration, elevated container permissions, sensitive-data "
                "access, or lasting system changes. Normalize copied scripts to LF. Source archives contain no .git "
                "directory, so initialize a local repository without a remote only when the build requires it. "
                "Healthchecks must verify the final application route and must not accept redirects as healthy."
            ),
            input_text=context + feedback_suffix,
            provider=provider,
            base_url=base_url,
        )
        generated_files = [
            {
                "path": "docker-compose.yml",
                "content": _canonicalize_compose_builds(
                    generation["docker_compose"], vulnerable_only=True
                ),
            },
            {"path": ".dockerignore", "content": generation["dockerignore"]},
            {"path": "vulnerable/Dockerfile", "content": generation["vulnerable_dockerfile"]},
            {
                "path": "validator/Dockerfile",
                "content": _canonicalize_validator_dockerfile(generation["validator_dockerfile"]),
            },
            {"path": "validator/validator.py", "content": generation["validator_py"]},
            *_adapter_files(generation["adapter_files"]),
        ]
        _validate_generated(generated_files, vulnerable_only=True)
        _check_build_inputs(generated_files, lab_dir, vulnerable_only=True)
        _validate_fidelity(generation["fidelity"])
        _validate_support_services(generation["support_services"], generation["docker_compose"])
        _remove_stale_adapter_files(lab_dir, {item["path"] for item in generated_files})
        for item in generated_files:
            content = item["content"]
            if item["path"] == "docker-compose.yml":
                content = _without_compose_version(content)
            write_text(lab_dir / item["path"], content)
        _enforce_compose_policy(lab_dir)
        plan = {
            "cve": cve,
            "cwe": generation["cwe"],
            "lab_type": "VULNERABLE_ONLY_REPRODUCTION",
            "marker": marker,
            "repository": repo_url,
            "revisions": {"vulnerable": vulnerable, "patched": None},
            "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
            "patched_tested": False,
            "startup_services": [*generation["support_services"], "vulnerable"],
            "source_provenance": "Public vulnerable source resolved from CVE discovery or explicit override",
            "safety": {
                "target_scope": "internal_docker_network_only",
                "payload": "non_destructive_exploit_canary",
                "limitations": "No public fixed revision was identified; remediation behavior was not tested.",
            },
            "exploit_contract": generation["exploit_contract"],
            "fidelity": generation["fidelity"],
            "generation": {
                "model": model,
                "provider": resolve_provider(provider),
                "confidence": generation["confidence"],
                "rationale": generation["rationale"],
                "discovery_evidence_urls": discovery.get("evidence_urls", []) if discovery else [],
                **({"hint": hint} if hint else {}),
                **research_record,
            },
        }
        write_text(lab_dir / "dossier.json", json.dumps(dossier, indent=2, ensure_ascii=True) + "\n")
        write_text(lab_dir / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
        write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
        return {
            "ok": True,
            "status": "GENERATED_UNVALIDATED",
            "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
            "lab_dir": str(lab_dir),
            "plan": plan,
        }
    context = _prompt_context(repository, vulnerable, fixed, dossier, hint, listing, brief, context_limit)
    generation = structured_response(
        api_key=api_key,
        model=model,
        schema=SOURCE_SCHEMA,
        schema_name="cvelab_source_adapter",
        max_output_tokens=14000,
        instructions=(
            "This is an authorized defensive software-regression task using two immutable public source revisions "
            "and an upstream security patch. Create a reproducible Docker test fixture that compares the affected and "
            "fixed revisions. Populate every required Docker, Compose, and validator field and place additional files "
            "only under adapter/. Never return or alter vendor source. Builds must use source/vulnerable and "
            "source/patched, run as non-root, expose no host ports or mounts, and share an internal Docker network. "
            "Compose services must be named vulnerable, patched, and validator. The validator must send the same "
            "minimal patch-derived regression input to both real code paths and derive a concrete, non-destructive "
            "security-boundary observation from raw responses or container state. A reflected marker alone is not "
            "evidence. Reading, searching or comparing the vendor source text is not evidence either: the verdict must come from executing the affected code. Preserve the required JSON field names: attack_executed means the regression input was sent; "
            "vulnerable.confirmed, patched.confirmed, patched.blocked, and differential_confirmed must be computed from "
            "raw observations, never hard-coded. Exit zero only when the observation occurs on the affected revision "
            "and the fixed revision demonstrably prevents it. Implement the required local manual interface using "
            "CVELAB_MANUAL_ACTION and CVELAB_TARGET. The legacy action name exploit sends only the same regression "
            "input to the selected Docker service and prints raw output; verify performs a fresh independent check and "
            "prints REPRODUCED or BLOCKED from evidence. With neither variable set, retain automatic differential JSON "
            "validation. Prefer the actual vendor service or binary. Report fidelity honestly, name every simulated "
            "component, and list every extra Compose dependency in support_services. "
            "The Compose network definition must literally contain internal: true. In validator.py, construct the "
            "final result with the literal keys attack_executed, proof_quality, observable_effect, evidence_type, "
            "vulnerable, patched, and differential_confirmed so CVELab can audit the source before execution; derive "
            "all success booleans from the current raw observations. "
            f"Use only harmless canary data ({marker}) inside the isolated containers. Do not add arbitrary target "
            "selection, external connectivity, host integration, elevated container permissions, sensitive-data "
            "access, or lasting system changes. Dockerfiles may install ordinary build dependencies. Normalize copied "
            "scripts to LF. Before using a Gradle wrapper, verify that its JAR exists; otherwise install the exact "
            "declared Gradle version. "
            "Measure confirmed the same way on both sides: one function that decides whether "
            "the exploit succeeded, called once for vulnerable and once for patched, so the two "
            "verdicts are comparable. confirmed means the security effect was observed, not that "
            "the service answered. A rejection, an error status, a thrown exception or any "
            "response without the effect is confirmed=false and blocked=true. A patched build "
            "that refuses the input is the expected outcome; recording that as a confirmation "
            "inverts the proof. "
            "Source archives have no .git directory, so initialize a local repository without "
            "a remote only if build logic requires it. Healthchecks and the validator must use the final application "
            "scheme, port, and route, and redirects must not count as healthy. "
            "Build contexts are fixed: vulnerable and patched build from the lab directory, where the vendor "
            "snapshots are source/vulnerable and source/patched and adapter/ holds only the adapter files you "
            "return; the validator builds from validator/ alone, so its Dockerfile can copy only validator.py and "
            "requirements.txt. Every COPY source must exist in its context. vulnerable/Dockerfile and "
            "patched/Dockerfile, and their Compose services, must be identical except for the snapshot they "
            "copy, labels carrying their own name, package versions and commit ids; the adapter runs unchanged "
            "in both and must never compare against the variant name."
        ),
        input_text=context + feedback_suffix,
        provider=provider,
        base_url=base_url,
    )
    generated_files = [
        {
            "path": "docker-compose.yml",
            "content": _canonicalize_compose_builds(generation["docker_compose"]),
        },
        {"path": ".dockerignore", "content": generation["dockerignore"]},
        {"path": "vulnerable/Dockerfile", "content": generation["vulnerable_dockerfile"]},
        {"path": "patched/Dockerfile", "content": generation["patched_dockerfile"]},
        {
            "path": "validator/Dockerfile",
            "content": _canonicalize_validator_dockerfile(generation["validator_dockerfile"]),
        },
        {"path": "validator/validator.py", "content": generation["validator_py"]},
        *_adapter_files(generation["adapter_files"]),
    ]
    _validate_generated(generated_files)
    _check_build_inputs(generated_files, lab_dir)
    _validate_fidelity(generation["fidelity"])
    _validate_support_services(generation["support_services"], generation["docker_compose"])

    _remove_stale_adapter_files(lab_dir, {item["path"] for item in generated_files})
    for item in generated_files:
        write_text(lab_dir / item["path"], item["content"])
    _enforce_compose_policy(lab_dir)
    plan = {
        "cve": cve,
        "cwe": generation["cwe"],
        "lab_type": (
            "END_TO_END_REPRODUCTION"
            if generation["fidelity"]["execution_level"] == "product_end_to_end"
            else "SOURCE_REPRODUCTION"
        ),
        "marker": marker,
        "repository": repo_url,
        "revisions": {"vulnerable": vulnerable, "patched": fixed},
        "source_provenance": "CVE reference or explicit user override",
        "startup_services": [*generation["support_services"], "vulnerable", "patched"],
        "safety": {
            "target_scope": "internal_docker_network_only",
            "payload": "non_destructive_exploit_canary",
            "limitations": "Generated from a public security patch; validation is required before claiming reproduction.",
        },
        "exploit_contract": generation["exploit_contract"],
        "fidelity": generation["fidelity"],
        "generation": {
            "model": model,
            "provider": resolve_provider(provider),
            "confidence": generation["confidence"],
            "rationale": generation["rationale"],
            # A steered run says so, for whoever reviews what it reproduced.
            **({"hint": hint} if hint else {}),
            **research_record,
        },
    }
    write_text(lab_dir / "dossier.json", json.dumps(dossier, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    return {"ok": True, "status": "GENERATED_UNVALIDATED", "lab_dir": str(lab_dir), "plan": plan}


def _adapter_tree(lab_dir: Path) -> list[Path]:
    """Every regular file under adapter/, at any depth, without following links."""
    adapter_dir = lab_dir / "adapter"
    found = []
    for directory, folders, names in os.walk(adapter_dir):
        folders[:] = sorted(name for name in folders if not os.path.islink(os.path.join(directory, name)))
        found.extend(Path(directory) / name for name in names)
    return sorted(
        (path for path in found if path.is_file() and not path.is_symlink()),
        key=lambda path: path.relative_to(adapter_dir).as_posix(),
    )


def _remove_stale_adapter_files(lab_dir: Path, keep: set[str]) -> None:
    """Delete adapter files a new answer no longer contains, at any depth.

    Only the top level was cleaned, so a nested file from an earlier attempt
    -- adapter/app/package.json -- stayed in the build context after the
    answer that wrote it had been replaced.
    """
    for path in _adapter_tree(lab_dir):
        relative = path.relative_to(lab_dir).as_posix()
        if ALLOWED_GENERATED.fullmatch(relative) and relative not in keep:
            path.unlink()
    adapter_dir = lab_dir / "adapter"
    for directory, _folders, _names in sorted(os.walk(adapter_dir), reverse=True):
        if Path(directory) != adapter_dir and not os.listdir(directory):
            os.rmdir(directory)


def _repair_material(lab_dir: Path, limit: int = 120000) -> dict[str, str]:
    """Return only generated adapter inputs, never the vendor source snapshots.

    The whole adapter tree, not only its top level: a repair that could not
    see adapter/app/server.js answered without it. Files past the limit are
    named, so the model knows they exist.
    """
    candidates = [
        lab_dir / "docker-compose.yml",
        lab_dir / ".dockerignore",
        lab_dir / "vulnerable" / "Dockerfile",
        lab_dir / "patched" / "Dockerfile",
        lab_dir / "validator" / "Dockerfile",
        lab_dir / "validator" / "validator.py",
        *_adapter_tree(lab_dir),
    ]
    material = {}
    used = 0
    for path in candidates:
        if not path.is_file():
            continue
        relative = path.relative_to(lab_dir).as_posix()
        if not ALLOWED_GENERATED.fullmatch(relative):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")[:30000]
        size = len(json.dumps(text, ensure_ascii=True))
        if used + size > limit:
            material[relative] = "[CVELab: omitted, the failed adapter is larger than this prompt allows]"
            continue
        material[relative] = text
        used += size
    return material


def repair_source_lab(
    cve_value: str,
    output_root: Path,
    failure: dict,
    attempt: int,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    research_mode: str | None = None,
) -> dict:
    """Regenerate a failed source adapter using its observed runtime diagnostics."""
    cve = normalize_cve(cve_value)
    lab_dir = output_root.resolve() / cve
    plan_path = lab_dir / "plan.json"
    dossier_path = lab_dir / "dossier.json"
    if not plan_path.is_file() or not dossier_path.is_file():
        raise RuntimeError("Automatic repair requires an existing generated source lab")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("runner"):
        raise RuntimeError("Curated runners are deterministic and cannot be AI-repaired")
    dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
    repo_url = plan.get("repository")
    revisions = plan.get("revisions", {})
    vulnerable = revisions.get("vulnerable")
    fixed = revisions.get("patched")
    if not repo_url or not vulnerable:
        raise RuntimeError("Automatic repair is missing repository provenance")
    # plan.json is part of the lab and reaches git below.
    vulnerable = _safe_revision(vulnerable, "vulnerable revision in plan.json")
    if fixed is not None:
        fixed = _safe_revision(fixed, "fixed revision in plan.json")
    cache_key = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
    repository = output_root.resolve() / ".source-cache" / cache_key
    if not repository.is_dir():
        raise RuntimeError(f"Automatic repair source cache is missing: {repository}")

    vulnerable_only = fixed is None
    local_provider = resolve_provider(provider) == "local"
    mode = research.research_mode(research_mode)
    hint = plan.get("generation", {}).get("hint")
    # Docker and validator output can quote whatever reached a container, and
    # this goes to the provider: redacted before it is cut, so a cut cannot
    # leave half a secret behind.
    diagnostic = redact(json.dumps(failure, ensure_ascii=True, indent=2))[
        :12000 if local_provider else 40000
    ]
    listing = _fix_listing(repository, vulnerable, fixed or vulnerable)
    brief = None
    if mode != "off":
        saved = research.load(lab_dir)
        # A failure is the best evidence of what the brief got wrong, so
        # every repair may read more source before it rewrites the lab.
        brief = _research(
            cve=cve, dossier=dossier, hint=hint, repository=repository,
            vulnerable=vulnerable, fixed=fixed, lab_dir=lab_dir, listing=listing,
            api_key=api_key, model=model, provider=provider, base_url=base_url,
            rounds=min(2, research.research_rounds()), situation=diagnostic,
            prior=saved if research.matches(saved, cve, vulnerable, fixed, hint) else None,
        )
    context = _prompt_context(
        repository, vulnerable, fixed or vulnerable, dossier, hint, listing, brief,
        30000 if local_provider else research.prompt_budget(False) * 5 // 8,
    )
    current = json.dumps(
        _repair_material(lab_dir, 24000 if local_provider else 120000), ensure_ascii=True, indent=2
    )
    variant_contract = (
        "This is vulnerable-only: do not create a patched image or service. Emit patched_tested=false, "
        "differential_confirmed=false, and fix_status=PUBLIC_FIX_NOT_IDENTIFIED."
        if vulnerable_only
        else
        "Send the identical patch-derived regression input to vulnerable and patched services. Success requires the effect on "
        "vulnerable, its absence on patched, patched.blocked=true, and differential_confirmed=true."
    )
    generation = structured_response(
        api_key=api_key,
        model=model,
        schema=VULNERABLE_ONLY_SCHEMA if vulnerable_only else SOURCE_SCHEMA,
        schema_name="cvelab_autonomous_adapter_repair",
        max_output_tokens=16000,
        instructions=(
            "Repair a complete authorized, local-only defensive security-regression fixture. The observed failure and "
            "container logs are authoritative: identify their root cause and return a full replacement, not a patch. "
            "Do not repeat the failing design when the diagnostics disprove it. Build and run the supplied immutable "
            "vendor source snapshots; never modify or return vendor source. Prefer the actual vendor service or binary. "
            "Build contexts are fixed: vulnerable and patched build from the lab directory, where the vendor "
            "snapshots are source/vulnerable and source/patched and adapter/ holds only the adapter files you "
            "return; the validator builds from validator/ alone, so its Dockerfile can copy only validator.py and "
            "requirements.txt. Every COPY source must exist in its context. vulnerable/Dockerfile and "
            "patched/Dockerfile, and their Compose services, must be identical except for the snapshot they "
            "copy, labels carrying their own name, package versions and commit ids; the adapter runs unchanged "
            "in both and must never compare against the variant name. "
            "Use source_component only if launching the product is genuinely impractical, vendor_service when the real "
            "service starts with simulated surrounding components, and product_end_to_end only when the complete "
            "security-relevant product path executes. Disclose every simulated component. Compose must use an internal "
            "network, no host ports or mounts, services named vulnerable, patched where applicable, and validator, and "
            "list all extra services in support_services. Run containers non-root with no-new-privileges. The automatic "
            "validator must deliver the same patch-derived regression input, derive its booleans from raw observations, print one JSON document with "
            "attack_executed, proof_quality=security_effect_observed, observable_effect, evidence_type, vulnerable, and "
            "the required comparison fields, and exit zero only on genuine proof. It must also support independently "
            "runnable CVELAB_MANUAL_ACTION=exploit|verify and CVELAB_TARGET=vulnerable|patched modes; the legacy exploit action prints raw "
            "evidence and verify prints REPRODUCED or BLOCKED only after evaluating a fresh request. Never hard-code a "
            "successful result or treat canary reflection alone as proof. Reading, searching or comparing the vendor source text is not evidence either: the verdict must come from executing the affected code. Preserve the regression contract unless runtime "
            "evidence shows it is technically wrong. Keep all interaction inside the internal Docker network, accept "
            "only fixed service names, use harmless canary data, and add no host integration, elevated permissions, "
            "sensitive-data access, external connectivity, or lasting system changes. "
            + variant_contract
        ),
        input_text=(
            context
            + "\n\n--- FAILED ADAPTER ---\n"
            + current
            + "\n\n--- OBSERVED FAILURE (AUTOMATIC ATTEMPT "
            + str(attempt)
            + ") ---\n"
            + diagnostic
        ),
        provider=provider,
        base_url=base_url,
    )
    compose = _canonicalize_compose_builds(
        generation["docker_compose"], vulnerable_only=vulnerable_only
    )
    generated_files = [
        {"path": "docker-compose.yml", "content": compose},
        {"path": ".dockerignore", "content": generation["dockerignore"]},
        {"path": "vulnerable/Dockerfile", "content": generation["vulnerable_dockerfile"]},
        {
            "path": "validator/Dockerfile",
            "content": _canonicalize_validator_dockerfile(generation["validator_dockerfile"]),
        },
        {"path": "validator/validator.py", "content": generation["validator_py"]},
    ]
    if not vulnerable_only:
        generated_files.insert(
            3,
            {"path": "patched/Dockerfile", "content": generation["patched_dockerfile"]},
        )
    generated_files.extend(_adapter_files(generation["adapter_files"]))
    _validate_generated(generated_files, vulnerable_only=vulnerable_only)
    _check_build_inputs(generated_files, lab_dir, vulnerable_only=vulnerable_only)
    _validate_fidelity(generation["fidelity"])
    _validate_support_services(generation["support_services"], compose)

    _remove_stale_adapter_files(lab_dir, {item["path"].replace("\\", "/") for item in generated_files})
    for item in generated_files:
        write_text(lab_dir / item["path"], item["content"])
    _enforce_compose_policy(lab_dir)

    history = plan.get("generation", {}).get("repair_history", [])
    history.append({
        "attempt": attempt,
        "model": model or os.getenv("CVELAB_MODEL"),
        "provider": resolve_provider(provider),
        "failure": diagnostic[:8000],
        "confidence": generation["confidence"],
        "rationale": generation["rationale"],
    })
    plan["cwe"] = generation["cwe"]
    if not vulnerable_only:
        plan["lab_type"] = (
            "END_TO_END_REPRODUCTION"
            if generation["fidelity"]["execution_level"] == "product_end_to_end"
            else "SOURCE_REPRODUCTION"
        )
    plan["startup_services"] = [
        *generation["support_services"], "vulnerable",
        *([] if vulnerable_only else ["patched"]),
    ]
    plan["exploit_contract"] = generation["exploit_contract"]
    plan["fidelity"] = generation["fidelity"]
    plan["generation"] = {
        **plan.get("generation", {}),
        "model": model or os.getenv("CVELAB_MODEL"),
        "provider": resolve_provider(provider),
        "confidence": generation["confidence"],
        "rationale": generation["rationale"],
        "repair_history": history,
        **({"research": research.summary(brief)} if brief else {}),
    }
    write_text(plan_path, json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    return {
        "ok": True,
        "status": "REPAIRED_UNVALIDATED",
        "attempt": attempt,
        "lab_dir": str(lab_dir),
        "plan": plan,
    }
