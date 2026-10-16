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
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from . import progress
from .ai import (
    ai_is_configured,
    provider_supports_web_search,
    resolve_provider,
    structured_response,
)
from .core import CVE_PATTERN, collect_cve, normalize_cve, write_text

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
                "exercised_vendor_components": {
                    "type": "array", "items": {"type": "string"},
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
        "support_services": {
            "type": "array",
            "maxItems": 5,
            "items": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"},
        },
        "adapter_files": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "content"],
                "properties": {
                    "path": {
                        "type": "string",
                        "pattern": "^(adapter/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*|validator/requirements\\.txt)$",
                    },
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

VALIDATOR_REPAIR_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["validator_py"],
    "properties": {"validator_py": {"type": "string", "minLength": 1}},
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
ALLOWED_GENERATED = re.compile(
    r"^(docker-compose\.yml|\.dockerignore|(?:vulnerable|patched)/Dockerfile|"
    r"validator/(?:Dockerfile|validator\.py|requirements\.txt)|"
    r"adapter/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)$"
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
    archive = _run_git(["archive", "--format=tar", revision], cwd=repository, binary=True)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        if hasattr(tarfile, "data_filter"):
            bundle.extractall(destination, filter="data")
        else:
            # Python 3.11 lacks extraction filters. Validate the Git archive
            # before using its older extractall implementation.
            root = destination.resolve()
            for member in bundle.getmembers():
                target = (root / member.name).resolve()
                if not target.is_relative_to(root) or not (member.isfile() or member.isdir()):
                    raise ValueError(f"Unsafe archive member: {member.name}")
            bundle.extractall(destination)


def _clip_context_section(content: str, limit: int) -> str:
    if len(content) <= limit:
        return content
    marker = "\n... [CVELab truncated this section for the local context window] ...\n"
    if limit <= len(marker):
        return content[:max(0, limit)]
    usable = max(0, limit - len(marker))
    head = usable * 3 // 4
    return content[:head] + marker + content[-(usable - head):]


def _source_context(
    repository: Path,
    vulnerable_ref: str,
    fixed_ref: str,
    dossier: dict,
    max_chars: int | None = None,
) -> str:
    diff = _run_git(["diff", "--no-ext-diff", "--unified=80", vulnerable_ref, fixed_ref], cwd=repository)
    files = _run_git(["diff", "--name-only", vulnerable_ref, fixed_ref], cwd=repository).splitlines()
    tree = _run_git(["ls-tree", "-r", "--name-only", fixed_ref], cwd=repository).splitlines()
    useful_names = {
        "package.json", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
        "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Cargo.toml", "composer.json",
        "Makefile", "README.md", "README", "Gemfile",
    }
    excerpts = []
    for path in list(dict.fromkeys(files + [item for item in tree if PurePosixPath(item).name in useful_names]))[:24]:
        try:
            content = _run_git(["show", f"{fixed_ref}:{path}"], cwd=repository)
        except RuntimeError:
            continue
        excerpts.append(f"\n--- FILE {path} (fixed revision) ---\n{content[:12000]}")
    material = {
        "dossier": dossier,
        "vulnerable_ref": vulnerable_ref,
        "fixed_ref": fixed_ref,
        "changed_files": files,
        "repository_tree_sample": tree[:500],
    }
    metadata = json.dumps(material, ensure_ascii=True, indent=2)
    patch = diff[:90000]
    if max_chars is None:
        return metadata + "\n\n--- SECURITY PATCH ---\n" + patch + "".join(excerpts)

    prefix = _clip_context_section(metadata, min(len(metadata), max_chars // 4))
    patch_header = "\n\n--- SECURITY PATCH ---\n"
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
            raise RuntimeError(f"Unsafe generated path rejected: {path}")
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
            if "raw" not in item["content"]:
                raise RuntimeError(
                    "Validator must include the actual raw observation for each tested target"
                )
            if not re.search(r"['\"]security_effect_observed['\"]", item["content"]):
                raise RuntimeError(
                    "Validator must use the exact proof_quality value security_effect_observed when proven"
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


def _validate_support_services(services: list[str], compose: str) -> None:
    reserved = {"vulnerable", "patched", "validator"}
    if len(services) != len(set(services)) or reserved.intersection(services):
        raise RuntimeError("Support service names must be unique and cannot use reserved names")
    for service in services:
        if not re.search(rf"(?m)^  {re.escape(service)}:\s*$", compose):
            raise RuntimeError(f"Compose support service is missing: {service}")




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
) -> dict:
    cve = normalize_cve(cve_value)
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
                resolved = (_safe_repo_url(candidate_repo), candidate_fixed)
                vulnerable_ref = vulnerable_ref or discovery.get("vulnerable_ref")
        elif discovery["status"] == "VULNERABLE_ONLY":
            candidate_repo = discovery.get("repository_url")
            candidate_vulnerable = discovery.get("vulnerable_ref")
            if candidate_repo and candidate_vulnerable:
                vulnerable_only_resolved = (
                    _safe_repo_url(candidate_repo), candidate_vulnerable
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
        fixed = None
    else:
        repo_url, fixed = resolved
    cache_key = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
    repository = output_root.resolve() / ".source-cache" / cache_key
    repository.parent.mkdir(parents=True, exist_ok=True)
    if not repository.exists():
        with progress.stage(f"cloning {repo_url}"):
            _run_git(["clone", "--filter=blob:none", "--no-checkout", repo_url, str(repository)])
    else:
        with progress.stage("fetching updates"):
            _run_git(["fetch", "--force", "origin"], cwd=repository)
    if fixed:
        _run_git(["fetch", "--force", "origin", fixed], cwd=repository)
        _run_git(["rev-parse", "--verify", f"{fixed}^{{commit}}"], cwd=repository)
        vulnerable = vulnerable_ref or f"{fixed}^"
    else:
        _run_git(["fetch", "--force", "origin", vulnerable], cwd=repository)
    _run_git(["rev-parse", "--verify", f"{vulnerable}^{{commit}}"], cwd=repository)

    marker = "CVELAB-" + uuid.uuid4().hex
    feedback_suffix = ""
    if generation_feedback:
        feedback_suffix = (
            "\n\n--- PREVIOUS CVELAB PREFLIGHT FAILURES ---\n"
            + json.dumps(generation_feedback[-3:], ensure_ascii=True, indent=2)[:6000]
            + "\nReturn a complete replacement adapter that specifically corrects every listed failure."
        )
    if vulnerable_only:
        context = _source_context(
            repository,
            vulnerable,
            vulnerable,
            dossier,
            max_chars=60000 if resolve_provider(provider) == "local" else None,
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
                "alone is insufficient. Preserve the required JSON field names: attack_executed means the regression "
                "input was actually delivered; vulnerable.confirmed must be computed from raw observations; set "
                "vulnerable.raw to the actual nonempty response or serialized observation from this run; "
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
            *generation["adapter_files"],
        ]
        _validate_generated(generated_files, vulnerable_only=True)
        _validate_fidelity(generation["fidelity"])
        _validate_support_services(generation["support_services"], generation["docker_compose"])
        lab_dir = output_root.resolve() / cve
        _snapshot(repository, vulnerable, lab_dir / "source" / "vulnerable")
        for item in generated_files:
            write_text(lab_dir / item["path"], item["content"])
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
    context = _source_context(
        repository,
        vulnerable,
        fixed,
        dossier,
        max_chars=60000 if resolve_provider(provider) == "local" else None,
    )
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
            "evidence. Preserve the required JSON field names: attack_executed means the regression input was sent; "
            "vulnerable.confirmed, patched.confirmed, patched.blocked, and differential_confirmed must be computed from "
            "raw observations, never hard-coded. "
            "Include nonempty vulnerable.raw and patched.raw fields with the actual response or serialized "
            "observation from each target in this run; describe only effects supported by those observations. "
            "Use the exact proof_quality value security_effect_observed only when the stated security effect is "
            "observed; use inconclusive otherwise. "
            "Exit zero only when the observation occurs on the affected revision "
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
            "Measure confirmed the same way on both sides: one function that decides whether "
            "the exploit succeeded, called once for vulnerable and once for patched, so the two "
            "verdicts are comparable. confirmed means the security effect was observed, not that "
            "the service answered. A rejection, an error status, a thrown exception or any "
            "response without the effect is confirmed=false and blocked=true. A patched build "
            "that refuses the input is the expected outcome; recording that as a confirmation "
            "inverts the proof. patched.confirmed and patched.blocked must never both be true. "
            f"Use only harmless canary data ({marker}) inside the isolated containers. Do not add arbitrary target "
            "selection, external connectivity, host integration, elevated container permissions, sensitive-data "
            "access, or lasting system changes. Dockerfiles may install ordinary build dependencies. Normalize copied "
            "scripts to LF. Before using a Gradle wrapper, verify that its JAR exists; otherwise install the exact "
            "declared Gradle version. Source archives have no .git directory, so initialize a local repository without "
            "a remote only if build logic requires it. Healthchecks and the validator must use the final application "
            "scheme, port, and route, and redirects must not count as healthy."
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
        *generation["adapter_files"],
    ]
    _validate_generated(generated_files)
    _validate_fidelity(generation["fidelity"])
    _validate_support_services(generation["support_services"], generation["docker_compose"])

    lab_dir = output_root.resolve() / cve
    _snapshot(repository, vulnerable, lab_dir / "source" / "vulnerable")
    _snapshot(repository, fixed, lab_dir / "source" / "patched")
    for item in generated_files:
        write_text(lab_dir / item["path"], item["content"])
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
        },
    }
    write_text(lab_dir / "dossier.json", json.dumps(dossier, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    return {"ok": True, "status": "GENERATED_UNVALIDATED", "lab_dir": str(lab_dir), "plan": plan}


def _repair_material(lab_dir: Path) -> dict[str, str]:
    """Return only generated adapter inputs, never the vendor source snapshots."""
    candidates = [
        lab_dir / "docker-compose.yml",
        lab_dir / ".dockerignore",
        lab_dir / "vulnerable" / "Dockerfile",
        lab_dir / "patched" / "Dockerfile",
        lab_dir / "validator" / "Dockerfile",
        lab_dir / "validator" / "validator.py",
        lab_dir / "validator" / "requirements.txt",
    ]
    adapter_dir = lab_dir / "adapter"
    if adapter_dir.is_dir():
        candidates.extend(sorted(path for path in adapter_dir.rglob("*") if path.is_file()))
    material = {}
    for path in candidates:
        if not path.is_file():
            continue
        relative = path.relative_to(lab_dir).as_posix()
        if ALLOWED_GENERATED.fullmatch(relative):
            material[relative] = path.read_text(encoding="utf-8", errors="replace")[:30000]
    return material


def repair_validator_verdict(
    cve_value: str,
    output_root: Path,
    failure: dict,
    attempt: int,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    """Repair validator proof fields without regenerating a working adapter."""
    cve = normalize_cve(cve_value)
    lab_dir = output_root.resolve() / cve
    plan_path = lab_dir / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    material = _repair_material(lab_dir)
    diagnostic = json.dumps(failure, ensure_ascii=True, indent=2)[:24000]
    generated = structured_response(
        api_key=api_key,
        model=model,
        schema=VALIDATOR_REPAIR_SCHEMA,
        schema_name="cvelab_validator_verdict_repair",
        max_output_tokens=10000,
        instructions=(
            "Return a complete replacement validator.py for this local defensive regression lab. "
            "Keep the existing request, canary, service names, and manual exploit/verify interface. "
            "Fix every listed failed_checks item using the actual raw observations; preserve the adapter. "
            "confirmed means the attack's security effect occurred on "
            "that target; it does not mean that the patch's protection was confirmed. When the patched "
            "response rejects the attack and does not show the security effect, patched.confirmed must "
            "be false and patched.blocked must be true. These fields must never both be true. "
            "Compute every success verdict from fresh raw observations and retain truthful raw evidence. "
            "For a proven effect, proof_quality must be the exact string security_effect_observed; use "
            "inconclusive otherwise. Labels such as definitive and none do not satisfy CVELab's contract. "
            "The automatic JSON must include nonempty vulnerable.raw and patched.raw fields containing the "
            "actual response or serialized observation from this run. "
            "Do not weaken or fake the proof, add external targets, or change the exploit input."
        ),
        input_text=(
            "--- CURRENT VALIDATOR ---\n"
            + material["validator/validator.py"]
            + "\n--- OBSERVED FAILURE ---\n"
            + diagnostic
        ),
        provider=provider,
        base_url=base_url,
    )
    material["validator/validator.py"] = generated["validator_py"]
    _validate_generated(
        [{"path": path, "content": content} for path, content in material.items()]
    )
    write_text(lab_dir / "validator" / "validator.py", generated["validator_py"])
    history = plan.get("generation", {}).get("repair_history", [])
    history.append({
        "attempt": attempt,
        "kind": "validator_verdict",
        "model": model or os.getenv("CVELAB_MODEL"),
        "provider": resolve_provider(provider),
        "failure": diagnostic[:8000],
    })
    plan.setdefault("generation", {})["repair_history"] = history
    write_text(plan_path, json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    return {
        "ok": True,
        "status": "VALIDATOR_REPAIRED_UNVALIDATED",
        "attempt": attempt,
        "lab_dir": str(lab_dir),
        "plan": plan,
    }


def repair_source_lab(
    cve_value: str,
    output_root: Path,
    failure: dict,
    attempt: int,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
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
    cache_key = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
    repository = output_root.resolve() / ".source-cache" / cache_key
    if not repository.is_dir():
        raise RuntimeError(f"Automatic repair source cache is missing: {repository}")

    vulnerable_only = fixed is None
    local_provider = resolve_provider(provider) == "local"
    context = _source_context(
        repository,
        vulnerable,
        fixed or vulnerable,
        dossier,
        max_chars=30000 if local_provider else None,
    )
    diagnostic = json.dumps(failure, ensure_ascii=True, indent=2)[
        :12000 if local_provider else 40000
    ]
    current = json.dumps(_repair_material(lab_dir), ensure_ascii=True, indent=2)[
        :24000 if local_provider else 100000
    ]
    variant_contract = (
        "This is vulnerable-only: do not create a patched image or service. Emit patched_tested=false, "
        "differential_confirmed=false, and fix_status=PUBLIC_FIX_NOT_IDENTIFIED."
        if vulnerable_only
        else
        "Send the identical patch-derived regression input to vulnerable and patched services. Success requires the effect on "
        "vulnerable, its absence on patched, patched.confirmed=false, patched.blocked=true, and differential_confirmed=true. "
        "confirmed means the attack effect occurred, not that the patch worked; patched.confirmed and "
        "patched.blocked must never both be true."
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
            "Address every listed failed_checks item; do not assert success in observable_effect when the raw response "
            "does not show it. "
            "Do not repeat the failing design when the diagnostics disprove it. Build and run the supplied immutable "
            "vendor source snapshots; never modify or return vendor source. Every adapter_files.path must be "
            "under adapter/ or exactly validator/requirements.txt; never return a source/ path. "
            "Prefer the actual vendor service or binary. "
            "Use source_component only if launching the product is genuinely impractical, vendor_service when the real "
            "service starts with simulated surrounding components, and product_end_to_end only when the complete "
            "security-relevant product path executes. Disclose every simulated component. Compose must use an internal "
            "network, no host ports or mounts, services named vulnerable, patched where applicable, and validator, and "
            "list all extra services in support_services. Run containers non-root with no-new-privileges. The automatic "
            "validator must deliver the same patch-derived regression input, derive its booleans from raw observations, print one JSON document with "
            "attack_executed, proof_quality, observable_effect, evidence_type, vulnerable, and "
            "the required comparison fields. Use the exact proof_quality value security_effect_observed only when "
            "the effect is observed, and inconclusive otherwise. The validator must exit zero only on genuine proof. "
            "The JSON must include nonempty "
            "vulnerable.raw and, when patched is tested, patched.raw with the actual response or serialized observation "
            "from this run. Describe only effects supported by that evidence. It must also support independently "
            "runnable CVELAB_MANUAL_ACTION=exploit|verify and CVELAB_TARGET=vulnerable|patched modes; the legacy exploit action prints raw "
            "evidence and verify prints REPRODUCED or BLOCKED only after evaluating a fresh request. Never hard-code a "
            "successful result or treat canary reflection alone as proof. Preserve the regression contract unless runtime "
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
    generated_files.extend(generation["adapter_files"])
    _validate_generated(generated_files, vulnerable_only=vulnerable_only)
    _validate_fidelity(generation["fidelity"])
    _validate_support_services(generation["support_services"], compose)

    new_paths = {item["path"].replace("\\", "/") for item in generated_files}
    adapter_dir = lab_dir / "adapter"
    if adapter_dir.is_dir():
        for old_file in adapter_dir.rglob("*"):
            relative = old_file.relative_to(lab_dir).as_posix()
            if old_file.is_file() and ALLOWED_GENERATED.fullmatch(relative) and relative not in new_paths:
                old_file.unlink()
    for item in generated_files:
        write_text(lab_dir / item["path"], item["content"])

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
