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
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path

from . import policy, predicate, progress, sidecar, steps
from .ai import ai_is_configured, plan_with_ai
from .providers import PROVIDERS
from .templates import APP_PY, DOCKERFILE, VALIDATOR_DOCKERFILE, VALIDATOR_PY, compose_yaml

SUPPORTED_CWES = {"CWE-22", "CWE-78", "CWE-89", "CWE-284", "CWE-434", "CWE-918"}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def normalize_cve(value: str) -> str:
    cve = value.strip().upper()
    if not CVE_PATTERN.fullmatch(cve):
        raise ValueError(f"Invalid CVE identifier: {value}")
    return cve


def normalize_cwe(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"CWE[-_ ]?(\d+)", value, re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else value.upper()


CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve/{cve}"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories?type=reviewed&cve_id={cve}"


class CVERecordNotFound(RuntimeError):
    """Neither CVE.org nor GitHub's advisory database has a record.

    Permanent for the run: asking again returns the same answer, so the
    automatic retry loop stops on it instead of spending every attempt on a
    404.
    """


def _get_json(url: str, headers: dict[str, str]) -> object:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def collect_github_advisory(cve: str) -> dict | None:
    """Build a dossier from GitHub's reviewed advisory for a CVE.

    A CNA can publish its advisory, CVE number included, before CVE.org
    publishes the record: until then CVE.org holds the identifier as RESERVED
    and answers 404. GitHub's reviewed advisory already carries the
    description, the CWEs, the affected versions and the fix commits, in the
    references the source resolver reads. Returns None when GitHub has no
    advisory for the identifier.
    """
    url = GITHUB_ADVISORY_URL.format(cve=cve)
    try:
        advisories = _get_json(
            url, {"Accept": "application/vnd.github+json", "User-Agent": "cvelab"}
        )
    except urllib.error.HTTPError as exc:
        # A 403 or 429 here is GitHub's rate limit, not an answer: retryable.
        raise RuntimeError(f"GitHub advisory API returned HTTP {exc.code} for {cve}") from exc
    if not isinstance(advisories, list):
        return None
    matching = [
        item for item in advisories
        if isinstance(item, dict)
        and str(item.get("cve_id") or "").upper() == cve
        and not item.get("withdrawn_at")
    ]
    if not matching:
        return None
    advisory = matching[0]

    summary = str(advisory.get("summary") or "").strip()
    details = str(advisory.get("description") or "").strip()
    description = "\n\n".join(part for part in (summary, details) if part)
    cwes = []
    for item in advisory.get("cwes") or []:
        candidate = normalize_cwe(item.get("cwe_id") if isinstance(item, dict) else None)
        if candidate and candidate.startswith("CWE-"):
            cwes.append(candidate)
    repository = advisory.get("source_code_location") or None
    affected = []
    for vulnerability in advisory.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue
        package = vulnerability.get("package") or {}
        versions = []
        if vulnerability.get("vulnerable_version_range"):
            versions.append({"version": vulnerability["vulnerable_version_range"], "status": "affected"})
        if vulnerability.get("first_patched_version"):
            versions.append({"version": vulnerability["first_patched_version"], "status": "unaffected"})
        affected.append({
            "vendor": package.get("ecosystem"),
            "product": package.get("name"),
            "packageName": package.get("name"),
            "repo": repository,
            "versions": versions,
        })
    references = [str(item) for item in advisory.get("references") or [] if item]
    if repository and repository not in references:
        references.append(repository)
    return {
        "cve": cve,
        "state": None,
        "published": advisory.get("published_at"),
        "descriptions": [description] if description else [],
        "cwes": sorted(set(cwes)),
        "affected": affected,
        "references": references,
        "source": advisory.get("html_url") or url,
        "record": {
            "kind": "github_advisory",
            "id": advisory.get("ghsa_id"),
            "reason": "CVE.org has no published record for this identifier (HTTP 404)",
        },
    }


def collect_cve(cve: str) -> dict:
    url = CVE_RECORD_URL.format(cve=cve)
    try:
        raw = _get_json(url, {"User-Agent": "cvelab/0.1"})
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise RuntimeError(f"CVE API returned HTTP {exc.code} for {cve}") from exc
        advisory = collect_github_advisory(cve)
        if advisory is None:
            raise CVERecordNotFound(
                f"CVE API returned HTTP 404 for {cve}, and GitHub has no reviewed "
                "advisory for it either. The identifier may be reserved and not "
                "yet published, or mistyped."
            ) from exc
        return advisory
    if not isinstance(raw, dict):
        raise RuntimeError(f"CVE API returned an unexpected document for {cve}")

    cna = raw.get("containers", {}).get("cna", {})
    descriptions = [item.get("value", "") for item in cna.get("descriptions", [])]
    cwes = []
    for problem in cna.get("problemTypes", []):
        for description in problem.get("descriptions", []):
            candidate = normalize_cwe(description.get("cweId") or description.get("description"))
            if candidate and candidate.startswith("CWE-"):
                cwes.append(candidate)
    references = [item.get("url") for item in cna.get("references", []) if item.get("url")]
    return {
        "cve": cve,
        "state": raw.get("cveMetadata", {}).get("state"),
        "published": raw.get("cveMetadata", {}).get("datePublished"),
        "descriptions": descriptions,
        "cwes": sorted(set(cwes)),
        "affected": cna.get("affected", []),
        "references": references,
        "source": url,
    }


def select_cwe(
    dossier: dict,
    override: str | None,
    ai_mode: str,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> tuple[str, dict | None]:
    explicit = normalize_cwe(override)
    candidates = [explicit] if explicit else dossier.get("cwes", [])
    for candidate in candidates:
        if candidate in SUPPORTED_CWES:
            return candidate, None

    if ai_mode in {"auto", "on"} and ai_is_configured(api_key, model, provider):
        ai_plan = plan_with_ai(
            dossier,
            api_key=api_key,
            model=model,
            provider=provider,
            base_url=base_url,
        )
        candidate = normalize_cwe(ai_plan.get("cwe"))
        if candidate in SUPPORTED_CWES:
            return candidate, ai_plan
        if ai_mode == "on":
            raise RuntimeError(f"AI selected unsupported CWE: {candidate}")
    elif ai_mode == "on":
        raise RuntimeError("--ai on requires a configured AI provider and CVELAB_MODEL")

    found = ", ".join(dossier.get("cwes", [])) or "none"
    raise RuntimeError(f"No supported CWE found (metadata: {found}). Use --cwe with one of {sorted(SUPPORTED_CWES)}")


_SECRETS: set[str] = set()

# Shorter values would match ordinary words and redact harmless text.
MINIMUM_SECRET_LENGTH = 12


def register_secret(value: str | None) -> None:
    """Record a credential that must never reach disk or stdout.

    Provider errors are stored verbatim in automation.json so a failed run can
    be diagnosed, and a gateway that echoes the request in its error body would
    otherwise put the key in a file users attach to bug reports.
    """
    if value and len(value) >= MINIMUM_SECRET_LENGTH:
        _SECRETS.add(value)


def redact(text: str) -> str:
    """Replace every registered credential in `text`."""
    for secret in _SECRETS:
        text = text.replace(secret, "[REDACTED]")
    return text


#: Credentials that are not provider keys but are as likely to be exported in
#: the shell a run starts from, and as bad to find in an uploaded report.
CREDENTIAL_VARIABLES = (
    "CVELAB_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "HF_TOKEN",
)


def register_environment_secrets() -> None:
    """Register every provider key variable the registry declares.

    This list used to be written out by hand, and adding DeepSeek did not
    update it: a DEEPSEEK_API_KEY echoed back inside a provider error would
    have been written to automation.json in the clear. Reading the registry
    means a provider is covered the moment it is declared, which matters more
    now that a finished run can be uploaded to a control plane.

    The upload token is covered too, wherever it lives: the control plane
    gets it in a header, and a report that quoted it would hand it to anyone
    who can open the entry.
    """
    for provider in PROVIDERS.values():
        register_secret(os.getenv(provider.key_variable))
    for variable in CREDENTIAL_VARIABLES:
        register_secret(os.getenv(variable))
    # Imported here: upload imports this module for redact().
    from .upload import find_token

    register_secret(find_token())


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact(content), encoding="utf-8", newline="\n")


def select_scenario(dossier: dict, cwe: str) -> str:
    description = " ".join(dossier.get("descriptions", [])).lower()
    if cwe == "CWE-284" and (
        "destination namespace" in description
        or "endpointslice" in description
        or "serviceimport" in description
    ):
        return "namespace_injection"
    if cwe == "CWE-284":
        return "generic_access_control"
    return "default"


def build_lab(
    cve_value: str,
    output_root: Path,
    cwe_override: str | None,
    ai_mode: str,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    cve = normalize_cve(cve_value)
    dossier = collect_cve(cve)
    cwe, ai_plan = select_cwe(
        dossier, cwe_override, ai_mode, api_key, model, provider, base_url
    )
    lab_dir = output_root.resolve() / cve
    digest = int(hashlib.sha256(cve.encode()).hexdigest()[:6], 16)
    vulnerable_port = 20000 + (digest % 18000)
    patched_port = vulnerable_port + 1
    marker = "CVELAB-" + uuid.uuid4().hex
    scenario = select_scenario(dossier, cwe)
    plan = {
        "cve": cve,
        "cwe": cwe,
        "lab_type": "SYNTHETIC_CLASS_LAB",
        "marker": marker,
        "scenario": scenario,
        "ports": {"vulnerable": vulnerable_port, "patched": patched_port},
        "safety": {
            "target_scope": "loopback_and_internal_docker_network_only",
            "payload": "marker_only",
            "limitations": "Demonstrates the CWE class; it is not vendor-source reproduction.",
        },
        "ai_plan": ai_plan,
    }

    write_text(lab_dir / "app" / "app.py", APP_PY)
    write_text(lab_dir / "app" / "Dockerfile", DOCKERFILE)
    write_text(lab_dir / "validator" / "validator.py", VALIDATOR_PY)
    write_text(lab_dir / "validator" / "Dockerfile", VALIDATOR_DOCKERFILE)
    write_text(
        lab_dir / "docker-compose.yml",
        compose_yaml(cwe, marker, vulnerable_port, patched_port, scenario),
    )
    write_text(lab_dir / "dossier.json", json.dumps(dossier, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    return {"ok": True, "lab_dir": str(lab_dir), "plan": plan}


def docker_executable() -> str:
    found = shutil.which("docker")
    if found:
        return found
    if os.name == "nt":
        candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
        if candidate.exists():
            return str(candidate)
    raise RuntimeError("Docker CLI was not found")


#: What Docker is given of the user's environment.
#:
#: It used to be all of it. Compose interpolates `${VAR}` from the
#: environment it runs in, so a build arg of `${ANTHROPIC_API_KEY}` or
#: `environment: [DEEPSEEK_API_KEY, CVELAB_TOKEN]` resolved to the real
#: secrets -- inside a build that has network access, and a container whose
#: validator output lands in report.json, which is uploaded. Docker itself
#: needs little: where the engine is, where its configuration lives, a proxy,
#: a locale, a temporary directory, and on Windows the variables a process
#: cannot start without. SSH_AUTH_SOCK is for an engine reached over ssh://;
#: forwarding it into a build is refused by policy.py. Names are compared
#: upper-cased because Windows does, and so a lower-case http_proxy counts.
DOCKER_VARIABLES = frozenset({
    "PATH", "HOME", "USER", "USERNAME", "LANG", "TMP", "TEMP", "TMPDIR",
    "XDG_RUNTIME_DIR", "SSH_AUTH_SOCK",
    "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY", "DOCKER_BUILDKIT",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "APPDATA", "LOCALAPPDATA", "USERPROFILE",
    "PROGRAMDATA", "PROGRAMW6432", "COMSPEC", "PATHEXT",
})
DOCKER_PREFIXES = ("LC_", "BUILDKIT_", "BUILDX_", "COMPOSE_", "PROGRAMFILES")
#: COMPOSE_* variables that add files to a project or fetch remote ones.
#: COMPOSE_DISABLE_ENV_FILE is set below, not inherited.
COMPOSE_EXCLUDED = (
    "COMPOSE_FILE", "COMPOSE_ENV_FILES", "COMPOSE_PATH_SEPARATOR",
    "COMPOSE_EXPERIMENTAL_", "COMPOSE_DISABLE_ENV_FILE",
)


def docker_environment(docker: str) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if (name.upper() in DOCKER_VARIABLES or name.upper().startswith(DOCKER_PREFIXES))
        and not name.upper().startswith(COMPOSE_EXCLUDED)
    }
    docker_bin = str(Path(docker).resolve().parent)
    environment["PATH"] = docker_bin + os.pathsep + environment.get("PATH", "")
    # A lab's own .env would otherwise be read for interpolation and for
    # COMPOSE_* settings -- COMPOSE_FILE among them.
    environment["COMPOSE_DISABLE_ENV_FILE"] = "1"
    if os.name == "nt":
        # Docker Desktop context metadata can be briefly locked by another
        # desktop process. Addressing the Linux engine pipe directly avoids
        # that context-file race without changing the user's Docker settings.
        environment["DOCKER_HOST"] = "npipe:////./pipe/dockerDesktopLinuxEngine"
        environment.pop("DOCKER_CONTEXT", None)
        # Recent Compose versions may delegate builds to Bake/Buildx, which
        # re-opens Docker Desktop's context metadata even when DOCKER_HOST is
        # explicit. That metadata is occasionally locked by Docker Desktop on
        # Windows. Keep this process on the direct Compose builder instead.
        environment["COMPOSE_BAKE"] = "false"
        environment["BUILDX_BUILDER"] = "default"
    return environment


def ensure_docker(docker: str, environment: dict[str, str]) -> None:
    check = subprocess.run([docker, "info"], capture_output=True, text=True, env=environment)
    if check.returncode == 0:
        return
    if os.name == "nt":
        local_app_data = Path(os.environ.get("LOCALAPPDATA", "")).resolve()
        desktop = local_app_data / "Programs" / "DockerDesktop" / "Docker Desktop.exe"
        if desktop.exists():
            for image in ("Docker Desktop.exe", "com.docker.backend.exe"):
                subprocess.run(
                    ["taskkill", "/F", "/T", "/IM", image],
                    capture_output=True,
                    text=True,
                )
            time.sleep(2)
            stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"
            stale_runtimes = (
                local_app_data / "Docker" / "run",
                local_app_data / "docker-secrets-engine",
            )
            for runtime in stale_runtimes:
                if runtime.exists():
                    destination = runtime.with_name(runtime.name + f".stale-{stamp}")
                    moved = subprocess.run(
                        [
                            "powershell.exe",
                            "-NoProfile",
                            "-NonInteractive",
                            "-Command",
                            (
                                "& { param([string]$source, [string]$destination) "
                                "Move-Item -LiteralPath $source -Destination $destination "
                                "-ErrorAction Stop }"
                            ),
                            str(runtime),
                            str(destination),
                        ],
                        capture_output=True,
                        text=True,
                    )
                    if moved.returncode != 0:
                        detail = (moved.stderr or moved.stdout).strip()
                        raise RuntimeError(f"Could not archive stale Docker runtime: {detail}")
            (local_app_data / "Docker" / "run").mkdir(parents=True, exist_ok=True)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.Popen(
                [str(desktop), "--minimized"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            for _ in range(90):
                time.sleep(2)
                if subprocess.run([docker, "info"], capture_output=True, env=environment).returncode == 0:
                    return
    detail = (check.stderr or check.stdout).strip().splitlines()
    suffix = f" Last Docker error: {detail[-1]}" if detail else ""
    raise RuntimeError("Docker engine recovery failed." + suffix)


#: A ceiling for the build phase.
#:
#: The lab *runtime* is bounded at run time: run_lab gives every service
#: that sets no limit of its own the runtime_limits() below, through a
#: Compose override, and policy.py keeps it on an internal network with no
#: host ports or mounts. (The built-in template sets 128 MB and half a core
#: itself; generated labs mostly set nothing.) The build had nothing, and it
#: is the part that runs untrusted code -- `npm
#: install`, `cargo build` and `pip install` execute whatever the upstream
#: dependency tree says, on every run. One runaway postinstall could take
#: the machine down.
#:
#: Memory is the only ceiling Compose offers here: `docker compose build`
#: takes -m/--memory and has no --cpus, which was checked against the
#: installed Compose rather than assumed -- passing --cpus fails the build
#: with "unknown flag". A CPU bound needs a cgroup around the daemon or a
#: builder of its own, which belongs with the builder machine rather than
#: here.
#:
#: Deliberately roomy: compiling Pillow or a Rust harness is real work.
#: This exists to bound a pathological build, not to fail an honest one.
#: CVELAB_BUILD_MEMORY overrides it, and an empty value removes it.
DEFAULT_BUILD_MEMORY = "4g"


def build_limits() -> list[str]:
    """`docker compose build` flags that bound what a build may consume."""
    memory = os.getenv("CVELAB_BUILD_MEMORY", DEFAULT_BUILD_MEMORY).strip()
    return ["--memory", memory] if memory else []


#: Ceilings for a running lab service that sets none of its own.
#:
#: Only the built-in template set limits, and a generated lab ran unbounded
#: although this file claimed 128 MB and half a core for every lab. These
#: are roomy on purpose -- a JVM or a Rails app is a real workload,
#: and the point is to stop a fork bomb or a leak from taking the machine,
#: not to fail an honest lab. CVELAB_RUNTIME_MEMORY, CVELAB_RUNTIME_CPUS and
#: CVELAB_RUNTIME_PIDS override them, and an empty value removes one.
#:
#: CPUs are bounded with a CFS quota rather than `cpus`: the daemon refuses
#: `cpus` above the engine's core count ("range of CPUs is from 0.01 to
#: N"), which would break every lab on a two-core VM, and accepts any quota.
DEFAULT_RUNTIME_MEMORY = "2g"
DEFAULT_RUNTIME_CPUS = "2"
DEFAULT_RUNTIME_PIDS = "1024"
CPU_PERIOD = 100_000
_MEMORY = re.compile(r"\d+(?:\.\d+)?\s?(?:[kmgtp]i?)?b?", re.IGNORECASE)


DEFAULT_STARTUP_GRACE = 120


def startup_grace() -> int:
    """Seconds a health-checked service may take to come up (CVELAB_STARTUP_GRACE, 0 to 900)."""
    raw = os.getenv("CVELAB_STARTUP_GRACE", "").strip()
    if not raw:
        return DEFAULT_STARTUP_GRACE
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"CVELAB_STARTUP_GRACE must be a whole number of seconds, got {raw!r}") from error
    if not 0 <= value <= 900:
        raise ValueError("CVELAB_STARTUP_GRACE must be between 0 and 900 seconds")
    return value


def runtime_limits() -> dict[str, object]:
    """Compose service keys for the default runtime ceilings."""
    limits: dict[str, object] = {}
    memory = os.getenv("CVELAB_RUNTIME_MEMORY", DEFAULT_RUNTIME_MEMORY).strip()
    if memory:
        if not _MEMORY.fullmatch(memory):
            raise ValueError(f"CVELAB_RUNTIME_MEMORY must be a size such as 2g or 512m, got {memory!r}")
        limits["mem_limit"] = memory
    cpus = os.getenv("CVELAB_RUNTIME_CPUS", DEFAULT_RUNTIME_CPUS).strip()
    if cpus:
        try:
            value = float(cpus)
        except ValueError as error:
            raise ValueError(f"CVELAB_RUNTIME_CPUS must be a number of CPUs, got {cpus!r}") from error
        if not 0.01 <= value <= 1024:
            raise ValueError("CVELAB_RUNTIME_CPUS must be between 0.01 and 1024")
        limits["cpu_period"] = CPU_PERIOD
        limits["cpu_quota"] = round(value * CPU_PERIOD)
    pids = os.getenv("CVELAB_RUNTIME_PIDS", DEFAULT_RUNTIME_PIDS).strip()
    if pids:
        try:
            count = int(pids)
        except ValueError as error:
            raise ValueError(f"CVELAB_RUNTIME_PIDS must be a whole number, got {pids!r}") from error
        if count < 1:
            raise ValueError("CVELAB_RUNTIME_PIDS must be at least 1")
        limits["pids_limit"] = count
    return limits


def runtime_flags() -> list[str]:
    """The same ceilings as `docker run` flags, for containers started without Compose."""
    limits = runtime_limits()
    flags = []
    if "mem_limit" in limits:
        flags += ["--memory", str(limits["mem_limit"])]
    if "cpu_quota" in limits:
        flags += ["--cpu-period", str(limits["cpu_period"]), "--cpu-quota", str(limits["cpu_quota"])]
    if "pids_limit" in limits:
        flags += ["--pids-limit", str(limits["pids_limit"])]
    return flags


#: Seconds a single Docker stage may take before it is killed.
#:
#: There was no ceiling at all. A `cargo build` that never finishes, or an
#: upstream server that accepts a connection and never answers, held the
#: stage forever -- and on a serial queue that is the whole queue. Compiling
#: two source trees is genuinely slow, so the default is generous rather
#: than tight; CVELAB_STAGE_TIMEOUT overrides it.
DEFAULT_STAGE_TIMEOUT = 1800


def stage_timeout() -> int:
    raw = os.getenv("CVELAB_STAGE_TIMEOUT")
    if not raw:
        return DEFAULT_STAGE_TIMEOUT
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(
            f"CVELAB_STAGE_TIMEOUT must be a whole number of seconds, got {raw!r}"
        ) from error
    if value < 1:
        raise ValueError("CVELAB_STAGE_TIMEOUT must be at least 1 second")
    return value


def run_docker_stage(
    command: list[str],
    *,
    stage: str,
    docker: str,
    environment: dict[str, str],
    cwd: Path,
) -> None:
    limit = stage_timeout()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=limit,
        )
    except subprocess.TimeoutExpired as expired:
        # The output so far is the only evidence of where it stalled, and a
        # repair attempt reads it.
        tail = "".join(
            part.decode("utf-8", "replace") if isinstance(part, bytes) else (part or "")
            for part in (expired.stdout, expired.stderr)
        )[-8000:]
        raise RuntimeError(
            f"Docker stage '{stage}' exceeded {limit}s and was stopped. "
            f"Raise CVELAB_STAGE_TIMEOUT if this lab is genuinely slow."
            + (f"\nDocker output:\n{tail.strip()}" if tail.strip() else "")
        ) from expired
    if result.returncode == 0:
        return
    engine = subprocess.run([docker, "info"], capture_output=True, text=True, env=environment)
    if os.name == "nt" and engine.returncode != 0:
        ensure_docker(docker, environment)
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=limit,
        )
        if result.returncode == 0:
            return
    detail = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part and part.strip()
    )[-16000:]
    suffix = f"\nDocker output:\n{detail}" if detail else ""
    raise RuntimeError(
        f"Docker stage '{stage}' failed with exit code {result.returncode}{suffix}"
    )


def wait_health(port: int) -> None:
    url = f"http://127.0.0.1:{port}/health"
    for _ in range(40):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f"Lab service did not become healthy on port {port}")


#: Opt-in for a plan.json runner, which executes a lab's script on the host.
HOST_RUNNER_VARIABLE = "CVELAB_ALLOW_HOST_RUNNER"
WSL_DISTRIBUTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def wsl_distribution(runner: dict) -> str:
    """The WSL distribution a runner names, which it then runs in as root."""
    distribution = runner.get("distribution", "kali-linux")
    if not isinstance(distribution, str) or not WSL_DISTRIBUTION.fullmatch(distribution):
        raise RuntimeError(f"Shipyard runner WSL distribution is not a plain name: {distribution!r}")
    return distribution


def run_shipyard_script(lab_dir: Path, runner: dict) -> None:
    """Run a curated lab's own E2E script, outside Docker, when allowed to.

    plan.json chooses this, and plan.json is part of the lab: one copied from
    someone else could name any script -- an absolute path included -- and on
    Windows any WSL distribution to run it in as root. No generator writes a
    runner; it is how hand-curated Kubernetes labs were driven. So it needs an
    explicit opt-in, the script has to be a file inside the lab once symlinks
    are followed, and the distribution has to look like a name.
    """
    relative = runner.get("script")
    if os.getenv(HOST_RUNNER_VARIABLE) != "1":
        where = "on the host as root inside WSL" if os.name == "nt" else "on the host as your user"
        raise RuntimeError(
            f"This lab's plan.json asks to run {relative!r} {where}, outside Docker and "
            f"its isolation. Read the script, then set {HOST_RUNNER_VARIABLE}=1 to allow it."
        )
    if not isinstance(relative, str) or not relative or Path(relative).anchor:
        raise RuntimeError(f"Shipyard runner script must be relative to the lab directory: {relative!r}")
    script = (lab_dir / relative).resolve()
    try:
        script.relative_to(lab_dir.resolve())
    except ValueError:
        raise RuntimeError(f"Shipyard runner script resolves outside the lab directory: {script}") from None
    if not script.is_file():
        raise RuntimeError(f"Shipyard runner script was not found: {script}")

    if os.name == "nt":
        distribution = wsl_distribution(runner)
        converted = subprocess.run(
            ["wsl", "-d", distribution, "--", "wslpath", "-a", str(script)],
            capture_output=True,
            text=True,
        )
        if converted.returncode != 0:
            detail = (converted.stderr or converted.stdout).strip()
            raise RuntimeError(f"Could not resolve the Shipyard script in WSL: {detail}")
        command = [
            "wsl", "-d", distribution, "-u", "root", "--", "bash",
            converted.stdout.strip(),
        ]
        environment = None
    else:
        required = ("bash", "curl", "docker", "git", "make")
        missing = [name for name in required if not shutil.which(name)]
        if missing:
            raise RuntimeError(
                "Native Shipyard runner is missing required commands: "
                + ", ".join(missing)
            )
        docker = docker_executable()
        environment = docker_environment(docker)
        ensure_docker(docker, environment)
        command = [shutil.which("bash") or "bash", str(script)]

    completed = subprocess.run(
        command,
        cwd=lab_dir,
        env=environment,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        hint = (
            " Inspect the Shipyard output above for the first Docker error; "
            "exit 125 normally means Docker could not create or start a "
            "container. VPN/firewall rules are relevant only when that output "
            "shows failed access to localhost:5000 or a Docker bridge address."
            if os.name != "nt"
            else ""
        )
        detail = "\n".join(
            part.strip()
            for part in (completed.stdout, completed.stderr)
            if part and part.strip()
        )[-16000:]
        output = f"\nRunner output:\n{detail}" if detail else ""
        raise RuntimeError(
            f"Shipyard E2E runner failed with exit code {completed.returncode}."
            + hint
            + output
        )


def shipyard_report(cve: str, lab_dir: Path, plan: dict) -> dict:
    result_path = lab_dir / "e2e" / "result.json"
    if not result_path.is_file():
        raise RuntimeError(f"Shipyard runner did not produce evidence: {result_path}")
    validation = json.loads(result_path.read_text(encoding="utf-8"))
    vulnerable_result = validation.get("vulnerable", {})
    patched_result = validation.get("patched", {})
    proof_contract = plan.get("exploit_contract", {})
    # The same measurement as the Docker path, for the same reason, and the
    # second instance of the same defect rather than a different one: this
    # read a string out of a JSON file an arbitrary script wrote and treated
    # it as a mandatory proof. Nothing in CVELab generates a Shipyard runner
    # -- plan.get("runner") is honoured only for a lab that arrived with one,
    # behind the host-runner opt-in -- so there is no generation step here in
    # which a predicate could be declared and refused. That makes this path
    # fail closed where the Docker path can be made to pass: a plan that
    # declares no effect_predicate, or a result.json that prints no
    # observations, no longer reproduces. That is the right way round. The
    # opt-in this path sits behind is about running a script on the host,
    # not about whether its verdict is sound, and the report it writes is
    # the strongest claim CVELab makes -- real_poc_verified together with
    # product_e2e_verified, both shipped by `cvelab upload`.
    effect_held, effect_evidence = effect_observed(validation, proof_contract)
    proof_checks = {
        "source_reproduction": plan.get("lab_type") == "END_TO_END_REPRODUCTION",
        "contract_effect_defined": bool(proof_contract.get("observable_effect")),
        "contract_evidence_defined": bool(proof_contract.get("evidence_type")),
        "attack_executed": validation.get("attack_executed") is True,
        "security_effect_observed": effect_held,
        "observable_effect_recorded": bool(validation.get("observable_effect")),
        "evidence_type_matches": validation.get("evidence_type")
        == proof_contract.get("evidence_type"),
        "vulnerable_confirmed": vulnerable_result.get("confirmed") is True,
        "patched_not_confirmed": patched_result.get("confirmed") is False,
        "patched_blocked": patched_result.get("rejection_logged") is True,
        "differential_confirmed": validation.get("differential_confirmed") is True,
    }
    validated = all(proof_checks.values())
    fidelity = plan.get("fidelity", {})
    product_e2e_verified = (
        validated and fidelity.get("execution_level") == "product_end_to_end"
    )
    report = {
        "cve": cve,
        "cwe": plan["cwe"],
        "lab_type": plan["lab_type"],
        "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "validation": validation,
        "proof_contract": proof_contract,
        "fidelity": fidelity,
        "proof_checks": proof_checks,
        "effect_evidence": effect_evidence,
        "proof_quality_agreement": label_agreement(
            validation, "end_to_end_security_effect_observed", effect_held
        ),
        "real_poc_verified": validated,
        "product_e2e_verified": product_e2e_verified,
        "fix_status": plan.get("fix_status", "PUBLIC_FIX_AVAILABLE"),
        "patched_tested": True,
        "differential_confirmed": validation.get("differential_confirmed") is True,
        "ok": validated,
    }
    write_text(lab_dir / "report.json", json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    return {"ok": validated, "lab_dir": str(lab_dir), "report": report}


def compose_command(docker: str, lab_dir: Path) -> list[str]:
    """`docker compose` for one lab, under a project name CVELab chooses.

    A top-level `name:` used to pick the project, and teardown runs `down
    --volumes --remove-orphans` on it: a lab that named itself after one of
    the user's own projects would have stopped it and deleted its volumes.
    -p wins over `name:`, and this is the name Compose gives a project in
    this directory when the file names none.
    """
    project = re.sub(r"[^a-z0-9_-]+", "", lab_dir.name.lower()) or "cvelab"
    return [docker, "compose", "-p", project, "-f", str(lab_dir / "docker-compose.yml")]


#: Characters of service log kept with a failed validation, newest last.
SERVICE_LOG_CHARS = 8000


def _service_logs(
    compose: list[str], services: list[str], lab_dir: Path, environment: dict[str, str]
) -> str:
    """The end of each target service's log, for a validation that did not prove the effect.

    The validator says what it saw from outside; the services' own logs say
    whether the request reached the code the fix changed at all. A repair
    without them could only guess which of the two went wrong.
    """
    inspected = subprocess.run(
        compose + ["logs", "--no-color", "--tail", "60", *services],
        cwd=lab_dir,
        capture_output=True,
        text=True,
        env=environment,
    )
    output = "\n".join(part.strip() for part in (inspected.stdout, inspected.stderr) if part and part.strip())
    return redact(output)[-SERVICE_LOG_CHARS:]




def evidence_label(
    lab_type: str, reproduced: bool, manual_poc: bool,
    through_harness: bool = False,
) -> str:
    """One line saying what this run established, for a listing or a report.

    A fixed build is what you want, because it answers the question a single
    observation cannot: is this the bug, or is it how the thing always
    behaves. Plenty of projects publish no resolvable fixed revision, and the
    effect is still worth showing, so the two cases have to read differently
    rather than both saying "reproduced".

    The wording says what the evidence is rather than what the lab contained.
    "Vulnerable only" is this code's own name for a lab shape and means
    nothing to someone reading a report, and "no patched version" said twice
    over added nothing; what a reader needs is that there was no fixed build
    to compare against. The manual PoC clause says "proven" rather than
    "provided" because the script is only written after it showed the effect
    on the vulnerable build and, where there was one, stayed silent on the
    fixed one -- which is the whole difference between it and a script found
    in the wild.

    Whether the product's own server was started belongs here too, because
    it is the difference a reader cannot otherwise see. Measured over 62
    reproduced labs: of the 27 that started the product, 3 went on to hand
    over a manual PoC; of the 35 that stood in for it, 1 did. A lab that
    reaches the weakness through a harness it wrote proves the CVE through a
    route the product does not serve, so the finding cannot be shown on
    anyone's server -- and the differential still passes, which is exactly
    why it has to be said out loud rather than left in plan.json.
    """
    if not reproduced:
        return "Not reproduced"
    base = (
        "Reproduced on the vulnerable build; no fixed build available"
        if lab_type == "VULNERABLE_ONLY_REPRODUCTION"
        else "Reproduced, differential against the fixed build"
    )
    if through_harness:
        base += ", through a lab harness rather than the product's own server"
    return base + ", manual PoC proven" if manual_poc else base


#: What a lab's contract has to carry before CVELab will seed anything, and
#: the name of the state it establishes. Read from plan.json rather than
#: asked for again: the steps were validated against the grammar before the
#: lab was built, and the plan is what records them.
def setup_contract(plan: dict) -> tuple[list[dict], int] | None:
    """The validated seeding steps and the port they are sent to, or None.

    None for every lab generated before this existed and every lab that
    needs no seeding, which is what keeps those labs running exactly as they
    did: nothing is injected, nothing is started, and the validator is
    reached by the same call with the same arguments.
    """
    contract = plan.get("exploit_contract")
    if not isinstance(contract, dict):
        return None
    declared = contract.get("setup")
    port = contract.get("setup_port")
    if not isinstance(declared, list) or not declared:
        return None
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise RuntimeError(
            "exploit_contract.setup names steps but exploit_contract.setup_port does "
            "not name the port they are sent to"
        )
    return declared, port


def prepare_compose(
    lab_dir: Path, setup: tuple[list[dict], int] | None = None
) -> tuple[str, dict[str, str], list[str], Path]:
    """Vet a lab's Compose definition and build the command that runs it.

    Every path that starts a lab's containers goes through here, because
    `policy.enforce` is the gate that refuses a definition reaching for the
    host, and it has to run before anything is built -- for a lab CVELab
    generated and one copied from someone else alike, while there is still
    nothing to tear down.

    `setup` is the validated seeding steps and their port, when the lab's
    contract declares any. The service that runs them is added to the same
    override as the runtime limits, because that override is already a
    deterministic Compose file of CVELab's that Compose merges over the
    lab's; there is no second mechanism to invent.

    Returns the docker executable, the environment both it and Compose need,
    the Compose command with the override appended, and the scratch
    directory holding that override, which the caller removes.
    """
    docker = docker_executable()
    environment = docker_environment(docker)
    ensure_docker(docker, environment)
    base = compose_command(docker, lab_dir)
    model = policy.enforce(base, lab_dir, environment)
    limits = policy.limits_override(model, runtime_limits())
    grace = policy.startup_grace_override(model, startup_grace())
    for name, extra in grace["services"].items():
        limits.setdefault("services", {}).setdefault(name, {}).update(extra)
    if setup is not None:
        declared, port = setup
        injected = policy.setup_override(
            model,
            image=sidecar.BASE_IMAGE,
            program=steps.SETUP_RUNNER,
            environment={
                steps.SETUP_SPEC_VARIABLE: json.dumps(declared),
                steps.SETUP_PORT_VARIABLE: str(port),
                steps.SETUP_WAIT_VARIABLE: str(steps.SETUP_CONNECT_WAIT),
                # CVELab has no value for an input the operator would
                # supply, and sending one's spelling to the lab would seed
                # an account named {{user}} and call it done. The runner
                # refuses an unfilled substitution, and generation refuses a
                # setup step that uses an input nothing binds, so this is
                # empty by contract rather than by accident.
                steps.SETUP_INPUTS_VARIABLE: "{}",
                # Which build this run seeds. Interpolated rather than baked,
                # because one override file serves both runs and `up` has no
                # equivalent of -e; the manual actions already travel this
                # way.
                steps.SETUP_TARGET_VARIABLE: "${" + steps.SETUP_TARGET_VARIABLE + ":-}",
            },
            limits=runtime_limits(),
        )
        limits.setdefault("services", {}).update(injected["services"])
    # Outside the lab directory, which is the lab's to shape: a symlink
    # there would turn this write into one anywhere.
    scratch = Path(tempfile.mkdtemp(prefix="cvelab-limits-"))
    override = scratch / "runtime-limits.json"
    override.write_text(json.dumps(limits, indent=2), encoding="utf-8")
    return docker, environment, [*base, "-f", str(override)], scratch


#: What `run_lab` calls once the lab's verdict is settled and its services are
#: still up, for an artifact that is not part of the lab's claim. It is passed
#: in rather than imported so core goes on knowing nothing about model
#: providers: a lab is built and validated with none configured at all.
AfterValidation = Callable[
    [str, Path, dict, list[str], dict[str, str], bool], dict[str, object]
]


def _run_tool_service(
    compose: list[str],
    docker: str,
    environment: dict[str, str],
    lab_dir: Path,
    service: str,
    extra: dict[str, str] | None = None,
    wait_for_services: bool = True,
    force_recreate: bool = True,
) -> tuple[int, str, str]:
    """Run one of the lab's `profiles: ["tools"]` services to completion.

    Started with `up`, not `run`, because a one-off `compose run` container
    does not get the aliases its service declares on the network. A validator
    that reaches its own canary by name -- an HTTPS endpoint standing in for
    the upstream the product calls, which is how a request-forgery finding is
    observed without leaving the lab -- then cannot resolve it.

    Measured: 9router's lab declared the alias codewhisperer.canary.local on
    the validator and recorded "gaierror: Temporary failure in name
    resolution" and "Not reproduced", three runs running. The same lab
    started with `up` reports differential_confirmed, with the canary
    receiving Authorization: Bearer and the injected Host. Every lab built
    around a named stand-in was failing this way. The lesson applies
    identically to the setup service, which reaches the product by the same
    service name on the same network.

    The dependencies are waited for unless the caller says they are already
    up. A validator declares `depends_on: {vulnerable: {condition:
    service_healthy}}`, and that wait is the only thing standing between it
    and a product that has not finished booting. Skipping it cost a batch:
    the validator started first and reported "targets not ready", which
    reads as a lab that failed to reproduce.

    `force_recreate` is the setting the setup service turns off, and the
    reason is the whole point of running it: `up --force-recreate` applies to
    everything that `up` brings up, dependencies included, so recreating this
    container would restart the product and discard the state the previous
    setup run had just established.
    """
    launched = subprocess.run(
        compose + [
            "--profile", "tools", "up", "-d",
            *(["--force-recreate"] if force_recreate else []),
            *([] if wait_for_services else ["--no-deps"]),
            service,
        ],
        cwd=lab_dir,
        capture_output=True,
        text=True,
        env={**environment, **(extra or {})},
    )
    if launched.returncode != 0:
        detail = (launched.stderr or launched.stdout).strip()
        raise RuntimeError(f"{service} startup failed: {detail}")
    found = subprocess.run(
        compose + ["--profile", "tools", "ps", "-aq", service],
        cwd=lab_dir, capture_output=True, text=True, env=environment,
    )
    container_id = (found.stdout or "").strip().splitlines()[-1:] or [""]
    if not container_id[0]:
        raise RuntimeError(f"{service} started but no container id came back")
    waited = subprocess.run(
        [docker, "wait", container_id[0]],
        capture_output=True, text=True, env=environment, check=True,
    )
    logged = subprocess.run(
        [docker, "logs", container_id[0]],
        capture_output=True, text=True, env=environment, check=True,
    )
    subprocess.run(
        [docker, "rm", "-f", container_id[0]], capture_output=True, env=environment,
    )
    return int(waited.stdout.strip() or 1), logged.stdout, logged.stderr.strip()


def run_validator(
    compose: list[str],
    docker: str,
    environment: dict[str, str],
    lab_dir: Path,
    extra: dict[str, str] | None = None,
    wait_for_services: bool = True,
) -> tuple[int, str, str]:
    """Run the validator to completion and return its exit code and output.

    The mechanics, and why they are what they are, are in
    `_run_tool_service`: the validator and the setup service are the same
    kind of thing -- a service behind the `tools` profile, run once, read
    from its logs -- and were the same forty lines twice.
    """
    launched = _run_tool_service(
        compose, docker, environment, lab_dir, "validator", extra, wait_for_services
    )
    return launched


def _manual_action_passed(
    action: str, expected_verdict: str, returncode: int, output: str
) -> bool:
    """Whether one manual-kit action did what it was asked to.

    For `verify` the verdict the script printed is the measurement, and the
    exit status is how it chose to signal the same thing a second time.
    Which matters on the patched side: the attack is SUPPOSED to fail there,
    and a script that says so by exiting non-zero is using the convention
    CVELab's own shipped Manual-PoC.py documents in its help -- "Exit 0 and
    OBSERVED when the effect is present on that target, 1 and NOT_OBSERVED
    when it is not". Requiring exit zero of it as well failed a validator
    that was right.

    Measured once, on an express lab: `patched_verify` printed
    "status: 302 anchor_present: False error: None" and then "BLOCKED",
    exited 1, and was recorded as the one false check in a run whose other
    eleven proof checks all passed. The repair budget then spent twelve
    attempts on it, because the feedback said `manual_poc_verified` failed
    while the output said BLOCKED -- there was nothing for a model to fix.
    Rare: zero occurrences in the 91 archived labs that measured a manual
    kit, which is why this widens the rule for exactly that case instead of
    dropping the exit status from the check.

    Exit 1 and not "non-zero": a signal shows up here as a negative return
    code and a crash as 2 or more, and neither of those is a script
    reporting a verdict. For `exploit`, which only re-sends the input and
    prints what came back, the exit status is all there is to go on and is
    still required to be zero.
    """
    if action != "verify":
        return returncode == 0 and bool(output)
    if not output or expected_verdict not in output:
        return False
    return returncode in ((0,) if expected_verdict == "REPRODUCED" else (0, 1))


#: What a run says when the lab's setup could not put it in the state the
#: attack needs. A failure class of its own, distinct from a build that did
#: not compile, a service that never became healthy, and an effect that was
#: measured and did not hold: here the attack was never delivered and the
#: mechanical reason is known, which is the one case where a repair can be
#: told exactly what to fix.
SETUP_FAILURE_MARKER = "lab setup did not establish the state the attack needs"


def run_setup(
    compose: list[str],
    docker: str,
    environment: dict[str, str],
    lab_dir: Path,
    target: str,
    wait_for_services: bool = True,
) -> dict[str, str]:
    """Put one build into the state its attack needs, and return what it bound.

    Run once per build, because a session on the affected build is not a
    session on the fixed one: a single run whose bindings were used for both
    would hand the fixed build a token the affected build issued, and the
    comparison that is the whole proof would be between two different things.
    `_check_variant_parity` cannot catch that -- the setup is CVELab's and
    never passes through it -- so the separation is kept here instead.

    A setup that does not complete stops the run. An unseeded instance
    answers the attack with nothing to show, which is indistinguishable from
    a fixed build refusing it, so carrying on would report the unseeded
    behaviour for both and call it a differential.
    """
    code, out, err = _run_tool_service(
        compose, docker, environment, lab_dir, policy.SETUP_SERVICE,
        {steps.SETUP_TARGET_VARIABLE: target},
        wait_for_services=wait_for_services,
        force_recreate=False,
    )
    tail = (out or "").strip().splitlines()[-1:] or [""]
    try:
        reported = json.loads(tail[0])
    except json.JSONDecodeError:
        reported = None
    if code != 0 or not isinstance(reported, dict):
        detail = reported if isinstance(reported, dict) else (err or out or "").strip()[-600:]
        raise RuntimeError(
            f"{SETUP_FAILURE_MARKER} on the {target} build: {detail}"
        )
    return {
        # Read from this build during this run, for this proof only.
        str(name): str(value)
        for name, value in (reported.get("bound") or {}).items()
    }


def _validator_said(validation: dict[str, object], build: str, answer: str) -> bool:
    """One of the validator's own verdicts, in either shape it writes them.

    The contract asks for nested evidence -- {"vulnerable": {"confirmed":
    true}} -- and most validators write that. Some write the same answer
    flat, as "vulnerable_confirmed": true beside "vulnerable": true, and
    reading only the nested form threw away two confirmed differentials in
    one batch of ten. Both djust and nuclei reproduced, both reported
    differential_confirmed, both had their effect on the vulnerable build
    and a refusal on the fixed one in the record -- and both were written
    down as "Not reproduced" after fourteen repair attempts chasing a check
    whose content had never been the problem. The generator's own pre-flight
    check passed them, because it looks for the word "confirmed" and
    "vulnerable_confirmed" contains it.

    A bare `"vulnerable": true` counts for confirmed, because it says the
    same thing with nothing left out. It is not read that way for the fixed
    build: there `true` could as easily mean the build was tested, and
    treating it as "the effect fired there too" would fail a sound lab.
    """
    held = validation.get(build)
    if isinstance(held, dict):
        return held.get(answer) is True
    flat = validation.get(f"{build}_{answer}")
    if isinstance(flat, bool):
        return flat
    return held is True and build == "vulnerable" and answer == "confirmed"


def _validator_observations(validation: dict, build: str) -> dict:
    """The raw status, body and headers the validator printed for one build.

    Nested beside that build's own `confirmed`, which is where the contract
    asks for it, with the flat `vulnerable_observations` spelling accepted
    for the same reason `_validator_said` accepts `vulnerable_confirmed`:
    both shapes arrive, neither is worth a repair, and reading only one of
    them has already cost this project two reproduced differentials.

    An absent or wrongly shaped record returns an empty mapping rather than
    raising. `predicate.effect_observed` then reports every clause as
    undecided, which is the honest answer: nothing was measured.
    """
    held = validation.get(build)
    if isinstance(held, dict) and isinstance(held.get("observations"), dict):
        return held["observations"]
    flat = validation.get(f"{build}_observations")
    if isinstance(flat, dict):
        return flat
    return {}


def effect_observed(
    validation: dict, contract: dict, vulnerable_only: bool = False
) -> tuple[bool, list[str]]:
    """CVELab's own verdict on whether the declared security effect happened.

    WHY THIS IS NOT A FIELD THE VALIDATOR WROTE

    This check used to be `validation.get("proof_quality") ==
    "security_effect_observed"`: a string equality on a key the model's own
    validator prints about itself. A validator that printed that one literal
    cleared a mandatory proof gate having measured nothing, and the lab
    fixture checked in beside this package does exactly that -- it labels
    the run from its own differential boolean. The anti-hardcoding guard in
    sourcegen never looked at the field, so nothing stood in the way.
    Reading some other validator-written key instead would only have moved
    the hole: the problem was that the thing being judged was also the judge.

    So the contract names the effect before any image is built, the
    validator prints the observations, and the decision is made here. That
    is the order of events the closed path has always had, and the evaluator
    is literally the same one, lifted into `predicate.py` for this.

    WHY THE DIFFERENTIAL IS WHAT ENFORCES SUBSTANCE

    Moving the check onto a declared predicate is not on its own enough.
    Executed against the evaluator, `{"body_contains": ""}` holds against a
    body reading "nothing interesting happened here"; so does
    `{"body_regex": ".*"}`; so does a status list naming both outcomes. A
    model inclined to pass could declare one of those and clear the gate
    exactly as hollowly as writing the literal did.

    What rules that out is the shape of the question rather than a blocklist
    of degenerate patterns: for a lab with a fixed build, the effect is that
    the predicate held on the vulnerable side and did NOT hold on the
    patched side. A vacuous predicate holds on both and so fails on its own
    terms. There is nothing to write around, because the looser the
    predicate the more certainly it fails.

    A vulnerable-only lab has no patched side, so the comparison cannot do
    that work there; the declaration is instead held to a syntactic minimum
    at generation time, in `sourcegen._vulnerable_only_substance`.

    Returns the verdict and the evidence lines behind it. Fails closed in
    every direction: an undeclared predicate, a kind nothing evaluates, an
    observation that was never printed and a pattern that does not compile
    all read as the effect not having been observed, with the reason kept
    rather than lost.
    """
    declared = contract.get("effect_predicate")
    if not isinstance(declared, dict) or not predicate.declared_kinds(declared):
        return False, [
            "the contract declared no effect predicate, so nothing was measured; passed=False"
        ]
    unknown = predicate.unknown_kinds(declared)
    if unknown:
        # Refused at generation, so reaching here means the plan was edited
        # afterwards. Still answered rather than raised: an ignored clause
        # makes the predicate weaker than it reads, and the run has
        # therefore not measured what the contract claims.
        return False, [
            "the contract's effect predicate names "
            + ", ".join(unknown)
            + ", which is not evaluated, so it measures less than it claims; passed=False"
        ]
    where = "exploit_contract.effect_predicate"
    vulnerable = predicate.effect_observed(
        _validator_observations(validation, "vulnerable"), declared, where=where
    )
    evidence = [f"vulnerable: {line}" for line in vulnerable.evidence]
    if vulnerable_only:
        return vulnerable.held, evidence
    patched = predicate.effect_observed(
        _validator_observations(validation, "patched"), declared, where=where
    )
    evidence += [f"patched: {line}" for line in patched.evidence]
    held = vulnerable.held and not patched.held
    evidence.append(
        f"effect on vulnerable={vulnerable.held} effect on patched={patched.held} "
        f"passed={held}"
    )
    return held, evidence


def label_agreement(validation: dict, label: str, measured: bool) -> str:
    """Whether the validator's own label agrees with what CVELab measured.

    Recorded beside the proof checks and deliberately never among them.
    Every value in proof_checks is ANDed into the lab's status, and this is
    a claim rather than a measurement, so it must not be able to fail a run
    that measured; the comment above the anti-hardcoding guard records what
    banning a literal too broadly cost -- "banning that literal rejected
    every validator written exactly as asked, across two unrelated model
    families, on all four attempts".

    It is still worth writing down, because a disagreement is a defect in
    one of the two: a validator labelling a run it did not reproduce, or a
    predicate that does not describe the effect the validator was written to
    look for. Silence would hide both, and the second is the likelier one
    while this contract is new.
    """
    claimed = validation.get("proof_quality") == label
    if claimed == measured:
        return "agrees" if measured else "agrees_not_observed"
    return "claimed_but_not_measured" if claimed else "measured_but_not_claimed"


def run_lab(
    cve_value: str,
    output_root: Path,
    keep: bool,
    after_validation: AfterValidation | None = None,
) -> dict:
    cve = normalize_cve(cve_value)
    lab_dir = output_root.resolve() / cve
    plan_path = lab_dir / "plan.json"
    if not plan_path.exists():
        raise RuntimeError(f"Lab not generated: {lab_dir}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    runner = plan.get("runner")
    if isinstance(runner, dict) and runner.get("type") in {"shipyard", "wsl_shipyard"}:
        run_shipyard_script(lab_dir, runner)
        return shipyard_report(cve, lab_dir, plan)
    startup_services = plan.get("startup_services", ["vulnerable", "patched", "metadata"])
    if plan.get("lab_type") in {
        "SOURCE_REPRODUCTION", "END_TO_END_REPRODUCTION",
        "VULNERABLE_ONLY_REPRODUCTION",
    }:
        required = [
            lab_dir / "docker-compose.yml",
            lab_dir / "vulnerable" / "Dockerfile",
            lab_dir / "validator" / "Dockerfile",
            lab_dir / "validator" / "validator.py",
            lab_dir / "source" / "vulnerable",
        ]
        if plan.get("lab_type") != "VULNERABLE_ONLY_REPRODUCTION":
            required.extend([
                lab_dir / "patched" / "Dockerfile",
                lab_dir / "source" / "patched",
            ])
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise RuntimeError("Generated lab preflight failed; missing: " + ", ".join(missing))
    declared_setup = setup_contract(plan)
    docker, environment, compose, scratch = prepare_compose(lab_dir, declared_setup)
    validated_run = False
    try:
        with progress.stage("building lab images"):
            run_docker_stage(
                compose + ["build", *build_limits(), *startup_services, "validator"],
                stage="build",
                docker=docker,
                environment=environment,
                cwd=lab_dir,
            )
        with progress.stage("starting lab services"):
            run_docker_stage(
                compose + ["up", "-d", *startup_services],
                stage="startup",
                docker=docker,
                environment=environment,
                cwd=lab_dir,
            )
        vulnerable_only = plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION"
        # Between the services starting and the first attack, which is the
        # position closed.py has always applied its fixture in: after the
        # lab is up and before anything is measured. A non-zero exit aborts
        # the run rather than letting the attack be sent to an unseeded
        # instance, because an unseeded instance and a fixed one answer the
        # same way.
        bound: dict[str, dict[str, str]] = {}
        validator_extra: dict[str, str] = {}
        if declared_setup is not None:
            builds = ["vulnerable"] if vulnerable_only else ["vulnerable", "patched"]
            for index, build in enumerate(builds):
                progress.step(f"putting the {build} build in state")
                bound[build] = run_setup(
                    compose, docker, environment, lab_dir, build,
                    # The first run waits on the setup service's own
                    # depends_on, which is the lab's validator's; after that
                    # the services are up and healthy, and bringing the
                    # dependencies up again for the second build would
                    # recreate the first build's container and lose what was
                    # just seeded into it.
                    wait_for_services=index == 0,
                )
            validator_extra[steps.SETUP_BOUND_VARIABLE] = json.dumps(
                bound, ensure_ascii=True, sort_keys=True
            )
        progress.step("running the validator")
        validator_exit, out, err = run_validator(
            compose, docker, environment, lab_dir,
            validator_extra or None,
            # The setup already waited for the lab to be healthy, and
            # `--force-recreate` would restart the builds it seeded. A lab
            # with no setup takes neither branch and is reached by the same
            # call it always was.
            wait_for_services=declared_setup is None,
        )
        try:
            validation = json.loads(out)
        except json.JSONDecodeError:
            validation = {"error": err or out or "validator produced no JSON"}
        vulnerable_confirmed = _validator_said(validation, "vulnerable", "confirmed")
        patched_confirmed = _validator_said(validation, "patched", "confirmed")
        patched_blocked = _validator_said(validation, "patched", "blocked")
        proof_contract = plan.get("exploit_contract", {})
        effect_held, effect_evidence = effect_observed(
            validation, proof_contract, vulnerable_only
        )
        proof_checks = {
            "source_reproduction": plan.get("lab_type")
            in {
                "SOURCE_REPRODUCTION", "END_TO_END_REPRODUCTION",
                "VULNERABLE_ONLY_REPRODUCTION",
            },
            "contract_effect_defined": bool(proof_contract.get("observable_effect")),
            "contract_evidence_defined": bool(proof_contract.get("evidence_type")),
            "attack_executed": validation.get("attack_executed") is True,
            # CVELab's measurement over the observations the validator
            # printed, against the predicate the contract declared before
            # the build. It was a string equality on proof_quality, which
            # the validator writes about itself; see effect_observed.
            "security_effect_observed": effect_held,
            "observable_effect_recorded": bool(validation.get("observable_effect")),
            "evidence_type_matches": validation.get("evidence_type")
            == proof_contract.get("evidence_type"),
            "vulnerable_confirmed": vulnerable_confirmed,
        }
        if vulnerable_only:
            proof_checks.update({
                "public_fix_not_identified": validation.get("fix_status")
                == "PUBLIC_FIX_NOT_IDENTIFIED",
                "patched_not_tested": validation.get("patched_tested") is False,
                "not_differential": validation.get("differential_confirmed") is False,
            })
        else:
            proof_checks.update({
                "patched_not_confirmed": not patched_confirmed,
                "patched_blocked": patched_blocked,
            })
        automatic_proof = all(proof_checks.values()) and (
            validation.get("differential_confirmed") is False
            if vulnerable_only
            else validation.get("differential_confirmed") is True
        )
        # The gate stays: running the handed-over actions against a lab that
        # did not prove is wasted container time. What has to stay out of
        # proof_checks is the verdict on actions that never ran. Folding the
        # empty dict with `bool(manual_poc_checks) and all(...)` claimed the
        # check and failed it on every failed run, and autoflow's repair
        # digest names the checks whose value is False -- so the model was
        # told to fix one name in the list it cannot reach. Measured on the
        # picoclaw lab, identically in three benchmark runs: the digest
        # carried four names and only three were real, the fourth being this
        # one. Note the converse is not a phantom -- where the gate does open
        # and an action genuinely fails, this check is the only false name in
        # the list and belongs there, which is why the gate is kept rather
        # than the fold loosened. An absent key is not listed at all; the
        # state an operator still wants is manual_poc_status in the report
        # below.
        manual_poc_checks = {}
        if automatic_proof:
            targets = ["vulnerable"] if vulnerable_only else ["vulnerable", "patched"]
            for target in targets:
                for action in ("exploit", "verify"):
                    code, said, complained = run_validator(
                        compose, docker, environment, lab_dir,
                        # The compose file declares these as ${...}, so they
                        # travel in the environment rather than as -e flags,
                        # which `up` has no equivalent of. The bindings go
                        # with them: a manual action sends the attack again,
                        # so it needs the same state the automatic proof
                        # had, and without them a lab whose session came
                        # from setup would fail its own handed-over script.
                        {
                            "CVELAB_MANUAL_ACTION": action,
                            "CVELAB_TARGET": target,
                            **validator_extra,
                        },
                        # The services are up and were just proved against.
                        wait_for_services=False,
                    )
                    checked = subprocess.CompletedProcess(
                        ["validator", action, target], code, said, complained
                    )
                    output = checked.stdout.strip()
                    expected_verdict = (
                        "REPRODUCED" if target == "vulnerable" else "BLOCKED"
                    )
                    passed = _manual_action_passed(
                        action, expected_verdict, checked.returncode, output
                    )
                    manual_poc_checks[f"{target}_{action}"] = {
                        "passed": passed,
                        "exit_code": checked.returncode,
                        "expected_verdict": expected_verdict if action == "verify" else None,
                        "output": output[:6000],
                        "stderr": checked.stderr.strip()[:2000],
                    }
            # Inside the gate, and only here: targets is never empty, so the
            # dict always holds the two or four actions this run made, and
            # the check keeps its teeth where it is a real measurement.
            proof_checks["manual_poc_verified"] = all(
                item["passed"] for item in manual_poc_checks.values()
            )
        real_source_proof = all(proof_checks.values())
        # After proof_checks is complete and never part of it: those are ANDed
        # into the lab's status, and an artifact beside the lab's claim must
        # not be able to downgrade a run that reproduced its CVE. The services
        # are still up here, which is what proving one needs; teardown is in
        # the finally below.
        manual_poc_field: dict[str, object] = {"shipped": False, "reason": "not requested"}
        if after_validation is not None:
            try:
                manual_poc_field = after_validation(
                    cve, lab_dir, plan, compose, environment, real_source_proof
                )
            except Exception as error:  # noqa: BLE001 - the lab's verdict stands
                manual_poc_field = {
                    "shipped": False,
                    "reason": f"{type(error).__name__}: {error}"[:600],
                }
        # Compose can surface a lifecycle exit code after `docker wait` even
        # when the validator completed and emitted a complete proof document.
        # Accept only the strict, independently checked proof contract; retain
        # the process exit code in the report for diagnostics.
        validated = real_source_proof
        fidelity = plan.get("fidelity", {
            "execution_level": "source_component",
            "vendor_product_started": False,
            "exercised_vendor_components": [],
            "simulated_components": ["unspecified adapter components"],
            "rationale": "Legacy generated lab without explicit fidelity metadata.",
        })
        product_e2e_verified = (
            real_source_proof
            and plan.get("lab_type") == "END_TO_END_REPRODUCTION"
            and fidelity.get("execution_level") == "product_end_to_end"
            and fidelity.get("vendor_product_started") is True
        )
        report = {
            "cve": cve,
            "cwe": plan["cwe"],
            "lab_type": plan["lab_type"],
            "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "validation": validation,
            "proof_contract": proof_contract,
            "fidelity": fidelity,
            "proof_checks": proof_checks,
            # What the predicate measured, clause by clause, so a failed
            # effect check says which clause failed on which side rather
            # than only that it failed. These lines are the whole of the
            # evidence for the mandatory check, and a repair that cannot see
            # them can only guess.
            "effect_evidence": effect_evidence,
            "proof_quality_agreement": label_agreement(
                validation, "security_effect_observed", effect_held
            ),
            "manual_poc_checks": manual_poc_checks,
            # Beside the checks rather than among them: "not_run" is the
            # third state proof_checks has no room for, since every value
            # there is ANDed into the status.
            "manual_poc_status": (
                "not_run" if "manual_poc_verified" not in proof_checks
                else "verified" if proof_checks["manual_poc_verified"]
                else "failed"
            ),
            "manual_poc_field": manual_poc_field,
            "validator_exit_code": validator_exit,
            # The names each build bound and not their values. A repair that
            # has to see what the setup established needs to know which
            # names reached the validator; the values are a session and a
            # token read out of this run's own lab, and a report is written
            # to disk and shipped beside a deliverable.
            "setup_bindings": {
                build: sorted(values) for build, values in sorted(bound.items())
            },
            "real_poc_verified": real_source_proof,
            "evidence_label": evidence_label(
                str(plan.get("lab_type") or ""), real_source_proof,
                bool(manual_poc_field.get("shipped")),
                not (plan.get("fidelity") or {}).get("vendor_product_started"),
            ),
            "product_e2e_verified": product_e2e_verified,
            "fix_status": plan.get("fix_status", "PUBLIC_FIX_AVAILABLE"),
            "patched_tested": not vulnerable_only,
            "differential_confirmed": validation.get("differential_confirmed") is True,
            "ok": validated,
        }
        if not validated:
            report["service_logs"] = _service_logs(compose, list(startup_services), lab_dir, environment)
        write_text(lab_dir / "report.json", json.dumps(report, indent=2, ensure_ascii=True) + "\n")
        validated_run = report["ok"]
        return {"ok": report["ok"], "lab_dir": str(lab_dir), "report": report}
    except Exception as exc:
        diagnostics = []
        for arguments in (("ps", "-a"), ("logs", "--no-color", "--tail", "200")):
            inspected = subprocess.run(
                compose + list(arguments),
                cwd=lab_dir,
                capture_output=True,
                text=True,
                env=environment,
            )
            output = "\n".join(
                part.strip()
                for part in (inspected.stdout, inspected.stderr)
                if part and part.strip()
            )
            if output:
                diagnostics.append(f"docker compose {' '.join(arguments)}:\n{output[-12000:]}")
        suffix = "\n\nCompose diagnostics:\n" + "\n\n".join(diagnostics) if diagnostics else ""
        raise RuntimeError(str(exc) + suffix) from exc
    finally:
        if not keep or not validated_run:
            subprocess.run(
                compose + ["down", "--volumes", "--remove-orphans"],
                cwd=lab_dir,
                env=environment,
            )
        shutil.rmtree(scratch, ignore_errors=True)
