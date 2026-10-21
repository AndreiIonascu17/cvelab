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
from pathlib import Path

from . import policy, progress
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


def collect_cve(cve: str) -> dict:
    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    request = urllib.request.Request(url, headers={"User-Agent": "cvelab/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"CVE API returned HTTP {exc.code} for {cve}") from exc

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
    proof_checks = {
        "source_reproduction": plan.get("lab_type") == "END_TO_END_REPRODUCTION",
        "contract_effect_defined": bool(proof_contract.get("observable_effect")),
        "contract_evidence_defined": bool(proof_contract.get("evidence_type")),
        "attack_executed": validation.get("attack_executed") is True,
        "security_effect_observed": validation.get("proof_quality")
        == "end_to_end_security_effect_observed",
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


def run_lab(cve_value: str, output_root: Path, keep: bool) -> dict:
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
    docker = docker_executable()
    environment = docker_environment(docker)
    ensure_docker(docker, environment)
    base = compose_command(docker, lab_dir)
    # Before anything is built: this covers a generated lab and one copied
    # from someone else alike, and nothing has started that needs tearing
    # down if it is refused.
    model = policy.enforce(base, lab_dir, environment)
    limits = policy.limits_override(model, runtime_limits())
    # Outside the lab directory, which is the lab's to shape: a symlink
    # there would turn this write into one anywhere.
    scratch = Path(tempfile.mkdtemp(prefix="cvelab-limits-"))
    override = scratch / "runtime-limits.json"
    override.write_text(json.dumps(limits, indent=2), encoding="utf-8")
    compose = [*base, "-f", str(override)]
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
        progress.step("running the validator")
        started = subprocess.run(
            compose + ["--profile", "tools", "run", "-d", "validator"],
            cwd=lab_dir,
            capture_output=True,
            text=True,
            env=environment,
        )
        if started.returncode != 0:
            detail = (started.stderr or started.stdout).strip()
            raise RuntimeError(f"Validator startup failed: {detail}")
        container_id = started.stdout.strip().splitlines()[-1]
        waited = subprocess.run(
            [docker, "wait", container_id],
            capture_output=True,
            text=True,
            env=environment,
            check=True,
        )
        validator_exit = int(waited.stdout.strip())
        logged = subprocess.run(
            [docker, "logs", container_id],
            capture_output=True,
            text=True,
            env=environment,
            check=True,
        )
        subprocess.run(
            [docker, "rm", container_id],
            capture_output=True,
            env=environment,
        )
        try:
            validation = json.loads(logged.stdout)
        except json.JSONDecodeError:
            validation = {"error": logged.stderr or logged.stdout or "validator produced no JSON"}
        vulnerable_result = validation.get("vulnerable", {})
        patched_result = validation.get("patched", {})
        vulnerable_confirmed = (
            vulnerable_result.get("confirmed") is True
            if isinstance(vulnerable_result, dict)
            else False
        )
        patched_confirmed = (
            patched_result.get("confirmed") is True
            if isinstance(patched_result, dict)
            else False
        )
        patched_blocked = (
            patched_result.get("blocked") is True
            if isinstance(patched_result, dict)
            else False
        )
        proof_contract = plan.get("exploit_contract", {})
        vulnerable_only = plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION"
        proof_checks = {
            "source_reproduction": plan.get("lab_type")
            in {
                "SOURCE_REPRODUCTION", "END_TO_END_REPRODUCTION",
                "VULNERABLE_ONLY_REPRODUCTION",
            },
            "contract_effect_defined": bool(proof_contract.get("observable_effect")),
            "contract_evidence_defined": bool(proof_contract.get("evidence_type")),
            "attack_executed": validation.get("attack_executed") is True,
            "security_effect_observed": validation.get("proof_quality")
            == "security_effect_observed",
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
        manual_poc_checks = {}
        if automatic_proof:
            targets = ["vulnerable"] if vulnerable_only else ["vulnerable", "patched"]
            for target in targets:
                for action in ("exploit", "verify"):
                    checked = subprocess.run(
                        compose + [
                            "--profile", "tools", "run", "--rm", "--no-deps",
                            "-e", f"CVELAB_MANUAL_ACTION={action}",
                            "-e", f"CVELAB_TARGET={target}",
                            "validator",
                        ],
                        cwd=lab_dir,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                    output = checked.stdout.strip()
                    expected_verdict = (
                        "REPRODUCED" if target == "vulnerable" else "BLOCKED"
                    )
                    passed = checked.returncode == 0 and bool(output)
                    if action == "verify":
                        passed = passed and expected_verdict in output
                    manual_poc_checks[f"{target}_{action}"] = {
                        "passed": passed,
                        "exit_code": checked.returncode,
                        "expected_verdict": expected_verdict if action == "verify" else None,
                        "output": output[:6000],
                        "stderr": checked.stderr.strip()[:2000],
                    }
        proof_checks["manual_poc_verified"] = bool(manual_poc_checks) and all(
            item["passed"] for item in manual_poc_checks.values()
        )
        real_source_proof = all(proof_checks.values())
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
            "manual_poc_checks": manual_poc_checks,
            "validator_exit_code": validator_exit,
            "real_poc_verified": real_source_proof,
            "product_e2e_verified": product_e2e_verified,
            "fix_status": plan.get("fix_status", "PUBLIC_FIX_AVAILABLE"),
            "patched_tested": not vulnerable_only,
            "differential_confirmed": validation.get("differential_confirmed") is True,
            "ok": validated,
        }
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
