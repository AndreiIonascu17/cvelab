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

"""Environment preflight.

A run clones repositories, calls a paid model and builds images. Discovering
at minute three that Docker is not reachable, or that the key is rejected,
costs the user both time and money. Every check here is read-only: nothing is
started, restarted or installed, because a diagnostic that changes the system
cannot be trusted to describe it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import upload
from .ai import _local_base_url, _provider_key, resolve_provider
from .core import docker_environment
from .providers import auth_headers_for, base_url_for, require_private_transport
from .providers import get as get_provider

OK = "ok"
WARN = "warn"
FAIL = "fail"

MINIMUM_PYTHON = (3, 11)
# A source lab holds two git snapshots plus built images.
RECOMMENDED_FREE_GIB = 10


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def warned(self) -> list[Check]:
        return [c for c in self.checks if c.status == WARN]

    def as_dict(self) -> dict:
        return {
            "ok": not self.failed,
            "failed": len(self.failed),
            "warnings": len(self.warned),
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "fix": c.fix}
                for c in self.checks
            ],
        }


def _run(command: list[str], timeout: int = 20,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None


def _first_line(value: str) -> str:
    return (value or "").strip().splitlines()[0] if (value or "").strip() else ""


def check_python() -> Check:
    current = sys.version_info[:3]
    text = ".".join(str(part) for part in current)
    if current[:2] >= MINIMUM_PYTHON:
        return Check("python", OK, text)
    wanted = ".".join(str(part) for part in MINIMUM_PYTHON)
    return Check("python", FAIL, f"{text} is older than {wanted}",
                 f"Install Python {wanted} or newer and recreate the virtual environment.")


def check_executable(name: str, version_args: list[str], required: bool = True) -> Check:
    resolved = shutil.which(name)
    if not resolved:
        return Check(
            name,
            FAIL if required else WARN,
            "not found on PATH",
            f"Install {name} and make sure it is on PATH.",
        )
    # Resolved path, never the bare name: on Windows CreateProcess searches
    # System32 before PATH, so "bash" there reaches the WSL launcher stub.
    completed = _run([resolved, *version_args])
    if completed is None or completed.returncode != 0:
        return Check(name, WARN, f"found at {resolved} but did not report a version")
    return Check(name, OK, _first_line(completed.stdout) or resolved)


def check_docker_daemon() -> Check:
    docker = shutil.which("docker")
    if not docker:
        return Check("docker daemon", FAIL, "docker CLI not found",
                     "Install Docker Engine, or Docker Desktop on Windows.")
    # The environment a run gives Docker, which is not all of the shell's:
    # a check that passes here should mean the run reaches the same engine.
    completed = _run([docker, "info", "--format", "{{.ServerVersion}}"], timeout=30,
                     env=docker_environment(docker))
    if completed is None:
        return Check("docker daemon", FAIL, "docker info did not respond",
                     "Start the Docker service and try again.")
    if completed.returncode != 0:
        detail = _first_line(completed.stderr) or "docker info failed"
        fix = "Start Docker, and on Linux add your user to the docker group."
        if "permission denied" in (completed.stderr or "").lower():
            fix = "Add your user to the docker group: sudo usermod -aG docker \"$USER\", then log in again."
        return Check("docker daemon", FAIL, detail, fix)
    return Check("docker daemon", OK, f"server {completed.stdout.strip()}")


def check_compose() -> Check:
    docker = shutil.which("docker")
    if not docker:
        return Check("docker compose", FAIL, "docker CLI not found")
    completed = _run([docker, "compose", "version", "--short"], env=docker_environment(docker))
    if completed is None or completed.returncode != 0:
        return Check("docker compose", FAIL, "the Compose plugin is not available",
                     "Install the docker-compose-plugin package.")
    return Check("docker compose", OK, completed.stdout.strip())


def check_output_root(output_root: Path) -> Check:
    target = output_root.resolve()
    probe_parent = target
    while not probe_parent.exists() and probe_parent != probe_parent.parent:
        probe_parent = probe_parent.parent
    if not os.access(probe_parent, os.W_OK):
        return Check("output root", FAIL, f"{target} is not writable",
                     "Choose a writable --output-root.")
    try:
        free_gib = shutil.disk_usage(probe_parent).free / (1024 ** 3)
    except OSError:
        return Check("output root", OK, str(target))
    if free_gib < RECOMMENDED_FREE_GIB:
        return Check(
            "output root", WARN,
            f"{target} has {free_gib:.1f} GiB free; {RECOMMENDED_FREE_GIB} GiB is recommended",
            "Free disk space, or point --output-root at a larger volume.",
        )
    return Check("output root", OK, f"{target} ({free_gib:.0f} GiB free)")


def check_report_upload() -> Check:
    """Say plainly whether a finished run will be sent anywhere.

    Uploading is opt-out: configure a token once and every run files its
    report without being asked again. Something that happens by default
    should be visible by default, so the preflight states which way it is
    set rather than leaving it to be discovered from a log line.

    Both wordings carry the whole fact rather than half of it. "No token"
    used to read "reports stay on this machine", which says where they stay
    without saying that nothing is kept on our side, or what a token would
    change. The fix line cannot carry it: it renders only for a check that
    did not pass, and running without a token is a supported choice rather
    than a fault.
    """
    endpoint = upload.endpoint()
    refusal = upload.insecure_endpoint()
    if refusal and upload.find_token():
        return Check("report upload", FAIL, refusal,
                     f"Set {upload.ENDPOINT_VARIABLE} to an https:// origin, or unset it.")
    if not upload.find_token():
        return Check(
            "report upload", OK,
            f"off: nothing is sent anywhere. This run stays on this machine "
            f"and we keep no copy. A token from {endpoint}/app/ saves each "
            f"report to your account, where you can open what you filed",
        )
    return Check(
        "report upload", OK,
        f"on: each finished run files its report to your account at "
        f"{endpoint}, exploit included. --no-poc sends the report alone, "
        f"--no-upload sends nothing",
    )


def check_provider_config(provider: str | None, model: str | None,
                          api_key: str | None, base_url: str | None) -> Check:
    try:
        selected = resolve_provider(provider)
    except ValueError as exc:
        return Check("ai provider", FAIL, str(exc))
    selected_model = model or os.getenv("CVELAB_MODEL")
    if not selected_model:
        return Check("ai provider", FAIL, f"{selected}: no model selected",
                     "Pass --model, or set CVELAB_MODEL.")
    if selected == "local":
        try:
            return Check("ai provider", OK, f"local {selected_model} at {_local_base_url(base_url)}")
        except ValueError as exc:
            return Check("ai provider", FAIL, str(exc))
    if not _provider_key(selected, api_key):
        variable = get_provider(selected).key_variable
        return Check("ai provider", FAIL, f"{selected}: no API key",
                     f"Pass --key, or set {variable}.")
    # The key itself is never echoed, here or anywhere else.
    return Check("ai provider", OK, f"{selected} {selected_model}, key present")


def check_provider_reachable(provider: str | None, api_key: str | None,
                             base_url: str | None) -> Check:
    """List models at the provider. Free, instant, and catches a rejected key."""
    try:
        selected = resolve_provider(provider)
    except ValueError as exc:
        return Check("provider reachable", FAIL, str(exc))
    key = _provider_key(selected, api_key)
    provider = get_provider(selected)
    if not provider.models_path:
        return Check("provider reachable", OK, f"{selected}: no model listing to check")
    if selected == "local":
        try:
            base = _local_base_url(base_url)
        except ValueError as exc:
            return Check("provider reachable", FAIL, str(exc))
    else:
        base = base_url_for(selected, base_url)
    url = base + provider.models_path
    try:
        require_private_transport(url, key)
    except ValueError as exc:
        return Check("provider reachable", FAIL, str(exc),
                     "Point --base-url at https://, or run the server on this machine.")
    headers = auth_headers_for(selected, key)

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read(1)
        return Check("provider reachable", OK, f"{selected} answered at {url}")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return Check("provider reachable", FAIL, f"{selected} rejected the key (HTTP {exc.code})",
                         "Check the key, and that it is enabled for this model.")
        return Check("provider reachable", WARN, f"{selected} answered HTTP {exc.code}")
    except (urllib.error.URLError, OSError) as exc:
        return Check("provider reachable", FAIL, f"could not reach {url}: {exc}",
                     "Check connectivity, a proxy, or a VPN that blocks the provider.")


def run_doctor(output_root: Path, provider: str | None = None, model: str | None = None,
               api_key: str | None = None, base_url: str | None = None,
               offline: bool = False) -> Report:
    report = Report()
    report.checks.append(check_python())
    report.checks.append(check_executable("git", ["--version"]))
    report.checks.append(check_executable("docker", ["--version"]))
    report.checks.append(check_docker_daemon())
    report.checks.append(check_compose())
    report.checks.append(check_executable("bash", ["--version"]))
    # Only the Shipyard and Kubernetes profiles need these.
    report.checks.append(check_executable("curl", ["--version"], required=False))
    report.checks.append(check_executable("make", ["--version"], required=False))
    report.checks.append(check_output_root(output_root))
    report.checks.append(check_report_upload())
    report.checks.append(check_provider_config(provider, model, api_key, base_url))
    if not offline:
        report.checks.append(check_provider_reachable(provider, api_key, base_url))
    return report


MARKS = {OK: "ok  ", WARN: "warn", FAIL: "FAIL"}


def format_report(report: Report) -> str:
    width = max(len(c.name) for c in report.checks)
    lines = []
    for check in report.checks:
        lines.append(f"  {MARKS[check.status]}  {check.name.ljust(width)}  {check.detail}")
        if check.fix and check.status != OK:
            lines.append(f"        {' ' * width}  -> {check.fix}")
    if report.failed:
        lines.append("")
        lines.append(f"{len(report.failed)} check(s) failed. A run would not get far.")
    elif report.warned:
        lines.append("")
        lines.append(f"Ready, with {len(report.warned)} warning(s).")
    else:
        lines.append("")
        lines.append("Ready.")
    return "\n".join(lines)


def doctor_command(output_root: Path, provider: str | None, model: str | None,
                   api_key: str | None, base_url: str | None,
                   offline: bool, as_json: bool) -> int:
    report = run_doctor(output_root, provider, model, api_key, base_url, offline)
    print(json.dumps(report.as_dict(), indent=2) if as_json else format_report(report))
    return 2 if report.failed else 0
