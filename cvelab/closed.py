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
import re
import shlex
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .core import runtime_flags

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MAX_BODY = 64 * 1024
_MAX_RESPONSE = 1024 * 1024

#: Where a contract's fixture files land inside the lab container.
_FIXTURE_ROOT = "/cvelab/fixture"
_FIXTURE_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_MAX_FIXTURE_FILE = 256 * 1024
_MAX_FIXTURE_OUTPUT = 16 * 1024

#: Seconds to wait for an image to answer its health path.
#:
#: Two minutes is enough for an application server to bind a port. It is not
#: enough for a product that migrates a database on first boot, so a contract
#: may raise it: a GitLab image answered after 31 seconds on a warm host and
#: 101 on a cold one, and a slower host has further to go.
DEFAULT_HEALTH_TIMEOUT = 120
MAX_HEALTH_TIMEOUT = 1800

#: Seconds a fixture command may take. Seeding through a product's own console
#: pays for booting its runtime first; GitLab's took 18 seconds.
DEFAULT_FIXTURE_TIMEOUT = 600
MAX_FIXTURE_TIMEOUT = 1800


def _docker(*args: str, check: bool = True) -> str:
    completed = subprocess.run(
        ["docker", *args], check=check, capture_output=True, text=True
    )
    return completed.stdout.strip()


def _request(base_url: str, spec: dict[str, Any]) -> dict[str, Any]:
    path = str(spec.get("path", "/"))
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or not path.startswith("/"):
        raise ValueError("HTTP contract paths must be relative and start with /")
    body_value = spec.get("body")
    body = None if body_value is None else str(body_value).encode()
    if body is not None and len(body) > _MAX_BODY:
        raise ValueError("HTTP request body exceeds 64 KiB")
    headers = {str(k): str(v) for k, v in spec.get("headers", {}).items()}
    headers.setdefault("User-Agent", "CVELab-Closed-PoC/1.0")
    request = urllib.request.Request(
        base_url + path,
        data=body,
        headers=headers,
        method=str(spec.get("method", "GET")).upper(),
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            content = response.read(_MAX_RESPONSE).decode("utf-8", errors="replace")
            return {
                "status": response.status,
                "headers": dict(response.headers.items()),
                "body": content,
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": exc.code,
            "headers": dict(exc.headers.items()),
            "body": exc.read(_MAX_RESPONSE).decode("utf-8", errors="replace"),
        }


_PROBE_CODE = r'''import json, os, urllib.error, urllib.request
spec = json.loads(os.environ["CVELAB_REQUEST"])
body = spec.get("body")
request = urllib.request.Request(
    os.environ["CVELAB_BASE"] + str(spec.get("path", "/")),
    data=None if body is None else str(body).encode(),
    headers={str(k): str(v) for k, v in spec.get("headers", {}).items()},
    method=str(spec.get("method", "GET")).upper(),
)
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        result = {"status": response.status, "headers": dict(response.headers.items()),
                  "body": response.read(1048576).decode("utf-8", errors="replace")}
except urllib.error.HTTPError as exc:
    result = {"status": exc.code, "headers": dict(exc.headers.items()),
              "body": exc.read(1048576).decode("utf-8", errors="replace")}
print(json.dumps(result))
'''


def _container_request(
    network_name: str, base_url: str, spec: dict[str, Any]
) -> dict[str, Any]:
    output = _docker(
        "run", "--rm", "--network", network_name,
        "--security-opt", "no-new-privileges:true",
        *runtime_flags(),
        "-e", f"CVELAB_BASE={base_url}",
        "-e", f"CVELAB_REQUEST={json.dumps(spec, separators=(',', ':'))}",
        "python:3.13-alpine", "python", "-c", _PROBE_CODE,
    )
    return json.loads(output)


def _matches(response: dict[str, Any], match: dict[str, Any]) -> tuple[bool, list[str]]:
    checks: list[bool] = []
    evidence: list[str] = []
    if "status" in match:
        allowed = match["status"]
        if not isinstance(allowed, list):
            allowed = [allowed]
        passed = response["status"] in [int(value) for value in allowed]
        checks.append(passed)
        evidence.append(f"status={response['status']} allowed={allowed} passed={passed}")
    if "body_contains" in match:
        value = str(match["body_contains"])
        passed = value in response["body"]
        checks.append(passed)
        evidence.append(f"body_contains={value!r} passed={passed}")
    if "body_regex" in match:
        value = str(match["body_regex"])
        passed = re.search(value, response["body"]) is not None
        checks.append(passed)
        evidence.append(f"body_regex={value!r} passed={passed}")
    if "header" in match:
        expected = match["header"]
        name, value = str(expected["name"]), str(expected["contains"])
        actual = next(
            (v for k, v in response["headers"].items() if k.lower() == name.lower()), ""
        )
        passed = value in actual
        checks.append(passed)
        evidence.append(f"header={name!r} contains={value!r} passed={passed}")
    if not checks:
        raise ValueError("observe.match must define at least one predicate")
    return all(checks), evidence


def _seconds(value: Any, name: str, default: int, ceiling: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"contract.{name} must be a whole number of seconds")
    if not 1 <= value <= ceiling:
        raise ValueError(f"contract.{name} must be between 1 and {ceiling} seconds")
    return value


def _validate_fixture(fixture: Any) -> dict[str, Any]:
    """The state an attack needs in place before it can prove anything.

    A product-class vulnerability is rarely reachable on an empty instance: a
    GraphQL field that discloses a private comment needs a project, an item and
    a comment to exist first, and creating them is authenticated work the
    attack itself is not allowed to do. The fixture is how a contract asks for
    that state, and it stays as inspectable as the rest of the contract -- an
    argv list rather than a shell string, and named files copied into one
    directory the command can read.
    """
    if not isinstance(fixture, dict):
        raise ValueError("contract.fixture must be an object")
    command = fixture.get("command")
    if not isinstance(command, list) or not command:
        raise ValueError("contract.fixture.command must be a non-empty list")
    if not all(isinstance(argument, str) and argument for argument in command):
        raise ValueError("contract.fixture.command must hold non-empty strings")
    files = fixture.get("files", {})
    if not isinstance(files, dict):
        raise ValueError("contract.fixture.files must map a file name to its text")
    for name, text in files.items():
        if not _FIXTURE_NAME.fullmatch(str(name)):
            raise ValueError(
                f"contract.fixture.files name {name!r} must match {_FIXTURE_NAME.pattern}"
            )
        if not isinstance(text, str):
            raise ValueError(f"contract.fixture.files[{name!r}] must be text")
        if len(text.encode()) > _MAX_FIXTURE_FILE:
            raise ValueError(f"contract.fixture.files[{name!r}] exceeds 256 KiB")
    environment = fixture.get("env", {})
    if not isinstance(environment, dict):
        raise ValueError("contract.fixture.env must map a variable name to its value")
    for key in environment:
        if not _ENV_NAME.fullmatch(str(key)):
            raise ValueError(
                f"contract.fixture.env name {key!r} must match {_ENV_NAME.pattern}"
            )
    return {
        "command": [str(argument) for argument in command],
        "files": {str(name): text for name, text in files.items()},
        "env": {str(key): str(value) for key, value in environment.items()},
        "timeout": _seconds(
            fixture.get("timeout"), "fixture.timeout",
            DEFAULT_FIXTURE_TIMEOUT, MAX_FIXTURE_TIMEOUT,
        ),
    }


def _validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    attacks = contract.get("attack")
    observe = contract.get("observe")
    if not isinstance(attacks, list) or not attacks:
        raise ValueError("contract.attack must be a non-empty list")
    if not isinstance(observe, dict) or not isinstance(observe.get("request"), dict):
        raise ValueError("contract.observe.request is required")
    if not isinstance(observe.get("match"), dict):
        raise ValueError("contract.observe.match is required")
    for request in [*attacks, observe["request"]]:
        if not isinstance(request, dict):
            raise ValueError("every HTTP request must be an object")
        path = str(request.get("path", "/"))
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc or not path.startswith("/"):
            raise ValueError("contract contains a non-relative HTTP path")
    contract["health_timeout"] = _seconds(
        contract.get("health_timeout"), "health_timeout",
        DEFAULT_HEALTH_TIMEOUT, MAX_HEALTH_TIMEOUT,
    )
    if contract.get("fixture") is not None:
        contract["fixture"] = _validate_fixture(contract["fixture"])
    return contract


def _wait_ready(
    network_name: str, base_url: str, health_path: str,
    timeout: int = DEFAULT_HEALTH_TIMEOUT,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = _container_request(
                network_name, base_url, {"method": "GET", "path": health_path}
            )
            if response["status"] < 500:
                return
        except (TimeoutError, OSError, subprocess.CalledProcessError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise RuntimeError(
        f"container did not become ready at {health_path} within {timeout}s"
    )


_POC_BOOTSTRAP = r'''import os, pathlib, runpy, sys
home = pathlib.Path("/tmp/cvelab")
home.mkdir(parents=True, exist_ok=True)
(home / "PoC.py").write_text(os.environ["CVELAB_POC"])
(home / "contract.json").write_text(os.environ["CVELAB_CONTRACT"])
sys.argv = ["PoC.py", "--base-url", os.environ["CVELAB_BASE"]]
runpy.run_path(str(home / "PoC.py"), run_name="__main__")
'''


def _run_poc_script(
    container: str, port: int, contract: dict[str, Any], expected: str
) -> dict[str, Any]:
    """Run the PoC this lab ships, and report whether it reached `expected`.

    The reproduction the runner performs and the script a reviewer is handed
    are two different programs. Only running the second one proves the lab is
    reproducible by hand, which is what the source path's manual check means,
    so the closed path earns the same claim the same way.

    The sidecar joins the lab container's network namespace instead of the
    lab publishing a port: `127.0.0.1` then reaches the product, so the
    script's own loopback guard holds with nothing exposed to the host.
    """
    completed = subprocess.run(
        [
            "docker", "run", "--rm", "--network", f"container:{container}",
            "--security-opt", "no-new-privileges:true",
            *runtime_flags(),
            "-e", f"CVELAB_BASE=http://127.0.0.1:{port}",
            "-e", f"CVELAB_POC={_POC_SCRIPT}",
            "-e", f"CVELAB_CONTRACT={json.dumps(contract, separators=(',', ':'))}",
            "python:3.13-alpine", "python", "-c", _POC_BOOTSTRAP,
        ],
        capture_output=True, text=True, timeout=300, check=False,
    )
    output = completed.stdout.strip()
    return {
        "expected_verdict": expected,
        "passed": completed.returncode == 0 and expected in output.splitlines()[-1:],
        "exit_code": completed.returncode,
        "output": output[-_MAX_FIXTURE_OUTPUT:],
        "stderr": completed.stderr.strip()[-2000:],
    }


def _apply_fixture(container: str, fixture: dict[str, Any]) -> dict[str, Any]:
    """Put the contract's fixture in place inside the running container.

    A fixture that fails must stop the run. An unseeded instance answers the
    attack with nothing to disclose, which is indistinguishable from a fixed
    one -- so a silent failure here would report the patched variant's own
    behavior for both variants and call it a differential.
    """
    with tempfile.TemporaryDirectory() as staging:
        for name, text in fixture["files"].items():
            (Path(staging) / name).write_text(text, encoding="utf-8")
        _docker("exec", container, "mkdir", "-p", _FIXTURE_ROOT)
        for name in fixture["files"]:
            _docker("cp", str(Path(staging) / name), f"{container}:{_FIXTURE_ROOT}/{name}")
    environment: list[str] = []
    for key, value in fixture["env"].items():
        environment += ["-e", f"{key}={value}"]
    completed = subprocess.run(
        ["docker", "exec", *environment, container, *fixture["command"]],
        capture_output=True, text=True, timeout=fixture["timeout"], check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-2000:]
        raise RuntimeError(
            f"fixture command exited {completed.returncode}: {detail}"
        )
    return {
        "command": fixture["command"],
        "files": sorted(fixture["files"]),
        "root": _FIXTURE_ROOT,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-_MAX_FIXTURE_OUTPUT:],
        "stderr": completed.stderr[-_MAX_FIXTURE_OUTPUT:],
    }


def _run_variant(
    cve: str,
    variant: str,
    image: str,
    port: int,
    health_path: str,
    contract: dict[str, Any],
) -> dict[str, Any]:
    token = uuid.uuid4().hex[:12]
    name = f"cvelab-{cve.lower()}-{variant}-{token}"
    network_name = f"{name}-net"
    container_id = ""
    network_id = ""
    try:
        network_id = _docker(
            "network", "create", "--internal",
            "--label", "io.cvelab.managed=true",
            "--label", f"io.cvelab.cve={cve}",
            "--label", f"io.cvelab.run={token}",
            network_name,
        )
        container_id = _docker(
            "run", "-d", "--name", name,
            "--label", "io.cvelab.managed=true",
            "--label", f"io.cvelab.cve={cve}",
            "--label", f"io.cvelab.run={token}",
            "--security-opt", "no-new-privileges:true",
            # The image is the user's or a model's pick, and ran with no
            # ceiling at all; these are the ones a Compose lab gets.
            *runtime_flags(),
            "--network", network_name, image,
        )
        base_url = f"http://{name}:{port}"
        _wait_ready(
            network_name, base_url, health_path,
            int(contract.get("health_timeout", DEFAULT_HEALTH_TIMEOUT)),
        )
        fixture = contract.get("fixture")
        applied = _apply_fixture(name, fixture) if fixture else None
        attack_results = [
            _container_request(network_name, base_url, step) for step in contract["attack"]
        ]
        observation = _container_request(
            network_name, base_url, contract["observe"]["request"]
        )
        confirmed, predicates = _matches(observation, contract["observe"]["match"])
        shipped = _run_poc_script(
            name, port, contract, "REPRODUCED" if variant == "vulnerable" else "BLOCKED"
        )
        return {
            "variant": variant,
            "image": image,
            "fixture": applied,
            "shipped_poc": shipped,
            "attack_executed": True,
            "confirmed": confirmed,
            "predicates": predicates,
            "attack_responses": attack_results,
            "observation": observation,
        }
    finally:
        if container_id:
            current = _docker("inspect", "--format", "{{.Id}}", name, check=False)
            if current == container_id:
                _docker("rm", "-f", container_id, check=False)
        if network_id:
            current_network = _docker(
                "network", "inspect", "--format", "{{.Id}}", network_name, check=False
            )
            if current_network == network_id:
                _docker("network", "rm", network_id, check=False)


_POC_SCRIPT = r'''"""Loopback-only closed software PoC.

Reads `contract.json` beside this file, replays its attack, then checks the
observation against the contract's own predicate and prints one verdict:
REPRODUCED when the predicate holds, BLOCKED when it does not. The exit code
is 0 either way -- a blocked run is a successful measurement of a fixed build,
not a failure of this script.
"""
from __future__ import annotations
import argparse, json, re, urllib.error, urllib.parse, urllib.request
from pathlib import Path

def send(base, spec):
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Refusing non-loopback target")
    path = str(spec.get("path", "/"))
    if urllib.parse.urlsplit(path).scheme or not path.startswith("/"):
        raise SystemExit("Contract path must be relative")
    body = spec.get("body")
    headers = {str(k): str(v) for k, v in spec.get("headers", {}).items()}
    headers.setdefault("User-Agent", "CVELab-Closed-PoC/1.0")
    req = urllib.request.Request(base.rstrip("/") + path,
        data=None if body is None else str(body).encode(),
        headers=headers,
        method=str(spec.get("method", "GET")).upper())
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, dict(response.headers.items()), response.read(1048576).decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read(1048576).decode(errors="replace")

def matches(status, headers, body, match):
    """The same predicates the runner applies, so both reach one verdict."""
    checks = []
    if "status" in match:
        allowed = match["status"]
        allowed = allowed if isinstance(allowed, list) else [allowed]
        checks.append(("status", status in [int(v) for v in allowed]))
    if "body_contains" in match:
        checks.append(("body_contains", str(match["body_contains"]) in body))
    if "body_regex" in match:
        checks.append(("body_regex", re.search(str(match["body_regex"]), body) is not None))
    if "header" in match:
        name, value = str(match["header"]["name"]), str(match["header"]["contains"])
        actual = next((v for k, v in headers.items() if k.lower() == name.lower()), "")
        checks.append(("header", value in actual))
    if not checks:
        raise SystemExit("observe.match defines no predicate")
    return all(passed for _, passed in checks), checks

parser = argparse.ArgumentParser(description="Loopback-only closed software PoC")
parser.add_argument("--base-url", required=True, help="Loopback URL printed by docker port")
args = parser.parse_args()
contract = json.loads((Path(__file__).parent / "contract.json").read_text())
if contract.get("fixture"):
    print("This contract needs its fixture in place first; see WALKTHROUGH.md.")
for index, step in enumerate(contract["attack"], 1):
    status, _, body = send(args.base_url, step)
    print(f"attack[{index}] status={status}\n{body[:4000]}")
status, headers, body = send(args.base_url, contract["observe"]["request"])
print(f"observation status={status}\n{body[:4000]}")
confirmed, checks = matches(status, headers, body, contract["observe"]["match"])
for name, passed in checks:
    print(f"predicate {name} passed={passed}")
print("REPRODUCED" if confirmed else "BLOCKED")
'''


def run_closed_lab(
    cve: str,
    output_root: Path,
    vulnerable_image: str,
    fixed_image: str | None,
    container_port: int,
    health_path: str,
    contract_path: Path,
) -> dict[str, Any]:
    cve = cve.upper()
    if not _CVE.fullmatch(cve):
        raise ValueError("invalid CVE identifier")
    if not 1 <= container_port <= 65535:
        raise ValueError("container port must be between 1 and 65535")
    if not health_path.startswith("/"):
        raise ValueError("health path must start with /")
    contract = _validate_contract(json.loads(contract_path.read_text(encoding="utf-8")))
    lab_dir = output_root.resolve() / cve
    artifacts = lab_dir / "artifacts"
    evidence_dir = lab_dir / "closed" / "evidence"
    artifacts.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (artifacts / "contract.json").write_text(json.dumps(contract, indent=2), encoding="utf-8")
    (artifacts / "PoC.py").write_text(_POC_SCRIPT, encoding="ascii")
    fixture = contract.get("fixture")
    if fixture:
        # The same files the runner copies in, beside the PoC, so the manual
        # walkthrough is a command a reader can run rather than a description.
        fixture_dir = artifacts / "fixture"
        fixture_dir.mkdir(parents=True, exist_ok=True)
        for name, text in fixture["files"].items():
            (fixture_dir / name).write_text(text, encoding="utf-8")

    vulnerable = _run_variant(
        cve, "vulnerable", vulnerable_image, container_port, health_path, contract
    )
    patched = None
    if fixed_image:
        patched = _run_variant(
            cve, "patched", fixed_image, container_port, health_path, contract
        )
    differential = bool(vulnerable["confirmed"] and patched and not patched["confirmed"])
    tested = [variant for variant in (vulnerable, patched) if variant]
    manual_poc_checks = {
        variant["variant"]: variant["shipped_poc"]
        for variant in tested
        if variant.get("shipped_poc")
    }
    manual_poc_verified = bool(manual_poc_checks) and all(
        check["passed"] for check in manual_poc_checks.values()
    )
    proof_checks = {
        "closed_software_reproduction": bool(vulnerable["confirmed"]),
        "attack_executed": all(variant["attack_executed"] for variant in tested),
        "security_effect_observed": bool(vulnerable["confirmed"]),
        "vulnerable_confirmed": bool(vulnerable["confirmed"]),
        "patched_not_confirmed": patched is None or not patched["confirmed"],
        "patched_blocked": differential,
        "manual_poc_verified": manual_poc_verified,
    }
    fixture_text = (
        "No fixture was declared; the attack ran against the image as published."
        if not fixture
        else "The contract's fixture ran inside each container before the attack:\n\n"
        f"```\n{' '.join(fixture['command'])}\n```\n\n"
        "A fixture that exits non-zero aborts the run, so neither variant is\n"
        "reported on an instance that was never seeded."
    )
    # A lab whose own shipped script was never run is a lab that might not
    # reproduce for the reviewer holding it, so `ok` now requires both: the
    # runner's measurement and the script it hands over reaching the verdict.
    ok = bool(
        vulnerable["confirmed"]
        and (patched is None or differential)
        and manual_poc_verified
    )
    result = {
        "ok": ok,
        "cve": cve,
        "lab_type": "CLOSED_SOFTWARE_HTTP_REPRODUCTION",
        "scope": "loopback-only Docker containers supplied by the user",
        "real_poc_verified": bool(vulnerable["confirmed"]),
        "manual_poc_verified": manual_poc_verified,
        "fixture_applied": bool(fixture),
        "proof_checks": proof_checks,
        "manual_poc_checks": manual_poc_checks,
        "patched_tested": patched is not None,
        "differential_confirmed": differential,
        "vulnerable": vulnerable,
        "patched": patched,
    }
    (evidence_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    plan = {
        "cve": cve,
        "lab_type": "CLOSED_SOFTWARE_HTTP_REPRODUCTION",
        # No revision is resolved here: a published image is the whole input,
        # and the control plane checks a repository only when one is named.
        "repository": None,
        "revisions": {},
        "images": {"vulnerable": vulnerable_image, "patched": fixed_image},
        "container_port": container_port,
        "health_path": health_path,
        "fixture": bool(fixture),
    }
    evidence = {
        "schema_version": 1,
        "cve": cve,
        "status": (
            "REAL_CLOSED_SOFTWARE_POC_VALIDATED"
            if ok
            else "CLOSED_SOFTWARE_POC_NOT_VALIDATED"
        ),
        "lab_type": "CLOSED_SOFTWARE_HTTP_REPRODUCTION",
        "fidelity": {
            "execution_level": "vendor_product",
            "vendor_product_started": True,
            "exercised_vendor_components": [vulnerable_image]
            + ([fixed_image] if fixed_image else []),
            "simulated_components": [],
            "rationale": (
                "Both targets are the vendor's own published images, started "
                "unmodified and reached only over HTTP."
            ),
        },
        "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "validation": {
            "attack_executed": proof_checks["attack_executed"],
            "proof_quality": (
                "security_effect_observed"
                if vulnerable["confirmed"]
                else "no_effect_observed"
            ),
            "evidence_type": "contract_predicate",
            "observable_effect": "; ".join(vulnerable["predicates"]),
            "vulnerable": {
                "image": vulnerable_image,
                "confirmed": vulnerable["confirmed"],
                "predicates": vulnerable["predicates"],
            },
            "patched": None
            if patched is None
            else {
                "image": fixed_image,
                "confirmed": patched["confirmed"],
                "predicates": patched["predicates"],
            },
            "differential_confirmed": differential,
        },
        "proof_contract": {
            "attack_summary": (
                f"{len(contract['attack'])} HTTP request(s), then the observation "
                f"{contract['observe']['request'].get('method', 'GET')} "
                f"{contract['observe']['request'].get('path', '/')}"
            ),
            "preconditions": (
                [f"fixture: {' '.join(fixture['command'])}"] if fixture else []
            ),
            "observable_effect": json.dumps(contract["observe"]["match"]),
            "evidence_type": "contract_predicate",
        },
        "proof_checks": proof_checks,
        "manual_poc_checks": manual_poc_checks,
        "provenance": {
            "repository": None,
            "vulnerable_image": vulnerable_image,
            "patched_image": fixed_image,
            "contract": "artifacts/contract.json",
        },
    }
    (lab_dir / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (artifacts / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (artifacts / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    fixed_text = (
        f"The supplied fixed image `{fixed_image}` did not satisfy the exploit predicate."
        if patched and not patched["confirmed"]
        else "No fixed image was supplied; no patched behavior is claimed."
        if patched is None
        else "The supplied fixed image still satisfied the exploit predicate."
    )
    walkthrough = f"""# {cve} Closed Software HTTP PoC

## Scope

This reproduction uses only user-supplied Docker images and loopback HTTP ports.
The inspectable attack contract is `contract.json`; `PoC.py` refuses non-loopback targets.

## Automatic reproduction

Run the same `cvelab closed` command with the supplied image names and contract.
The runner starts each image with a unique UUID name, records its Docker ID, and removes
only that exact ID after evidence collection.

## Fixture

{fixture_text}

## Manual reproduction

1. Start the supplied vulnerable image with a loopback-only published port.
2. Read the assigned port using `docker port <container> {container_port}/tcp`.
3. If `contract.json` declares a fixture, copy `fixture/` into the container at
   `{_FIXTURE_ROOT}` and run the fixture command shown above, with the same
   environment the contract lists.
4. Run `python PoC.py --base-url http://127.0.0.1:<port>`.
5. Compare the printed observation with `contract.json` and `closed/evidence/result.json`.

## Result

Vulnerable exploit predicate: `{vulnerable['confirmed']}`.
{fixed_text}
"""
    report = f"""# {cve} Closed Software PoC Report

- Lab type: `CLOSED_SOFTWARE_HTTP_REPRODUCTION`
- Vulnerable image: `{vulnerable_image}`
- Real exploit predicate observed: `{vulnerable['confirmed']}`
- Fixed image tested: `{patched is not None}`
- Differential confirmed: `{differential}`
- Fixture applied: `{bool(fixture)}`
- Target scope: loopback-only

## Interpretation

The report claims only the behavior defined by the supplied HTTP contract. It does not
infer source-level root cause, patch provenance, or behavior outside the tested images.

## Fixed variant

{fixed_text}

## Fixture

{fixture_text}
"""
    fixture_steps = ""
    if fixture:
        exports = " ".join(
            f"-e {shlex.quote(f'{key}={value}')}" for key, value in fixture["env"].items()
        )
        fixture_steps = (
            f'  docker exec "$container" mkdir -p {_FIXTURE_ROOT}\n'
            f'  docker cp "$LAB_ROOT/fixture/." "$container":{_FIXTURE_ROOT}/\n'
            f'  docker exec {exports} "$container" '
            + " ".join(shlex.quote(argument) for argument in fixture["command"])
            + "\n"
        )
    manual = f"""#!/usr/bin/env bash
# {cve} manual reproduction. Loopback only: the port is published to 127.0.0.1
# and `PoC.py` refuses any other host.
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")" && pwd)"
PORT={container_port}
HEALTH_PATH={shlex.quote(health_path)}
VULNERABLE_IMAGE={shlex.quote(vulnerable_image)}
PATCHED_IMAGE={shlex.quote(fixed_image or "")}

usage() {{
  echo "Usage: bash manual.sh <setup|exploit|cleanup> [vulnerable|patched]" >&2
  exit 2
}}

target="${{2:-vulnerable}}"
case "$target" in
  vulnerable) image="$VULNERABLE_IMAGE" ;;
  patched) image="$PATCHED_IMAGE" ;;
  *) usage ;;
esac
[ -n "$image" ] || {{ echo "this lab has no $target image" >&2; exit 2; }}
container="cvelab-manual-{cve.lower()}-$target"
state="$LAB_ROOT/.manual-base-$target"

case "${{1:-}}" in
setup)
  docker run -d --name "$container" -p 127.0.0.1::"$PORT" "$image" >/dev/null
  port="$(docker port "$container" "$PORT"/tcp | head -1 | sed 's/.*://')"
  base="http://127.0.0.1:$port"
  echo "waiting for $base$HEALTH_PATH"
  deadline=$((SECONDS + {int(contract["health_timeout"])}))
  while [ $SECONDS -lt $deadline ]; do
    code="$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 "$base$HEALTH_PATH" || true)"
    if [ "${{code:-000}}" != "000" ] && [ "$code" -lt 500 ]; then break; fi
    sleep 5
  done
{fixture_steps}  printf '%s\\n' "$base" > "$state"
  echo "ready at $base"
  ;;
exploit)
  python3 "$LAB_ROOT/PoC.py" --base-url "$(cat "$state")"
  ;;
cleanup)
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$state"
  ;;
*) usage ;;
esac
"""
    (artifacts / "manual.sh").write_text(manual, encoding="utf-8")
    (artifacts / "manual.sh").chmod(0o755)
    (artifacts / "WALKTHROUGH.md").write_text(walkthrough, encoding="utf-8")
    (artifacts / "REPORT.md").write_text(report, encoding="utf-8")
    (artifacts / "report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["lab_dir"] = str(lab_dir)
    result["deliverables"] = {
        "poc": str(artifacts / "PoC.py"),
        "manual": str(artifacts / "manual.sh"),
        "contract": str(artifacts / "contract.json"),
        "plan": str(artifacts / "plan.json"),
        "evidence_document": str(artifacts / "EVIDENCE.json"),
        "walkthrough": str(artifacts / "WALKTHROUGH.md"),
        "report": str(artifacts / "REPORT.md"),
        "evidence": str(evidence_dir / "result.json"),
    }
    return result
