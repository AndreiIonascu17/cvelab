from __future__ import annotations

import json
import re
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MAX_BODY = 64 * 1024
_MAX_RESPONSE = 1024 * 1024


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
    return contract


def _wait_ready(network_name: str, base_url: str, health_path: str) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            response = _container_request(
                network_name, base_url, {"method": "GET", "path": health_path}
            )
            if response["status"] < 500:
                return
        except (OSError, subprocess.CalledProcessError, urllib.error.URLError, socket.timeout):
            pass
        time.sleep(2)
    raise RuntimeError(f"container did not become ready at {health_path}")


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
            "--network", network_name, image,
        )
        base_url = f"http://{name}:{port}"
        _wait_ready(network_name, base_url, health_path)
        attack_results = [
            _container_request(network_name, base_url, step) for step in contract["attack"]
        ]
        observation = _container_request(
            network_name, base_url, contract["observe"]["request"]
        )
        confirmed, predicates = _matches(observation, contract["observe"]["match"])
        return {
            "variant": variant,
            "image": image,
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


_POC_SCRIPT = r'''from __future__ import annotations
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
    req = urllib.request.Request(base.rstrip("/") + path,
        data=None if body is None else str(body).encode(),
        headers={str(k): str(v) for k, v in spec.get("headers", {}).items()},
        method=str(spec.get("method", "GET")).upper())
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, response.read(1048576).decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1048576).decode(errors="replace")

parser = argparse.ArgumentParser(description="Loopback-only closed software PoC")
parser.add_argument("--base-url", required=True, help="Loopback URL printed by docker port")
args = parser.parse_args()
contract = json.loads((Path(__file__).parent / "contract.json").read_text())
for index, step in enumerate(contract["attack"], 1):
    status, body = send(args.base_url, step)
    print(f"attack[{index}] status={status}\n{body[:4000]}")
status, body = send(args.base_url, contract["observe"]["request"])
print(f"observation status={status}\n{body[:4000]}")
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

    vulnerable = _run_variant(
        cve, "vulnerable", vulnerable_image, container_port, health_path, contract
    )
    patched = None
    if fixed_image:
        patched = _run_variant(
            cve, "patched", fixed_image, container_port, health_path, contract
        )
    differential = bool(vulnerable["confirmed"] and patched and not patched["confirmed"])
    ok = bool(vulnerable["confirmed"] and (patched is None or differential))
    result = {
        "ok": ok,
        "cve": cve,
        "lab_type": "CLOSED_SOFTWARE_HTTP_REPRODUCTION",
        "scope": "loopback-only Docker containers supplied by the user",
        "real_poc_verified": bool(vulnerable["confirmed"]),
        "patched_tested": patched is not None,
        "differential_confirmed": differential,
        "vulnerable": vulnerable,
        "patched": patched,
    }
    (evidence_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

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

## Manual reproduction

1. Start the supplied vulnerable image with a loopback-only published port.
2. Read the assigned port using `docker port <container> {container_port}/tcp`.
3. Run `python PoC.py --base-url http://127.0.0.1:<port>`.
4. Compare the printed observation with `contract.json` and `closed/evidence/result.json`.

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
- Target scope: loopback-only

## Interpretation

The report claims only the behavior defined by the supplied HTTP contract. It does not
infer source-level root cause, patch provenance, or behavior outside the tested images.

## Fixed variant

{fixed_text}
"""
    (artifacts / "WALKTHROUGH.md").write_text(walkthrough, encoding="utf-8")
    (artifacts / "REPORT.md").write_text(report, encoding="utf-8")
    (artifacts / "report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["lab_dir"] = str(lab_dir)
    result["deliverables"] = {
        "poc": str(artifacts / "PoC.py"),
        "contract": str(artifacts / "contract.json"),
        "walkthrough": str(artifacts / "WALKTHROUGH.md"),
        "report": str(artifacts / "REPORT.md"),
        "evidence": str(evidence_dir / "result.json"),
    }
    return result
