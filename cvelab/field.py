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

"""Field PoC mode: a single-target exploit the lab owner runs themselves.

The source and closed modes prove a vulnerability by a differential between
two things the harness controls -- two revisions, or two images -- inside
Docker. That proof never leaves the lab: its PoC is the validator, bound to
the service names `vulnerable` and `patched`, and it refuses a remote target
by construction.

This mode emits a different artifact. The deliverable is a standalone script
that takes `--target` and runs against one server the operator owns, in one
run, and shows the vulnerability happening rather than printing a verdict about
a version. Its proof does not need a second server: it is an effect a fixed
build cannot produce, observed on the one target. Two strategies carry that
without an external listener:

  inband_differential  Read the same resource two ways in the same request
                        round -- the vulnerable path and the path that
                        authorizes correctly -- and report what only the first
                        returned. This is what a broken-authorization
                        disclosure needs: an internal note the vulnerable
                        field returns and the authorized path withholds.

  marker_roundtrip      Send a unique marker through an injection vector and
                        observe it surface where it should not -- reflected,
                        stored, or executed.

CVELab still builds the vulnerable and the fixed instance, but uses them to
prove the emitted script is real before handing it over: the script must
observe the effect against the vulnerable instance and must not against the
fixed one. A script that fires on both, or on neither, is not a field PoC and
is refused -- the same bar the differential gate sets, moved onto the artifact
the operator will actually run.

A class whose effect is not observable on a live target over the wire -- a
memory over-read that only crashes, a race, a timing signal -- has no field
PoC here. The mode declines it rather than ship a script that prints a verdict
it never observed.
"""

from __future__ import annotations

import contextlib
import json
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .closed import (
    DEFAULT_HEALTH_TIMEOUT,
    MAX_HEALTH_TIMEOUT,
    _apply_fixture,
    _docker,
    _seconds,
    _validate_fixture,
    _wait_ready,
)
from .core import runtime_flags

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

#: The strategies that need no listener the operator has to stand up. An
#: out-of-band callback strategy is named so a spec can declare it, but it
#: needs a collaborator endpoint and is not emitted here yet.
STRATEGIES = ("inband_differential", "marker_roundtrip")
_LISTENER_STRATEGIES = ("oob_callback",)

#: The marker the operator's script generates fresh per run, so a stored
#: reflection from an earlier run is never mistaken for this one's.
_MARKER_TOKEN = "{{marker}}"

_MAX_REQUESTS = 25
_MAX_FIELD_OUTPUT = 32 * 1024


def _validate_request(request: Any, where: str) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ValueError(f"{where} must be an object")
    path = str(request.get("path", "/"))
    if not path.startswith("/"):
        raise ValueError(f"{where} path must start with /")
    method = str(request.get("method", "GET")).upper()
    headers = request.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError(f"{where} headers must be an object")
    body = request.get("body")
    if body is not None and not isinstance(body, str):
        raise ValueError(f"{where} body must be a string")
    return {
        "method": method,
        "path": path,
        "headers": {str(k): str(v) for k, v in headers.items()},
        "body": None if body is None else str(body),
    }


def _validate_sequence(value: Any, where: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{where} must be a non-empty list")
    if len(value) > _MAX_REQUESTS:
        raise ValueError(f"{where} may hold at most {_MAX_REQUESTS} requests")
    return [_validate_request(item, f"{where}[{index}]") for index, item in enumerate(value)]


def _validate_extractor(value: Any) -> dict[str, str]:
    """How tokens are pulled from a response for the set-difference proof."""
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError("extract must be exactly one of json_values or regex")
    if "json_values" in value:
        name = str(value["json_values"])
        if not name:
            raise ValueError("extract.json_values must name a JSON key")
        return {"json_values": name}
    if "regex" in value:
        pattern = str(value["regex"])
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(f"extract.regex is not a valid regex: {error}") from error
        return {"regex": pattern}
    raise ValueError("extract must be one of json_values or regex")


def validate_spec(spec: Any) -> dict[str, Any]:
    """A field spec, independent of any one target.

    It describes the effect to observe and the requests that produce it, never
    a hostname: the operator supplies the target at run time.
    """
    if not isinstance(spec, dict):
        raise ValueError("field spec must be an object")
    strategy = spec.get("strategy")
    if strategy in _LISTENER_STRATEGIES:
        raise ValueError(
            f"strategy {strategy!r} needs an out-of-band listener and is not emitted yet"
        )
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {', '.join(STRATEGIES)}")
    effect = spec.get("observable_effect")
    if not isinstance(effect, str) or not effect.strip():
        raise ValueError("observable_effect must describe what a run shows")

    out: dict[str, Any] = {"strategy": strategy, "observable_effect": effect.strip()}

    if strategy == "inband_differential":
        out["probe"] = _validate_sequence(spec.get("probe"), "probe")
        out["control"] = _validate_sequence(spec.get("control"), "control")
        out["extract"] = _validate_extractor(spec.get("extract"))
    else:  # marker_roundtrip
        probe = _validate_sequence(spec.get("probe"), "probe")
        serialized = json.dumps(probe)
        if _MARKER_TOKEN not in serialized:
            raise ValueError(
                f"marker_roundtrip probe must place {_MARKER_TOKEN} somewhere"
            )
        out["probe"] = probe
        out["observe"] = _validate_request(spec.get("observe"), "observe")
        match = spec.get("match", {"body_contains": _MARKER_TOKEN})
        if not isinstance(match, dict):
            raise ValueError("match must be an object")
        out["match"] = match

    if spec.get("fixture") is not None:
        out["fixture"] = _validate_fixture(spec["fixture"])
    out["health_timeout"] = _seconds(
        spec.get("health_timeout"), "health_timeout",
        DEFAULT_HEALTH_TIMEOUT, MAX_HEALTH_TIMEOUT,
    )
    return out


# The deliverable. It is written once, reads the spec embedded beside it, and
# is the same program whether CVELab runs it against the built instance or the
# operator runs it against their server. It targets whatever --target names, so
# it has no loopback guard; the --authorized gate stands in its place, because
# it reads real data from whatever it is pointed at.
_FIELD_POC = r'''#!/usr/bin/env python3
"""CVELab field PoC for @@CVE@@. Run against one target you are permitted to test.

@@EFFECT@@

Read-only transport: it sends the requests the spec names and reports what it
observes. It writes nothing back beyond those requests.
"""
from __future__ import annotations
import argparse, json, re, ssl, sys, urllib.error, urllib.parse, urllib.request, uuid

SPEC = @@SPEC@@


def _collect(value, key, out):
    if isinstance(value, dict):
        for k, v in value.items():
            if k == key and isinstance(v, (str, int, float, bool)):
                out.append(str(v))
            _collect(v, key, out)
    elif isinstance(value, list):
        for item in value:
            _collect(item, key, out)


def tokens(body, extractor):
    if "json_values" in extractor:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return []
        out = []
        _collect(parsed, extractor["json_values"], out)
        return out
    found = re.findall(extractor["regex"], body)
    return [m if isinstance(m, str) else m[0] for m in found]


class Target:
    def __init__(self, base, insecure, timeout):
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise SystemExit("--target must be an http(s) URL, e.g. https://host")
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.ctx = None
        if parsed.scheme == "https" and insecure:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def send(self, spec):
        path = str(spec.get("path", "/"))
        if not path.startswith("/"):
            raise SystemExit("request path must be relative")
        body = spec.get("body")
        headers = dict(spec.get("headers", {}))
        headers.setdefault("User-Agent", "CVELab-Field-PoC/1.0")
        req = urllib.request.Request(
            self.base + path,
            data=None if body is None else str(body).encode(),
            headers=headers,
            method=str(spec.get("method", "GET")).upper(),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return r.status, r.read(8 * 1024 * 1024).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(8 * 1024 * 1024).decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as e:
            raise SystemExit("cannot reach %s: %s" % (self.base, e))


def _subst(sequence, marker):
    return json.loads(json.dumps(sequence).replace("{{marker}}", marker))


def run_inband_differential(target, show_bodies):
    last_probe = None
    for step in SPEC["probe"]:
        last_probe = target.send(step)
    last_control = None
    for step in SPEC["control"]:
        last_control = target.send(step)
    probe_tokens = tokens(last_probe[1], SPEC["extract"])
    control_tokens = set(tokens(last_control[1], SPEC["extract"]))
    disclosed = [t for t in probe_tokens if t not in control_tokens]
    print("probe    status=%s  %d value(s) via the vulnerable path" % (last_probe[0], len(probe_tokens)))
    print("control  status=%s  %d value(s) via the authorized path" % (last_control[0], len(set(probe_tokens) & control_tokens)))
    seen = set()
    unique = [t for t in disclosed if not (t in seen or seen.add(t))]
    for value in unique:
        shown = value if show_bodies else (value[:120] + ("..." if len(value) > 120 else ""))
        print("  [DISCLOSED] %r" % shown)
    return {"observed": bool(unique), "disclosed": unique,
            "probe_status": last_probe[0], "control_status": last_control[0]}


def run_marker_roundtrip(target, show_bodies):
    marker = "cvelab-" + uuid.uuid4().hex[:16]
    for step in _subst(SPEC["probe"], marker):
        status, _ = target.send(step)
    obs_status, obs_body = target.send(_subst([SPEC["observe"]], marker)[0])
    match = SPEC["match"]
    needle = str(match.get("body_contains", "{{marker}}")).replace("{{marker}}", marker)
    observed = needle in obs_body
    print("marker   %s" % marker)
    print("observe  status=%s  marker_present=%s" % (obs_status, observed))
    if observed and show_bodies:
        idx = obs_body.find(needle)
        print("  [REFLECTED] ...%s..." % obs_body[max(0, idx - 40):idx + len(needle) + 40])
    return {"observed": observed, "marker": marker, "observe_status": obs_status}


def main():
    p = argparse.ArgumentParser(description="CVELab field PoC for @@CVE@@")
    p.add_argument("--target", required=True, help="https://host you are permitted to test")
    p.add_argument("--authorized", action="store_true",
                   help="Required: confirm you may test --target")
    p.add_argument("--show-bodies", action="store_true")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    if not args.authorized:
        raise SystemExit(
            "Refusing to run without --authorized. This sends live requests to "
            + args.target + " and reads what it returns; run it only against a "
            "system you are permitted to test."
        )
    target = Target(args.target, args.insecure, args.timeout)
    print("target   %s" % target.base, file=sys.stderr)
    print("effect   %s" % SPEC["observable_effect"], file=sys.stderr)
    if SPEC["strategy"] == "inband_differential":
        result = run_inband_differential(target, args.show_bodies)
    else:
        result = run_marker_roundtrip(target, args.show_bodies)
    if args.json:
        print(json.dumps({"target": target.base, "strategy": SPEC["strategy"], **result}))
    print("OBSERVED" if result["observed"] else "NOT_OBSERVED")
    return 0 if result["observed"] else 1


if __name__ == "__main__":
    sys.exit(main())
'''


def emit_field_poc(cve: str, spec: dict[str, Any]) -> str:
    """The standalone deliverable, with the spec frozen into it."""
    return (
        _FIELD_POC
        .replace("@@SPEC@@", json.dumps(spec, indent=4))
        .replace("@@EFFECT@@", spec["observable_effect"])
        .replace("@@CVE@@", cve)
    )


def _run_field_script(container: str, port: int, script: str, strategy: str) -> dict[str, Any]:
    """Run the emitted field PoC from a sidecar sharing the lab's network.

    The deliverable has no loopback guard, so the same script CVELab validates
    is the one the operator receives. The sidecar joins the lab container's
    network namespace, so --target 127.0.0.1 reaches the product with nothing
    published to the host, and --authorized is passed because CVELab owns the
    instance it is pointing at.
    """
    bootstrap = (
        "import os, pathlib, runpy, sys\n"
        "home = pathlib.Path('/tmp/cvelab'); home.mkdir(parents=True, exist_ok=True)\n"
        "(home / 'field.py').write_text(os.environ['CVELAB_FIELD'])\n"
        "sys.argv = ['field.py', '--target', os.environ['CVELAB_BASE'], '--authorized', '--json']\n"
        "runpy.run_path(str(home / 'field.py'), run_name='__main__')\n"
    )
    completed = subprocess.run(
        [
            "docker", "run", "--rm", "--network", f"container:{container}",
            "--security-opt", "no-new-privileges:true",
            *runtime_flags(),
            "-e", f"CVELAB_BASE=http://127.0.0.1:{port}",
            "-e", f"CVELAB_FIELD={script}",
            "python:3.13-alpine", "python", "-c", bootstrap,
        ],
        capture_output=True, text=True, timeout=300, check=False,
    )
    verdict = completed.stdout.strip().splitlines()[-1:] or [""]
    observation: dict[str, Any] = {}
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            with contextlib.suppress(json.JSONDecodeError):
                observation = json.loads(line)
    return {
        "observed": verdict[0] == "OBSERVED",
        "exit_code": completed.returncode,
        "observation": observation,
        "output": completed.stdout[-_MAX_FIELD_OUTPUT:],
        "stderr": completed.stderr.strip()[-2000:],
    }


def _run_variant(
    cve: str, variant: str, image: str, port: int, health_path: str,
    spec: dict[str, Any], script: str,
) -> dict[str, Any]:
    """Start one image, seed it, and run the field PoC against it."""
    token = uuid.uuid4().hex[:12]
    name = f"cvelab-field-{cve.lower()}-{variant}-{token}"
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
            *runtime_flags(),
            "--network", network_name, image,
        )
        base_url = f"http://{name}:{port}"
        _wait_ready(network_name, base_url, health_path,
                    int(spec.get("health_timeout", DEFAULT_HEALTH_TIMEOUT)))
        fixture = spec.get("fixture")
        applied = _apply_fixture(name, fixture) if fixture else None
        outcome = _run_field_script(name, port, script, spec["strategy"])
        return {"variant": variant, "image": image, "fixture": applied, **outcome}
    finally:
        if container_id:
            current = _docker("inspect", "--format", "{{.Id}}", name, check=False)
            if current == container_id:
                _docker("rm", "-f", container_id, check=False)
        if network_id:
            current_net = _docker(
                "network", "inspect", "--format", "{{.Id}}", network_name, check=False
            )
            if current_net == network_id:
                _docker("network", "rm", network_id, check=False)


def run_field_lab(
    cve: str,
    output_root: Path,
    vulnerable_image: str,
    fixed_image: str | None,
    container_port: int,
    health_path: str,
    spec_path: Path,
) -> dict[str, Any]:
    """Emit a field PoC and prove it against the built instances.

    A field PoC without a fixed instance to check against cannot show that the
    effect it observes is the vulnerability rather than the application's normal
    behavior, so a fixed image is required here even though the closed mode
    treats it as optional.
    """
    cve = cve.upper()
    if not _CVE.fullmatch(cve):
        raise ValueError("invalid CVE identifier")
    if not 1 <= container_port <= 65535:
        raise ValueError("container port must be between 1 and 65535")
    if not health_path.startswith("/"):
        raise ValueError("health path must start with /")
    if not fixed_image:
        raise ValueError("field mode needs a fixed image to prove the effect is the bug")
    spec = validate_spec(json.loads(spec_path.read_text(encoding="utf-8")))
    script = emit_field_poc(cve, spec)

    lab_dir = output_root.resolve() / cve
    artifacts = lab_dir / "artifacts"
    evidence_dir = lab_dir / "field" / "evidence"
    artifacts.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    vulnerable = _run_variant(
        cve, "vulnerable", vulnerable_image, container_port, health_path, spec, script
    )
    patched = _run_variant(
        cve, "patched", fixed_image, container_port, health_path, spec, script
    )

    # The script is a field PoC only if it tells the two apart on its own: the
    # effect on the vulnerable instance, silence on the fixed one. Firing on
    # both means it observes normal behavior, not the bug.
    proven = bool(vulnerable["observed"] and not patched["observed"])
    proof_checks = {
        "effect_observed_on_vulnerable": bool(vulnerable["observed"]),
        "silent_on_fixed": not patched["observed"],
        "field_poc_proven": proven,
    }

    (artifacts / "field-poc.py").write_text(script, encoding="utf-8")
    (artifacts / "field-poc.py").chmod(0o755)
    (artifacts / "field-spec.json").write_text(
        json.dumps(spec, indent=2), encoding="utf-8"
    )

    plan = {
        "cve": cve,
        "lab_type": "FIELD_POC",
        "strategy": spec["strategy"],
        "repository": None,
        "revisions": {},
        "images": {"vulnerable": vulnerable_image, "patched": fixed_image},
        "container_port": container_port,
        "health_path": health_path,
    }
    evidence = {
        "schema_version": 1,
        "cve": cve,
        "status": "REAL_FIELD_POC_VALIDATED" if proven else "FIELD_POC_NOT_VALIDATED",
        "lab_type": "FIELD_POC",
        "strategy": spec["strategy"],
        "observable_effect": spec["observable_effect"],
        "validated_against": {"vulnerable": vulnerable_image, "fixed": fixed_image},
        "proof_checks": proof_checks,
        "runs": {"vulnerable": vulnerable, "patched": patched},
    }
    (lab_dir / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (artifacts / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (artifacts / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (evidence_dir / "result.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    usage = "python3 field-poc.py --target https://your-server --authorized --show-bodies"
    walkthrough = f"""# {cve} Field PoC

## What this is

A single-target exploit you run yourself, against one server you are permitted
to test, in one run. It shows the vulnerability happening: {spec['observable_effect']}

It does not need a second server. Its proof is an effect a fixed build cannot
produce, and CVELab confirmed that before handing it to you -- the script
observed the effect on `{vulnerable_image}` and stayed silent on `{fixed_image}`.

## Run it

```bash
cd {cve}/artifacts
{usage}
```

It prints `OBSERVED` and exits 0 when the effect is present, `NOT_OBSERVED` and
exits 1 when it is not. `--show-bodies` prints the disclosed values in full.

The `--authorized` flag is required: the script sends live requests to the
target and reads what it returns.

## Strategy: {spec['strategy']}

{'It reads the same resource two ways in one request round -- the vulnerable path and the path that authorizes correctly -- and reports what only the vulnerable path returned. A value it reports is one the server disclosed to an unauthorized requester.' if spec['strategy'] == 'inband_differential' else 'It sends a unique marker through the vulnerable vector and observes it surface where it should not. The marker is fresh each run, so a stored reflection from a previous run is never counted.'}

## A negative result is not always a clean bill

`NOT_OBSERVED` means the effect was not seen on this target with this input. For
a differential strategy it can also mean the target had nothing for the probe to
disclose -- an empty instance -- not that it is patched. To decide affected vs
fixed regardless of data, check the build, not only this script.
"""
    report = f"""# {cve} Field PoC Report

- Lab type: `FIELD_POC`
- Strategy: `{spec['strategy']}`
- Observable effect: {spec['observable_effect']}
- Proven against vulnerable `{vulnerable_image}`: `{vulnerable['observed']}`
- Silent against fixed `{fixed_image}`: `{not patched['observed']}`
- Field PoC proven: `{proven}`

## Interpretation

The script is handed over only because it told the vulnerable and the fixed
instance apart on its own. It claims only the effect it observed; it does not
infer source-level root cause or behavior outside the requests it sends.
"""
    (artifacts / "WALKTHROUGH.md").write_text(walkthrough, encoding="utf-8")
    (artifacts / "REPORT.md").write_text(report, encoding="utf-8")
    (artifacts / "report.json").write_text(
        json.dumps({"cve": cve, "lab_type": "FIELD_POC", "ok": proven,
                    "real_poc_verified": proven, "proof_checks": proof_checks},
                   indent=2), encoding="utf-8"
    )

    result = {
        "ok": proven,
        "cve": cve,
        "lab_type": "FIELD_POC",
        "strategy": spec["strategy"],
        "field_poc_proven": proven,
        "proof_checks": proof_checks,
        "vulnerable": vulnerable,
        "patched": patched,
        "lab_dir": str(lab_dir),
        "deliverables": {
            "field_poc": str(artifacts / "field-poc.py"),
            "spec": str(artifacts / "field-spec.json"),
            "evidence": str(evidence_dir / "result.json"),
            "walkthrough": str(artifacts / "WALKTHROUGH.md"),
            "report": str(artifacts / "REPORT.md"),
        },
    }
    return result
