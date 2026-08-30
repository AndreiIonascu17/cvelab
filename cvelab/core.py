from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .ai import plan_with_openai
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
) -> tuple[str, dict | None]:
    explicit = normalize_cwe(override)
    candidates = [explicit] if explicit else dossier.get("cwes", [])
    for candidate in candidates:
        if candidate in SUPPORTED_CWES:
            return candidate, None

    effective_key = api_key or os.getenv("OPENAI_API_KEY")
    if ai_mode in {"auto", "on"} and effective_key:
        ai_plan = plan_with_openai(dossier, api_key=api_key, model=model)
        candidate = normalize_cwe(ai_plan.get("cwe"))
        if candidate in SUPPORTED_CWES:
            return candidate, ai_plan
        if ai_mode == "on":
            raise RuntimeError(f"AI selected unsupported CWE: {candidate}")
    elif ai_mode == "on":
        raise RuntimeError("--ai on requires OPENAI_API_KEY and CVELAB_MODEL")

    found = ", ".join(dossier.get("cwes", [])) or "none"
    raise RuntimeError(f"No supported CWE found (metadata: {found}). Use --cwe with one of {sorted(SUPPORTED_CWES)}")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


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
) -> dict:
    cve = normalize_cve(cve_value)
    dossier = collect_cve(cve)
    cwe, ai_plan = select_cwe(dossier, cwe_override, ai_mode, api_key, model)
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


def docker_environment(docker: str) -> dict[str, str]:
    environment = os.environ.copy()
    docker_bin = str(Path(docker).resolve().parent)
    environment["PATH"] = docker_bin + os.pathsep + environment.get("PATH", "")
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


def run_docker_stage(
    command: list[str],
    *,
    stage: str,
    docker: str,
    environment: dict[str, str],
    cwd: Path,
) -> None:
    result = subprocess.run(command, cwd=cwd, env=environment)
    if result.returncode == 0:
        return
    engine = subprocess.run([docker, "info"], capture_output=True, text=True, env=environment)
    if os.name == "nt" and engine.returncode != 0:
        ensure_docker(docker, environment)
        result = subprocess.run(command, cwd=cwd, env=environment)
        if result.returncode == 0:
            return
    raise RuntimeError(f"Docker stage '{stage}' failed with exit code {result.returncode}")


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


def run_lab(cve_value: str, output_root: Path, keep: bool) -> dict:
    cve = normalize_cve(cve_value)
    lab_dir = output_root.resolve() / cve
    plan_path = lab_dir / "plan.json"
    if not plan_path.exists():
        raise RuntimeError(f"Lab not generated: {lab_dir}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("runner", {}).get("type") == "wsl_shipyard":
        if os.name != "nt":
            raise RuntimeError("The curated Shipyard runner currently requires Windows with WSL")
        runner = plan["runner"]
        script = lab_dir / runner["script"]
        converted = subprocess.run(
            ["wsl", "-d", runner["distribution"], "--", "wslpath", "-a", str(script)],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        subprocess.run(
            ["wsl", "-d", runner["distribution"], "-u", "root", "--", "bash", converted],
            cwd=lab_dir, check=True,
        )
        validation = json.loads((lab_dir / "e2e" / "result.json").read_text(encoding="utf-8"))
        vulnerable_result = validation.get("vulnerable", {})
        patched_result = validation.get("patched", {})
        validated = (
            validation.get("attack_executed") is True
            and validation.get("proof_quality") == "end_to_end_security_effect_observed"
            and validation.get("differential_confirmed") is True
            and vulnerable_result.get("confirmed") is True
            and patched_result.get("confirmed") is False
        )
        report = {
            "cve": cve,
            "cwe": plan["cwe"],
            "lab_type": plan["lab_type"],
            "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "validation": validation,
            "proof_contract": plan.get("exploit_contract", {}),
            "real_poc_verified": validated,
            "ok": validated,
        }
        write_text(lab_dir / "report.json", json.dumps(report, indent=2, ensure_ascii=True) + "\n")
        return {"ok": validated, "lab_dir": str(lab_dir), "report": report}
    docker = docker_executable()
    environment = docker_environment(docker)
    ensure_docker(docker, environment)
    compose = [docker, "compose", "-f", str(lab_dir / "docker-compose.yml")]
    try:
        startup_services = plan.get("startup_services", ["vulnerable", "patched", "metadata"])
        if plan.get("lab_type") in {
            "SOURCE_REPRODUCTION", "VULNERABLE_ONLY_REPRODUCTION"
        }:
            required = [
                lab_dir / "docker-compose.yml",
                lab_dir / "vulnerable" / "Dockerfile",
                lab_dir / "validator" / "Dockerfile",
                lab_dir / "validator" / "validator.py",
                lab_dir / "source" / "vulnerable",
            ]
            if plan.get("lab_type") == "SOURCE_REPRODUCTION":
                required.extend([
                    lab_dir / "patched" / "Dockerfile",
                    lab_dir / "source" / "patched",
                ])
            missing = [str(path) for path in required if not path.exists()]
            if missing:
                raise RuntimeError("Generated lab preflight failed; missing: " + ", ".join(missing))
        configured = subprocess.run(
            compose + ["config", "--quiet"],
            cwd=lab_dir,
            capture_output=True,
            text=True,
            env=environment,
        )
        if configured.returncode != 0:
            detail = (configured.stderr or configured.stdout).strip()
            raise RuntimeError(f"Compose preflight failed: {detail}")
        run_docker_stage(
            compose + ["build", *startup_services, "validator"],
            stage="build",
            docker=docker,
            environment=environment,
            cwd=lab_dir,
        )
        run_docker_stage(
            compose + ["up", "-d", *startup_services],
            stage="startup",
            docker=docker,
            environment=environment,
            cwd=lab_dir,
        )
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
        real_source_proof = all(proof_checks.values())
        # Compose can surface a lifecycle exit code after `docker wait` even
        # when the validator completed and emitted a complete proof document.
        # Accept only the strict, independently checked proof contract; retain
        # the process exit code in the report for diagnostics.
        validated = real_source_proof and (
            validation.get("differential_confirmed") is False
            if vulnerable_only
            else validation.get("differential_confirmed") is True
        )
        report = {
            "cve": cve,
            "cwe": plan["cwe"],
            "lab_type": plan["lab_type"],
            "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "validation": validation,
            "proof_contract": proof_contract,
            "proof_checks": proof_checks,
            "validator_exit_code": validator_exit,
            "real_poc_verified": real_source_proof,
            "fix_status": plan.get("fix_status", "PUBLIC_FIX_AVAILABLE"),
            "patched_tested": not vulnerable_only,
            "differential_confirmed": validation.get("differential_confirmed") is True,
            "ok": validated,
        }
        write_text(lab_dir / "report.json", json.dumps(report, indent=2, ensure_ascii=True) + "\n")
        return {"ok": report["ok"], "lab_dir": str(lab_dir), "report": report}
    finally:
        if not keep:
            subprocess.run(
                compose + ["down", "--volumes", "--remove-orphans"],
                cwd=lab_dir,
                env=environment,
            )
