from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Callable

from .core import normalize_cve, run_lab, write_text
from .deliverables import create_deliverables
from .sourcegen import generate_source_lab, repair_source_lab


Progress = Callable[[str], None]


def _default_progress(message: str) -> None:
    print(f"[cvelab auto] {message}", file=sys.stderr, flush=True)


def _infrastructure_failure(message: str) -> bool:
    lowered = message.lower()
    indicators = (
        "docker engine recovery failed",
        "docker cli was not found",
        "permission denied while trying to connect",
        "cannot connect to the docker daemon",
        "is the docker daemon running",
        "no space left on device",
        "openai api http 401",
        "openai api http 403",
        "openai_api_key is not set",
        "anthropic_api_key is not set",
        "anthropic api http 400",
        "anthropic api http 404",
        "anthropic reached max_tokens",
        "anthropic refused structured generation",
        "anthropic response did not contain structured output",
        "could not connect to local api",
        "cvelab_model is not set",
    )
    return any(indicator in lowered for indicator in indicators)


def _record(
    lab_dir: Path,
    attempts: list[dict],
    status: str = "RUNNING",
    failure: dict | None = None,
) -> None:
    document = {
        "schema_version": 1,
        "status": status,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "attempts": attempts,
    }
    if failure is not None:
        document["failure"] = failure
    write_text(
        lab_dir / "automation.json",
        json.dumps(document, indent=2, ensure_ascii=True) + "\n",
    )


def run_auto_workflow(
    cve_value: str,
    output_root: Path,
    repo: str | None,
    fixed_ref: str | None,
    vulnerable_ref: str | None,
    api_key: str | None,
    model: str | None,
    keep: bool,
    max_attempts: int = 4,
    progress: Progress | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    """Generate, execute, diagnose, repair, and re-run a CVE lab autonomously."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    announce = progress or _default_progress
    cve = normalize_cve(cve_value)
    lab_dir = output_root.resolve() / cve
    attempts: list[dict] = []
    generation_feedback: list[str] = []
    _record(lab_dir, attempts)

    generated = None
    for generation_attempt in range(1, max_attempts + 1):
        announce(f"{cve}: generating source-backed lab ({generation_attempt}/{max_attempts})")
        try:
            generated = generate_source_lab(
                cve,
                output_root,
                repo,
                fixed_ref,
                vulnerable_ref,
                api_key,
                model,
                provider,
                base_url,
                generation_feedback,
            )
        except Exception as exc:
            generation_feedback.append(str(exc)[:6000])
            attempts.append({
                "phase": "generation",
                "attempt": generation_attempt,
                "ok": False,
                "error": str(exc)[:16000],
            })
            if lab_dir.exists():
                _record(lab_dir, attempts)
            if _infrastructure_failure(str(exc)) or generation_attempt == max_attempts:
                _record(
                    lab_dir,
                    attempts,
                    "AUTO_GENERATION_FAILED",
                    {"kind": "generation_error", "error": str(exc)[:24000]},
                )
                return {
                    "ok": False,
                    "status": "AUTO_GENERATION_FAILED",
                    "cve": cve,
                    "lab_dir": str(lab_dir),
                    "attempts": attempts,
                    "error": str(exc),
                }
            announce(f"{cve}: generation failed; retrying automatically")
            continue
        if not generated.get("ok"):
            _record(
                lab_dir,
                attempts,
                generated.get("status", "GENERATION_NOT_AVAILABLE"),
                {"kind": "generation_result", "result": generated},
            )
            generated["automation"] = {"attempts": attempts, "max_attempts": max_attempts}
            return generated
        attempts.append({
            "phase": "generation",
            "attempt": generation_attempt,
            "ok": True,
            "status": generated.get("status"),
        })
        _record(lab_dir, attempts)
        break

    if generated is None:
        raise RuntimeError("Automatic generation ended without a result")

    plan = generated.get("plan", {})
    curated_runner = bool(plan.get("runner"))
    pending_failure: dict | None = None
    repair_calls = 0
    validation_attempt = 0

    while validation_attempt < max_attempts:
        if pending_failure and not curated_runner and not _infrastructure_failure(
            json.dumps(pending_failure, ensure_ascii=True)
        ):
            if repair_calls >= max_attempts - 1:
                break
            repair_calls += 1
            announce(
                f"{cve}: repairing adapter from observed evidence "
                f"({repair_calls}/{max_attempts - 1})"
            )
            try:
                repaired = repair_source_lab(
                    cve,
                    output_root,
                    pending_failure,
                    repair_calls,
                    api_key,
                    model,
                    provider,
                    base_url,
                )
            except Exception as exc:
                attempts.append({
                    "phase": "repair",
                    "attempt": repair_calls,
                    "ok": False,
                    "error": str(exc)[:16000],
                })
                pending_failure = {
                    "kind": "repair_generation_error",
                    "previous_failure": pending_failure,
                    "repair_error": str(exc),
                }
                _record(lab_dir, attempts)
                if _infrastructure_failure(str(exc)):
                    break
                continue
            attempts.append({
                "phase": "repair",
                "attempt": repair_calls,
                "ok": True,
                "status": repaired.get("status"),
                "fidelity": repaired.get("plan", {}).get("fidelity"),
            })
            plan = repaired.get("plan", plan)
            pending_failure = None
            _record(lab_dir, attempts)

        validation_attempt += 1
        announce(f"{cve}: build and E2E validation ({validation_attempt}/{max_attempts})")
        try:
            validated = run_lab(cve, output_root, keep)
        except Exception as exc:
            pending_failure = {"kind": "runtime_error", "error": str(exc)}
            attempts.append({
                "phase": "validation",
                "attempt": validation_attempt,
                "ok": False,
                "error": str(exc)[:24000],
            })
        else:
            if validated.get("ok"):
                attempts.append({
                    "phase": "validation",
                    "attempt": validation_attempt,
                    "ok": True,
                    "proof_checks": validated.get("report", {}).get("proof_checks", {}),
                })
                automation = {
                    "mode": "autonomous_generate_repair_validate",
                    "validation_attempts": validation_attempt,
                    "repair_calls": repair_calls,
                    "max_attempts": max_attempts,
                    "attempts": attempts,
                }
                validated.setdefault("report", {})["automation"] = automation
                write_text(
                    lab_dir / "report.json",
                    json.dumps(validated["report"], indent=2, ensure_ascii=True) + "\n",
                )
                _record(lab_dir, attempts, "VALIDATED")
                announce(f"{cve}: exploit, patched control, and manual PoC verified")
                delivered = create_deliverables(
                    cve, lab_dir, validated, api_key, model, provider, base_url
                )
                delivered["automation"] = automation
                return delivered
            pending_failure = {
                "kind": "proof_not_verified",
                "report": validated.get("report", validated),
            }
            attempts.append({
                "phase": "validation",
                "attempt": validation_attempt,
                "ok": False,
                "proof_checks": validated.get("report", {}).get("proof_checks", {}),
                "validation": validated.get("report", {}).get("validation", {}),
            })
        _record(lab_dir, attempts)
        if validation_attempt < max_attempts:
            if pending_failure and _infrastructure_failure(
                json.dumps(pending_failure, ensure_ascii=True)
            ):
                announce(f"{cve}: transient/infrastructure failure; retrying without rewriting the PoC")
            elif curated_runner:
                announce(f"{cve}: curated runner failed; retrying the deterministic workflow")

    reason = pending_failure or {"kind": "repair_budget_exhausted"}
    _record(lab_dir, attempts, "AUTO_REPAIR_EXHAUSTED", reason)
    return {
        "ok": False,
        "status": "AUTO_REPAIR_EXHAUSTED",
        "cve": cve,
        "lab_dir": str(lab_dir),
        "validation_attempts": validation_attempt,
        "repair_calls": repair_calls,
        "max_attempts": max_attempts,
        "failure": reason,
        "attempts": attempts,
    }
