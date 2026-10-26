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
import os
import time
from collections.abc import Callable
from pathlib import Path

from . import progress, usage
from .core import CVERecordNotFound, normalize_cve, run_lab, write_text
from .deliverables import create_deliverables
from .sourcegen import generate_source_lab, repair_source_lab

Progress = Callable[[str], None]


def _default_progress(message: str) -> None:
    progress.step(message)


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


_STARTUP_MARKERS = (
    "dependency failed to start",
    "is unhealthy",
    "docker stage 'startup' failed",
    "lab service did not become healthy",
)


def _startup_failure(message: str) -> bool:
    """Whether a run ended because the lab's services never came up.

    The validator only runs once its targets are healthy, so these runs say
    nothing about the PoC. They are repaired on their own, without spending
    a validation attempt or one of the repairs meant for the exploit.
    """
    lowered = message.lower()
    return any(marker in lowered for marker in _STARTUP_MARKERS)


def startup_repair_limit() -> int:
    """Startup-only repairs allowed per run (CVELAB_STARTUP_REPAIRS, 0 to 5)."""
    raw = os.getenv("CVELAB_STARTUP_REPAIRS", "").strip()
    try:
        value = int(raw) if raw else 2
    except ValueError:
        value = 2
    return max(0, min(value, 5))


STARTUP_HINT = (
    "The lab's services did not become healthy, so the validator never ran and "
    "nothing is known yet about the exploit. Fix only what keeps the services from "
    "starting: the build output, the start command, the port, the healthcheck command "
    "and route, and anything the logs below show failing. Keep the regression input "
    "and the validator's evidence logic as they are unless they are the cause."
)


def effect_repair_limit() -> int:
    """Repairs added when the lab runs but the effect does not show (CVELAB_EFFECT_REPAIRS, 0 to 5)."""
    raw = os.getenv("CVELAB_EFFECT_REPAIRS", "").strip()
    try:
        value = int(raw) if raw else 2
    except ValueError:
        value = 2
    return max(0, min(value, 5))


EFFECT_HINT = (
    "The lab started and the validator reached both services, but the security effect did "
    "not show the way the contract requires; failed_proof_checks names what is missing. "
    "Read what each revision answered and the service logs, and settle two things in order: "
    "first whether the regression input reached the code the fix changes at all (route, "
    "configuration, parameters, the condition the fix tests), then whether the observation "
    "is the one this fix actually changes. Change the input or the observation, and keep the "
    "build and the services if they worked."
)


def _compact(value: object, limit: int = 600) -> object:
    """A validator result with every long string cut, so the digest stays small."""
    if isinstance(value, dict):
        return {key: _compact(item, limit) for key, item in list(value.items())[:20]}
    if isinstance(value, list):
        return [_compact(item, limit) for item in value[:10]]
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"... [{len(value) - limit} more characters]"
    return value


def _reached_targets(report: dict) -> bool:
    """Whether the validator sent its input to the services, as opposed to failing before."""
    validation = report.get("validation") or {}
    return isinstance(validation, dict) and validation.get("attack_executed") is True


def _validation_digest(report: dict) -> dict:
    """What a repair needs first from a validation that did not prove the effect."""
    validation = report.get("validation") or {}
    if not isinstance(validation, dict):
        validation = {}
    checks = report.get("proof_checks") or {}
    return {
        "failed_proof_checks": sorted(name for name, passed in checks.items() if passed is False),
        "attack_executed": validation.get("attack_executed"),
        "observable_effect": validation.get("observable_effect"),
        "vulnerable": _compact(validation.get("vulnerable")),
        "patched": _compact(validation.get("patched")),
        "service_logs": report.get("service_logs"),
    }


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
        # Written on every update, so an interrupted run still shows what it
        # spent before it stopped.
        "usage": usage.as_dict(),
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
    hint: str | None = None,
    research_mode: str | None = None,
) -> dict:
    """Generate, execute, diagnose, repair, and re-run a CVE lab autonomously."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    announce = progress or _default_progress
    usage.reset()
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
                hint=hint,
                research_mode=research_mode,
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
            if (
                isinstance(exc, CVERecordNotFound)
                or _infrastructure_failure(str(exc))
                or generation_attempt == max_attempts
            ):
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
    scripted_runner = bool(plan.get("runner"))
    pending_failure: dict | None = None
    repair_calls = 0
    startup_repairs = 0
    effect_repairs = 0
    validation_attempt = 0

    while validation_attempt < max_attempts + effect_repairs:
        if pending_failure and not scripted_runner and not _infrastructure_failure(
            json.dumps(pending_failure, ensure_ascii=True)
        ):
            if repair_calls >= max_attempts - 1 + effect_repairs:
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
                    research_mode=research_mode,
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
            if (
                _startup_failure(str(exc))
                and not _infrastructure_failure(str(exc))
                and not scripted_runner
                and startup_repairs < startup_repair_limit()
            ):
                # The validator never ran: this attempt is given back, and
                # the repair below does not count against the exploit's.
                validation_attempt -= 1
                startup_repairs += 1
                attempts.append({
                    "phase": "startup",
                    "attempt": startup_repairs,
                    "ok": False,
                    "error": str(exc)[:24000],
                })
                _record(lab_dir, attempts)
                announce(
                    f"{cve}: services did not start; repairing the startup "
                    f"({startup_repairs}/{startup_repair_limit()}) without spending a repair"
                )
                try:
                    repaired = repair_source_lab(
                        cve,
                        output_root,
                        {"hint": STARTUP_HINT, "kind": "startup_failure", "error": str(exc)},
                        repair_calls,
                        api_key,
                        model,
                        provider,
                        base_url,
                        research_mode=research_mode,
                    )
                except Exception as repair_error:
                    attempts.append({
                        "phase": "startup_repair",
                        "attempt": startup_repairs,
                        "ok": False,
                        "error": str(repair_error)[:16000],
                    })
                    _record(lab_dir, attempts)
                    if _infrastructure_failure(str(repair_error)):
                        break
                    # Fall back to the ordinary path: the next loop repairs
                    # from the startup failure and counts it.
                    validation_attempt += 1
                    pending_failure = {"kind": "runtime_error", "error": str(exc)}
                    continue
                attempts.append({
                    "phase": "startup_repair",
                    "attempt": startup_repairs,
                    "ok": True,
                    "status": repaired.get("status"),
                })
                plan = repaired.get("plan", plan)
                pending_failure = None
                _record(lab_dir, attempts)
                continue
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
                    "effect_repairs": effect_repairs,
                    "startup_repairs": startup_repairs,
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
            report = validated.get("report", validated)
            reached = _reached_targets(report)
            # The digest comes first so a long report cannot push it past
            # what the repair prompt keeps.
            pending_failure = {
                **({"hint": EFFECT_HINT} if reached else {}),
                "kind": "proof_not_verified",
                "digest": _validation_digest(report),
                "report": report,
            }
            if (
                reached
                and not scripted_runner
                and validation_attempt >= max_attempts + effect_repairs
                and effect_repairs < effect_repair_limit()
            ):
                # The closest case to a reproduction: the lab builds, starts
                # and is probed, and only the effect is missing.
                effect_repairs += 1
                announce(
                    f"{cve}: the lab runs but the effect did not show; one more repair "
                    f"({effect_repairs}/{effect_repair_limit()})"
                )
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
            elif scripted_runner:
                announce(f"{cve}: scripted runner failed; retrying the deterministic workflow")

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
        "effect_repairs": effect_repairs,
        "startup_repairs": startup_repairs,
        "failure": reason,
        "attempts": attempts,
    }
