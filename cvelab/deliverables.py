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
from pathlib import Path

from .ai import ai_is_configured, structured_response
from .core import write_text
from .field import MANUAL_POC_NAME

ANALYSIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "executive_summary", "mechanism", "prerequisites", "attack_path", "impact",
        "affected_components", "evidence_interpretation", "fidelity", "limitations",
        "remediation_status", "confidence_statement",
    ],
    "properties": {
        "executive_summary": {"type": "string"},
        "mechanism": {"type": "string"},
        "prerequisites": {"type": "array", "items": {"type": "string"}},
        "attack_path": {"type": "array", "items": {"type": "string"}},
        "impact": {"type": "array", "items": {"type": "string"}},
        "affected_components": {"type": "array", "items": {"type": "string"}},
        "evidence_interpretation": {"type": "string"},
        "fidelity": {"type": "string"},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "remediation_status": {"type": "string"},
        "confidence_statement": {"type": "string"},
    },
}


def _evidence(value: object, limit: int = 6000) -> str:
    text = json.dumps(value, ensure_ascii=True) if not isinstance(value, str) else value
    return text.replace("`", "'")[:limit]


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) or "- Nu exista date suficiente."


def _steps(items: list[str]) -> str:
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items, 1)) or "1. Date insuficiente."


def _variant_evidence(value: object) -> object:
    if not isinstance(value, dict):
        return value
    if "evidence" in value:
        return value["evidence"]
    if "raw_observations" in value:
        return value["raw_observations"]
    return value


def _fidelity(plan: dict) -> dict:
    fidelity = plan.get("fidelity")
    if isinstance(fidelity, dict):
        return fidelity
    if plan.get("lab_type") == "END_TO_END_REPRODUCTION":
        return {
            "execution_level": "product_end_to_end",
            "vendor_product_started": True,
            "exercised_vendor_components": ["vendor product"],
            "simulated_components": [],
            "rationale": "Legacy curated end-to-end profile.",
        }
    return {
        "execution_level": "source_component",
        "vendor_product_started": False,
        "exercised_vendor_components": [],
        "simulated_components": ["unspecified adapter components"],
        "rationale": "Legacy generated lab without explicit fidelity metadata.",
    }


#: The lab types that built the vendor's own source, as against a synthetic
#: class model. Two sentences are decided on this -- whether a PoC is emitted
#: at all, and whether the documents call the lab a vendor-source
#: reproduction -- and they were two copies of the same three names. A type
#: added to one and not the other would ship a source lab that described
#: itself as synthetic, or refuse a PoC for a lab the documents then described.
_SOURCE_BACKED = frozenset({
    "SOURCE_REPRODUCTION", "END_TO_END_REPRODUCTION",
    "VULNERABLE_ONLY_REPRODUCTION",
})

#: What the Manual PoC line of REPORT.md says, per report.manual_poc_status.
#: "verified" and "failed" render as the boolean they replaced, so a real
#: verdict reads exactly as it did before the third state existed.
_MANUAL_POC_VERDICTS = {
    "verified": "True",
    "failed": "False",
    "not_run": "not run; the handed-over actions were not executed",
}


def _manual_poc_verdict(report: dict) -> str:
    """The Manual PoC verdict, for each shape a report can carry.

    run_lab runs the handed-over actions only behind `if automatic_proof`, so
    "never ran" is a third state rather than a failure. core.run_lab no longer
    folds that empty result into proof_checks["manual_poc_verified"]: it leaves
    the key out and records the three states in manual_poc_status beside the
    checks. Reading the old key alone therefore fell through to the default
    below and credited a separate curated runner to a lab that never had one --
    the actions simply were not reached.

    The default stays, because one lab shape is exactly that. A plan.json
    `runner` lab is driven by core.run_shipyard_script and reported by
    core.shipyard_report, whose report carries no manual-PoC key at all, and
    its own script is that separate curated runner. A report.json written
    before manual_poc_status existed still has the boolean, so it is read
    before falling through.
    """
    status = str(report.get("manual_poc_status") or "")
    if status in _MANUAL_POC_VERDICTS:
        return _MANUAL_POC_VERDICTS[status]
    verified = report.get("proof_checks", {}).get("manual_poc_verified")
    return "separate curated runner" if verified is None else str(verified)


def _write_generic_manual_assets(
    cve: str,
    lab_dir: Path,
    artifacts: Path,
    vulnerable_only: bool,
) -> None:
    allowed_variants = '"vulnerable"' if vulnerable_only else '"vulnerable"|"patched"'
    patched_note = (
        "No patched target is available for this CVE."
        if vulnerable_only
        else "Repeat the same steps with `patched`; successful verification prints `BLOCKED`."
    )
    manual_runner = f'''#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$LAB_ROOT/artifacts/.manual-state"
COMPOSE=(docker compose -f "$LAB_ROOT/docker-compose.yml" --project-directory "$LAB_ROOT")

usage() {{
  echo "Usage: bash manual.sh <setup|exploit|verify|cleanup> [vulnerable{'|patched' if not vulnerable_only else ''}]" >&2
  exit 2
}}

target() {{
  local requested="${{1:-}}"
  if [[ -z "$requested" && -s "$STATE" ]]; then requested="$(<"$STATE")"; fi
  case "$requested" in
    {allowed_variants}) printf '%s' "$requested" ;;
    *) echo "Choose a valid target and run setup first." >&2; exit 2 ;;
  esac
}}

action="${{1:-}}"
if [[ "$action" == "cleanup" ]]; then
  "${{COMPOSE[@]}}" down --volumes --remove-orphans
  rm -f "$STATE"
  exit 0
fi
variant="$(target "${{2:-}}")"
case "$action" in
  setup)
    [[ ! -e "$STATE" ]] || {{ echo "A manual lab is already active; run cleanup first." >&2; exit 2; }}
    "${{COMPOSE[@]}}" build "$variant" validator
    "${{COMPOSE[@]}}" up -d --build "$variant"
    printf '%s' "$variant" > "$STATE"
    echo "Manual lab ready: $variant"
    ;;
  exploit|verify)
    [[ -s "$STATE" ]] || {{ echo "Run setup first." >&2; exit 2; }}
    [[ "$(<"$STATE")" == "$variant" ]] || {{ echo "Target differs from the active manual lab." >&2; exit 2; }}
    "${{COMPOSE[@]}}" --profile tools run --rm --no-deps \
      -e "CVELAB_MANUAL_ACTION=$action" -e "CVELAB_TARGET=$variant" validator
    ;;
  *) usage ;;
esac
'''
    write_text(artifacts / "manual.sh", manual_runner)
    manual_wrapper = r'''param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("setup", "exploit", "verify", "cleanup")]
    [string]$Action,
    [ValidateSet("vulnerable", "patched")]
    [string]$Variant = "vulnerable"
)
$script = Join-Path $PSScriptRoot "manual.sh"
$wslScript = (& wsl -- wslpath -a $script).Trim()
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& wsl -- bash $wslScript $Action $Variant
exit $LASTEXITCODE
'''
    write_text(artifacts / "PoC.ps1", manual_wrapper)
    patched_section = "" if vulnerable_only else '''## Patched control

```bash
bash manual.sh setup patched
bash manual.sh exploit patched
bash manual.sh verify patched
bash manual.sh cleanup
```

Successful verification of the fixed revision prints `BLOCKED`.

'''
    manual_guide = f'''# {cve} Manual PoC

The manual runner uses the same isolated images and exact request as automatic validation,
but leaves setup, exploitation, evidence verification, and cleanup as separate inspectable steps.

## Kali/Linux

Run these from the lab's `artifacts/` directory, the one this file is in:

```bash
cd {cve}/artifacts
sed -n '1,260p' PoC.py
bash manual.sh setup vulnerable
bash manual.sh exploit vulnerable
bash manual.sh verify vulnerable
bash manual.sh cleanup
```

A confirmed vulnerable reproduction prints `REPRODUCED`. {patched_note}

{patched_section}## What each step does

- `setup` builds the selected source revision and starts only that target.
- `exploit` sends the exact local attack and prints the raw observation without deciding the result.
- `verify` repeats the controls and evaluates the declared security effect.
- `cleanup` removes this Compose project's containers, network, and volumes.

Targets are Docker service names only; this PoC has no arbitrary or remote target option.
'''
    write_text(artifacts / "MANUAL-POC.md", manual_guide)


def _automatic_analysis(
    dossier: dict,
    plan: dict,
    report: dict,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    material = {"cve_dossier": dossier, "lab_plan": plan, "validation_report": report}
    return structured_response(
        api_key=api_key,
        model=model,
        schema=ANALYSIS_SCHEMA,
        schema_name="cvelab_final_analysis",
        max_output_tokens=6000,
        instructions=(
            "Write a technically precise English defensive-research analysis for the supplied CVE and local lab. "
            "Use only facts present in the input. Clearly distinguish CVE metadata, model inference, and observed "
            "lab evidence. Never claim the vendor product was validated when lab_type is SYNTHETIC_CLASS_LAB. "
            "Treat lab_plan.fidelity as authoritative: never describe source_component as product end-to-end, and "
            "name simulated components when explaining limitations. "
            "Explain the actual vulnerability mechanism and prerequisites, not merely the CWE definition. "
            "For the legacy attack_path field, describe only the regression input already executed inside the generated "
            "Docker network and its observed security effect. Do not introduce capabilities, targets, procedures, or "
            "claims beyond the contained test evidence. Do not add unverified versions, commits, patches, mitigations, "
            "or repositories. If a fix is not in the input, say "
            "that remediation status cannot be confirmed from the collected record. "
            # This analysis overrides remediation_status and
            # evidence_interpretation, which are two of the four places a
            # demoted lab used to deny its own fixing reference, so the
            # distinction has to reach the model as well as the templates.
            "A lab_plan.demotion means something different from an absent fix: a fixed "
            "revision was resolved and then discarded because the pair could not show a fix. "
            "Where it is present, say that and give its recorded reason, and do not say that "
            "no fix was identified or that one should be waited for."
        ),
        input_text=json.dumps(material, ensure_ascii=True),
        provider=provider,
        base_url=base_url,
    )


def create_deliverables(
    cve: str,
    lab_dir: Path,
    result: dict,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    plan = json.loads((lab_dir / "plan.json").read_text(encoding="utf-8"))
    dossier = json.loads((lab_dir / "dossier.json").read_text(encoding="utf-8"))
    report = result.get("report", {})
    validation = report.get("validation", {})
    automation = report.get("automation", {})
    artifacts = lab_dir / "artifacts"
    fidelity_record = _fidelity(plan)
    real_poc_verified = (
        result.get("ok") is True
        and plan.get("lab_type") in _SOURCE_BACKED
        and report.get("real_poc_verified") is True
        and validation.get("attack_executed") is True
        and validation.get("proof_quality") in {
            "security_effect_observed",
            "end_to_end_security_effect_observed",
        }
    )
    if not real_poc_verified:
        return {
            "ok": False,
            "status": "POC_NOT_VERIFIED",
            "cve": cve,
            "lab_dir": str(lab_dir),
            "reason": (
                "The real vulnerable source path did not produce a verified security effect. "
                "No PoC, walkthrough, or success report was emitted."
            ),
            "validation": validation,
        }
    analysis = None
    analysis_error = None
    if model and ai_is_configured(api_key, model, provider):
        try:
            analysis = _automatic_analysis(
                dossier, plan, report, api_key, model, provider, base_url
            )
        except Exception as exc:
            # The evidence-backed deterministic report is still complete. A
            # prose-analysis API failure must not discard a validated PoC.
            analysis_error = str(exc)
        else:
            write_text(artifacts / "analysis.json", json.dumps(analysis, indent=2, ensure_ascii=True) + "\n")
    elif (artifacts / "analysis.json").is_file():
        analysis = json.loads((artifacts / "analysis.json").read_text(encoding="utf-8"))

    validator = (lab_dir / "validator" / "validator.py").read_text(encoding="utf-8")
    poc_header = (
        f'"""Local-only verified exploit PoC for {cve}.\n\n'
        f'Lab type: {plan["lab_type"]}. Scenario: {plan.get("scenario", "default")}.\n'
        'This script is designed for the generated Docker lab, not remote targets.\n"""\n\n'
    )
    poc_path = artifacts / "PoC.py"
    write_text(poc_path, poc_header + validator)
    poc_name = "PoC.py"
    # Read once rather than per sentence. It was asked of the plan here and
    # then again below, which is one expression to keep in step with itself
    # for no gain: the manual assets and the prose have to agree about which
    # lab this is or the kit describes a patched side the documents deny.
    vulnerable_only = plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION"
    _write_generic_manual_assets(cve, lab_dir, artifacts, vulnerable_only)
    write_text(artifacts / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")

    source_note = (
        "This is a vendor-source reproduction using the revisions recorded below. "
        "Its fidelity level is recorded separately and must not be inferred from source use alone."
        if plan["lab_type"] in _SOURCE_BACKED
        else "This is a synthetic CWE-class demonstration, not a vendor-source reproduction."
    )
    revisions = plan.get("revisions", {})
    # Two different labs wear the same lab_type, and every sentence below that
    # says why there is no patched side has to tell them apart. A demoted lab
    # did identify a fixed revision -- sourcegen resolved it, read its diff,
    # found the pair could not show a fix and discarded it -- so the stock
    # "no public fixed revision was identified" is false for it, and its
    # remedy is wrong too: there is nothing to wait for, the reference needs
    # resolving again. plan.json carries the reason; these read it.
    demotion = plan.get("demotion") or {}
    demoted = vulnerable_only and bool(demotion)
    demotion_reason = demotion.get("reason") or "the pair could not show the fix"
    rejected_fixed = demotion.get("rejected_fixed")
    # The revision as every sentence names it. A demotion that recorded no
    # revision still has to be nameable, because the point of the sentence is
    # that one was identified.
    named_fix = rejected_fixed or "unrecorded"
    # The clause that says what happened to it, in one place.
    #
    # The reason ends with the remedy, so it goes last in whatever sentence
    # carries it, introduced by a colon. Three sentences carry it -- the scope
    # note of both documents, the report's interpretation of its own status,
    # and its remediation status -- and all three held a verbatim copy of it
    # under a comment saying there was one place to change the wording. There
    # was not: a reworded copy would have had the same lab answer the question
    # two ways in one deliverable.
    discarded_fix = (
        f"A fixed revision (`{named_fix}`) was identified and then discarded: "
        f"{demotion_reason}."
    )
    # What stands in the Patched row of both documents. revisions.patched is
    # null for a demoted lab too, so the row fell through to "no public fixed
    # revision identified" -- which denies the very reference the row exists
    # to show.
    discarded_revision = (
        f"{named_fix} (identified, then discarded as unusable)" if demoted else None
    )
    if demoted:
        source_note = (
            "This is a vendor-source vulnerable-only reproduction, so no patched behavior "
            f"is claimed. {discarded_fix}"
        )
    elif vulnerable_only:
        source_note = (
            "This is a vendor-source vulnerable-only reproduction. No public fixed revision "
            "was identified at generation time, so no patched behavior is claimed."
        )
    scenario = plan.get("scenario", "default")
    contract = plan.get("exploit_contract", {})
    scenario_details = (
        "The synthetic model submits an object from `tenant-a` with an attacker-selected "
        "destination of `kube-system`. The vulnerable variant creates it there; the patched "
        "model rejects cross-namespace injection."
        if scenario == "namespace_injection"
        else (
            "The validator executes the real vulnerable source path and records the declared "
            "security effect. No synthetic patched variant is created."
            if vulnerable_only
            else contract.get(
                "attack_summary",
                "The validator executes the source-backed scenario recorded in plan.json.",
            )
        )
    )
    if analysis:
        scenario_details = analysis["mechanism"]
        prerequisites = _bullets(analysis["prerequisites"])
        attack_path = _steps(analysis["attack_path"])
        analyst_fidelity = analysis["fidelity"]
    else:
        prerequisites = "- Consult the CVE dossier and generated plan."
        if vulnerable_only:
            # Step 4 is an instruction to the operator, so a false version of
            # it does not merely misreport: it has the operator write down
            # that no fix was identified for a lab where one was.
            attack_path = (
                "1. Build and start the recorded vulnerable upstream revision.\n"
                "2. Execute the generated local-only attack with a unique canary.\n"
                "3. Verify the concrete security effect using an independent observation.\n"
                + (
                    "4. Record that no patched control was tested because the fixed revision "
                    f"that was identified could not serve as one: {demotion_reason}."
                    if demoted
                    else "4. Record that no patched control was tested because no public fix "
                    "was identified."
                )
            )
            analyst_fidelity = (
                "This is a source-backed vulnerable-only reproduction. It proves the observed "
                "effect for the recorded revision but makes no remediation claim."
            )
        else:
            prerequisites = _bullets(contract.get("preconditions", []))
            attack_path = (
                "1. Build and start both recorded source revisions.\n"
                "2. Execute the exact local attack declared in plan.json against the vulnerable target.\n"
                "3. Capture the raw response and independently check the declared security effect.\n"
                "4. Repeat the identical attack against the patched target and require it to be blocked."
            )
            analyst_fidelity = fidelity_record.get("rationale", "See plan.json.")
    fidelity = (
        f"Execution level: `{fidelity_record.get('execution_level', 'unknown')}`. "
        f"Vendor product started: `{fidelity_record.get('vendor_product_started', False)}`. "
        f"{fidelity_record.get('rationale', analyst_fidelity)}"
    )
    # Where the lab stops being the vendor's own code, as both documents say
    # it. One pair of bullets rather than two identical ones: this is the
    # boundary a reader is entitled to rely on, and a walkthrough naming
    # different components from the report beside it would make the claim
    # unreadable rather than merely untidy.
    boundary = (
        f"- Exercised vendor components: `{_evidence(fidelity_record.get('exercised_vendor_components', []))}`\n"
        f"- Simulated components: `{_evidence(fidelity_record.get('simulated_components', []))}`"
    )
    walkthrough = f"""# {cve} Walkthrough

## Scope

{source_note}

The lab is restricted to a disposable local environment and uses a non-destructive exploit canary.
The PoC has no arbitrary remote-target option. Automatic evidence is stored in
`report.json` and `artifacts/EVIDENCE.json`.

## Reproduction on Linux

```bash
cvelab run {cve}
```

For an inspectable, step-by-step reproduction that keeps the lab running, follow
`MANUAL-POC.md` and use `manual.sh`.

## Reproduction on Windows/WSL

```powershell
& \"$env:LOCALAPPDATA\\Programs\\Python\\Python313\\Scripts\\cvelab.exe\" run {cve}
```

For an inspectable, step-by-step reproduction that keeps the lab running, follow
`MANUAL-POC.md` and use `PoC.ps1`.

## Modeled attack path

{scenario_details}

## Preconditions

{prerequisites}

## Validation steps

{attack_path}

## Components

- `../docker-compose.yml`: isolated vulnerable{'' if vulnerable_only else ', patched'}, and validator services.
- `../validator/validator.py`: executable real-effect validator.
- `{poc_name}`: source-backed local PoC executed against the vulnerable revision.
- `manual.sh`: Linux runner with separate setup, exploit, verify, and cleanup actions.
- `MANUAL-POC.md`: inspectable manual reproduction instructions.
- `EVIDENCE.json`: normalized evidence, proof checks, provenance, and fidelity metadata.
- `REPORT.md`: validation result and limitations.

## Revisions

- Repository: `{plan.get('repository', 'not applicable')}`
- Vulnerable: `{revisions.get('vulnerable', 'synthetic variant')}`
- Patched: `{discarded_revision or revisions.get('patched') or 'not tested; no public fixed revision identified'}`

## Success condition

{('The run succeeds only when the declared security effect is independently observed on `vulnerable`. No patched behavior or differential confirmation is claimed.' if vulnerable_only else 'The run succeeds only when the declared security effect is observed on `vulnerable`, blocked on `patched`, and `differential_confirmed` is `true`.')}

## Fidelity boundary

{fidelity}

{boundary}
"""
    write_text(artifacts / "WALKTHROUGH.md", walkthrough)

    descriptions = dossier.get("descriptions", [])
    description = descriptions[0] if descriptions else "No public description available."
    vulnerable_result = validation.get("vulnerable", {})
    patched_result = validation.get("patched", {})
    if result.get("ok") and vulnerable_only:
        status = "REAL_VULNERABLE_ONLY_POC_VALIDATED"
    elif result.get("ok") and plan["lab_type"] == "END_TO_END_REPRODUCTION":
        status = "REAL_END_TO_END_POC_VALIDATED"
    elif result.get("ok"):
        status = "REAL_SOURCE_POC_VALIDATED"
    else:
        status = "NOT_VALIDATED"
    # What the status means, and the fourth place a demoted lab used to assert
    # that no fix was found.
    if demoted:
        status_meaning = (
            "`REAL_VULNERABLE_ONLY_POC_VALIDATED` means the recorded vulnerable upstream "
            "revision executed the declared security-sensitive path inside the isolated lab. "
            f"No patched behavior is claimed. {discarded_fix}"
        )
    elif vulnerable_only:
        status_meaning = (
            "`REAL_VULNERABLE_ONLY_POC_VALIDATED` means the recorded vulnerable upstream "
            "revision executed the declared security-sensitive path inside the isolated lab. "
            "No public fix was identified and no patched behavior is claimed."
        )
    else:
        status_meaning = (
            "`REAL_POC_VALIDATED` means the recorded vulnerable upstream revision executed the "
            "declared security-sensitive path inside the isolated lab and the fixed revision "
            "blocked it."
        )
    if analysis:
        summary = analysis["executive_summary"]
        mechanism = analysis["mechanism"]
        impacts = _bullets(analysis["impact"])
        components = _bullets(analysis["affected_components"])
        interpretation = analysis["evidence_interpretation"]
        remediation = analysis["remediation_status"]
        limitations = _bullets(analysis["limitations"])
        confidence = analysis["confidence_statement"]
    else:
        summary = description
        mechanism = scenario_details
        impacts = "- Consult the public CVE description."
        components = "- Consult dossier.json."
        if vulnerable_only:
            interpretation = "The declared effect was observed on the recorded vulnerable source revision; no patched control was available."
            # The remedy differs as much as the fact does. Waiting for a fix
            # to become public is useless advice for a lab whose fix is
            # already public and was already read: what is needed is the
            # fixing reference resolved to the commit that carries the fix.
            remediation = (
                "Re-run differential validation once the fixing reference resolves to the "
                "commit that carries the fix; there is nothing to wait for. "
                f"{discarded_fix}"
                if demoted
                else "No public fixed revision was identified at generation time. Re-run "
                "differential validation when a fix becomes public."
            )
            limitations = "- Patched behavior and remediation effectiveness were not tested."
            confidence = "Confidence applies to the observed vulnerable revision only; there is no differential confirmation."
        else:
            interpretation = "The differential result applies only to the generated lab."
            remediation = "Not established by the generated lab."
            limitations = "- Vendor-product behavior was not exercised."
            confidence = "Confidence is limited to the observed local class model."
    markdown_report = f"""# {cve} Validation Report

## Result

- Status: **{status}**
- Fix status: `{plan.get('fix_status', 'PUBLIC_FIX_AVAILABLE')}`
- Patched tested: `{not vulnerable_only}`
- Differential confirmed: `{validation.get('differential_confirmed', False)}`
- Attack executed: `{validation.get('attack_executed', False)}`
- Proof quality: `{validation.get('proof_quality', 'not observed')}`
- Observable effect: `{_evidence(validation.get('observable_effect', 'none'))}`
- Lab type: `{plan['lab_type']}`
- Fidelity level: `{fidelity_record.get('execution_level', 'unknown')}`
- Vendor product started: `{fidelity_record.get('vendor_product_started', False)}`
- Product E2E verified: `{report.get('product_e2e_verified', False)}`
- Manual PoC verified: `{_manual_poc_verdict(report)}`
- Autonomous validation attempts: `{automation.get('validation_attempts', 1)}`
- Autonomous adapter repairs: `{automation.get('repair_calls', 0)}`
- CWE: `{plan.get('cwe', 'unknown')}`
- Scenario: `{scenario}`
- Validated at: `{report.get('validated_at', 'not completed')}`

## CVE summary

{summary}

## Vulnerability mechanism

{mechanism}

## Preconditions

{prerequisites}

## Affected components

{components}

## Potential impact

{impacts}

## Evidence

- Vulnerable confirmed: `{vulnerable_result.get('confirmed', False)}`
- Patched confirmed: `{patched_result.get('confirmed', False)}`

### Vulnerable raw evidence

```json
{json.dumps(_variant_evidence(vulnerable_result), indent=2, ensure_ascii=True)[:12000]}
```

### Patched raw evidence

```json
{json.dumps(_variant_evidence(patched_result), indent=2, ensure_ascii=True)[:12000]}
```

{interpretation}

## Fidelity

- Execution level: `{fidelity_record.get('execution_level', 'unknown')}`
- Vendor product started: `{fidelity_record.get('vendor_product_started', False)}`
{boundary}
- Boundary: {fidelity_record.get('rationale', 'Not recorded.')}

## Remediation status

{remediation}

## Provenance

- CVE source: `{dossier.get('source', 'unknown')}`
- Repository: `{plan.get('repository', 'not applicable')}`
- Vulnerable revision: `{revisions.get('vulnerable', 'synthetic variant')}`
- Patched revision: `{discarded_revision or revisions.get('patched') or 'not available / not tested'}`

## Safety and limitations

{source_note}

- Target scope: `{plan.get('safety', {}).get('target_scope', 'local only')}`
- Payload: `{plan.get('safety', {}).get('payload', 'non-destructive exploit canary')}`
- Limitation: {plan.get('safety', {}).get('limitations', 'See plan.json.')}

{limitations}

## Confidence

{confidence}

## Interpretation

{status_meaning}

This result does not authorize or establish exploitability of any remote deployment.
"""
    write_text(artifacts / "REPORT.md", markdown_report)
    write_text(artifacts / "report.json", json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    evidence_document = {
        "schema_version": 1,
        "cve": cve,
        "status": status,
        "lab_type": plan.get("lab_type"),
        "fidelity": fidelity_record,
        "validated_at": report.get("validated_at"),
        "validation": validation,
        "proof_contract": report.get("proof_contract", plan.get("exploit_contract", {})),
        "proof_checks": report.get("proof_checks", {}),
        "manual_poc_checks": report.get("manual_poc_checks", {}),
        # Beside the checks, because the dict alone cannot say which of two
        # things happened: an action that failed leaves its entry above, but a
        # run that never reached the actions leaves {} -- the same {} a
        # curated-runner lab has, which records no manual actions at all.
        # EVIDENCE.json is the copy sharing keeps: it is in upload.ALWAYS and
        # in REQUIRED_TO_SHARE and absent from upload.EXPLOIT, so --no-poc
        # does not strip it. Null is the third case, a report with no manual
        # record of its own.
        "manual_poc_status": report.get("manual_poc_status"),
        "automation": automation,
        "provenance": {
            "cve_source": dossier.get("source", "unknown"),
            "repository": plan.get("repository"),
            "vulnerable_revision": revisions.get("vulnerable"),
            "patched_revision": revisions.get("patched"),
            # Beside the null patched revision, because the two say different
            # things and the null alone reads as a CVE with no public fix.
            # This document is the only place the demotion survives being
            # shared: plan.json is in upload.EXPLOIT, so --no-poc strips it,
            # and upload.collect sends fixed_ref from revisions.patched,
            # which is correctly null here -- no fixed revision was built or
            # tested. EVIDENCE.json is in upload.ALWAYS and in
            # REQUIRED_TO_SHARE, so it goes either way.
            "discarded_fixed_revision": rejected_fixed,
            "demotion_reason": demotion.get("reason"),
        },
    }
    write_text(
        artifacts / "EVIDENCE.json",
        json.dumps(evidence_document, indent=2, ensure_ascii=True) + "\n",
    )

    result["deliverables"] = {
        "poc": str(poc_path),
        "walkthrough": str(artifacts / "WALKTHROUGH.md"),
        "report_markdown": str(artifacts / "REPORT.md"),
        "report_json": str(artifacts / "report.json"),
        "evidence": str(artifacts / "EVIDENCE.json"),
    }
    optional_deliverables = {
        "manual_poc": artifacts / "PoC.ps1",
        "manual_guide": artifacts / "MANUAL-POC.md",
        "manual_runner": artifacts / "manual.sh",
        # Written by run_lab, and only when it showed the effect on the
        # vulnerable build and stayed silent on the fixed one, so its
        # presence is the claim. Most labs will not have one.
        "target_poc": artifacts / MANUAL_POC_NAME,
    }
    result["deliverables"].update({
        name: str(path) for name, path in optional_deliverables.items() if path.is_file()
    })
    if analysis:
        result["deliverables"]["analysis"] = str(artifacts / "analysis.json")
    if analysis_error:
        result["analysis_warning"] = analysis_error
    return result
