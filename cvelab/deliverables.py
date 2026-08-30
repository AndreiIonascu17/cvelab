from __future__ import annotations

import json
from pathlib import Path

from .ai import structured_response
from .core import write_text


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


def _evidence(value: object) -> str:
    text = json.dumps(value, ensure_ascii=True) if not isinstance(value, str) else value
    return text.replace("`", "'")[:1200]


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) or "- Nu exista date suficiente."


def _steps(items: list[str]) -> str:
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items, 1)) or "1. Date insuficiente."


def _automatic_analysis(
    dossier: dict,
    plan: dict,
    report: dict,
    api_key: str,
    model: str,
) -> dict:
    material = {"cve_dossier": dossier, "lab_plan": plan, "validation_report": report}
    return structured_response(
        api_key=api_key,
        model=model,
        schema=ANALYSIS_SCHEMA,
        schema_name="cvelab_final_analysis",
        max_output_tokens=6000,
        instructions=(
            "Write a technically precise Romanian defensive-research analysis for the supplied CVE and local lab. "
            "Use only facts present in the input. Clearly distinguish CVE metadata, model inference, and observed "
            "lab evidence. Never claim the vendor product was validated when lab_type is SYNTHETIC_CLASS_LAB. "
            "Explain the actual vulnerability mechanism and prerequisites, not merely the CWE definition. "
            "For attack_path, describe the executed local exploit path and its observed security effect, not remote "
            "targeting instructions. Do not add shells, persistence, credential access, destructive actions, or "
            "unverified versions, commits, patches, mitigations, or repositories. If a fix is not in the input, say "
            "that remediation status cannot be confirmed from the collected record."
        ),
        input_text=json.dumps(material, ensure_ascii=True),
    )


def create_deliverables(
    cve: str,
    lab_dir: Path,
    result: dict,
    api_key: str | None = None,
    model: str | None = None,
) -> dict:
    plan = json.loads((lab_dir / "plan.json").read_text(encoding="utf-8"))
    dossier = json.loads((lab_dir / "dossier.json").read_text(encoding="utf-8"))
    report = result.get("report", {})
    validation = report.get("validation", {})
    artifacts = lab_dir / "artifacts"
    real_poc_verified = (
        result.get("ok") is True
        and plan.get("lab_type")
        in {
            "SOURCE_REPRODUCTION", "END_TO_END_REPRODUCTION",
            "VULNERABLE_ONLY_REPRODUCTION",
        }
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
    if api_key and model:
        analysis = _automatic_analysis(dossier, plan, report, api_key, model)
        write_text(artifacts / "analysis.json", json.dumps(analysis, indent=2, ensure_ascii=True) + "\n")

    if plan.get("scenario") == "lighthouse_broker_namespace_injection_e2e":
        poc_path = artifacts / "PoC.yaml"
        write_text(poc_path, (lab_dir / "e2e" / "poc.yaml").read_text(encoding="utf-8"))
        write_text(
            artifacts / "manual.sh",
            (lab_dir / "e2e" / "manual.sh").read_text(encoding="utf-8"),
        )
        manual_wrapper = r'''param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("setup", "exploit", "verify", "cleanup")]
    [string]$Action,
    [ValidateSet("vulnerable", "patched")]
    [string]$Variant = "vulnerable"
)
$script = Join-Path $PSScriptRoot "manual.sh"
$wslScript = (& wsl -d kali-linux -u root -- wslpath -a $script).Trim()
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& wsl -d kali-linux -u root -- bash $wslScript $Action $Variant
exit $LASTEXITCODE
'''
        write_text(artifacts / "PoC.ps1", manual_wrapper)
        manual_guide = fr'''# {cve} Manual PoC

This kit reproduces the real authorization-bypass effect in a disposable local two-cluster lab.
The lab stays active between steps so every resource and command can be inspected.

## Vulnerable reproduction

```powershell
Set-ExecutionPolicy -Scope Process Bypass
Set-Location "{artifacts}"
Get-Content .\PoC.yaml
.\PoC.ps1 setup vulnerable
.\PoC.ps1 exploit
.\PoC.ps1 verify
```

Successful reproduction prints `REPRODUCED` and displays an `EndpointSlice` in
`cluster1/kube-system` containing the attacker-controlled TEST-NET address `198.51.100.77`.

## Cleanup

```powershell
.\PoC.ps1 cleanup
```

## Patched control

```powershell
.\PoC.ps1 setup patched
.\PoC.ps1 exploit
.\PoC.ps1 verify
.\PoC.ps1 cleanup
```

The patched control succeeds only when it prints `BLOCKED` and no attacker-controlled
`EndpointSlice` appears in `cluster1/kube-system`.

## Files

- `PoC.yaml`: inspectable attack payload.
- `PoC.ps1`: Windows entry point with separate setup, exploit, verify, and cleanup actions.
- `manual.sh`: WSL/Kali implementation used by the PowerShell entry point.
- `REPORT.md`: evidence captured by the automatic differential validation.
'''
        write_text(artifacts / "MANUAL-POC.md", manual_guide)
        poc_name = "PoC.yaml"
    elif plan.get("scenario") == "lighthouse_namespace_injection":
        poc_path = artifacts / "PoC.go"
        poc_source = (lab_dir / "adapter" / "vulnerable_poc_test.go").read_text(encoding="utf-8")
        write_text(poc_path, poc_source)
        poc_name = "PoC.go"
    else:
        validator = (lab_dir / "validator" / "validator.py").read_text(encoding="utf-8")
        poc_header = (
            f'"""Local-only verified exploit PoC for {cve}.\n\n'
            f'Lab type: {plan["lab_type"]}. Scenario: {plan.get("scenario", "default")}.\n'
            'This script is designed for the generated Docker lab, not remote targets.\n"""\n\n'
        )
        poc_path = artifacts / "PoC.py"
        write_text(poc_path, poc_header + validator)
        poc_name = "PoC.py"
    write_text(artifacts / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")

    source_note = (
        "This is a vendor-source reproduction using the revisions recorded below."
        if plan["lab_type"] in {
            "SOURCE_REPRODUCTION", "END_TO_END_REPRODUCTION",
            "VULNERABLE_ONLY_REPRODUCTION",
        }
        else "This is a synthetic CWE-class demonstration, not a vendor-source reproduction."
    )
    revisions = plan.get("revisions", {})
    vulnerable_only = plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION"
    if vulnerable_only:
        source_note = (
            "This is a vendor-source vulnerable-only reproduction. No public fixed revision "
            "was identified at generation time, so no patched behavior is claimed."
        )
    scenario = plan.get("scenario", "default")
    scenario_details = (
        "A crafted EndpointSlice from compromised cluster2 declares kube-system as its source namespace. "
        "The real vulnerable Lighthouse agent and broker propagate it into cluster1/kube-system; the fixed "
        "agent rejects the same object before local creation."
        if scenario == "lighthouse_broker_namespace_injection_e2e"
        else
        "The synthetic model submits an object from `tenant-a` with an attacker-selected "
        "destination of `kube-system`. The vulnerable variant creates it there; the patched "
        "model rejects cross-namespace injection."
        if scenario == "namespace_injection"
        else (
            "The validator executes the real vulnerable source path and records the declared "
            "security effect. No synthetic patched variant is created."
            if vulnerable_only
            else "The validator exercises the marker-only scenario recorded in plan.json."
        )
    )
    if analysis:
        scenario_details = analysis["mechanism"]
        prerequisites = _bullets(analysis["prerequisites"])
        attack_path = _steps(analysis["attack_path"])
        fidelity = analysis["fidelity"]
    else:
        if scenario == "lighthouse_broker_namespace_injection_e2e":
            prerequisites = "- Docker Desktop and Kali WSL.\n- A disposable two-cluster local lab created by the supplied PoC kit."
            attack_path = (
                "1. Deploy the recorded vulnerable upstream revision to two local kind clusters.\n"
                "2. Apply PoC.yaml in cluster2/cvelab-source and force a fresh update with a nonce.\n"
                "3. Observe address 198.51.100.77 in an EndpointSlice under cluster1/kube-system.\n"
                "4. Repeat on the fixed revision and require both object absence and the explicit agent rejection log."
            )
            fidelity = "This is an end-to-end reproduction using recorded upstream source revisions and the real agent/broker flow."
        else:
            prerequisites = "- Consult the CVE dossier and generated plan."
            if vulnerable_only:
                attack_path = (
                    "1. Build and start the recorded vulnerable upstream revision.\n"
                    "2. Execute the generated local-only attack with a unique canary.\n"
                    "3. Verify the concrete security effect using an independent observation.\n"
                    "4. Record that no patched control was tested because no public fix was identified."
                )
                fidelity = (
                    "This is a source-backed vulnerable-only reproduction. It proves the observed "
                    "effect for the recorded revision but makes no remediation claim."
                )
            else:
                attack_path = (
                    "1. The validator acts as a compromised, low-trust source namespace.\n"
                    "2. It supplies a protected destination namespace with a unique marker.\n"
                    "3. It checks whether the marker-backed object appears in that destination.\n"
                    "4. It repeats the request against the patched model and expects rejection."
                )
                fidelity = (
                    "This synthetic lab does not deploy the vendor product or its complete environment. "
                    "It validates only the modeled trust-boundary failure."
                )
    walkthrough = f"""# {cve} Walkthrough

## Scope

{source_note}

The lab is restricted to an internal Docker network and uses a non-destructive exploit canary.
The PoC has no remote-target option. The E2E runner executes the attack, writes
`e2e/result.json`, and the validator container can independently verify that evidence afterward.

## Reproduction

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
- `REPORT.md`: validation result and limitations.

## Revisions

- Repository: `{plan.get('repository', 'not applicable')}`
- Vulnerable: `{revisions.get('vulnerable', 'synthetic variant')}`
- Patched: `{revisions.get('patched') or 'not tested; no public fixed revision identified'}`

## Success condition

{('The run succeeds only when the declared security effect is independently observed on `vulnerable`. No patched behavior or differential confirmation is claimed.' if vulnerable_only else 'The run succeeds only when the declared security effect is observed on `vulnerable`, blocked on `patched`, and `differential_confirmed` is `true`.')}

## Fidelity boundary

{fidelity}
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
        if scenario == "lighthouse_broker_namespace_injection_e2e":
            interpretation = "The vulnerable upstream revision propagated the canary into kube-system; the fixed revision kept it absent and logged an explicit rejection."
            remediation = "The recorded fixed upstream revision enforces namespace validation for remote EndpointSlices."
            limitations = "- Validation is restricted to the isolated two-cluster local environment and recorded revisions."
            confidence = "High confidence for the executed local upstream revisions because both positive exploit evidence and explicit negative-control rejection were captured."
        else:
            if vulnerable_only:
                interpretation = "The declared effect was observed on the recorded vulnerable source revision; no patched control was available."
                remediation = "No public fixed revision was identified at generation time. Re-run differential validation when a fix becomes public."
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
- Vulnerable evidence: `{_evidence(vulnerable_result.get('evidence', 'none'))}`
- Patched confirmed: `{patched_result.get('confirmed', False)}`
- Patched evidence: `{_evidence(patched_result.get('evidence', 'none'))}`

{interpretation}

## Remediation status

{remediation}

## Provenance

- CVE source: `{dossier.get('source', 'unknown')}`
- Repository: `{plan.get('repository', 'not applicable')}`
- Vulnerable revision: `{revisions.get('vulnerable', 'synthetic variant')}`
- Patched revision: `{revisions.get('patched') or 'not available / not tested'}`

## Safety and limitations

{source_note}

- Target scope: `{plan.get('safety', {}).get('target_scope', 'local only')}`
- Payload: `{plan.get('safety', {}).get('payload', 'non-destructive exploit canary')}`
- Limitation: {plan.get('safety', {}).get('limitations', 'See plan.json.')}

{limitations}

## Confidence

{confidence}

## Interpretation

{('`REAL_VULNERABLE_ONLY_POC_VALIDATED` means the recorded vulnerable upstream revision executed the declared security-sensitive path inside the isolated lab. No public fix was identified and no patched behavior is claimed.' if vulnerable_only else '`REAL_POC_VALIDATED` means the recorded vulnerable upstream revision executed the declared security-sensitive path inside the isolated lab and the fixed revision blocked it.')}

This result does not authorize or establish exploitability of any remote deployment.
"""
    write_text(artifacts / "REPORT.md", markdown_report)
    write_text(artifacts / "report.json", json.dumps(report, indent=2, ensure_ascii=True) + "\n")

    result["deliverables"] = {
        "poc": str(poc_path),
        "walkthrough": str(artifacts / "WALKTHROUGH.md"),
        "report_markdown": str(artifacts / "REPORT.md"),
        "report_json": str(artifacts / "report.json"),
    }
    if plan.get("scenario") == "lighthouse_broker_namespace_injection_e2e":
        result["deliverables"].update({
            "manual_poc": str(artifacts / "PoC.ps1"),
            "manual_guide": str(artifacts / "MANUAL-POC.md"),
            "manual_runner": str(artifacts / "manual.sh"),
        })
    if analysis:
        result["deliverables"]["analysis"] = str(artifacts / "analysis.json")
    return result
