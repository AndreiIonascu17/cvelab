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
import subprocess
from pathlib import Path
from typing import Any

from . import progress, research
from .ai import structured_response
from .closed import run_closed_lab
from .core import collect_cve, normalize_cve
from .sourcegen import fix_patch, resolve_source

_REQUEST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["method", "path", "headers", "body"],
    "properties": {
        "method": {"type": "string"},
        "path": {"type": "string"},
        "headers": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "value"],
                "properties": {
                    "name": {"type": "string"},
                    "value": {"type": "string"},
                },
            },
        },
        "body": {"type": ["string", "null"]},
    },
}

_MATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["status", "body_contains", "body_regex"],
    "properties": {
        "status": {"type": "array", "items": {"type": "integer"}},
        "body_contains": {"type": ["string", "null"]},
        "body_regex": {"type": ["string", "null"]},
    },
}

_PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "status", "reason", "vulnerable_image", "fixed_image", "container_port",
        "health_path", "attack", "observe_request", "observe_match", "sources",
    ],
    "properties": {
        "status": {"type": "string", "enum": ["READY", "ARTIFACT_REQUIRED", "UNSUPPORTED"]},
        "reason": {"type": "string"},
        "vulnerable_image": {"type": ["string", "null"]},
        "fixed_image": {"type": ["string", "null"]},
        "container_port": {"type": ["integer", "null"]},
        "health_path": {"type": ["string", "null"]},
        "attack": {"type": "array", "items": _REQUEST_SCHEMA},
        "observe_request": {"anyOf": [_REQUEST_SCHEMA, {"type": "null"}]},
        "observe_match": {"anyOf": [_MATCH_SCHEMA, {"type": "null"}]},
        "sources": {"type": "array", "items": {"type": "string"}},
    },
}


def _catalog_paths() -> list[Path]:
    configured = os.getenv("CVELAB_CLOSED_CATALOG")
    if configured:
        return [Path(configured).expanduser()]
    return [Path.cwd() / "closed-catalog.json", Path.home() / ".cvelab" / "closed-catalog.json"]


def _catalog_entry(cve: str) -> tuple[dict[str, Any] | None, str | None]:
    for path in _catalog_paths():
        if not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        entries = payload.get("cves", payload)
        entry = entries.get(cve)
        if entry:
            return entry, str(path.resolve())
    return None, None


def _ai_plan(
    cve: str,
    dossier: dict[str, Any],
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    fix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return structured_response(
        api_key=api_key,
        model=model,
        instructions=(
            "Research a defensive, local-only Docker reproduction for the supplied CVE. "
            "Use only public vendor documentation, advisories, official registries, and precise evidence. "
            "Return READY only when an exact publicly accessible vulnerable Docker image tag, HTTP port, "
            "and non-destructive marker-only HTTP reproduction are documented. Never guess image names, "
            "tags, endpoints, credentials, or patched behavior. Keep the result to a marker-based HTTP regression "
            "request against the named service inside the generated Docker network; do not add capabilities or "
            "targets beyond that contained check. "
            "Use relative HTTP paths only and express headers as name/value list items. "
            "Use null for optional match predicates that do not apply. "
            "When security_patch is supplied it is the authoritative account of the vulnerability, and it "
            "outranks the advisory's prose: read it for the endpoint, the parameter and the authorization the "
            "fix restored, and derive the reproduction from that. A vendor advisory is often written to "
            "withhold exactly those details, so their absence from it is not a reason to decline. The patch "
            "does not relieve the image requirement -- the vulnerable tag must still be a published image "
            "inside the affected range -- and it is not a licence to exceed the contained HTTP check. "
            "If proprietary artifacts, authentication, a license, non-HTTP interaction, or missing technical "
            "details prevent a faithful reproduction, return ARTIFACT_REQUIRED or UNSUPPORTED."
        ),
        input_text=json.dumps(
            {"cve": cve, "cve_record": dossier, "security_patch": fix},
            ensure_ascii=True,
        ),
        schema=_PLAN_SCHEMA,
        schema_name="closed_software_resolution",
        max_output_tokens=5000,
        tools=[{"type": "web_search"}],
        include=["web_search_call.action.sources"],
        provider=provider,
        base_url=base_url,
    )


def _normalize_request(request: dict[str, Any] | None) -> dict[str, Any] | None:
    if request is None:
        return None
    normalized = dict(request)
    headers = normalized.get("headers", {})
    if isinstance(headers, list):
        normalized["headers"] = {
            str(item["name"]): str(item["value"]) for item in headers
        }
    return normalized


def _normalize_plan(entry: dict[str, Any]) -> dict[str, Any]:
    if "contract" in entry:
        source_contract = entry["contract"]
        contract = {
            "attack": [_normalize_request(item) for item in source_contract.get("attack", [])],
            "observe": {
                "request": _normalize_request(source_contract.get("observe", {}).get("request")),
                "match": source_contract.get("observe", {}).get("match", {}),
            },
        }
    else:
        match = entry.get("observe_match") or {}
        match = {key: value for key, value in match.items() if value is not None}
        contract = {
            "attack": [_normalize_request(item) for item in entry.get("attack", [])],
            "observe": {
                "request": _normalize_request(entry.get("observe_request")),
                "match": match,
            },
        }
    return {
        "status": entry.get("status", "READY"),
        "reason": entry.get("reason", "resolved from local catalog"),
        "vulnerable_image": entry.get("vulnerable_image"),
        "fixed_image": entry.get("fixed_image"),
        "container_port": entry.get("container_port"),
        "health_path": entry.get("health_path", "/"),
        "contract": contract,
        "sources": entry.get("sources", []),
    }


def _ensure_image(image: str) -> None:
    local = subprocess.run(
        ["docker", "image", "inspect", image], capture_output=True, text=True
    )
    if local.returncode == 0:
        return
    subprocess.run(["docker", "pull", image], check=True)


def _security_patch(
    dossier: dict[str, Any],
    output_root: Path,
    repo: str | None,
    fixed_ref: str | None,
) -> dict[str, Any] | None:
    """The fix behind this CVE, when a public one can be pointed at.

    A product advisory names a patched release and nothing else, so a
    resolver working from prose cannot say which request to send. The fix
    commit can: for closed source it is not something to build, only the
    evidence that says what to exercise. Failing to read one is not fatal --
    the resolver then answers from the record alone, as it did before.
    """
    resolved = resolve_source(dossier, repo, fixed_ref)
    if not resolved:
        return None
    repo_url, reference = resolved
    described = research.words(
        " ".join(str(text) for text in dossier.get("descriptions") or [])
    )
    try:
        return fix_patch(repo_url, reference, output_root, described=described)
    except (RuntimeError, ValueError, OSError) as exc:
        progress.step(f"the fix at {repo_url} could not be read: {exc}")
        return None


def run_closed_auto(
    cve_value: str,
    output_root: Path,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    repo: str | None = None,
    fixed_ref: str | None = None,
) -> dict[str, Any]:
    cve = normalize_cve(cve_value)
    entry, catalog_source = _catalog_entry(cve)
    dossier: dict[str, Any] | None = None
    fix: dict[str, Any] | None = None
    if entry is None:
        dossier = collect_cve(cve)
        fix = _security_patch(dossier, output_root, repo, fixed_ref)
        plan = _normalize_plan(
            _ai_plan(cve, dossier, api_key, model, provider, base_url, fix)
        )
        resolution_source = "public_research"
    else:
        plan = _normalize_plan(entry)
        resolution_source = "local_catalog"

    resolution_dir = output_root.resolve() / cve / "closed"
    resolution_dir.mkdir(parents=True, exist_ok=True)
    resolution = {
        "cve": cve,
        "resolution_source": resolution_source,
        "catalog": catalog_source,
        "plan": plan,
    }
    if fix:
        # The patch itself is not kept: it is public, and a copy here would
        # go out with every uploaded report. Where it came from is the part
        # a reader needs to check the plan against.
        resolution["security_patch"] = {
            "repository": fix["repository"],
            "vulnerable_ref": fix["vulnerable_ref"],
            "fixed_ref": fix["fixed_ref"],
            "changed_files": fix["changed_files"],
        }
    (resolution_dir / "resolution.json").write_text(
        json.dumps(resolution, indent=2), encoding="utf-8"
    )
    if plan["status"] != "READY":
        return {
            "ok": False,
            "status": plan["status"],
            "cve": cve,
            "reason": plan["reason"],
            "resolution": str(resolution_dir / "resolution.json"),
            "required": "A licensed local image can be registered once in closed-catalog.json",
        }
    required = ["vulnerable_image", "container_port", "health_path", "contract"]
    missing = [name for name in required if not plan.get(name)]
    if missing:
        raise RuntimeError(f"resolver returned an incomplete READY plan: {', '.join(missing)}")

    _ensure_image(str(plan["vulnerable_image"]))
    if plan.get("fixed_image"):
        _ensure_image(str(plan["fixed_image"]))
    contract_path = resolution_dir / "auto-contract.json"
    contract_path.write_text(json.dumps(plan["contract"], indent=2), encoding="utf-8")
    result = run_closed_lab(
        cve,
        output_root,
        str(plan["vulnerable_image"]),
        str(plan["fixed_image"]) if plan.get("fixed_image") else None,
        int(plan["container_port"]),
        str(plan["health_path"]),
        contract_path,
    )
    result["automatic_resolution"] = {
        "source": resolution_source,
        "catalog": catalog_source,
        "sources": plan.get("sources", []),
        "resolution": str(resolution_dir / "resolution.json"),
        "security_patch": resolution.get("security_patch"),
    }
    return result
