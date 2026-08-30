from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .ai import structured_response
from .closed import run_closed_lab
from .core import collect_cve, normalize_cve


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


def _ai_plan(cve: str, dossier: dict[str, Any], api_key: str | None, model: str | None) -> dict[str, Any]:
    return structured_response(
        api_key=api_key,
        model=model,
        instructions=(
            "Research a defensive, local-only Docker reproduction for the supplied CVE. "
            "Use only public vendor documentation, advisories, official registries, and precise evidence. "
            "Return READY only when an exact publicly accessible vulnerable Docker image tag, HTTP port, "
            "and non-destructive marker-only HTTP reproduction are documented. Never guess image names, "
            "tags, endpoints, credentials, or patched behavior. Do not produce command execution, shells, "
            "persistence, credential theft, destructive payloads, or remote-target instructions. "
            "Use relative HTTP paths only and express headers as name/value list items. "
            "Use null for optional match predicates that do not apply. "
            "If proprietary artifacts, authentication, a license, non-HTTP interaction, or missing technical "
            "details prevent a faithful reproduction, return ARTIFACT_REQUIRED or UNSUPPORTED."
        ),
        input_text=json.dumps({"cve": cve, "cve_record": dossier}, ensure_ascii=True),
        schema=_PLAN_SCHEMA,
        schema_name="closed_software_resolution",
        max_output_tokens=5000,
        tools=[{"type": "web_search"}],
        include=["web_search_call.action.sources"],
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


def run_closed_auto(
    cve_value: str,
    output_root: Path,
    api_key: str | None,
    model: str | None,
) -> dict[str, Any]:
    cve = normalize_cve(cve_value)
    entry, catalog_source = _catalog_entry(cve)
    dossier: dict[str, Any] | None = None
    if entry is None:
        dossier = collect_cve(cve)
        plan = _normalize_plan(_ai_plan(cve, dossier, api_key, model))
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
    }
    return result
