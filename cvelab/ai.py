from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["cwe", "confidence", "rationale", "source_hints", "manual_inputs"],
    "properties": {
        "cwe": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
        "source_hints": {"type": "array", "items": {"type": "string"}},
        "manual_inputs": {"type": "array", "items": {"type": "string"}},
    },
}


def structured_response(
    *,
    api_key: str | None,
    model: str | None,
    instructions: str,
    input_text: str,
    schema: dict,
    schema_name: str,
    max_output_tokens: int,
    tools: list[dict] | None = None,
    include: list[str] | None = None,
) -> dict:
    api_key = api_key or os.getenv("OPENAI_API_KEY")
    model = model or os.getenv("CVELAB_MODEL")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set; use --key or the environment variable")
    if not model:
        raise RuntimeError("CVELAB_MODEL is not set; use --model or the environment variable")

    body = {
        "model": model,
        "store": False,
        "max_output_tokens": max_output_tokens,
        "instructions": instructions,
        "input": input_text,
        "text": {
            "format": {
                "type": "json_schema",
                "name": schema_name,
                "strict": True,
                "schema": schema,
            }
        },
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    if include:
        body["include"] = include
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API HTTP {exc.code}: {detail[:4000]}") from exc

    for item in payload.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text":
                return json.loads(content["text"])
    raise RuntimeError("OpenAI response did not contain structured output")


def plan_with_openai(
    dossier: dict,
    api_key: str | None = None,
    model: str | None = None,
) -> dict:
    return structured_response(
        api_key=api_key,
        model=model,
        max_output_tokens=1800,
        schema=PLAN_SCHEMA,
        schema_name="cvelab_plan",
        instructions=(
            "You classify CVE metadata for a local defensive research lab. "
            "Do not provide shells, persistence, credential theft, destructive payloads, "
            "or public-target instructions. Prefer the explicit CWE in the dossier."
        ),
        input_text=json.dumps(dossier, ensure_ascii=True),
    )
