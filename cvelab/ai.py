from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import urlparse


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


SUPPORTED_PROVIDERS = {"auto", "openai", "anthropic", "local"}


class AIHTTPError(RuntimeError):
    def __init__(self, provider: str, status: int, detail: str):
        super().__init__(f"{provider} API HTTP {status}: {detail[:4000]}")
        self.status = status


def resolve_provider(provider: str | None = None) -> str:
    selected = (provider or os.getenv("CVELAB_AI_PROVIDER") or "auto").lower()
    if selected not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unsupported AI provider: {selected}. Choose openai, anthropic, or local."
        )
    if selected != "auto":
        return selected
    if os.getenv("CVELAB_BASE_URL"):
        return "local"
    if os.getenv("ANTHROPIC_API_KEY") and not os.getenv("OPENAI_API_KEY"):
        return "anthropic"
    return "openai"


def _provider_key(provider: str, api_key: str | None) -> str | None:
    if api_key:
        return api_key
    if provider == "openai":
        return os.getenv("OPENAI_API_KEY")
    if provider == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY")
    return os.getenv("CVELAB_LOCAL_API_KEY")


def ai_is_configured(
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
) -> bool:
    selected = resolve_provider(provider)
    selected_model = model or os.getenv("CVELAB_MODEL")
    return bool(selected_model and (selected == "local" or _provider_key(selected, api_key)))


def provider_supports_web_search(provider: str | None = None) -> bool:
    return resolve_provider(provider) in {"openai", "anthropic"}


def _local_base_url(base_url: str | None) -> str:
    value = (base_url or os.getenv("CVELAB_BASE_URL") or "http://127.0.0.1:11434/v1").rstrip("/")
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Local AI base URL must be an HTTP(S) URL without credentials, query, or fragment")
    return value


def _local_timeout() -> int:
    raw = os.getenv("CVELAB_LOCAL_TIMEOUT", "1800")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("CVELAB_LOCAL_TIMEOUT must be an integer number of seconds") from exc
    if value < 1 or value > 86400:
        raise ValueError("CVELAB_LOCAL_TIMEOUT must be between 1 and 86400 seconds")
    return value


def _request_json(
    provider: str,
    url: str,
    body: dict,
    headers: dict[str, str],
    *,
    timeout_seconds: int = 180,
) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AIHTTPError(provider, exc.code, detail) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not connect to {provider} API at {url}: {exc.reason}") from exc


def _decode_json_text(text: str, provider: str) -> dict:
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        candidate = "\n".join(lines).strip()
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{provider} response was not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{provider} structured response must be a JSON object")
    return value


def _anthropic_compatible_schema(schema: dict) -> dict:
    """Return Anthropic's supported JSON Schema subset without weakening local checks."""
    unsupported = {
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
        "minLength", "maxLength", "maxItems", "uniqueItems", "contains", "minContains",
        "maxContains", "minProperties", "maxProperties", "propertyNames",
        "patternProperties", "dependentRequired", "dependentSchemas", "oneOf", "not",
        "if", "then", "else", "unevaluatedProperties", "unevaluatedItems",
    }
    transformed = {}
    removed = []
    for key, value in schema.items():
        if key in unsupported or (key == "minItems" and value not in {0, 1}):
            removed.append(f"{key}={value!r}")
            continue
        if isinstance(value, dict):
            transformed[key] = _anthropic_compatible_schema(value)
        elif isinstance(value, list):
            transformed[key] = [
                _anthropic_compatible_schema(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            transformed[key] = value
    if removed:
        note = "CVELab validates these constraints after generation: " + ", ".join(removed) + "."
        description = transformed.get("description", "")
        transformed["description"] = (description + " " + note).strip()
    return transformed


def _validate_schema(value: object, schema: dict, path: str = "$") -> None:
    alternatives = schema.get("anyOf")
    if alternatives:
        errors = []
        for alternative in alternatives:
            try:
                _validate_schema(value, alternative, path)
                return
            except RuntimeError as exc:
                errors.append(str(exc))
        raise RuntimeError(f"Structured response does not match any schema at {path}: {'; '.join(errors)}")

    declared = schema.get("type")
    if declared:
        allowed = declared if isinstance(declared, list) else [declared]
        matches = {
            "object": lambda item: isinstance(item, dict),
            "array": lambda item: isinstance(item, list),
            "string": lambda item: isinstance(item, str),
            "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
            "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
            "boolean": lambda item: isinstance(item, bool),
            "null": lambda item: item is None,
        }
        if not any(matches[kind](value) for kind in allowed):
            raise RuntimeError(f"Structured response has invalid type at {path}; expected {allowed}")
    if "enum" in schema and value not in schema["enum"]:
        raise RuntimeError(f"Structured response has invalid value at {path}")
    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise RuntimeError(f"Structured response is missing {', '.join(missing)} at {path}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unexpected = [key for key in value if key not in properties]
            if unexpected:
                raise RuntimeError(f"Structured response has unexpected fields at {path}: {', '.join(unexpected)}")
        for key, item in value.items():
            if key in properties:
                _validate_schema(item, properties[key], f"{path}.{key}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise RuntimeError(f"Structured response array is too short at {path}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise RuntimeError(f"Structured response array is too long at {path}")
        if "items" in schema:
            for index, item in enumerate(value):
                _validate_schema(item, schema["items"], f"{path}[{index}]")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise RuntimeError(f"Structured response string is too short at {path}")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise RuntimeError(f"Structured response string does not match pattern at {path}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise RuntimeError(f"Structured response number is below minimum at {path}")
        if "maximum" in schema and value > schema["maximum"]:
            raise RuntimeError(f"Structured response number is above maximum at {path}")


def _openai_response(
    api_key: str,
    model: str,
    instructions: str,
    input_text: str,
    schema: dict,
    schema_name: str,
    max_output_tokens: int,
    tools: list[dict] | None,
    include: list[str] | None,
) -> dict:
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
    payload = _request_json(
        "OpenAI",
        "https://api.openai.com/v1/responses",
        body,
        {"Authorization": f"Bearer {api_key}"},
    )
    for item in payload.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text":
                return _decode_json_text(content["text"], "OpenAI")
    raise RuntimeError("OpenAI response did not contain structured output")


def _anthropic_response(
    api_key: str,
    model: str,
    instructions: str,
    input_text: str,
    schema: dict,
    max_output_tokens: int,
    tools: list[dict] | None,
) -> dict:
    compatible_schema = _anthropic_compatible_schema(schema)
    effort = os.getenv("CVELAB_ANTHROPIC_EFFORT", "low").lower()
    if effort not in {"low", "medium", "high", "xhigh", "max"}:
        raise ValueError(
            "CVELAB_ANTHROPIC_EFFORT must be low, medium, high, xhigh, or max"
        )
    body = {
        "model": model,
        "max_tokens": max_output_tokens,
        "system": instructions,
        "messages": [{"role": "user", "content": input_text}],
        "output_config": {
            "effort": effort,
            "format": {"type": "json_schema", "schema": compatible_schema},
        },
    }
    if tools:
        body["tools"] = [
            {"type": "web_search_20250305", "name": "web_search", "max_uses": 5}
            for tool in tools
            if tool.get("type") == "web_search"
        ]
    payload = _request_json(
        "Anthropic",
        "https://api.anthropic.com/v1/messages",
        body,
        {"x-api-key": api_key, "anthropic-version": "2023-06-01"},
    )
    stop_reason = payload.get("stop_reason")
    usage = payload.get("usage", {})
    content = payload.get("content", [])
    content_types = [block.get("type", "unknown") for block in content]
    if stop_reason == "max_tokens":
        raise RuntimeError(
            "Anthropic reached max_tokens before producing structured output "
            f"(output_tokens={usage.get('output_tokens', 'unknown')}, "
            f"content_types={content_types})"
        )
    if stop_reason == "refusal" or any(block.get("type") == "refusal" for block in content):
        refusal = next((block for block in content if block.get("type") == "refusal"), {})
        details = payload.get("stop_details") or refusal
        raise RuntimeError(f"Anthropic refused structured generation: {details}")
    for block in content:
        if block.get("type") == "text":
            return _decode_json_text(block.get("text", ""), "Anthropic")
    raise RuntimeError(
        "Anthropic response did not contain structured output "
        f"(stop_reason={stop_reason!r}, output_tokens={usage.get('output_tokens', 'unknown')}, "
        f"content_types={content_types})"
    )


def _local_response(
    api_key: str | None,
    base_url: str | None,
    model: str,
    instructions: str,
    input_text: str,
    schema: dict,
    schema_name: str,
    max_output_tokens: int,
) -> dict:
    base = _local_base_url(base_url)
    url = base if base.endswith("/chat/completions") else base + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": instructions},
            {"role": "user", "content": input_text},
        ],
        "temperature": 0,
        "max_tokens": max_output_tokens,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": schema_name, "strict": True, "schema": schema},
        },
    }
    try:
        payload = _request_json(
            "Local", url, body, headers, timeout_seconds=_local_timeout()
        )
    except AIHTTPError as exc:
        if exc.status not in {400, 422}:
            raise
        body["response_format"] = {"type": "json_object"}
        body["messages"][0]["content"] += (
            " Return exactly one JSON object matching this schema: "
            + json.dumps(schema, ensure_ascii=True)
        )
        payload = _request_json(
            "Local", url, body, headers, timeout_seconds=_local_timeout()
        )
    choices = payload.get("choices", [])
    if not choices:
        raise RuntimeError("Local API response did not contain a completion choice")
    content = choices[0].get("message", {}).get("content", "")
    if isinstance(content, list):
        content = "".join(item.get("text", "") for item in content if isinstance(item, dict))
    return _decode_json_text(str(content), "Local")


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
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    selected = resolve_provider(provider)
    api_key = _provider_key(selected, api_key)
    model = model or os.getenv("CVELAB_MODEL")
    if selected != "local" and not api_key:
        variable = "OPENAI_API_KEY" if selected == "openai" else "ANTHROPIC_API_KEY"
        raise RuntimeError(f"{variable} is not set; use --key or the environment variable")
    if not model:
        raise RuntimeError("CVELAB_MODEL is not set; use --model or the environment variable")
    instructions += (
        " Write all generated prose, documentation, comments, and user-facing messages in English. "
        "Preserve source quotations, identifiers, and raw evidence verbatim."
    )
    if selected == "openai":
        result = _openai_response(
            api_key or "", model, instructions, input_text, schema, schema_name,
            max_output_tokens, tools, include,
        )
    elif selected == "anthropic":
        result = _anthropic_response(
            api_key or "", model, instructions, input_text, schema,
            max_output_tokens, tools,
        )
    else:
        if tools:
            instructions += (
                " No web-search tool is available from this local endpoint. Use only the supplied input and "
                "return insufficient-data status rather than inventing provenance."
            )
        result = _local_response(
            api_key, base_url, model, instructions, input_text, schema,
            schema_name, max_output_tokens,
        )
    _validate_schema(result, schema)
    return result


def plan_with_ai(
    dossier: dict,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    return structured_response(
        api_key=api_key,
        model=model,
        max_output_tokens=1800,
        schema=PLAN_SCHEMA,
        schema_name="cvelab_plan",
        instructions=(
            "You classify CVE metadata for an authorized local defensive research lab. "
            "Return classification and source hints only; do not design or expand a reproduction procedure. "
            "Prefer the explicit CWE in the dossier."
        ),
        input_text=json.dumps(dossier, ensure_ascii=True),
        provider=provider,
        base_url=base_url,
    )


def plan_with_openai(
    dossier: dict,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    """Backward-compatible alias for callers using the original public helper."""
    return plan_with_ai(dossier, api_key, model, provider, base_url)
