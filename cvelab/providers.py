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

"""Every provider, declared once.

Adding DeepSeek meant editing eight places: the supported set, the key
variable, the masked prompt's label, the dispatch, the usage shape, the price
table, the environment check and the control plane. Scattered knowledge like
that drifts, and one of those eight was missed in a way that raised KeyError
for the first user who tried it.

A provider is a row here now, and everything else reads this table. Nothing
below is fixed: a base URL takes CVELAB_<NAME>_BASE_URL, prices take
CVELAB_PRICE_INPUT and CVELAB_PRICE_OUTPUT, and the model is always the
user's choice. These are defaults, not decisions made for anyone.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# How a provider expects to be spoken to. The dispatch reads this rather than
# the provider's name, so a new provider that speaks an existing dialect needs
# no new request code at all.
RESPONSES = "responses"
MESSAGES = "messages"
CHAT_COMPLETIONS = "chat_completions"

# Appended to a provider's base URL. One place, so no request function spells
# an endpoint out.
DIALECT_PATH = {
    RESPONSES: "/responses",
    MESSAGES: "/messages",
    CHAT_COMPLETIONS: "/chat/completions",
}


@dataclass(frozen=True)
class Provider:
    name: str
    label: str
    dialect: str
    # Empty when the endpoint is the user's to supply, as for a local server.
    base_url: str = ""
    key_variable: str = ""
    # A key is required unless the endpoint is something the user runs.
    requires_key: bool = True
    # Only providers with a web search tool can be asked to find a source when
    # the CVE record names no commit.
    web_search: bool = False
    # Path appended to the base URL to list models, used by `cvelab doctor` to
    # check a key cheaply. Empty means the check is skipped.
    models_path: str = "/models"
    # Whether the endpoint accepts response_format json_schema. Where it does
    # not, the schema travels in the instructions instead. Asking first and
    # falling back costs a rejected request on every call.
    json_schema: bool = False
    # Seconds allowed per request. A hosted API answers in minutes; a local
    # model on CPU can take far longer.
    timeout_seconds: int = 600
    # Header used to carry the key. Anthropic takes its own; everyone else
    # uses Bearer.
    auth_header: str = "Authorization"
    auth_format: str = "Bearer {key}"
    extra_headers: dict[str, str] = field(default_factory=dict)
    # USD per million tokens, {model: (input, output)}. Defaults only: the
    # price environment variables override them, and an unknown model reports
    # tokens with no price rather than a guess.
    prices: dict[str, tuple[float, float]] = field(default_factory=dict)
    # Model identifiers known to work, offered as suggestions. Not a
    # whitelist: a provider ships models faster than this file is edited, and
    # the model is always the user's choice. An unlisted model runs fine and
    # simply reports no price.
    models: tuple[str, ...] = ()
    notes: str = ""


PROVIDERS: dict[str, Provider] = {
    "openai": Provider(
        name="openai",
        label="OpenAI",
        dialect=RESPONSES,
        base_url="https://api.openai.com/v1",
        key_variable="OPENAI_API_KEY",
        web_search=True,
        models=("gpt-5.6-sol",),
        prices={"gpt-5.6-sol": (4.00, 20.00)},
    ),
    "anthropic": Provider(
        name="anthropic",
        label="Anthropic",
        dialect=MESSAGES,
        base_url="https://api.anthropic.com/v1",
        key_variable="ANTHROPIC_API_KEY",
        auth_header="x-api-key",
        auth_format="{key}",
        extra_headers={"anthropic-version": "2023-06-01"},
        web_search=True,
        models=(
            "claude-opus-5-5",
            "claude-sonnet-5-5",
            "claude-haiku-5-5",
        ),
        prices={
            "claude-opus-5-5": (4.00, 20.00),
            "claude-opus-5": (5.00, 25.00),
            "claude-opus-4-8": (5.00, 25.00),
            "claude-opus-4-7": (5.00, 25.00),
            "claude-opus-4-6": (5.00, 25.00),
            "claude-sonnet-5-5": (2.00, 10.00),
            "claude-sonnet-5": (2.00, 10.00),
            "claude-sonnet-4-6": (3.00, 15.00),
            "claude-haiku-5-5": (0.10, 0.50),
            "claude-haiku-4-5": (1.00, 5.00),
            "claude-fable-5-1": (10.00, 50.00),
            "claude-fable-5": (10.00, 50.00),
        },
    ),
    "deepseek": Provider(
        name="deepseek",
        label="DeepSeek",
        dialect=CHAT_COMPLETIONS,
        base_url="https://api.deepseek.com/v1",
        key_variable="DEEPSEEK_API_KEY",
        web_search=False,
        # Peak hours cost double, 01:00-04:00 and 06:00-10:00 UTC on weekdays.
        # Off-peak is listed, so a peak run costs about twice what is reported.
        models=("deepseek-flash", "deepseek-v4-pro"),
        prices={
            "deepseek-flash": (0.15, 0.60),
            "deepseek-v4-flash": (0.15, 0.60),
            "deepseek-v4-pro": (0.66, 1.98),
        },
        json_schema=False,
        notes="No web search: source discovery cannot fall back to the model.",
    ),
    "local": Provider(
        name="local",
        label="Local",
        dialect=CHAT_COMPLETIONS,
        base_url="http://127.0.0.1:11434/v1",
        key_variable="CVELAB_LOCAL_API_KEY",
        requires_key=False,
        web_search=False,
        # Unknown server, so try the richer form and fall back if refused.
        json_schema=True,
        timeout_seconds=1800,
        notes="Any OpenAI-compatible server. Prices are unknown, so set "
              "CVELAB_PRICE_INPUT and CVELAB_PRICE_OUTPUT to see a cost.",
    ),
}

# "auto" is a selection mode rather than a provider, so it is not a row.
SELECTABLE = ("auto", *PROVIDERS)


def get(name: str) -> Provider:
    try:
        return PROVIDERS[name]
    except KeyError:
        raise ValueError(
            f"Unsupported AI provider: {name}. Choose "
            + ", ".join(PROVIDERS)
            + "."
        ) from None


def endpoint_for(name: str, override: str | None = None) -> str:
    """The URL a request to this provider goes to."""
    base = base_url_for(name, override)
    path = DIALECT_PATH[get(name).dialect]
    return base if base.endswith(path) else base + path


def base_url_for(name: str, override: str | None = None) -> str:
    """Explicit argument, then environment, then the declared default."""
    if override:
        return override.rstrip("/")
    variable = f"CVELAB_{name.upper()}_BASE_URL"
    return (os.getenv(variable) or get(name).base_url).rstrip("/")


def auth_headers_for(name: str, key: str | None) -> dict[str, str]:
    provider = get(name)
    headers = dict(provider.extra_headers)
    if key or provider.requires_key:
        headers[provider.auth_header] = provider.auth_format.format(key=key or "")
    return headers


def timeout_for(name: str) -> int:
    """Seconds per request. CVELAB_<NAME>_TIMEOUT overrides the default."""
    raw = os.getenv(f"CVELAB_{name.upper()}_TIMEOUT")
    if raw is None:
        return get(name).timeout_seconds
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"CVELAB_{name.upper()}_TIMEOUT must be an integer number of seconds"
        ) from exc
    if value < 1 or value > 86400:
        raise ValueError(
            f"CVELAB_{name.upper()}_TIMEOUT must be between 1 and 86400 seconds"
        )
    return value


def price_for(model: str) -> tuple[float, float] | None:
    for provider in PROVIDERS.values():
        if model in provider.prices:
            return provider.prices[model]
    return None


def as_dicts() -> list[dict]:
    """The table as data, for anything that is not Python."""
    return [
        {
            "name": p.name,
            "label": p.label,
            "requires_key": p.requires_key,
            "web_search": p.web_search,
            "models": list(p.models),
        }
        for p in PROVIDERS.values()
    ]
