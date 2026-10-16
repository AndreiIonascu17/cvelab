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

"""Token accounting for a run.

The auto workflow makes up to four attempts, and each prompt can carry source
patches, so a single CVE is not a single call. Token counts come from the
provider and are exact. Cost is derived, and derived numbers go stale: the
table below is a convenience with a date on it, not a billing record. An
unpriced model still reports its tokens.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

from .providers import CHAT_COMPLETIONS, MESSAGES, PROVIDERS, RESPONSES
from .providers import get as get_provider

# USD per million tokens. Checked 2026-10-15 against each provider's own
# model documentation. Override per run with CVELAB_PRICE_INPUT and
# CVELAB_PRICE_OUTPUT rather than editing this, and treat the provider's
# invoice as authoritative.
PRICES_CHECKED = "2026-10-15"
# Assembled from the per-provider tables, so a price lives next to the
# provider that charges it. Overridden by CVELAB_PRICE_INPUT and
# CVELAB_PRICE_OUTPUT, and an unknown model reports tokens with no price.
PRICES: dict[str, tuple[float, float]] = {
    model: price
    for provider in PROVIDERS.values()
    for model, price in provider.prices.items()
}


@dataclass
class Totals:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    models: set[str] = field(default_factory=set)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


_lock = threading.Lock()
_totals = Totals()


def reset() -> None:
    global _totals
    with _lock:
        _totals = Totals()


def _extract(provider: str, payload: dict) -> tuple[int, int, int]:
    """Return (input, output, cached) for one provider payload."""
    usage = payload.get("usage") or {}
    dialect = get_provider(provider).dialect if provider in PROVIDERS else CHAT_COMPLETIONS
    if dialect == MESSAGES:
        return (
            int(usage.get("input_tokens") or 0),
            int(usage.get("output_tokens") or 0),
            int(usage.get("cache_read_input_tokens") or 0),
        )
    if dialect == RESPONSES:
        details = usage.get("input_tokens_details") or {}
        return (
            int(usage.get("input_tokens") or 0),
            int(usage.get("output_tokens") or 0),
            int(details.get("cached_tokens") or 0),
        )
    # The chat/completions shape. Many local servers report nothing at all; a
    # missing count is zero, not an error. DeepSeek additionally reports cache
    # hits, billed at a fiftieth of the miss rate.
    return (
        int(usage.get("prompt_tokens") or 0),
        int(usage.get("completion_tokens") or 0),
        int(usage.get("prompt_cache_hit_tokens") or 0),
    )


def record(provider: str, model: str | None, payload: dict) -> None:
    input_tokens, output_tokens, cached = _extract(provider, payload)
    with _lock:
        _totals.calls += 1
        _totals.input_tokens += input_tokens
        _totals.output_tokens += output_tokens
        _totals.cached_input_tokens += cached
        if model:
            _totals.models.add(model)


def _override() -> tuple[float, float] | None:
    raw_in = os.getenv("CVELAB_PRICE_INPUT")
    raw_out = os.getenv("CVELAB_PRICE_OUTPUT")
    if raw_in is None and raw_out is None:
        return None
    try:
        return (float(raw_in or 0), float(raw_out or 0))
    except ValueError as exc:
        raise ValueError(
            "CVELAB_PRICE_INPUT and CVELAB_PRICE_OUTPUT must be USD per million tokens"
        ) from exc


def estimate_cost(totals: Totals | None = None) -> float | None:
    """USD for the run, or None when no price is known for the model used."""
    totals = totals or snapshot()
    price = _override()
    if price is None:
        if len(totals.models) != 1:
            # Mixed or unknown models: a single number would be a guess.
            return None
        price = PRICES.get(next(iter(totals.models)))
        if price is None:
            return None
    per_input, per_output = price
    return (
        totals.input_tokens * per_input + totals.output_tokens * per_output
    ) / 1_000_000


def snapshot() -> Totals:
    with _lock:
        return Totals(
            calls=_totals.calls,
            input_tokens=_totals.input_tokens,
            output_tokens=_totals.output_tokens,
            cached_input_tokens=_totals.cached_input_tokens,
            models=set(_totals.models),
        )


def as_dict() -> dict:
    totals = snapshot()
    cost = estimate_cost(totals)
    report: dict = {
        "calls": totals.calls,
        "input_tokens": totals.input_tokens,
        "output_tokens": totals.output_tokens,
        "cached_input_tokens": totals.cached_input_tokens,
        "total_tokens": totals.total_tokens,
        "models": sorted(totals.models),
    }
    if cost is None:
        report["estimated_cost_usd"] = None
        report["cost_note"] = (
            "No price is known for this model. Set CVELAB_PRICE_INPUT and "
            "CVELAB_PRICE_OUTPUT in USD per million tokens."
        )
    else:
        report["estimated_cost_usd"] = round(cost, 4)
        report["cost_note"] = (
            f"Estimate from a price table checked {PRICES_CHECKED}. "
            "The provider's invoice is authoritative."
        )
    return report


def format_summary() -> str:
    totals = snapshot()
    if not totals.calls:
        return ""
    cost = estimate_cost(totals)
    parts = [
        f"{totals.calls} model call(s)",
        f"{totals.input_tokens:,} in",
        f"{totals.output_tokens:,} out",
    ]
    if totals.cached_input_tokens:
        parts.append(f"{totals.cached_input_tokens:,} cached")
    parts.append(f"~${cost:.2f}" if cost is not None else "cost unknown")
    return " | ".join(parts)
