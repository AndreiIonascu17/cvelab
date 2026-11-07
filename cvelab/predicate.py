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

"""Deciding whether the effect a contract named in advance actually happened.

WHY THIS IS ITS OWN MODULE

A proof check that reads a field a model's own validator wrote measures
nothing. The source path's mandatory `security_effect_observed` is a string
comparison against `proof_quality`, a key the validator prints about itself, so
a validator that prints the expected literal clears a mandatory gate without
observing anything. Reading some other validator-written key instead would only
move the hole: the problem is not which key is read, it is that the thing being
judged is also the judge.

The closed path does not have that problem, and the reason is the order of
events rather than anything about HTTP. The contract names, before any
container is started, the status, body text or header that would count as the
effect. CVELab then sends the observation request itself and decides whether
that predicate holds. Committing first and measuring second is what makes the
verdict a measurement.

This module is that decision, lifted out of `closed.py` so the source path can
be held to the same standard. It takes the observations and the predicate --
not a response -- because the next caller observes whatever a validator
printed, which is a flat mapping of strings and numbers, not a status and a
body. The only HTTP-shaped thing left is the vocabulary of kinds, which is the
vocabulary the closed-lab contract has always declared; naming the observation
each kind reads is how a non-HTTP caller reuses it.

Nothing here imports another CVELab module and nothing here performs I/O, so a
caller does not widen its own dependencies by reaching for a sound verdict.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any, NamedTuple

#: The kinds a predicate may declare, in the order the evidence reports them.
#:
#: This is the closed-lab contract's own vocabulary, unchanged and unextended:
#: a kind that is not in here was never evaluated and must not start being
#: evaluated as a side effect of moving the code. The order is fixed here
#: rather than taken from the predicate's own key order, because the evidence
#: lines are quoted into EVIDENCE.json and the walkthrough, and a contract that
#: listed its keys differently would otherwise produce a different-looking
#: record of the same measurement.
KINDS: tuple[str, ...] = ("status", "body_contains", "body_regex", "header")

#: Which observation each kind reads. A caller observing something other than
#: an HTTP response supplies these names and nothing else: it does not have to
#: provide an observation for a kind its predicate never declares.
READS: Mapping[str, str] = {
    "status": "status",
    "body_contains": "body",
    "body_regex": "body",
    "header": "headers",
}


class PredicateError(ValueError):
    """A predicate that cannot be decided, so nothing was measured.

    It subclasses ValueError because that is what a malformed contract has
    always raised on this path, and because every caller between here and the
    CLI already reads a ValueError as the contract's fault rather than the
    run's.
    """


class Verdict(NamedTuple):
    """Whether the declared effect was observed, and what was measured.

    Exactly two fields, so `confirmed, predicates = evaluate(...)` keeps
    reading the way the closed path has always read it.
    """

    held: bool
    evidence: list[str]


def _names(observations: Any) -> str:
    """The observation names available, for an error that has to name them."""
    try:
        return ", ".join(sorted(str(key) for key in observations)) or "nothing"
    except TypeError:
        return "nothing that can be read by name"


def _observed(kind: str, observations: Mapping[str, Any]) -> Any:
    name = READS[kind]
    try:
        return observations[name]
    except (KeyError, IndexError, TypeError) as exc:
        raise PredicateError(
            f"{kind} reads the observation {name!r}, which was not observed; observed: {_names(observations)}"
        ) from exc


def _text(kind: str, observations: Mapping[str, Any]) -> str:
    value = _observed(kind, observations)
    if not isinstance(value, str):
        # Deliberately not coerced: str(200) would let a predicate written
        # about a response body be satisfied by a status code, which is the
        # kind of accident this module exists to rule out.
        raise PredicateError(
            f"{kind} reads {READS[kind]!r} as text, and {type(value).__name__} was observed"
        )
    return value


def _status(declared: Any, observations: Mapping[str, Any]) -> tuple[bool, str]:
    allowed = declared if isinstance(declared, list) else [declared]
    observed = _observed("status", observations)
    try:
        wanted = [int(value) for value in allowed]
    except (TypeError, ValueError) as exc:
        raise PredicateError(f"status must name whole numbers, not {allowed!r}") from exc
    passed = observed in wanted
    return passed, f"status={observed} allowed={allowed} passed={passed}"


def _body_contains(declared: Any, observations: Mapping[str, Any]) -> tuple[bool, str]:
    needle = str(declared)
    passed = needle in _text("body_contains", observations)
    return passed, f"body_contains={needle!r} passed={passed}"


def _body_regex(declared: Any, observations: Mapping[str, Any]) -> tuple[bool, str]:
    pattern = str(declared)
    body = _text("body_regex", observations)
    try:
        passed = re.search(pattern, body) is not None
    except re.error as exc:
        raise PredicateError(f"body_regex {pattern!r} is not a usable regular expression: {exc}") from exc
    return passed, f"body_regex={pattern!r} passed={passed}"


def _header(declared: Any, observations: Mapping[str, Any]) -> tuple[bool, str]:
    if not isinstance(declared, Mapping) or "name" not in declared or "contains" not in declared:
        raise PredicateError("header must declare the header's name and the text it contains")
    name, text = str(declared["name"]), str(declared["contains"])
    observed = _observed("header", observations)
    if not isinstance(observed, Mapping):
        raise PredicateError(
            f"header reads {READS['header']!r} as a mapping of header names to values, "
            f"and {type(observed).__name__} was observed"
        )
    actual = next((value for key, value in observed.items() if str(key).lower() == name.lower()), "")
    passed = text in str(actual)
    return passed, f"header={name!r} contains={text!r} passed={passed}"


_DECIDE: Mapping[str, Callable[[Any, Mapping[str, Any]], tuple[bool, str]]] = {
    "status": _status,
    "body_contains": _body_contains,
    "body_regex": _body_regex,
    "header": _header,
}


def declared_kinds(predicate: Mapping[str, Any]) -> list[str]:
    """The kinds this predicate declares, in the order they are evaluated."""
    return [kind for kind in KINDS if kind in predicate]


def unknown_kinds(predicate: Mapping[str, Any]) -> list[str]:
    """Keys this evaluator will ignore.

    Ignoring them is what the closed path has always done, and it is not safe
    to leave unreported: a predicate of `{"status": 200, "body_contins": "x"}`
    is decided on the status alone, which is weaker than what the contract
    appears to claim. A caller validating a contract should refuse these
    rather than discover them in the evidence.
    """
    return sorted(str(key) for key in predicate if key not in KINDS)


#: The kinds whose declaration is text the response itself has to carry.
#:
#: `status` is missing on purpose, and the absence is the whole content of
#: this tuple rather than an oversight. A status code is drawn from a fixed
#: vocabulary the service answers from on every build, so it can never name a
#: value that something in particular put there; every other kind declares a
#: string, and a string can be one the lab planted.
QUOTING: tuple[str, ...] = ("body_contains", "body_regex", "header")


def quoted_texts(predicate: Mapping[str, Any]) -> dict[str, str]:
    """The text each clause requires the response to carry, keyed by kind.

    `header` reports its `contains` and not its `name`: the name says which
    header is read and the value is what was observed in it, so only the
    value can carry something the attack introduced. A clause whose text is
    not a string is left out rather than coerced, for the reason `_text`
    refuses to coerce: a caller asking what text a predicate looks for must
    not be handed `str(200)`.
    """
    texts: dict[str, str] = {}
    for kind in ("body_contains", "body_regex"):
        declared = predicate.get(kind)
        if isinstance(declared, str):
            texts[kind] = declared
    header = predicate.get("header")
    if isinstance(header, Mapping) and isinstance(header.get("contains"), str):
        texts["header"] = header["contains"]
    return texts


def quotes(predicate: Mapping[str, Any], value: str | None) -> list[str]:
    """The clauses of this predicate that quote `value`, in kind order.

    WHY A CALLER WANTS TO KNOW

    For a lab with a fixed build to contradict it, nothing here is needed:
    the comparison rules out a predicate that does not describe the effect,
    because such a predicate holds on the patched side too. A lab with only
    a vulnerable build has no such contradiction available, and the question
    that replaces it is whether the declared effect is something the attack
    introduced or something the system produces on its own. The caller
    answers that by asking whether any clause quotes a value the lab planted
    -- which is what the canary marker is for.

    Containment, not equality, so that a clause may name the planted value
    inside the surrounding text it is expected to appear in. For `body_regex`
    that is containment in the pattern's source, which is sound exactly when
    `value` holds no regular-expression metacharacter -- otherwise a pattern
    could "quote" it as syntax rather than as text. The one value CVELab
    asks about is the marker, which is a fixed prefix and hex digits by
    construction, so the condition holds for it and the caller need not
    escape anything.

    An absent or blank `value` quotes nothing, and the empty list is the
    honest answer: there is no planted value to have named.
    """
    if not isinstance(value, str) or not value.strip():
        return []
    texts = quoted_texts(predicate)
    return [kind for kind in QUOTING if value in texts.get(kind, "")]


def evaluate(
    observations: Mapping[str, Any],
    predicate: Mapping[str, Any],
    *,
    where: str = "predicate",
) -> Verdict:
    """Decide the predicate against the observations, or refuse to decide.

    `observations` is a plain mapping of names to what was observed under
    them -- a status integer, body text, a mapping of response headers, or
    whatever a validator printed. `predicate` names one or more of `KINDS`.

    A predicate that cannot be decided raises instead of answering, because
    there is no honest answer: the run has measured nothing, and the caller is
    the only place that can tell whether that should abort the run or count as
    the effect not having happened. `effect_observed` is the second of those.
    """
    kinds = declared_kinds(predicate)
    if not kinds:
        raise PredicateError(f"{where} must define at least one predicate")
    results: list[bool] = []
    evidence: list[str] = []
    for kind in kinds:
        passed, line = _DECIDE[kind](predicate[kind], observations)
        results.append(passed)
        evidence.append(line)
    return Verdict(all(results), evidence)


def effect_observed(
    observations: Mapping[str, Any],
    predicate: Mapping[str, Any],
    *,
    where: str = "predicate",
) -> Verdict:
    """The same measurement, failing closed instead of raising.

    For a caller that gates a security claim on the answer. A predicate that
    cannot be decided -- an observation that was never printed, a pattern that
    does not compile, a predicate that declares no kind at all -- is reported
    as the effect not having been observed, never as the effect happening, and
    the reason is recorded in the evidence instead of being lost. Every clause
    reports, so one undecidable clause does not hide what the others measured.

    Any other failure in deciding a clause is treated the same way on purpose:
    on the path that gates a claim, an unanticipated error is exactly when the
    answer must be "not observed".
    """
    kinds = declared_kinds(predicate)
    if not kinds:
        return Verdict(False, [f"{where} declares no predicate, so nothing was measured; passed=False"])
    held = True
    evidence: list[str] = []
    for kind in kinds:
        try:
            passed, line = _DECIDE[kind](predicate[kind], observations)
        except Exception as exc:  # noqa: BLE001 - see the docstring
            passed, line = False, f"{kind} could not be decided ({exc}); passed=False"
        held = held and passed
        evidence.append(line)
    return Verdict(held, evidence)
