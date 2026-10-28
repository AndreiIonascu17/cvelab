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

import contextlib
import json
import re
import shutil
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import progress, sidecar
from .ai import ProviderDeclined, ai_is_configured, structured_response
from .closed import (
    DEFAULT_HEALTH_TIMEOUT,
    MAX_HEALTH_TIMEOUT,
    _apply_fixture,
    _docker,
    _seconds,
    _validate_fixture,
    _wait_ready,
)
from .core import (
    build_limits,
    prepare_compose,
    run_docker_stage,
    runtime_flags,
    startup_grace,
    write_text,
)

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

#: How a run shows the effect. The first two read the answer the target sends
#: back. oob_callback is for an effect that produces no answer at all -- a
#: blind injection, a blind SSRF, a command whose output goes nowhere -- where
#: the only evidence is the target reaching out. The script listens for that
#: itself rather than handing the data to a third-party collaborator service,
#: which on a client engagement would send their traffic somewhere neither
#: party controls.
STRATEGIES = (
    "inband_differential", "marker_roundtrip", "oob_callback", "direct_observation",
)

#: What direct_observation may assert about the one response it reads.
EXPECTATIONS = ("status", "header", "body_contains", "extract")

#: The marker the operator's script generates fresh per run, so a stored
#: reflection from an earlier run is never mistaken for this one's.
_MARKER_TOKEN = "{{marker}}"

#: Where the script's own listener can be reached, substituted into the probe.
#: The operator names it when the target cannot reach the bound address
#: directly, which is the usual case across a network.
_CALLBACK_TOKEN = "{{callback}}"

_MAX_REQUESTS = 25
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
TRANSPORTS = ("http", "tcp", "tls", "ssh", "smb")

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


def _validate_request(request: Any, where: str) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ValueError(f"{where} must be an object")
    path = str(request.get("path", "/"))
    if not path.startswith("/"):
        raise ValueError(f"{where} path must start with /")
    method = str(request.get("method", "GET")).upper()
    headers = request.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError(f"{where} headers must be an object")
    body = request.get("body")
    if body is not None and not isinstance(body, str):
        raise ValueError(f"{where} body must be a string")
    return {
        "method": method,
        "path": path,
        "headers": {str(k): str(v) for k, v in headers.items()},
        "body": None if body is None else str(body),
    }


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
    if (text is None) == (raw is None):
        raise ValueError(f"{where} needs exactly one of send or send_hex")
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
    if value is None:
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


def _validate_sequence(value: Any, where: str, transport: str = "http") -> list[dict[str, Any]]:
    """A sequence of requests, or of socket exchanges on one connection.

    Over a socket the whole sequence shares one connection, because a
    protocol that needs a login before a command cannot be expressed as
    independent messages. HTTP requests stay independent, as they were.
    """
    if not isinstance(value, list) or not value:
        raise ValueError(f"{where} must be a non-empty list")
    if len(value) > _MAX_REQUESTS:
        raise ValueError(f"{where} may hold at most {_MAX_REQUESTS} requests")
    one = {
        "http": _validate_request,
        "tcp": _validate_message,
        "tls": _validate_message,
        "ssh": _validate_exec,
        "smb": _validate_smb_op,
    }[transport]
    return [one(item, f"{where}[{index}]") for index, item in enumerate(value)]


#: Where the evidence is read from. Only bodies could be read at first, which
#: left two measured labs unprovable for no reason to do with their CVE: one
#: disclosed a token in a response header, and one differed only in its status
#: code, 200 against 401. Both are the ordinary shape of an authorization
#: finding, so both are read now.
_BIND_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")

EXTRACTORS = ("json_values", "regex", "header", "status")


def _validate_extractor(value: Any) -> dict[str, Any]:
    """How tokens are pulled from a response for the set-difference proof."""
    listed = ", ".join(EXTRACTORS)
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError(f"extract must be exactly one of {listed}")
    if "json_values" in value:
        name = str(value["json_values"])
        if not name:
            raise ValueError("extract.json_values must name a JSON key")
        return {"json_values": name}
    if "regex" in value:
        pattern = str(value["regex"])
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(f"extract.regex is not a valid regex: {error}") from error
        return {"regex": pattern}
    if "header" in value:
        name = str(value["header"]).strip()
        if not name:
            raise ValueError("extract.header must name a response header")
        return {"header": name}
    if "status" in value:
        if value["status"] is not True:
            raise ValueError("extract.status takes only true")
        return {"status": True}
    raise ValueError(f"extract must be one of {listed}")


#: Values the operator supplies at run time, which the lab cannot know: a test
#: account's credential, a tenant id, a licence key. A control request that
#: has to read a resource "the correctly authorized way" needs one, and
#: without them that whole shape of check could not be written.
_MAX_INPUTS = 8


def _validate_inputs(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > _MAX_INPUTS:
        raise ValueError(f"inputs must be a list of at most {_MAX_INPUTS} names")
    names = []
    for offered in value:
        name = str(offered)
        if not _BIND_NAME.fullmatch(name):
            raise ValueError(f"inputs name {name!r} must be lowercase letters, digits and _")
        if name in ("marker", "callback"):
            raise ValueError(f"inputs cannot redefine {{{{{name}}}}}")
        names.append(name)
    return names


_MAX_DISCOVER_STEPS = 6


def _substitutions(text: str) -> set[str]:
    return set(re.findall(r"\{\{([a-z][a-z0-9_]*)\}\}", text))


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


def _validate_discover(value: Any) -> tuple[list[dict[str, Any]], set[str]]:
    """The chain that enumerates targets before the probe tests each one.

    Each step binds one name. A query step runs requests and binds every value
    its extractor pulls, fanning the run out over them; a derive step binds a
    value computed from names already bound. A step may use only names bound by
    an earlier step, so a spec cannot reference a target it never discovered.
    """
    if value is None:
        return [], set()
    if not isinstance(value, list):
        raise ValueError("discover must be a list of steps")
    if len(value) > _MAX_DISCOVER_STEPS:
        raise ValueError(f"discover may hold at most {_MAX_DISCOVER_STEPS} steps")
    steps: list[dict[str, Any]] = []
    bound: set[str] = set()
    for index, step in enumerate(value):
        where = f"discover[{index}]"
        if not isinstance(step, dict):
            raise ValueError(f"{where} must be an object")
        name = str(step.get("bind", ""))
        if not _BIND_NAME.fullmatch(name):
            raise ValueError(f"{where}.bind must match {_BIND_NAME.pattern}")
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


def _validate_check(
    check: Any, strategy: str, where: str, transport: str = "http",
    inputs: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(check, dict):
        raise ValueError(f"{where} must be an object")
    discover, bound = _validate_discover(check.get("discover"))
    bound = bound | set(inputs or ())
    if discover and transport != "http":
        # Discovery enumerates a target by reading it and binding names. The
        # steps are HTTP requests, so over a socket there is nothing to run
        # them with -- better said plainly than silently ignored.
        raise ValueError(f"{where}.discover works over http only, not {transport}")
    out: dict[str, Any] = {"label": str(check.get("label", where)), "discover": discover}

    def _allowed(sequence: list[dict[str, Any]], what: str) -> None:
        missing = _substitutions(json.dumps(sequence)) - bound - {"marker", "callback"}
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
    auth = _validate_auth(spec.get("auth"), transport, inputs)
    out: dict[str, Any] = {
        "strategy": strategy,
        "transport": transport,
        "observable_effect": effect.strip(),
        "inputs": inputs,
        "auth": auth,
    }

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

    if spec.get("fixture") is not None:
        out["fixture"] = _validate_fixture(spec["fixture"])
    out["health_timeout"] = _seconds(
        spec.get("health_timeout"), "health_timeout",
        DEFAULT_HEALTH_TIMEOUT, MAX_HEALTH_TIMEOUT,
    )
    return out


# The deliverable. It is written once, reads the spec embedded beside it, and
# is the same program whether CVELab runs it against the built instance or the
# operator runs it against their server. It targets whatever --target names, so
# it has no loopback guard: running it is itself the operator's statement that
# they may test that host. It names the target and the effect on stderr before
# the first request, so a run against the wrong host is visible in the output
# and in whatever log captured it.
_FIELD_POC = r'''#!/usr/bin/env python3
"""@@CVE@@ - @@EFFECT@@

@@FACTS@@
Usage:
    python3 @@FILE@@ 10.0.0.5:8080
    python3 @@FILE@@ 10.0.0.5:8080 --show-bodies
    python3 @@FILE@@ https://app.example.com --insecure

Exit 0 and OBSERVED when the effect is present on that target, 1 and
NOT_OBSERVED when it is not. A NOT_OBSERVED is not a clean bill: the effect
may simply not be reachable with this input, or the instance may hold nothing
to disclose. To decide affected against fixed regardless of the data, check
the build. Any other ending is a run that did not finish, not a result.

It sends what the embedded spec names, and nothing else. It does not escalate,
create accounts, write files or plant anything to make the effect easier to
see, and it asks for no more than the observation needs. Read SPEC below to
see every request before you run it.

@@LEAVES@@
Requests carry User-Agent: CVELab-Field-PoC/1.0, so the target's own logs can
be matched to this run.
"""
from __future__ import annotations
import argparse, json, re, socket, socketserver, ssl, sys, threading, time
import urllib.error, urllib.parse, urllib.request, uuid

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
        port = port or {"ssh": 22, "smb": 445}.get(transport)
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
        self.ctx = None
        if self.transport == "http":
            base = normalize_target(base)
            parsed = urllib.parse.urlsplit(base)
            self.base = base.rstrip("/")
            if parsed.scheme == "https" and insecure:
                self.ctx = ssl.create_default_context()
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
            return
        self.host, self.port = normalize_target(base)
        self.base = "%s://%s:%s" % (self.transport, self.host, self.port)
        if self.transport == "tls":
            self.ctx = ssl.create_default_context()
            if insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE

    def fill(self, obj, ctx):
        """Substitute discovered names and the operator's own inputs.

        The inputs are merged here rather than into the context, because the
        context is printed and recorded with every finding: a credential
        passed on the command line must not end up in the output or in the
        JSON a report quotes.
        """
        return _subst(obj, dict(self.inputs, **ctx))

    def exchange(self, messages):
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
        req = urllib.request.Request(
            self.base + path,
            data=None if body is None else str(body).encode(),
            headers=headers,
            method=str(spec.get("method", "GET")).upper(),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return (r.status, r.read(8 * 1024 * 1024).decode("utf-8", "replace"),
                        dict(r.headers.items()))
        except urllib.error.HTTPError as e:
            # A refusal is a response, and for a status differential it is the
            # whole point: 401 here against 200 there is the finding.
            return (e.code, e.read(8 * 1024 * 1024).decode("utf-8", "replace"),
                    dict(e.headers.items() if e.headers else []))
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as e:
            raise SystemExit("cannot reach %s: %s" % (self.base, e))


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
                last = target.exchange(target.fill(step["query"], ctx))
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
    probe = target.exchange(target.fill(check["probe"], ctx))
    control = target.exchange(target.fill(check["control"], ctx))
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
    target.exchange(target.fill(check["probe"], local))
    obs_status, obs_body, _ = target.exchange(target.fill(check["observe"], local))
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
    response = target.exchange(target.fill(check["probe"], ctx))
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
        target.exchange(target.fill(check["probe"], local))
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
    p = argparse.ArgumentParser(description="CVELab field PoC for @@CVE@@")
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
    args = p.parse_args()
    where = args.target or args.target_positional
    if not where:
        p.error("name one target, as an argument or with --target")
    if args.target and args.target_positional:
        p.error("name the target once, not twice")
    oob = SPEC["strategy"] == "oob_callback"
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


if __name__ == "__main__":
    sys.exit(main())
'''


def _poc_facts(cve: str, spec: dict[str, Any], plan: dict[str, Any] | None) -> str:
    """The header an operator reads before running it.

    The shape a published single-file PoC has: what it is, what it affects,
    how it decides, and what it was tested against. The versions come from
    the lab, which installed them, so a reader can tell at a glance whether
    the host in front of them is even in range.
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
}

#: A session that authenticates leaves more than a request does, and the
#: operator should know before they run it, not after.
_SESSION_FOOTPRINT = (
    "It authenticates with the values you pass as --input, so those credentials travel\n"
    "to the target and its logs will show the session. Over ssh the commands in SPEC\n"
    "run as that account and nothing else does; read them before you run this.\n"
)


def _poc_footprint(spec: dict[str, Any]) -> str:
    text = _FOOTPRINTS[spec["strategy"]]
    if spec.get("transport") in HANDSHAKE_TRANSPORTS:
        text += "\n" + _SESSION_FOOTPRINT
    return text


def emit_field_poc(
    cve: str, spec: dict[str, Any], plan: dict[str, Any] | None = None,
    filename: str = "Manual-PoC.py",
) -> str:
    """The standalone deliverable, with the spec frozen into it.

    The fixture is dropped: it seeds CVELab's own validation instance and has
    no place in a script pointed at a server that already holds real data, and
    it would otherwise ship the fixture's markers and object ids inside the
    deliverable.
    """
    embedded = {key: value for key, value in spec.items() if key != "fixture"}
    text = json.dumps(embedded, indent=4)
    # The spec sits inside a triple-quoted raw string so a reviewer reads it
    # indented. JSON escapes every quote inside a string, so three in a row
    # cannot occur and the text always ends in a brace -- but the script is a
    # deliverable, so the invariant is checked rather than assumed.
    if '"""' in text or text.endswith("\\"):
        raise ValueError("the spec cannot be embedded verbatim in the deliverable")
    effect = spec["observable_effect"]
    if '"""' in effect:
        raise ValueError("observable_effect must not contain a triple quote")
    return (
        _FIELD_POC
        .replace("@@SPEC@@", text)
        .replace("@@FACTS@@", _poc_facts(cve, spec, plan))
        .replace("@@LEAVES@@", _poc_footprint(spec))
        .replace("@@FILE@@", filename)
        .replace("@@EFFECT@@", effect)
        .replace("@@CVE@@", cve)
    )


def _run_field_script(
    container: str, port: int, script: str, transport: str = "http",
    image: str = sidecar.BASE_IMAGE, inputs: dict[str, str] | None = None,
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
        "for name, value in given.items():\n"
        "    sys.argv += ['--input', '%s=%s' % (name, value)]\n"
        "runpy.run_path(str(home / 'field.py'), run_name='__main__')\n"
    )
    completed = subprocess.run(
        [
            "docker", "run", "--rm", "--network", f"container:{container}",
            "--security-opt", "no-new-privileges:true",
            *runtime_flags(),
            # A socket PoC takes a host and a port and refuses a URL, so the
        # form the sidecar passes has to follow the spec's transport.
        "-e", "CVELAB_BASE=" + (
            f"http://127.0.0.1:{port}" if transport == "http" else f"127.0.0.1:{port}"
        ),
            "-e", f"CVELAB_FIELD={script}",
            "-e", "CVELAB_INPUTS=" + json.dumps(inputs or {}),
            image, "python", "-c", bootstrap,
        ],
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
    """Start one image, seed it, and run the field PoC against it."""
    token = uuid.uuid4().hex[:12]
    name = f"cvelab-field-{cve.lower()}-{variant}-{token}"
    network_name = f"{name}-net"
    container_id = ""
    network_id = ""
    try:
        network_id = _docker(
            "network", "create", "--internal",
            "--label", "io.cvelab.managed=true",
            "--label", f"io.cvelab.cve={cve}",
            "--label", f"io.cvelab.run={token}",
            network_name,
        )
        container_id = _docker(
            "run", "-d", "--name", name,
            "--label", "io.cvelab.managed=true",
            "--label", f"io.cvelab.cve={cve}",
            "--label", f"io.cvelab.run={token}",
            "--security-opt", "no-new-privileges:true",
            *runtime_flags(),
            "--network", network_name, image,
        )
        base_url = f"http://{name}:{port}"
        _wait_ready(network_name, base_url, health_path,
                    int(spec.get("health_timeout", DEFAULT_HEALTH_TIMEOUT)))
        fixture = spec.get("fixture")
        applied = _apply_fixture(name, fixture) if fixture else None
        outcome = _run_field_script(
            name, port, script, spec.get("transport", "http"),
            sidecar.ensure_image({spec.get("transport", "http")}, True),
        )
        return {"variant": variant, "image": image, "fixture": applied, **outcome}
    finally:
        if container_id:
            current = _docker("inspect", "--format", "{{.Id}}", name, check=False)
            if current == container_id:
                _docker("rm", "-f", container_id, check=False)
        if network_id:
            current_net = _docker(
                "network", "inspect", "--format", "{{.Id}}", network_name, check=False
            )
            if current_net == network_id:
                _docker("network", "rm", network_id, check=False)


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
    cve = cve.upper()
    if not _CVE.fullmatch(cve):
        raise ValueError("invalid CVE identifier")
    if not 1 <= container_port <= 65535:
        raise ValueError("container port must be between 1 and 65535")
    if not health_path.startswith("/"):
        raise ValueError("health path must start with /")
    if not fixed_image:
        raise ValueError("field mode needs a fixed image to prove the effect is the bug")
    spec = validate_spec(json.loads(spec_path.read_text(encoding="utf-8")))
    script = emit_field_poc(cve, spec)

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

#: The artifact that leaves the lab: one script, one --target, run by the
#: operator against a server they are permitted to test. Named apart from
#: MANUAL-POC.md and manual.sh, which drive PoC.py inside the lab and reach
#: nothing outside it.
MANUAL_POC_NAME = "Manual-PoC.py"
MANUAL_POC_GUIDE_NAME = "Manual-PoC.md"

#: What the attempt found, written whether or not the script was handed over.
#: A spec that was refused is only fixable if the reason survives the run.
MANUAL_POC_RECORD_NAME = "Manual-PoC.json"


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
    "while time.monotonic() < deadline:\n"
    "    try:\n"
    "        socket.create_connection(('127.0.0.1', port), timeout=3).close()\n"
    "        raise SystemExit(0)\n"
    "    except OSError:\n"
    "        time.sleep(2)\n"
    "raise SystemExit(1)\n"
)


def _wait_container_port(container: str, port: int, timeout: int) -> bool:
    """Wait for a service to answer on its own port, from inside its namespace.

    For a lab that declares no healthcheck, where `up --wait` returns as soon
    as the container is running and a probe would then race the application's
    own startup.
    """
    completed = subprocess.run(
        [
            "docker", "run", "--rm", "--network", f"container:{container}",
            "--security-opt", "no-new-privileges:true",
            *runtime_flags(),
            "python:3.13-alpine", "python", "-c", _PORT_READY, str(port), str(timeout),
        ],
        capture_output=True, text=True, timeout=timeout + 60, check=False,
    )
    return completed.returncode == 0


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
    for name in probe:
        container = _service_container(compose, name, lab_dir, environment)
        if not container:
            raise RuntimeError(f"{name} did not start")
        if not _wait_container_port(container, port, timeout):
            raise RuntimeError(
                f"{name} did not answer on port {port} within {timeout}s; "
                "pass --container-port for the port the service listens on"
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
    """Emit the single-target script and say whether it earned the handover.

    The lab's own proof is the differential between two builds it controls,
    and that proof cannot leave the lab: PoC.py is the validator, bound to the
    service names, and contract-checked to reach no other host. This is the
    other artifact, and it is held to the same bar -- the effect against the
    vulnerable build, silence against the fixed one. A script that fires on
    both is watching normal behaviour rather than the bug; one that crashed
    observed nothing because it never looked. Neither is handed over.

    The script is run from a sidecar joined to each service container's network
    namespace, so `--target 127.0.0.1` reaches the product although the lab
    publishes no port and its network is internal, and the script CVELab proves
    is byte for byte the one the operator receives.

    Returns the outcome, carrying the script text under "script" when it
    passed. Nothing here raises: the caller records the outcome either way.
    """
    try:
        # Before anything is probed: a handshake transport needs a library in
        # the sidecar, which cannot be fetched once it is in the lab's
        # internal network, and building it is the operator's to agree to.
        missing = [name for name in spec.get("inputs") or () if name not in (inputs or {})]
        if missing:
            # Said before anything is built: without these the script refuses
            # to start, and the proof would read that as the effect being absent.
            return {
                "shipped": False,
                "reason": "this spec needs values only you have: "
                          + ", ".join(missing)
                          + ". Pass each as --input NAME=VALUE",
            }
        image = sidecar.ensure_image({spec.get("transport", "http")}, assume_yes)
        script = emit_field_poc(cve, spec, plan, MANUAL_POC_NAME)
        containers = {
            name: _service_container(compose, name, lab_dir, environment)
            for name in ("vulnerable", "patched")
        }
        missing = [name for name, cid in containers.items() if not cid]
        if missing:
            return {"shipped": False, "reason": f"no running container for {', '.join(missing)}"}
        runs = {
            name: _run_field_script(
                cid, port, script, spec.get("transport", "http"), image, inputs
            )
            for name, cid in containers.items()
        }
    except Exception as error:  # noqa: BLE001 - the outcome is the report
        return {"shipped": False, "reason": f"{type(error).__name__}: {error}"[:600]}

    vulnerable, patched = runs["vulnerable"], runs["patched"]
    both_ran = bool(vulnerable["ran"] and patched["ran"])
    proven = bool(both_ran and vulnerable["observed"] and not patched["observed"])
    outcome: dict[str, Any] = {
        "shipped": proven,
        "strategy": spec["strategy"],
        "observable_effect": spec["observable_effect"],
        "container_port": port,
        "proof_checks": {
            "script_ran_on_both": both_ran,
            "effect_observed_on_vulnerable": bool(vulnerable["observed"]),
            "silent_on_fixed": bool(patched["ran"] and not patched["observed"]),
            "manual_poc_proven": proven,
        },
        "runs": {
            name: {key: run[key] for key in ("observed", "ran", "verdict", "exit_code")}
            for name, run in runs.items()
        },
    }
    if proven:
        outcome["script"] = script
        return outcome
    outcome["reason"] = (
        "the script did not tell the two builds apart"
        if both_ran
        else "the script did not finish against both builds"
    )
    # Kept because a spec that was refused is only fixable if the run that
    # refused it is visible: a generic reason sends the operator back to guess.
    outcome["output"] = {
        name: {"stderr": run["stderr"], "tail": run["output"][-2000:]}
        for name, run in runs.items()
    }
    return outcome


def run_manual_poc(
    lab_dir: Path,
    spec_path: Path | None = None,
    container_port: int | None = None,
    keep: bool = False,
    assume_yes: bool = False,
    inputs: dict[str, str] | None = None,
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
    plan = _lab_plan(lab_dir)
    cve = str(plan.get("cve") or lab_dir.name).upper()
    if plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION":
        raise RuntimeError(
            f"{cve} has no fixed build, so a script cannot be shown to go silent against "
            "one; without that half the proof is missing"
        )
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
    timeout = int(spec.get("health_timeout", DEFAULT_HEALTH_TIMEOUT)) + startup_grace()

    services = list(plan.get("startup_services") or [])
    for required in ("vulnerable", "patched"):
        if required not in services:
            services.append(required)

    docker, environment, compose, scratch = prepare_compose(lab_dir)
    try:
        resolved = _resolved_compose(compose, lab_dir, environment)
        _bring_up(
            services, ["vulnerable", "patched"], container_port, timeout,
            lab_dir, compose, docker, environment, resolved,
        )
        progress.step("proving the single-target script against both builds")
        outcome = prove_manual_poc(
            cve, spec, container_port, lab_dir, compose, environment, plan,
            assume_yes, inputs,
        )
    finally:
        if not keep:
            subprocess.run(
                compose + ["down", "--volumes", "--remove-orphans"],
                cwd=lab_dir,
                env=environment,
            )
        shutil.rmtree(scratch, ignore_errors=True)

    write_manual_poc(cve, lab_dir, plan, spec, container_port, outcome)
    if not outcome["shipped"]:
        progress.step(f"nothing handed over: {outcome.get('reason')}")
    return {"ok": bool(outcome["shipped"]), "cve": cve, "lab_dir": str(lab_dir), **outcome}


def _manual_poc_guide(cve: str, spec: dict[str, Any], plan: dict[str, Any], port: int) -> str:
    """What the operator needs beside the script, and nothing more."""
    strategy = spec["strategy"]
    how = (
        "It reads the same resource two ways in one request round -- the way the "
        "vulnerability allows and the way that authorizes correctly -- and reports "
        "what only the first returned. A value it prints is one the server "
        "disclosed to a requester that should not have seen it."
        if strategy == "inband_differential"
        else "It sends a marker, fresh on every run, through the vulnerable vector and "
        "looks for it where it should not appear. Because the marker is new each "
        "time, a reflection left by an earlier run is never counted."
    )
    leaves = (
        "This strategy only reads, so it leaves nothing behind."
        if strategy == "inband_differential"
        else "This strategy sends one inert random marker, `cvelab-<16 hex>`, through the "
        "vulnerable vector, because a reflection or storage bug cannot be shown "
        "without sending something. Where the vector stores what it is given, that "
        "marker stays until someone removes it -- this script does not remove it, so "
        "tell the owner and clean it up."
    )
    return f"""# {cve} Manual PoC

A single-target script you run yourself, against one server you are permitted to
test. It shows the vulnerability happening: {spec['observable_effect']}

This is not the lab's proof. `PoC.py` is: it compares the vulnerable and the
fixed build inside Docker and reaches nothing else. This script is the other
artifact, the one that leaves the lab.

## Run it

```bash
cd {cve}/artifacts
python3 {MANUAL_POC_NAME} --target 10.0.0.5:8080 --show-bodies
```

`--target` is one host and port, however you write it: `10.0.0.5:8080`,
`[2001:db8::1]:8443`, `app.example.com` or `https://app.example.com`. Without a
scheme it assumes `http`, except on port 443. Every request path comes from the
embedded spec, so the target carries none.

Without `--show-bodies` each disclosed value is cut at 120 characters; with it
they print in full, which is what a report needs as evidence. Add `--insecure`
for a self-signed certificate and `--json` for machine-readable findings.

It names the target and the effect on stderr before it sends anything, so the
run is visible in the output and in whatever log captured it. It sends live
requests and reads what comes back, so point it only at a host your engagement
covers, and keep that permission in writing: the effect it demonstrates is real
data leaving a real server.

## Rehearse it first

`cvelab demo-target up <lab-dir>` starts this lab's vulnerable build on a
network your host can reach and prints the host and port to point at, so you
can see the run end to end before it touches anyone else's server. The fixed
build is never started, and `cvelab demo-target down <lab-dir>` puts the lab
back.

## What it means

`OBSERVED`, exit 0, is the effect on that target. `NOT_OBSERVED`, exit 1, means
the effect was not seen there with this input -- which is not the same as
patched. A differential strategy also prints it when the instance simply held
nothing to disclose. To decide affected against fixed regardless of the data,
check the build.

Any other ending is a run that did not finish, not a result.

## How it decides

- Strategy: `{strategy}`
- {how}

## What it does to the target

It sends the requests in its embedded `SPEC` and nothing else. It does not
escalate, create accounts, write files, or plant anything to make the effect
easier to see. Read `SPEC` to see every request before you run it. The requests
carry `User-Agent: CVELab-Field-PoC/1.0`, so the target's own logs can be
matched to your run.

{leaves}

## Why you can trust it

CVELab built both revisions of {plan.get('repository') or 'the affected project'}
and ran this exact script against each, on port {port} inside the container,
before writing it here. It observed the effect on the vulnerable build and
stayed silent on the fixed one. A script that fired on both would be watching
normal behaviour rather than the bug, and would not have been written.
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
    """The container's own address on its first network, as the host reaches it."""
    shown = _docker(
        "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
        container, check=False,
    )
    for candidate in shown.split():
        if candidate:
            return candidate
    return ""


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
            subprocess.run(
                compose + ["down", "--volumes", "--remove-orphans"],
                cwd=lab_dir,
                env=environment,
            )
            progress.step(f"{cve} is back to its sealed posture")
            return {"ok": True, "cve": cve, "lab_dir": str(lab_dir), "running": False}

        record = lab_dir / "artifacts" / MANUAL_POC_RECORD_NAME
        port = container_port
        if port is None and record.exists():
            with contextlib.suppress(json.JSONDecodeError, TypeError, ValueError):
                port = int(json.loads(record.read_text(encoding="utf-8"))["container_port"])
        if port is None:
            raise RuntimeError(
                "No port to point at: pass --container-port, or run `cvelab manual-poc` "
                f"first, which records the one it proved in artifacts/{MANUAL_POC_RECORD_NAME}"
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
        address = _container_address(container) if container else ""
        if not address:
            raise RuntimeError("the vulnerable build started but has no address to reach")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    target = f"{address}:{port}"
    script = lab_dir / "artifacts" / MANUAL_POC_NAME
    progress.step(f"{cve} vulnerable build is reachable at {target}")
    if script.is_file():
        progress.step(f"python3 {script} --target {target} --show-bodies")
    progress.step(f"this lab is reachable from the host until: cvelab demo-target down {lab_dir}")
    return {
        "ok": True,
        "cve": cve,
        "lab_dir": str(lab_dir),
        "running": True,
        "target": target,
        "manual_poc": str(script) if script.is_file() else None,
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
    "required": ["feasible", "reason", "container_port", "spec_json"],
    "properties": {
        "feasible": {"type": "boolean"},
        "reason": {"type": "string"},
        "container_port": {"type": ["integer", "null"]},
        "spec_json": {"type": ["string", "null"]},
    },
}

_DRAFT_INSTRUCTIONS = (
    "A CVE reproduction lab has already been built and validated: it compiled a vulnerable "
    "and a fixed revision of the project, ran its validator against both, and confirmed the "
    "effect occurs on the vulnerable revision and not on the fixed one. That work is "
    "finished and recorded, and nothing in your answer changes it.\n\n"
    "Decide one thing. Can the effect the lab already confirmed also be observed on a single "
    "running instance over HTTP, with no second instance to compare against, no out-of-band "
    "listener, and no destructive or state-changing action beyond what the observation needs? "
    "Many vulnerabilities cannot: a crash or hang, a race, a timing or memory signal, a "
    "library with no listener, anything needing a callback or a second host. When this one "
    "cannot, answer feasible=false and give the reason. That is the expected answer for most "
    "labs and is not a failure -- prefer it over a guess.\n\n"
    "When it can, answer feasible=true, give container_port, the port the service listens on "
    "inside its container, and put the spec in spec_json as a JSON string with these keys.\n"
    "  transport: http when the service speaks HTTP, which is the default and may be left "
    "out; tcp when it speaks its own protocol over a plain socket, a cache, a queue, a "
    "database or a daemon with a text protocol; tls for the same wrapped in TLS; ssh when "
    "the weakness is in what an authenticated session may do, such as a file an account "
    "should not be able to read or a restricted shell that can be escaped; smb when it is "
    "in what a share or a path exposes. The service not speaking HTTP is not a reason to "
    "answer feasible=false.\n"
    "  Over ssh a message is {\"exec\": \"<command>\"} and what the sequence returns is "
    "the output; over smb it is {\"op\": \"list_shares\"} or {\"op\": \"list_path\", "
    "\"share\": \"<name>\", \"path\": \"/\"} or {\"op\": \"read\", \"share\": "
    "\"<name>\", \"path\": \"/file\"}. Both authenticate through auth, whose values "
    "come from inputs, as {\"username\": \"{{user}}\", \"password\": "
    "\"{{password}}\"} -- never a credential written into the spec. These reach access "
    "and what a session is permitted to do; they are not a way to attack the handshake, so "
    "do not propose one for a flaw in the protocol implementation itself.\n"
    "  strategy: direct_observation, inband_differential, marker_roundtrip or "
    "oob_callback, exactly one of those four spellings and no other.\n"
    "  observable_effect: one sentence naming what a run shows.\n"
    "  For direct_observation, which fits most authorization and disclosure findings and "
    "is the one to reach for first: probe, a list of requests asking the way the weakness "
    "allows, and expect, exactly one of {\"status\": 200} when the finding is that the "
    "route answered at all, {\"header\": \"<name>\"} when the evidence is a response "
    "header, {\"body_contains\": \"<text>\"} for a literal, or {\"extract\": {...}} "
    "when a value has to be pulled out. The effect is that this response came back at all; "
    "CVELab checks that a fixed build does not produce it, so no second reading is needed. "
    "Do not use inband_differential for this shape: comparing an unauthenticated read "
    "against an authorized one finds nothing on the vulnerable build, because both see the "
    "data, and finds the refusal on the fixed build, which is backwards.\n"
    "  For inband_differential, when the same reading authorized correctly genuinely "
    "withholds part of what the weakness returns, such as a field a different query shape "
    "hides: probe, a list of requests reading the resource the way the "
    "weakness allows; control, a list of requests reading the same resource the way that "
    "authorizes correctly; and extract, either {\"json_values\": \"<key>\"} or "
    "{\"regex\": \"<pattern>\"}. A run reports what probe returned and control did not, so "
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
    "  For marker_roundtrip: probe, a list of requests of which at least one places the "
    "literal {{marker}}; observe, one request; and match, {\"body_contains\": \"{{marker}}\"}. "
    "Only observe's body is read and the probe responses are discarded, so when the effect is "
    "visible only in the response to the request that causes it, that request belongs in "
    "observe.\n"
    "  Over http a request is {\"method\": \"GET\", \"path\": \"/x\", \"headers\": {}, "
    "\"body\": null}, and each one stands alone. Over tcp or tls a message is instead "
    "{\"send\": \"<text, with \\r\\n where the protocol needs it>\", "
    "\"read_until\": \"<the reply delimiter>\"}, or send_hex with an even-length hex string "
    "when the framing is not text; a whole sequence shares one connection, so a protocol "
    "needing a login or a handshake command first is expressed by putting it earlier in the "
    "same list, and what a sequence returns is everything read during it. Sending nothing and "
    "only reading is allowed, which is how a banner is taken.\n"
    "  Paths and messages name no host: the operator supplies the one target at run time, so "
    "a hostname anywhere in the spec is wrong. Over tcp and tls there is no discover chain.\n"
    "  inputs: a list of names for values this lab cannot know and the operator supplies at "
    "run time, such as a test account's credential or a tenant id. A request fills one in as "
    "{{name}}. Declare one rather than guessing a credential, and rather than answering "
    "feasible=false because a value is missing.\n"
    "  A check may also carry discover, steps that read identifiers from the instance and bind "
    "them for probe and control to fill in as {{name}}, so the spec does not name objects this "
    "lab happened to create and works against an instance holding its own data.\n\n"
    "CVELab emits one script from your spec and runs it against both of the lab's builds. It "
    "is kept only if it observes the effect on the vulnerable build and stays silent on the "
    "fixed one, so a spec that watches ordinary behaviour is discarded rather than shipped."
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
    ):
        path = lab_dir / name
        if not path.is_file():
            continue
        found = re.search(pattern, path.read_text(encoding="utf-8", errors="replace"))
        if found and 1 <= int(found.group(1)) <= 65535:
            return int(found.group(1))
    return None


#: The validator's own attack is the best description of the effect there is:
#: it holds the exact requests that trigger it and how the response was
#: recognised, which is what a spec needs and what a prose contract leaves
#: out. Drafts were declining for want of a response shape to extract from.
_MAX_VALIDATOR_CHARS = 20_000


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
) -> dict[str, Any]:
    """Ask once whether the confirmed effect can be shown on one instance.

    Returns a dict with "spec" and "container_port" when the answer is usable,
    or "reason" when it is not. It never raises: the caller records whatever
    comes back and the lab stands either way.
    """
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
                "container_port": _port_hint(lab_dir) if lab_dir else None,
                "validator_that_proved_it": _validator_source(lab_dir) if lab_dir else "",
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
            or "the model judged the effect not observable on one instance"
        }
    offered = answered.get("spec_json")
    if not isinstance(offered, str) or not offered.strip():
        return {"reason": "the answer said feasible but carried no spec"}
    try:
        spec = validate_spec(json.loads(offered))
    except json.JSONDecodeError as error:
        return {"reason": f"spec_json was not valid JSON: {error}"}
    except (ValueError, TypeError) as error:
        # Named precisely: two of two DeepSeek drafts were rejected for shape,
        # once for a strategy it invented and once for an empty probe, and a
        # bare "not usable" left nothing to correct.
        return {"reason": f"the drafted spec is not usable: {error}"}
    port = answered.get("container_port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        # The lab states it in its healthcheck, so an answer that leaves it
        # out is not a reason to throw an otherwise usable spec away.
        port = _port_hint(lab_dir) if lab_dir else None
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return {"reason": "the answer gave no port the service listens on"}
    return {"spec": spec, "container_port": port}


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
        if plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION":
            return {
                "shipped": False,
                "reason": "no fixed build for the script to go silent against",
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
        spec, port = drafted["spec"], drafted["container_port"]
        progress.step("proving the single-target script against both builds")
        outcome = prove_manual_poc(
            cve, spec, port, lab_dir, compose, environment, plan, assume_yes, inputs
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
    """Write the record always, and the script and its guide only if proven.

    The record goes down either way: a spec that was refused is only fixable
    if the run that refused it survives, and `demo-target` reads the port from
    it. The outcome is edited in place, so the script text never reaches
    report.json.
    """
    artifacts = lab_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    script = str(outcome.pop("script", ""))
    write_text(
        artifacts / MANUAL_POC_RECORD_NAME,
        json.dumps({"cve": cve, **outcome}, indent=2, ensure_ascii=True) + "\n",
    )
    if not script:
        return outcome
    target = artifacts / MANUAL_POC_NAME
    write_text(target, script)
    target.chmod(0o755)
    write_text(artifacts / MANUAL_POC_GUIDE_NAME, _manual_poc_guide(cve, spec, plan, port))
    outcome["deliverables"] = {
        "manual_poc": str(target),
        "guide": str(artifacts / MANUAL_POC_GUIDE_NAME),
        "record": str(artifacts / MANUAL_POC_RECORD_NAME),
    }
    return outcome
