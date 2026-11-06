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

"""The grammar for putting a lab into the state an attack needs.

A lab starts empty. An attack that acts on an object -- a document, an
account, a session, a record -- finds nothing there unless something puts it
there first, and an attack that never ran is indistinguishable from one the
fixed build refused: both show no effect. An unverified proof is the largest
measured failure class, and one shape inside it is a lab that never delivered
its attack at all because it could not establish the state the attack needed:
a mobile security framework lab reported `victim session not established` on
both services while its login answered 200.

This module is the vocabulary for saying that in data instead of in prose.
A setup step is a request, or a request whose answer binds a name for the
requests that follow, and the binding is the irreplaceable part: an admin key
generated fresh on each boot cannot be recorded as a fixed lab value, so
reading it out of a response is the only way a spec can name it.

It holds the grammar and its validators, and no runner. Running the steps
needs a route to the lab, and that route differs by mode -- a single-target
script's proof reaches one container's network namespace, a generated source
lab has an internal compose network and no container id to hand -- so each
mode brings its own.

Nothing here imports from the rest of the package, and nothing here speaks to
a network. That is deliberate rather than tidy: the step that validates a
model's answer runs before anything is built, and it has to be able to read
this grammar without importing a mode that brings a provider and Docker with
it.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable, Sequence
from typing import Any

#: The marker the operator's script generates fresh per run, so a stored
#: reflection from an earlier run is never mistaken for this one's.
MARKER_TOKEN = "{{marker}}"

#: The target as the operator wrote it, and its host alone. A spec cannot
#: name a host -- the operator supplies that at run time -- but some effects
#: are about the target's own address: an Origin or Referer the server is
#: supposed to reject, a DNS-rebinding check, a redirect back to itself. A
#: measured lab reproduced and then had no spec for exactly this reason.
TARGET_TOKENS = ("target", "targetHost")

#: How many entries one sequence may hold, whatever it is a sequence of.
MAX_REQUESTS = 25

#: A name a discover step or an input binds, used only as a substitution key.
#: Lowercase-only was arbitrary and cost a measured lab its spec: the draft
#: was otherwise right and bound oauthState, so a correct answer was thrown
#: away over a letter's case.
BIND_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")

#: Where the evidence is read from. Only bodies could be read at first, which
#: left two measured labs unprovable for no reason to do with their CVE: one
#: disclosed a token in a response header, and one differed only in its status
#: code, 200 against 401. Both are the ordinary shape of an authorization
#: finding, so both are read now.
EXTRACTORS = ("json_values", "regex", "header", "status")

#: Values the operator supplies at run time, which the lab cannot know: a test
#: account's credential, a tenant id, a licence key. A control request that
#: has to read a resource "the correctly authorized way" needs one, and
#: without them that whole shape of check could not be written.
MAX_INPUTS = 8


def validate_inputs(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_INPUTS:
        raise ValueError(f"inputs must be a list of at most {MAX_INPUTS} names")
    names = []
    for offered in value:
        name = str(offered)
        if not BIND_NAME.fullmatch(name):
            raise ValueError(f"inputs name {name!r} must match {BIND_NAME.pattern}")
        if name in ("marker", "callback", *TARGET_TOKENS):
            raise ValueError(f"inputs cannot redefine {{{{{name}}}}}")
        if name in names:
            # One name twice spends two of the eight slots asking for one
            # value, and nothing downstream can see the difference: every
            # membership test on inputs -- validate_setup's `name not in
            # set(inputs)` among them -- answers a duplicate exactly as it
            # answers a single declaration. So a spec that meant two values
            # and wrote one name twice would validate, be filled from one
            # answer, and send that one answer in both places.
            raise ValueError(f"inputs declares {name!r} twice")
        names.append(name)
    return names


def substitutions(text: str) -> set[str]:
    return set(re.findall(r"\{\{([A-Za-z][A-Za-z0-9_]*)\}\}", text))


#: What "begins with a substitution" has to mean for a path: a whole
#: {{name}}, not an opening brace. The rule was spelled `startswith("{{")`,
#: which the bare string "{{" satisfies, and nothing downstream caught it --
#: substitutions() finds no name in it, so validate_setup's missing-name
#: check has nothing to report, and the first thing to notice is the shipped
#: script's "request path must be relative" at run time, on a path that was
#: never fillable by anything. The latitude the exception grants is a route
#: the operator names; a path that names nothing is outside it.
PATH_SUBSTITUTION = re.compile(r"\{\{[A-Za-z][A-Za-z0-9_]*\}\}")


def validate_request(request: Any, where: str) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ValueError(f"{where} must be an object")
    path = str(request.get("path", "/"))
    if not (path.startswith("/") or PATH_SUBSTITUTION.match(path)):
        # A path that begins with a substitution is the one exception, and it
        # is what makes a library CVE expressible: nobody runs a library, they
        # run an application that calls it, and that application's route is
        # the operator's to name. The lab's own adapter route stands in for it
        # while the script is proved here. What the value has to be is checked
        # where it is known -- the script refuses a filled path that is not
        # relative, so an operator passing a whole URL is told so rather than
        # sending a request somewhere else entirely.
        raise ValueError(
            f"{where} path must start with / or with a substitution naming an input"
        )
    method = str(request.get("method", "GET")).upper()
    headers = request.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError(f"{where} headers must be an object")
    body = request.get("body")
    if isinstance(body, (dict, list)):
        # A JSON body written as an object is what anyone means, and demanding
        # the escaped string form cost a lab its spec for nothing: the draft
        # was otherwise correct and was thrown away over quoting. Serialised
        # here, so what the script sends is still one exact string.
        body = json.dumps(body)
    elif body is not None and not isinstance(body, str):
        raise ValueError(f"{where} body must be a string or a JSON object")
    out: dict[str, Any] = {
        "method": method,
        "path": path,
        "headers": {str(k): str(v) for k, v in headers.items()},
        "body": body,
    }
    if request.get("upload") is not None:
        if body is not None:
            raise ValueError(f"{where} takes body or upload, not both")
        out["upload"] = validate_upload(request["upload"], f"{where}.upload")
    return out


#: Parts in one upload. A few: this is a form, not a filesystem.
MAX_UPLOAD_PARTS = 6

#: What one part's content may be built from, besides a plain form field.
PART_CONTENT = ("text", "base64", "tar_gz", "zip")


def validate_upload(value: Any, where: str) -> list[dict[str, Any]]:
    """A multipart/form-data body, with its file parts built at run time.

    Three labs that reproduced were refused a manual PoC over this, the last
    of them naming it outright: "the precondition needs a denied report.dat
    uploaded through the user files API as multipart", and before it, "the
    effect is a write of a gzip-compressed tar bundle ... a binary gzip
    archive cannot be expressed faithfully". A crafted upload is a whole
    class of weakness -- an archive that escapes its extraction root, a file
    whose name or type a filter should have refused -- and it was the one
    thing a spec could not say.
    """
    if not isinstance(value, list) or not value:
        raise ValueError(f"{where} must be a non-empty list of parts")
    if len(value) > MAX_UPLOAD_PARTS:
        raise ValueError(f"{where} may hold at most {MAX_UPLOAD_PARTS} parts")
    parts = []
    for index, part in enumerate(value):
        at = f"{where}[{index}]"
        if not isinstance(part, dict):
            raise ValueError(f"{at} must be an object")
        name = str(part.get("name", "")).strip()
        if not name:
            raise ValueError(f"{at}.name must be the form field's name")
        kinds = [kind for kind in PART_CONTENT if part.get(kind) is not None]
        if "value" in part and not kinds:
            parts.append({"name": name, "value": str(part["value"])})
            continue
        if len(kinds) != 1:
            raise ValueError(
                f"{at} needs value for a form field, or exactly one of "
                f"{', '.join(PART_CONTENT)} for a file part"
            )
        kind = kinds[0]
        built: dict[str, Any] = {
            "name": name,
            "filename": str(part.get("filename") or name),
            "content_type": str(part.get("content_type") or "application/octet-stream"),
            "kind": kind,
        }
        if kind == "text":
            built["text"] = str(part["text"])
        elif kind == "base64":
            raw = str(part["base64"])
            # Checked before the encoding is, because a marker here is the
            # mistake worth naming: it would be sent as six literal
            # characters inside the bytes, or refused as bad base64, and
            # neither says what to do instead.
            if MARKER_TOKEN in raw:
                raise ValueError(
                    f"{at}.base64 cannot carry {MARKER_TOKEN}; put the marker in a "
                    "text, tar_gz or zip part, which are built at run time"
                )
            try:
                base64.b64decode(raw, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError(f"{at}.base64 is not valid base64: {error}") from error
            built["base64"] = raw
        else:
            files = part[kind]
            if not isinstance(files, dict) or not files:
                raise ValueError(f"{at}.{kind} must map a file name to its text")
            if any(not str(n).strip() or not isinstance(t, str) for n, t in files.items()):
                raise ValueError(f"{at}.{kind} names must be text and so must their contents")
            built[kind] = {str(n): t for n, t in files.items()}
        parts.append(built)
    return parts


def validate_sequence(
    value: Any,
    where: str,
    one: Callable[[Any, str], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """A sequence of requests, or of socket exchanges on one connection.

    Over a socket the whole sequence shares one connection, because a
    protocol that needs a login before a command cannot be expressed as
    independent messages. HTTP requests stay independent, as they were.

    `one` validates a single entry. It defaults to validate_request, which is
    what a setup step and an HTTP probe both hold; a mode whose entry is a
    socket exchange or a session operation passes its own, so the transports
    that need one stay where they are run from.
    """
    if not isinstance(value, list) or not value:
        raise ValueError(f"{where} must be a non-empty list")
    if len(value) > MAX_REQUESTS:
        raise ValueError(f"{where} may hold at most {MAX_REQUESTS} requests")
    if one is None:
        one = validate_request
    return [one(item, f"{where}[{index}]") for index, item in enumerate(value)]


def validate_extractor(value: Any) -> dict[str, Any]:
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


#: How many requests may put the lab in the state the proof needs. Small on
#: purpose: this is seeding, and a spec that needs more than this is
#: describing a workflow rather than a precondition.
#:
#: Counted in requests, not entries, because a binding entry holds a whole
#: sequence: ten entries each carrying MAX_REQUESTS in their query validated
#: clean and sent 250 requests, which is the workflow this bound exists to
#: refuse. Measured by construction once the grammar was lifted out, before
#: anything was mounted on it.
MAX_SETUP_REQUESTS = 10


def validate_setup(value: Any, inputs: Sequence[str]) -> list[dict[str, Any]]:
    """Steps that put this lab in the state the effect needs.

    They are HTTP whatever the probe speaks, because a seeding route is: the
    lab's own /lab/seed, an admin API, a sign-up. An entry is a request, or
    {"bind": name, "query": [requests], "extract": {...}} to read a value out
    of one and fill it in for what follows.

    That reading is what a fixed lab value cannot replace. A nebula-mesh lab
    reproduced end to end and was refused a script because the effect needs a
    non-admin API key, and "that admin key is generated fresh on each run, so
    no fixed lab value can be recorded for it". A name bound here has to be
    declared in inputs as well: the shipped script asks the operator for
    their own, and this only supplies the lab's for the proof.

    A step may use only a name an earlier step bound, as in the discover
    chain. The membership check alone cannot say that here: a bound name is
    also a declared input, so a reference to a name the next step binds is
    spelled exactly like a reference to an input the operator supplies, and
    the first is filled left to right by the runner and would go out as the
    literal {{name}}. Which step binds what is therefore read once, before
    the loop, so the ordering can be checked at all.
    """
    if not isinstance(value, list) or not value:
        raise ValueError("setup must be a non-empty list of steps")
    if len(value) > MAX_SETUP_REQUESTS:
        # Entries first, so an absurd list is refused before every entry in it
        # is validated. Requests are never fewer than entries, so nothing that
        # passes the real bound below can fail here.
        raise ValueError(f"setup may hold at most {MAX_SETUP_REQUESTS} requests")
    out: list[dict[str, Any]] = []
    known = set(inputs) | set(TARGET_TOKENS)
    binds_at: dict[str, int] = {}
    for index, item in enumerate(value):
        if isinstance(item, dict) and "bind" in item:
            binds_at.setdefault(str(item.get("bind") or ""), index)
    bound: set[str] = set()

    def refuse_forward_use(used: set[str], index: int, at: str) -> None:
        # At or after this step's own index: a step's own query runs before
        # its extractor, so naming what it is about to bind is as unfillable
        # as naming what a later step binds.
        early = sorted(name for name in used if binds_at.get(name, -1) >= index)
        if early:
            raise ValueError(
                f"{at} uses {early}, which setup binds at or after this step; a step "
                "may use only a name an earlier step bound, or one inputs declares "
                "and setup does not bind"
            )

    for index, item in enumerate(value):
        at = f"setup[{index}]"
        if isinstance(item, dict) and "bind" in item:
            name = str(item.get("bind") or "")
            if not BIND_NAME.fullmatch(name):
                raise ValueError(f"{at}.bind {name!r} must match {BIND_NAME.pattern}")
            if name in bound:
                # As the discover chain refuses it. Two steps binding one
                # name leaves the second silently winning for everything
                # after it, and no reading of the spec says which was meant.
                raise ValueError(f"{at}.bind {name!r} is already bound")
            if name not in set(inputs):
                raise ValueError(
                    f"{at}.bind {name!r} must also be declared in inputs, so the script "
                    "the operator receives asks them for their own value"
                )
            query = validate_sequence(item.get("query"), f"{at}.query")
            used = substitutions(json.dumps(query))
            missing = used - known
            if missing:
                raise ValueError(f"{at}.query uses names nothing binds: {sorted(missing)}")
            refuse_forward_use(used, index, f"{at}.query")
            out.append({
                "bind": name, "query": query,
                "extract": validate_extractor(item.get("extract")),
            })
            bound.add(name)
            continue
        request = validate_request(item, at)
        used = substitutions(json.dumps(request))
        missing = used - known
        if missing:
            raise ValueError(f"{at} uses names nothing binds: {sorted(missing)}")
        refuse_forward_use(used, index, at)
        out.append(request)
    sent = sum(len(step["query"]) if "query" in step else 1 for step in out)
    if sent > MAX_SETUP_REQUESTS:
        raise ValueError(
            f"setup would send {sent} requests, more than the {MAX_SETUP_REQUESTS} "
            "this bound allows; seeding puts the lab in one state, and a sequence "
            "this long is the workflow the bound refuses"
        )
    return out
