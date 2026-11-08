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
import time
from collections.abc import Callable
from pathlib import Path

from . import progress, usage
from .ai import ProviderDeclined, ai_is_configured, provider_supports_web_search
from .closed_auto import run_closed_auto
from .core import (
    SETUP_FAILURE_MARKER,
    AfterValidation,
    CVERecordNotFound,
    normalize_cve,
    run_lab,
    write_text,
)
from .deliverables import create_deliverables
from .sourcegen import generate_source_lab, repair_source_lab

Progress = Callable[[str], None]


def _default_progress(message: str) -> None:
    progress.step(message)


def _infrastructure_failure(message: str) -> bool:
    lowered = message.lower()
    indicators = (
        "docker engine recovery failed",
        "docker cli was not found",
        "permission denied while trying to connect",
        "cannot connect to the docker daemon",
        "is the docker daemon running",
        "no space left on device",
        "openai api http 401",
        "openai api http 403",
        "openai_api_key is not set",
        "anthropic_api_key is not set",
        "anthropic api http 400",
        "anthropic api http 404",
        "anthropic reached max_tokens",
        "anthropic refused structured generation",
        "anthropic response did not contain structured output",
        "could not connect to local api",
        "cvelab_model is not set",
    )
    return any(indicator in lowered for indicator in indicators)


_STARTUP_MARKERS = (
    "dependency failed to start",
    "is unhealthy",
    "docker stage 'startup' failed",
    "lab service did not become healthy",
)


def _setup_failure(message: str) -> bool:
    """Whether CVELab's own setup steps did not put the lab into state.

    `core.run_setup` raises with SETUP_FAILURE_MARKER in the message, and
    the marker is imported rather than spelled again here: core owns the
    sentence and this only recognises it, so the two cannot drift apart.

    It sits between a startup failure and an unproved effect, and it is
    narrower than either. By the time the steps run, the build has produced
    its images and the services have passed the health gate the lab's own
    validator declares -- the setup service waits on exactly that
    `depends_on` -- so a message carrying this marker is never a build that
    failed and never a service that did not come up, whatever the
    diagnostics appended to it say.
    """
    return SETUP_FAILURE_MARKER.lower() in message.lower()


def _startup_failure(message: str) -> bool:
    """Whether a run ended because the lab's services never came up.

    The validator only runs once its targets are healthy, so these runs say
    nothing about the PoC. They are repaired on their own, without spending
    a validation attempt or one of the repairs meant for the exploit.

    A message carrying the setup marker is never one of these, whatever else
    it carries, and the guard is here rather than only in the branch order
    below. `run_lab` wraps every exception it raises with `docker compose ps
    -a` and `docker compose logs`, which report the state of every service
    in the project: one unrelated container sitting at `Up (unhealthy)`, or
    one log line quoting the phrase, puts `is unhealthy` into the text of a
    failure that happened after the health gate had already opened.

    Measured on 2026-11-06, by calling this on both: the bare marker reads
    False and the same marker with compose diagnostics appended reads True.
    So a setup failure would have been handed STARTUP_HINT and spent the
    startup budget rewriting a build and healthchecks that had both worked.
    Ordering the branches alone does not fix that -- once the setup budget is
    spent the loop falls through to this test, which would then take the
    startup budget for the same failure by the back door.
    """
    if _setup_failure(message):
        return False
    lowered = message.lower()
    return any(marker in lowered for marker in _STARTUP_MARKERS)


def startup_repair_limit() -> int:
    """Startup-only repairs allowed per run (CVELAB_STARTUP_REPAIRS, 0 to 5)."""
    raw = os.getenv("CVELAB_STARTUP_REPAIRS", "").strip()
    try:
        value = int(raw) if raw else 2
    except ValueError:
        value = 2
    return max(0, min(value, 5))


def setup_repair_limit() -> int:
    """Setup-only repairs allowed per run (CVELAB_SETUP_REPAIRS, 0 to 5).

    Its own budget, spent the way `startup_repair_limit`'s is and not the way
    `effect_repair_limit`'s is. The validator never started, so nothing was
    measured and nothing is known about the vulnerability; the effect budget
    is for a lab whose validator ran and observed the wrong thing.
    """
    raw = os.getenv("CVELAB_SETUP_REPAIRS", "").strip()
    try:
        value = int(raw) if raw else 2
    except ValueError:
        value = 2
    return max(0, min(value, 5))


#: What a mirror, a module proxy or a name server leaves behind when it is
#: briefly unwell rather than wrong. A 404 is deliberately not here: it says
#: the file is not there and will not be, which is a different problem with a
#: different answer, below.
_FETCH_RETRY_MARKERS = (
    "hash sum mismatch",
    "temporary failure resolving",
    "could not resolve host",
    "name or service not known",
    "server misbehaving",
    "no route to host",
    "connection reset by peer",
    "connection timed out",
    # go module downloads, and anything else speaking TLS to a proxy
    "tls handshake timeout",
    "i/o timeout",
    "unexpected eof",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
)


def _build_stage_failure(message: str) -> bool:
    """Whether the failure is a build that never produced an image.

    The guard both classifiers below share. A fetch marker on its own would
    also catch a validator that cannot reach the product, which is a real
    failure and has to keep reaching a repair; only a build that did not
    run is silent about the PoC in the way they both assume.
    """
    return "docker stage 'build' failed" in message.lower()


def _transient_failure(message: str) -> bool:
    """Whether a build failed because something it fetched was briefly away.

    A third class, between the two that already existed. An infrastructure
    failure is the environment being unfit and worth giving up on. A lab
    that is wrong is worth a repair. This is neither: the lab is fine and
    the next attempt is likely to pass, so it is retried as it stands,
    without spending a repair and without asking a model to change
    anything.

    Measured over three runs of the same ten CVEs, three of thirty attempts
    ended on a fetch the build needed and could not get, and none was
    answerable by a model. All three were sent to `repair_source_lab` to
    rewrite a Dockerfile that was already correct.
    """
    return _build_stage_failure(message) and any(
        marker in message.lower() for marker in _FETCH_RETRY_MARKERS
    )


def _archived_suite_failure(message: str) -> bool:
    """Whether the build asked a live mirror for what only the archive has.

    Debian moves a release's pool to archive.debian.org when its support
    ends, while deb.debian.org keeps serving that release's index. So
    `apt-get update` succeeds, reads a version out of a current index, and
    every download of it 404s -- in the same layer, seconds apart, with
    nothing wrong in the Dockerfile.

    This is not transient and retrying is futile, which is why a 404 is
    kept out of the markers above. It is a real repair with a known answer,
    so it gets the hint that names it.

    Verified on 2026-11-04 against python:3.8-slim-bullseye, which is the
    sentry lab's own base: the security index lists libpq5
    13.23-0+deb11u4 and gives its pool path, deb.debian.org and every
    mirror behind it 404 that path, archive.debian.org serves it, and the
    install then completes.
    """
    lowered = message.lower()
    if not _build_stage_failure(lowered):
        return False
    return "failed to fetch" in lowered and "404" in lowered and "not found" in lowered


#: What a registry says when the tag in a FROM line was never published.
#:
#: Verified on 2026-11-05 against docker 29.9.2 and buildx 0.38.1, by asking
#: for three kinds of reference that cannot resolve:
#:
#:   unpublished tag of a real repository
#:     failed to resolve source metadata for <ref>: <ref>: not found
#:   repository that is not there
#:     failed to resolve source metadata for <ref>: pull access denied,
#:     repository does not exist or may require authorization
#:   tag with no image for the requested platform
#:     failed to resolve source metadata for <ref>: no match for platform
#:     in manifest: not found
#:
#: So `failed to resolve source metadata` is the one marker all three share,
#: and it is the only one that matches the measured run: buildkit says plain
#: `not found` and never `manifest unknown`. That phrase is kept anyway
#: because older daemons and other registry clients still emit it, and it
#: costs nothing.
#:
#: `manifest for` was considered and left out. It is not something buildkit
#: says here -- the platform case says "in manifest" -- and as a bare
#: substring it is ordinary program text: it occurs over a thousand times in
#: the source trees the benchmark labs check out, and a build log carries
#: source lines whenever a compiler or a traceback quotes them. It would
#: classify arbitrary build failures as an unresolvable base image.
_UNKNOWN_IMAGE_MARKERS = (
    "failed to resolve source metadata",
    "manifest unknown",
    "no match for platform",
    "pull access denied",
    "repository does not exist",
)


def _unknown_base_image(message: str) -> bool:
    """Whether the build died because a base image tag does not exist.

    Metadata resolution is the first thing a build does, so this target ran
    no layer at all and the log says nothing about the lab beyond the tag it
    asked for. It is not transient -- the registry's answer will not change
    -- and it is not the archived pool either, so until now it fell through
    every classifier and reached a repair carrying only the Docker log. A
    repair given the log and no hint tends to reach for another tag the same
    way it reached for the first.

    Measured on 2026-11-04: a lab escaping an archived pool moved its
    interpreter onto a newer Debian release and invented the pairing, which
    no image was ever published for. The build died before any layer ran, and
    the run was recorded `runtime_error`.
    """
    lowered = message.lower()
    if not _build_stage_failure(lowered):
        return False
    return any(marker in lowered for marker in _UNKNOWN_IMAGE_MARKERS)


#: What an index, a lockfile or a module proxy says when a pinned version is
#: not available and will not become available.
#:
#: Each of these is deliberately kept out of `_FETCH_RETRY_MARKERS`. A `410
#: Gone` is the proxy saying the version has been withdrawn, which is the
#: opposite of the `502`/`503`/`504` beside it; a Go `checksum mismatch` is
#: the recorded sum disagreeing with what the proxy serves, which is why
#: apt's `hash sum mismatch` -- a mirror caught mid-sync, and genuinely
#: transient -- is in the retry list and this is not. Retrying any of them
#: builds the same lab against the same index and gets the same answer, so
#: what they need is a repair that is told which pin to change.
_DEPENDENCY_PIN_MARKERS = (
    # pip, measured: the requirement and the versions that do exist are both
    # named in the output, which is what makes this answerable.
    "no matching distribution found",
    "could not find a version that satisfies",
    # go modules
    "checksum mismatch",
    "verifying module",
    # any index or proxy that has withdrawn the version
    "410 gone",
)


def _dependency_pin_failure(message: str) -> bool:
    """Whether the build asked for a dependency version it cannot have.

    The second class that used to fall through to an unhinted repair. The
    build did run, so the Dockerfile is reachable and the failure is a
    question a model can answer -- but only if it is told that the pin is
    the thing to change and that the two revisions' own versions are not.

    Measured on 2026-10-29: one lab pinned a package whose own dependency
    range no published version satisfied, pip listed every version that
    existed, and the 16000-character build output went to a repair with no
    hint at all.
    """
    lowered = message.lower()
    if not _build_stage_failure(lowered):
        return False
    return any(marker in lowered for marker in _DEPENDENCY_PIN_MARKERS)


#: Told to the repair rather than worked out by it, because the symptom
#: points at the package list and the cause is somewhere else entirely.
ARCHIVE_HINT = (
    "The build could not download packages that the mirror's own index lists. "
    "Debian moves a release's pool to archive.debian.org once its support ends "
    "but keeps serving that release's index from deb.debian.org, so "
    "`apt-get update` succeeds and then every download 404s. Nothing in the "
    "package list is wrong and retrying cannot help. "
    "Point apt at the archive before installing anything: replace the sources "
    "with archive.debian.org for both the release and its security suite. "
    "Verified for bullseye, where this is enough on its own; should the Release "
    "file be refused as expired, add Acquire::Check-Valid-Until=false. "
    "Do not reach for a newer base image instead: for a release this old there "
    "is usually no image of the pinned interpreter on a supported release at "
    "all, and a tag formed by analogy does not exist. "
    "Change nothing else: the package list, the regression "
    "input and the validator's evidence logic are not the cause."
)


#: The warning that used to live at the end of ARCHIVE_HINT, now attached to
#: the failure it describes rather than to the one the model has already
#: escaped. It was advice about inventing tags, shown only to a run that had
#: not invented one yet.
BASE_IMAGE_HINT = (
    "The build never started: a base image tag in one of the Dockerfiles does "
    "not exist, so the registry could not resolve it and not a single layer "
    "ran. Nothing below the FROM line has been tested yet and nothing in the "
    "log says anything about the lab. The registry's answer will not change, so "
    "retrying cannot help. "
    "Name only a tag you know to be published -- one the upstream project's own "
    "packaging or documentation uses -- and keep the Dockerfile's layers as "
    "they are. "
    "Expect the version you want not to exist at all. A distribution release "
    "reaches the archive at about the time the interpreter pinned on top of it "
    "reaches end of life, so for an old CVE there is usually no variant of that "
    "interpreter on a supported release, and pairing the interpreter with a "
    "newer release by analogy produces a tag that was never built: "
    "python:3.8.16-bookworm was tried and the build died on it at once, because "
    "python 3.8 never had a bookworm image. Where that is the situation, the "
    "answer is the older release with apt pointed at archive.debian.org, not a "
    "newer tag. "
    "Change nothing else: the package list, the regression input and the "
    "validator's evidence logic are not the cause."
)


#: The pin is the thing to change, and the product's own two versions are the
#: thing not to: a repair told only "this cannot be fetched" is as likely to
#: loosen the revision pair as the dependency, and that silently removes the
#: difference the lab exists to show.
DEPENDENCY_HINT = (
    "A dependency this build pins cannot be fetched: the index has no version "
    "that satisfies the requirement, the proxy has withdrawn the one named, or "
    "what came down does not match the checksum a sum file records. The output "
    "names the requirement, and usually the versions that do exist. This is a "
    "pin rather than a network fault, so retrying gets the same answer. "
    "Change the pin the output names -- to a version the index offers, or to a "
    "range wide enough to resolve -- and where a lockfile or sum file records "
    "the old one, update or drop that entry too. "
    "Leave the vulnerable and patched revisions on the versions they are on: "
    "the difference between those two is the whole lab, and relaxing the "
    "product's own pin to make the build pass removes the fix along with it. "
    "Change nothing else: the base image, the regression input and the "
    "validator's evidence logic are not the cause."
)


def _runtime_failure(message: str) -> dict:
    """What a build or run exception becomes, with a hint where one is known.

    The setup is tested first because it is the only one of the four whose
    message says what already worked: the steps run after the build produced
    its images, and each of the other three requires the build stage's own
    failure line, which this message cannot carry. It is also the only one
    matched on a sentence of CVELab's own rather than on a tool's output, so
    nothing a diagnostics tail carries can divert it. SETUP_HINT is defined
    beside PRECONDITION_HINT below, where the two shapes of an undelivered
    attack can be read against each other.

    The order of the remaining three is load-bearing, because one log can
    match more than one of them. A compose build runs every target, so a log
    can carry an archived pool from one target and an unresolvable tag from
    another, and `not found` appears in both.

    The archived pool is first because it is the narrowest test -- three
    tokens that have to co-occur -- and because it is the one whose remedy
    the other two would contradict. It says to keep the base image and
    redirect apt; BASE_IMAGE_HINT says to change the tag. Sending an archived
    pool the base-image hint is how the invented tag happened in the first
    place, so the classifier must not be able to do it on purpose.

    The base image comes next because metadata resolution precedes every
    layer: a target that failed there ran no install, so a pin inside it has
    not been reached yet and there is nothing to say about it.

    In each case the hint is inserted before the error. `repair_source_lab`
    serialises this dict and cuts it to fit the prompt, so insertion order is
    what decides whether the hint survives a long build log.
    """
    if _setup_failure(message):
        return {"hint": SETUP_HINT, "kind": "setup_not_established", "error": message}
    if _archived_suite_failure(message):
        return {"hint": ARCHIVE_HINT, "kind": "archived_suite", "error": message}
    if _unknown_base_image(message):
        return {"hint": BASE_IMAGE_HINT, "kind": "unknown_base_image", "error": message}
    if _dependency_pin_failure(message):
        return {"hint": DEPENDENCY_HINT, "kind": "dependency_pin", "error": message}
    return {"kind": "runtime_error", "error": message}


def _source_unavailable_failure(message: str) -> bool:
    """Whether the source repository cannot be had at all.

    A clone that fails because the repository is not there is not a bad
    minute on the network: the next three attempts get the same answer, and
    spending them leaves a plain "the source is gone" recorded as a generic
    generation failure with its cause four attempts back. GitHub answers the
    same way for a repository that was deleted and for one that was made
    private, and from here those are the same thing.

    Measured on 2026-11-04: one lab's upstream had been removed between the
    advisory and the run, and the run spent all four generation attempts
    asking again, in four seconds.
    """
    lowered = message.lower()
    if "remote: repository not found" in lowered:
        return True
    return "fatal: repository" in lowered and "not found" in lowered


def _generation_failure(message: str) -> dict:
    """What a generation exception becomes, named where the cause is known."""
    if _source_unavailable_failure(message):
        return {"kind": "source_unavailable", "error": message[:24000]}
    return {"kind": "generation_error", "error": message[:24000]}


# A revision pair that cannot show its fix used to be classified here and
# stop the run, because asking the same question again gets the same two
# snapshots. It no longer arrives: sourcegen demotes such a pair to a
# vulnerable-only lab instead of raising, in generation and in repair alike,
# so there is no message left to recognise and nothing a classifier here
# could keep anyone from retrying. A branch for it would be an abort path
# for an input the generator now completes.


def _provider_unavailable_failure(message: str) -> bool:
    """Whether the provider was too busy or too unwell to answer at all.

    `ai._request_json` already asks a busy provider again with a widening
    pause. This is what is left when that did not outlast the overload: the
    model never answered, so the attempt it took bought nothing, and the
    message is no use in the next prompt either, because it describes the API
    rather than the lab.

    The statuses that mean the request was wrong -- 400, 401, 403, 404 -- are
    not here. Those belong to `_infrastructure_failure`, which stops the run,
    because asking again with the same key and the same body gets the same
    answer.

    Measured on 2026-11-04: two of one CVE's four repair attempts ended on
    `overloaded_error`, and each one also pushed the real failure a level
    deeper into the prompt that followed it.
    """
    lowered = message.lower()
    if "overloaded_error" in lowered:
        return True
    return any(
        f"api http {status}" in lowered
        for status in (429, 500, 502, 503, 504, 529)
    )


def transient_retry_limit() -> int:
    """Retries allowed per run for a failed fetch (CVELAB_TRANSIENT_RETRIES, 0 to 5)."""
    raw = os.getenv("CVELAB_TRANSIENT_RETRIES", "").strip()
    try:
        value = int(raw) if raw else 2
    except ValueError:
        value = 2
    return max(0, min(value, 5))


def transient_retry_pause() -> float:
    """Seconds before a failed fetch is retried (CVELAB_TRANSIENT_PAUSE, 0 to 120).

    Long enough that a mirror mid-sync has a chance to settle, short enough
    that a batch does not notice. Retrying instantly is the one thing worth
    avoiding: the condition these wait out is measured in seconds.
    """
    raw = os.getenv("CVELAB_TRANSIENT_PAUSE", "").strip()
    try:
        value = float(raw) if raw else 15.0
    except ValueError:
        value = 15.0
    return max(0.0, min(value, 120.0))


STARTUP_HINT = (
    "The lab's services did not become healthy, so the validator never ran and "
    "nothing is known yet about the exploit. Fix only what keeps the services from "
    "starting: the build output, the start command, the port, the healthcheck command "
    "and route, and anything the logs below show failing. Keep the regression input "
    "and the validator's evidence logic as they are unless they are the cause."
)


def effect_repair_limit() -> int:
    """Repairs added when the lab runs but the proof does not (CVELAB_EFFECT_REPAIRS, 0 to 5).

    Covers both shapes of `proof_not_verified`: the effect that did not show
    and the attack that was never delivered. The setting keeps its name
    because the runs, the records and the documentation all use it.
    """
    raw = os.getenv("CVELAB_EFFECT_REPAIRS", "").strip()
    try:
        value = int(raw) if raw else 2
    except ValueError:
        value = 2
    return max(0, min(value, 5))


EFFECT_HINT = (
    "The lab started and the validator reached both services, but the security effect did "
    "not show the way the contract requires; failed_proof_checks names what is missing. "
    "Read what each revision answered and the service logs, and settle two things in order: "
    "first whether the regression input reached the code the fix changes at all (route, "
    "configuration, parameters, the condition the fix tests), then whether the observation "
    "is the one this fix actually changes. Change the input or the observation, and keep the "
    "build and the services if they worked."
)


#: The other half of `proof_not_verified`, and until now the unhelped half:
#: both EFFECT_HINT and the extra repair budget hung off `reached`, so the
#: earlier and more mechanical failure -- the attack was never delivered at
#: all -- got strictly less guidance and fewer attempts than one that reached
#: the services and merely observed the wrong thing.
#:
#: Measured on 2026-11-06: a mobile security framework lab spent all four
#: attempts reporting attack_executed false, with the validator's own
#: "victim session not established" against the vulnerable and the patched
#: service alike, while the login it had already made reported 200. The
#: setup's status code was the only thing checked, so the run never learned
#: that the setup was the problem.
PRECONDITION_HINT = (
    "The lab built and its services started, but the validator stopped before the "
    "attack input was delivered: attack_executed is false, so the exploit has not been "
    "tried even once and nothing is known yet about the vulnerability itself. The "
    "validator's own error below names the setup step that did not complete. "
    "Settle what state the service needs before the input can reach the code the fix "
    "changes -- a session, an authenticated account, a record seeded for the attack to "
    "act on, a CSRF or anti-forgery token taken from the page that issues it -- then "
    "establish it in that order. Where the state can be reached over HTTP, declare "
    "the steps in exploit_contract.setup and let CVELab run them before the validator "
    "starts: a value minted fresh each boot is bound there and arrives as CVELAB_BOUND, "
    "which is what no fixed lab value can replace. Write it into the validator only "
    "where setup cannot express it. Either way name the state in "
    "exploit_contract.preconditions, so a run that loses it says which step it lost. "
    "Read what each setup step returned rather than its status code: a login can "
    "answer 200 and hand back the form again instead of a cookie, and a step checked "
    "only for 200 reports success and leaves the attack with no session. "
    "Change nothing else. The build and the services worked, so they are not the "
    "cause, and the observation cannot be the cause of a failure that happened before "
    "anything was observed: leave the regression input's expected effect, the "
    "validator's evidence logic and the revision pair as they are."
)


#: The mechanical half of the same failure, and the one the hint above can
#: only describe in prose. There the validator reached the services and
#: stopped before delivering the attack, and why is a question for the model.
#: Here CVELab's own setup steps did not complete and the reason is already
#: in hand: which step it was, and what it could not reach or could not bind.
#:
#: The two must read distinctly, because the remedies are in different files.
#: PRECONDITION_HINT sends a repair to the validator; this one sends it to
#: `exploit_contract.setup` and says the validator cannot be the cause,
#: because `core.run_setup` raises before the validator is started.
#:
#: What the hint does NOT say, and must not: that a step failed because its
#: route answered 4xx. The runner reads a refusal as an answer -- `send`
#: catches HTTPError and returns the code -- so the steps carry on past a
#: 4xx, and the only two things that stop them are a route that cannot be
#: reached at all and an extractor that bound nothing. A 4xx reaches the
#: error as the `status` recorded beside such a binding, which is why the
#: hint tells the repair to read that status before touching the extractor.
#: Nor does it mention a step ordered before the one that binds what it
#: uses: `steps.validate_setup` refuses that shape at generation time, in
#: repair as well, so it cannot be what a run failed on.
SETUP_HINT = (
    "The lab built, its services started and became healthy, and then CVELab's own "
    "setup steps did not complete, so the validator never ran: the attack was not "
    "attempted even once and nothing is yet known about the vulnerability. The error "
    "below is the step runner's own. It names the step by its index in "
    "exploit_contract.setup, with whichever of these the failure had: the path it "
    "could not reach, or the name its extractor was to bind and the status the "
    "response carried. "
    "Change exploit_contract.setup, and nothing else. "
    "Two things, and only two, stop the steps. One is a route that could not be "
    "reached at all after waiting; where that is the first step, check "
    "exploit_contract.setup_port, since the steps are sent to that port inside the "
    "service's own container. The other, and the usual one, is a binding step whose "
    "extractor found nothing: either it reads a JSON key, a response header or a "
    "pattern the answer does not carry, or the route answered something else "
    "entirely and the value was never in the body. Read the status recorded beside "
    "the binding before rewriting the extractor -- a 401, a 403 or a 404 there says "
    "the request is wrong and the extractor is not. A refusal does not stop the "
    "steps on its own: it is read as an answer and the next step is sent, so a 4xx "
    "shows up only as that status. "
    "Leave the rest alone. The regression input's expected effect, the effect "
    "predicate, the validator's evidence logic, the revision pair and both "
    "Dockerfiles are not the cause: the build and the services worked, and nothing "
    "downstream of the setup ran at all."
)


def _compact(value: object, limit: int = 600) -> object:
    """A validator result with every long string cut, so the digest stays small."""
    if isinstance(value, dict):
        return {key: _compact(item, limit) for key, item in list(value.items())[:20]}
    if isinstance(value, list):
        return [_compact(item, limit) for item in value[:10]]
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"... [{len(value) - limit} more characters]"
    return value


def _reached_targets(report: dict) -> bool:
    """Whether the validator sent its input to the services, as opposed to failing before."""
    validation = report.get("validation") or {}
    return isinstance(validation, dict) and validation.get("attack_executed") is True


def _validation_digest(report: dict) -> dict:
    """What a repair needs first from a validation that did not prove the effect."""
    validation = report.get("validation") or {}
    if not isinstance(validation, dict):
        validation = {}
    checks = report.get("proof_checks") or {}
    return {
        "failed_proof_checks": sorted(name for name, passed in checks.items() if passed is False),
        # Not a proof check, so it can never appear in the list above, and a run
        # whose every check passes while this is false sent a repair a digest
        # that named nothing at all. Measured once in the archive, under a
        # different provider: every real check passed and the only name handed
        # over was the manual verdict, which was itself a phantom of the gate
        # that had not opened. Named here so the one blocker is sayable.
        "differential_confirmed": validation.get("differential_confirmed"),
        # The predicate the effect was judged against, and the clause-by-clause
        # verdict. Without them a repair can see what was observed -- the
        # compacted builds below carry the observations -- but not what it was
        # measured against, and the project's own note on this digest is that a
        # repair without the failed names "could only guess".
        "effect_predicate": (report.get("proof_contract") or {}).get("effect_predicate"),
        "effect_evidence": report.get("effect_evidence"),
        "attack_executed": validation.get("attack_executed"),
        # The names each build's setup bound, and never their values: a
        # binding is a session or a token read out of this run's own lab, and
        # core writes only the names into the report for that reason.
        #
        # It is here for the `attack_executed: false` case directly above,
        # which is the one place it changes what a repair can conclude. A
        # validator reporting no session while the setup reported success is
        # two different labs: one that declares no setup at all, where the
        # remedy is to declare it, and one whose setup bound a name the
        # validator then did not use, where the remedy is in the validator's
        # reading of CVELAB_BOUND. The full report carries this too, but the
        # report is the last key and the first thing the prompt's limit cuts.
        #
        # It does nothing for a setup that failed, despite being the obvious
        # place to look for it: `core.run_setup` raises before any report is
        # written, so that failure arrives through the exception path, where
        # this function is never called and SETUP_HINT carries the error.
        "setup_bindings": report.get("setup_bindings"),
        "observable_effect": validation.get("observable_effect"),
        "vulnerable": _compact(validation.get("vulnerable")),
        "patched": _compact(validation.get("patched")),
        "service_logs": report.get("service_logs"),
    }


def _declined(
    cve: str,
    lab_dir: Path,
    attempts: list[dict],
    error: ProviderDeclined,
    announce: Callable[[str], None],
) -> dict:
    """End a run the model provider declined, as its own outcome rather than a failure."""
    detail = error.detail
    explanation = detail.get("explanation") if isinstance(detail, dict) else None
    declined = {
        "provider": error.provider,
        "model": error.model,
        "category": detail.get("category") if isinstance(detail, dict) else None,
        "explanation": explanation or (str(detail) if detail else None),
    }
    message = (
        f"{error.provider} declined this request under its usage policy (model {error.model}). "
        "That is the provider's decision, not a fault in the lab, and CVELab does not retry "
        "or reword the request. The provider's own explanation is included; you may rerun "
        "with another provider you have configured."
    )
    announce(f"{cve}: {message}")
    _record(lab_dir, attempts, "PROVIDER_DECLINED", {"kind": "provider_declined", **declined})
    return {
        "ok": False,
        "status": "PROVIDER_DECLINED",
        "cve": cve,
        "lab_dir": str(lab_dir),
        "declined": declined,
        "message": message,
        "attempts": attempts,
        "error": str(error),
    }


def _record(
    lab_dir: Path,
    attempts: list[dict],
    status: str = "RUNNING",
    failure: dict | None = None,
) -> None:
    document = {
        "schema_version": 1,
        "status": status,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # Written on every update, so an interrupted run still shows what it
        # spent before it stopped.
        "usage": usage.as_dict(),
        "attempts": attempts,
    }
    if failure is not None:
        document["failure"] = failure
    write_text(
        lab_dir / "automation.json",
        json.dumps(document, indent=2, ensure_ascii=True) + "\n",
    )


#: The two generation results that say the same thing: there is no public
#: repository and fixed commit, so there is no differential to build. They are
#: returned rather than raised, so until now each one ended the run on the
#: spot -- no second generation, no repair, not one model call for an adapter.
#: `sourcegen` picks between them by whether discovery named a vendor
#: artifact; nothing else about the run differs, and nothing about the retreat
#: below differs either.
#:
#: Measured over 40 attempts: 7.5% ended here, byte-identically from run to
#: run, because the resolution chain that reaches this point is deterministic.
#: Asking it again cannot change the answer -- but a published image is a
#: different question, and `closed_auto` is the path that asks it.
_ARTIFACT_REQUIRED_STATUSES = ("ARTIFACT_REQUIRED", "VENDOR_ARTIFACT_REQUIRED")


def _closed_retreat_possible(
    status: str,
    api_key: str | None,
    model: str | None,
    provider: str | None,
) -> bool:
    """Whether the closed-software path is worth asking for this stop.

    The same two conditions `generate_source_lab` already puts on source
    discovery, composed the same way and for the same reason: the closed path
    drafts its request plan with a model and asks that model to find a
    published vulnerable image tag, a port and an endpoint by searching the
    web. A provider with no web-search tool cannot answer that -- `ai`
    appends "return insufficient-data status rather than inventing
    provenance" to the instructions when a tool is requested and the endpoint
    has none -- so the retreat would spend a model call to be told what is
    already known. Where it cannot run, the honest stop stands unchanged.
    """
    return (
        status in _ARTIFACT_REQUIRED_STATUSES
        and ai_is_configured(api_key, model, provider)
        and provider_supports_web_search(provider)
    )


def _closed_retreat(
    cve: str,
    output_root: Path,
    api_key: str | None,
    model: str | None,
    provider: str | None,
    base_url: str | None,
    repo: str | None,
    fixed_ref: str | None,
    announce: Callable[[str], None],
) -> tuple[dict, dict | None]:
    """Ask the closed-software path for a CVE whose source is not public.

    Returns what to record and, only when the retreat produced a validated
    lab, that lab's result.

    Deliberately one call and not a loop. `run_closed_auto` resolves once and
    runs `run_closed_lab` once; it has no repair of its own, and building one
    around it here would spend the source budget on a different lab. So this
    turns a class that reproduced nothing into a one-shot class, not into the
    repaired path a source lab gets. Its cost sits outside `max_attempts` for
    the same reason: it is a second strategy, not another attempt at the
    first, and it must not be able to eat a generation or a repair -- nor be
    eaten by one.

    The retreat can only improve the outcome, never relabel it. This
    population is the one `closed_auto` is least likely to serve: its prompt
    requires an exact publicly accessible vulnerable image tag, its image
    preparation hard-fails on a pull, and a product with no public source
    usually has no public image either. So a decline is the expected answer
    and the correct one -- the caller keeps the honest "an artifact is
    required" it already had, with what the second strategy returned attached
    to it, rather than a status that reads as a crash or as a new kind of
    failure.
    """
    announce(
        f"{cve}: no public source to build a differential from; asking the "
        f"closed-software path for a published image instead"
    )
    record: dict = {"phase": "closed_retreat", "attempt": 1}
    try:
        result = run_closed_auto(
            cve, output_root, api_key, model, provider, base_url, repo, fixed_ref,
        )
    except Exception as exc:
        # Every way this can end badly is ordinary for this population rather
        # than exceptional: the image tag the resolver named does not exist
        # and `docker pull` fails, a READY plan came back incomplete, the
        # provider declined the request. None of them says anything new about
        # the CVE, and none of them should turn a correctly declined run into
        # something that looks like a crash.
        record.update({"ok": False, "error": str(exc)[:16000]})
        announce(f"{cve}: the closed-software path could not run: {exc}")
        return record, None
    record.update({
        "ok": bool(result.get("ok")),
        "status": result.get("status"),
        **({"reason": result["reason"]} if result.get("reason") else {}),
        **(
            {"proof_checks": result["proof_checks"]}
            if result.get("proof_checks")
            else {}
        ),
    })
    if result.get("ok"):
        announce(f"{cve}: the vendor's published images reproduced it")
        return record, result
    announce(
        f"{cve}: no public image either "
        f"({result.get('status') or 'the proof did not hold'}); "
        f"the artifact requirement stands"
    )
    return record, None


def run_auto_workflow(
    cve_value: str,
    output_root: Path,
    repo: str | None,
    fixed_ref: str | None,
    vulnerable_ref: str | None,
    api_key: str | None,
    model: str | None,
    keep: bool,
    max_attempts: int = 4,
    progress: Progress | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    hint: str | None = None,
    research_mode: str | None = None,
    after_validation: AfterValidation | None = None,
) -> dict:
    """Generate, execute, diagnose, repair, and re-run a CVE lab autonomously."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    announce = progress or _default_progress
    usage.reset()
    cve = normalize_cve(cve_value)
    lab_dir = output_root.resolve() / cve
    attempts: list[dict] = []
    generation_feedback: list[str] = []
    _record(lab_dir, attempts)

    generated = None
    for generation_attempt in range(1, max_attempts + 1):
        announce(f"{cve}: generating source-backed lab ({generation_attempt}/{max_attempts})")
        try:
            generated = generate_source_lab(
                cve,
                output_root,
                repo,
                fixed_ref,
                vulnerable_ref,
                api_key,
                model,
                provider,
                base_url,
                generation_feedback,
                hint=hint,
                research_mode=research_mode,
            )
        except Exception as exc:
            generation_feedback.append(str(exc)[:6000])
            attempts.append({
                "phase": "generation",
                "attempt": generation_attempt,
                "ok": False,
                "error": str(exc)[:16000],
            })
            if lab_dir.exists():
                _record(lab_dir, attempts)
            if isinstance(exc, ProviderDeclined):
                return _declined(cve, lab_dir, attempts, exc, announce)
            if _source_unavailable_failure(str(exc)):
                announce(
                    f"{cve}: the upstream repository is not there to clone; "
                    f"asking again cannot change that"
                )
            if (
                isinstance(exc, CVERecordNotFound)
                or _infrastructure_failure(str(exc))
                or _source_unavailable_failure(str(exc))
                or generation_attempt == max_attempts
            ):
                _record(
                    lab_dir,
                    attempts,
                    "AUTO_GENERATION_FAILED",
                    _generation_failure(str(exc)),
                )
                return {
                    "ok": False,
                    "status": "AUTO_GENERATION_FAILED",
                    "cve": cve,
                    "lab_dir": str(lab_dir),
                    "attempts": attempts,
                    "error": str(exc),
                }
            announce(f"{cve}: generation failed; retrying automatically")
            continue
        if not generated.get("ok"):
            status = generated.get("status", "GENERATION_NOT_AVAILABLE")
            retreat: dict | None = None
            if _closed_retreat_possible(status, api_key, model, provider):
                retreat, closed = _closed_retreat(
                    cve, output_root, api_key, model, provider, base_url,
                    repo, fixed_ref, announce,
                )
                # Recorded whichever way it went, in the file a batch operator
                # reads: a second strategy that fires silently is a second
                # strategy nobody can tell fired. `usage` is written on every
                # update, so the retreat's own spend is in the record too.
                attempts.append(retreat)
                if closed is not None:
                    _record(lab_dir, attempts, "VALIDATED")
                    closed["automation"] = {
                        "mode": "closed_retreat_after_artifact_required",
                        "generation_status": status,
                        "attempts": attempts,
                        "max_attempts": max_attempts,
                    }
                    return closed
            failure: dict = {"kind": "generation_result", "result": generated}
            if retreat:
                failure["closed_retreat"] = retreat
                generated["closed_retreat"] = retreat
            _record(lab_dir, attempts, status, failure)
            generated["automation"] = {"attempts": attempts, "max_attempts": max_attempts}
            return generated
        attempts.append({
            "phase": "generation",
            "attempt": generation_attempt,
            "ok": True,
            "status": generated.get("status"),
            # A demotion is the one thing a generation can do while reporting
            # ok and GENERATED_UNVALIDATED that changes what the lab can
            # prove, and automation.json is the file a batch operator reads.
            # Without this the record said only that generation succeeded:
            # the single progress.step that announced the demotion goes to
            # stderr and CVELAB_QUIET silences it, so a batch of 190 pairs
            # had no machine-readable trace of which labs lost their
            # differential or why.
            **(
                {"demotion": (generated.get("plan") or {}).get("demotion")}
                if (generated.get("plan") or {}).get("demotion")
                else {}
            ),
        })
        _record(lab_dir, attempts)
        break

    if generated is None:
        raise RuntimeError("Automatic generation ended without a result")

    plan = generated.get("plan", {})
    scripted_runner = bool(plan.get("runner"))
    pending_failure: dict | None = None
    repair_calls = 0
    startup_repairs = 0
    setup_repairs = 0
    transient_retries = 0
    provider_stalls = 0
    effect_repairs = 0
    validation_attempt = 0

    while validation_attempt < max_attempts + effect_repairs:
        if pending_failure and not scripted_runner and not _infrastructure_failure(
            json.dumps(pending_failure, ensure_ascii=True)
        ):
            if repair_calls >= max_attempts - 1 + effect_repairs:
                break
            repair_calls += 1
            announce(
                f"{cve}: repairing adapter from observed evidence "
                f"({repair_calls}/{max_attempts - 1})"
            )
            try:
                repaired = repair_source_lab(
                    cve,
                    output_root,
                    pending_failure,
                    repair_calls,
                    api_key,
                    model,
                    provider,
                    base_url,
                    research_mode=research_mode,
                )
            except Exception as exc:
                if isinstance(exc, ProviderDeclined):
                    attempts.append({
                        "phase": "repair",
                        "attempt": repair_calls,
                        "ok": False,
                        "error": str(exc)[:16000],
                    })
                    return _declined(cve, lab_dir, attempts, exc, announce)
                if (
                    _provider_unavailable_failure(str(exc))
                    and provider_stalls < transient_retry_limit()
                ):
                    # The model never answered. The slot it took bought
                    # nothing, so it is given back, and pending_failure is
                    # left alone: it still describes the lab, while the API's
                    # own complaint would only bury it a level deeper in the
                    # next prompt.
                    repair_calls -= 1
                    provider_stalls += 1
                    attempts.append({
                        "phase": "provider_busy",
                        "attempt": provider_stalls,
                        "ok": False,
                        "error": str(exc)[:16000],
                    })
                    _record(lab_dir, attempts)
                    pause = transient_retry_pause()
                    announce(
                        f"{cve}: the provider could not answer the repair "
                        f"({provider_stalls}/{transient_retry_limit()}); "
                        f"asking again unchanged after {pause:.0f}s"
                    )
                    if pause:
                        time.sleep(pause)
                    continue
                attempts.append({
                    "phase": "repair",
                    "attempt": repair_calls,
                    "ok": False,
                    "error": str(exc)[:16000],
                })
                pending_failure = {
                    "kind": "repair_generation_error",
                    "previous_failure": pending_failure,
                    "repair_error": str(exc),
                }
                _record(lab_dir, attempts)
                if _infrastructure_failure(str(exc)):
                    break
                continue
            attempts.append({
                "phase": "repair",
                "attempt": repair_calls,
                "ok": True,
                "status": repaired.get("status"),
                "fidelity": repaired.get("plan", {}).get("fidelity"),
                # The repair-side demotion is defence in depth and should
                # never fire for a lab this version generated, so a record
                # of it here is also how anyone would find out that it did.
                **(
                    {"demotion": repaired.get("plan", {}).get("demotion")}
                    if repaired.get("plan", {}).get("demotion")
                    else {}
                ),
            })
            plan = repaired.get("plan", plan)
            pending_failure = None
            _record(lab_dir, attempts)

        validation_attempt += 1
        announce(f"{cve}: build and E2E validation ({validation_attempt}/{max_attempts})")
        try:
            validated = run_lab(cve, output_root, keep, after_validation)
        except Exception as exc:
            if (
                _transient_failure(str(exc))
                and not _infrastructure_failure(str(exc))
                and transient_retries < transient_retry_limit()
            ):
                # Nothing was built, so nothing is known about the PoC and
                # there is nothing for a model to fix. The attempt is given
                # back and the same lab is built again. Not gated on
                # scripted_runner: a mirror is indifferent to how the lab
                # drives itself.
                validation_attempt -= 1
                transient_retries += 1
                attempts.append({
                    "phase": "transient",
                    "attempt": transient_retries,
                    "ok": False,
                    "error": str(exc)[:24000],
                })
                _record(lab_dir, attempts)
                pause = transient_retry_pause()
                announce(
                    f"{cve}: a fetch the build needs failed; retrying it unchanged "
                    f"({transient_retries}/{transient_retry_limit()}) after {pause:.0f}s"
                )
                if pause:
                    time.sleep(pause)
                continue
            if (
                _setup_failure(str(exc))
                and not _infrastructure_failure(str(exc))
                and not scripted_runner
                and setup_repairs < setup_repair_limit()
            ):
                # Before the startup test below, which is where this failure
                # used to end up: `run_lab` appends compose diagnostics to
                # every exception, and those carry `is unhealthy` from any
                # service in the project. `_startup_failure` now refuses a
                # message carrying the marker, so the ordering here is only
                # the second lock on the same door -- but it is the lock that
                # holds while the setup budget lasts, and the predicate's is
                # the one that holds after it runs out.
                #
                # The attempt is given back, as a startup failure's is. The
                # validator was never started, so this attempt measured
                # nothing and learned nothing about the vulnerability; the
                # effect budget, which is for a lab whose validator ran, is
                # deliberately not what pays for this.
                validation_attempt -= 1
                setup_repairs += 1
                attempts.append({
                    "phase": "setup",
                    "attempt": setup_repairs,
                    "ok": False,
                    "error": str(exc)[:24000],
                })
                _record(lab_dir, attempts)
                announce(
                    f"{cve}: the setup did not put the lab in the state the attack "
                    f"needs; repairing the steps "
                    f"({setup_repairs}/{setup_repair_limit()}) without spending a repair"
                )
                try:
                    repaired = repair_source_lab(
                        cve,
                        output_root,
                        # The same dict the ordinary path would build, rather
                        # than a second copy of it assembled here: one
                        # classifier means the hint and the kind cannot
                        # differ between the budgeted path and the fallback
                        # below.
                        _runtime_failure(str(exc)),
                        repair_calls,
                        api_key,
                        model,
                        provider,
                        base_url,
                        research_mode=research_mode,
                    )
                except Exception as repair_error:
                    attempts.append({
                        "phase": "setup_repair",
                        "attempt": setup_repairs,
                        "ok": False,
                        "error": str(repair_error)[:16000],
                    })
                    _record(lab_dir, attempts)
                    if isinstance(repair_error, ProviderDeclined):
                        return _declined(cve, lab_dir, attempts, repair_error, announce)
                    if _infrastructure_failure(str(repair_error)):
                        break
                    # Fall back to the ordinary path, as the startup branch
                    # does: the next loop repairs from this failure and
                    # counts it.
                    validation_attempt += 1
                    pending_failure = _runtime_failure(str(exc))
                    continue
                attempts.append({
                    "phase": "setup_repair",
                    "attempt": setup_repairs,
                    "ok": True,
                    "status": repaired.get("status"),
                })
                plan = repaired.get("plan", plan)
                pending_failure = None
                _record(lab_dir, attempts)
                continue
            if (
                _startup_failure(str(exc))
                and not _infrastructure_failure(str(exc))
                and not scripted_runner
                and startup_repairs < startup_repair_limit()
            ):
                # The validator never ran: this attempt is given back, and
                # the repair below does not count against the exploit's.
                validation_attempt -= 1
                startup_repairs += 1
                attempts.append({
                    "phase": "startup",
                    "attempt": startup_repairs,
                    "ok": False,
                    "error": str(exc)[:24000],
                })
                _record(lab_dir, attempts)
                announce(
                    f"{cve}: services did not start; repairing the startup "
                    f"({startup_repairs}/{startup_repair_limit()}) without spending a repair"
                )
                try:
                    repaired = repair_source_lab(
                        cve,
                        output_root,
                        {"hint": STARTUP_HINT, "kind": "startup_failure", "error": str(exc)},
                        repair_calls,
                        api_key,
                        model,
                        provider,
                        base_url,
                        research_mode=research_mode,
                    )
                except Exception as repair_error:
                    attempts.append({
                        "phase": "startup_repair",
                        "attempt": startup_repairs,
                        "ok": False,
                        "error": str(repair_error)[:16000],
                    })
                    _record(lab_dir, attempts)
                    if isinstance(repair_error, ProviderDeclined):
                        return _declined(cve, lab_dir, attempts, repair_error, announce)
                    if _infrastructure_failure(str(repair_error)):
                        break
                    # Fall back to the ordinary path: the next loop repairs
                    # from the startup failure and counts it.
                    validation_attempt += 1
                    pending_failure = _runtime_failure(str(exc))
                    continue
                attempts.append({
                    "phase": "startup_repair",
                    "attempt": startup_repairs,
                    "ok": True,
                    "status": repaired.get("status"),
                })
                plan = repaired.get("plan", plan)
                pending_failure = None
                _record(lab_dir, attempts)
                continue
            pending_failure = _runtime_failure(str(exc))
            attempts.append({
                "phase": "validation",
                "attempt": validation_attempt,
                "ok": False,
                "error": str(exc)[:24000],
            })
        else:
            if validated.get("ok"):
                attempts.append({
                    "phase": "validation",
                    "attempt": validation_attempt,
                    "ok": True,
                    "proof_checks": validated.get("report", {}).get("proof_checks", {}),
                })
                automation = {
                    "mode": "autonomous_generate_repair_validate",
                    "validation_attempts": validation_attempt,
                    "repair_calls": repair_calls,
                    "max_attempts": max_attempts,
                    "effect_repairs": effect_repairs,
                    "startup_repairs": startup_repairs,
                    "setup_repairs": setup_repairs,
                    "transient_retries": transient_retries,
                    "provider_stalls": provider_stalls,
                    "attempts": attempts,
                }
                validated.setdefault("report", {})["automation"] = automation
                write_text(
                    lab_dir / "report.json",
                    json.dumps(validated["report"], indent=2, ensure_ascii=True) + "\n",
                )
                _record(lab_dir, attempts, "VALIDATED")
                # Says what the run measured and stops there. It used to say
                # "verified" and nothing else, printed before the deliverables
                # were attempted, so the line an operator read as "done" was
                # the last thing a run printed that shipped an empty artifacts
                # directory.
                announce(
                    f"{cve}: exploit, patched control, and manual PoC verified; "
                    "writing the deliverables"
                )
                delivered = create_deliverables(
                    cve, lab_dir, validated, api_key, model, provider, base_url
                )
                # Nobody read this status, and that is the whole of how a
                # benchmark tree came to hold 40 labs recorded VALIDATED with
                # no artifacts/PoC.py beside them: `create_deliverables` took
                # its own refusal path, VALIDATED was already on disk from the
                # _record above -- it is written before this call, not after
                # -- and the run returned without a word about the kit it did
                # not write. The gate it took has been corrected, but the
                # silence is what let that hide until someone counted PoC.py
                # files instead of reading statuses, so the contradiction now
                # reaches both the operator and the record whatever causes it
                # next.
                #
                # The status stays VALIDATED. The lab did reproduce its CVE
                # differentially, which is what that word records, and
                # demoting it to punish the packaging would throw the proof
                # away -- the same reasoning core.run_lab applies to a kit
                # that cannot seed. What must not survive is the impression
                # that a kit was shipped, so the failure slot says otherwise.
                if not delivered.get("ok"):
                    gap = {
                        "kind": "deliverables_not_written",
                        "status": delivered.get("status"),
                        "reason": delivered.get("reason"),
                    }
                    _record(lab_dir, attempts, "VALIDATED", gap)
                    announce(
                        f"{cve}: validated, but no deliverables were written "
                        f"({gap['status'] or 'no status returned'}); there is no "
                        "PoC, manual kit, report, or walkthrough beside this lab"
                    )
                delivered["automation"] = automation
                return delivered
            report = validated.get("report", validated)
            reached = _reached_targets(report)
            # Both shapes of this failure carry a hint, and the hint is
            # inserted first so a long report cannot push it past what the
            # repair prompt keeps: `repair_source_lab` serialises this dict
            # and cuts it to 12000 characters on a local provider.
            #
            # `reached` chooses between them and nothing more. What the
            # validator did reach is still read exactly as before; the false
            # case simply stopped being the silent one.
            pending_failure = {
                "hint": EFFECT_HINT if reached else PRECONDITION_HINT,
                "kind": "proof_not_verified",
                "digest": _validation_digest(report),
                "report": report,
            }
            if (
                not scripted_runner
                and validation_attempt >= max_attempts + effect_repairs
                and effect_repairs < effect_repair_limit()
            ):
                # The two closest cases to a reproduction, and they get the
                # same budget. The lab builds, starts and runs its validator;
                # what is missing is either the effect or the state the attack
                # needed first. The precondition case used to be excluded
                # here, which gave the earlier failure fewer attempts than the
                # later one -- backwards, since it is the more mechanical of
                # the two and the one a repair can usually settle.
                effect_repairs += 1
                announce(
                    f"{cve}: "
                    + (
                        "the lab runs but the effect did not show"
                        if reached
                        else "the lab runs but the attack was never delivered"
                    )
                    + f"; one more repair ({effect_repairs}/{effect_repair_limit()})"
                )
            attempts.append({
                "phase": "validation",
                "attempt": validation_attempt,
                "ok": False,
                "proof_checks": validated.get("report", {}).get("proof_checks", {}),
                "validation": validated.get("report", {}).get("validation", {}),
            })
        _record(lab_dir, attempts)
        if validation_attempt < max_attempts:
            if pending_failure and _infrastructure_failure(
                json.dumps(pending_failure, ensure_ascii=True)
            ):
                announce(f"{cve}: transient/infrastructure failure; retrying without rewriting the PoC")
            elif scripted_runner:
                announce(f"{cve}: scripted runner failed; retrying the deterministic workflow")

    reason = pending_failure or {"kind": "repair_budget_exhausted"}
    _record(lab_dir, attempts, "AUTO_REPAIR_EXHAUSTED", reason)
    return {
        "ok": False,
        "status": "AUTO_REPAIR_EXHAUSTED",
        "cve": cve,
        "lab_dir": str(lab_dir),
        "validation_attempts": validation_attempt,
        "repair_calls": repair_calls,
        "max_attempts": max_attempts,
        "effect_repairs": effect_repairs,
        "startup_repairs": startup_repairs,
        "setup_repairs": setup_repairs,
        "transient_retries": transient_retries,
        "provider_stalls": provider_stalls,
        "failure": reason,
        "attempts": attempts,
    }
