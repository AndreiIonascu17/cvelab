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

"""Send a finished run to a CVELab control plane.

The lab runs on the user's own machine with the user's own provider key.
That key never leaves the machine: nothing here reads it, and the registry in
providers.py is what register_environment_secrets() uses to redact it out of
anything that does get sent.

Uploading is opt-in twice over. There has to be a token, and the run has to
not carry --no-upload. Without a token this module is never reached, so the
default install talks to nobody.

A run that validated joins a shared corpus, without being attributed to the
account that filed it. A run that did not validate never does: it says what
somebody was looking at and little else. describe() states this before each
upload rather than leaving it in a policy nobody opens.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

from . import __version__, progress, usage
from .core import redact
from .providers import is_loopback

# A default, not a constant: a self-hosted control plane sets CVELAB_ENDPOINT.
DEFAULT_ENDPOINT = "https://cvelab.tech"
ENDPOINT_VARIABLE = "CVELAB_ENDPOINT"

TOKEN_VARIABLE = "CVELAB_TOKEN"
TOKEN_PREFIX = "cvelab_"

#: Where a token lives when it is not in the environment. Kept out of the
#: shell history and out of CI logs, which is where exported variables leak.
TOKEN_FILE = Path.home() / ".config" / "cvelab" / "token"

#: One document that is trimmed is better than a run that is refused, but a
#: silent trim is not: anything cut is marked so the dashboard can say so.
MAX_DOCUMENT_BYTES = 128 * 1024

#: What the control plane accepts for one run. Ten documents at the
#: per-document cap would exceed it, and a 413 loses the whole entry rather
#: than part of it, so the payload is trimmed here instead. Real labs run
#: 50 to 140 KiB, so this only bites a pathological one.
MAX_PAYLOAD_BYTES = 900 * 1024

#: What leaves the machine.
#:
#: Everything the run generated, because the corpus is what the service
#: sells and a corpus of reports without runnable labs is worth little. The
#: exploit travels with the rest unless --no-poc says otherwise, which is
#: the reverse of how this started: the first version sent REPORT.md alone
#: and the exploit only on request, and that would have filled the database
#: with descriptions of labs nobody could run.
ALWAYS = (
    "REPORT.md",
    "WALKTHROUGH.md",
    "MANUAL-POC.md",
    "EVIDENCE.json",
    "PoC.py",
    "manual.sh",
    "PoC.ps1",
    "plan.json",
    "report.json",
    "analysis.json",
)

#: Withheld by --no-poc: what makes the lab reproducible rather than merely
#: described.
EXPLOIT = ("PoC.py", "manual.sh", "PoC.ps1", "MANUAL-POC.md", "plan.json")

#: What the control plane requires before a validated run joins the shared
#: corpus (site/worker/gate.js in cvelab-prod). Kept first when a payload has
#: to be trimmed, because losing one of these turns a shareable lab into a
#: refused upload.
REQUIRED_TO_SHARE = (
    "EVIDENCE.json",
    "report.json",
    "plan.json",
    "REPORT.md",
    "WALKTHROUGH.md",
    "PoC.py",
    "manual.sh",
)

#: Why a validated run was kept private, as the control plane says it.
NOT_SHARED = {
    "exploit_withheld": "kept private: filed without the exploit (--no-poc)",
    "duplicate": "kept private: this PoC is already in the database",
    "review_queue_full": (
        "kept private: ten of your entries are already waiting for review; "
        "upload it again once they are reviewed"
    ),
    "script_not_generated": (
        "kept private: manual.sh or PoC.ps1 is not the script CVELab writes; "
        "regenerate the lab rather than editing them"
    ),
    "poc_rejected": "kept private: this PoC was rejected in review",
    "earlier_entry_rejected": (
        "kept private: an earlier entry of yours for this CVE was rejected in review"
    ),
}

#: Lab status to the status the control plane stores. A status this does not
#: know is reported as "failed" rather than guessed at.
STATUS = {
    "VALIDATED": "succeeded",
    "ARTIFACT_REQUIRED": "declined",
    "GENERATION_NOT_AVAILABLE": "declined",
    "AUTO_GENERATION_FAILED": "failed",
    "AUTO_REPAIR_EXHAUSTED": "failed",
}


class UploadError(RuntimeError):
    """The control plane refused the run, or could not be reached.

    `failures` lists the checks a refused validated run did not pass (HTTP
    422), and `retry_after` is the wait, in seconds, a rate limit asked for
    (HTTP 429). Both are empty otherwise.
    """

    def __init__(self, message: str, *, failures: list[str] | None = None,
                 retry_after: int | None = None) -> None:
        super().__init__(message)
        self.failures = failures or []
        self.retry_after = retry_after


def endpoint() -> str:
    return os.getenv(ENDPOINT_VARIABLE, DEFAULT_ENDPOINT).rstrip("/")


def insecure_endpoint() -> str | None:
    """Why the endpoint may not carry a token, or None when it may.

    The token travels in a header and the exploit in the body, so plain
    HTTP is refused except to this machine, where a control plane under
    `wrangler dev` listens on http://localhost:8787.
    """
    url = endpoint()
    scheme = urlparse(url).scheme.lower()
    if scheme == "https" or (scheme == "http" and is_loopback(url)):
        return None
    return (
        f"{ENDPOINT_VARIABLE} is {url}; uploads need https://, "
        "or http:// to localhost, 127.0.0.1 or [::1]"
    )


def find_token() -> str | None:
    """The environment first, then the file; neither is an error."""
    token = (os.getenv(TOKEN_VARIABLE) or "").strip()
    if token:
        return token
    try:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


def strip_local_paths(text: str, lab_dir: Path) -> str:
    """Replace this machine's paths with ones that say nothing about it.

    A lab's documents quote the paths it ran from: Docker and Compose errors
    name the lab directory, tool output names the home directory. In the
    shared database that shows the filer's user name and how their disk is
    laid out. The lab directory becomes its own name, which is the CVE, and
    anything else under the home directory becomes `~`.
    """
    replacements: dict[str, str] = {}
    for root in (lab_dir, lab_dir.resolve()):
        if str(root) not in ("", "/", "."):
            replacements[str(root)] = lab_dir.name
    home = str(Path.home())
    if home not in ("", "/"):
        replacements.setdefault(home, "~")
    # Longest first, so the lab directory wins over the home directory it
    # sits under.
    for old in sorted(replacements, key=len, reverse=True):
        new = replacements[old]
        text = text.replace(old, new)
        # A Windows path inside JSON text has its backslashes doubled.
        escaped = json.dumps(old)[1:-1]
        if escaped != old:
            text = text.replace(escaped, json.dumps(new)[1:-1])
    return text


def read_document(path: Path, lab_dir: Path | None = None) -> dict | None:
    """One file, redacted, trimmed if it is enormous, or None if absent."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    # Files were written through write_text and are already redacted. Doing it
    # again costs nothing and covers anything assembled another way.
    text = redact(text)
    text = strip_local_paths(text, lab_dir if lab_dir is not None else path.parent.parent)
    encoded = text.encode("utf-8")
    truncated = len(encoded) > MAX_DOCUMENT_BYTES
    if truncated:
        # A JSON document cut at the end no longer parses, so it is shortened
        # from the inside instead. Anything else, or JSON that will not fit
        # that way, is cut on a character boundary, not a byte one.
        trimmed = fit_json(text, MAX_DOCUMENT_BYTES) if path.suffix == ".json" else None
        text = trimmed or encoded[:MAX_DOCUMENT_BYTES].decode("utf-8", "ignore")
    return {"name": path.name, "text": text, "truncated": truncated}


#: fit_json() never cuts a string below this, so the short fields a reader or
#: the share gate looks at (cve, status, lab_type, proof checks) stay whole.
MIN_STRING_CAP = 1024


def fit_json(text: str, limit: int) -> str | None:
    """A JSON document shortened inside its strings, so that it still parses.

    Every string longer than one cap keeps its head and says how much it
    lost, and the cap is the highest that brings the document under `limit`.
    In practice one field is enormous, the validator's raw output, and that
    is the one that gives way. None when the text is not JSON, or when even
    MIN_STRING_CAP leaves it too large.
    """
    try:
        value = json.loads(text)
    except ValueError:
        return None
    longest = max(_string_lengths(value), default=0)
    best, low, high = None, MIN_STRING_CAP, longest
    while low <= high:
        cap = (low + high) // 2
        candidate = json.dumps(_cap_strings(value, cap), indent=2)
        if len(candidate.encode("utf-8")) <= limit:
            best, low = candidate, cap + 1
        else:
            high = cap - 1
    return best


def _string_lengths(value: object) -> Iterator[int]:
    if isinstance(value, str):
        yield len(value)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_lengths(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_lengths(item)


def _cap_strings(value: object, cap: int) -> object:
    if isinstance(value, str):
        if len(value) <= cap:
            return value
        lost = len(value[cap:].encode("utf-8"))
        shortened = f"{value[:cap]}... [{lost:,} bytes trimmed]"
        # Just over the cap, the note would be longer than what it replaces.
        return shortened if len(shortened) < len(value) else value
    if isinstance(value, dict):
        return {key: _cap_strings(item, cap) for key, item in value.items()}
    if isinstance(value, list):
        return [_cap_strings(item, cap) for item in value]
    return value


def _plan(lab_dir: Path) -> dict:
    """plan.json holds what was actually resolved, not what was asked for."""
    try:
        return json.loads((lab_dir / "plan.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def collect(
    lab_dir: Path,
    result: dict,
    *,
    provider: str | None,
    model: str | None,
    include_poc: bool,
) -> dict:
    """Build the payload, reading only from the allowlist above."""
    artifacts = lab_dir / "artifacts"
    names = ALWAYS if include_poc else tuple(n for n in ALWAYS if n not in EXPLOIT)
    documents = [doc for doc in (read_document(artifacts / n, lab_dir) for n in names) if doc]
    documents, dropped = fit_payload(documents)

    plan = _plan(lab_dir)
    revisions = plan.get("revisions") or {}
    totals = usage.as_dict()
    outcome = result.get("status") or ("VALIDATED" if result.get("ok") else None)
    automation = result.get("automation") or {}

    return {
        "client_run_id": str(uuid.uuid4()),
        "cvelab_version": __version__,
        "cve": result.get("cve") or lab_dir.name,
        "repo": plan.get("repository"),
        "fixed_ref": revisions.get("patched"),
        "provider": provider,
        "model": model or (totals["models"][0] if totals["models"] else None),
        "status": STATUS.get(outcome or "", "failed"),
        "outcome": outcome,
        "attempts": automation.get("validation_attempts"),
        "input_tokens": totals["input_tokens"],
        "output_tokens": totals["output_tokens"],
        "cost_usd": totals["estimated_cost_usd"],
        "error": (
            strip_local_paths(redact(str(result["error"])), lab_dir)[:4000]
            if result.get("error")
            else None
        ),
        "documents": documents,
        "dropped_documents": dropped,
    }


def fit_payload(documents: list[dict]) -> tuple[list[dict], list[str]]:
    """Trim to what the control plane will accept, least useful first.

    What sharing requires is kept first, then the rest in ALWAYS order, so
    the analysis goes before anything the corpus gate checks. The kept
    documents stay in their original order.
    """
    total = sum(len(d["text"].encode("utf-8")) for d in documents)
    if total <= MAX_PAYLOAD_BYTES:
        return documents, []
    priority = sorted(documents, key=lambda d: d["name"] not in REQUIRED_TO_SHARE)
    kept_names, dropped, used = set(), [], 0
    for document in priority:
        size = len(document["text"].encode("utf-8"))
        if used + size <= MAX_PAYLOAD_BYTES:
            kept_names.add(document["name"])
            used += size
        else:
            dropped.append(document["name"])
    return [d for d in documents if d["name"] in kept_names], dropped


def describe(payload: dict) -> str:
    """What is about to be sent, before it is sent."""
    lines = [
        f"uploading {payload['cve']} to {endpoint()}",
        f"  status      {payload['status']} ({payload['outcome'] or 'unknown'})",
    ]
    for document in payload["documents"]:
        size = len(document["text"].encode("utf-8"))
        mark = " (truncated)" if document["truncated"] else ""
        lines.append(f"  {document['name']:<16}{size:>8,} bytes{mark}")
    if not payload["documents"]:
        lines.append("  (no documents; metadata only)")
    if payload.get("dropped_documents"):
        lines.append(
            "  too large for one upload, left out: "
            + ", ".join(payload["dropped_documents"])
        )
    lines.append("  the provider key is not part of this payload")
    if payload["status"] == "succeeded":
        # Saying this once per run is the difference between a corpus people
        # chose to join and one they were enrolled in.
        lines.append(
            "  a validated run joins the shared database under your account, "
            "listed as awaiting review; subscribers can open it once it is reviewed"
        )
        missing = [name for name in REQUIRED_TO_SHARE if name not in
                   {d["name"] for d in payload["documents"]}]
        exploit_sent = any(d["name"] in ("PoC.py", "manual.sh") for d in payload["documents"])
        if missing and exploit_sent:
            # Said before sending: the control plane will refuse it, and a
            # reason up front beats a 422 after the upload.
            lines.append("  missing what sharing requires, so it will be refused: " + ", ".join(missing))
        exploit = [d["name"] for d in payload["documents"] if d["name"] in EXPLOIT]
        lines.append(
            "  the exploit is included: " + ", ".join(exploit) + " (--no-poc to withhold)"
            if exploit
            else "  the exploit is withheld; the entry will not be runnable"
        )
    return "\n".join(lines)


def send(payload: dict, token: str, *, timeout: int = 30) -> dict:
    refusal = insecure_endpoint()
    if refusal:
        raise UploadError(refusal)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{endpoint()}/api/runs",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": f"cvelab/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", "replace")
        try:
            answer = json.loads(raw)
        except ValueError:
            answer = {}
        if not isinstance(answer, dict):
            answer = {}
        if error.code in (401, 403):
            raise UploadError(
                f"The control plane rejected the token ({error.code}). "
                f"Create a new one at {endpoint()}/app/ and set {TOKEN_VARIABLE}."
            ) from error
        if error.code == 422:
            failures = [str(f) for f in answer.get("failures") or []]
            raise UploadError(
                "The control plane refused the run: a validated run must carry the "
                "artifacts CVELab generates, and these checks failed:\n"
                + "\n".join(f"  - {failure}" for failure in failures),
                failures=failures,
            ) from error
        if error.code == 429:
            retry = _retry_after(error.headers.get("Retry-After"), answer.get("retry_after"))
            wait = f" Try again in {_duration(retry)}." if retry else ""
            raise UploadError(
                f"Rate limited: {answer.get('error') or 'too many uploads'}.{wait}",
                retry_after=retry,
            ) from error
        detail = answer.get("error") or raw[:600]
        raise UploadError(f"Upload failed with HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise UploadError(f"Could not reach {endpoint()}: {error.reason}") from error


def _retry_after(header: str | None, body: object) -> int | None:
    for value in (header, body):
        try:
            seconds = int(str(value))
        except (TypeError, ValueError):
            continue
        if seconds > 0:
            return seconds
    return None


def _duration(seconds: int) -> str:
    if seconds < 120:
        return f"{seconds} seconds"
    if seconds < 7200:
        return f"{round(seconds / 60)} minutes"
    return f"{round(seconds / 3600)} hours"


def sharing(answer: dict) -> str | None:
    """One line on whether a filed run joined the shared database, or why not."""
    if answer.get("shared") is True:
        return "shared: listed as awaiting review; subscribers can open it once it is reviewed"
    reason = answer.get("not_shared")
    if reason:
        return NOT_SHARED.get(reason, f"kept private: {reason}")
    return None


def upload_result(
    lab_dir: Path,
    result: dict,
    *,
    provider: str | None = None,
    model: str | None = None,
    include_poc: bool = True,
    token: str | None = None,
) -> dict | None:
    """Upload a finished run. Returns None when no token is configured.

    A failed upload never fails the run: the lab is on disk and `cvelab
    upload <CVE>` sends it later. Losing a validated lab because a network
    was down would be a worse outcome than an unsynced report.
    """
    token = token or find_token()
    if not token:
        return None
    payload = collect(
        lab_dir, result, provider=provider, model=model, include_poc=include_poc
    )
    progress.step(describe(payload))
    try:
        answer = send(payload, token)
    except UploadError as error:
        progress.step(f"upload failed: {error}")
        progress.step(f"the lab is kept at {lab_dir}; retry with 'cvelab upload {payload['cve']}'")
        return {"ok": False, "error": str(error)}
    if answer.get("url"):
        progress.step(f"stored at {answer['url']}")
    note = sharing(answer)
    if note:
        progress.step(note)
    return answer
