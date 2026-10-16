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
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from . import __version__, progress, usage
from .core import redact

# A default, not a constant: a self-hosted control plane sets CVELAB_ENDPOINT.
DEFAULT_ENDPOINT = "https://cvelab.tech"

TOKEN_VARIABLE = "CVELAB_TOKEN"
TOKEN_PREFIX = "cvelab_"

#: Where a token lives when it is not in the environment. Kept out of the
#: shell history and out of CI logs, which is where exported variables leak.
TOKEN_FILE = Path.home() / ".config" / "cvelab" / "token"

#: One document that is trimmed is better than a run that is refused, but a
#: silent trim is not: anything cut is marked so the dashboard can say so.
MAX_DOCUMENT_BYTES = 128 * 1024

#: What may leave the machine, and when.
#:
#: The report is the deliverable, so it goes by default. The exploit and the
#: plan do not: a service that collects working exploits against its own
#: customers' software becomes a target worth attacking. Sending them is a
#: deliberate flag, not a default.
ALWAYS = ("REPORT.md",)
WITH_POC = ("WALKTHROUGH.md", "MANUAL-POC.md", "PoC.py", "plan.json", "report.json")

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
    """The control plane refused the run, or could not be reached."""


def endpoint() -> str:
    return os.getenv("CVELAB_ENDPOINT", DEFAULT_ENDPOINT).rstrip("/")


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


def read_document(path: Path) -> dict | None:
    """One file, redacted, trimmed if it is enormous, or None if absent."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    # Files were written through write_text and are already redacted. Doing it
    # again costs nothing and covers anything assembled another way.
    text = redact(text)
    encoded = text.encode("utf-8")
    truncated = len(encoded) > MAX_DOCUMENT_BYTES
    if truncated:
        # Cut on a character boundary, not a byte one.
        text = encoded[:MAX_DOCUMENT_BYTES].decode("utf-8", "ignore")
    return {"name": path.name, "text": text, "truncated": truncated}


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
    names = ALWAYS + (WITH_POC if include_poc else ())
    documents = [doc for doc in (read_document(artifacts / n) for n in names) if doc]

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
        "error": redact(str(result["error"]))[:4000] if result.get("error") else None,
        "documents": documents,
    }


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
    lines.append("  the provider key is not part of this payload")
    return "\n".join(lines)


def send(payload: dict, token: str, *, timeout: int = 30) -> dict:
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
        detail = error.read().decode("utf-8", "replace")[:600]
        if error.code in (401, 403):
            raise UploadError(
                f"The control plane rejected the token ({error.code}). "
                f"Create a new one at {endpoint()}/app/ and set {TOKEN_VARIABLE}."
            ) from error
        raise UploadError(f"Upload failed with HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise UploadError(f"Could not reach {endpoint()}: {error.reason}") from error


def upload_result(
    lab_dir: Path,
    result: dict,
    *,
    provider: str | None = None,
    model: str | None = None,
    include_poc: bool = False,
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
    return answer
