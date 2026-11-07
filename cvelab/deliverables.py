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
from pathlib import Path

from . import policy
from .ai import ai_is_configured, structured_response
from .core import (
    SEEDING_NOT_SHIPPED,
    SHIPPED_MANUAL_PORTS_FILE,
    SHIPPED_SETUP_FILE,
    service_port,
    setup_contract,
    shipped_setup_gap,
    write_text,
)
# LAB_POC_GUIDE_NAME is the document this module writes, so it would normally
# be declared here. It is declared in field.py instead, in one block with the
# single-instance script's own names, because the two documents used to
# collide case-insensitively and declaring them in two modules is exactly how
# that happened. The comment on that block is the whole account.
from .field import LAB_POC_GUIDE_NAME, MANUAL_POC_GUIDE_NAME, MANUAL_POC_NAME

ANALYSIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "executive_summary", "mechanism", "prerequisites", "attack_path", "impact",
        "affected_components", "evidence_interpretation", "fidelity", "limitations",
        "remediation_status", "confidence_statement",
    ],
    "properties": {
        "executive_summary": {"type": "string"},
        "mechanism": {"type": "string"},
        "prerequisites": {"type": "array", "items": {"type": "string"}},
        "attack_path": {"type": "array", "items": {"type": "string"}},
        "impact": {"type": "array", "items": {"type": "string"}},
        "affected_components": {"type": "array", "items": {"type": "string"}},
        "evidence_interpretation": {"type": "string"},
        "fidelity": {"type": "string"},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "remediation_status": {"type": "string"},
        "confidence_statement": {"type": "string"},
    },
}


def _evidence(value: object, limit: int = 6000) -> str:
    text = json.dumps(value, ensure_ascii=True) if not isinstance(value, str) else value
    return text.replace("`", "'")[:limit]


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) or "- Nu exista date suficiente."


def _steps(items: list[str]) -> str:
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items, 1)) or "1. Date insuficiente."


def _variant_evidence(value: object) -> object:
    if not isinstance(value, dict):
        return value
    if "evidence" in value:
        return value["evidence"]
    if "raw_observations" in value:
        return value["raw_observations"]
    return value


#: How the boundary bullets say what the lab triggered, per trigger_source.
#:
#: Spelled out rather than printed as the bare enum name, because this is the
#: one line of the documents a reader uses to tell a reproduction of the
#: documented trigger from a route that reached the same condition another
#: way, and `substituted` on its own does not say which way round that is.
_TRIGGER_SOURCE_BULLET = {
    "documented": (
        "\n- Trigger: the configuration and request the evidence names as "
        "triggering the weakness"
    ),
    "substituted": (
        "\n- Trigger: **substituted** -- the regression input reaches the same "
        "condition by another route, not the one the evidence names. Read the "
        "simulated components above before relying on this lab as a reproduction"
    ),
}


def _fidelity(plan: dict) -> dict:
    fidelity = plan.get("fidelity")
    if isinstance(fidelity, dict):
        return fidelity
    if plan.get("lab_type") == "END_TO_END_REPRODUCTION":
        return {
            "execution_level": "product_end_to_end",
            "vendor_product_started": True,
            "exercised_vendor_components": ["vendor product"],
            "simulated_components": [],
            "rationale": "Legacy curated end-to-end profile.",
        }
    return {
        "execution_level": "source_component",
        "vendor_product_started": False,
        "exercised_vendor_components": [],
        "simulated_components": ["unspecified adapter components"],
        "rationale": "Legacy generated lab without explicit fidelity metadata.",
    }


#: The lab types that built the vendor's own source, as against a synthetic
#: class model. Two sentences are decided on this -- whether a PoC is emitted
#: at all, and whether the documents call the lab a vendor-source
#: reproduction -- and they were two copies of the same three names. A type
#: added to one and not the other would ship a source lab that described
#: itself as synthetic, or refuse a PoC for a lab the documents then described.
_SOURCE_BACKED = frozenset({
    "SOURCE_REPRODUCTION", "END_TO_END_REPRODUCTION",
    "VULNERABLE_ONLY_REPRODUCTION",
})

#: What the Manual PoC line of REPORT.md says, per report.manual_poc_status.
#: "verified" and "failed" render as the boolean they replaced, so a real
#: verdict reads exactly as it did before the third state existed.
_MANUAL_POC_VERDICTS = {
    "verified": "True",
    "failed": "False",
    "not_run": "not run; the handed-over actions were not executed",
    # The actions ran and passed, under CVELab, with CVELab's own seeding
    # merged in and its own bindings in the environment -- none of which the
    # operator has. Saying "True" here would be the report claiming a demo
    # nobody but CVELab can run; saying "False" would blame the actions,
    # which did what they were asked.
    SEEDING_NOT_SHIPPED: (
        "not verified; the handed-over actions passed under CVELab, but the kit beside "
        "this report cannot establish the state its own contract declares -- see "
        "manual_poc_shipping_gap in report.json"
    ),
}


def _manual_poc_verdict(report: dict) -> str:
    """The Manual PoC verdict, for each shape a report can carry.

    run_lab runs the handed-over actions only behind `if automatic_proof`, so
    "never ran" is a third state rather than a failure. core.run_lab no longer
    folds that empty result into proof_checks["manual_poc_verified"]: it leaves
    the key out and records the three states in manual_poc_status beside the
    checks. Reading the old key alone therefore fell through to the default
    below and credited a separate curated runner to a lab that never had one --
    the actions simply were not reached.

    The default stays, because one lab shape is exactly that. A plan.json
    `runner` lab is driven by core.run_shipyard_script and reported by
    core.shipyard_report, whose report carries no manual-PoC key at all, and
    its own script is that separate curated runner. A report.json written
    before manual_poc_status existed still has the boolean, so it is read
    before falling through.
    """
    status = str(report.get("manual_poc_status") or "")
    if status in _MANUAL_POC_VERDICTS:
        return _MANUAL_POC_VERDICTS[status]
    verified = report.get("proof_checks", {}).get("manual_poc_verified")
    return "separate curated runner" if verified is None else str(verified)


#: What the lab document says about the other kind, for each of the four
#: states a lab can be in.
#:
#: This is the half that matters more than the rename. A reader opens a file
#: called "Manual PoC", follows it, watches it work, and learns nothing about
#: whether any of it can be pointed at the client's server -- and for most
#: labs it cannot, because the single-instance script was refused. The refusal
#: reason is already written and is often the best sentence in the whole
#: record ("a stock application that calls the affected helper does not report
#: that state"), but it lived only in report.json, and nobody reads report.json
#: before a client meeting. So it goes in the document the reader actually
#: opens.
_SHIPPED_NOTE = f"""A single-instance script **does** exist for this lab, beside this document:
`{MANUAL_POC_NAME}`, with `{MANUAL_POC_GUIDE_NAME}` for how to run it. That one takes
an address you supply, and it is the artifact to use against a server you are
permitted to test.

{{proof}}"""

#: How the shipped script was proved, which differs with the lab. Said here
#: because "silent on the fixed one" is the whole strength of the claim, and a
#: vulnerable-only lab has no fixed build to have been silent on -- printing
#: that sentence for one would credit it with a differential it never had.
_SHIPPED_PROOF = {
    True: f"""CVELab ran that script against this lab's one build and observed the
effect. There was no fixed revision to compare against, so it was never held to
a differential; `{MANUAL_POC_GUIDE_NAME}` says what stands in for one.""",
    False: """CVELab built both of this lab's revisions and ran that script against each
before writing it: it observed the effect on the vulnerable build and stayed
silent on the fixed one. A script that fired on both would be watching normal
behaviour rather than the bug, and would not have been written.""",
}

#: The opening sentence of the lab document, which has to count the builds
#: correctly: a vulnerable-only lab has one, and `manual.sh` accepts only the
#: one service name. Written out per lab rather than interpolated, so the
#: emitted Markdown is wrapped like the rest of the file instead of wherever
#: a substitution happened to land.
_LAB_REACH = {
    True: """The one Docker build in this lab directory. `manual.sh` takes a Compose
service name -- `vulnerable` -- not an address, so there is no host to supply and
no option that would accept one. `PoC.py` beside it takes one optional address,
and with none it runs against this same build.""",
    False: """This lab directory's two Docker builds. `manual.sh` takes a Compose service
name -- `vulnerable` or `patched` -- not an address, so there is no host to
supply and no option that would accept one. `PoC.py` beside it takes one
optional address, and with none it runs against these same builds.""",
}

_NOT_REQUESTED_NOTE = """There is no single-instance script for this lab, because one was never asked
for. `cvelab run --manual-poc`, or `cvelab manual-poc` on a lab that has already
validated, attempts one. Until that is run, nothing here has been proved past
this lab's own builds."""

_NO_RECORD_NOTE = """This run kept no record of a single-instance script either way, and none is
present. Treat that as "not available" rather than "refused": a lab driven by
its own curated runner never attempts one. Everything in this document reaches
this lab's own builds only: `PoC.py` here accepts an address, and nothing in this
run proved it against one."""

_REFUSED_NOTE = """There is **no** single-instance script for this lab. CVELab tried to write one,
proved it could not, and recorded why:

{reason}

That sentence is the limit of what this lab can show, and it is the one to
repeat rather than implying the demonstration below would carry over. `PoC.py`
here will accept an address, but nothing in this document proves it may be
pointed at a server you did not build here."""


def _quoted(reason: str) -> str:
    """A recorded reason as a Markdown blockquote, however it was written.

    Prefixed line by line. The reason is model prose from a refused draft and
    a blank line inside it would end the quote and leave the rest of the
    sentence rendering as body text, which reads as CVELab's own claim rather
    than as the drafter's reason for refusing.
    """
    return "\n".join(f"> {line}" if line.strip() else ">" for line in reason.splitlines())


def _single_instance_note(artifacts: Path, report: dict, vulnerable_only: bool) -> str:
    """What the lab document says about the single-instance script.

    Read from `report.manual_poc_field`, which core.run_lab already writes for
    every run: `{"shipped": bool, "reason": str}`, with
    `reason: "not requested"` when the step was never asked for. No change to
    core.py was needed -- create_deliverables is handed the same report dict
    that run_lab returns, and the field is in it.

    The file on disk is consulted first and wins. The script is written by
    field.write_manual_poc, which core.run_lab calls as `after_validation`
    before create_deliverables runs, so by the time this executes the answer
    is on disk. Trusting disk first also keeps the document honest when it is
    re-rendered for an archived lab whose report predates the field: the
    document describes what the reader actually has.
    """
    record = report.get("manual_poc_field")
    record = record if isinstance(record, dict) else {}
    if record.get("shipped") is True or (artifacts / MANUAL_POC_NAME).is_file():
        return _SHIPPED_NOTE.format(proof=_SHIPPED_PROOF[vulnerable_only])
    reason = str(record.get("reason") or "").strip()
    if not record:
        return _NO_RECORD_NOTE
    # The one reason core.py writes itself, rather than taking from the
    # drafter: the step was never asked for, so there is nothing to quote and
    # quoting it would read as a refusal the model made.
    if not reason or reason == "not requested":
        return _NOT_REQUESTED_NOTE
    return _REFUSED_NOTE.format(reason=_quoted(reason))


#: The handed-over demo, as a template filled by substitution rather than an
#: f-string.
#:
#: Every `${...}` a shell script needs is a brace pair an f-string has to
#: have doubled, and this script is almost entirely braces. The version that
#: was an f-string documented a `cd` into a directory it also said to run
#: from, passed `--no-deps` to the one command whose dependency wait was the
#: point, and reached the validator with `compose run`, which the internal
#: path had already stopped doing and written down why. Reading it was the
#: problem; the three substitutions it genuinely needs are named instead.
_MANUAL_RUNNER = r'''#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$LAB_ROOT/artifacts/.manual-state"
BOUND="$LAB_ROOT/artifacts/.manual-bound"
SEEDING="$LAB_ROOT/artifacts/__SETUP_FILE__"
PORTS="$LAB_ROOT/artifacts/__PORTS_FILE__"
SERVICE_PORT="__SERVICE_PORT__"
COMPOSE=(docker compose -f "$LAB_ROOT/docker-compose.yml" --project-directory "$LAB_ROOT")

# The one port this lab publishes, on loopback, with the host side left for
# the kernel to assign. It is a Compose file of CVELab's merged over the
# lab's, exactly as the seeding below is -- the lab's own docker-compose.yml
# still publishes nothing and its network is still internal. Without it the
# product is reachable only from inside that network, which is where the
# steps below reach it either way; this is what gives PoC.py an address on
# this machine. A lab generated before this existed ships no such file, takes
# neither branch, and runs exactly as it did.
if [[ -n "$SERVICE_PORT" && -f "$PORTS" ]]; then
  COMPOSE+=(-f "$PORTS")
fi

# The state this lab's own contract declares, as a Compose file merged over
# the lab's -- the same file, byte for byte, that CVELab merged while it
# validated this lab. A lab that declares no seeding ships none, takes
# neither branch, and runs exactly as it did before this existed.
if [[ -f "$SEEDING" ]]; then
  COMPOSE+=(-f "$SEEDING")
elif grep -q '"setup_port"' "$LAB_ROOT/artifacts/plan.json" 2>/dev/null; then
  echo "This lab's contract declares setup steps, but artifacts/__SETUP_FILE__ is not here." >&2
  echo "Without it the demo starts the product unseeded, the attack reaches an instance" >&2
  echo "with nothing to act on, and the affected build reports BLOCKED. Regenerate the" >&2
  echo "lab rather than running it this way." >&2
  exit 2
fi

usage() {
  echo "Usage: bash manual.sh <setup|exploit|verify|address|cleanup> [__USAGE_TARGETS__]" >&2
  exit 2
}

# The address PoC.py takes, read back from Docker rather than written down.
# The override publishes "127.0.0.1::<container port>" -- the host side is
# empty on purpose, so nothing collides with a port the operator is already
# using and nothing the model wrote picks a number. That means the number is
# not knowable until the container is up, and it differs between runs, which
# is why this asks Docker instead of printing a constant.
address() {
  local variant="$1" published=""
  [[ -n "$SERVICE_PORT" && -f "$PORTS" ]] || return 1
  published="$("${COMPOSE[@]}" port "$variant" "$SERVICE_PORT" 2>/dev/null | tail -n 1)" || published=""
  [[ -n "$published" ]] || return 1
  printf '%s' "$published"
}

target() {
  local requested="${1:-}"
  if [[ -z "$requested" && -s "$STATE" ]]; then requested="$(<"$STATE")"; fi
  case "$requested" in
    __CASE_TARGETS__) printf '%s' "$requested" ;;
    *) echo "Choose a valid target and run setup first." >&2; exit 2 ;;
  esac
}

TOOL_OUT=""
TOOL_ERR=""
TOOL_CODE=1

# One of the lab's `profiles: ["tools"]` services, run to completion: this is
# what CVELab does internally, in shell.
#
# Brought up with `up` and not `run`, which is the whole reason this is a
# function. A one-off `compose run` container does not get the aliases its
# service declares on the network, so a validator that reaches its own canary
# by name -- an endpoint standing in for the upstream the product calls, which
# is how a request-forgery finding is observed without leaving the lab -- gets
# "Temporary failure in name resolution" and the lab reads as not reproduced.
# Measured on one lab three runs running, and every lab built around a named
# stand-in was failing the same way.
#
# `--no-deps` is deliberate here and safe only because of the line above each
# call site: the health wait it would otherwise skip is done by `up --wait` on
# the build itself. It is also what keeps a single-target manual lab
# single-target -- the validator declares a wait on both builds, so without it
# `up` would build and start the one the operator did not ask for.
# `--force-recreate` cannot reach the product for the same reason.
tool_run() {
  local service="$1" container="" code=""
  "${COMPOSE[@]}" --profile tools up -d --force-recreate --no-deps "$service" >&2
  container="$("${COMPOSE[@]}" --profile tools ps -aq "$service" | tail -n 1)" || container=""
  if [[ -z "$container" ]]; then
    echo "$service started but no container id came back" >&2
    return 1
  fi
  code="$(docker wait "$container")" || code=""
  TOOL_CODE="$(printf '%s\n' "$code" | tail -n 1)"
  [[ -n "$TOOL_CODE" ]] || TOOL_CODE=1
  TOOL_OUT="$(docker logs "$container" 2>/dev/null)" || TOOL_OUT=""
  TOOL_ERR="$(docker logs "$container" 2>&1 1>/dev/null)" || TOOL_ERR=""
  docker rm -f "$container" >/dev/null 2>&1 || true
}

# Put this build in the state its attack needs, and keep what that bound.
#
# Run once per build and never shared between them: a session on the affected
# build is not a session on the fixed one, and one set of bindings used for
# both would hand the fixed build a token the affected build issued -- which
# is a comparison between two different things, and the comparison is the
# proof.
seed() {
  local variant="$1" line="" bound=""
  rm -f "$BOUND"
  [[ -f "$SEEDING" ]] || return 0
  echo "Putting the $variant build in the state the attack needs"
  export CVELAB_SETUP_TARGET="$variant"
  tool_run __SETUP_SERVICE__ || TOOL_CODE=1
  unset CVELAB_SETUP_TARGET
  line="${TOOL_OUT##*$'\n'}"
  if [[ "$TOOL_CODE" != "0" || "$line" != *'"bound":'* ]]; then
    echo "lab setup did not establish the state the attack needs; run cleanup first" >&2
    [[ -z "$line" ]] || printf '%s\n' "$line" >&2
    [[ -z "$TOOL_ERR" ]] || printf '%s\n' "$TOOL_ERR" >&2
    exit 1
  fi
  # The runner reports {"requests": [...], "bound": {...}} and `bound` is its
  # last key, so the object is what is left after the key and before the
  # report's own closing brace. Parameter expansion and nothing else: the
  # only thing this script asks the machine to have is Docker.
  bound="${line#*\"bound\":}"
  bound="${bound%\}}"
  bound="${bound# }"
  printf '{"%s": %s}\n' "$variant" "$bound" > "$BOUND"
}

action="${1:-}"
if [[ "$action" == "cleanup" ]]; then
  "${COMPOSE[@]}" down --volumes --remove-orphans
  rm -f "$STATE" "$BOUND"
  exit 0
fi
variant="$(target "${2:-}")"
case "$action" in
  setup)
    [[ ! -e "$STATE" ]] || { echo "A manual lab is already active; run cleanup first." >&2; exit 2; }
    "${COMPOSE[@]}" build "$variant" validator
    # `--wait` is the health gate, and it is the step that used to be missing.
    # This printed "Manual lab ready" the moment `up -d` returned, which is
    # before a product that compiles assets or migrates a database on first
    # boot has listened at all: the attack then went out first and reported
    # "targets not ready", which reads as a lab that failed to reproduce.
    # Internally the wait comes from the validator's own
    # `depends_on: {condition: service_healthy}`; here it has to be done by
    # whoever starts the build, because the later steps deliberately do not
    # start the dependencies that would carry it.
    "${COMPOSE[@]}" up -d --build --wait "$variant"
    seed "$variant"
    printf '%s' "$variant" > "$STATE"
    echo "Manual lab ready: $variant"
    # The one address, and the one command that uses it, printed where the
    # operator is already looking. The steps below reach the product by
    # service name inside the lab's network and need none of this; PoC.py run
    # by hand on this machine needs exactly this line, and the host port is
    # assigned at `up` so there is nowhere else it could have been written
    # down. `address` reprints it.
    if POC_AT="$(address "$variant")"; then
      echo "This build is reachable on $POC_AT"
      echo "  python3 \"$LAB_ROOT/artifacts/PoC.py\" $POC_AT__COMMAND_HINT__"
    fi
    ;;
  address)
    [[ -s "$STATE" ]] || { echo "Run setup first." >&2; exit 2; }
    [[ "$(<"$STATE")" == "$variant" ]] || { echo "Target differs from the active manual lab." >&2; exit 2; }
    POC_AT="$(address "$variant")" || {
      echo "This lab publishes no host port, so there is no address to give PoC.py." >&2
      echo "Drive it with exploit and verify, which reach the product inside the" >&2
      echo "lab's own network." >&2
      exit 2
    }
    printf '%s\n' "$POC_AT"
    ;;
  exploit|verify)
    [[ -s "$STATE" ]] || { echo "Run setup first." >&2; exit 2; }
    [[ "$(<"$STATE")" == "$variant" ]] || { echo "Target differs from the active manual lab." >&2; exit 2; }
    # The health wait again, and idempotent: a container the host restarted
    # between two steps is running before it is ready. `--no-recreate` leaves
    # the build, and whatever setup seeded into it, exactly as it is.
    "${COMPOSE[@]}" up -d --no-recreate --wait "$variant"
    # The lab's Compose file declares these as ${...}, so they travel in the
    # environment: `up` has no equivalent of -e. The bindings go with them,
    # because a manual action sends the attack again and needs the same state
    # the automatic proof had.
    export CVELAB_MANUAL_ACTION="$action"
    export CVELAB_TARGET="$variant"
    export CVELAB_BOUND=""
    [[ ! -s "$BOUND" ]] || CVELAB_BOUND="$(<"$BOUND")"
    tool_run validator || exit 1
    [[ -z "$TOOL_ERR" ]] || printf '%s\n' "$TOOL_ERR" >&2
    [[ -z "$TOOL_OUT" ]] || printf '%s\n' "$TOOL_OUT"
    # The verdict the script printed is the measurement, and the exit status
    # is how it says the same thing a second time. It is passed through
    # rather than flattened, because on the fixed build the attack is
    # supposed to fail: exit 1 beside BLOCKED is the convention, not an error.
    exit "$TOOL_CODE"
    ;;
  *) usage ;;
esac
'''

#: What the exit status of `exploit` and `verify` means, per lab.
#:
#: The convention is the same either way, but only one of the two labs has a
#: build the convention is about. A vulnerable-only lab has no fixed build --
#: the section above this one says so, and `manual.sh` offers no service name
#: for one -- so telling its reader that exit 1 beside `BLOCKED` is expected
#: points at a build the same document denies, and reads as though a
#: non-zero exit were nothing to worry about on the only build there is.
_EXIT_STATUS = {
    True: """`exploit` and `verify` exit 0 when the effect is present on the target they were
given and 1 when it is not. This lab has only the affected build, so a non-zero
exit is the effect not being observed, not a control refusing the attack.""",
    False: """`exploit` and `verify` exit 0 when the effect is present on the target they were
given and 1 when it is not, so on the fixed build exit 1 beside `BLOCKED` is the
expected outcome rather than a failure.""",
}

#: The Windows wrapper. Four steps, in PowerShell's spelling, through WSL.
_MANUAL_WRAPPER = r'''param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("setup", "exploit", "verify", "address", "cleanup")]
    [string]$Action,
    [ValidateSet(__PS_TARGETS__)]
    [string]$Variant = "vulnerable"
)
$script = Join-Path $PSScriptRoot "manual.sh"
$wslScript = (& wsl -- wslpath -a $script).Trim()
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& wsl -- bash $wslScript $Action $Variant
exit $LASTEXITCODE
'''


def _write_generic_manual_assets(
    cve: str,
    lab_dir: Path,
    artifacts: Path,
    vulnerable_only: bool,
    report: dict | None = None,
    seeds: bool = False,
    port: int | None = None,
    executes: bool = False,
) -> None:
    """Write the kit the lab is handed over with: runner, wrapper and guide.

    `report` is the dict `run_lab` returns. It is read for one thing only --
    `manual_poc_field`, which is how the guide can say whether a
    single-instance script exists for this lab and, where one was refused,
    quote the drafter's own reason for refusing.

    `seeds` says whether this lab's contract declares the state its attack
    needs. It changes only the guide: the runner keys on whether the seeding
    file is beside it, so one script serves both and a lab without seeding
    gets the behaviour it always had.

    `port` is `exploit_contract.service_port` -- the port the product listens
    on inside its container. Given one, `manual.sh` appends the loopback
    publishing override `prepare_compose` wrote and prints the assigned
    address; without one, which is every lab generated before that field
    existed, it does neither and the guide says so. It is substituted here
    rather than parsed out of plan.json by the shell, so the script's only
    dependency stays Docker.

    `executes` says the lab's declared evidence is command execution, which
    is the one shape where the generated script takes a command as its second
    argument. It changes what the guide shows and the hint `manual.sh` prints
    beside the address; a lab of any other shape is shown neither, because
    there a command has nothing to mean.
    """
    targets = ("vulnerable",) if vulnerable_only else ("vulnerable", "patched")
    patched_note = (
        "No patched target is available for this CVE."
        if vulnerable_only
        else "Repeat the same steps with `patched`; successful verification prints `BLOCKED`."
    )
    manual_runner = (
        _MANUAL_RUNNER
        .replace("__SETUP_FILE__", SHIPPED_SETUP_FILE)
        .replace("__SETUP_SERVICE__", policy.SETUP_SERVICE)
        .replace("__PORTS_FILE__", SHIPPED_MANUAL_PORTS_FILE)
        .replace("__SERVICE_PORT__", "" if port is None else str(port))
        .replace("__COMMAND_HINT__", " id" if executes else "")
        .replace("__USAGE_TARGETS__", "|".join(targets))
        .replace("__CASE_TARGETS__", "|".join(f'"{name}"' for name in targets))
    )
    write_text(artifacts / "manual.sh", manual_runner)
    manual_wrapper = _MANUAL_WRAPPER.replace(
        "__PS_TARGETS__", ", ".join(f'"{name}"' for name in targets)
    )
    write_text(artifacts / "PoC.ps1", manual_wrapper)
    patched_section = "" if vulnerable_only else '''## Patched control

```bash
bash manual.sh setup patched
bash manual.sh exploit patched
bash manual.sh verify patched
bash manual.sh cleanup
```

Successful verification of the fixed revision prints `BLOCKED`.

'''
    seeded_section = f'''## Seeded state

This lab's attack needs the product to be in a state first -- a session, an
account, a record for the attack to act on. The steps that establish it are in
this lab's contract, and they travel with the lab as `{SHIPPED_SETUP_FILE}`
beside this file: a Compose file `manual.sh` merges over the lab's own, which
is the same file CVELab merged while it validated this lab.

`setup` runs those steps against the build it has just started, once per
build, and carries what they bound through to `exploit` and `verify`. If a
step does not complete, `setup` stops there and says which one: an unseeded
instance answers the attack with nothing to show, which is indistinguishable
from a fixed build refusing it.

The steps and what they bind are recorded in `plan.json` under
`exploit_contract.setup`.

''' if seeds else ""
    # The section the whole change exists for: one address, and the line that
    # uses it. `PoC.py` was `validator.py` with a six-line docstring on top --
    # byte-identical otherwise in all 89 archived labs -- so this document
    # told the reader to read it and then run `manual.sh`, which starts the
    # same code inside the Compose network. Nothing published a host port and
    # nothing read an argument, so there was no third thing to do with the
    # script. Both halves are now here: the override `manual.sh` appends, and
    # the argument the script takes.
    #
    # Absent for a lab whose plan declares no port, which is every lab
    # generated before the contract asked for one. The script in such a lab
    # does not read an argument either, so a section telling its reader to
    # pass one would describe a lab they do not have.
    command_block = f'''
This lab's declared evidence is command execution, so a second argument is one
command to run on the target:

```bash
python3 PoC.py "$(bash manual.sh address vulnerable)" id
```

It delivers that command through the same weakness the differential proved and
prints its output. With no command it runs this lab's own harmless canary, so
the one-argument form is unchanged.
''' if executes else ""
    direct_section = f'''## Running PoC.py yourself

`PoC.py` is the script `exploit` runs inside the lab, and it takes one optional
argument: the address of an instance that is already running. Given none it
behaves exactly as it does inside the lab, which is the path automatic
validation takes.

`setup` publishes this build's container port {port} on loopback and prints the
address the kernel assigned it. The host side is assigned at `setup`, so it is
different every run and there is no constant to write down -- `address` reprints
the current one.

```bash
bash manual.sh setup vulnerable
python3 PoC.py "$(bash manual.sh address vulnerable)"
```
{command_block}
Given an address the script holds one session for the whole run and performs this
lab's declared setup steps itself: CVELab establishes that state for `exploit`
and a person running the script by hand has none of it.

Where you point it is yours to answer for. It sends live requests to whatever
address you give it, so give it only a host your engagement covers, and keep
that authorization in writing.

''' if port is not None else '''## Running PoC.py yourself

This lab was generated before the contract asked for the port the product listens
on, so `manual.sh` publishes nothing, there is no host address to give `PoC.py`,
and the script here reads no argument. Drive it with `exploit` and `verify`,
which reach the product inside the lab's own network. Regenerating the lab
produces a kit that publishes the port and a script that takes an address.

'''
    # The title and the first two sections say the reach before anything
    # else, because this document is read standing up. Both documents used to
    # open with the identical line `# {{cve}} Manual PoC`, so the reader could
    # not tell from the heading, the filename or the first paragraph which of
    # the two reaches a live server. Only one does, and it is not this one.
    single_instance = _single_instance_note(artifacts, report or {}, vulnerable_only)
    manual_guide = f'''# {cve} Lab PoC

## What this runs against

{_LAB_REACH[vulnerable_only]} The one thing here that can
be pointed at a client's server, a staging instance, or anything else outside
this lab is that argument, and only where you are authorized to test it.

## Is there a version that runs against a live instance?

{single_instance}

## How the steps work

The manual runner uses the same isolated images and exact request as automatic validation,
but leaves setup, exploitation, evidence verification, and cleanup as separate inspectable steps.

Everything below needs Docker and this lab directory. Nothing else: not CVELab,
and not a network route back to the machine that generated it. The one step that
wants Python on the host is running `PoC.py` yourself, and it imports only the
standard library.

## Kali/Linux

Run these from the lab's `artifacts/` directory, the one this file is in:

```bash
sed -n '1,260p' PoC.py
bash manual.sh setup vulnerable
bash manual.sh exploit vulnerable
bash manual.sh verify vulnerable
bash manual.sh cleanup
```

`manual.sh` finds the lab from its own path, so it runs from any directory;
the block above is written for `artifacts/` because that is where `PoC.py` is.

A confirmed vulnerable reproduction prints `REPRODUCED`. {patched_note}

## Windows

`PoC.ps1` is the same actions, in PowerShell's spelling, run through WSL. It
resolves `manual.sh` beside itself, hands WSL the translated path, and returns
the exit status the runner returned, so the verdicts and the convention below
are identical.

```powershell
.\\PoC.ps1 -Action setup -Variant vulnerable
.\\PoC.ps1 -Action exploit -Variant vulnerable
.\\PoC.ps1 -Action verify -Variant vulnerable
.\\PoC.ps1 -Action cleanup
```

It needs WSL with a distribution installed and Docker reachable from inside it.
Docker Desktop's WSL integration is one way; a Docker installed in the
distribution itself is another.

{patched_section}{seeded_section}{direct_section}## What each step does

- `setup` builds the selected source revision, starts only that target, and waits
  for it to report healthy before going on{' -- then establishes the state the attack needs' if seeds else ''}.
- `exploit` sends the exact local attack and prints the raw observation without deciding the result.
- `verify` repeats the controls and evaluates the declared security effect.
- `address` reprints the host address this build was published on.
- `cleanup` removes this Compose project's containers, network, and volumes.

{_EXIT_STATUS[vulnerable_only]}

`manual.sh` takes Docker service names only; `PoC.py` takes one optional address, and
where you point it is yours to answer for -- only a host your engagement authorizes.
'''
    write_text(artifacts / LAB_POC_GUIDE_NAME, manual_guide)


def _automatic_analysis(
    dossier: dict,
    plan: dict,
    report: dict,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    material = {"cve_dossier": dossier, "lab_plan": plan, "validation_report": report}
    return structured_response(
        api_key=api_key,
        model=model,
        schema=ANALYSIS_SCHEMA,
        schema_name="cvelab_final_analysis",
        max_output_tokens=6000,
        instructions=(
            "Write a technically precise English defensive-research analysis for the supplied CVE and local lab. "
            "Use only facts present in the input. Clearly distinguish CVE metadata, model inference, and observed "
            "lab evidence. Never claim the vendor product was validated when lab_type is SYNTHETIC_CLASS_LAB. "
            "Treat lab_plan.fidelity as authoritative: never describe source_component as product end-to-end, and "
            "name simulated components when explaining limitations. "
            "Explain the actual vulnerability mechanism and prerequisites, not merely the CWE definition. "
            "For the legacy attack_path field, describe only the regression input already executed inside the generated "
            "Docker network and its observed security effect. Do not introduce capabilities, targets, procedures, or "
            "claims beyond the contained test evidence. Do not add unverified versions, commits, patches, mitigations, "
            "or repositories. If a fix is not in the input, say "
            "that remediation status cannot be confirmed from the collected record. "
            # This analysis overrides remediation_status and
            # evidence_interpretation, which are two of the four places a
            # demoted lab used to deny its own fixing reference, so the
            # distinction has to reach the model as well as the templates.
            "A lab_plan.demotion means something different from an absent fix: a fixed "
            "revision was resolved and then discarded because the pair could not show a fix. "
            "Where it is present, say that and give its recorded reason, and do not say that "
            "no fix was identified or that one should be waited for."
        ),
        input_text=json.dumps(material, ensure_ascii=True),
        provider=provider,
        base_url=base_url,
    )


def create_deliverables(
    cve: str,
    lab_dir: Path,
    result: dict,
    api_key: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict:
    plan = json.loads((lab_dir / "plan.json").read_text(encoding="utf-8"))
    dossier = json.loads((lab_dir / "dossier.json").read_text(encoding="utf-8"))
    report = result.get("report", {})
    validation = report.get("validation", {})
    automation = report.get("automation", {})
    artifacts = lab_dir / "artifacts"
    fidelity_record = _fidelity(plan)
    real_poc_verified = (
        result.get("ok") is True
        and plan.get("lab_type") in _SOURCE_BACKED
        and report.get("real_poc_verified") is True
        and validation.get("attack_executed") is True
        and validation.get("proof_quality") in {
            "security_effect_observed",
            "end_to_end_security_effect_observed",
        }
    )
    if not real_poc_verified:
        return {
            "ok": False,
            "status": "POC_NOT_VERIFIED",
            "cve": cve,
            "lab_dir": str(lab_dir),
            "reason": (
                "The real vulnerable source path did not produce a verified security effect. "
                "No PoC, walkthrough, or success report was emitted."
            ),
            "validation": validation,
        }
    analysis = None
    analysis_error = None
    if model and ai_is_configured(api_key, model, provider):
        try:
            analysis = _automatic_analysis(
                dossier, plan, report, api_key, model, provider, base_url
            )
        except Exception as exc:
            # The evidence-backed deterministic report is still complete. A
            # prose-analysis API failure must not discard a validated PoC.
            analysis_error = str(exc)
        else:
            write_text(artifacts / "analysis.json", json.dumps(analysis, indent=2, ensure_ascii=True) + "\n")
    elif (artifacts / "analysis.json").is_file():
        analysis = json.loads((artifacts / "analysis.json").read_text(encoding="utf-8"))

    validator = (lab_dir / "validator" / "validator.py").read_text(encoding="utf-8")
    poc_header = (
        f'"""Local-only verified exploit PoC for {cve}.\n\n'
        f'Lab type: {plan["lab_type"]}. Scenario: {plan.get("scenario", "default")}.\n'
        'This script is designed for the generated Docker lab, not remote targets.\n"""\n\n'
    )
    poc_path = artifacts / "PoC.py"
    write_text(poc_path, poc_header + validator)
    poc_name = "PoC.py"
    # Read once rather than per sentence. It was asked of the plan here and
    # then again below, which is one expression to keep in step with itself
    # for no gain: the manual assets and the prose have to agree about which
    # lab this is or the kit describes a patched side the documents deny.
    vulnerable_only = plan.get("lab_type") == "VULNERABLE_ONLY_REPRODUCTION"
    try:
        seeds = setup_contract(plan) is not None
    except RuntimeError:
        # A contract that names steps without a usable port never reaches
        # here -- `run_lab` refuses it before anything is built -- and if one
        # somehow did, the guard below is what says so.
        seeds = False
    # The report goes in so the document can say whether a single-instance
    # script exists for this lab and, where one was refused, quote the
    # drafter's own reason. That reason is already in report.manual_poc_field,
    # which run_lab writes for every run and hands back in the dict this
    # function is called with -- so core.py needed no change to pass it.
    # The declared port and the declared evidence shape, both read from the
    # contract in plan.json and neither inferred. A lab that declares no port
    # is an archived one, and gets the kit it always had.
    contract = plan.get("exploit_contract")
    contract = contract if isinstance(contract, dict) else {}
    _write_generic_manual_assets(
        cve, lab_dir, artifacts, vulnerable_only, report, seeds,
        service_port(plan),
        contract.get("evidence_type") == "code_execution",
    )
    # Where the guard in `core.run_lab` is settled, because this is the line
    # above that makes it answerable.
    #
    # The kit is written here and the report is written there, and neither
    # place can see the whole of it: when `run_lab` asks, the seeding file is
    # on disk -- `prepare_compose` writes it before anything is built -- but
    # `manual.sh` is not, because this pass runs after `run_lab` has
    # returned. So run_lab's answer is provisional for any lab that declares
    # seeding, and this one is final: both call the same function in core,
    # and the verdict is recomputed here rather than only lowered, or a lab
    # whose kit is complete would keep the "no manual.sh" answer run_lab
    # could not avoid giving.
    #
    # `lab_dir/report.json` is rewritten with it, so the lab does not ship
    # two reports disagreeing about one claim.
    shipping_gap = shipped_setup_gap(lab_dir, plan)
    claimed = report.get("manual_poc_status")
    # Only where the manual PoC was claimed at all. "failed" and "not_run"
    # are verdicts on the actions, which this knows nothing about, and the
    # third shape is a report with no manual record of its own.
    if claimed in {"verified", SEEDING_NOT_SHIPPED}:
        settled = SEEDING_NOT_SHIPPED if shipping_gap else "verified"
        if (claimed, report.get("manual_poc_shipping_gap")) != (settled, shipping_gap or None):
            report["manual_poc_status"] = settled
            report["manual_poc_shipping_gap"] = shipping_gap or None
            write_text(
                lab_dir / "report.json",
                json.dumps(report, indent=2, ensure_ascii=True) + "\n",
            )
    write_text(artifacts / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")

    source_note = (
        "This is a vendor-source reproduction using the revisions recorded below. "
        "Its fidelity level is recorded separately and must not be inferred from source use alone."
        if plan["lab_type"] in _SOURCE_BACKED
        else "This is a synthetic CWE-class demonstration, not a vendor-source reproduction."
    )
    revisions = plan.get("revisions", {})
    # Two different labs wear the same lab_type, and every sentence below that
    # says why there is no patched side has to tell them apart. A demoted lab
    # did identify a fixed revision -- sourcegen resolved it, read its diff,
    # found the pair could not show a fix and discarded it -- so the stock
    # "no public fixed revision was identified" is false for it, and its
    # remedy is wrong too: there is nothing to wait for, the reference needs
    # resolving again. plan.json carries the reason; these read it.
    demotion = plan.get("demotion") or {}
    demoted = vulnerable_only and bool(demotion)
    demotion_reason = demotion.get("reason") or "the pair could not show the fix"
    rejected_fixed = demotion.get("rejected_fixed")
    # The revision as every sentence names it. A demotion that recorded no
    # revision still has to be nameable, because the point of the sentence is
    # that one was identified.
    named_fix = rejected_fixed or "unrecorded"
    # The clause that says what happened to it, in one place.
    #
    # The reason ends with the remedy, so it goes last in whatever sentence
    # carries it, introduced by a colon. Three sentences carry it -- the scope
    # note of both documents, the report's interpretation of its own status,
    # and its remediation status -- and all three held a verbatim copy of it
    # under a comment saying there was one place to change the wording. There
    # was not: a reworded copy would have had the same lab answer the question
    # two ways in one deliverable.
    discarded_fix = (
        f"A fixed revision (`{named_fix}`) was identified and then discarded: "
        f"{demotion_reason}."
    )
    # What stands in the Patched row of both documents. revisions.patched is
    # null for a demoted lab too, so the row fell through to "no public fixed
    # revision identified" -- which denies the very reference the row exists
    # to show.
    discarded_revision = (
        f"{named_fix} (identified, then discarded as unusable)" if demoted else None
    )
    if demoted:
        source_note = (
            "This is a vendor-source vulnerable-only reproduction, so no patched behavior "
            f"is claimed. {discarded_fix}"
        )
    elif vulnerable_only:
        source_note = (
            "This is a vendor-source vulnerable-only reproduction. No public fixed revision "
            "was identified at generation time, so no patched behavior is claimed."
        )
    scenario = plan.get("scenario", "default")
    contract = plan.get("exploit_contract", {})
    scenario_details = (
        "The synthetic model submits an object from `tenant-a` with an attacker-selected "
        "destination of `kube-system`. The vulnerable variant creates it there; the patched "
        "model rejects cross-namespace injection."
        if scenario == "namespace_injection"
        else (
            "The validator executes the real vulnerable source path and records the declared "
            "security effect. No synthetic patched variant is created."
            if vulnerable_only
            else contract.get(
                "attack_summary",
                "The validator executes the source-backed scenario recorded in plan.json.",
            )
        )
    )
    if analysis:
        scenario_details = analysis["mechanism"]
        prerequisites = _bullets(analysis["prerequisites"])
        attack_path = _steps(analysis["attack_path"])
        analyst_fidelity = analysis["fidelity"]
    else:
        prerequisites = "- Consult the CVE dossier and generated plan."
        if vulnerable_only:
            # Step 4 is an instruction to the operator, so a false version of
            # it does not merely misreport: it has the operator write down
            # that no fix was identified for a lab where one was.
            attack_path = (
                "1. Build and start the recorded vulnerable upstream revision.\n"
                "2. Execute the generated local-only attack with a unique canary.\n"
                "3. Verify the concrete security effect using an independent observation.\n"
                + (
                    "4. Record that no patched control was tested because the fixed revision "
                    f"that was identified could not serve as one: {demotion_reason}."
                    if demoted
                    else "4. Record that no patched control was tested because no public fix "
                    "was identified."
                )
            )
            analyst_fidelity = (
                "This is a source-backed vulnerable-only reproduction. It proves the observed "
                "effect for the recorded revision but makes no remediation claim."
            )
        else:
            prerequisites = _bullets(contract.get("preconditions", []))
            attack_path = (
                "1. Build and start both recorded source revisions.\n"
                "2. Execute the exact local attack declared in plan.json against the vulnerable target.\n"
                "3. Capture the raw response and independently check the declared security effect.\n"
                "4. Repeat the identical attack against the patched target and require it to be blocked."
            )
            analyst_fidelity = fidelity_record.get("rationale", "See plan.json.")
    fidelity = (
        f"Execution level: `{fidelity_record.get('execution_level', 'unknown')}`. "
        f"Vendor product started: `{fidelity_record.get('vendor_product_started', False)}`. "
        f"{fidelity_record.get('rationale', analyst_fidelity)}"
    )
    # Where the lab stops being the vendor's own code, as both documents say
    # it. One pair of bullets rather than two identical ones: this is the
    # boundary a reader is entitled to rely on, and a walkthrough naming
    # different components from the report beside it would make the claim
    # unreadable rather than merely untidy.
    boundary = (
        f"- Exercised vendor components: `{_evidence(fidelity_record.get('exercised_vendor_components', []))}`\n"
        f"- Simulated components: `{_evidence(fidelity_record.get('simulated_components', []))}`"
        # Appended rather than inserted, and omitted entirely when the record
        # predates the field: a lab generated before trigger_source existed
        # asserted nothing about its trigger, and a default would put a claim
        # in the documents that nothing in that lab ever made. The two bullets
        # above keep their wording and their order for every lab alike.
        + _TRIGGER_SOURCE_BULLET.get(fidelity_record.get("trigger_source"), "")
    )
    walkthrough = f"""# {cve} Walkthrough

## Scope

{source_note}

The lab is restricted to a disposable local environment and uses a non-destructive exploit canary.
The PoC has no arbitrary remote-target option. Automatic evidence is stored in
`report.json` and `artifacts/EVIDENCE.json`.

## Reproduction on Linux

```bash
cvelab run {cve}
```

For an inspectable, step-by-step reproduction that keeps the lab running, follow
`{LAB_POC_GUIDE_NAME}` and use `manual.sh`. Both reach this lab's own {'build' if vulnerable_only else 'two builds'}
and nothing else; `{LAB_POC_GUIDE_NAME}` says whether a single-instance script
exists for this lab, and if not, why not.

## Reproduction on Windows/WSL

```powershell
& \"$env:LOCALAPPDATA\\Programs\\Python\\Python313\\Scripts\\cvelab.exe\" run {cve}
```

For an inspectable, step-by-step reproduction that keeps the lab running, follow
`{LAB_POC_GUIDE_NAME}` and use `PoC.ps1`.

## Modeled attack path

{scenario_details}

## Preconditions

{prerequisites}

## Validation steps

{attack_path}

## Components

- `../docker-compose.yml`: isolated vulnerable{'' if vulnerable_only else ', patched'}, and validator services.
- `../validator/validator.py`: executable real-effect validator.
- `{poc_name}`: source-backed PoC executed against the vulnerable revision. With no argument it
  runs as validation ran it; given one `host:port` it runs against that instead.
- `manual.sh`: Linux runner with separate setup, exploit, verify, address, and cleanup actions.
- `{LAB_POC_GUIDE_NAME}`: inspectable manual reproduction instructions. `manual.sh` reaches this lab's own {'build' if vulnerable_only else 'two builds'} only, and the guide says what giving the PoC an address of your own does and does not prove.
- `EVIDENCE.json`: normalized evidence, proof checks, provenance, and fidelity metadata.
- `REPORT.md`: validation result and limitations.

## Revisions

- Repository: `{plan.get('repository', 'not applicable')}`
- Vulnerable: `{revisions.get('vulnerable', 'synthetic variant')}`
- Patched: `{discarded_revision or revisions.get('patched') or 'not tested; no public fixed revision identified'}`

## Success condition

{('The run succeeds only when the declared security effect is independently observed on `vulnerable`. No patched behavior or differential confirmation is claimed.' if vulnerable_only else 'The run succeeds only when the declared security effect is observed on `vulnerable`, blocked on `patched`, and `differential_confirmed` is `true`.')}

## Fidelity boundary

{fidelity}

{boundary}
"""
    write_text(artifacts / "WALKTHROUGH.md", walkthrough)

    descriptions = dossier.get("descriptions", [])
    description = descriptions[0] if descriptions else "No public description available."
    vulnerable_result = validation.get("vulnerable", {})
    patched_result = validation.get("patched", {})
    if result.get("ok") and vulnerable_only:
        status = "REAL_VULNERABLE_ONLY_POC_VALIDATED"
    elif result.get("ok") and plan["lab_type"] == "END_TO_END_REPRODUCTION":
        status = "REAL_END_TO_END_POC_VALIDATED"
    elif result.get("ok"):
        status = "REAL_SOURCE_POC_VALIDATED"
    else:
        status = "NOT_VALIDATED"
    # What the status means, and the fourth place a demoted lab used to assert
    # that no fix was found.
    if demoted:
        status_meaning = (
            "`REAL_VULNERABLE_ONLY_POC_VALIDATED` means the recorded vulnerable upstream "
            "revision executed the declared security-sensitive path inside the isolated lab. "
            f"No patched behavior is claimed. {discarded_fix}"
        )
    elif vulnerable_only:
        status_meaning = (
            "`REAL_VULNERABLE_ONLY_POC_VALIDATED` means the recorded vulnerable upstream "
            "revision executed the declared security-sensitive path inside the isolated lab. "
            "No public fix was identified and no patched behavior is claimed."
        )
    else:
        status_meaning = (
            "`REAL_POC_VALIDATED` means the recorded vulnerable upstream revision executed the "
            "declared security-sensitive path inside the isolated lab and the fixed revision "
            "blocked it."
        )
    if analysis:
        summary = analysis["executive_summary"]
        mechanism = analysis["mechanism"]
        impacts = _bullets(analysis["impact"])
        components = _bullets(analysis["affected_components"])
        interpretation = analysis["evidence_interpretation"]
        remediation = analysis["remediation_status"]
        limitations = _bullets(analysis["limitations"])
        confidence = analysis["confidence_statement"]
    else:
        summary = description
        mechanism = scenario_details
        impacts = "- Consult the public CVE description."
        components = "- Consult dossier.json."
        if vulnerable_only:
            interpretation = "The declared effect was observed on the recorded vulnerable source revision; no patched control was available."
            # The remedy differs as much as the fact does. Waiting for a fix
            # to become public is useless advice for a lab whose fix is
            # already public and was already read: what is needed is the
            # fixing reference resolved to the commit that carries the fix.
            remediation = (
                "Re-run differential validation once the fixing reference resolves to the "
                "commit that carries the fix; there is nothing to wait for. "
                f"{discarded_fix}"
                if demoted
                else "No public fixed revision was identified at generation time. Re-run "
                "differential validation when a fix becomes public."
            )
            limitations = "- Patched behavior and remediation effectiveness were not tested."
            confidence = "Confidence applies to the observed vulnerable revision only; there is no differential confirmation."
        else:
            interpretation = "The differential result applies only to the generated lab."
            remediation = "Not established by the generated lab."
            limitations = "- Vendor-product behavior was not exercised."
            confidence = "Confidence is limited to the observed local class model."
    markdown_report = f"""# {cve} Validation Report

## Result

- Status: **{status}**
- Fix status: `{plan.get('fix_status', 'PUBLIC_FIX_AVAILABLE')}`
- Patched tested: `{not vulnerable_only}`
- Differential confirmed: `{validation.get('differential_confirmed', False)}`
- Attack executed: `{validation.get('attack_executed', False)}`
- Proof quality: `{validation.get('proof_quality', 'not observed')}`
- Observable effect: `{_evidence(validation.get('observable_effect', 'none'))}`
- Lab type: `{plan['lab_type']}`
- Fidelity level: `{fidelity_record.get('execution_level', 'unknown')}`
- Vendor product started: `{fidelity_record.get('vendor_product_started', False)}`
- Product E2E verified: `{report.get('product_e2e_verified', False)}`
- Manual PoC verified: `{_manual_poc_verdict(report)}`
- Autonomous validation attempts: `{automation.get('validation_attempts', 1)}`
- Autonomous adapter repairs: `{automation.get('repair_calls', 0)}`
- CWE: `{plan.get('cwe', 'unknown')}`
- Scenario: `{scenario}`
- Validated at: `{report.get('validated_at', 'not completed')}`

## CVE summary

{summary}

## Vulnerability mechanism

{mechanism}

## Preconditions

{prerequisites}

## Affected components

{components}

## Potential impact

{impacts}

## Evidence

- Vulnerable confirmed: `{vulnerable_result.get('confirmed', False)}`
- Patched confirmed: `{patched_result.get('confirmed', False)}`

### Vulnerable raw evidence

```json
{json.dumps(_variant_evidence(vulnerable_result), indent=2, ensure_ascii=True)[:12000]}
```

### Patched raw evidence

```json
{json.dumps(_variant_evidence(patched_result), indent=2, ensure_ascii=True)[:12000]}
```

{interpretation}

## Fidelity

- Execution level: `{fidelity_record.get('execution_level', 'unknown')}`
- Vendor product started: `{fidelity_record.get('vendor_product_started', False)}`
{boundary}
- Boundary: {fidelity_record.get('rationale', 'Not recorded.')}

## Remediation status

{remediation}

## Provenance

- CVE source: `{dossier.get('source', 'unknown')}`
- Repository: `{plan.get('repository', 'not applicable')}`
- Vulnerable revision: `{revisions.get('vulnerable', 'synthetic variant')}`
- Patched revision: `{discarded_revision or revisions.get('patched') or 'not available / not tested'}`

## Safety and limitations

{source_note}

- Target scope: `{plan.get('safety', {}).get('target_scope', 'local only')}`
- Payload: `{plan.get('safety', {}).get('payload', 'non-destructive exploit canary')}`
- Limitation: {plan.get('safety', {}).get('limitations', 'See plan.json.')}

{limitations}

## Confidence

{confidence}

## Interpretation

{status_meaning}

This result does not authorize or establish exploitability of any remote deployment.
"""
    write_text(artifacts / "REPORT.md", markdown_report)
    write_text(artifacts / "report.json", json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    evidence_document = {
        "schema_version": 1,
        "cve": cve,
        "status": status,
        "lab_type": plan.get("lab_type"),
        "fidelity": fidelity_record,
        "validated_at": report.get("validated_at"),
        "validation": validation,
        "proof_contract": report.get("proof_contract", plan.get("exploit_contract", {})),
        "proof_checks": report.get("proof_checks", {}),
        "manual_poc_checks": report.get("manual_poc_checks", {}),
        # Beside the checks, because the dict alone cannot say which of two
        # things happened: an action that failed leaves its entry above, but a
        # run that never reached the actions leaves {} -- the same {} a
        # curated-runner lab has, which records no manual actions at all.
        # EVIDENCE.json is the copy sharing keeps: it is in upload.ALWAYS and
        # in REQUIRED_TO_SHARE and absent from upload.EXPLOIT, so --no-poc
        # does not strip it. Null is the third case, a report with no manual
        # record of its own.
        "manual_poc_status": report.get("manual_poc_status"),
        "automation": automation,
        "provenance": {
            "cve_source": dossier.get("source", "unknown"),
            "repository": plan.get("repository"),
            "vulnerable_revision": revisions.get("vulnerable"),
            "patched_revision": revisions.get("patched"),
            # Beside the null patched revision, because the two say different
            # things and the null alone reads as a CVE with no public fix.
            # This document is the only place the demotion survives being
            # shared: plan.json is in upload.EXPLOIT, so --no-poc strips it,
            # and upload.collect sends fixed_ref from revisions.patched,
            # which is correctly null here -- no fixed revision was built or
            # tested. EVIDENCE.json is in upload.ALWAYS and in
            # REQUIRED_TO_SHARE, so it goes either way.
            "discarded_fixed_revision": rejected_fixed,
            "demotion_reason": demotion.get("reason"),
        },
    }
    write_text(
        artifacts / "EVIDENCE.json",
        json.dumps(evidence_document, indent=2, ensure_ascii=True) + "\n",
    )

    result["deliverables"] = {
        "poc": str(poc_path),
        "walkthrough": str(artifacts / "WALKTHROUGH.md"),
        "report_markdown": str(artifacts / "REPORT.md"),
        "report_json": str(artifacts / "report.json"),
        "evidence": str(artifacts / "EVIDENCE.json"),
    }
    optional_deliverables = {
        "manual_poc": artifacts / "PoC.ps1",
        "manual_guide": artifacts / LAB_POC_GUIDE_NAME,
        "manual_runner": artifacts / "manual.sh",
        # Written by run_lab, and only when it showed the effect on the
        # vulnerable build and stayed silent on the fixed one, so its
        # presence is the claim. Most labs will not have one.
        "target_poc": artifacts / MANUAL_POC_NAME,
    }
    result["deliverables"].update({
        name: str(path) for name, path in optional_deliverables.items() if path.is_file()
    })
    if analysis:
        result["deliverables"]["analysis"] = str(artifacts / "analysis.json")
    if analysis_error:
        result["analysis_warning"] = analysis_error
    return result
