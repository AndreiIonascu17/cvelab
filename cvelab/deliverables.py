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
import textwrap
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
# be declared here. It is declared in field.py instead, in one block with
# every other name a lab's artifacts/ carries, because two of those names used
# to collide case-insensitively and declaring them in two modules is exactly
# how that happened. The comment on that block is the whole account.
from .field import (
    _SHELL_CEILING,
    LAB_POC_GUIDE_NAME,
    LEGACY_MANUAL_POC_NAMES,
    POC_NAME,
    POC_NO_RECORD,
    POC_NOT_PROVED,
    POC_NOT_REPRODUCED,
    POC_NOT_REQUESTED,
    POC_REFUSED,
    POC_SHIPPED,
    _executes,
    emit_poc,
    poc_record,
    poc_standing,
    prompt_standing,
    takes_lab_address,
)

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


#: What the lab document says about remote mode, for each of the states in
#: `field.POC_STANDINGS` a lab can be in.
#:
#: This is the half that matters more than the merge. A reader opens a file
#: called "Manual PoC", follows it, watches it work, and learns nothing about
#: whether any of it can be pointed at the client's server -- and for most
#: labs it cannot, because the single-instance script was refused. The refusal
#: reason is already written and is often the best sentence in the whole
#: record ("a stock application that calls the affected helper does not report
#: that state"), but it lived only in report.json, and nobody reads report.json
#: before a client meeting. So it goes in the document the reader actually
#: opens, and in the script's own header beside it. They are the same questions
#: as before, asked of one script's two modes rather than of whether a second
#: file is there -- with the two `field.poc_standing` learned to tell apart
#: from a refusal, which are below.
_SHIPPED_NOTE = f"""Yes. `{POC_NAME}` beside this document has two modes, and the argument
chooses: with none it is the lab program documented below, and given the
address of an instance you are permitted to test it is the single-instance
script CVELab proved before writing it here.

{{proof}}

That script's own header is the handover document -- what it sends, what it
leaves behind, what it needs from you, what each exit code means and what it
was proved against. Read it before you point it anywhere."""

#: How remote mode was proved, which differs with the lab. Said here because
#: "silent on the fixed one" is the whole strength of the claim, and a
#: vulnerable-only lab has no fixed build to have been silent on -- printing
#: that sentence for one would credit it with a differential it never had.
_SHIPPED_PROOF = {
    True: f"""CVELab ran that mode against this lab's one build and observed the
effect. There was no fixed revision to compare against, so it was never held to
a differential; the `{POC_NAME}` header says what stands in for one.""",
    False: """CVELab built both of this lab's revisions and ran that mode against each
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
    True: f"""The one Docker build in this lab directory. `manual.sh` takes a Compose
service name -- `vulnerable` -- not an address, so there is no host to supply and
no option that would accept one. `{POC_NAME}` beside it runs against that same
build when it is given no argument at all.""",
    False: f"""This lab directory's two Docker builds. `manual.sh` takes a Compose service
name -- `vulnerable` or `patched` -- not an address, so there is no host to
supply and no option that would accept one. `{POC_NAME}` beside it runs against
those same builds when it is given no argument at all.""",
}

#: Said under a rehearsal command that carries this lab's own values, because
#: the whole point of the inputs is that CVELab cannot know them: the route in
#: the command below is the one this lab's adapter serves, and copying it to a
#: client would test a path that does not exist there and report NOT_OBSERVED,
#: which reads as "not vulnerable".
_REMOTE_ARGUMENT_NOTE = """Those `--input` values are this lab's own -- the route its adapter serves, the
account its setup created -- and they are here so the command above runs
against the build `setup` has just started. Against anyone else's instance they
are theirs, not these.

"""

_NOT_REQUESTED_NOTE = """No, because one was never asked for. `cvelab run --manual-poc`, or
`cvelab manual` on a lab that has already validated, attempts one: it
drafts a single-instance spec, proves the script it emits against both of this
lab's builds, and keeps it only if the effect showed on one and not the other.
Until that is run, {address}"""

_NO_RECORD_NOTE = """This run kept no record of a single-instance script either way. Treat that as
"not available" rather than "refused": a lab driven by its own curated runner
never attempts one. {address}"""

#: Both notes that quote the record end on `{route}` rather than carrying the
#: route paragraph inside `{address}`, and that is the whole of why the slot
#: exists.
#:
#: `{address}` ends on a colon for these two standings, because the colon
#: introduces the quote. Where the lab publishes a port, the route paragraph
#: used to be appended to `{address}` -- and it begins with a single newline, so
#: it landed in the same paragraph as that colon. What the reader got was a
#: colon promising the drafter's reason and delivering nine lines about the
#: route, with the blockquote arriving after them. Measured: 7 archived labs,
#: all refused; none of the 11 whose script was drafted and not proved declares
#: a port yet, and a future one would.
#:
#: So the route goes last, after the sentence that frames the quote. It answers
#: a different question -- where this file's one address may point, and what a
#: negative verdict from it is worth -- and that question is owed its answer
#: after the one in the heading rather than wedged inside it.
#: `_ADDRESS_IS_REFUSED` needs no slot: nothing is appended there, so its colon
#: was always adjacent to its quote, and that adjacency is the shape being
#: restored rather than abandoned.
_REFUSED_NOTE = """{address}

{reason}

That sentence is the limit of what this lab can show, and it is the one to
repeat rather than implying the demonstration below would carry over.{route}"""

#: The note that used to be _REFUSED_NOTE's, for the labs where it was false.
#:
#: Measured across the 264 archived labs: 11 of them record a script of
#: CVELab's own that was written, emitted and run and did not hold up -- "the
#: script did not tell the two builds apart", "the script did not finish
#: against both builds" -- and all 11 ship a kit. Every one of them was handed
#: the note above, which calls that our own sentence "the limit of what this
#: lab can show" and "the one to repeat". It is not a statement about the
#: vulnerability at all: `field._spec_complaint` feeds the same reason back to
#: the next draft as OUR problem, with the script's output attached, precisely
#: because "did not tell the two builds apart" says nothing about the finding.
#:
#: So the reason is still quoted -- it is the only thing that says which part
#: of the attempt to look at -- and the paragraph under it says whose failure
#: it is, that the lab's differential proof is untouched, and nothing at all
#: about repeating it to anyone.
_NOT_PROVED_NOTE = """{address}

{reason}

That is CVELab's own script failing, and not a finding about the
vulnerability. A spec was drafted for this lab, emitted as a script and run
against both builds, and it could not be made to hold up against them; the
sentence above is quoted because it says which part of that attempt to look
at. The differential proof below is this lab's own, it is what established
the effect, and none of this weakens it. A drafted spec is sampled, so asking
again may well produce one that holds: `cvelab manual` on this lab with
`--redraft` asks for another, and `--spec` proves one of yours.{route}"""

#: A lab with nothing to hand over, because it had nothing. No document is
#: written for one of these -- `create_deliverables` refuses the whole kit on
#: `real_poc_verified`, and all 42 in the archive have empty artifacts -- but
#: the standing is read by both writers and this is the entry it needs, rather
#: than a KeyError on the first lab whose kit is ever rendered another way.
_NOT_REPRODUCED_NOTE = """No, and the question was never reached: this lab did not reproduce, so there
was no demonstrated effect for a single-instance script to carry. Nothing was
drafted and nothing was run against an instance. {address}"""

#: What the three notes above say the address argument does, which the lab's
#: own shape decides and not the address: `field.takes_lab_address` is the
#: predicate, read once and passed in, so the document and the artifact's own
#: header cannot give different answers.
#:
#: A lab that publishes no port has a validator that reads no argument, so the
#: address really is refused and the sentence that says so is the one that was
#: always here -- 247 of the 264 archived labs. A lab that publishes one hands
#: that address to the lab program instead, and what the document owes there is
#: not a warning about where it may point but the fact that the route is a
#: constant: a BLOCKED from a host that never served this lab's route is the
#: sentence an operator would otherwise write as "not affected".
_ADDRESS_IS_REFUSED = {
    POC_NOT_REQUESTED: f"""`{POC_NAME}` given an address refuses with exit 2, and nothing
here has been proved past this lab's own builds.""",
    POC_NO_RECORD: f"""`{POC_NAME}` given an address refuses with exit 2, and
everything in this document reaches this lab's own builds only.""",
    POC_REFUSED: f"""No. `{POC_NAME}` has a remote mode, and for this lab it refuses: given an
address it prints the reason below and exits 2 without sending anything. CVELab
drafted a single-instance script, proved it could not stand, and recorded why:""",
    POC_NOT_PROVED: f"""Not out of this lab. `{POC_NAME}` given an address refuses with exit 2 and
sends nothing. CVELab drafted a single-instance script for this finding,
emitted it, ran it against both of this lab's builds, and could not make it
hold up. What it recorded is about that script:""",
    POC_NOT_REPRODUCED: f"""`{POC_NAME}` given an address refuses with exit 2, and nothing
in this lab was proved against anything.""",
}

_ADDRESS_RUNS_THE_LAB_PROGRAM = {
    POC_NOT_REQUESTED: f"""nothing here has been proved past this lab's own builds --
and an address given to `{POC_NAME}` is not refused, because there is no remote
mode for it to be refused by. It runs the lab program instead, over this lab's
own route.""",
    POC_NO_RECORD: f"""An address given to `{POC_NAME}` is not refused, because
there is no remote mode for it to be refused by: it runs the lab program
instead, over this lab's own route.""",
    POC_REFUSED: """No. The one address this file takes does not reach a single-instance script,
because there is none, and it is not refused either -- it runs the lab program,
which the last paragraph here is about. CVELab drafted a single-instance script
for this lab, proved it could not stand, and recorded why:""",
    POC_NOT_PROVED: """Not out of this lab. The one address this file takes does not reach a
single-instance script, because there is none, and it is not refused either --
it runs the lab program, which the last paragraph here is about. CVELab drafted
a single-instance script for this finding, emitted it, ran it against both of
this lab's builds, and could not make it hold up. What it recorded is about
that script:""",
    POC_NOT_REPRODUCED: f"""An address given to `{POC_NAME}` is not refused, because
there is no remote mode for it to be refused by: it runs the lab program
instead, over this lab's own route -- a program whose own differential did not
reproduce here.""",
}

#: Said under either of the two above wherever the address does reach the lab
#: program. The route the lab program sends is a constant in it, so a negative
#: verdict from a foreign host is a fact about CVELab's adapter wearing the
#: shape of a fact about that host. The artifact says this in its own output,
#: next to the verdict; this is the same sentence where the reader met the
#: command.
_THE_ROUTE_IS_A_CONSTANT = f"""
That address is yours to choose and nothing checks it. What it cannot choose is
the route: the lab program sends the route this lab's own differential proved,
which is a constant in it, so against anything but this lab it asks for a route
that is most likely not there. `BLOCKED` or `NOT_OBSERVED` from such a host
says that route is not served there and says nothing about whether the host is
affected. `{POC_NAME}` says so itself whenever the address is not on loopback --
before the run, and again under the verdict, which is the line that gets pasted
into a report."""


#: The prompt, in the document that is read before anything is run.
#:
#: The gap this fills: the document never mentioned the prompt for any lab
#: shape, including the labs that have one. It named the two invocations an
#: address can be given and stopped, so an operator who did not open the
#: artifact's own header did not learn that a third one exists.
#:
#: `field.prompt_standing` decides, here as in that header, and the wording is
#: the artifact's own -- `field._lab_mode_note` writes the same paragraph into
#: the header and `field._POC_PROMPT` prints it again before the first line is
#: typed. Three surfaces, one answer; this was the surface giving none.
#:
#: Named as an invocation and never as a third mode. The prompt is the lab
#: program again, once per line -- `field._lab_mode_note`'s docstring is the
#: account -- so the sentences in this document that say the file holds two
#: modes stay true and stay as they are.
#:
#: The mode's own cost is named here for the same reason the session's four
#: are: a line the lab program reports as not run is followed by one more
#: delivery, a probe of the artifact's own, to whatever address the operator
#: gave -- the only request the mode sends that is not a line they typed. The
#: prompt prints it again before the first line, but by then --allow-prompt
#: has been given, and this document is what is read before that.
_PROMPT_IS_NOT_A_SESSION = f"""One command per line, and not a session. Every line you type is one more run
of the lab program's one-command form -- one address and one command, through
the weakness this lab's differential proved, its output printed -- so nothing
is held open between lines: no persistent environment, no interactive
programs, no job control and no signals, and `cd` is tracked by the prompt
rather than on the target. It asks for `--allow-prompt` because it runs
whatever you type for as long as you keep typing, which is more than any other
mode here asks; without the flag nothing is sent. One line costs more than one
request: a line the lab program reports as not run is followed by a probe of
`{POC_NAME}`'s own to that same address, which is how a route that never
answered is told from a line the target answered and its own shell refused.
That is the only request this mode sends that is not a line you typed, it is
sent only after a line that did not run, and it goes wherever the address
points -- this lab's build or not. `{POC_NAME}` says all of this again at the
prompt, before the first line, together with whose route answers the
commands."""

#: The session, said in the same document and gated the same way: whenever there
#: is a prompt there is a session, because `field.prompt_standing` decides both
#: and the session rides the prompt's own delivery. Still an invocation and not
#: a third mode -- the same lab program, held open -- so "one script, two modes"
#: stays true. The four costs the mode had to be built around are each named,
#: because a reader deciding whether to run it against a client's host decides on
#: those: it is a session and not a route; it writes two files and leaves a
#: process on the target until teardown; it is a poll and not a stream; and while
#: a line runs the product is held only for each short read, so a slow line does
#: not take the target down, but a line past the ceiling is reported unfinished.
_SHELL_IS_A_SESSION = f"""A session, and still not a route. The same delivery, run line after line into
a shell held open on the target, so an export or a `cd` on one line is still
there on the next -- real state, and on the target. It exists only because this
lab's weakness carries it, so it proves what the weakness proves and nothing
about reaching that host any other way. Holding it writes two files on the
target and leaves a detached process running until you leave, so leaving tears
that down -- the shell is killed and both files removed -- and the two paths are
named before the first line so you can audit them. The shell is detached and the
waiting is done at your end, so while a line runs the product is held only for
each short read and keeps answering -- a line that takes ten seconds does not
take the target down for ten seconds, which a single blocking request would --
but after about {_SHELL_CEILING} seconds a line is reported unfinished, though it
may still be running there. It asks for `--allow-shell` because holding a shell
open is more than any other mode here does; without the flag nothing is started.
`{POC_NAME}` says all of this again, with the two paths, before the first
line."""

#: Where the lines go, which the lab's own standing decides and not the
#: address: `field.takes_lab_address` is the predicate, the same one the
#: sections above are keyed on, so the document cannot describe one
#: destination in two ways.
#:
#: True is the shape where an address already reaches the lab program, so the
#: prompt adds no destination and the route paragraph the reader has just
#: passed covers every line. False is the shape where it reaches remote mode:
#: there the lab program is reachable at an address ONLY at this prompt, the
#: route paragraph is nowhere in the document, and the sentence that keeps an
#: operator from reading a silent line as "not affected" has to be here.
_PROMPT_REACHES = {
    True: """The address is the one the section above publishes, and a line typed at the
prompt reaches the same lab program that address already reaches -- so what
that section says about the route holds for every line you type.""",
    False: """An address on its own reaches remote mode in this file, which the section above
is about, and a line typed at this prompt does not: it reaches the lab program,
at the address you gave the prompt, over the route this lab's own differential
proved. That route is a constant in it, so a line that comes back with nothing
from a host that never served it says that about the route and not about the
host. The prompt tells its own child which of the two programs it means, in the
environment, where the lab program already takes its instructions from -- so
nothing new is reachable either way and there is no further flag.""",
}

#: Said where the lab declared command execution and `field.prompt_standing`
#: refused it the prompt anyway, which is a fact about the lab every time: 32
#: of the 264 archived labs, each one a real candidate turned down for
#: something about itself. The artifact prints this same sentence in its own
#: header; the reason is taken from the one function that gives it rather than
#: restated here, so the two cannot drift.
#:
#: `{reason}` is CVELab's own prose and not the drafter's, so it is body text
#: rather than a blockquote -- `_quoted` is for the recorded reason, which is a
#: model's. Measured: of the three reasons that function gives, the one that
#: interpolates anything a model wrote is the "declared something else"
#: reason, and that is exactly the lab this section is not written for, so
#: nothing a model wrote can reach the document this way. It is flowed at the
#: use site anyway, because the substitution lands mid-paragraph.
_NO_PROMPT_NOTE = (
    f"No. There is no prompt in `{POC_NAME}` -- no mode where line after line is "
    "run against this build -- because {reason}"
)

#: The last line of the document, which is the one a reader quotes. It names
#: what the file takes, so it is keyed on both answers that decide that: where
#: the address goes (`field.takes_lab_address`) and whether there is a prompt
#: to give one to (`field.prompt_standing`).
#:
#: It named the mode the address reaches, and for a lab whose address reaches
#: the lab program that was the wrong mode: "one address for remote mode" sent
#: the reader looking for a mode this file does not have, and read as a promise
#: that the argument had been proved against an instance when the section above
#: says the opposite. It then still named two invocations for the labs that
#: take three. Written out per shape rather than interpolated, like `_LAB_REACH`
#: above and for the same reason: a substitution lands mid-line and prints a
#: sentence wrapped nowhere near the rest of the file.
_CLOSING = {
    (False, False): f"""`{POC_NAME}` takes no argument for
lab mode and one address for remote mode, and where you point that is yours to
answer for -- only a host your engagement authorizes.""",
    (True, False): f"""`{POC_NAME}` takes no argument
for lab mode and one address, which runs that same lab program against a host
instead of the Compose network. Where you point it is yours to answer for --
only a host your engagement authorizes.""",
    (False, True): f"""`{POC_NAME}` takes no argument for
lab mode, one address for remote mode, and that address with `--prompt
--allow-prompt` for a prompt that runs the lab program once per line, or with
`--shell --allow-shell` for a session that holds it open. Where you point either
is yours to answer for -- only a host your engagement authorizes.""",
    (True, True): f"""`{POC_NAME}` takes no argument
for lab mode, one address, which runs that same lab program against a host
instead of the Compose network, and that address with `--prompt --allow-prompt`
for a prompt that runs it once per line, or `--shell --allow-shell` for a session
that holds it open. Where you point it is yours to answer
for -- only a host your engagement authorizes.""",
}


#: The column the emitted Markdown is hard-wrapped at, measured rather than
#: chosen: every other note shape renders at 79 or under, so that is the
#: document's own width and a line past it is a line the generator broke.
_NOTE_WIDTH = 79


def _flowed(paragraph: str) -> str:
    """One paragraph re-wrapped, for a paragraph assembled from two halves.

    Where a note splices a standing's own sentence into the middle of its
    prose, each half is hard-wrapped for the half it was written beside, and
    the join lands wherever the two happen to meet. The `not_reproduced` note
    was 107 columns wide at that seam without an address and 101 with one, in
    a document read next to a client, where an overrun reads as the generator
    having broken rather than as prose.

    Re-wrapped rather than hand-broken, because hand-breaking is correct only
    until the next edit to either half: a sentence added to the lead, or a
    word to the standing's entry, puts the overrun back with nothing to
    notice it. Flowing the joined text cannot overrun whatever either half
    becomes. `break_on_hyphens` is off so the `--` this prose uses as a dash
    is not split across lines, and `break_long_words` so a backticked
    `PoC.py` stays one token.
    """
    return textwrap.fill(
        " ".join(paragraph.split()), width=_NOTE_WIDTH,
        break_long_words=False, break_on_hyphens=False,
    )


def _quoted(reason: str) -> str:
    """A recorded reason as a Markdown blockquote, however it was written.

    Prefixed line by line. The reason is model prose from a refused draft and
    a blank line inside it would end the quote and leave the rest of the
    sentence rendering as body text, which reads as CVELab's own claim rather
    than as the drafter's reason for refusing.
    """
    return "\n".join(f"> {line}" if line.strip() else ">" for line in reason.splitlines())


def _single_instance_note(
    record: dict, vulnerable_only: bool, takes_address: bool = False
) -> str:
    """What the lab document says about the artifact's remote mode.

    `record` is what `field.poc_record` read: `report.manual_poc_field` for a
    run of this CVELab, falling back to the old `Manual-PoC.json` beside an
    archived lab. `field.poc_standing` decides which standing it is, and
    the same function decides what the script's own header says, so the
    document and the artifact cannot give different answers -- they were two
    files written by two modules, which is how a lab came to ship a document
    about a script that was never there.

    `takes_address` is `field.takes_lab_address`, and it decides one sentence
    in each of the notes that are not the shipped one: whether an address is
    refused, which is what a lab publishing no port does, or runs the lab
    program, which is what a lab publishing one does now that the flag that
    used to be required for it is gone. Defaulted, because a caller that does
    not know is a caller whose lab publishes nothing. On the two notes that
    quote the record it also decides where the route paragraph lands, which
    the comment on `_REFUSED_NOTE` is about.
    """
    standing = poc_standing(record)
    if standing == POC_SHIPPED:
        return _SHIPPED_NOTE.format(proof=_SHIPPED_PROOF[vulnerable_only])
    lead = (
        _ADDRESS_RUNS_THE_LAB_PROGRAM[standing] if takes_address
        else _ADDRESS_IS_REFUSED[standing]
    )
    # The two that quote the record, which are not the same answer: one is the
    # drafter's judgement about the finding and the other is a script of ours
    # that did not hold up, and the paragraph under the quote is the whole
    # difference between them.
    #
    # They are also the two whose lead ends on a colon, so the route paragraph
    # goes in `{route}` at the end instead of being appended here: appended, it
    # joined the colon's own paragraph and stood between the colon and the
    # quote it introduces. The leading newline is this template's, because
    # `_THE_ROUTE_IS_A_CONSTANT` opens with one of its own and a paragraph
    # break needs both.
    if standing in (POC_REFUSED, POC_NOT_PROVED):
        template = _REFUSED_NOTE if standing == POC_REFUSED else _NOT_PROVED_NOTE
        return template.format(
            address=lead,
            reason=_quoted(str(record.get("reason") or "")),
            route=("\n" + _THE_ROUTE_IS_A_CONSTANT) if takes_address else "",
        )
    # The rest splice the standing's own sentence into their own prose and end
    # there, so the route paragraph is appended here -- and as its own
    # paragraph, which is the break the two above just got. Appended to the
    # lead it joined the spliced sentence's paragraph, and nine lines about
    # the route ran on from a sentence about something else.
    route = ("\n" + _THE_ROUTE_IS_A_CONSTANT) if takes_address else ""
    if standing == POC_NOT_REPRODUCED:
        # Flowed, because this is the note whose seam overran: 107 columns
        # without an address and 101 with one. The other two splice a short
        # enough entry to stay inside the width today, and they are left as
        # written rather than reflowed -- reflowing them would rewrite the
        # document for the 135 archived labs that have no record at all, for
        # a line that is already 71 columns. `_flowed` says why the fix is a
        # re-wrap and not a hand-break; the width test is what holds the two
        # that were not reflowed.
        return _flowed(_NOT_REPRODUCED_NOTE.format(address=lead)) + route
    # The one reason core.py writes itself, rather than taking from the
    # drafter: the step was never asked for, so there is nothing to quote and
    # quoting it would read as a refusal the model made.
    if standing == POC_NOT_REQUESTED:
        return _NOT_REQUESTED_NOTE.format(address=lead) + route
    return _NO_RECORD_NOTE.format(address=lead) + route


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
# still publishes nothing and its own network is still internal, which is why
# that file also brings a network of CVELab's for the publication to land on:
# a service whose networks are all internal publishes nothing, and Docker
# drops the mapping silently rather than refusing it, which is what used to
# print ":0" here as an address. That network carries no NAT, so this build is
# reachable from this machine while its own outbound connections still go
# nowhere an ordinary route can answer, and `cleanup` removes it with the
# project. Without the file the product is reachable only from inside the
# lab's network, which is where the steps below reach it either way; this is
# what gives PoC.py an address on this machine. A lab generated before this
# existed ships no such file, takes neither branch, and runs exactly as it did.
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
    # The one address, and what it is good for, printed where the operator is
    # already looking. The steps below reach the product by service name
    # inside the lab's network and need none of this; remote mode run by hand
    # on this machine needs exactly this line, and the host port is assigned
    # at `up` so there is nowhere else it could have been written down.
    # `address` reprints it. The second line is per lab, because for most labs
    # remote mode refuses: a printed command that exits 2 reads as the kit
    # being broken rather than as the drafter having refused the proof.
    if POC_AT="$(address "$variant")"; then
      echo "This build is reachable on $POC_AT"
__POC_HINT__
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


def _remote_arguments(record: dict) -> str:
    """The `--input` flags remote mode needs, with this lab's own values.

    Remote mode refuses to start without every input its spec declares, so a
    command line printed without them cannot run -- and a library's own route
    is declared as an input on 19 of the 29 archived specs that shipped. The
    values are the lab's: the route its adapter serves, the account its setup
    created. They are what makes the printed command work against the build
    `manual.sh` has just started, they are already in plan.json's exploit
    contract and in report.json, and the sentence beside them says a client's
    are theirs. A name the lab recorded no value for is printed as a
    placeholder, which is the honest form of "only you have this".
    """
    spec = record.get("spec") if isinstance(record.get("spec"), dict) else {}
    values = record.get("lab_values")
    values = values if isinstance(values, dict) else {}
    return "".join(
        f" --input {name}={values.get(name, '...')}"
        for name in spec.get("inputs") or ()
    )


def _write_generic_manual_assets(
    cve: str,
    lab_dir: Path,
    artifacts: Path,
    vulnerable_only: bool,
    seeds: bool = False,
    port: int | None = None,
    record: dict | None = None,
    prompt: tuple[bool, str] | None = None,
    declares_a_command: bool = False,
) -> None:
    """Write the kit the lab is handed over with: runner, wrapper and guide.

    `record` is what `field.poc_record` read -- `report.manual_poc_field`, or
    the old file beside an archived lab -- and the whole report is no longer
    passed, because that one key was the only thing read from it.

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

    The record decides what the kit says about the address: whether remote
    mode is there to be pointed at it, and with which arguments.

    `prompt` is `field.prompt_standing`'s whole answer -- whether this lab has
    the prompt, and the reason where it has none -- and it decides two things
    that are one fact. The first is the other command printed beside the
    address: the lab program's one-command form, which runs against this
    lab's own published build and prints what one command on it returns. That
    is the form an owner demonstrates impact with, so it is printed where they
    are already looking. It is one address and no flag, like everything else
    this artifact takes -- which of the file's two programs that address
    reaches is `field.takes_lab_address`, computed here from the same port and
    the same record the artifact's own dispatch was built from. The second is
    the prompt, which is that same form run once per line: the standing grants
    it exactly where the form is there to be run, so one bit answers both and
    the document cannot offer a command it has no prompt for.

    It is what the artifact IMPLEMENTS and not what the plan declares, and
    the difference is the correction here. This was `_executes(plan)`, the
    declared evidence shape, while the artifact offers the form on
    `prompt_standing` -- a declared port AND a validator that reads the
    command. Measured across 262 archived labs: 34 declare command
    execution, 2 implement it, and all 32 of the rest declare no service
    port at all -- so the kit printed a flag for a file that does not have
    one. The comment under the offers below already said what
    that costs: a printed command that fails reads as the kit being broken
    rather than as the drafter having refused the proof. One predicate for
    one question, asked of the thing that answers it.

    `declares_a_command` is `field._executes(plan)`, what the contract
    DECLARES, and it decides only what is EXPLAINED: whether this lab was ever
    a candidate for the prompt, and so whether the document owes a reason for
    not having one. The artifact's header is gated on the same two arguments
    in the same way -- `field._poc_header` passes both to
    `field._lab_mode_note` -- so the two answer together or not at all.
    """
    record = record if isinstance(record, dict) else {}
    proved = poc_standing(record) == POC_SHIPPED
    # One bit from `prompt`, under the name the sentences below need it by: the
    # form the lab program takes after an address. The prompt is that form once
    # per line, so reading the same bit twice under two names is how the kit
    # and the document would come to disagree about one file.
    takes_a_command = bool(prompt and prompt[0])
    # Whether this lab's one address argument reaches the lab program, which
    # is what decides that the commands printed below are real: on a lab with
    # a proved remote mode the same address goes there instead, and a printed
    # command that lands in the wrong program reads as the kit being broken.
    lab_at_an_address = takes_lab_address(port, record)
    targets = ("vulnerable",) if vulnerable_only else ("vulnerable", "patched")
    patched_note = (
        "No patched target is available for this CVE."
        if vulnerable_only
        else "Repeat the same steps with `patched`; successful verification prints `BLOCKED`."
    )
    # One echo line per thing that can actually be pointed at this address,
    # and a line saying so when there is neither: a printed command that
    # exits 2 reads as the kit being broken rather than as the drafter having
    # refused the proof.
    #
    # `lab_at_an_address` is one of those things, and it is the one the flag's
    # removal added: the lab program now takes the address, so for a lab that
    # publishes a port and has no proved remote mode there IS something to
    # point at it -- measured, 12 archived labs of that shape, where the
    # command after the address is not offered because the validator reads
    # none. Printing the fallback for them said "nothing here may be pointed
    # at that address" in the runner while the document written by this same
    # call printed the command that does, which is the disagreement between
    # the kit and the file this predicate exists to make impossible.
    # `takes_a_command` implies it and `proved` excludes it, so the three
    # branches stay one line each.
    poc = f'python3 \\"$LAB_ROOT/artifacts/{POC_NAME}\\"'
    offers = []
    if lab_at_an_address:
        offers.append(
            f'      echo "  {poc} $POC_AT{" id" if takes_a_command else ""}"'
        )
    if proved:
        offers.append(
            f'      echo "  {poc} $POC_AT{_remote_arguments(record)}"'
        )
    hint = "\n".join(offers) or (
        f'      echo "  nothing here may be pointed at that address; see '
        f'{LAB_POC_GUIDE_NAME}"'
    )
    manual_runner = (
        _MANUAL_RUNNER
        .replace("__SETUP_FILE__", SHIPPED_SETUP_FILE)
        .replace("__SETUP_SERVICE__", policy.SETUP_SERVICE)
        .replace("__PORTS_FILE__", SHIPPED_MANUAL_PORTS_FILE)
        .replace("__SERVICE_PORT__", "" if port is None else str(port))
        .replace("__POC_HINT__", hint)
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
    # The section the whole merge exists for: one address, and what may be
    # pointed at it. `PoC.py` was `validator.py` with a six-line docstring on
    # top -- byte-identical otherwise in all 89 archived labs -- so this
    # document told the reader to read it and then run `manual.sh`, which
    # starts the same code inside the Compose network. Nothing published a
    # host port and nothing read an argument, so there was no third thing to
    # do with the script. Both halves are here now: the override `manual.sh`
    # appends, and the mode the argument chooses.
    #
    # It says "rehearse" rather than "run it yourself", because that is what
    # it is for. Remote mode is for an instance the operator is permitted to
    # test, and this lab's own published build is the one such instance that
    # costs nobody anything -- so the sentence that used to describe a second
    # thing to do with the lab script now describes seeing the handover run
    # end to end before it touches a client.
    #
    # Absent for a lab whose plan declares no port, which is every lab
    # generated before the contract asked for one.
    # The command an owner demonstrates impact with, and the one thing on
    # this page that is neither the lab's differential nor a client's server:
    # the lab program, against the build `setup` has just published. The
    # command after the address is shown only where the lab's declared
    # evidence is command execution, because that is the only shape where the
    # program takes one -- but the address itself is shown wherever the lab
    # program is what an address reaches, which is every lab here that has no
    # proved remote mode. Printing the address only for the command form left
    # the reader of every other one to find out from the script that its one
    # argument is no longer refused.
    # Written out per form rather than interpolated, like `_LAB_REACH` above
    # and for the same reason: a substitution lands mid-line and prints a
    # paragraph wrapped nowhere near the rest of the file.
    runs = """That runs the lab program against this lab's own published build and prints
what one command on it returns, which is how the impact of a reproduction is
shown to someone watching. That build is the one target whose result means what
it looks like it means.""" if takes_a_command else """That runs the lab program against this lab's own published build, which is the
one target whose result means what it looks like it means."""
    impact = f'''```bash
bash manual.sh setup vulnerable
python3 {POC_NAME} "$(bash manual.sh address vulnerable)"{' id' if takes_a_command else ''}
```

{runs}
{_THE_ROUTE_IS_A_CONSTANT.lstrip()}

''' if lab_at_an_address else ""
    rehearsal = impact + f'''```bash
bash manual.sh setup vulnerable
python3 {POC_NAME} "$(bash manual.sh address vulnerable)"{_remote_arguments(record)}
```

{_REMOTE_ARGUMENT_NOTE if _remote_arguments(record) else ""}Remote mode holds one session for the whole run and performs whatever setup
its own spec declares; CVELab establishes the lab's state for `exploit`, and a
person running the script by hand has none of it.

Where you point it is yours to answer for. It sends live requests to whatever
address you give it, so give it only a host your engagement covers, and keep
that authorization in writing.
''' if proved else impact + '''Remote mode -- a script CVELab drafts and proves against one instance of
yours -- was refused for this lab, and no argument reaches one: the address
above goes to the lab program. The section above carries the recorded reason.
Lab mode with no argument, which is what `exploit` runs inside the lab, is
unaffected.
'''
    direct_section = f'''## The address this lab publishes

`setup` publishes this build's container port {port} on loopback and prints the
address the kernel assigned it. The host side is assigned at `setup`, so it is
different every run and there is no constant to write down -- `address` reprints
the current one.

That publication is the one loosening in this lab, and it lives in
`{SHIPPED_MANUAL_PORTS_FILE}` beside this file rather than in
`docker-compose.yml`: a Compose file `manual.sh` merges and CVELab's own run
never does. Docker will not publish a port for a service whose networks are all
internal, so that file also attaches this build to a second network that is not
internal -- carrying no NAT, so the build is reachable from this machine while
its own outbound connections still go nowhere an ordinary route answers. It is
reachable without credentials for as long as the lab is up, by anything running
on this machine. `cleanup` removes the network with the project; run it when you
are done rather than leaving the lab up.

{rehearsal}
''' if port is not None else '''## The address this lab publishes

It does not. This lab was generated before the contract asked for the port the
product listens on, so `manual.sh` publishes nothing and there is no address on
this machine to point anything at. Drive it with `exploit` and `verify`, which
reach the product inside the lab's own network. Regenerating the lab produces a
kit that publishes the port.

'''
    # The title and the first two sections say the reach before anything
    # else, because this document is read standing up. The two documents this
    # one replaced opened with the identical line `# {{cve}} Manual PoC`, so
    # the reader could not tell from the heading, the filename or the first
    # paragraph which of the two reached a live server.
    single_instance = _single_instance_note(
        record, vulnerable_only, lab_at_an_address
    )
    # The one thing on this page that can be aimed outside this lab, named as
    # what it is for this lab. It used to say "remote mode" for every lab,
    # which is right for a lab that publishes no port -- there an address
    # reaches remote mode or its refusal and nothing else. For a lab that
    # publishes one and has no proved remote mode, the same argument reaches
    # the lab program, and saying "remote mode" would have the reader looking
    # for a mode this file does not have while the thing it warns about sat
    # one section above.
    #
    # The middle shape is the prompt's: a lab whose address reaches remote
    # mode and which also has a prompt has two things that take an address,
    # and "the one thing" counted one of them. Where the address already
    # reaches the lab program the first sentence covers the prompt too -- the
    # lines it sends are that same program over that same route.
    outside = (
        f"""is the address you can give `{POC_NAME}`, which on this lab runs the lab
program over this lab's own route -- so a negative result from anywhere else is
a fact about that route, and only where you are authorized to send it at all."""
        if lab_at_an_address else
        f"""is `{POC_NAME}` given an address -- its remote mode, or the prompt below,
which runs the lab program once per line -- and only where you are authorized
to test it."""
        if takes_a_command else
        f"""is `{POC_NAME}`'s remote mode, and only where you are authorized to
test it."""
    )
    # The prompt, where this lab has one, and the reason where it was a
    # candidate and was refused. The same split the artifact's own header
    # makes, from the same two answers: `prompt` is what `prompt_standing` said
    # and `declares_a_command` is what the contract declared. A lab that
    # declared some other evidence hears nothing, because a section about a
    # prompt it was never a candidate for is noise in a document read standing
    # up -- 229 of the 264 archived labs.
    #
    # Its own section rather than a paragraph in the one above it: the reason
    # is owed on the declaration, and all 32 of the archived labs that hear it
    # publish no port at all, so the section about the address they publish is
    # the section saying they publish none.
    prompt_section = ""
    if prompt is not None and declares_a_command:
        offered, reason = prompt
        if offered:
            prompt_section = f'''## Is there a prompt?

Yes.

```bash
bash manual.sh setup vulnerable
python3 {POC_NAME} "$(bash manual.sh address vulnerable)" --prompt --allow-prompt
```

{_PROMPT_IS_NOT_A_SESSION}

{_PROMPT_REACHES[lab_at_an_address]}

## And a session?

Yes -- the same lab program again, held open instead of run once per line.

```bash
python3 {POC_NAME} "$(bash manual.sh address vulnerable)" --shell --allow-shell
```

{_SHELL_IS_A_SESSION}

'''
        elif reason:
            prompt_section = f'''## Is there a prompt?

{_flowed(_NO_PROMPT_NOTE.format(reason=reason))}

'''
    # The last line of the document, which is the one a reader quotes. Same
    # predicates as the sections above, read once each, so the summary and the
    # sections cannot answer differently; `_CLOSING` is the account of what it
    # got wrong twice.
    closing = _CLOSING[(lab_at_an_address, takes_a_command)]
    manual_guide = f'''# {cve} Lab PoC

## What this runs against

{_LAB_REACH[vulnerable_only]} The one thing here that can
be pointed at a client's server, a staging instance, or anything else outside
this lab {outside}

## Can this be pointed at a live instance?

{single_instance}

## How the steps work

The manual runner uses the same isolated images and exact request as automatic validation,
but leaves setup, exploitation, evidence verification, and cleanup as separate inspectable steps.

Everything below needs Docker and this lab directory. Nothing else: not CVELab,
and not a network route back to the machine that generated it. The one step that
wants Python on the host is running `{POC_NAME}` yourself, and it imports only
the standard library.

## Kali/Linux

Run these from the lab's `artifacts/` directory, the one this file is in:

```bash
sed -n '1,120p' {POC_NAME}
bash manual.sh setup vulnerable
bash manual.sh exploit vulnerable
bash manual.sh verify vulnerable
bash manual.sh cleanup
```

The first line is the artifact's own header, which says what each of its two
modes is worth. `manual.sh` finds the lab from its own path, so it runs from any
directory; the block above is written for `artifacts/` because that is where
`{POC_NAME}` is.

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

{patched_section}{seeded_section}{direct_section}{prompt_section}## What each step does

- `setup` builds the selected source revision, starts only that target, and waits
  for it to report healthy before going on{' -- then establishes the state the attack needs' if seeds else ''}.
- `exploit` sends the exact local attack and prints the raw observation without deciding the result.
- `verify` repeats the controls and evaluates the declared security effect.
- `address` reprints the host address this build was published on.
- `cleanup` removes this Compose project's containers, networks, and volumes.

{_EXIT_STATUS[vulnerable_only]}

`manual.sh` takes Docker service names only. {closing}
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
    # CVELab's own verdict, and nothing the validator wrote about itself. Two
    # clauses are gone from this gate. The first required
    # validation["proof_quality"] to equal one of two literals -- free text
    # the model's own validator prints about its run -- while core.py had
    # already removed exactly that string equality from the proof gate it
    # decides with, and left the field in the report as the claim it is, with
    # a non-decisive agreement note beside it; see `effect_observed`. So this
    # file went on enforcing the check the other half of the project had
    # abandoned, against the field that half had demoted, and the early
    # return below writes nothing whatever: no PoC, no manual kit, no
    # report, no walkthrough, no evidence. Measured over one benchmark tree:
    # 40 labs whose automation.json says VALIDATED hold no artifacts/PoC.py,
    # against 89 that do, splitting by batch date rather than by lab. Three
    # read by hand had reproduced differentially and labelled themselves
    # "wrapper_observed", "state_observation", and a sentence of behavioural
    # prose about an adapter.
    #
    # The second clause asked `attack_executed` a second time. `ok` is
    # all(proof_checks.values()) in both of core's validation paths, and
    # attack_executed and security_effect_observed -- the computed answer
    # that replaced the literal -- are two of those checks, so `ok` carries
    # both already. Reading security_effect_observed back out of
    # report["proof_checks"] here would be truthful but would add a third
    # key whose absence drops the whole kit in silence, which is the defect
    # and not the fix; the implication `ok` rests on is pinned in core's
    # source by test_deliverables instead.
    real_poc_verified = (
        result.get("ok") is True
        and plan.get("lab_type") in _SOURCE_BACKED
        and report.get("real_poc_verified") is True
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

    # The one artifact, written here as well as by field.write_manual_poc,
    # from the same validator and the same record, so the two agree byte for
    # byte. This pass is the one that runs for every validated lab -- a lab
    # built with no model configured never reaches the other -- and it is also
    # what re-renders an archived lab, which is why the record is read back
    # rather than taken from this run's report alone.
    validator = (lab_dir / "validator" / "validator.py").read_text(encoding="utf-8")
    record = poc_record(lab_dir, report)
    poc_path = artifacts / POC_NAME
    write_text(poc_path, emit_poc(cve, plan, validator, record))
    poc_name = POC_NAME
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
    # The record goes in so the document can say whether remote mode was
    # proved for this lab and, where it was refused, quote the drafter's own
    # reason -- the same record the artifact's own header was built from, so
    # the two cannot disagree. The declared port is read from the contract in
    # plan.json and not inferred; a lab that declares none is an archived one,
    # and gets the kit it always had.
    # `prompt_standing` and not `_executes`: the question the kit is asking
    # is whether the artifact beside it offers the command form, and only
    # the validator can answer that. Reading the declaration instead printed
    # the command for 32 of the 34 labs that declare command execution,
    # every one of which declares no port and so reaches none of this. Same
    # predicate the artifact's own prompt is gated on, read once here and not
    # re-derived, so the kit and the file cannot disagree -- including the
    # record, which that predicate now reads too: a lab with a proved remote
    # mode spends its one address argument there, so the lab program's
    # command form is not reachable and is not printed.
    #
    # The whole answer now and not its first element: the reason is the other
    # half, and the document owes it to a lab that declared the form and was
    # refused it. `_executes(plan)` beside it is the declaration, which is
    # what decides whether this lab was a candidate at all -- the two
    # arguments `field._poc_header` hands the same question, so the document
    # and the header cannot answer it differently.
    _write_generic_manual_assets(
        cve, lab_dir, artifacts, vulnerable_only, seeds, service_port(plan), record,
        prompt_standing(plan, validator, record), _executes(plan),
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
    rewrite = False
    # Only where the manual PoC was claimed at all. "failed" and "not_run"
    # are verdicts on the actions, which this knows nothing about, and the
    # third shape is a report with no manual record of its own.
    if claimed in {"verified", SEEDING_NOT_SHIPPED}:
        settled = SEEDING_NOT_SHIPPED if shipping_gap else "verified"
        if (claimed, report.get("manual_poc_shipping_gap")) != (settled, shipping_gap or None):
            report["manual_poc_status"] = settled
            report["manual_poc_shipping_gap"] = shipping_gap or None
            rewrite = True
    # The record, moved to the home it has now. An archived lab keeps its
    # proved spec in the file beside it, which this pass has just read and is
    # about to remove: without writing it here, the next re-render of that
    # lab would find no spec anywhere and turn a proved remote mode into a
    # refusal.
    if record and report.get("manual_poc_field") != record:
        report["manual_poc_field"] = record
        rewrite = True
    if rewrite:
        write_text(
            lab_dir / "report.json",
            json.dumps(report, indent=2, ensure_ascii=True) + "\n",
        )
    # The three files the merged artifact absorbed, where an older CVELab
    # left them. A stale `Manual-PoC.py` claiming to be the handover, beside
    # a `PoC.py` that now is one, is the pair this merge replaced -- and the
    # record above is why it is safe to take the third away.
    for name in LEGACY_MANUAL_POC_NAMES:
        (artifacts / name).unlink(missing_ok=True)
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
Everything automatic happens inside it: `cvelab run` gives `{poc_name}` no
argument, which is the mode bound to this lab's Docker service names.
`{poc_name}` also has a remote mode, for one address the operator supplies;
`{LAB_POC_GUIDE_NAME}` says whether it was proved for this lab, and where it
was not, that mode refuses with the recorded reason. Automatic evidence is
stored in `report.json` and `artifacts/EVIDENCE.json`.

## Reproduction on Linux

```bash
cvelab run {cve}
```

For an inspectable, step-by-step reproduction that keeps the lab running, follow
`{LAB_POC_GUIDE_NAME}` and use `manual.sh`. Both reach this lab's own {'build' if vulnerable_only else 'two builds'}
and nothing else; `{LAB_POC_GUIDE_NAME}` says whether `{poc_name}` may also be
pointed at an instance of your own, and if not, why not.

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
- `{poc_name}`: the one PoC, in two modes. With no argument it is this lab's own
  differential, as validation ran it; given one address it is the single-instance
  script, which is proved per CVE and refuses where it was not. Its own header
  says which of the two this lab has.
- `manual.sh`: Linux runner with separate setup, exploit, verify, address, and cleanup actions.
- `{LAB_POC_GUIDE_NAME}`: inspectable manual reproduction instructions. `manual.sh` reaches this lab's own {'build' if vulnerable_only else 'two builds'} only, and the guide says what `{poc_name}` given an address of your own does and does not prove.
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
    }
    # There is no separate single-instance script to list any more, so the
    # claim is a key rather than a file: remote mode is inside `poc` above,
    # and whether it was proved for this lab is one of `field.POC_STANDINGS`.
    result["remote_mode"] = poc_standing(record)
    result["deliverables"].update({
        name: str(path) for name, path in optional_deliverables.items() if path.is_file()
    })
    if analysis:
        result["deliverables"]["analysis"] = str(artifacts / "analysis.json")
    if analysis_error:
        result["analysis_warning"] = analysis_error
    return result
