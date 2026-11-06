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

"""Checking the revision pair before a lab is built from it.

Measured over 40 attempts, `proof_not_verified` was the largest failure
class at 20%, and a share of it was never the model's fault: the pair the
run was given could not show the fix, so every repair chased an effect the
inputs forbid. The pair itself was never checked, in three ways.

The vulnerable side was always a guess. With no explicit --vulnerable-ref
the generator used `fixed^` -- the first parent, unconditionally, with
nothing asking whether the fixing reference was a merge at all. A merge has
one before-state per parent, and only one of them has the fix between it
and the merge; the other is whichever line the merge brought in, whose diff
to the merge is that line's divergence and not the fix.

The advisory's own affected versions were never consulted once a commit had
resolved. `releases.pair_from_advisory` and `releases.tag_pair` both exist
and work, but they ran only when nothing had resolved a commit and
discovery had run, so a commit that resolved badly was never checked
against the versions the advisory itself says were affected and patched.

And `plan.json` recorded `source_provenance` as a constant string rather
than which resolver had decided, so after a bad pair the artifacts could
not say how it had been chosen. README states under Limitations that a
guessed repository or commit is not accepted as provenance; until this
module that was asserted and not recorded.

Nothing here is fatal and nothing here is a second disposition. A verdict
this module cannot reach means "unknown", never "unverifiable": an
unreachable advisory, a tag listing that times out, a parent whose diff
cannot be read all leave the pair exactly as it arrived. Only a local,
deterministic check that says positively that the two revisions are not a
before and an after of one history produces a reason, and that reason
travels back into the demotion the generator already has rather than a
path of its own.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import releases, research

#: Which resolver decided the reference, for `plan.json.source_provenance`.
#: The caller names the branch it took; the two it cannot tell apart on its
#: own -- a commit URL in the CVE record, and OSV -- are told apart here by
#: looking for the revision among the record's own references.
EXPLICIT = "explicit operator override"
DISCOVERY = "AI web search discovery"
TAG_PAIR = "advisory release tag pair"
CVE_REFERENCE = "commit reference in the CVE record"
OSV = "OSV affected range"

#: How the vulnerable side was decided. The distinction that matters is
#: between a parent that was assumed and a parent that was chosen: both can
#: be parent 1, and only one of them is evidence.
VULNERABLE_EXPLICIT = "explicit"
FIRST_PARENT = "first parent of a non-merge fixing revision"
CHOSEN_PARENT = "chosen parent of a merge"
RELEASE_TAG = "advisory release tag"

#: What an unanswered question looks like in the verdict. Separate from any
#: negative answer on purpose: an advisory that could not be read and an
#: advisory that contradicts the pair are different facts, and collapsing
#: them would let a timeout read as evidence against a good pair.
UNKNOWN = "unknown"

#: One `git ls-remote --tags` per repository per run. releases.repo_tags has
#: a 60s timeout and lists every tag a project ever published, which on a
#: monorepo is seconds rather than free, and generation plus three repairs
#: would otherwise ask for the same list four times. Keyed by repository and
#: CVE because the advisory half of the answer is per CVE.
_PAIRS: dict[tuple[str, str], dict | None] = {}


@dataclass(frozen=True)
class Verdict:
    """The pair to build from, and how much of it was checked rather than assumed.

    `demotion` is a reason in the same shape `_unusable_pair` returns, so the
    caller can hand either to the one demotion it already has.
    """

    vulnerable: str
    fixed: str | None
    verified: bool
    demotion: str | None = None
    provenance: dict = field(default_factory=dict)


def clear_cache() -> None:
    """Forget the resolved release pairs. For tests; a run is one process."""
    _PAIRS.clear()


def _git(repository: Path, arguments: list[str]) -> str | None:
    """One git command's output, or None when it did not succeed.

    Through sourcegen._run_git for its convention: one place that finds git,
    and --end-of-options on every call that is handed a revision from
    outside. Imported inside the function because sourcegen imports this
    module -- a module-level import would be a cycle, and nothing here is
    worth making generate_source_lab unimportable for.

    _run_git raises on any non-zero exit, which conflates "no" with "I could
    not tell": `merge-base --is-ancestor` answers no with exit 1 and a
    missing object with 128. The one caller that needs them apart checks
    that both objects exist first.
    """
    from .sourcegen import _run_git

    try:
        return _run_git(arguments, cwd=repository)
    except (RuntimeError, OSError):
        return None


def _exists(repository: Path, revision: str) -> bool:
    """Whether the repository has this revision as a commit."""
    return (
        _git(repository, ["rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"])
        is not None
    )


def is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool | None:
    """Whether `ancestor` is reachable from `descendant`; None when either is missing.

    A tag the clone never fetched, or a commit on a branch that has since
    been deleted, is not an answer of no -- it is no answer, and the caller
    must not read it as evidence against the pair.
    """
    if not _exists(repository, ancestor) or not _exists(repository, descendant):
        return None
    return (
        _git(repository, ["merge-base", "--is-ancestor", "--end-of-options", ancestor, descendant])
        is not None
    )


def parents(repository: Path, revision: str) -> list[str]:
    """The revision's parents, in git's own order. Empty when they cannot be read."""
    line = _git(repository, ["rev-list", "--parents", "-n", "1", "--end-of-options", revision])
    # `rev-list --parents` prints the commit first and then its parents.
    return (line or "").split()[1:]


def _scored_parents(
    repository: Path, fixed: str, listed: list[str], described: set[str]
) -> list[dict]:
    """Each parent of a merge, what it changes against the merge, and its match.

    `--name-only` and not the patch text: a merge on a large project can
    bring in thousands of files, and the question here only needs the change
    set, which is what the brief for this work asked for and what keeps the
    cost of a merge the same as the cost of an ordinary pair.
    """
    from .sourcegen import _unusable_pair

    scored = []
    for position, parent in enumerate(listed, start=1):
        names = _git(repository, ["diff", "--name-only", "--end-of-options", parent, fixed])
        files = (names or "").splitlines()
        scored.append({
            "parent": parent,
            "position": position,
            "changed_files": len(files),
            # research._match_score against the paths alone, with no changed
            # lines: the same scorer that orders a fix for the prompt, so a
            # path the advisory names counts here exactly as much as it does
            # there.
            "match": sum(
                research._match_score(described, research.words(path), set()) for path in files
            ),
            "unusable": (
                _unusable_pair(files) if names is not None else "the diff could not be read"
            ),
        })
    return scored


def _best_parent(scored: list[dict]) -> dict | None:
    """The parent to treat as the before-state, or None when none can be.

    The rule, in order:

    1. A parent whose change set cannot show a fix is out. `_unusable_pair`
       decides that, so an empty or prose-only change set is rejected here
       for the same reason and with the same words it would be rejected for
       downstream -- and a merge of two identical trees drops both parents
       and leaves the guess alone to be demoted as it always was.
    2. Then the best match to what the advisory names. A merge's two change
       sets differ in kind, not degree: one is the fix, the other is a
       line's divergence, and the advisory names files in the first.
    3. Then the earliest parent. With nothing to choose on -- an advisory
       that names no path, which is common -- this is `fixed^`, the
       behaviour that was there before, so the change can only move a pair
       the advisory actually points away from.
    """
    usable = [item for item in scored if not item["unusable"]]
    if not usable:
        return None
    return min(usable, key=lambda item: (-item["match"], item["position"]))


def _lookup_off() -> bool:
    """Whether the operator turned the advisory and registry lookups off.

    releases.find_releases honours CVELAB_PUBLISHED_RELEASES and
    pair_from_advisory does not, because until now it only ran on a path
    that had already decided to look things up. Verifying every pair would
    otherwise have made a documented off switch stop turning the lookup off.
    """
    return os.getenv("CVELAB_PUBLISHED_RELEASES", "").strip().lower() in {
        "0", "off", "false", "no",
    }


def release_pair(repo_url: str, cve: str) -> dict | None:
    """The advisory's last affected and first patched tags, resolved once per run.

    None for every kind of silence: no advisory, no inclusive upper bound and
    no registry, a repository whose tags cannot be listed, a project that
    does not tag releases, or a network that is not there. releases._get and
    resolve_source_via_osv both answer that way rather than raising, and a
    verification that failed a run over an unreachable GitHub would be worse
    than the guessing it replaced.
    """
    key = (repo_url, cve)
    if key in _PAIRS:
        return _PAIRS[key]
    found = None
    if repo_url and not _lookup_off():
        try:
            found = releases.tag_pair(repo_url, releases.pair_from_advisory(cve))
        except Exception:  # noqa: BLE001 - see the docstring: never fatal
            found = None
    _PAIRS[key] = _safe_tags(found)
    return _PAIRS[key]


def _safe_tags(pair: dict | None) -> dict | None:
    """The pair, or None when either tag name is not something to hand git.

    A tag name arrives from `git ls-remote` on a public repository, so it is
    as untrusted as a revision from a model or the command line, and these
    two reach `git diff` and `git archive` once the pair is preferred. The
    resolver that already accepted this pair sanitised the tags with
    _safe_revision on its own path; this one must too, and a repository that
    publishes a tag git would read as an option loses the verification
    rather than the run.
    """
    if not pair:
        return None
    from .sourcegen import _safe_revision

    try:
        for role in ("vulnerable_tag", "fixed_tag"):
            _safe_revision(pair.get(role), f"{role} the advisory's release pair resolved to")
    except ValueError:
        return None
    return pair


def reference_for(dossier: dict, revision: str | None) -> str:
    """The CVE record's own reference that names this revision, or "".

    resolve_source walks the record's references and returns the first commit
    URL it finds without saying which one it was, so the URL is found again
    here rather than threaded back through a return value every other caller
    of resolve_source would have to change.
    """
    wanted = str(revision or "").strip().lower()
    if not wanted:
        return ""
    from .sourcegen import GITHUB_COMMIT, GITLAB_COMMIT

    for entry in dossier.get("references") or []:
        text = str(entry)
        github = GITHUB_COMMIT.match(text)
        if github and github.group(3).lower() == wanted:
            return text
        gitlab = GITLAB_COMMIT.match(text)
        if gitlab and gitlab.group(2).lower() == wanted:
            return text
    return ""


def verify_pair(
    repository: Path,
    vulnerable: str,
    fixed: str | None,
    dossier: dict,
    cve: str,
    repo_url: str = "",
    *,
    explicit: bool = False,
    resolver: str = "",
) -> Verdict:
    """Check the pair, correct the vulnerable side where the evidence says to, and say how.

    Called before either snapshot is extracted and before the first token is
    spent, so a correction costs nothing and a pair that cannot work is known
    before it is paid for.

    `explicit` says the vulnerable side came from the operator or from
    discovery rather than from `fixed^`. An explicit revision is not a guess
    and is not overruled here; a disagreement with the advisory is recorded
    for whoever reads the plan, and that is all.
    """
    described = research.words(" ".join(str(text) for text in dossier.get("descriptions") or []))
    reference = reference_for(dossier, fixed or vulnerable)
    record = {
        "resolver": resolver or (CVE_REFERENCE if reference else OSV),
        "reference": reference,
        "vulnerable_side": VULNERABLE_EXPLICIT if (explicit or not fixed) else FIRST_PARENT,
        "ancestry": UNKNOWN,
        "affected_line": UNKNOWN,
        "verified": False,
    }

    # (a) A merge has one before-state per parent. Which one is the fix's is
    #     a question with an answer, and `fixed^` never asked it.
    if fixed and not explicit:
        listed = parents(repository, fixed)
        if len(listed) > 1:
            scored = _scored_parents(repository, fixed, listed, described)
            record["merge_parents"] = listed
            record["parent_match"] = [
                {key: item[key] for key in ("position", "changed_files", "match", "unusable")}
                for item in scored
            ]
            best = _best_parent(scored)
            if best:
                vulnerable = best["parent"]
                record["vulnerable_side"] = CHOSEN_PARENT
                record["chosen_parent"] = best["position"]

    # (b) The advisory's own affected line, consulted for a pair that
    #     resolved and not only when nothing did.
    pair = release_pair(repo_url, cve)
    if pair:
        record["advisory_tags"] = {
            "vulnerable": pair["vulnerable_tag"],
            "fixed": pair["fixed_tag"],
            "vulnerable_version": pair["vulnerable_version"],
            "fixed_version": pair["fixed_version"],
        }
        on_line = is_ancestor(repository, vulnerable, pair["fixed_tag"])
        if on_line is True:
            record["affected_line"] = f"ancestor of {pair['fixed_tag']}"
        elif on_line is False:
            # The pair in hand is not on the line the fix shipped on, which
            # is what a reference resolved to the wrong release line looks
            # like. The advisory states its own two ends and the repository
            # tags them, so prefer that pair and keep the one it replaced in
            # the record: the disagreement is the evidence, and an artifact
            # that hid it could not be argued with afterwards.
            tagged = is_ancestor(repository, pair["vulnerable_tag"], pair["fixed_tag"])
            if tagged is True and fixed:
                record["rejected"] = {"vulnerable": vulnerable, "fixed": fixed}
                record["resolver"] = TAG_PAIR
                record["reference"] = pair["repository"]
                record["vulnerable_side"] = RELEASE_TAG
                record["affected_line"] = f"{pair['vulnerable_tag']} -> {pair['fixed_tag']}"
                vulnerable, fixed = pair["vulnerable_tag"], pair["fixed_tag"]
            else:
                record["affected_line"] = (
                    f"{vulnerable} is not an ancestor of {pair['fixed_tag']}"
                )

    # (c) The one check that can say no on its own, with no network and no
    #     advisory: two revisions that are not on one line of history are not
    #     a before and an after, and their diff carries the fix mixed with
    #     everything each side changed alone. A pair that cannot be verified
    #     is not aborted -- it goes to the demotion the generator already
    #     has, which is where an unusable pair has gone since it landed.
    demotion = None
    if fixed:
        linear = is_ancestor(repository, vulnerable, fixed)
        if linear is True:
            record["ancestry"] = "confirmed"
        elif linear is False:
            from .sourcegen import _RESOLVE_AGAIN

            record["ancestry"] = "not one line of history"
            demotion = (
                f"the vulnerable revision ({vulnerable}) is not an ancestor of the fixed "
                f"revision ({fixed}), so the two are not a before and an after of one "
                f"history and their diff is not the fix; {_RESOLVE_AGAIN}"
            )
    # Verified means both halves answered, not merely that neither objected:
    # the two revisions are on one line of history, and the advisory's own
    # affected line says so too.
    verified = record["ancestry"] == "confirmed" and record["affected_line"] != UNKNOWN
    record["verified"] = verified
    return Verdict(vulnerable, fixed, verified, demotion, record)
