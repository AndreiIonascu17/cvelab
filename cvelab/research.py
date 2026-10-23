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

"""What the model sees of a security fix, and how it asks for more.

A fix that fits in the prompt is shown whole. A larger one is ranked and cut
to a budget, which on its own still decides for the model what matters: a
2.35 MB PHP fix covering two CVEs showed 74 of its 423 files, all under the
first directory, and the model reproduced the CVE it could see rather than
the one it was asked for.

So a fix that does not fit, and every repair, gets a research phase. The
model reads an index of every file the fix touches and asks for the source
it needs -- one file's diff with whole functions around each change, a range
of lines, a literal search, a directory listing -- before the lab is
written. Any file in the repository can be asked for, so the number of files
a CVE needs is no longer bounded by what fits in one prompt.

Nothing a request does runs code. Reads come from the source snapshots the
lab is built from and from git in the lab's own cache, and every path is
checked to stay inside them.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import progress
from .ai import structured_response
from .core import write_text

# How much of a fix the model is shown in one prompt. A fix that fits is
# shown whole and in git's order; a larger one is ranked and cut.
PATCH_BUDGET = 90000
HINT_LIMIT = 2000
RESEARCH_FILE = "research.json"
MODES = ("auto", "on", "off")

_TEST_DIRS = frozenset({
    "test", "tests", "testing", "testdata", "spec", "specs", "__tests__", "fixtures", "e2e",
})
_DOC_DIRS = frozenset({"doc", "docs", "documentation"})
_DOC_SUFFIXES = frozenset({".md", ".rst", ".adoc"})
_DOC_NAMES = frozenset({"news", "changelog", "changes", "history", "upgrading", "authors"})
# Words so common in CVE text that matching them says nothing about a file.
_STOPWORDS = frozenset({
    "about", "affected", "after", "allow", "allows", "also", "another", "attacker", "attackers",
    "because", "been", "before", "being", "both", "cause", "could", "does", "during", "each",
    "even", "fixed", "from", "have", "into", "issue", "lead", "leads", "more", "multiple",
    "must", "only", "other", "patched", "prior", "remote", "same", "some", "such", "than",
    "that", "their", "them", "then", "there", "these", "this", "those", "through", "under",
    "used", "uses", "using", "various", "version", "versions", "very", "vulnerability",
    "vulnerable", "when", "where", "which", "while", "with", "within", "without", "would",
})
_HUNK = re.compile(r"^@@ [^@]* @@ ?(.*)$")


@dataclass(frozen=True)
class Budget:
    """Characters, per part of the research phase."""

    record: int  # the CVE record in a research prompt
    overview: int  # the repository's top level in a research prompt
    index: int  # the file index in a research prompt
    preview: int  # the ranked preview of the fix in a research prompt
    answer: int  # one request's answer
    round: int  # every answer in one round
    material: int  # everything gathered, across rounds and repairs
    brief: int  # the analysis, and the build notes, each
    requests: int  # requests honoured per round


HOSTED = Budget(
    record=20000, overview=6000, index=60000, preview=40000, answer=40000, round=120000, material=200000, brief=8000,
    requests=12,
)
# A local model's window is small enough that the prompt has to stay near
# the 60,000 characters a local generation is cut to.
LOCAL = Budget(
    record=6000, overview=2000, index=12000, preview=8000, answer=8000, round=16000, material=24000, brief=3000, requests=4,
)

# What one request may return before the answer is cut.
FILE_LINES = 400
FILE_BYTES = 8 * 1024 * 1024
LIST_ENTRIES = 300
SEARCH_MATCHES = 120
SEARCH_FILES = 200000
SEARCH_FILE_BYTES = 2 * 1024 * 1024
QUERY_LIMIT = 200


def clip_section(content: str, limit: int) -> str:
    if len(content) <= limit:
        return content
    marker = "\n... [CVELab truncated this section for the local context window] ...\n"
    if limit <= len(marker):
        return content[:max(0, limit)]
    usable = max(0, limit - len(marker))
    head = usable * 3 // 4
    return content[:head] + marker + content[-(usable - head):]


def _positive_setting(variable: str, default: int, upper: int) -> int:
    raw = os.getenv(variable)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{variable} must be a whole number, got {raw!r}") from error
    if value < 1 or value > upper:
        raise ValueError(f"{variable} must be between 1 and {upper}")
    return value


def prompt_budget(local: bool) -> int:
    """Characters of source context a generation prompt may carry.

    A local model gets the 60,000 it always had. A hosted one used to be
    unbounded, which a large fix plus research could push past a model's
    window; 320,000 characters is about 90,000 tokens of code, room for the
    answer under a 200,000-token window. CVELAB_CONTEXT_CHARS overrides it
    for hosted models with a larger window.
    """
    if local:
        return 60000
    return _positive_setting("CVELAB_CONTEXT_CHARS", 320000, 4000000)


def research_rounds() -> int:
    """Research calls before a lab is written. CVELAB_RESEARCH_ROUNDS overrides it."""
    return _positive_setting("CVELAB_RESEARCH_ROUNDS", 3, 10)


def research_mode(value: str | None) -> str:
    """auto, on or off: the flag, else CVELAB_RESEARCH, else auto."""
    mode = (value or os.getenv("CVELAB_RESEARCH") or "auto").strip().lower()
    if mode not in MODES:
        raise ValueError(f"Research mode must be one of {', '.join(MODES)}, got {mode!r}")
    return mode


def normalize_hint(hint: str | None) -> str | None:
    text = (hint or "").strip()
    return text[:HINT_LIMIT] or None


def words(text: str) -> set[str]:
    """Words of four characters or more, with identifiers also split on "_"."""
    found = set()
    for token in re.findall(r"[a-z0-9_]{4,}", text.lower()):
        found.add(token)
        found.update(part for part in token.split("_") if len(part) >= 4)
    return {word for word in found if not word.isdigit() and word not in _STOPWORDS}


def split_diff(diff: str) -> list[tuple[str, str]]:
    """A git diff as (path, section) pairs, in git's order."""
    starts = [match.start() for match in re.finditer(r"^diff --git ", diff, re.M)]
    if not starts:
        return [("", diff)] if diff else []
    sections = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(diff)
        section = diff[start:end]
        header = re.match(r"diff --git a/(.*) b/(.*)$", section.split("\n", 1)[0])
        sections.append((header.group(2) if header else "", section))
    return sections


def file_kind(path: str) -> int:
    """0 for code, 1 for tests, 2 for documentation: the order a cut fix is shown in."""
    pure = PurePosixPath(path.lower())
    folders = set(pure.parts[:-1])
    if (
        folders & _DOC_DIRS
        or pure.suffix in _DOC_SUFFIXES
        or pure.stem in _DOC_NAMES
        or pure.name in _DOC_NAMES
    ):
        return 2
    if folders & _TEST_DIRS or re.search(r"^test_|_test\.|\.test\.|_spec\.|\.spec\.", pure.name):
        return 1
    return 0


def _hunk_lines(section: str) -> list[str]:
    """The lines inside a section's hunks, not its file headers."""
    lines = section.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("@@"):
            return lines[index:]
    return []


def _changed_words(section: str) -> set[str]:
    return words("\n".join(
        line[1:] for line in _hunk_lines(section) if line[:1] in ("+", "-")
    ))


def _match_score(terms: set[str], path_words: set[str], changed_words: set[str]) -> int:
    """A term in a file's path counts three times one in its changed lines."""
    return sum(
        3 if term in path_words else 1
        for term in terms
        if term in path_words or term in changed_words
    )


def rank_sections(
    sections: list[tuple[str, str]],
    described: set[str],
    hinted: set[str],
) -> list[int]:
    """Section indices, best first.

    Files matching the operator's hint come first, then code before tests and
    documentation, then by match to the CVE text, then git's order.
    """
    keys = []
    for index, (path, section) in enumerate(sections):
        path_words = words(path)
        changed = _changed_words(section)
        keys.append((
            -_match_score(hinted, path_words, changed),
            file_kind(path),
            -_match_score(described, path_words, changed),
            index,
        ))
    keys.sort()
    return [key[3] for key in keys]


def select_patch(
    diff: str,
    described: set[str],
    hinted: set[str],
    budget: int = PATCH_BUDGET,
) -> tuple[str, list[str]]:
    """Fit a fix into the budget, best matches first.

    Code may take two thirds of the budget before tests get a turn, because
    an upstream test is often the clearest statement of what a fix guards;
    either may use what the other leaves. No file takes more than a quarter.
    Returns the text and every changed path in ranked order.
    """
    sections = split_diff(diff)
    if len(diff) <= budget:
        return diff, [path for path, _ in sections]
    order = rank_sections(sections, described, hinted)
    file_limit = budget // 4
    code_share = budget * 2 // 3
    minimum = budget // 20
    shown: dict[int, str] = {}
    used = code_used = 0
    for first_pass in (True, False):
        for index in order:
            if index in shown:
                continue
            kind = file_kind(sections[index][0])
            room = budget - used
            if first_pass:
                if kind == 2:
                    continue
                if kind == 0:
                    room = min(room, code_share - code_used)
            piece = clip_section(sections[index][1], file_limit)
            if len(piece) > room:
                if room < minimum:
                    continue
                piece = clip_section(piece, room)
            shown[index] = piece
            used += len(piece)
            if kind == 0:
                code_used += len(piece)
    note = (
        f"[CVELab: this fix changes {len(sections)} files in {len(diff)} characters, more than the "
        f"{budget} shown here. {len(shown)} files are shown, best match to the CVE text"
        + (" and the operator hint" if hinted else "")
        + " first and code before tests; changed_files lists every file the fix touches.]\n"
    )
    return (
        note + "".join(shown[index] for index in order if index in shown),
        [sections[index][0] for index in order],
    )


def fix_index(sections: list[tuple[str, str]], order: list[int], limit: int) -> str:
    """One line per changed file, in ranked order: kind, size and functions."""
    entries = []
    for index in order:
        path, section = sections[index]
        added = removed = 0
        functions: list[str] = []
        for line in _hunk_lines(section):
            if line.startswith("@@"):
                match = _HUNK.match(line)
                name = match.group(1).strip()[:80] if match else ""
                if name and name not in functions:
                    functions.append(name)
            elif line.startswith("+"):
                added += 1
            elif line.startswith("-"):
                removed += 1
        entry = f"{('code', 'test', 'docs')[file_kind(path)]} +{added} -{removed} {path}"
        if functions:
            entry += "  in: " + "; ".join(functions[:6]) + ("; ..." if len(functions) > 6 else "")
        entries.append(entry)
    shown: list[str] = []
    used = 0
    for entry in entries:
        if used + len(entry) + 1 > limit:
            break
        shown.append(entry)
        used += len(entry) + 1
    if len(shown) < len(entries):
        shown.append(
            f"... {len(entries) - len(shown)} more changed files, ranked lower; "
            "list a directory or search to find them."
        )
    return "\n".join(shown)


class RequestRefused(Exception):
    """A research request that cannot be answered, and why."""


class Workspace:
    """The source a research request can read, and nothing else."""

    def __init__(
        self,
        repository: Path,
        vulnerable: str,
        fixed: str | None,
        roots: dict[str, Path],
        changed: list[str],
        run_git: Callable[..., str],
    ) -> None:
        self.repository = repository
        self.vulnerable = vulnerable
        self.fixed = fixed
        self.roots = {name: root.resolve() for name, root in roots.items()}
        self.changed = set(changed)
        self.run_git = run_git

    def answer(self, request: dict, limit: int) -> str:
        handlers = {
            "diff": self._diff, "file": self._file, "search": self._search, "list": self._list,
        }
        handler = handlers.get(str(request.get("kind")))
        try:
            if handler is None:
                raise RequestRefused(f"unknown kind {request.get('kind')!r}")
            text = handler(request)
        except RequestRefused as refused:
            return f"### {describe(request)}\nRefused: {refused}\n"
        return clip_section(text, limit)

    def _revision(self, request: dict) -> tuple[str, str]:
        """The snapshot to read, and a note when the request named another."""
        if request.get("revision") == "fixed" and "fixed" in self.roots:
            return "fixed", ""
        if request.get("revision") == "fixed":
            return "vulnerable", " (no fixed revision exists, so this is the vulnerable one)"
        return "vulnerable", ""

    @staticmethod
    def _relative(value: object) -> str:
        text = str(value or "").strip().replace("\\", "/")
        while text.startswith("./"):
            text = text[2:]
        text = text.strip("/")
        if text in ("", "."):
            return ""
        pure = PurePosixPath(text)
        if ".." in pure.parts:
            raise RequestRefused("paths are relative to the repository root and may not contain ..")
        return pure.as_posix()

    def _local(self, revision: str, path: str) -> Path:
        root = self.roots[revision]
        candidate = (root / path).resolve() if path else root
        if candidate != root and root not in candidate.parents:
            raise RequestRefused("that path leaves the repository")
        return candidate

    def _diff(self, request: dict) -> str:
        if self.fixed is None:
            raise RequestRefused("there is no fixed revision, so there is no diff; ask for the file")
        path = self._relative(request.get("path"))
        if path not in self.changed:
            raise RequestRefused("not a file this fix changes; ask for it with kind file")
        text = self.run_git(
            [
                "--literal-pathspecs", "diff", "--no-ext-diff", "--function-context",
                "--end-of-options", self.vulnerable, self.fixed, "--", path,
            ],
            cwd=self.repository,
        )
        return f"### diff {path} (whole functions around each change)\n{text}"

    def _file(self, request: dict) -> str:
        revision, note = self._revision(request)
        path = self._relative(request.get("path"))
        if not path:
            raise RequestRefused("name a file; list shows a directory")
        local = self._local(revision, path)
        if local.is_dir():
            raise RequestRefused("that is a directory; use list")
        if not local.is_file():
            raise RequestRefused(f"no such file at the {revision} revision")
        if local.stat().st_size > FILE_BYTES:
            raise RequestRefused("the file is larger than 8 MB; search it instead")
        data = local.read_bytes()
        if b"\0" in data[:8192]:
            raise RequestRefused("binary file")
        lines = data.decode("utf-8", errors="replace").splitlines()
        total = len(lines)
        start = max(1, _whole(request.get("start_line")) or 1)
        if start > total:
            raise RequestRefused(f"the file has {total} lines")
        end = _whole(request.get("end_line")) or start + FILE_LINES - 1
        end = max(start, min(total, end, start + FILE_LINES - 1))
        body = "\n".join(f"{number:>6}  {lines[number - 1]}" for number in range(start, end + 1))
        return f"### file {revision}:{path} lines {start}-{end} of {total}{note}\n{body}\n"

    def _search(self, request: dict) -> str:
        query = str(request.get("query") or "")
        if not query.strip():
            raise RequestRefused("search needs a query")
        if len(query) > QUERY_LIMIT or "\n" in query:
            raise RequestRefused(f"a query is one line of at most {QUERY_LIMIT} characters")
        revision, note = self._revision(request)
        prefix = self._relative(request.get("path"))
        start = self._local(revision, prefix)
        if not start.exists():
            raise RequestRefused(f"no such path at the {revision} revision")
        root = self.roots[revision]
        needle = query.encode("utf-8")
        matches: list[str] = []
        total = files = scanned = 0
        stopped = False
        for path in _walk(start):
            scanned += 1
            if scanned > SEARCH_FILES:
                stopped = True
                break
            try:
                if path.stat().st_size > SEARCH_FILE_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if needle not in data or b"\0" in data[:8192]:
                continue
            files += 1
            relative = path.relative_to(root).as_posix()
            for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                if query in line:
                    total += 1
                    if len(matches) < SEARCH_MATCHES:
                        matches.append(f"{relative}:{number}: {line.strip()[:240]}")
        header = (
            f"### search {revision}:{prefix or '.'} for {query!r}{note}: "
            f"{total} matching lines in {files} files"
        )
        if total > len(matches):
            header += f", the first {len(matches)} shown"
        if stopped:
            header += f"; stopped after {SEARCH_FILES} files, so name a directory"
        return header + "\n" + "\n".join(matches) + "\n"

    def _list(self, request: dict) -> str:
        revision, note = self._revision(request)
        path = self._relative(request.get("path"))
        local = self._local(revision, path)
        if not local.is_dir():
            raise RequestRefused(f"no such directory at the {revision} revision")
        entries = sorted(local.iterdir(), key=lambda item: (not _is_real_dir(item), item.name))
        lines = []
        for entry in entries[:LIST_ENTRIES]:
            if entry.is_symlink():
                lines.append(f"{entry.name}  (symbolic link)")
            elif entry.is_dir():
                lines.append(f"{entry.name}/  ({sum(1 for _ in entry.iterdir())} entries)")
            else:
                lines.append(f"{entry.name}  {entry.stat().st_size} bytes")
        header = f"### list {revision}:{path or '.'}{note}: {len(entries)} entries"
        if len(entries) > LIST_ENTRIES:
            header += f", the first {LIST_ENTRIES} shown"
        return header + "\n" + "\n".join(lines) + "\n"


def _whole(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _is_real_dir(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink()


def _walk(start: Path):
    """Regular files under start, in a stable order, without following links."""
    if start.is_file():
        if not start.is_symlink():
            yield start
        return
    for directory, folders, names in os.walk(start):
        folders[:] = sorted(
            name for name in folders
            if name != ".git" and not os.path.islink(os.path.join(directory, name))
        )
        for name in sorted(names):
            path = Path(directory) / name
            if not path.is_symlink():
                yield path


def describe(request: dict) -> str:
    kind = request.get("kind")
    revision = request.get("revision") or "vulnerable"
    path = request.get("path") or "."
    if kind == "diff":
        return f"diff {path}"
    if kind == "file":
        return f"file {revision}:{path} lines {request.get('start_line')}-{request.get('end_line')}"
    if kind == "search":
        return f"search {revision}:{path} for {request.get('query')!r}"
    return f"{kind} {revision}:{path}"


def _request_key(request: dict) -> tuple:
    return tuple(
        request.get(field)
        for field in ("kind", "revision", "path", "query", "start_line", "end_line")
    )


RESEARCH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["analysis", "build_notes", "requests", "done"],
    "properties": {
        "analysis": {"type": "string"},
        "build_notes": {"type": "string"},
        # No maxItems: Anthropic's schema subset drops it and the answer
        # would then be refused after the fact. Extra requests are simply
        # not honoured.
        "requests": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "revision", "path", "query", "start_line", "end_line"],
                "properties": {
                    "kind": {"type": "string", "enum": ["diff", "file", "search", "list"]},
                    "revision": {"type": "string", "enum": ["vulnerable", "fixed"]},
                    "path": {"type": "string"},
                    "query": {"type": ["string", "null"]},
                    "start_line": {"type": ["integer", "null"]},
                    "end_line": {"type": ["integer", "null"]},
                },
            },
        },
        "done": {"type": "boolean"},
    },
}


def _instructions(cve: str, round_number: int, rounds: int, requests: int, repairing: bool) -> str:
    text = (
        f"You are preparing an authorized, local-only defensive regression lab for {cve}: Docker images "
        "of the affected and the fixed revision of an open-source project, and a validator that sends "
        "the same input to both. This step is research only; do not write the lab. From the CVE record "
        "and the fix, work out: (1) which part of the fix addresses this CVE -- one commit may fix "
        "several issues, so name the files and functions that matter for this one and say which do "
        "not; (2) the code path from input an attacker controls to the flaw, and the state it needs: "
        "configuration, extensions or modules compiled in, authentication, earlier requests or "
        "sessions; (3) what building and running the affected revision needs: build system, configure "
        "flags, extensions, dependencies, services. Ask for the source that settles these. kind diff: "
        "path is a changed file, and you get its diff with whole functions around each change. kind "
        "file: path, revision, start_line and end_line, at most 400 lines a request. kind search: a "
        "literal string in query (not a regular expression) under the directory in path, empty for "
        "the whole tree. kind list: the directory in path. Use null for fields a kind does not take. "
        f"Ask only for what you need, at most {requests} requests this round. Set done to true when "
        "you can describe the lab without guessing. Write analysis and build_notes for the engineer "
        "who will build the lab from them: concrete, with file paths, functions, flags and request "
        "sequences, and say plainly what you could not establish. They are the brief itself, so "
        "leave out notes about rounds and requests. "
        f"This is round {round_number} of at most {rounds}. Requests in the last round are still "
        "answered and shown to the engineer, though you will not see the answers."
    )
    if repairing:
        text += (
            " A lab built from an earlier brief failed; the failure is under SITUATION. Ask for the "
            "source that explains it -- a build option, a missing module or extension, a code path the "
            "validator did not reach -- and rewrite the brief to account for it."
        )
    return text


def _material_text(material: list[dict], limit: int) -> str:
    """Answers in the order they were given, keeping the newest when not all fit.

    The newest answer is the one a repair asked for about the failure in
    front of it, so it is the last to go.
    """
    chosen: list[str] = []
    used = 0
    for item in reversed(material):
        answer = item["answer"]
        if used + len(answer) > limit:
            continue
        chosen.append(answer)
        used += len(answer)
    omitted = len(material) - len(chosen)
    chosen.reverse()
    text = "\n".join(chosen)
    if omitted:
        text += f"\n[{omitted} earlier answers omitted for space.]\n"
    return text


def research_fix(
    *,
    cve: str,
    dossier: dict,
    hint: str | None,
    workspace: Workspace,
    index: str,
    preview: str,
    overview: str,
    budget: Budget,
    rounds: int,
    api_key: str | None,
    model: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    situation: str | None = None,
    prior: dict | None = None,
) -> dict:
    """Let the model read the fix and ask for source until it is done.

    Returns the brief: the model's analysis and build notes, and every
    answer it was given. A prior brief is extended rather than replaced, so
    a repair keeps what generation learnt.
    """
    brief = {
        "cve": cve,
        "revisions": {"vulnerable": workspace.vulnerable, "patched": workspace.fixed},
        "hint": hint,
        "analysis": "",
        "build_notes": "",
        "rounds": 0,
        "material": [],
        **(prior or {}),
    }
    brief["material"] = list(brief["material"])
    asked = {_request_key(item["request"]) for item in brief["material"]}
    used = sum(len(item["answer"]) for item in brief["material"])
    head = [
        "--- CVE RECORD ---\n"
        + clip_section(json.dumps(dossier, ensure_ascii=True, indent=2), budget.record),
    ]
    if hint:
        head.append("--- OPERATOR HINT ---\n" + hint)
    if workspace.fixed is None:
        head.append(
            "--- THE SOURCE ---\nNo public fix was identified; only the affected revision "
            f"{workspace.vulnerable} exists. Ask for files, searches and listings at revision vulnerable."
        )
    else:
        head.append(
            f"--- THE FIX: {len(workspace.changed)} changed files between {workspace.vulnerable} "
            f"(affected) and {workspace.fixed} (fixed), best match to this CVE first ---\n" + index
        )
        head.append("--- PREVIEW OF THE FIX ---\n" + preview)
    head.append("--- REPOSITORY ROOT ---\n" + overview)
    for round_number in range(1, rounds + 1):
        parts = list(head)
        if brief["analysis"] or brief["build_notes"]:
            parts.append(
                "--- YOUR BRIEF SO FAR ---\nAnalysis:\n" + brief["analysis"]
                + "\nBuild notes:\n" + brief["build_notes"]
            )
        if brief["material"]:
            parts.append("--- SOURCE YOU ASKED FOR ---\n" + _material_text(brief["material"], budget.material))
        if situation:
            parts.append("--- SITUATION ---\n" + situation)
        with progress.stage(f"researching the fix ({round_number}/{rounds})"):
            answer = structured_response(
                api_key=api_key,
                model=model,
                schema=RESEARCH_SCHEMA,
                schema_name="cvelab_fix_research",
                max_output_tokens=6000,
                instructions=_instructions(cve, round_number, rounds, budget.requests, bool(situation)),
                input_text="\n\n".join(parts),
                provider=provider,
                base_url=base_url,
            )
        brief["analysis"] = answer["analysis"][:budget.brief]
        brief["build_notes"] = answer["build_notes"][:budget.brief]
        brief["rounds"] += 1
        spent = fresh = 0
        for request in answer["requests"][:budget.requests]:
            key = _request_key(request)
            if key in asked:
                continue
            asked.add(key)
            fresh += 1
            if used >= budget.material or spent >= budget.round:
                text = f"### {describe(request)}\nRefused: the research budget is spent.\n"
            else:
                text = workspace.answer(
                    request, min(budget.answer, budget.round - spent, budget.material - used)
                )
            brief["material"].append({"request": request, "answer": text})
            spent += len(text)
            used += len(text)
        # Nothing new to read means another round would see the same prompt.
        if answer["done"] or not fresh:
            break
    return brief


def render_brief(brief: dict, limit: int) -> str:
    """The brief as the generation and repair prompts read it, within limit."""
    head = (
        "\n\n--- RESEARCH BRIEF ---\n"
        f"Written by the model after reading the fix ({brief.get('rounds', 0)} rounds, "
        f"{len(brief.get('material') or [])} pieces of source). It says which part of the fix this "
        "CVE is and what the build needs. Follow it unless the source contradicts it.\n"
        "Analysis:\n" + str(brief.get("analysis") or "") + "\n"
        "Build notes:\n" + str(brief.get("build_notes") or "") + "\n"
    )
    if len(head) >= limit:
        return clip_section(head, limit)
    material = brief.get("material") or []
    if not material:
        return head
    title = "\n--- SOURCE GATHERED DURING RESEARCH ---\n"
    return head + title + _material_text(material, limit - len(head) - len(title))


def summary(brief: dict) -> dict:
    """What plan.json records of the research: enough to know it happened."""
    return {
        "rounds": brief.get("rounds", 0),
        "requests": len(brief.get("material") or []),
        "file": RESEARCH_FILE,
    }


def save(lab_dir: Path, brief: dict) -> None:
    write_text(lab_dir / RESEARCH_FILE, json.dumps(brief, indent=2, ensure_ascii=True) + "\n")


def load(lab_dir: Path) -> dict | None:
    try:
        brief = json.loads((lab_dir / RESEARCH_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return brief if isinstance(brief, dict) and isinstance(brief.get("material"), list) else None


def matches(brief: dict | None, cve: str, vulnerable: str, fixed: str | None, hint: str | None) -> bool:
    """Whether a saved brief was made for this CVE, these revisions and this hint."""
    return bool(
        brief
        and brief.get("cve") == cve
        and brief.get("revisions") == {"vulnerable": vulnerable, "patched": fixed}
        and brief.get("hint") == hint
    )
