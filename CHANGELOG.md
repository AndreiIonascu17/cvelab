# Changelog

All notable changes to CVELab are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- An answer refused before the build is asked for again with the reason,
  up to twice (`CVELAB_CONTRACT_RETRIES`, 0 to 5), instead of costing a
  generation attempt or one of the three repairs. Rerunning the failed
  entries of three benchmark batches, half of the repair budget went to
  layout refusals the model repeated. The refusals are kept in plan.json.
- When the fix also shipped in an npm or PyPI release, the prompt offers
  the last vulnerable and the first patched version, resolved from GitHub's
  reviewed advisory and the registry, so a lab for a large monorepo can
  install the two instead of building the source. Most framework labs
  (Next.js, Nuxt, Storybook, Astro, Sentry) failed in that build. The pair
  is kept in plan.json; `CVELAB_PUBLISHED_RELEASES=off` turns it off.

- A lab whose two variants could differ for any reason but the fix is
  refused before it is built. vulnerable/Dockerfile and patched/Dockerfile,
  and their Compose services, may differ only in the snapshot they copy, in
  labels carrying their own name, in package versions and in commit ids,
  and the adapter may not compare against the variant name. A TanStack
  Start lab passed validation with a harness that read `ROLE=vulnerable`,
  never ran TanStack code, and said so in its own fidelity report.

### Fixed

- A Dockerfile that copies a file its build context does not hold is
  refused before Docker runs, with the file, the context it is built from
  and the closest file the answer does contain. Docker reported it as a
  checksum failure deep in the build log, and the repair given that log
  tended to repeat it: 15 of 27 failed builds across three benchmark
  batches were this, most of them a validator copying from adapter/. A
  target that copies the whole lab directory is refused too: it put both
  snapshots in one image and the vendor tree one level deeper than the build
  expected. The generation and repair prompts now state the fixed build
  contexts.

## [0.6.7] - 2026-10-23

### Security

- A shared lab no longer shows where, or as whom, it was generated.
  MANUAL-POC.md told the reader to `cd` into the lab's absolute path, and
  Docker and Compose errors kept in EVIDENCE.json, report.json and plan.json
  quoted it too, so a published entry carried the filer's user name and
  folder layout. The guide now says `cd CVE-…/artifacts`, and every
  uploaded document and error has the lab directory replaced by its name
  and anything else under the home directory by `~`.

## [0.6.6] - 2026-10-23

### Added

- A CVE that CVE.org still holds as reserved is read from GitHub's reviewed
  advisory instead. A CNA can publish the advisory, CVE number included,
  days before CVE.org publishes the record, and until then every run on it
  ended on `CVE API returned HTTP 404`. The advisory's description, CWEs,
  affected versions and fix commits fill the same dossier, and the report
  names the advisory as its source. CVE.org is still asked first.

### Fixed

- An identifier with no record at CVE.org or at GitHub stops after one
  attempt with a message saying it may be reserved or mistyped. The answer
  cannot change between attempts, and the run used to spend all four on it.
  A server error or a rate limit is still retried.

## [0.6.5] - 2026-10-23

### Added

- A research phase before a lab is written, for a fix that does not fit in
  one prompt (more than 90,000 characters of diff or more than 24 changed
  files) and on every repair. The model reads an index of every changed file,
  with the functions each change is in, and asks for the source it needs: one
  file's diff with whole functions around each change, a range of lines from
  either revision, a literal search, or a directory listing. Any file in the
  repository can be asked for, so a CVE is no longer limited to what fits in
  one prompt. A repair asks with the failure in front of it. Requests only
  read, from the lab's source snapshots and its git cache, and no path can
  leave them. The analysis, the build notes and everything read are saved in
  `research.json`; `plan.json` records the rounds and requests. `--research
  auto|on|off` and `CVELAB_RESEARCH` choose when it runs, and
  `CVELAB_RESEARCH_ROUNDS` (default 3) bounds it.
- `--hint` on `source`, `source-all` and `auto` tells the model which part of
  a fix, or which behaviour, to reproduce. It ranks the fix's files too, and
  is recorded in `plan.json`.

### Changed

- A fix too large for the prompt is ranked rather than cut in path order:
  files matching the hint, then code before tests and documentation, then by
  match to the CVE text. A 2.35 MB PHP fix covering two CVEs used to show 74
  of its 423 files, all under `Zend/`, and the model reproduced the CVE it
  could see instead of the one it was asked for.
- A hosted model's prompt carries at most 320,000 characters of source
  context instead of an unbounded amount; `CVELAB_CONTEXT_CHARS` raises it.
  A context under its limit is no longer cut anyway: every excerpt used to
  lose half its length whenever a limit applied.
- The tree sample shows build files (`config.m4`, `CMakeLists.txt`,
  `configure.ac` and the like) and the fix's own directories first, and says
  how many files the repository has.
- An answer cut off at its output budget is asked for again with twice the
  budget, at most twice, up to the provider's ceiling
  (`CVELAB_<PROVIDER>_MAX_OUTPUT`), and with twice the time. It used to end
  the run as an infrastructure failure. OpenAI requests now wait for the
  provider's timeout instead of 180 seconds.
- A lab may carry up to 80 adapter files and eight support services, up from
  10 and 5.

### Fixed

- A Nuxt lab was refused for `adapter/fixture/app/pages/admin/[slug].vue`,
  the only way Nuxt names that route. An adapter path may now carry the
  characters file-based routers use: `[slug]`, `[...all]`, `(group)`,
  `@modal`, `+page.svelte`, `posts.$id.tsx`, `[id=int]`. Characters no
  platform can hold in a name are still refused, and so is leaving the
  lab directory.
- A lab could pass by reading the fix out of the source instead of running
  it. An Electron lab returned
  `readFileSync(guest-window-manager.ts).includes('if (navigate) {')` as its
  verdict, simulated the browser and the cookie jar, and validated. A text
  read of the path the Dockerfiles copy the source to, from an adapter file
  or the validator, is now refused before the build with the file and line;
  so is a fidelity report whose exercised component is read rather than run.
  Reading an upstream fixture as bytes, importing the source and the
  adapter's own files are unaffected, and of the twenty labs validated so
  far only that one is refused. Every prompt says that source text is not
  evidence.
- A repair saw only the top level of `adapter/`, so a nested file such as
  `adapter/app/server.js` never reached the model, and a nested file the
  repaired answer dropped stayed in the build context. Both now work at any
  depth, and generation cleans up after an earlier attempt too.
- A source snapshot extracted over one from another revision kept that
  revision's deleted files. A snapshot is now made once per revision, and
  from empty when the revision changes.
- The generation prompt split "install the exact declared Gradle version"
  around an unrelated paragraph.
- A generation answer that named no exercised vendor component was refused
  after it arrived, spending an attempt. The schema now says so, and a
  provider with constrained decoding cannot produce one.

## [0.6.4] - 2026-10-23

### Security

- A lab's Compose file is checked on what Docker will run, not on its text.
  The old checks were substrings, and a quoted `"privileged": true`,
  `network_mode: "host"`, flow-style `"volumes": [...]`, a second network
  that was not internal, a service with no `networks:` (it landed on the
  default bridge) or `internal: true` in a comment all passed. `run` now
  resolves the file with `docker compose config` before anything is built,
  for generated labs and copied ones alike, and refuses any service key,
  build option, network or top-level section not on an allowlist, naming the
  service and key. `include` and `extends`, which Compose merges invisibly,
  are refused in the raw file; `env_file`, secrets, configs, extra build
  contexts and contexts outside the lab are refused; a `${VAR}` the host
  environment would fill is refused. Every project is named after its lab
  directory, so a lab's `name:` can no longer point teardown at another
  project, and the lab's own `.env` is not read.
- Docker no longer receives the whole environment. A build arg of
  `${ANTHROPIC_API_KEY}` resolved to the real key; Compose now gets only
  what it needs (PATH, HOME, locale, temporary directories, `DOCKER_*`,
  `BUILDKIT_*`, `BUILDX_*`, `COMPOSE_*` except the variables that add files,
  proxies, and the Windows essentials).
- Running lab services are bounded: a service that sets no limit of its own
  gets 2 GB of memory, two CPUs and 1,024 processes. `CVELAB_RUNTIME_MEMORY`,
  `CVELAB_RUNTIME_CPUS` and `CVELAB_RUNTIME_PIDS` change them; an empty value
  removes one. `cvelab closed` applies the same limits to the images it runs.
- A `runner` in `plan.json`, which runs a lab's script on the host outside
  Docker, needs `CVELAB_ALLOW_HOST_RUNNER=1`. The script must be inside the
  lab once symlinks are followed, and a WSL distribution must be a plain name.
- SIGTERM and SIGHUP (and SIGBREAK on Windows) now stop the lab before the
  process exits, with status 128 plus the signal. A closed terminal, systemd
  or a parent's timeout used to leave the containers running.
- The upload token, `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN` and `HF_TOKEN` are redacted like provider keys, and the
  failure output a repair attempt sends to the provider is redacted first.
- An adapter file can no longer replace `docker-compose.yml`, a Dockerfile
  or `validator.py` after they were checked.
- Revisions from source discovery, `plan.json` and the command line must be
  a commit id or a plain tag or branch name, and git is called with
  `--end-of-options`, which needs Git 2.30 or newer.
- `CVELAB_ENDPOINT` must be `https://`, or `http://` to localhost,
  127.0.0.1 or [::1]. A provider base URL may be plain `http://` to another
  host only when no API key is sent, as for Ollama on a LAN.
- `--key VALUE` prints a warning: the value is visible in the process list.
  `--key` alone prompts for it, or set the provider's key variable.

### Changed

- A shared run is described as listed and awaiting review: cvelab.tech now
  releases an entry's documents to subscribers only once it has been
  reviewed. The three new reasons it gives for keeping a run private (a
  `manual.sh` or `PoC.ps1` that is not the generated one, a PoC rejected in
  review, an earlier rejected entry for the same CVE) are explained.

## [0.6.3] - 2026-10-21

### Fixed

- An upload cut an oversized document at its last byte, which for JSON
  leaves text nothing can parse, so the control plane refused a validated
  run whose `EVIDENCE.json` carried a 395 KB validator transcript. A JSON
  document over 128 KiB is now shortened inside its long strings instead,
  each ending with how many bytes it lost, so it still parses; strings under
  1 KiB are never touched. It is still marked truncated, and cvelab.tech
  accepts `EVIDENCE.json` and `report.json` trimmed this way.

## [0.6.2] - 2026-10-20

### Fixed

- Claude models could not generate a lab. They think by default, the
  thinking is billed against `max_tokens`, and Claude Haiku 5.5 ran out of
  budget with the lab's JSON half written (`stop_reason: max_tokens`), on
  every CVE. The Anthropic output budget is now four times larger, as
  DeepSeek's already was; the largest request is 64,000 tokens, under every
  current model's 128K limit. With it, Claude Haiku 5.5 reproduced 9 of 10
  benchmark entries for $0.31 in total.
- Anthropic requests ignored their timeout and waited at most 180 seconds
  for a non-streaming answer. They now use the provider's 600 seconds, or
  `CVELAB_ANTHROPIC_TIMEOUT`.

### Changed

- The acceptable use and security policies are maintained on cvelab.tech
  (`/acceptable-use/`, `/security/`). `ACCEPTABLE_USE.md` keeps the required
  conditions and `SECURITY.md` keeps how to report; both name the pages as
  authoritative. The package's "Security Policy" URL points there too.

## [0.6.1] - 2026-10-20

### Added

- The CLI says what the control plane decided about an upload. A validated
  run the service refuses (HTTP 422) lists every check it failed; a rate
  limit (HTTP 429) says which limit and how long to wait; and a filed run
  says whether it joined the shared database or why it was kept private --
  filed with `--no-poc`, a PoC already listed, or a full review queue. The
  failures and the wait are also in `cvelab upload`'s JSON output.
- Before sending, the upload summary warns when a validated run lacks a file
  the shared database requires, rather than learning it from a refusal.

### Changed

- Trimming an oversized upload keeps the files the shared database requires
  first, so a large `analysis.json` can no longer turn a shareable lab into a
  refused one.
- The upload summary no longer says shared entries are unattributed. They
  carry the filing account, and are marked unverified until reviewed.

## [0.6.0] - 2026-10-18

The first release published to PyPI. The entries below were collected under
Unreleased and shipped in it; the list from the earlier, unpublished 0.6.0
(2026-09-10) is folded in at the end of Added.

### Added

- `cvelab.pyz`, a single-file archive built by `scripts/build_pyz.py` and
  published at `https://cvelab.tech/cvelab.pyz` with a SHA-256 alongside it.
  CVELab imports nothing outside the standard library, so a download and a
  Python 3.11 interpreter are the whole installation.
- Upload tokens and `POST /api/runs`: a run on your own machine can file its
  report to your account. Create a token in the dashboard, set `CVELAB_TOKEN`,
  and the report is sent when the run finishes. Without a token nothing is
  sent; `--no-upload` suppresses it when one exists.
- `cvelab upload <CVE>` sends a lab that is already on disk, so a run that
  finished while the network was down is not lost. `--dry-run` prints what
  would be sent without sending it.
- A run report page at `/app/runs/<id>`, reachable only by the account that
  filed the run.
- Anthropic and OpenAI-compatible local model providers.
- Native Linux build and install bundle.
- Autonomous Linux CVE validation workflow.
- Vulnerable-only PoC generation when no public fix is identified.
- Closed-source HTTP reproduction workflow backed by a local artifact catalog.
- Inspectable manual PoC reproduction kit.

### Changed

- An upload carries the whole lab, the exploit included, because a shared
  entry nobody can run is worth little. `--no-poc` withholds the exploit and
  the plan; `--no-upload` sends nothing. (An earlier draft of this entry
  described the reverse, an `--upload-poc` flag, which was never released.)

### Fixed

- `DEEPSEEK_API_KEY` was never registered for redaction. The list of key
  variables was written out by hand and adding DeepSeek did not update it, so
  a key echoed back inside a provider error would have been written to
  `automation.json` in the clear. The list now comes from the provider
  registry, and the test that covers it does too — it named the same three
  variables and so agreed with the bug.
- An upload that named no provider returned 500 rather than being accepted:
  `runs.provider` is `NOT NULL` and the handler allowed a null through.

### Added (Phase 0)

- Apache-2.0 license, `NOTICE`, and trademark attribution for the CVE marks.
- `SECURITY.md` with a coordinated disclosure process and an explicit scope
  statement separating CVELab defects from the intentionally vulnerable
  services inside generated labs.
- `ACCEPTABLE_USE.md` defining authorized-use boundaries for a tool that
  produces working proofs of concept.
- `CONTRIBUTING.md` with a Developer Certificate of Origin sign-off
  requirement, and `CODE_OF_CONDUCT.md`.
- Continuous integration: lint, type check, and the unit test suite across
  Python 3.11 through 3.14 on Linux and Windows.
- CodeQL analysis and Dependabot updates for GitHub Actions.
- Release automation publishing signed artifacts to PyPI through Trusted
  Publishing, together with the Linux bundle and its checksums.
- Issue and pull request templates, including a dedicated template for
  reporting a CVE that failed to reproduce.
- Complete package metadata, plus `ruff`, `mypy`, and `pytest` configuration.
- Apache-2.0 licence headers on every Python and shell source file.
- A DCO workflow that fails a pull request when any commit lacks a
  `Signed-off-by` trailer.
- `cvelab --version`, which reports the installed version.
- `scripts/install-git-hooks.sh`, installing a pre-commit hook that blocks a
  commit adding provider API keys, AWS access keys, GitHub tokens or private
  keys, while leaving documentation placeholders alone.

- `cvelab doctor`, a read-only preflight over the interpreter, git, Docker,
  the Compose plugin, bash, the output directory and the provider, including
  a free model listing that catches a rejected key. Exit code 2 on failure.
- Token accounting for every provider call, reported on stderr and in
  `automation.json`, with a dated price table and the
  `CVELAB_PRICE_INPUT` / `CVELAB_PRICE_OUTPUT` overrides.
- Progress reporting from the operations that take minutes, on stderr so
  stdout stays pipeable, silenced by `--quiet` or `CVELAB_QUIET`.
- `benchmarks/`: a suite derived from OSV across six ecosystems, an unattended
  runner, and a report that prints every rate beside its denominator and lists
  every CVE that did not reproduce.
- `tests/test_no_per_cve_logic.py`, which fails if per-CVE handling returns to
  the shipped package.

### Removed

- The curated lab for CVE-2026-66788: a hardcoded commit pair, six handwritten
  templates and an `if cve == ...` branch on the default path. One identifier
  reproduced perfectly for reasons no other could share. The assets are a test
  fixture now, and 772 lines of per-CVE handling left the package.

### Security

- The provider key is registered once and redacted in `write_text`, which all
  generated-file writes pass through, and on stdout and stderr. Previously a
  provider error echoing the request would have written the key into
  `automation.json`, the file users attach to bug reports.

- DeepSeek as a first-class provider, with `DEEPSEEK_API_KEY`, its own
  pricing, `cvelab doctor` support and the dashboard accepting its keys.
- Source resolution from OSV before any paid model call, which resolves 37 of
  the 38 benchmark entries without a provider.
- `benchmarks/dry_run.py`, which measures the free half of the pipeline and
  prices a run without sending anything.

### Fixed

- The generated `manual.sh` syntax check invoked `bash` by bare name, so on
  Windows it reached the WSL launcher stub in `System32` — which `CreateProcess`
  searches before `PATH` — rather than the Git Bash that `shutil.which` finds.
  The stub exits 1 with a UTF-16 notice about having no installed distribution,
  failing the check on every Windows runner. The test now uses the resolved
  interpreter path, as `run_shipyard_script` already did, feeds the script on
  stdin as bytes, and reports both streams on failure instead of raising an
  opaque `CalledProcessError`.
- `cvelab.__version__` reported `0.1.0` while the package declared `0.6.0`.
  The attribute is now read from the installed package metadata, so the two
  cannot drift apart again.

### Changed

- Import ordering and a small number of lint findings were normalized across
  the package. No behavior changed.

[Unreleased]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.7...HEAD
[0.6.7]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.6...v0.6.7
[0.6.6]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.5...v0.6.6
[0.6.5]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/AndreiIonascu17/cvelab/releases/tag/v0.6.0
