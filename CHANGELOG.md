# Changelog

All notable changes to CVELab are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/AndreiIonascu17/cvelab/releases/tag/v0.6.0
