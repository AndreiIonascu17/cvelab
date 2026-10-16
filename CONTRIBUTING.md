# Contributing to CVELab

Thanks for considering a contribution. This document covers how to set up a
development environment, what the project accepts, and the sign-off every
commit needs.

## Developer Certificate of Origin

CVELab uses the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a contributor licence agreement. Every commit must carry a
`Signed-off-by` trailer with your real name and email:

```bash
git commit -s -m "Describe the change"
```

The trailer certifies that you wrote the contribution, or have the right to
submit it, and that you agree to license it under the Apache License,
Version 2.0. Pull requests with unsigned commits cannot be merged.

## Development setup

```bash
git clone https://github.com/AndreiIonascu17/cvelab.git
cd cvelab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Install the local pre-commit hook once:

```bash
bash scripts/install-git-hooks.sh
```

It refuses a commit that adds something shaped like a provider API key, an AWS
access key, a GitHub token or a private key. Documentation placeholders such as
`OPENAI_API_KEY=YOUR_KEY` do not trip it. This repository is private, where
GitHub secret scanning with push protection requires a Code Security licence,
so the check runs locally instead.

CVELab has **no runtime dependencies** and only uses the Python standard
library. Keep it that way: a pull request that adds a runtime dependency needs
a strong justification, because the zero-dependency install is a deliberate
design property of a tool that runs in security-sensitive environments.

## Licence headers

Every new `.py` and `.sh` file carries the Apache-2.0 header used throughout
the tree. Copy it from any existing source file. Do not change the copyright
line; contributions are licensed to the project, not assigned away from you.

## Checks

Run all three before opening a pull request:

```bash
ruff check cvelab tests
mypy cvelab
pytest -q
```

`ruff` and `pytest` must pass. `mypy` is currently advisory: the package has a
known backlog of type errors, and CI reports them without failing. Do not add
new ones.

### Tests that need Docker

Unit tests must not touch Docker, the network, or a model provider. Anything
that does belongs behind a marker:

```python
@pytest.mark.docker
def test_something_that_builds_a_lab() -> None:
    ...
```

Those tests are excluded from the default run and execute in the nightly
end-to-end workflow.

## What the project accepts

Useful contributions, roughly in order of value:

- A CVE that fails to reproduce, reported with the full `automation.json`.
  This is the most valuable thing you can contribute.
- Fixes to adapter generation, repair prompts, or validation logic.
- Support for additional runner profiles and ecosystems.
- Hardening of the sandbox and of the generated-file allowlist.
- Documentation, especially troubleshooting for real failures you hit.

## What the project does not accept

- Weaponized exploits, payloads intended to cause damage, persistence
  mechanisms, or command-and-control functionality.
- Changes that weaken the sandbox: relaxing `ALLOWED_GENERATED`, removing
  entries from `FORBIDDEN`, allowing privileged containers, host networking,
  Docker socket mounts, or outbound network access from lab services.
- Artifacts obtained in violation of a vendor licence, or code that bypasses
  vendor authentication or entitlement checks.
- Proof-of-concept code for a vulnerability with no public CVE record, or for
  one still under coordinated disclosure.
- Hardcoded per-CVE logic on the default code path. Curated fixtures belong in
  tests, clearly labeled as fixtures.

## Pull requests

- One logical change per pull request.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Add or update tests for behavior you change.
- Describe how you verified the change. For adapter-generation changes, name
  the CVEs you ran it against and the outcome.
- Keep the existing documentation voice: plain, technical, no marketing
  language and no emoji.

## Reporting security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
