## What this changes

<!-- One paragraph. Link the issue it closes. -->

## Why

<!-- The problem this solves. -->

## How it was verified

<!--
Commands you ran and their result. For changes to adapter generation, name the
CVEs you tested against and the outcome for each.
-->

## Checklist

- [ ] Every commit is signed off (`git commit -s`), per [CONTRIBUTING.md](../CONTRIBUTING.md).
- [ ] `ruff check cvelab tests` passes.
- [ ] `pytest` passes.
- [ ] `mypy cvelab` reports no new errors.
- [ ] Tests were added or updated for the changed behavior.
- [ ] `CHANGELOG.md` is updated under `## [Unreleased]`.
- [ ] No runtime dependency was added.
- [ ] The sandbox was not weakened (`ALLOWED_GENERATED`, `FORBIDDEN`, network isolation, container limits).
- [ ] No per-CVE logic was hardcoded on the default code path.
