# Security Policy

CVELab builds and executes proofs of concept for known vulnerabilities. This
document covers vulnerabilities **in CVELab itself**, not the vulnerabilities
that CVELab reproduces.

## Supported versions

Only the latest released version receives security fixes. CVELab is
pre-1.0 and does not maintain release branches.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Report privately through GitHub Security Advisories:

<https://github.com/AndreiIonascu17/cvelab/security/advisories/new>

If you cannot use GitHub Security Advisories, email contact@syncbitsoft.com
instead. Do not open a public issue, pull request, or discussion for a
security report.

Please include the CVELab version, the operating system and Docker version, the
command you ran, the observed behavior, and a minimal reproduction. A generated
lab directory is useful, but remove any API keys before attaching it.

### Response targets

| Stage | Target |
| --- | --- |
| Acknowledgement | 3 working days |
| Initial assessment | 10 working days |
| Fix or mitigation plan | 30 days for high severity |

These are targets for a volunteer-maintained project, not contractual
commitments.

## In scope

A report is in scope when a defect in CVELab causes harm the user did not ask
for. Examples:

- A generated adapter escapes the Docker sandbox, reaches the host filesystem,
  or obtains host network access despite the `internal: true` lab network.
- The provider API key is written to disk, logged, embedded in a generated
  artifact, or transmitted anywhere other than the configured provider.
- Path traversal or arbitrary file write through a generated file path,
  bypassing the `ALLOWED_GENERATED` allowlist.
- Command injection through CVE identifiers, repository URLs, Git references,
  catalog entries, or model output.
- A bypass of the `FORBIDDEN` adapter checks that allows privileged containers,
  Docker socket mounts, host networking, added capabilities, or outbound
  callbacks.
- Lab cleanup removing containers, volumes, images, or files outside the lab
  it owns.
- Supply chain weaknesses in the release pipeline, installer, or published
  artifacts.

## Out of scope

- **Vulnerabilities inside generated labs.** Lab services are deliberately
  vulnerable; that is the product working as designed.
- The behavior of the CVE being reproduced, and the correctness of upstream
  vendor patches.
- Vulnerabilities in Docker, Python, Git, model providers, or any upstream
  project CVELab invokes. Report those to their maintainers.
- A model producing an inaccurate, incomplete, or non-working adapter. That is
  a quality issue; open a normal issue.
- Results that depend on running CVELab as root, with a modified safety
  allowlist, or on a host that already grants containers privileged access.

## Disclosure

Coordinated disclosure. Once a fix is released, the advisory is published with
credit to the reporter unless anonymity is requested. There is no bug bounty.
