# CVELab Guide

This guide covers installing and running CVELab and interpreting its results.
The recommended platform is native Linux with Docker Engine and the Compose plugin.

## 1. What CVELab does

CVELab starts with a CVE identifier and attempts to:

1. Collect public metadata and references.
2. Identify the repository and vulnerable revision.
3. Identify the public fix, if one exists.
4. Build a local Docker lab.
5. Execute a vulnerability-specific validator.
6. Confirm an observable security effect.
7. Produce evidence, a walkthrough, and a report.

CVELab does not treat a reflected marker or a hardcoded field as a PoC. A result
is accepted only if the validator executes the test and observes the effect
defined in the PoC contract.

## 2. Possible outcomes

### SOURCE_REPRODUCTION

Public vulnerable and fixed revisions are available. The same test demonstrates
the vulnerability on the first revision and its rejection on the patched revision.

Expected indicators:

```json
{
  "ok": true,
  "real_poc_verified": true,
  "patched_tested": true,
  "differential_confirmed": true
}
```

### VULNERABLE_ONLY_REPRODUCTION

The vulnerable revision is public and verifiable, but no public fix commit has
been identified with sufficient confidence. CVELab does not fabricate a patched
service.

Expected indicators:

```json
{
  "ok": true,
  "real_poc_verified": true,
  "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
  "patched_tested": false,
  "differential_confirmed": false
}
```

This result demonstrates the vulnerability but does not validate remediation.

### ARTIFACT_REQUIRED

The vulnerable product is not publicly available or requires authentication,
entitlement, a license, firmware, or a specific hardware environment. CVELab does
not bypass these requirements or replace the product with a simulation.

### POC_NOT_GENERATED

Public data does not support a faithful reproduction. This outcome is preferable
to a fabricated PoC or one attributed to an unverified revision.

## 3. Recommended Linux installation

### Requirements

- Python 3.11 or newer.
- The Python `venv` module.
- Git.
- A running Docker Engine.
- The Docker Compose plugin.
- Internet access for public sources, images, and the API.
- User access to the Docker socket.

On Debian, Ubuntu, or Kali, common base package names are:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
```

Install Docker Engine from the official repository appropriate for your distribution:
[Docker Engine installation](https://docs.docker.com/engine/install/).

Verify the environment:

```bash
python3 --version
git --version
docker version
docker compose version
```

Membership in the `docker` group grants privileges equivalent to root access.
Use this configuration only on a controlled lab system.

### Installation from Git

```bash
git clone https://github.com/AndreiIonascu17/cvelab.git
cd cvelab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
cvelab --help
```

Keep the repository and labs on the Linux filesystem. Avoid running from a
mounted NTFS partition if build performance matters.

### Installation from a bundle

Build the bundle:

```bash
bash scripts/build-linux.sh
```

Install the resulting bundle:

```bash
cd dist-linux
sha256sum --check cvelab-0.5.0-linux.tar.gz.sha256
tar -xzf cvelab-0.5.0-linux.tar.gz
cd cvelab-0.5.0-linux
./install.sh
```

The installer verifies the wheel's SHA-256 checksum and installs without `sudo` at:

```text
~/.local/share/cvelab/venv
~/.local/bin/cvelab
```

## 4. API key

The recommended approach uses the masked prompt:

```bash
cvelab auto CVE-YYYY-NNNNN --ai on --key --model gpt-5.6-sol
```

When this appears:

```text
OpenAI API key:
```

enter only the API key. Do not enter the `cvelab` command again.

Alternatively:

```bash
export OPENAI_API_KEY="your-api-key"
export CVELAB_MODEL="gpt-5.6-sol"
cvelab auto CVE-YYYY-NNNNN --ai on
```

Do not publish the key in Git, screenshots, shell history, or reports. Revoke
any exposed key immediately.

## 5. End-to-end execution

Main command:

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --ai on \
  --key \
  --model gpt-5.6-sol
```

This command performs discovery, generation, building, startup, validation, and reporting.

If the references are already known:

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --repo https://github.com/owner/project.git \
  --vulnerable-ref VULNERABLE_COMMIT \
  --fixed-ref FIX_COMMIT \
  --ai on \
  --key \
  --model gpt-5.6-sol
```

Without a public fix, omit `--fixed-ref`:

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --repo https://github.com/owner/project.git \
  --vulnerable-ref VULNERABLE_COMMIT \
  --ai on \
  --key \
  --model gpt-5.6-sol
```

## 6. Running an existing lab

```bash
cvelab --output-root "$HOME/cvelab-labs" run CVE-YYYY-NNNNN
```

Use `--keep` only when you want to inspect containers after validation:

```bash
cvelab --output-root "$HOME/cvelab-labs" run CVE-YYYY-NNNNN --keep
```

Normal cleanup is restricted to the lab's Compose project. Do not use
`docker system prune --volumes` for this workflow.

## 7. Deliverables

Results are written to:

```text
$HOME/cvelab-labs/CVE-YYYY-NNNNN/
```

Key files:

- `report.json`: the automatic verdict and PoC checks.
- `e2e/result.json`: the E2E profile result, if present.
- `validator/validator.py`: the generated executable validator.
- `artifacts/EVIDENCE.json`: structured evidence and provenance.
- `artifacts/WALKTHROUGH.md`: manual reproduction instructions.
- `artifacts/REPORT.md`: the technical report and limitations.
- `plan.json`: the lab type, revisions, and exploit contract.
- `docker-compose.yml`: lab services.
- `source/`: the source snapshots used.

The main verdict is `real_poc_verified`. For a test with a fix,
`differential_confirmed` must also be true. For a test without a fix, the report
must retain `patched_tested: false`.

## 8. Manual reproduction

Open `artifacts/WALKTHROUGH.md` and follow the commands documented there.
The walkthrough must specify:

- How to start the vulnerable version.
- The exact PoC request or action.
- The expected security effect.
- Where to inspect the evidence.
- How to clean up.
- Patched steps, only if a public fix has been validated.

If the walkthrough does not allow manual reproduction of the effect, the result
is not a complete PoC deliverable.

## 9. Closed-source software

```bash
cvelab closed-auto CVE-YYYY-NNNNN --key --model gpt-5.6-sol
```

For a proprietary product, CVELab continues only when the legally obtained
artifact is available locally and registered in `closed-catalog.json`. VirtualBox
can host the product, but the installation package, license, and vendor
configuration cannot be fabricated or downloaded by bypassing access controls.

## 10. Troubleshooting

### Docker does not respond

```bash
systemctl status docker
docker info
docker compose version
```

On native Linux, fix Docker Engine at the system level. CVELab does not
automatically modify the daemon or perform a factory reset.

### Docker permission denied

Check socket permissions and system policy:

```bash
ls -l /var/run/docker.sock
id
```

### Incomplete AI adapter

The generator performs preflight checks for `docker-compose.yml`, Dockerfiles,
and the validator. An incomplete adapter is rejected before the build.

### Missing public fix

The absence of a fix is not an error if the vulnerable revision is verified.
The correct result is `VULNERABLE_ONLY_REPRODUCTION`.

### Missing vulnerable artifact

The correct result is `ARTIFACT_REQUIRED` or `POC_NOT_GENERATED`. Provide a
verifiable repository/revision or the required legal artifact; do not use a
simulation as a substitute.

## 11. Safety and limitations

- Run only on systems you own or are explicitly authorized to test.
- Keep services on loopback and internal Docker networks.
- Use nondestructive payloads.
- Do not point the validator at external targets.
- Do not confuse synthetic CWE labs with PoCs for the actual product.
- Do not treat the absence of a result after a timeout as the sole evidence of a fix.
- No generator can faithfully reproduce every CVE from its identifier alone.

## 12. Development

Linux build:

```bash
bash scripts/build-linux.sh
```

Quick checks:

```bash
python3 -m compileall -q cvelab
bash -n linux/install.sh
bash -n scripts/build-linux.sh
```

Build artifacts are created in `dist-linux/` and are not tracked in version control.
