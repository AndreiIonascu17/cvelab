# CVELab

`cvelab` generates and runs local labs for reproducible validation of vulnerabilities described by a CVE. The user supplies a CVE identifier, and the application attempts to resolve public sources, build the environment, execute a safe proof of concept (PoC), and produce evidence, a walkthrough, and a report.

The generator does not treat a reflected marker alone as proof. A successful result must demonstrate the vulnerability's effect on the actual vulnerable artifact.

## Documentation

- [Complete installation and usage guide](GUIDE.md)
- [Linux bundle and installation](linux/README.md)

Native Linux is the recommended platform. Windows remains supported through Docker Desktop or the Docker Engine fallback in Kali WSL.

## Possible outcomes

- `SOURCE_REPRODUCTION`: both vulnerable and fixed versions are reproduced; the test succeeds against the vulnerable version and is blocked by the patched version.
- `VULNERABLE_ONLY_REPRODUCTION`: the vulnerable version is validated, but no public fix can be identified. A patched version is not fabricated.
- `CLOSED_SOURCE_REPRODUCTION`: uses only a legally obtained proprietary artifact registered locally.
- `ARTIFACT_REQUIRED`: the source code, image, or binary needed for a faithful reproduction is missing.
- `POC_NOT_GENERATED`: the available information is insufficient for real, verifiable proof.

## Requirements

- Linux or Windows 10/11.
- Python 3.11 or newer.
- Docker Engine on Linux or Docker Desktop on Windows.
- Git available in `PATH`.
- Bash, Make, and curl for E2E profiles that use Shipyard/Kind.
- WSL with a Kali distribution is required for Shipyard only on Windows.
- An OpenAI API key and a compatible model for automatic adapter generation.
- Legal access to the product and any required license for closed-source software.

## Installation

On Kali/Debian:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose python3-venv git make curl
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker

cd cvelab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
cvelab --help
```

On Windows, from PowerShell:

```powershell
cd "C:\OffSec Lab\cvelab"
py -m pip install .
cvelab --help
```

If the Python scripts directory is not in `PATH`:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts\cvelab.exe" --help
```

## Quick start

The recommended command for an open-source CVE on Linux is:

```bash
cvelab --output-root "$PWD/generated-labs" auto CVE-YYYY-NNNNN --ai on --key --model gpt-5.6-sol
```

On Windows:

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" auto CVE-YYYY-NNNNN --ai on --key --model gpt-5.6-sol
```

The `--key` option without a value opens the masked `OpenAI API key:` prompt. The key is not written to the project or included in the command line.

Example:

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" auto CVE-2026-47342 --ai on --key --model gpt-5.6-sol
```

The `auto` workflow:

1. Collects public CVE metadata.
2. Identifies the repository and vulnerable revision.
3. Identifies the public fix, if available.
4. Obtains the required source snapshots.
5. Generates a product-specific adapter.
6. Validates the adapter's structure before running Docker.
7. Builds and starts the local lab.
8. Executes the PoC and verifies the actual effect.
9. Automatically runs the manual PoC actions (`exploit` and `verify`) against each variant as well.
10. If the build, startup, or proof fails, captures logs, regenerates the adapter based on
    the observed cause, and repeats validation (up to 4 attempts by default).
11. Writes the evidence, walkthrough, and final report only after validation.

No intervention is required between attempts. To change the maximum number of attempts:

```bash
cvelab --output-root "$PWD/generated-labs" auto CVE-YYYY-NNNNN \
  --key --model gpt-5.6-sol --max-attempts 6
```

The history of generation, errors, repairs, and validation is saved in
`generated-labs/CVE-YYYY-NNNNN/automation.json`.

## CVEs with a public fix

When both the vulnerable version and the fix are available, the expected result is differential:

```json
{
  "ok": true,
  "real_poc_verified": true,
  "patched_tested": true,
  "differential_confirmed": true
}
```

This means the same test case demonstrated the effect on the vulnerable version and its absence on the fixed version.

References can be provided explicitly:

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" auto CVE-YYYY-NNNNN `
  --repo https://github.com/owner/project.git `
  --vulnerable-ref <vulnerable-commit> `
  --fixed-ref <fix-commit> `
  --ai on --key --model gpt-5.6-sol
```

## CVEs without a public fix

The same `auto` command can produce a real PoC against only the vulnerable version when vulnerable source code is available but no fix has been published or identified. The generator does not unnecessarily require `--fixed-ref` or create a synthetic patched service.

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" auto CVE-YYYY-NNNNN `
  --repo https://github.com/owner/project.git `
  --vulnerable-ref <vulnerable-commit> `
  --ai on --key --model gpt-5.6-sol
```

A successful result without a fix indicates:

```json
{
  "ok": true,
  "real_poc_verified": true,
  "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
  "patched_tested": false,
  "differential_confirmed": false
}
```

This is a proof of the vulnerability, but it does not validate remediation. The report retains this limitation and does not claim that a fixed version exists.

## Main commands

| Command | Purpose |
| --- | --- |
| `auto` | Resolves information, builds the lab, runs the PoC, and produces deliverables. |
| `run` | Runs a previously generated lab again. |
| `source` | Generates a source-level lab using explicit Git references. |
| `source-all` | Generates and runs the source-level lab. |
| `build` | Generates a CWE-class lab; this is not a real product PoC. |
| `all` | Generates and runs the CWE-class lab. |
| `closed-auto` | Resolves requirements for a closed-source product and uses a registered local artifact. |
| `closed` | Builds the closed-source reproduction from the catalog. |

Run an existing lab again:

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" run CVE-YYYY-NNNNN
```

Generate a source-level lab explicitly:

```powershell
cvelab source CVE-YYYY-NNNNN `
  --repo https://github.com/owner/project.git `
  --vulnerable-ref <vulnerable-commit> `
  --fixed-ref <fix-commit> `
  --ai on --key --model gpt-5.6-sol
```

Generate and run in a single command:

```powershell
cvelab source-all CVE-YYYY-NNNNN `
  --repo https://github.com/owner/project.git `
  --vulnerable-ref <vulnerable-commit> `
  --fixed-ref <fix-commit> `
  --ai on --key --model gpt-5.6-sol
```

## Deliverables

A validated lab is created in:

```text
generated-labs/<CVE>/
```

Key files:

- `e2e/result.json`: the verifiable result and reproduction statuses.
- `e2e/`: the product-specific E2E runner and probes, if used by the profile.
- `validator/validator.py`: the executable PoC/validator for the generated adapter.
- `artifacts/PoC.py` (or the profile-specific payload): the inspectable local PoC.
- `artifacts/manual.sh`: the Linux runner with separate `setup`, `exploit`, `verify`, and `cleanup` actions.
- `artifacts/MANUAL-POC.md`: manual reproduction instructions.
- `artifacts/EVIDENCE.json`: structured evidence and provenance.
- `artifacts/WALKTHROUGH.md`: manual reproduction steps.
- `artifacts/REPORT.md`: the technical report, limitations, and conclusion.
- `docker-compose.yml`: the local Docker lab topology.
- `source/`: the Git snapshots used by the lab.

For manual reproduction, follow `artifacts/WALKTHROUGH.md`. An accepted PoC must include the exact command or request, the observable effect, and the verification method. An `ok: true` field alone is insufficient without supporting evidence in the result.

On Kali/Linux, after a successful `auto` run:

```bash
cd generated-labs/CVE-YYYY-NNNNN/artifacts
bash manual.sh setup vulnerable
bash manual.sh exploit vulnerable
bash manual.sh verify vulnerable
bash manual.sh cleanup
```

For a CVE with a public fix, repeat the same steps with `patched`; the expected verdict is
`BLOCKED`. For `VULNERABLE_ONLY_REPRODUCTION`, the `patched` variant is not offered.

Every report uses the same contract and includes the fidelity level, vendor components
executed, simulated components, raw vulnerable/patched evidence, the probe contract, and
provenance. `source_component` does not mean product E2E; only
`product_end_to_end` together with `product_e2e_verified: true` confirms that level.

## Closed-source software

```powershell
cvelab closed-auto CVE-YYYY-NNNNN --key --model gpt-5.6-sol
```

If the product requires authentication, entitlement, or a license, the application stops with `ARTIFACT_REQUIRED`. After legally obtaining the image or installation package, register the artifact once in `closed-catalog.json`, then the command can continue.

The generator does not bypass vendor authentication, download pirated software, or substitute a synthetic simulation for the real product.

## API key and model

Recommended approach:

```powershell
cvelab auto CVE-YYYY-NNNNN --ai on --key --model gpt-5.6-sol
```

Alternatively:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:CVELAB_MODEL = "gpt-5.6-sol"
cvelab auto CVE-YYYY-NNNNN --ai on
```

Do not put the key in files, commits, screenshots, or public examples. If a key is exposed, revoke and replace it.

## Docker Desktop on Windows

Before running `auto` or `run`, Docker must respond:

```powershell
docker version
docker context show
docker info
```

If Shipyard fails while pushing to `localhost:5000` with `EOF` or `connection reset`,
check temporarily without a VPN. Some VPN policies block Docker daemon access to
published ports and bridge subnets, even when the registry is healthy between
containers. Retry the test only after `curl http://127.0.0.1:5000/v2/` can
reach a local registry published by Docker.

The runner handles known transient Docker context and Docker Desktop socket errors. If the Docker Desktop backend shuts down completely, the lab cannot continue until the engine is available again.

Errors such as `Dockerfile.vulnerable: no such file or directory` should be detected during preflight. An incomplete AI adapter is rejected rather than partially launched.

Cleanup removes only the current lab's resources. The project does not use `docker system prune --volumes` for normal cleanup.

## Docker Engine on Linux

The Shipyard runner is launched directly through Bash and uses the current user's
Docker Engine. WSL, Docker Desktop, and separate host installations of `kubectl`, Kind,
or Helm are not required; the profile's Kubernetes tools are provided by the Shipyard
environment. Verify with:

```bash
docker version
docker compose version
docker info
```

## Limitations

- No generator can faithfully reproduce every CVE from its identifier alone.
- A CVE without public vulnerable code or a legally available artifact remains `ARTIFACT_REQUIRED` or `POC_NOT_GENERATED`.
- The absence of a public fix does not prevent a PoC against the vulnerable version, but it prevents differential validation of remediation.
- A guessed repository or commit is not accepted as provenance.
- AI generates the adapter, but the result is accepted only after executable verification of the effect.
- Synthetic CWE-class labs are demonstrations, not PoCs for the product named by the CVE.

## Safety

- Labs are intended for authorized research.
- Generated services are restricted to loopback and the internal Docker network.
- Payloads must be nondestructive.
- Do not scan or attack external targets.
- Any test on a system you do not own requires explicit authorization.
