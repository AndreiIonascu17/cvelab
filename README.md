# cvelab

`cvelab` creates local-only, source-backed labs for defensive CVE research. The
MVP supports CWE-22, CWE-78, CWE-89, CWE-284, CWE-434, and CWE-918.

Generated source labs contain vulnerable and patched revisions. Validation succeeds
only when an actual security effect is observed on the vulnerable revision and
blocked by the patched revision. A marker may be used as a harmless canary, but
marker reflection alone never qualifies as a PoC.

## Important distinction

`build` emits `SYNTHETIC_CLASS_LAB`, which demonstrates the vulnerability class.
`source` emits `SOURCE_REPRODUCTION` from real vulnerable and fixed source
revisions. A source lab is not considered reproduced until `run` confirms the
differential result.

## Setup

```powershell
cd "C:\OffSec Lab\cvelab"
& "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" -m pip install -e .
```

Docker Desktop must be running.

Configure credentials once so day-to-day use requires only the CVE identifier:

```powershell
$env:OPENAI_API_KEY = "your-new-key"
$env:CVELAB_MODEL = "gpt-5.6-sol"
```

## One-command automatic workflow

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts\cvelab.exe" auto CVE-YYYY-NNNN
```

`auto` is strict: it attempts a real `SOURCE_REPRODUCTION` and writes PoC
deliverables only after executing the vulnerable code path and observing the
declared security effect against real source revisions. If sufficient
source provenance cannot be resolved, it returns `POC_NOT_GENERATED`. It does not
fabricate a patched variant or silently fall back to a synthetic CWE lab.

Curated CVEs with an upstream deployment profile use `END_TO_END_REPRODUCTION`.
For CVE-2026-66788 this creates two disposable `kind` clusters through the
upstream Shipyard workflow, runs the crafted object from a compromised spoke
through the real Lighthouse agent and Broker, observes injection into the peer
`kube-system` namespace, and repeats against the fixed revision. The source-level
Go test is not accepted as the final PoC for this profile.

After successful validation it writes:

- `artifacts/PoC.py`
- `artifacts/WALKTHROUGH.md`
- `artifacts/REPORT.md`
- `artifacts/report.json`

## Build and validate

```powershell
./cvelab.ps1 all CVE-2026-16286 --cwe CWE-434 --ai off
```

When the CVE record exposes a supported CWE, omit the override:

```powershell
./cvelab.ps1 all CVE-2026-16286
```

Generated artifacts are written under `generated-labs/<CVE>/`.

## Generate a PoC when no public PoC exists

When the CVE references include a GitHub or GitLab fixing commit, `source`
discovers it automatically, checks out the fix and its parent, asks the model to
create the Docker adapter and marker-only validator, and writes an unvalidated
source lab:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts\cvelab.exe" source CVE-YYYY-NNNN --key --model gpt-5.6-sol
& "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts\cvelab.exe" run CVE-YYYY-NNNN
```

Pentru generare si validare end-to-end intr-o singura comanda:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts\cvelab.exe" source-all CVE-YYYY-NNNN --key --model gpt-5.6-sol
```

If the CVE record does not identify the fixing commit, provide it explicitly:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts\cvelab.exe" source CVE-YYYY-NNNN `
  --repo https://github.com/owner/project.git --fixed-ref FIX_COMMIT `
  --key --model gpt-5.6-sol
```

`--vulnerable-ref` is optional and defaults to the parent of `--fixed-ref`.
If no public source and fixed revision can be resolved, the command returns
`ARTIFACT_REQUIRED`; proprietary products require a user-supplied legal artifact
rather than a fabricated reproduction.

## Optional OpenAI planning

Recommended: enter the key through a masked prompt. It is kept only in process
memory and is not written to generated artifacts.

```powershell
./cvelab.ps1 build CVE-2026-16286 --ai on --key --model gpt-5
```

Direct value form is also accepted, but can remain in PowerShell history:

```powershell
./cvelab.ps1 build CVE-2026-16286 --ai on --key "sk-..." --model gpt-5
```

Environment variables remain supported:

```powershell
$env:OPENAI_API_KEY = "..."
$env:CVELAB_MODEL = "your-enabled-model"
./cvelab.ps1 build CVE-2026-16286 --ai on
```

The API is used only when deterministic metadata is insufficient. The model
receives the normalized CVE dossier and returns strict JSON. It cannot invoke
Docker or shell commands. Never put the API key in a Dockerfile, Compose file,
generated lab, or repository.

## Safety boundaries

- Services bind only to `127.0.0.1`.
- Runtime traffic stays on an internal Docker network.
- Payloads use non-destructive canaries and avoid shells, persistence, and credential access.
- Containers use unprivileged users, resource limits, and `no-new-privileges`.
- The validator has no option for remote targets.
- Source adapters are rejected if they request host networking, host ports,
  host mounts, privileged mode, extra capabilities, or the Docker socket.
