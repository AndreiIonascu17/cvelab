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
- Git 2.30 or newer.
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

### Installation from one file

CVELab imports nothing outside the Python standard library. There is no
package to resolve, no virtual environment to create and no index to reach:

```bash
curl -LO https://cvelab.tech/cvelab.pyz
curl -LO https://cvelab.tech/cvelab.pyz.sha256
sha256sum -c cvelab.pyz.sha256

python3 cvelab.pyz doctor
```

Check the digest. It is the difference between running what was published
and running whatever answered.

Every command below works the same way: `python3 cvelab.pyz auto ...` where
the guide writes `cvelab auto ...`.

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
sha256sum --check cvelab-0.6.8-linux.tar.gz.sha256
tar -xzf cvelab-0.6.8-linux.tar.gz
cd cvelab-0.6.8-linux
./install.sh
```

The installer verifies the wheel's SHA-256 checksum and installs without `sudo` at:

```text
~/.local/share/cvelab/venv
~/.local/bin/cvelab
```

## 4. AI provider and API key

The recommended approach uses the masked prompt:

```bash
cvelab auto CVE-YYYY-NNNNN --ai on --provider openai --key --model YOUR_OPENAI_MODEL
```

When this appears:

```text
OpenAI API key:
```

enter only the API key. Do not enter the `cvelab` command again.

Alternatively:

```bash
export OPENAI_API_KEY="your-api-key"
export CVELAB_AI_PROVIDER="openai"
export CVELAB_MODEL="your-openai-model"
cvelab auto CVE-YYYY-NNNNN --ai on
```

Anthropic uses the same workflow:

```bash
export ANTHROPIC_API_KEY="your-api-key"
export CVELAB_AI_PROVIDER="anthropic"
export CVELAB_MODEL="your-anthropic-model"
cvelab auto CVE-YYYY-NNNNN --ai on
```

For a local OpenAI-compatible server, no API key is required by default:

```bash
export CVELAB_AI_PROVIDER="local"
export CVELAB_BASE_URL="http://127.0.0.1:11434/v1"
export CVELAB_MODEL="cvelab-qwen2.5-coder:7b"
cvelab auto CVE-YYYY-NNNNN --ai on
```

Source-generation prompts routinely need tens of thousands of tokens. For Ollama, create a
model with a 64K context instead of using its 4K default on GPUs below 24 GiB:

```text
FROM qwen2.5-coder:7b
PARAMETER num_ctx 65536
```

Save that text as `Modelfile`, then run:

```bash
ollama create cvelab-qwen2.5-coder:7b -f linux/ollama/Modelfile.qwen2.5-coder-7b
```

Local responses have a 30-minute timeout by default. Set `CVELAB_LOCAL_TIMEOUT` to a
different number of seconds when the model or hardware needs it.

Local endpoints do not supply web search. Provide exact `--repo`, `--vulnerable-ref`,
and `--fixed-ref` overrides when they are not already present in the CVE record.

Do not publish the key in Git, screenshots, shell history, or reports. Revoke
any exposed key immediately. `--key VALUE` works but prints a warning, because
other users of the machine can read it in the process list; prefer `--key` alone
or the environment variable.

A key is never sent over plain HTTP to another machine: a `--base-url` of
`http://` is accepted for `127.0.0.1`, `localhost` and `[::1]`, and for any host
when no key is configured (Ollama on a LAN, for example). Use `https://` for a
gateway that needs a key.

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

### Large fixes and complex CVEs

A fix that fits in one prompt is shown to the model whole. When it does not
(more than 90,000 characters of diff, or more than 24 changed files), CVELab
ranks the files by how well they match the CVE text, code before tests and
documentation, and adds a research phase before the lab is written. The model
reads an index of every changed file and asks for the source it needs: one
file's diff with whole functions around each change, a range of lines from
either revision, a literal search, or a directory listing. Any file in the
repository can be asked for, so the number of files a CVE needs is not limited
by what fits in one prompt. Every repair does the same with the failure in
front of it, which is how a missing build option or extension gets found.

Requests only read. They are answered from the source snapshots under
`source/` and from git in the lab's cache, and no path can leave them. The
model's analysis, its build notes and everything it read are saved in
`research.json` beside `plan.json`, and `plan.json` records how many rounds
and requests it took.

`--research on` researches every CVE, `--research off` never does, and `auto`
is the default described above; `CVELAB_RESEARCH` sets the default.
`CVELAB_RESEARCH_ROUNDS` (default 3) bounds the calls before a lab is written.
Research adds a few model calls per CVE, and they show in the cost.

When one commit fixes several CVEs, say which one you mean:

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --hint "the session upload-progress half of the fix, not the OOM tests under Zend/" \
  --key \
  --model gpt-5.6-sol
```

The hint goes to the model, ranks the fix's files, and is recorded in
`plan.json`, so a reviewer can see the run was steered.

A hosted model's prompt carries up to 320,000 characters of source context;
`CVELAB_CONTEXT_CHARS` raises it for a model with a larger window. An answer
cut off at its output budget is asked for again with twice the budget, up to
the provider's ceiling (`CVELAB_<PROVIDER>_MAX_OUTPUT` overrides it). A lab may
carry up to 80 files under `adapter/`, at any depth, and up to eight support
services.

## 6. Running an existing lab

```bash
cvelab --output-root "$HOME/cvelab-labs" run CVE-YYYY-NNNNN
```

Use `--keep` only when you want to inspect containers after validation:

```bash
cvelab --output-root "$HOME/cvelab-labs" run CVE-YYYY-NNNNN --keep
```

Normal cleanup is restricted to the lab's Compose project. Do not use
`docker system prune --volumes` for this workflow. The project is always named
after the lab directory, whatever `name:` the Compose file sets, so containers
kept with `--keep` are stopped with:

```bash
cd "$HOME/cvelab-labs/CVE-YYYY-NNNNN"
docker compose -p cve-yyyy-nnnnn -f docker-compose.yml down --volumes
```

A lab is untrusted input, whether a model generated it or someone sent it to
you. Before anything is built, `run` resolves `docker-compose.yml` with
`docker compose config` and refuses it unless every service stays on internal
networks, without host ports, mounts, devices, extra capabilities, privileged
mode, host namespaces, `env_file`, secrets or configs, and builds only from
inside the lab directory. `include` and `extends` are refused, and so is a
`${VARIABLE}` that the host environment would fill. The refusal names each
service and key. Docker is given only the environment variables it needs, not
your API keys or tokens.

While it runs, a service that sets no limit of its own is bounded at 2 GB of
memory, two CPUs and 1,024 processes. Change these with `CVELAB_RUNTIME_MEMORY`
(for example `4g`), `CVELAB_RUNTIME_CPUS` (for example `1.5`) and
`CVELAB_RUNTIME_PIDS`; an empty value removes that limit. The build is bounded
separately by `CVELAB_BUILD_MEMORY` (default `4g`).

A service with a healthcheck gets at least two minutes to come up
(`CVELAB_STARTUP_GRACE`, in seconds, 0 to 900; 0 leaves the lab's own
setting). Probes that fail during that time do not count, and a healthy answer
ends the wait at once. If the services still do not start, the run repairs the
startup on its own, from the container logs, up to twice
(`CVELAB_STARTUP_REPAIRS`, 0 to 5), without spending a validation attempt or a
repair meant for the exploit.

When the lab builds, starts and the validator reaches both services but the
effect does not show, the repair is given the validator's observations and the
end of each service's log first, and up to two repairs are added beyond the
budget (`CVELAB_EFFECT_REPAIRS`, 0 to 5). Tests the fix adds or changes are
shown ahead of the patch as the upstream statement of the input to start from.

Stopping a run with Ctrl+C, SIGTERM or SIGHUP, including closing the terminal,
stops the lab's containers before the process exits.

A few hand-curated labs set a `runner` in `plan.json` that runs the lab's own
script on the host, outside Docker. CVELab refuses it unless
`CVELAB_ALLOW_HOST_RUNNER=1` is set; read the script before setting it.

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

## 8. Sending a report to cvelab.tech

A run happens on your machine, with your provider key and your Docker. If you
want the history in one place rather than in a folder on one laptop, an
account at [cvelab.tech](https://cvelab.tech/app/) can hold the reports.

Create a token in the dashboard and export it:

```bash
export CVELAB_TOKEN=cvelab_...
cvelab auto CVE-2024-12345 --provider openai --model MODEL
```

The report is sent when the run finishes. What travels:

| | Sent |
|---|---|
| `REPORT.md`, `WALKTHROUGH.md`, `EVIDENCE.json`, `report.json`, `analysis.json` | yes |
| CVE, repository, fixed revision, model, token counts, cost | yes |
| `PoC.py`, `manual.sh`, `PoC.ps1`, `MANUAL-POC.md`, `plan.json` | yes, unless `--no-poc` |
| Your provider key | never |
| The source trees, the images, the containers | never |

**The exploit travels with the report.** A validated run becomes an entry in
a shared corpus that subscribers can open and run, and an entry without the
exploit is a description of a lab rather than a lab. `--no-poc` uploads the
report alone; the entry is kept, and marked as not runnable.

The key is not in the payload, and anything that looks like a registered
credential is replaced with `[REDACTED]` before the request is built. The
command prints what it is sending, including whether the exploit is in it,
before each upload.

Three ways to send nothing:

- Do not set a token. Without one the upload code is never reached.
- Pass `--no-upload` for a single run.
- Revoke the token in the dashboard. Reports already filed are kept.

A failed upload never fails a run. The lab stays on disk and goes up later:

```bash
cvelab upload CVE-2024-12345 --dry-run    # print what would be sent
cvelab upload CVE-2024-12345
```

Self-hosting the control plane: set `CVELAB_ENDPOINT` to its origin. It must
be `https://`; plain `http://` is accepted only for `localhost`, `127.0.0.1` or
`[::1]`, such as a local `wrangler dev`.

## 9. Manual reproduction

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

## 10. Closed-source software

```bash
cvelab closed-auto CVE-YYYY-NNNNN --key --model gpt-5.6-sol
```

For a proprietary product, CVELab continues only when the legally obtained
artifact is available locally and registered in `closed-catalog.json`. VirtualBox
can host the product, but the installation package, license, and vendor
configuration cannot be fabricated or downloaded by bypassing access controls.

## 11. Troubleshooting

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

### Compose policy refused this lab

The lab's `docker-compose.yml` asks Docker for something CVELab does not allow,
and each line of the message names the service and the key. During `auto` the
refusal is fed back to the next generation attempt. For a lab you wrote or
received, remove the key; if the word `include` or `extends` appears only in a
comment, reword the comment.

### The lab reproduced the wrong CVE

One commit sometimes fixes several CVEs, and a lab can demonstrate the half
the model found first. Read `research.json`: its analysis says which part of
the fix the model took to be this CVE. If that is wrong, run again with
`--hint` naming the right part, as in section 5.

### CVE API returned HTTP 404

CVE.org has no published record for the identifier. CVELab then reads
GitHub's reviewed advisory for it, which often exists days before the
record does. If GitHub has none either, the run stops after one attempt.
Check the identifier for a typo, or wait for the record: until it is
published, CVE.org reports the identifier as `RESERVED`.

```bash
curl -s https://cveawg.mitre.org/api/cve-id/CVE-YYYY-NNNNN
```

### Missing public fix

The absence of a fix is not an error if the vulnerable revision is verified.
The correct result is `VULNERABLE_ONLY_REPRODUCTION`.

### Missing vulnerable artifact

The correct result is `ARTIFACT_REQUIRED` or `POC_NOT_GENERATED`. Provide a
verifiable repository/revision or the required legal artifact; do not use a
simulation as a substitute.

## 12. Safety and limitations

- Run only on systems you own or are explicitly authorized to test.
- Keep services on loopback and internal Docker networks.
- Use nondestructive payloads.
- Do not point the validator at external targets.
- Do not confuse synthetic CWE labs with PoCs for the actual product.
- Do not treat the absence of a result after a timeout as the sole evidence of a fix.
- No generator can faithfully reproduce every CVE from its identifier alone.

## 13. Development

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
