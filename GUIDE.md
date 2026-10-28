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

### PROVIDER_DECLINED

The model provider declined the request under its own usage policy. This is
the provider's decision, not a fault in the lab or in CVELab, and the run stops
at once: the same request asked again gets the same answer, so it is neither
retried nor reworded. The result names the provider and the model and carries
the provider's explanation. You may rerun with another provider you have
configured. A declined run is uploaded as declined, not as failed.

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

### Pointing the resolver at the fix

A product advisory names a patched release and withholds the endpoint, so a
resolver reading only that prose answers `UNSUPPORTED` and is right to. The fix
commit is usually public even where the report behind it is not, and it names
the field, the authorization it restored, and often the test that exercises it:

```bash
cvelab closed-auto CVE-YYYY-NNNNN \
  --repo https://gitlab.com/owner/project.git \
  --fixed-ref FIX_COMMIT \
  --key --model gpt-5.6-sol
```

The two options name one patch together, so pass both or neither. Without them,
a commit the CVE record itself names is used. The patch is sent beside the
record with the advisory's prose outranked, and it is read as reference material
only -- it is a third-party diff, so nothing written inside it directs the run.

The patch does not relieve the image requirement: the vulnerable tag must still
be a published image inside the affected range. `resolution.json` records where
the patch came from, not the patch, since the diff is public anyway and a copy
would travel with every uploaded report.

### The fixture a product-class attack needs

A product rarely ships the state its own vulnerability needs. An access-control
flaw in a collaboration tool is reachable only once a project, an item and a
private comment exist, and creating them is authenticated work the unauthenticated
attack is not allowed to do. A contract declares that state as a fixture:

```json
"fixture": {
  "command": ["app-console", "run", "/cvelab/fixture/seed.script"],
  "files": { "seed.script": "create project cvelab-canary --public\n" },
  "env": { "CVELAB_MARKER": "cvelab-canary-7f2a91" },
  "timeout": 600
}
```

The files are copied into `/cvelab/fixture` inside each container and the command
runs there, once the image answers its health path and before the first attack
request. `command` is an argv list, never a shell string, and a file name is a
single name rather than a path. See `examples/closed-contract-fixture.example.json`.

Three things to know:

- A fixture that exits non-zero aborts the run. An unseeded instance discloses
  nothing, which is indistinguishable from a fixed one, so a fixture that failed
  quietly would report a differential that was never measured. Have it assert
  what it built: if the contract attacks item `1`, the fixture should refuse to
  pass when it created item `4`.
- `env` and `files` travel inside the contract, and the contract ships with the
  lab. Put a marker there, not a credential.
- A product that migrates a database on first boot needs longer than the default
  two minutes to answer its health path; raise `health_timeout` (up to 1800).
  It may also need more than the default 2 GB ceiling, which is
  `CVELAB_RUNTIME_MEMORY`, not a contract key.

## 10a. Field PoC: one target you own

The source and closed modes prove a vulnerability inside Docker, by a
differential between two revisions or two images. Their PoC never leaves that
harness: it is the validator, bound to the service names `vulnerable` and
`patched`, and refuses a remote target by construction. That answers "does this
bug reproduce"; it does not hand you something to run against a server to show a
client the bug happening.

The field mode emits that artifact. The deliverable is a standalone
`field-poc.py` that takes `--target`, runs against one server you are permitted
to test, in one run, and shows the effect rather than printing a version
verdict:

```bash
cvelab --output-root out field CVE-YYYY-NNNNN \
  --vulnerable-image vendor/app:vulnerable \
  --fixed-image vendor/app:fixed \
  --container-port 8080 --health-path /health \
  --spec field-spec.json
# then, from out/CVE-YYYY-NNNNN/artifacts:
python3 field-poc.py --target 10.0.0.5:8080 --show-bodies
```

`--target` is one host and port, however you write it: `10.0.0.5:8080`,
`[2001:db8::1]:8443`, `app.example.com` or `https://app.example.com`. Without a
scheme the script assumes `http`, except on port 443. Every request path comes
from the spec, so the target carries none, and a target with a path is refused
rather than silently ignored. Without `--show-bodies` a disclosed value is cut
at 120 characters; with it, it prints in full.

The script names the target and the effect on stderr before it sends anything,
so a run against the wrong host is visible rather than silent. Point it only at
a host the engagement covers.

Its proof does not need a second server. It is an effect a fixed build cannot
produce, observed on the one target, and CVELab confirms that before handing
the script over: the script must observe the effect on the vulnerable image and
must stay silent on the fixed one. A script that fires on both is observing
normal behavior, not the bug, and is refused.

Two strategies carry the effect without a listener you have to stand up:

- `inband_differential` reads the same resource two ways in one request round,
  the vulnerable path and the path that authorizes correctly, and reports what
  only the vulnerable path returned. The proof is per-target and needs no
  marker: a value the vulnerable path returned and the authorized one withheld
  was disclosed to someone who should not have it.
- `marker_roundtrip` sends a unique marker through the vulnerable vector and
  observes it surface where it should not. The marker is fresh each run, so a
  reflection left by an earlier run is never counted.

A spec names the strategy, the effect in words, and the requests; it never names
a host. See `examples/field-spec.example.json`.

### The usual shape: one response that should not exist

Most authorization and disclosure findings need no comparison at all. The
evidence is that the request the weakness allows came back with something, and
that a fixed build does not produce it. That is `direct_observation`:

```json
{"strategy": "direct_observation",
 "observable_effect": "an admin route answering 200 to an unauthenticated requester",
 "probe":  [{"method": "GET", "path": "/admin/secret"}],
 "expect": {"status": 200}}
```

`expect` is one of `{"status": 200}`, `{"header": "X-Report-Token"}`,
`{"body_contains": "root:x:0:0"}` or `{"extract": {...}}`.

Reach for this before `inband_differential`. Comparing an unauthenticated read
against a correctly authorized one looks right and is not: on the vulnerable
build both see the data, so the difference is empty, and on the fixed build the
difference is the `401` the probe got and the control did not -- the proof fires
on the patched side. Use `inband_differential` only when the authorized reading
genuinely withholds part of what the weakness returns, such as a field that a
different query shape hides.

### Values only you have

A control request often needs a credential the lab never knew. Declare it, and
the script asks you for it:

```json
{"inputs": ["credential"],
 "probe": [{"method": "GET", "path": "/r",
            "headers": {"Authorization": "Bearer {{credential}}"}}]}
```

```bash
python3 Manual-PoC.py --target 10.0.0.5:8080 --input credential=...
```

A missing value is refused before the first request, rather than sending
`{{credential}}` literally and reporting a clean target. Inputs are filled in
at substitution time and never join the context, so what you pass does not
appear in the output or in a recorded finding.

### An effect that sends nothing back

`oob_callback` is for a blind effect: an injection, a fetch of a URL you
supply, a command whose output goes nowhere. There is no answer to read, so the
evidence is the target reaching out. The script listens itself, and the probe
places both `{{callback}}` and `{{marker}}`, the marker inside the callback:

```json
{"strategy": "oob_callback",
 "observable_effect": "the server fetches a URL the caller supplied",
 "probe": [{"method": "POST", "path": "/fetch",
            "body": "{\"url\": \"http://{{callback}}/{{marker}}\"}"}]}
```

A run counts only when something arrives carrying that run's marker; without it
an unrelated request, or a payload an earlier run left stored, would read as a
result. Anything that connects is recorded, HTTP or not.

Across a network the target cannot reach the port the script bound, so say how
it can: `--callback 203.0.113.9:8000` goes into the payload while
`--callback-bind 0.0.0.0:8000` is what the script listens on. The bound address
is the default and is right only when the target reaches it directly -- which
is the case inside the lab, where the proving sidecar shares the target
container's network namespace. `--callback-wait` bounds the wait after the probe.

Nothing is sent to a third-party collaborator service. On a client engagement
that would route their traffic through infrastructure neither of you controls.

### Sessions: SSH and SMB

A protocol with a real handshake cannot be written as bytes to send -- SSH
negotiates keys, SMB negotiates a dialect -- so a library speaks it and a
message is an operation:

```json
{"strategy": "direct_observation", "transport": "ssh",
 "observable_effect": "a payroll file read by an account that should not read it",
 "inputs": ["user", "password"],
 "auth": {"username": "{{user}}", "password": "{{password}}"},
 "probe":  [{"exec": "cat /srv/payroll.csv"}],
 "expect": {"body_contains": "INTERNAL-"}}
```

Over `ssh` a message is `{"exec": "..."}` and the sequence returns the output.
Over `smb` it is `{"op": "list_shares"}`, `{"op": "list_path", "share": ...,
"path": ...}` or `{"op": "read", "share": ..., "path": ...}`; a path may not
climb out of its share and a read is capped. Both authenticate through `auth`,
whose values come from `inputs`, so the credential is yours and never the
spec's. `--target 10.0.0.5` is enough: port 22 and 445 are assumed.

**What these reach is access, and what an authenticated session is permitted to
do** -- a file an account should not read, a share that should not be exported,
a restricted shell that can be escaped, an injection in something the service
runs for you. They are not a way to attack the handshake. The library performs
it correctly on purpose, and a flaw in a protocol implementation itself is not
something this expresses.

A protocol refusal is an answer, not a broken run: a share that is gone is
exactly what a fixed build says, so it is recorded and the run ends
`NOT_OBSERVED`. A session that cannot be established at all, or credentials
refused, stops the run instead -- that answers nothing about the weakness.

These two need a library, which the delivered script will tell you how to
install, and the proof inside the lab needs it in the sidecar. A lab's network
is `internal: true`, so nothing can be fetched once the sidecar is in it: the
image is prepared beforehand, and CVELab asks you first.

```
  build      cvelab/protocol-sidecar:paramiko
  from       python:3.13-alpine
  installing paramiko>=3.4
             downloaded from PyPI by pip, inside that image

Type yes to build it:
```

Nothing is installed on your machine outside Docker and none of it needs root.
`--yes` agrees in advance; without a terminal and without it, the run stops
rather than treating silence as consent. The image is built once and reused.
Your own copy comes from `pip install 'cvelab[ssh]'`, `[smb]` or
`[protocols]`; CVELab's core keeps no runtime dependencies.

### Services that do not speak HTTP

`transport` picks how the script talks to the target: `http` by default, or
`tcp` and `tls` for a service with its own protocol -- a cache, a queue, a
database, a daemon with a text protocol. A socket message is `send` (text, and
where `{{marker}}` goes) or `send_hex` (even-length hex, for framing that is
not text), with an optional `read_until` naming the reply delimiter:

```json
{"strategy": "marker_roundtrip", "transport": "tcp",
 "observable_effect": "a value an unauthenticated client stored and read back",
 "probe":   [{"send": "SET k {{marker}}\r\n", "read_until": "\r\n"}],
 "observe": [{"send": "GET k\r\n", "read_until": "\r\n"}]}
```

The target is then a bare `--target 10.0.0.5:6379`; a URL is refused. A whole
sequence shares one connection, so a protocol that needs a login or a handshake
command first is expressed by putting it earlier in the same list, and what the
sequence returns is everything read during it. Sending nothing and only reading
takes a banner. `--read-timeout` bounds how long a quiet socket is waited on;
`read_until` ends a read at once and is better whenever the protocol allows it.

Only the standard library is used, because the delivered script has to run on
the operator's machine with nothing installed. That is also the boundary: a
protocol needing a real handshake -- SSH, SMB, a TLS-wrapped negotiation --
cannot be written as bytes to send, and is out of scope rather than a reason to
take on a dependency. `discover` is HTTP-only and a socket spec carrying one is
refused rather than silently skipped.

A spec can also discover its own targets instead of naming them. A check's
`discover` chain enumerates them from the target -- public projects, then the
items in each -- binding a name per step that the probe and control fill in with
`{{name}}`. One `field-poc.py` then sweeps every target it finds, so the same
script works against any instance rather than the objects a fixture happened to
create. A spec with several `checks` runs each independently and reports them
together.

### What the field mode will not do

A class whose effect is not observable on a live target over the wire has no
field PoC: a memory over-read that only crashes a worker, a race, a timing
signal. The mode declines such a spec rather than emit a script that prints a
verdict it never observed. And `NOT_OBSERVED` on a real target is not proof of a
patch -- a differential strategy also returns it when the instance simply had
nothing to disclose. To decide affected vs fixed regardless of data, check the
build.

## 10b. The same deliverable from a source lab

`cvelab field` needs a pair of published images, which is what a closed product
ships. A source lab has no equivalent: it builds its two revisions itself. For
one of those, ask for the script separately, once the lab has been validated:

```bash
cvelab manual-poc out/CVE-YYYY-NNNNN \
  --spec spec.json --container-port 8000
# then, from out/CVE-YYYY-NNNNN/artifacts:
python3 Manual-PoC.py --target 10.0.0.5:8080 --show-bodies
```

`--spec` is optional. Without it CVELab asks for one itself, in a call of its
own, and writes the script if it proves -- so `cvelab manual-poc out/CVE-...`
on its own is the whole thing. Pass `--spec` when you disagree with the answer
it gave, or when you know something the lab does not: a credential, a tenant
id, the one route that matters.

Generating labs and demonstrating one on a server are separate jobs, so
`run`, `auto`, `source-all` and `all` do **not** do this. A batch run gives you
the labs and their `PoC.py`, and nothing else. Pass `--manual-poc` to those
commands if you do want it inline; the answer then lands in `report.json` under
`manual_poc_field`, and `--manual-poc-provider` sends just that call elsewhere.

Either way "not observable on one instance" is the expected answer for most
vulnerabilities. The spec shape is the one `cvelab field` takes -- strategy,
the effect in words, the requests, never a host. `--container-port` is the port
the service listens on inside its container and is required with `--spec`;
otherwise it is read from the lab's own healthcheck or from the drafted answer.

### What you get

`Manual-PoC.py` is a single file that runs the way a published PoC does:

```bash
python3 Manual-PoC.py 10.0.0.5:8080 --show-bodies
```

Its header names the CVE, the effect, the affected and fixed package versions
the lab installed, the fix commit, the strategy, any `--input` it needs, and
that CVELab proved it against a build before and after the fix. The spec it
sends is embedded as readable JSON, so every request can be read -- and edited
-- before it is run. It needs nothing installed beyond Python.

CVELab's half is the proof. It brings up the lab's two builds, runs that exact
script against each from a sidecar joined to the container's network namespace,
and writes it only if it observed the effect on the vulnerable revision and
stayed silent on the fixed one. A script that fires on both is watching normal
behaviour rather than the bug; one that crashed observed nothing because it
never looked. Neither is handed over, and the run that refused your spec is
kept in `artifacts/Manual-PoC.json` so you can see what to change.

This is a command of its own, so it cannot cost a lab anything: the lab's status
and its own deliverables are untouched whatever happens here, and you can ask
for the script on any lab you already have, including one someone else built. A
lab that never reproduced is refused -- it has no demonstrated effect to hand
over -- and so is one with no fixed build to go silent against, because half the
proof would be missing. `Manual-PoC.py`, `Manual-PoC.md` and `Manual-PoC.json`
stay local; none of them is uploaded with the lab.

### Rehearsing it against the lab

A lab is sealed: its network is `internal: true` and it publishes no port, so
you cannot point the script at it from your own machine. To rehearse the run
before it touches anyone else's server:

```bash
cvelab demo-target up out/CVE-YYYY-NNNNN     # prints a host and port
cvelab demo-target down out/CVE-YYYY-NNNNN   # puts the lab back
```

`up` starts only the vulnerable build -- the differential is the lab's job and
is already done -- and lifts `internal` from the lab's networks for that one
run, through an override written outside the lab directory. While it is up, the
lab is reachable from your host, which is a posture the lab is otherwise built
to prevent, so `down` it when you are finished.

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
