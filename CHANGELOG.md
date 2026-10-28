# Changelog

All notable changes to CVELab are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `cvelab manual-poc <lab-dir> --spec spec.json --container-port N` writes
  `Manual-PoC.py` beside the `PoC.py` that validates the lab. It takes
  `--target host:port` and runs against one server the operator is permitted
  to test, to demonstrate impact rather than compare two builds. The spec is
  the operator's, in the shape `cvelab field` already accepts: the strategy,
  the effect to observe, and the requests that produce it, never a host. It is
  a separate command, so a lab's own run is untouched and the script can be
  asked for on any lab already generated and validated, including one built by
  someone else. CVELab writes it only after running that exact script against
  the lab's own two revisions, from a sidecar joined to each container's
  network namespace: it must observe the effect on the vulnerable revision and
  stay silent on the fixed one, so a script that fires on both is watching
  normal behaviour rather than the bug, and one that crashed observed nothing
  because it never looked. Neither is handed over, and the run that refused
  the spec is kept in `Manual-PoC.json` so it can be fixed. A lab that never
  reproduced, and one with no fixed build to stay silent against, are refused.
  `Manual-PoC.md` travels beside the script; none of the three is uploaded
  with the lab. Most vulnerabilities cannot be shown this way at all -- an
  effect that needs no listener, a crash, a race or a timing signal.

- `direct_observation`, a strategy for the shape most authorization and
  disclosure findings actually have: the effect is in the one response the
  weakness lets you ask for, with no second reading to compare against. It
  takes `probe` and `expect`, one of `status`, `header`, `body_contains` or
  `extract`. This was measured rather than reasoned. Asked to prove a token
  leaking in a response header, and a route answering 200 where it should
  answer 401, `inband_differential` found nothing on the vulnerable build --
  an authorized control legitimately sees the data, so the difference is
  empty -- and on the fixed build it found the 401 the probe got and the
  control did not, firing on the patched side. The proof gate caught that and
  handed nothing over, which is what it is for, but the shape needed its own
  strategy.

- `extract` reads more than bodies: `header` for a value in a response header
  and `status` for the status code, alongside `json_values` and `regex`. Two
  of the five labs measured on the previous release were unprovable for this
  reason alone and neither had anything to do with their CVE.

- `inputs`, values the lab cannot know and the operator supplies at run time:
  a test account's credential, a tenant id. A spec declares the names, a
  request fills one in as `{{name}}`, and the script takes
  `--input NAME=VALUE` and refuses to start when one is missing rather than
  sending `{{credential}}` literally and reporting a clean target. They are
  merged at substitution time and never join the context, so a credential
  cannot reach a printout or a recorded finding.

- `ssh` and `smb` transports, for protocols whose handshake cannot be written
  as bytes to send. A message is an operation -- `{"exec": "..."}` over SSH,
  `list_shares`, `list_path` or `read` over SMB -- and both authenticate
  through `auth`, whose values come from `inputs`, so a credential is the
  operator's and never the spec's. A bare `--target 10.0.0.5` assumes port 22
  or 445. What they reach is access and what an authenticated session is
  permitted to do: a file an account should not read, a share that should not
  be exported, a restricted shell that can be escaped. They are not a way to
  attack the handshake, which the library performs correctly on purpose.
  A protocol refusal is treated as an answer rather than a broken run, because
  a share that is gone is exactly what a fixed build says; a session that
  cannot be established, or credentials refused, still stops the run, since
  neither answers anything about the weakness.

- Those two need a library, so `pip install 'cvelab[ssh]'`, `[smb]` or
  `[protocols]` declare it and CVELab's core keeps no runtime dependencies of
  its own. Proving the script inside a lab needs it in the sidecar, and a
  lab's network is `internal: true`, so nothing can be fetched once the
  sidecar has joined it: the image is prepared beforehand, tagged by what is
  in it, built once and reused. CVELab asks first, printing exactly what would
  be installed and where, and `--yes` agrees in advance; without a terminal
  and without it the run stops rather than treating silence as consent.
  Nothing is installed outside Docker and none of it needs root.

- The proof step can supply the operator's `inputs`, which it could not
  before: a spec that declared one could never be proved, because the sidecar
  ran the script without it and the script rightly refused to start. They
  travel as one JSON environment value rather than in the sidecar's command
  line, and a spec whose inputs were not given is refused before anything is
  built rather than failing as an absent effect.

- `oob_callback`, the third strategy, for an effect that sends nothing back: a
  blind injection, a blind fetch of a URL the caller supplies, a command whose
  output goes nowhere. It was named in the spec vocabulary but refused,
  because it needs a listener. The script now starts its own, substitutes
  `{{callback}}` for where it can be reached, and counts a run only when
  something arrives carrying that run's `{{marker}}` -- without which an
  unrelated request, or a payload an earlier run left stored, would read as a
  result. It listens rather than using a third-party collaborator service,
  which on a client engagement would route their traffic through
  infrastructure neither party controls. Anything that connects is recorded,
  HTTP or not, since a payload may reach out with something else. Across a
  network the operator says how the target reaches them with `--callback`;
  the bound address is the default and is right only when the target can
  reach it directly, which is the case inside the lab, where the proving
  sidecar shares the target container's network namespace.

- A single-target spec can carry `transport`: `http`, or `tcp` and `tls` for a
  service that speaks its own protocol over a socket -- a cache, a queue, a
  database, a daemon with a text protocol. HTTP was the only transport
  because the spec vocabulary was taken from one web disclosure, not because
  the proof needed it: the sidecar, the two builds and the
  effect-here-silence-there bar were always transport-blind. A socket message
  is `send` (text, carrying `{{marker}}`) or `send_hex` (even-length hex, for
  framing that is not text) with an optional `read_until`, and a whole
  sequence shares one connection, so a protocol that needs a login before a
  command can be expressed. What a sequence returns is everything read during
  it. Only the standard library is used, because the delivered script has to
  run on the operator's machine with nothing installed -- which is also the
  boundary: a protocol needing a real handshake, SSH or SMB, cannot be written
  as bytes to send and is out of scope rather than a reason to take a
  dependency. `discover` stays HTTP-only and is refused for a socket spec
  rather than silently skipped. Existing specs are unchanged: `transport`
  defaults to `http`, and `observe` still accepts a single request.

- `Manual-PoC.py` is handed over the way a published single-file PoC is. The
  target is positional, `python3 Manual-PoC.py 10.0.0.5:8080`, with `--target`
  still accepted; the header names the CVE, the effect, the affected and fixed
  package versions the lab installed, the fix commit, the strategy, any
  `--input` it needs, and that CVELab proved it against a build before and
  after the fix. What the run leaves on the target is now described for the
  strategy in use instead of for all of them: a read-only script said a marker
  roundtrip's footprint was its own.

- `cvelab manual-poc <lab-dir>` no longer needs `--spec`. Without one it asks
  for a spec itself, in a call of its own, so the dedicated command does the
  whole job. The draft call is also given what the lab already knew and was
  being refused for want of: the port, read from the lab's own healthcheck,
  and the validator that proved the effect, which holds the exact requests and
  the response shape a prose contract leaves out. With those, a draft that had
  been declined for having to guess at the extraction produced a spec that
  proved on the first attempt.

- The post-validation call is off by default on `run`, `auto`, `source-all`
  and `all`, and asked for with `--manual-poc`. Generating labs and
  demonstrating one on a server are separate jobs: a batch run wants the labs
  and their `PoC.py`, and the single-target script is a deliberate step taken
  for one engagement.

- A lab that reproduces is now asked, in one separate call, whether the effect
  it confirmed can also be observed on a single running instance -- and if it
  can, the script is drafted, proved and written without being asked for. The
  call happens after the lab's verdict is recorded and settled, which is the
  whole point: asking for the same thing inside the generation prompt cost two
  of three labs a `PROVIDER_DECLINED`, while here a decline costs one small
  call and the lab stands. It is on by default for `run`, `auto`, `source-all`
  and `all`, skipped with `--no-manual-poc`, and can be pointed at another
  provider with `--manual-poc-provider`, because lab generation and this
  request are judged separately under each provider's policy. The answer is
  recorded in `report.json` under `manual_poc_field` and never enters the
  lab's proof checks, so it cannot change a status. "Not observable on one
  instance" is the expected answer for most vulnerabilities and the model is
  told to prefer it over a guess.

- `cvelab demo-target up <lab-dir>` starts a lab's vulnerable build where the
  host can reach it and prints the host and port to point at, so a
  single-target script can be rehearsed end to end before it is pointed at
  anyone else's server; `down` puts the lab back. A lab is sealed -- its
  network is `internal: true` and it publishes no port -- and in that state
  neither a published port nor the container's own address answers from the
  host, so the command lifts `internal` for that one run through an override
  written outside the lab directory and never named
  `docker-compose.override.yml`, which Compose would load by name on every
  later run of the lab. The fixed build is never started.

### Changed

- The single-target scripts, `field-poc.py` and `Manual-PoC.py`, no longer
  take `--authorized`. The flag verified nothing and anyone could pass it;
  running the script is the operator's own statement that they may test the
  host. Both still name the target and the effect on stderr before the first
  request, so a run against the wrong host is visible in the output and in
  whatever captured it, and `--show-bodies` is documented for what it does:
  print each disclosed value in full instead of its first 120 characters.

- `PROVIDER_DECLINED`, an outcome of its own for a run the model provider
  declined under its usage policy. It used to end as `AUTO_GENERATION_FAILED`
  and count as a failure of the tool. The run stops at once, without retrying
  or rewording the request, names the provider and the model, keeps the
  provider's explanation, and is uploaded as declined. Refusals are now
  recognised from OpenAI and Chat Completions providers too, not only from
  Anthropic.
- `closed-auto` reads the fix behind the CVE, not only the advisory. A
  product advisory names a patched release and withholds the endpoint, so
  the resolver answered `UNSUPPORTED` with nothing to work from; the fix
  commit is public even where the report behind it is not, and it names the
  field, the authorization it restored and often the test that exercises
  it. `--repo` with `--fixed-ref` points at that commit, and a commit the
  CVE record itself names is used otherwise. The patch is sent beside the
  record with the advisory's prose explicitly outranked, and read as
  reference material only -- a third-party diff from a public host, never a
  source of instructions. The image requirement is unchanged: a vulnerable
  tag must still be published and in the affected range. On CVE-2026-85529
  this moved the answer from `UNSUPPORTED` to `ARTIFACT_REQUIRED`, naming
  the GraphQL field and published tags either side of the fix.
  `resolution.json` records where the patch came from, not the patch.
- A closed-software contract can declare the state its vulnerability needs
  as a `fixture`: an argv list, named files copied into `/cvelab/fixture`,
  and an environment the contract carries. It runs once the image answers
  its health path and before the first attack request. A product rarely
  ships the state its own vulnerability needs -- the GraphQL field behind
  CVE-2026-85529 discloses a private comment only once a project, a work
  item and that comment exist -- and creating it is authenticated work the
  unauthenticated attack is not allowed to do, so the contract used to
  answer with nothing to disclose and the run looked like a fixed build. A
  fixture that exits non-zero aborts the run, because an unseeded instance
  discloses nothing and that is indistinguishable from a patched one. The
  readiness deadline is a contract key for the same reason: two minutes
  covers an application server binding a port, not a product migrating a
  database on first boot. Measured on the GitLab images: ready after 31
  seconds warm and 101 cold, with the fixture itself taking 18.
- `PoC.py` evaluates the contract's own predicate and prints one verdict,
  `REPRODUCED` or `BLOCKED`, and the runner executes it against each variant
  expecting the verdict that variant should produce. The reproduction the
  runner performed and the script a reviewer was handed used to be two
  different programs, and only the first ever ran; `ok` now requires both.
  The sidecar joins the lab container's network namespace instead of the lab
  publishing a port, so `127.0.0.1` reaches the product and nothing is
  exposed to the host.
- A `field` lab mode that emits a single-target PoC the operator runs against
  their own server, in one run, showing the effect rather than a version
  verdict. CVELab proves the script against a vulnerable and a fixed image --
  it must observe the effect on the first and stay silent on the second -- then
  hands it over; a script that fires on both is refused. Two listener-free
  strategies: `inband_differential` (read a resource the vulnerable and the
  authorized way, report the gap) and `marker_roundtrip` (a fresh marker sent
  through the vector and observed where it should not surface). Classes whose
  effect is not observable over the wire are declined rather than faked.
  A spec can carry several `checks`, and each check can `discover` its own
  targets from the instance -- enumerate public objects, bind an id per
  step, fill it into the probe -- so one emitted script sweeps every target
  it finds instead of the objects a fixture created.
  `--target` takes one host and port in whatever form an engagement names it:
  `10.0.0.5:8080`, `[2001:db8::1]:8443`, a bare hostname, or a full URL. A
  scheme is optional, `http` is assumed without one and `https` on port 443,
  and a target carrying a path is refused rather than quietly ignored, since
  every request path comes from the spec. `--authorized` is still required on
  every run.

### Changed

- A lab that builds and starts but does not show the effect is the most
  common failure now, and its repair was working blind: a successful run kept
  no service logs, and the validator's observations sat deep in a long report.
  The repair now gets a digest first, with the failed proof checks, what each
  revision answered and the end of each service's log, plus a hint to settle
  whether the input reached the fixed code before changing the observation.
  Such a run gets up to two repairs beyond the budget (`CVELAB_EFFECT_REPAIRS`).
- Tests the fix adds or changes are shown in a section of their own, ahead of
  the patch, as the project's statement of the input to start from. They used
  to sit inside the patch, or after the code when the patch was cut.
- The rule that builds use the source snapshots now names the published
  release pair as its exception, in generation and repair alike; the
  exception used to appear only further down in the input.

### Fixed

- A bodyless request made the emitted `field-poc.py` die on import with
  `NameError: null`, against every target, before sending anything: the spec
  was pasted in as a Python literal and `null` is not a Python name. It now
  travels as JSON text. Only a spec whose every request carried a body ever
  ran.
- A field PoC that crashed against the fixed image counted as silence, so the
  lab was stored as `REAL_FIELD_POC_VALIDATED` on the strength of a run that
  never looked. A verdict now counts only from a run that finished and said
  `OBSERVED` or `NOT_OBSERVED`, and `script_ran_on_both` is a proof check of
  its own.
- A discovered value containing a quote or a backslash was substituted into
  the serialized request raw, so it broke the request or moved a neighbouring
  field. Values are escaped as JSON before they are filled in.
- One busy object crowded every other discovered target out of the run: the
  cap was applied to a flat list of children, so a project with more items
  than the cap left the rest untested and the sweep reported a clean target.
  The cap now takes a share from each parent, and says when it truncates.
- A discovery that found nothing sent the probe anyway, carrying the
  unreplaced `{{name}}` in the request, and read the empty result as a clean
  target. It is now reported as nothing to test.
- A `match` predicate other than `body_contains` validated and was then
  ignored, so a spec asking for a regex got a bare marker check. It is now a
  spec error.


- A validator that built its target URL printf-style, `"http://%s:%d" %
  (target, port)`, was refused as reaching an external host named `%s`. An
  f-string placeholder was already treated as a variable; a printf one now
  is too, and a literal external host is still refused.
- A lab whose services were slow to start was declared unhealthy before it
  listened, and the run spent a validation attempt and a repair on what was
  never an exploit failure. A health-checked service now gets a start period
  of at least two minutes (`CVELAB_STARTUP_GRACE`), and a run whose services
  still do not start is repaired from the container logs on its own, up to
  twice (`CVELAB_STARTUP_REPAIRS`), without spending either. In the latest
  nginx batch, three of four labs lost their first validation this way.
- A commit fetched by id is asked for with `--depth=2` from a repository
  built aside and moved into place, so a cache entry that exists always
  holds the commit. Cleaning up only on a git error left an init-only
  repository behind whenever the fetch was interrupted, and every later run
  took it as cached, so that fix could never be read again.
- A CVE record naming a commit on a self-hosted GitLab -- gitlab.gnome.org,
  salsa.debian.org -- aborted the scan of the reference list, so
  `closed-auto` stopped before planning and a usable github.com reference
  further down was never reached. An unsupported host is skipped instead.
- A commit id written in uppercase failed the exact-id check and fell
  through to a blobless clone of the whole repository, which the
  single-commit fetch exists to avoid.
- `--repo` or `--fixed-ref` passed alone gave the resolver nothing and was
  dropped in silence, with the record's own commit used instead; the two
  name one patch together now. A fix the operator supplied that git rejects
  is an error rather than a step message, which `--quiet` hid.
- A contract carrying a fixture reached docker as a single argument over the
  128 KiB Linux allows, so the run raised `argument list too long` after the
  fixture and the attack had both finished, with no report written. The
  script is sent the attack alone -- the fixture has already run inside the
  container -- and a contract still too large is refused before the build.
- A run that raised partway left the previous run's `ok: true` and validated
  status on disk beside the new inputs, and `cvelab upload` offered them as
  this run's result. The verdict files are dropped when a run starts.
- A closed lab uploaded as a validated run could not be run by whoever
  downloaded it: `PoC.py` reads the attack from `contract.json` beside it,
  which was not among the shared documents. It travels with the exploit now.
- A fixture failed on any image declaring a non-root `USER`, because the
  directory it copies into could not be created. The directory is made as
  the container's own uid 0; the copy and the fixture command still run as
  the image's user.
- Without a fixed image the run reported `patched_blocked: false` beside a
  validated status, contradicting its own rule that every proof check must
  pass. There is no differential to confirm, so the check is not claimed.

## [0.6.8] - 2026-10-24

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

[Unreleased]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.8...HEAD
[0.6.8]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.7...v0.6.8
[0.6.7]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.6...v0.6.7
[0.6.6]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.5...v0.6.6
[0.6.5]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/AndreiIonascu17/cvelab/releases/tag/v0.6.0
