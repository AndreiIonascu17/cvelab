# Changelog

All notable changes to CVELab are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-11-15

### Added (interactive sessions through the PoC)

- **A generated `PoC.py` can now hold an interactive session on the target.**
  `python3 PoC.py <address> --shell --allow-shell` opens a shell on the address
  and runs the lines you type in it one after another, so state is real and it
  is on the target: a variable you export, a `cd`, a key you unlock on one line
  is still there on the next. It exists only because the lab's own weakness
  carries it, so it proves what that weakness proves and nothing about reaching
  the host any other way.
- The session is a poll and not a terminal over a socket, and the product stays
  up while a line runs. The line is written in one request and read back in
  short ones from the operator's end, so a slow line does not hold the target's
  single-threaded product for its duration: a `sleep 6` line answered 59 of 59
  health probes, where waiting on the target instead took it down for about six
  seconds. What that costs is latency and a ceiling -- past about twelve seconds
  a line is reported unfinished, though it may still be running there.
- Holding it writes two files on the target and leaves a detached process until
  you leave. Leaving tears that down -- the held shell is killed and both files
  removed -- and the two paths are printed before the first line and again at
  teardown, so they can be audited.
- Each line's output is bracketed by a one-use random marker the held shell is
  asked to echo. The marker is made when the file runs and is never written into
  it, so the emitted text stays a pure function of its inputs; its halves ride
  the wire apart and only the target joining them proves the shell answered
  rather than the product repeating the bytes it was sent.
- `python3 PoC.py <address> --prompt --allow-prompt` is the line-by-line form
  beside it: one command per line, nothing held between them.
- Both are offered for exactly the labs that can carry them -- a published port
  and a validator that reads a command as its second positional -- and the
  artifact's header, its first-use banner and `LAB-POC.md` all say which case a
  lab is and why.

### Changed (the one artifact, and what it is called)

- `PoC.py` takes **one positional address** and `--lab-address` is gone. Which
  of the two programs the argument reaches is the lab's own standing and not
  anything about the address: a proved remote mode spends it there, a published
  port hands it to the lab program, neither refuses with the recorded reason.
- Where a lab has no proved remote mode the route it sends is a constant in the
  validator, so a negative verdict against another host is a finding about that
  route. The file now prints that next to the verdict and gives the sentence to
  report instead, because "not affected" is a claim such a run cannot carry.
- **`--shell` is now the session and `--prompt` is the line-by-line form.** What
  shipped before as `--shell` held nothing open, so it took the name of what it
  is; `--allow-shell` and `--allow-prompt` follow, as does
  `CVELAB_POC_PROMPT_PARENT`. No old spelling is accepted.
- A lab's standing has six answers rather than four -- shipped, refused, not
  proved, not reproduced, not requested, no record -- decided in one place, so
  the artifact, the delivered document and `report.json` cannot disagree.
- `GUIDE.md`'s invocation table gains a row for the prompt and one for the
  session. They are invocations of the same lab program, so "one script, two
  modes" still holds.

### Removed

- **The connect-back session**, about 2600 lines that never once reached disk:
  no archived run had ever recorded one, its two gate conditions cannot both
  hold by construction, a lab build cannot reach a listener on the generating
  host, and its payloads ran the shell in the foreground and froze the delivery
  for the life of the session.
- **Seven subcommands that were extra doors onto `auto`** -- `build`, `all`,
  `source`, `source-all`, `run`, `field` and `demo-target` -- none of which
  touched code `auto` does not. Six remain: `auto`, `manual`, `closed`,
  `closed-auto`, `upload`, `doctor`.
- The synthetic class lab path, which no archived lab had ever used.

### Fixed (telling our own failure from the finding's limit)

- A recorded refusal is no longer presented as the vulnerability's own limit
  when it was CVELab's script that failed. Eleven archived labs whose script
  could not tell the two builds apart, and forty-two whose lab never reproduced,
  are now said to be exactly that.
- A validator that mentions `sys.argv` only as `sys.argv[0]` -- the name it was
  invoked as, not an argument -- is refused, and told which of the two mistakes
  it made.
- A `cd` that does not take is said and left untracked. It used to advance the
  remembered directory without asking the target, so every later line went out
  prefixed with a directory that was never entered and came back empty in
  silence.
- A line the target's own shell refuses -- a syntax error, a first word that
  reads as a flag -- is no longer reported as a route that never answered or a
  weakness that did not reproduce. The file sends one probe of its own to the
  same address and says which of the two happened.
- The prompt no longer promises that only stdout comes back: where a command
  fails hard enough to throw, the target's own complaint returns inside the
  failure the product reports.
- A patched build may report a blocked attack by exiting non-zero, which one
  archived lab had been losing a clean run to.


### Added

- A generated lab's `PoC.py` now runs the way a published PoC does:
  `python3 PoC.py 10.0.0.5:8080`, and where the weakness is command execution,
  `python3 PoC.py 10.0.0.5:8080 id`, whose output it prints. Given an address it
  holds one session for the whole run and performs the lab's declared setup
  steps itself. With no argument it behaves exactly as before -- the same
  environment variables, the same Compose service names, the same output and the
  same exit codes -- which is the path automatic validation takes. `manual.sh`
  gains an `address` action and publishes the build's port on loopback with the
  host side left for the kernel to assign; `setup` prints the assigned address
  and the line that uses it.

  Measured, and the reason it exists: `artifacts/PoC.py` is
  `validator/validator.py` with a six-line docstring prepended and nothing else
  changed -- across 89 archived labs `diff` prints `0a1,6` and stops. So the
  artifact the kit calls the manual PoC was the validator's own source, copied
  out to be read. None of the 89 read `sys.argv`, every one addressed its target
  by Compose service name, and no lab published a host port, so there was
  nothing on the host to point anything at. A tester carrying these to a client
  had a script they could read and could not run.

- `exploit_contract.service_port`: the port the product listens on inside its
  container, declared by the answer rather than recovered from the lab. There
  was no reliable source for it -- a healthcheck string in 53% of archived labs,
  `expose` in 15%, a `PORT = N` constant in 15%, and
  `exploit_contract.setup_port` in 2%, that last one only where the lab declares
  seeding and meaning the port the seeding goes to. An answer without it, or one
  whose two ports disagree, is refused before anything is built. A lab generated
  before the field existed publishes nothing and its guide says so, rather than
  describing a script it does not contain.

- `service_crash` and `timing_differential`, two strategies for the effects the
  manual PoC could not express. A crash, a panic or a hang is shown by asking
  an ordinary question, sending the input that kills the service, and asking
  again: answering before and not after is the finding, and a payload that
  merely returns an error is reported as no crash, because an answer means the
  service is still serving. An algorithmic blowup is shown by timing the
  pathological input against ordinary input of the same shape, medians over
  several measurements, counting only when the payload is both slow outright
  and far slower than its control.

  Measured, and the reason both exist: of ten CVEs in one batch, five
  reproduced and **none** shipped a script. Two were panics whose draft refused
  with "a crash signal rather than an answer"; one was a blowup it called
  unobservable from outside the process. The vocabulary had no way to say
  either, so the model was refusing correctly and the gap was ours.

- A library's route is an input, not a refusal. Nobody runs a library; they run
  an application that calls it, and the route reaching the vulnerable code
  belongs to that application. A probe path may now be a substitution naming an
  input, so the lab's own adapter route stands in while the script is proved
  and the operator passes `--input target_path=/their/route` to run it. Four of
  the five refusals above said some version of "a stock instance has no such
  route". The payload -- the part the lab proved, and the part that matters --
  is the same bytes wherever the library is called from.

- `--allow-disruption`, without which a `service_crash` script does nothing.
  Every other strategy asks no more of a target than an ordinary request; this
  one is expected to leave the service not answering, so the acknowledgement is
  required rather than assumed, and a run without it is refused rather than
  reported as nothing found. The script header, the generated guide and the
  refusal itself all say it causes an outage.

- `fidelity.trigger_source`, which says whether what the lab triggers is what
  the evidence says triggers the weakness. Every other field in that record
  says what the lab runs, and none said that: a route written to produce the
  weakness's precondition on demand reaches the same symptom without going
  near the weakness, and a fixed build driven the same way reaches it too, so
  the symptom is recorded as the effect and the lab reads as a reproduction.
  Across the 577 archived labs, three of the 674 distinct fidelity prose
  strings say in so many words that the lab does not reproduce the weakness --
  a route that reaches the fault condition directly rather than through the
  context the advisory names, an adapter standing in for the listener the
  weakness lives in, a fixed-side check that "is not reached" -- and all three
  shipped as reproductions. The sentence was in the record and nothing read it.

  `substituted` is a passing answer: it ships, it names the substitute among
  the simulated components, and it may not claim `product_end_to_end`.
  Refusing the substitution outright would teach the next answer to stop
  writing the disclaimer, and that prose is the only reason the defect was
  visible. What is refused is the one answer that cannot be true --
  `documented` asserted over prose that disclaims the reproduction -- which
  costs one model call and no build. The marker travels into `plan.json` and
  `report.json`, so a later step reads "reproduced the documented trigger" and
  "reached the same condition another way" apart instead of inferring one from
  the other.

### Changed (one PoC)

- The two scripts are one artifact, `artifacts/PoC.py`, with two modes. With no
  argument it is the lab's own differential, byte for byte the
  `validator/validator.py` beside it: the same environment variables, the same
  Compose service names, the same output and the same exit codes, which is the
  path automatic validation takes. Given one address it is the single-instance
  script, proved per CVE against the lab's two builds before it was written --
  and where the drafter could not prove one, that mode refuses with the
  drafter's own recorded reason and exits 2 without sending anything. The
  artifact's own header states both claims, and the four states `LAB-POC.md`
  reports are now the four states of one script's remote mode rather than
  whether a second file is there.

  Measured, and the reason it exists: across 148 validated labs the drafter was
  asked on 104 and shipped on 26, so three labs in four carried only the
  lab-only program under the name `PoC.py` -- whose own header said it was
  "designed for the generated Docker lab, not remote targets" -- while the
  script that did take a target sat beside it as `Manual-PoC.py`. The file a
  reader opened made no claim, and the claim was in a file nobody opened.

- `Manual-PoC.py`, `Manual-PoC.md` and `Manual-PoC.json` are no longer written.
  The first two are the modes and the header of `PoC.py`; the third is
  `report.json`'s `manual_poc_field`, which now carries the proved spec, the
  container port and the lab's own values for the inputs it declares. That is
  what makes asking the same lab twice give the same answer: a drafted spec is
  sampled, so without a record `cvelab manual` on a downloaded lab drafts
  afresh and can reach a different verdict with nothing having changed.
  `Manual-PoC.json` could never travel -- it was deliberately withheld -- and
  `report.json` is in `upload.ALWAYS` and in `upload.REQUIRED_TO_SHARE`. The
  three old names are still read off an archived lab, so a lab generated before
  this keeps the spec it proved, and they are removed when such a lab is
  re-rendered rather than left beside a `PoC.py` that has absorbed them.

- The merged script travels to the shared corpus whole, remote mode included.
  The project owner reversed the earlier decision on 2026-11-08; the
  consequence, recorded because it was chosen rather than drifted into, is that
  free-target exploit code is distributed to everyone who downloads a lab.
  Nothing was added to `upload.ALWAYS` or `upload.EXPLOIT` to do it: `PoC.py`
  was already on both as the lab-only script, and what changed is what the name
  contains. `--no-poc` still withholds it.

- `--lab-address`, which is how the command form survives the merge. `PoC.py
  --lab-address 127.0.0.1:32801 id` runs the lab program against this lab's own
  published build and prints what one command on it returns; a bare address is
  remote mode, which is proved per CVE or refuses. The flag is lab mode with an
  address, so the artifact's header describes it there, in the same breath as
  the sentence that it reaches a build CVELab made and shows nothing about any
  other host. An address that is not on loopback is refused, because loopback is
  where `manual.sh` publishes; which loopback port is this lab's the script
  cannot check, and its help says so rather than guessing. `--lab-address` with
  `--input` is refused as a contradiction, since which of the two the person
  wants decides whether they are testing their own application or this lab. It
  is emitted only for a lab whose contract declares a service port -- the
  validator of a lab that declares none reads no argument, so the flag would run
  the differential and call it a demonstration.

  The reason it is behind a flag at all: that mode was the carried validator's
  own, and the lab adapter's route is a constant in that validator, so a bare
  address aimed at a client would send a route that is not there and print
  BLOCKED -- a false negative dressed as a test.

- `--no-poc` now does what it says. It promised "leaving the entry
  non-runnable"; measured on a validated lab, what it filed was REPORT.md,
  WALKTHROUGH.md, EVIDENCE.json, report.json and analysis.json, and between them
  the route and method the attack used, the payload's construction in prose, the
  canary the effect is recognised by, the raw observations of both builds, and
  after the PoC merge every request the single-instance script sends, verbatim,
  under `manual_poc_field.spec`.

  None of those five can be withheld: `site/worker/gate.js` requires
  EVIDENCE.json, report.json, REPORT.md and WALKTHROUGH.md even of a withheld
  run and refuses one that arrives without them. So they are redacted in the
  payload instead, by an allowlist -- `upload.DESCRIBED_ONLY` names what may
  travel, field by field and section by section, and anything unnamed is
  withheld and said to be withheld, in the document. What is left says what was
  found; the request, the route, the body, the payload, the predicate, the
  steps that run it and everything the manual runner printed are gone, and so
  are the canary and the lab's own recorded input values wherever the model's
  prose quoted them. The lab on disk is untouched and an upload without the
  flag is byte for byte what it was.

  Two of those were found by review rather than by the first cut, and both are
  worth the record. `manual_poc_checks` was allowed wholesale while
  `validation.*.observations` was dropped, and each of its entries holds what
  the runner printed -- status, every response header, both builds' bodies --
  so the same material travelled from one key away; the allowlist takes `*`
  segments now and keeps only the pass, the exit code and the expected
  verdict. And the scrub ran over the serialized document while its needles
  are decoded strings, so a needle holding a quote, a backslash or a
  non-ASCII character could not match: measured on one archived lab, a
  `--no-poc` report.json still carried the traversal filename, which is the
  payload. It walks the parsed document now, and 30 needles in the archive
  carry such a character.

  The flag's help text and `cvelab doctor` now also say what it is not: the
  repository, both revisions and the CVE still travel, by design, so this is
  not the same as a reader being unable to reproduce the finding.

### Fixed

- The manual-PoC drafter no longer declines for reasons that are not true. Of
  78 archived labs where it was asked, 19 shipped a script, 11 drafted one and
  refused it after proving, and 48 never drafted at all; of those 48, 24
  genuinely cannot be shown against a single instance, and the other 24
  declined on a false reason or one the tool already answers. Four changes,
  none of which move the bar.

  It was given the predicate and never the verdict, and re-derived the
  differential from raw bodies -- twice on one panel, both times backwards.
  One lab's drafter read the warm-up pass out of the runs array and declined
  because the observation "found tail_nonzero false on both builds"; another
  quoted the patched build's line as the vulnerable build's, having said in
  the same answer that the shape was expressible and the record was the only
  obstacle. Measured by capturing the assembled input: the predicate arrived
  buried under the plan's declaration of what *would* be measured, the
  evidence not at all, and `differential_confirmed` only as a variable name
  inside a source listing. The verdict is now handed over ahead of the
  validator source, which can take half the input budget, so it cannot be what
  the limit truncates; a fourth key says whether a fixed build was tested at
  all, since on a vulnerable-only lab a bare false would manufacture a fresh
  wrong refusal.

  The harness's own diagnostic is now separated from the artifact it was
  computed over -- the decoded image, the cleaned text, the command output --
  because the clause forbidding a harness that reports the effect was
  swallowing the whole library case. Where the project ships no listener, the
  operator-supplied input *is* the route: 11 of 12 shipped component PoCs
  declare one and 9 name it `target_path`, while 19 of the 48 declines gave
  "ships no listener of its own" as the reason for declining -- the same
  sentence was the reason to use the pattern and the reason given for refusing
  it. And a decline is asked once more: the retry was gated on a flag set only
  for a malformed spec, so a decline was a single unretried sample. Declining
  again is a correct answer and is recorded as one. A provider decline is
  still never re-asked, and one on the second ask no longer replaces a real
  verdict with the absence of one.

  The bar is untouched and tests pin it: a script that fires on both builds
  does not ship, nor does one silent on both. Worth recording that the bar has
  never had anything to reject -- of the 11 refused after proving, 9 ran
  against both builds and in all 9 the script fired on neither. The cost is
  the drafting instructions growing 26% and the asks on that population going
  from 78 to at most 126; the re-ask doubles classifier exposure on exactly
  the labs that yield nothing today, and the PROVIDER_DECLINED rate on second
  asks is the number that decides whether it holds. It has not been measured.

- A vulnerable-only lab can no longer prove itself on something its target
  emits anyway. With no fixed build to contradict it, the effect check returned
  the vulnerable side's verdict on its own, and nothing required the declared
  effect to be related to the attack. One lab declared
  `{"body_regex": "Allowed memory size of [0-9]+ bytes exhausted"}`: specific,
  non-empty, not a status clause, and printed by the runtime for any script at
  all that exceeds its configured limit. It validated with
  `PUBLIC_FIX_NOT_IDENTIFIED` and a full deliverable set, and the only step
  that objected was the manual-PoC drafter, which refused to write a script for
  "only a proxy" after the automatic path had already passed. The same text is
  checked in under that product's own test suite as the expected output of an
  ordinary allocation failure, so what the predicate matched was documented
  behaviour.

  A vulnerable-only predicate must now quote the canary marker the lab planted,
  in at least one of `body_contains`, `body_regex` or `header`: with no
  comparison available, naming a value the attack introduced is the only way a
  declaration can tell the weakness from how the product behaves regardless.
  Refused before the build, where a repair can still act on it, and refused
  again at the gate, because the measured lab's plan was written before the
  rule existed and revalidating it must not reproduce it. Of the three
  vulnerable-only labs in the archive it accepts the one whose predicate quotes
  its marker, refuses the one above, and the third declared no predicate at all
  and was already refused. Differential labs are untouched and must stay so:
  43 of their 53 recorded predicates name an attacker-supplied value or a field
  the adapter computes rather than the marker, and the comparison is what
  judges those. A vulnerable-only lab whose effect is a crash, a hang or an
  allocation failure has no text to plant and no fixed build to compare
  against, so it is now refused rather than validated; `service_crash` and
  `timing_differential` are how such an effect is shown.

- The lab's own step-by-step document is `artifacts/LAB-POC.md`, renamed from
  `MANUAL-POC.md`, because that name was the same file as the single-instance
  script's guide on half the platforms CVELab ships for.
  `"MANUAL-POC.md".lower() == "Manual-PoC.md".lower()`, and on macOS and
  Windows the file system compares names without case, so a lab holding both
  kept only whichever was written second -- which of the two survived depended
  on write order. 13 of 103 archived labs hold both. CVELab ships for Windows
  (`PoC.ps1`, the `os.name == "nt"` branches in `upload.py`, `deliverables.py`
  and `core.py`), and `sourcegen._adapter_files` already compares adapter
  paths case-insensitively "as the file system on Windows and macOS compares
  names": the guard was in the repo and the shipped names walked past it,
  because the two names were declared in two modules and `test_manual_poc`
  asserted they differed with `assertNotIn` -- an exact-string test, which a
  difference of case passes. All four manual-PoC artifact names are now
  declared in one block in `field.py`, the test compares the way those file
  systems do, and a second test scans every quoted file name in the package so
  that a third module cannot reintroduce the fault.

  The `Manual-PoC.py`/`.md`/`.json` trio was deliberately left alone: its name
  is inside the emitted script's own usage text, so renaming it would have
  changed a shipped script's bytes. Archived labs keep the old document name
  and `cvelab upload` still ships it, since the share gate never required it
  and losing it would have been silent.

- Each of the two documents now says in its first section what it runs
  against, and `LAB-POC.md` says what the lab cannot show. Both used to open
  with the identical line `# <CVE> Manual PoC`, so following one to the end and
  watching it work told the reader nothing about whether any of it could be
  pointed at a client's server. For most labs it cannot: the single-instance
  script is refused far more often than it is written, because the effect is
  frequently not observable from outside the process at all.

  `LAB-POC.md` now states that it takes a Compose service name and not an
  address, says whether a single-instance script exists for this lab, and
  where one was attempted and refused, quotes the drafter's own reason for
  refusing. That reason was already recorded in `report.manual_poc_field`,
  where it was often the best sentence in the record and read by nobody,
  because nobody opens `report.json` before a client meeting. Those sentences
  -- "a stock daemon serves no HTTP route that reports its own root directory
  permissions" -- are exactly what stops a lab demonstration being described
  as a check that would run against a live instance. `create_deliverables`
  needed nothing new to reach the field: it is handed the same report dict
  `run_lab` returns. A step that was never asked for reads as never asked for
  rather than as a refusal, because `"not requested"` is `core.py`'s own
  default and not a judgement the drafter made.

- The handed-over demo now runs as its own guide documents it, on a machine
  that has Docker and the lab directory and nothing else. Five things were
  wrong with it and all five were in the one function that writes it:

  `manual.sh` reached the validator with `compose run --no-deps`. The internal
  path had already stopped doing that and recorded why: a one-off `run`
  container does not get the aliases its service declares on the network, so a
  validator that reaches its own canary by name gets "Temporary failure in
  name resolution" and the lab reads as not reproduced -- one lab, three runs
  running, and every lab built around a named stand-in failing the same way.
  The script now brings the service up, waits on the container, reads its logs
  and removes it, which is what CVELab does. 99 of 99 generated labs.

  `--no-deps` also skipped the only health wait there was, and `setup` printed
  "Manual lab ready" the moment `up -d` returned. A product that compiles
  assets or migrates a database on first boot had not listened yet, and the
  attack going out first reports "targets not ready", which reads as a lab
  that failed to reproduce. `setup` now waits for the build to report healthy
  and each later action re-waits without recreating anything. 63 labs exposed.

  MANUAL-POC.md said to run the block from the lab's `artifacts/` directory
  and opened with `cd CVE-…/artifacts`, which from `artifacts/` goes nowhere --
  the first line of the documented demo, in every lab. The relative path
  arrived in 0.6.7 as a privacy fix for an absolute one and was no more
  runnable than what it replaced. `manual.sh` resolves the lab from its own
  path, so the cd is gone rather than corrected.

  `PoC.ps1` shipped in every lab and no document named it, so the only
  instructions a Windows reader had were for a shell they do not have. The
  guide now has a Windows section, and the wrapper offers only the builds the
  lab actually has.

  A lab whose contract declares the state its attack needs had that state
  established by a Compose override written to a scratch directory and removed
  when CVELab exited, so it validated seeded and shipped a demo that could not
  seed: the attack reached an instance with nothing to act on and the affected
  build reported BLOCKED. The seeding now travels with the lab as
  `artifacts/cvelab-setup.json` -- the same file CVELab merged into its own
  run, written where the resolved Compose model exists because that is the
  only place it can be built -- and `manual.sh` merges it, runs it once per
  build, and carries what it bound through to the attack. 3 of 185 archived
  labs declare setup; 0 of 3 shipped it.

- A report can no longer call a manual PoC verified over a kit that cannot
  perform the seeding its own contract declares. One archived lab recorded
  `manual_poc_status: "verified"` and `ok: true` over exactly that, and it was
  not wrong about anything it measured: CVELab ran the handed-over actions
  itself, with its own override merged and its own bindings in the
  environment, and they passed. What nothing measured was whether the kit
  beside the report can do the same.

  That is now computed from the files in the lab directory -- the shipped
  seeding file against the steps and port the contract declares, and the
  shipped script against the names it has to carry -- and never from a field
  the model wrote or a sentence in the generated guide. A gap reports
  `manual_poc_status: "seeding_not_shipped"` with the reason beside it, in
  report.json, artifacts/report.json, EVIDENCE.json and the REPORT.md line.

  The lab is still carried. A differential reproduction is a proof whether or
  not the kit beside it can seed, so the check stays out of `proof_checks`,
  where every value is ANDed into `ok`: throwing away the proof to punish the
  packaging would leave nothing to show a client, which is the other half of
  the same problem.

- A provider too busy to answer no longer counts as a failed repair. Requests
  now retry a 429, 500, 502, 503, 504 or 529 with a widening pause, honouring
  `Retry-After` where the server sends one; the statuses that mean the request
  itself was wrong are untouched and still stop the run. A stall that outlasts
  those retries gives its attempt back instead of spending it, and leaves the
  lab's own failure in place rather than replacing it with an HTTP status:
  measured on a batch of ten, one CVE lost two of its four repair attempts to
  `overloaded_error`, and each loss also pushed the real evidence a level
  deeper into the next prompt. Tunable with `CVELAB_PROVIDER_RETRIES`.
- A pair of revisions that cannot show its fix becomes a vulnerable-only lab
  before generation, instead of being discovered after five repairs. One lab in
  the repeated benchmark set had snapshots differing in a single translated
  README, leaving the file the advisory names byte-identical in both; the
  attack ran, the effect appeared on both services, and every repair was asked
  for a differential the inputs forbade. A pair whose two revisions resolve to
  the same tree is the other half of the same fault and was not caught at all,
  because zero changed files is not prose.

  What such a pair costs is now the fixing reference, not the run: the
  vulnerable revision is still authentic, and as Limitations has always said,
  the absence of a public fix prevents differential validation of remediation
  rather than a PoC against the affected version. `fix_status` becomes
  `PUBLIC_FIX_NOT_IDENTIFIED`, and the reason ends with the remedy -- the
  fixing reference in hand is not the fix, so resolve it again. It reaches
  `plan.json`, the generation attempt in `automation.json` where a batch reads
  it, and `artifacts/EVIDENCE.json` under `provenance`, which is the copy that
  survives `--no-poc`; `REPORT.md` and `WALKTHROUGH.md` then say a fixed
  revision was identified and discarded, and why, so a demoted lab is neither
  confused with one whose fix was never found nor told to wait for a fix it
  already has. The patched snapshot is taken back off disk only once the
  answer has validated and the demoted plan is about to be written, so a
  provider that declines or a Ctrl-C leaves the lab exactly as it was; the
  stamp is unlinked before the tree it vouches for, so an interrupt mid-delete
  cannot leave an intact stamp hiding a truncated snapshot. Repair demotes the
  same way, as defence in depth for a lab generated before the check existed.
  The check is deterministic, so it runs before the first token is spent, and
  it leans toward keeping the differential: the extension decides and nothing
  else, so a dependency bump, a lockfile, a policy file, a template, a
  migration, a test and a workflow are all real fixes and still build a
  differential.
- The validator's build context is described by what the answer actually put
  there. The rejection for an uncopyable file named `requirements.txt` among
  the context's contents, which is only true when the answer returns
  `validator/requirements.txt`, so a model was told the file was present and
  then refused for copying it. The generation instructions now say the same
  thing, once, in both places they are built.
- The fidelity level and `vendor_product_started` are required to agree in the
  instructions, not only in the guard that rejects the answer. `source_component`
  with a started product was one of three repairs lost to contract violations
  in a single run.
- The archived-pool hint no longer offers a newer base image as the better
  alternative. It did, and the first run to receive it took the offer: a lab
  pinned to python 3.8 moved from bullseye to `python:3.8.16-bookworm` and the
  build died on a tag that has never existed, because python 3.8 reached end
  of life before bookworm shipped. A release reaches the archive at about the
  time the interpreter above it is dropped, so the population this hint is for
  is the one where its alternative cannot be built. The hint now names that
  failure and says to keep the base image and redirect apt.
- That warning is now attached to the failure it describes rather than to the
  one the model has already escaped. It lived at the end of the archived-pool
  hint, so the only run ever shown it was one that had not invented a tag yet;
  the run that did invent one was classified `runtime_error` and reached a
  repair carrying a Docker log and nothing else. Two classes of build failure
  were arriving that way, four of forty measured attempts between them, and
  each now has a name and a hint:

  - A base image tag that was never published is `unknown_base_image`.
    Metadata resolution precedes every layer, so nothing below the `FROM`
    line has run and the log says nothing about the lab. The hint carries the
    measured lesson -- for an old CVE there is often no variant of the pinned
    interpreter on a supported release at all, so the answer is the older
    release with apt redirected, not a newer tag -- and says to name only a
    tag known to be published.
  - A dependency version that cannot be fetched is `dependency_pin`: no
    published version satisfies the requirement, the proxy has withdrawn the
    one named, or a recorded checksum disagrees with what is served. The hint
    says to change the pin the output names and to leave the vulnerable and
    patched revisions on the versions they are on, because relaxing the
    product's own pin makes the build pass by removing the fix.

  Neither is retried: an unpublished tag and a bad pin are answers that will
  not change, which is the same reason a `404` is not in the retry markers.
  The archived pool is still classified first, because one compose solve can
  produce both and its remedy is the one the other would contradict.

  The marker list was checked against docker 29.9.2 and buildx 0.38.1 rather
  than assumed. Modern buildkit says `failed to resolve source metadata` and
  then plain `not found`; it does not say `manifest unknown`, which is the
  older distribution wording and is matched only for daemons that still emit
  it.
- A clone that fails because the repository is not there stops generation at
  once instead of asking three more times. One of the ten in the repeated
  benchmark set had its upstream removed between the advisory and the run; all
  four generation attempts went to an answer that could not change, and the
  artifact recorded a generic `generation_error` with the cause four attempts
  back. Such a failure is now `source_unavailable` and says so in one line.
  A name-resolution failure on the clone is untouched, and still retried.
- A build that failed for want of something it had to download is no longer
  sent to a model to rewrite. Three of thirty attempts across three runs of
  the same ten CVEs ended this way, and not one was a question a model could
  answer, so each spent the lab's whole repair budget making a correct
  Dockerfile worse and was recorded `AUTO_REPAIR_EXHAUSTED`. These now split
  in two, and neither goes to the old path:

  - A mirror, module proxy or name server that is briefly away -- a hash sum
    mismatch, a `503`, an `i/o timeout` -- is retried as it stands, up to
    `CVELAB_TRANSIENT_RETRIES` times (2, `CVELAB_TRANSIENT_PAUSE` seconds
    apart, 15), without spending a validation attempt or a repair. A build
    that never produced an image says nothing about the PoC, which is the same
    reason a startup failure already had its own budget.
  - A `404` is not that, and retrying it is futile: it says the file is not
    there and will not be. Debian moves a release's pool to
    `archive.debian.org` once its support ends but keeps serving that
    release's index from `deb.debian.org`, so `apt-get update` succeeds,
    reads a current version out of a current index, and every download of it
    404s in the same layer seconds later. This reaches a repair as it did
    before, but carrying the one thing the symptom does not point at: the
    packages are fine, the sources are not.

  Verified against `python:3.8-slim-bullseye`, the sentry lab's own base: the
  security index lists `libpq5 13.23-0+deb11u4` and gives its pool path, every
  mirror 404s that path, `archive.debian.org` serves it, and the install then
  completes. The sentry lab failed this way in all three runs and still does,
  which is how a retry alone was ruled out.

- A lab built from a monorepo links a module to the sibling beside it rather
  than to the version its `go.mod` names. Go's `go.work` is conventionally
  gitignored -- mattermost ignores it twice over -- so a checkout of such a
  repository cannot build as it stands, and the build fails on symbols the
  checkout plainly contains. The generator is now told the rule, and told to
  confirm it with `go list -m`, which names no version when a module resolved
  to a local directory.

  CVE-2026-6961 cost all three runs this way. Verified in
  `golang:1.25-bookworm` against that lab's own checkout: without a workspace
  `go list -m` answers `server/public v0.1.12`, the published module missing
  both symbols the build wanted; with `go work init . ./public` it answers
  `server/public` and no version, and the two packages compile. One of the
  three runs had written the workspace itself and lost the build to a module
  download, which the retry above now covers -- the two halves of that CVE's
  failure, and both measured rather than assumed.

- A request to a server that dies mid-response no longer ends the script as an
  unhandled traceback. `RemoteDisconnected` is `ConnectionResetError` and
  `BadStatusLine`, and neither is a `URLError`, so the clause naming
  `URLError`, `TimeoutError` and `SSLError` let it straight past. Found by
  running a `service_crash` PoC against a service that really does exit
  mid-request, where a dropped connection is the whole observation and came
  back as a crashed script instead.

- A `timing_differential` run takes every benign measurement before the first
  payload, not alternating with it. Alternating sounds fairer and is wrong
  here, measured: the payload this strategy exists for occupies the service,
  and against a single-threaded stand-in every benign request after it timed
  out too -- 30s against 30s, 1.0x, no finding, for a weakness that had wedged
  the service outright. It also stops sending payloads once one never answers,
  because a wedged service has nothing more to tell the check.

- The generated guide describes the script beside it. It branched on
  `inband_differential` against everything else, so a `direct_observation`
  guide told the operator it sends a marker it does not send -- and a
  `service_crash` guide would have read "it only reads" above a script that
  causes an outage. Every strategy now has its own description, and the
  footprint is the same text the script's own header carries, so the two cannot
  drift.

- The guide's pasteable command includes every input the spec declares. The
  script refuses to start without them, by design, so for any spec that
  declared one the guide printed a command that could not run.

- A declined request is asked again on another model by default, which recovers
  the CVE instead of losing it. The provider's own refusal text points
  integrators at this remedy. It was off unless `CVELAB_FALLBACK_MODEL` named a
  model, on the grounds that a decline a fallback answered is not the same
  measurement as a run never declined -- which is true, and the other error was
  bigger: three of ten CVEs in one batch were lost to declines with nothing
  else wrong. Both stay countable, because the decline is recorded before the
  second attempt is made. `CVELAB_FALLBACK_MODEL=off` restores the old
  behaviour, which is how refusals are measured as they fall.

### Changed

- A proven spec is kept and reused, so `cvelab manual` on the same lab gives
  the same answer and costs nothing the second time. It existed only embedded
  in the generated script before, so asking again re-asked the model and
  sampled a new spec -- a lab that produced a script one day could refuse the
  next with nothing having changed. `--redraft` asks again on purpose. A
  refusal is not kept; only a spec that passed the proof is worth repeating.

- Each service is checked again immediately before the script runs, both that
  the container is up and that the port still answers. A service can pass the
  readiness probe and then stop before its turn comes -- Storybook 10.6.1 did,
  twice, while the fixed build served both runs -- and the proof reported
  "the script did not finish against both builds", which was true and useless.
  The service that went away is named, nothing is run against it, and the tail
  of its log comes with the refusal, with terminal colour stripped: the first
  time those logs were needed the one informative line was buried in several
  hundred escape codes.

### Changed (earlier)

- The command is `cvelab manual <CVE> --poc <location>`. A CVE identifier is
  what anyone remembers once the lab is built; the path with that identifier
  already inside it is not. Both spellings of the location work -- the
  directory holding `CVE-YYYY-NNNNN`, and that directory itself -- and
  without `--poc` it falls back to `--output-root`.

- `expect: {"status": <code>}` takes any code, and the prompt now says so.
  It always did, but the wording read `{"status": 200}` "when the finding is
  that the route answered at all", so a lab whose effect was a 401-versus-403
  split was told by its own instructions that `direct_observation` could not
  express it.

### Added

- `{{target}}` and `{{targetHost}}`, the host and port the script was pointed
  at. A spec names no host by design, but some effects are about the target's
  own address: an Origin or Referer a server should reject, a rebinding check,
  a redirect back to itself.

### Added (earlier)

- A lab can be built from a tagged release pair when there is no fixing
  commit. Discovery will not invent one and is right not to, so a CVE whose
  fix is a release ended with `ARTIFACT_REQUIRED` and nothing else -- while
  the advisory said plainly "affected through 2.3.34, fixed in 2.3.35" and
  both tags were sitting in the repository. Resolving them costs one
  `git ls-remote` and no model call. Tags are matched exactly and never by
  prefix, because a repository that tags `v2.3.34` often also tags
  `v2.3.34-gae` for a different build; the repository name is tried as the
  tag prefix before the package coordinate, since netty tags
  `netty-4.1.127.Final` while the advisory names `io.netty:netty-handler`;
  and both ends must resolve or the pair is dropped. The versions are read
  from the advisory's own inclusive upper bound rather than from a package
  registry, which is what had dropped this pair -- the registry lookup
  returned nothing and took the pair with it.

### Added (manual PoC)

- `report.json` carries `evidence_label`, one line saying what a run
  established rather than what the lab contained:

  | | |
  | --- | --- |
  | `Reproduced, differential against the fixed build` | and `, manual PoC proven` |
  | `Reproduced on the vulnerable build; no fixed build available` | and `, manual PoC proven` |
  | `Not reproduced` | |

  A fixed build is preferred and the label says when there was none, because
  it answers what a single observation cannot: whether the effect is the bug
  or how the thing always behaves. It is stated rather than implied, carries
  none of this code's internal lab-shape names, and says the manual PoC was
  *proven* rather than provided -- the script is only written after it showed
  the effect and, where there was a fixed build, stayed silent against it.

### Changed

- A lab with no fixed build can hand over a manual PoC. It was refused
  outright, on the grounds that half the proof was missing. That had it
  backwards: a patched build answers one question -- is this the bug, or is it
  how the thing always behaves -- and it is a check against self-deception,
  not what makes a vulnerability real. Some projects publish no resolvable
  patched revision at all, and the effect is still worth showing.

  What replaces it is not nothing. `inband_differential`, `marker_roundtrip`
  and `oob_callback` each carry their own control inside the one instance they
  run against -- the same resource read the way that authorizes correctly, or
  a marker surfacing where it cannot legitimately -- so one of those is
  required. `direct_observation` is refused there, because its only check was
  the fixed build and "the route answered 200" on its own is the shape of
  proof that once passed a lab on `existsSync` seeing a path with `..`.
  `Manual-PoC.json` records `fixed_build_compared`, and the guide says plainly
  that this shows the effect happening rather than that a fix removes it.

### Added

- `ws` and `wss` transports, for an effect that lives in frames after a
  WebSocket upgrade. `ws_path` names the upgrade route and a message is `send`
  and `read_until` as over a socket, with the sequence sharing one session.
  The handshake is HTTP and the framing is a documented wire format, so this
  needs nothing installed: the `Sec-WebSocket-Accept` header is checked rather
  than assumed, because a plain 200 from a server that does not speak
  WebSocket would otherwise read as a successful upgrade and every later read
  would come back empty -- indistinguishable from the effect being absent. A
  ping is answered so the peer does not drop the exchange, and a close ends a
  read rather than failing it. This was the one gap in a ten-CVE batch that
  was the format's fault rather than the vulnerability's.

- The spec call is given what the lab declared it simulated. Measured on that
  batch: four of the five labs that reproduced but shipped nothing had proved
  their CVE through an endpoint the product does not serve -- a `/lab/state`
  added so the validator could read internal state, a `/probe` page rendered
  to watch a browser, a wrapper around a library that ships no listener at
  all -- and `fidelity.simulated_components` is where the lab says so. The
  prompt now draws the distinction that matters: a harness standing in for an
  application route is fine, because a real deployment has its own route of
  that shape and the weakness is still reached through it, while a harness
  that *reports* the effect is not, because a spec aimed at it would pass
  against the lab and mean nothing against a real server.

- `cvelab manual <CVE> --poc <location>` writes
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

- `cvelab manual <CVE> --poc <location>` no longer needs `--spec`. Without one it asks
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

[Unreleased]: https://github.com/AndreiIonascu17/cvelab/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.8...v0.7.0
[0.6.8]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.7...v0.6.8
[0.6.7]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.6...v0.6.7
[0.6.6]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.5...v0.6.6
[0.6.5]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/AndreiIonascu17/cvelab/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/AndreiIonascu17/cvelab/releases/tag/v0.6.0
