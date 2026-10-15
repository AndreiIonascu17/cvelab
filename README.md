# CVELab has moved

This repository is archived and read-only. Development continues elsewhere.

### → **[cvelab.tech](https://cvelab.tech)**

CVELab takes a CVE identifier, builds an isolated Docker lab from the real
vulnerable source, and runs a proof of concept against it. A run succeeds only
when the test produces an observable effect on the vulnerable artifact and the
patched revision blocks the same test. A reflected marker is not accepted as
proof.

| | |
| --- | --- |
| How it works | <https://cvelab.tech/how-it-works/> |
| Install | <https://cvelab.tech/install/> |
| Benchmark method | <https://cvelab.tech/benchmark/> |
| Safety and containment | <https://cvelab.tech/safety/> |

## About the code here

What is in this repository is the state of CVELab as of September 2026. It is
kept for history and attribution, not for use. It predates the licence, the
test suite, the environment preflight, the token accounting, and the removal
of per-CVE special casing, so treat anything here as superseded.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

This repository was published without a licence, which left it all rights
reserved and gave nobody the right to use it. The licence is applied here
before archiving so the history remains lawfully usable, with the agreement of
the contributors.

Copyright 2026 SyncBit Software SRL and the CVELab contributors.

CVE and the CVE logo are trademarks of The MITRE Corporation. CVELab is an
independent project, not affiliated with, endorsed by, sponsored by or
certified by The MITRE Corporation or the CVE Program, and it does not claim
CVE-Compatible status.
