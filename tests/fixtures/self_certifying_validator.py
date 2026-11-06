"""A generated validator that labels its own run, forked from the e2e lab.

WHY THIS FILE EXISTS

`tests/fixtures/e2e-lab/validator/validator.py` is the project's own
demonstration of the defect: it prints

    "proof_quality": "security_effect_observed" if differential else ...

and the source path's mandatory `security_effect_observed` check used to be
a string equality against exactly that literal. A validator that wrote it
cleared a mandatory proof gate without anything having been measured.

This is that fixture with one thing changed, and it is the change the
project has already seen a model make twice in production, on two CVEs in
two ecosystems: `confirmed` is derived from the fact that a reply arrived
rather than from the effect. Everything else about the document is honest
in form -- the differential is computed, nothing is hard-coded, the
anti-hardcoding guard has nothing to object to -- so every other proof check
passes and the effect check is the only one left to notice that the response
body says nothing happened.

The transport is the only other difference. The responses come from
CVELAB_FAKE_RESPONSES, a JSON mapping of service name to the status, headers
and body to answer with, so the file can be executed in a test without a
network, a container or a service. It is run as a subprocess and its real
stdout is fed to `core.run_lab`, because a hand-written JSON document would
test the assertion rather than the path.
"""
import json
import os
import sys

CANARY = "cvelab-e2e-secret"


def read_note(name):
    """The attack, answered from the canned table instead of over HTTP."""
    canned = json.loads(os.environ["CVELAB_FAKE_RESPONSES"])[name]
    return canned["status"], canned.get("headers", {}), canned["body"]


def probe(name):
    status, headers, body = read_note(name)
    # The defect, as a model wrote it twice: a reply arrived, so the exploit
    # must have worked. The honest rule is `status == 200 and CANARY in
    # body`, which is what the fixture this was forked from uses.
    confirmed = status == 200
    return {"confirmed": confirmed, "blocked": not confirmed,
            "http_status": status, "raw_body": body[:400],
            "observations": {"status": status, "headers": headers, "body": body[:4000]}}


def main():
    action = os.environ.get("CVELAB_MANUAL_ACTION", "").strip()
    target = os.environ.get("CVELAB_TARGET", "").strip()
    if action or target:
        if action not in ("exploit", "verify") or target not in ("vulnerable", "patched"):
            print("unsupported CVELAB_MANUAL_ACTION or CVELAB_TARGET")
            return 2
        seen = probe(target)
        if action == "exploit":
            print(json.dumps(seen, sort_keys=True))
            return 0
        if target == "vulnerable":
            print("REPRODUCED" if seen["confirmed"] else "BLOCKED")
        else:
            print("BLOCKED" if seen["blocked"] else "REPRODUCED")
        return 0
    vulnerable, patched = probe("vulnerable"), probe("patched")
    differential = vulnerable["confirmed"] and patched["blocked"]
    print(json.dumps({
        "attack_executed": vulnerable["http_status"] is not None
        and patched["http_status"] is not None,
        # The self-certification. Kept in the report as the validator's own
        # claim; it no longer decides anything.
        "proof_quality": "security_effect_observed" if differential else "not_observed",
        "observable_effect":
            "GET /notes/1 with no credential returns the owner's note on the affected "
            "build; the fixed build answers 403",
        "evidence_type": "unauthorized_read",
        "vulnerable": vulnerable,
        "patched": patched,
        "differential_confirmed": differential,
    }, sort_keys=True))
    return 0 if differential else 1


if __name__ == "__main__":
    sys.exit(main())
