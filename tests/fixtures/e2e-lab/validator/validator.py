"""The differential, as a generated validator writes one."""
import json, os, socket, sys, urllib.error, urllib.request

PORT = 8000
TARGETS = {"vulnerable": "http://vulnerable:8000", "patched": "http://patched:8000"}
CANARY = "cvelab-e2e-secret"


def read_note(base):
    """The attack: ask for someone else's note with no credential at all."""
    try:
        with urllib.request.urlopen(base + "/notes/1", timeout=10) as answer:
            return answer.status, answer.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as refused:
        return refused.code, refused.read().decode("utf-8", "replace")
    except OSError as error:
        return None, "transport: %s" % error


def probe(name):
    status, body = read_note(TARGETS[name])
    confirmed = status == 200 and CANARY in body
    return {"confirmed": confirmed, "blocked": not confirmed,
            "http_status": status, "raw_body": body[:400]}


def main():
    action = os.environ.get("CVELAB_MANUAL_ACTION", "").strip()
    target = os.environ.get("CVELAB_TARGET", "").strip()
    if action == "alias":
        # The alias the compose file gives the vulnerable service. A one-off
        # container does not get it, which is the regression this proves gone.
        try:
            socket.getaddrinfo("product.canary.local", PORT)
        except OSError as error:
            print("alias-missing: %s" % error)
            return 1
        print("alias-ok")
        return 0
    if action or target:
        if action not in ("exploit", "verify") or target not in TARGETS:
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
