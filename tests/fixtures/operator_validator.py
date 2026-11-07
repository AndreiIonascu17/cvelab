# Copyright 2026 SyncBit Software SRL and the CVELab contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A validator written to sourcegen._OPERATOR_CONTRACT, for the tests to run.

NOT a generated lab's validator and not a template for one. It is the
smallest script the contract admits -- one HTTP product, a session, a
command-execution weakness -- written here so that two things can be measured
rather than asserted about prose:

  * that the contract is satisfiable at all, in the standard library alone,
    and that `sourcegen._validate_generated` accepts a script written to it;
  * that the two entry points really are two, by running both against a stub
    server and comparing what each one does.

`CVELAB_FIXTURE_PORT` stands in for the port a real validator writes as a
literal (`PORT = 8080`) and the contract now has the lab declare as
`exploit_contract.service_port`. It is settable only because the stub server
in the test binds an ephemeral port; nothing in a lab reads such a variable.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

PORT = int(os.environ.get("CVELAB_FIXTURE_PORT", "8080"))
MARKER = "CVELAB-fixture-canary"
CANARY_COMMAND = "echo " + MARKER

# ONE session for the whole run, built once. Inside the lab each manual
# action is a fresh container, so this costs nothing there; run by hand it is
# what carries the login below through to the attack.
SESSION = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)


def send(base, method, path, body=None):
    data = body.encode("utf-8") if isinstance(body, str) else body
    asked = urllib.request.Request(base + path, data=data, method=method)
    try:
        with SESSION.open(asked, timeout=10) as answered:
            return answered.status, answered.read().decode("utf-8", "replace"), dict(answered.headers)
    except urllib.error.HTTPError as refused:
        return refused.code, refused.read().decode("utf-8", "replace"), dict(refused.headers)


def seed(base):
    """This lab's declared setup, performed by the script itself.

    Only on the address path. Inside the lab CVELab runs these steps and
    passes what they bound in CVELAB_BOUND; a person running this by hand has
    neither, and an unseeded instance answers the attack the way a fixed
    build does.
    """
    status, _, _ = send(base, "POST", "/login", "user=lab&password=labpassword")
    return status == 200


def observe(base, command):
    status, body, headers = send(
        base, "GET", "/run?" + urllib.parse.urlencode({"cmd": command})
    )
    # One function, called once per side, so the two verdicts are comparable.
    # "shell-ran" is what the weakness introduces; a refusal, an error status
    # or any answer without it is confirmed=false and blocked=true.
    ran = status == 200 and "shell-ran" in body
    return {
        "observations": {"status": status, "body": body, "headers": headers},
        "confirmed": ran,
        "blocked": not ran,
    }


def at(address):
    return "http://" + address


def inside(host):
    return "%s:%d" % (host, PORT)


def main(argv):
    rest = argv[1:]
    if len(rest) > 2:
        print("usage: PoC.py [<host>:<port>] [command]", file=sys.stderr)
        return 2
    if rest:
        address = rest[0]
        if ":" not in address.rsplit("]", 1)[-1]:
            address = inside(address)
        command = rest[1] if len(rest) > 1 else CANARY_COMMAND
        print("sending the regression input to " + address, file=sys.stderr)
        base = at(address)
        if not seed(base):
            print("could not establish the state the attack needs", file=sys.stderr)
            return 1
        found = observe(base, command)
        print("status: %s" % found["observations"]["status"])
        if len(rest) > 1:
            print("command output:")
            print(found["observations"]["body"])
        print("REPRODUCED" if found["confirmed"] else "NOT_OBSERVED")
        return 0 if found["confirmed"] else 1

    action = os.environ.get("CVELAB_MANUAL_ACTION", "").strip()
    target = os.environ.get("CVELAB_TARGET", "").strip()
    if action and target:
        found = observe(at(inside(target)), CANARY_COMMAND)
        if action == "exploit":
            print(found["observations"]["body"])
            return 0 if found["confirmed"] else 1
        if action == "verify":
            print("REPRODUCED" if found["confirmed"] else "BLOCKED")
            return 0 if found["confirmed"] else 1
        print("unsupported CVELAB_MANUAL_ACTION or CVELAB_TARGET", file=sys.stderr)
        return 2

    bound = json.loads(os.environ.get("CVELAB_BOUND", "").strip() or "{}")
    vulnerable = observe(at(inside("vulnerable")), CANARY_COMMAND)
    patched = observe(at(inside("patched")), CANARY_COMMAND)
    print(json.dumps({
        "attack_executed": True,
        "proof_quality": "security_effect_observed",
        "observable_effect": "the supplied command ran on the server",
        "evidence_type": "code_execution",
        "bound": sorted(bound),
        "vulnerable": vulnerable,
        "patched": patched,
        "differential_confirmed": vulnerable["confirmed"] and patched["blocked"],
    }))
    return 0 if vulnerable["confirmed"] and patched["blocked"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
