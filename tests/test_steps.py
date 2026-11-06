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

"""The step grammar, where three modes can reach it.

It was inside the field mode, which is why a generated source lab had no
machinery for a precondition at all: getting at it meant importing a module
that brings a provider and Docker with it. The grammar is now its own module
and the field mode reads it from there, so the step that validates a model's
answer before anything is built can read it too.

These tests hold two lines. One is that the module stands alone -- stdlib
only, nothing from the package, no runner -- because that independence is the
whole point of the move. The other is that it accepts and refuses exactly
what it did while it lived in field.py.
"""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cvelab import field, steps

REPO = Path(__file__).resolve().parent.parent


class TheModuleStandsAloneTests(unittest.TestCase):
    """Nothing in it reaches the rest of the package, or a network."""

    def test_it_imports_with_nothing_else_from_the_package_loaded(self) -> None:
        """A subprocess, because this session already imported field."""
        completed = subprocess.run(
            [
                sys.executable, "-c",
                "import sys; import cvelab.steps; "
                "print(sorted(n for n in sys.modules if n.startswith('cvelab')))",
            ],
            cwd=REPO,
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(completed.stdout.strip(), "['cvelab', 'cvelab.steps']")

    def test_it_imports_nothing_from_the_package(self) -> None:
        source = Path(steps.__file__).read_text(encoding="utf-8")
        for forbidden in ("from .", "from cvelab", "import cvelab"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_the_runner_stayed_with_the_mode_that_can_run_it(self) -> None:
        """Running the steps needs a route to the lab, and that differs.

        A single-target proof reaches one container's network namespace; a
        generated lab has an internal compose network and no container id to
        hand. The grammar is shared, the runner is not.
        """
        source = Path(steps.__file__).read_text(encoding="utf-8")
        for absent in ("docker", "subprocess", "urllib", "CVELAB_"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, source)
        ran = inspect.getsource(field._run_setup)
        self.assertIn("container:", ran)
        self.assertIn("CVELAB_SETUP", field._SETUP_RUNNER)


class FieldReadsTheSameGrammarTests(unittest.TestCase):
    """field.py uses the module's objects, not copies of them."""

    def test_the_validators_are_the_module_s_own(self) -> None:
        for name, moved in (
            ("_validate_request", steps.validate_request),
            ("_validate_upload", steps.validate_upload),
            ("_validate_extractor", steps.validate_extractor),
            ("_validate_inputs", steps.validate_inputs),
            ("_validate_setup", steps.validate_setup),
            ("_substitutions", steps.substitutions),
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(field, name), moved)

    def test_the_tokens_and_patterns_are_the_module_s_own(self) -> None:
        for name, moved in (
            ("_MARKER_TOKEN", steps.MARKER_TOKEN),
            ("_TARGET_TOKENS", steps.TARGET_TOKENS),
            ("_BIND_NAME", steps.BIND_NAME),
            ("EXTRACTORS", steps.EXTRACTORS),
            ("_PART_CONTENT", steps.PART_CONTENT),
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(field, name), moved)

    def test_the_bounds_are_the_module_s(self) -> None:
        for name, moved in (
            ("_MAX_REQUESTS", steps.MAX_REQUESTS),
            ("_MAX_INPUTS", steps.MAX_INPUTS),
            ("_MAX_UPLOAD_PARTS", steps.MAX_UPLOAD_PARTS),
            ("_MAX_SETUP_REQUESTS", steps.MAX_SETUP_REQUESTS),
        ):
            with self.subTest(name=name):
                self.assertEqual(getattr(field, name), moved)

    def test_the_bounds_are_the_ones_the_field_mode_shipped_with(self) -> None:
        """A refactor that loosened one of these would be a behaviour change."""
        self.assertEqual(steps.MAX_SETUP_REQUESTS, 10)
        self.assertEqual(steps.MAX_REQUESTS, 25)
        self.assertEqual(steps.MAX_INPUTS, 8)
        self.assertEqual(steps.MAX_UPLOAD_PARTS, 6)
        self.assertEqual(steps.EXTRACTORS, ("json_values", "regex", "header", "status"))
        self.assertEqual(steps.PART_CONTENT, ("text", "base64", "tar_gz", "zip"))
        self.assertEqual(steps.TARGET_TOKENS, ("target", "targetHost"))
        self.assertEqual(steps.MARKER_TOKEN, "{{marker}}")

    def test_a_socket_transport_still_reaches_its_own_entry_validator(self) -> None:
        """The HTTP entry is shared; a socket exchange is not, and still works."""
        self.assertEqual(
            field._validate_sequence([{"send": "hi"}], "spec.probe", "tcp"),
            [{"send": "hi", "read_bytes": 1024 * 1024}],
        )
        self.assertEqual(
            field._validate_sequence([{"exec": "id"}], "spec.probe", "ssh"),
            [{"exec": "id"}],
        )
        # The list is checked before the transport is looked up, which is the
        # order the one function had before the shared half of it moved out.
        with self.assertRaises(ValueError):
            field._validate_sequence([], "spec.probe", "not-a-transport")


class ASetupStepIsARequestOrABindingTests(unittest.TestCase):
    """What a step may be, and what it may name."""

    def test_a_plain_request_is_normalised(self) -> None:
        self.assertEqual(
            steps.validate_setup([{"method": "post", "path": "/lab/seed",
                                   "body": {"title": "t"}}], []),
            [{"method": "POST", "path": "/lab/seed", "headers": {},
              "body": '{"title": "t"}'}],
        )

    def test_a_binding_step_keeps_its_three_parts(self) -> None:
        out = steps.validate_setup(
            [{"bind": "admin_key", "query": [{"path": "/lab/admin-key"}],
              "extract": {"json_values": "key"}}],
            ["admin_key"],
        )
        self.assertEqual(out[0]["bind"], "admin_key")
        self.assertEqual(out[0]["extract"], {"json_values": "key"})
        self.assertEqual(out[0]["query"][0]["path"], "/lab/admin-key")

    def test_a_bound_name_has_to_be_declared_as_an_input(self) -> None:
        with self.assertRaises(ValueError) as refused:
            steps.validate_setup(
                [{"bind": "admin_key", "query": [{"path": "/k"}],
                  "extract": {"json_values": "key"}}],
                [],
            )
        self.assertIn("also be declared in inputs", str(refused.exception))

    def test_a_later_step_may_use_what_an_earlier_one_bound(self) -> None:
        out = steps.validate_setup(
            [
                {"bind": "admin_key", "query": [{"path": "/lab/admin"}],
                 "extract": {"json_values": "key"}},
                {"bind": "user_key",
                 "query": [{"path": "/v1/keys", "method": "POST",
                            "headers": {"Authorization": "Bearer {{admin_key}}"}}],
                 "extract": {"json_values": "key"}},
            ],
            ["admin_key", "user_key"],
        )
        self.assertIn("{{admin_key}}", json.dumps(out))

    def test_a_name_nothing_binds_is_refused(self) -> None:
        for setup in (
            [{"path": "/lab/seed/{{nobody}}"}],
            [{"bind": "k", "query": [{"path": "/k/{{nobody}}"}],
              "extract": {"status": True}}],
        ):
            with self.subTest(setup=setup):
                with self.assertRaises(ValueError) as refused:
                    steps.validate_setup(setup, ["k"])
                self.assertIn("nothing binds", str(refused.exception))

    def test_the_target_s_own_address_needs_no_declaring(self) -> None:
        for token in steps.TARGET_TOKENS:
            with self.subTest(token=token):
                steps.validate_setup(
                    [{"path": "/lab/seed", "headers": {"Origin": f"{{{{{token}}}}}"}}],
                    [],
                )

    def test_a_bind_name_has_to_look_like_a_name(self) -> None:
        for name in ("", "1st", "has-a-dash", "a" * 33):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    steps.validate_setup(
                        [{"bind": name, "query": [{"path": "/k"}],
                          "extract": {"status": True}}],
                        [name],
                    )

    def test_a_binding_step_without_an_extractor_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            steps.validate_setup(
                [{"bind": "k", "query": [{"path": "/k"}]}], ["k"]
            )

    def test_an_empty_list_and_a_workflow_are_both_refused(self) -> None:
        with self.assertRaises(ValueError):
            steps.validate_setup([], [])
        with self.assertRaises(ValueError) as refused:
            steps.validate_setup(
                [{"path": f"/s/{index}"}
                 for index in range(steps.MAX_SETUP_REQUESTS + 1)],
                [],
            )
        self.assertIn("at most", str(refused.exception))
        steps.validate_setup(
            [{"path": f"/s/{index}"} for index in range(steps.MAX_SETUP_REQUESTS)],
            [],
        )

    def test_a_normalised_list_validates_again_unchanged(self) -> None:
        """Saving one and handing it back is the ordinary thing to do with it."""
        once = steps.validate_setup(
            [{"path": "/lab/seed", "body": {"a": 1}},
             {"bind": "k", "query": [{"path": "/k"}], "extract": {"regex": "k=(\\w+)"}}],
            ["k"],
        )
        self.assertEqual(steps.validate_setup(once, ["k"]), once)


def _binding(name: str, path: str = "/k") -> dict[str, Any]:
    """The smallest binding step: one request, one value read out of it."""
    return {"bind": name, "query": [{"path": path}],
            "extract": {"json_values": "key"}}


class ASetupStepUsesOnlyWhatAnEarlierStepBoundTests(unittest.TestCase):
    """Ordering, which the membership check on its own cannot see.

    A bound name must also be a declared input, so a reference to a name the
    *next* step binds is spelled exactly like a reference to an input the
    operator supplies -- and the set of known names was built once before the
    loop, so both read as known. The runner fills left to right, so the first
    of the two goes out as the literal {{name}}: a request that validated
    clean and seeds nothing. The discover chain in field.py has always
    refused this and grew its bound set per step; this grammar did not.
    """

    def test_a_reference_to_a_name_a_later_step_binds_is_refused(self) -> None:
        with self.assertRaises(ValueError) as refused:
            steps.validate_setup(
                [{"method": "POST", "path": "/lab/seed",
                  "headers": {"Authorization": "Bearer {{admin_key}}"}},
                 _binding("admin_key", "/lab/admin-key")],
                ["admin_key"],
            )
        message = str(refused.exception)
        self.assertIn("setup[0]", message)
        self.assertIn("admin_key", message)
        self.assertIn("binds at or after this step", message)

    def test_the_same_reference_to_an_earlier_bind_is_accepted(self) -> None:
        """The one difference is the order, so the order is what is refused."""
        out = steps.validate_setup(
            [_binding("admin_key", "/lab/admin-key"),
             {"method": "POST", "path": "/lab/seed",
              "headers": {"Authorization": "Bearer {{admin_key}}"}}],
            ["admin_key"],
        )
        self.assertEqual(out[1]["headers"]["Authorization"], "Bearer {{admin_key}}")

    def test_a_binding_step_cannot_use_the_name_it_is_about_to_bind(self) -> None:
        """Its own query runs before its extractor reads anything."""
        with self.assertRaises(ValueError) as refused:
            steps.validate_setup([_binding("k", "/k/{{k}}")], ["k"])
        self.assertIn("binds at or after this step", str(refused.exception))

    def test_a_declared_input_no_step_binds_stays_usable_in_any_step(self) -> None:
        """The ordinary case, and the one the ordering rule must not break.

        An input the operator supplies is bound before the first step runs.
        Only a name setup itself binds has a position to be early of.
        """
        steps.validate_setup(
            [{"path": "/lab/seed", "headers": {"X-Tenant": "{{tenant}}"}},
             {"path": "/lab/seed/{{tenant}}"}],
            ["tenant"],
        )

    def test_the_inputs_rule_is_untouched_by_the_ordering_rule(self) -> None:
        """A bind still has to be declared, which is why ordering is checked."""
        with self.assertRaises(ValueError) as refused:
            steps.validate_setup([_binding("admin_key")], [])
        self.assertIn("also be declared in inputs", str(refused.exception))

    def test_rebinding_a_name_is_refused_as_the_sibling_grammar_does(self) -> None:
        with self.assertRaises(ValueError) as refused:
            steps.validate_setup(
                [_binding("k", "/first"), _binding("k", "/second")], ["k"]
            )
        self.assertIn("setup[1].bind", str(refused.exception))
        self.assertIn("already bound", str(refused.exception))
        # The same words, for the same refusal, in the chain this followed.
        with self.assertRaises(ValueError) as sibling:
            field._validate_discover([
                {"bind": "k", "query": [{"path": "/first"}],
                 "extract": {"status": True}},
                {"bind": "k", "query": [{"path": "/second"}],
                 "extract": {"status": True}},
            ])
        self.assertIn("already bound", str(sibling.exception))


class WhatAnExtractorMayDoTests(unittest.TestCase):
    def test_each_of_the_four_is_accepted(self) -> None:
        for value, expected in (
            ({"json_values": "key"}, {"json_values": "key"}),
            ({"regex": "k=(\\w+)"}, {"regex": "k=(\\w+)"}),
            ({"header": " Location "}, {"header": "Location"}),
            ({"status": True}, {"status": True}),
        ):
            with self.subTest(value=value):
                self.assertEqual(steps.validate_extractor(value), expected)

    def test_it_has_to_be_exactly_one_of_them(self) -> None:
        for value in (None, {}, [], {"json_values": "a", "regex": "b"}, {"nope": 1}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    steps.validate_extractor(value)

    def test_an_empty_name_and_a_broken_pattern_are_refused(self) -> None:
        for value in ({"json_values": ""}, {"header": "  "}, {"regex": "("},
                      {"status": False}, {"status": 1}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    steps.validate_extractor(value)


class WhatADeclaredInputMayBeTests(unittest.TestCase):
    def test_absent_is_none_declared(self) -> None:
        self.assertEqual(steps.validate_inputs(None), [])

    def test_a_name_is_a_letter_then_letters_digits_or_underscores(self) -> None:
        self.assertEqual(
            steps.validate_inputs(["admin_key", "oauthState", "A1"]),
            ["admin_key", "oauthState", "A1"],
        )
        for name in ("1st", "_lead", "has-a-dash", "a" * 33, ""):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    steps.validate_inputs([name])

    def test_the_tokens_the_run_fills_in_cannot_be_redefined(self) -> None:
        for name in ("marker", "callback", *steps.TARGET_TOKENS):
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as refused:
                    steps.validate_inputs([name])
                self.assertIn("cannot redefine", str(refused.exception))

    def test_one_name_declared_twice_is_refused(self) -> None:
        """Two slots for one value, and no test on inputs can see it.

        validate_setup asks `name not in set(inputs)`, which a duplicate
        answers exactly as a single declaration does, so a spec that meant
        two values would validate and then send one answer in both places.
        """
        with self.assertRaises(ValueError) as refused:
            steps.validate_inputs(["admin_key", "admin_key"])
        self.assertIn("twice", str(refused.exception))
        self.assertIn("admin_key", str(refused.exception))
        # Names that merely share a prefix are two names, not a duplicate.
        self.assertEqual(
            steps.validate_inputs(["admin_key", "admin_key2"]),
            ["admin_key", "admin_key2"],
        )

    def test_a_duplicate_cannot_buy_its_way_under_the_cap(self) -> None:
        """Eight slots are eight values, not eight mentions."""
        with self.assertRaises(ValueError):
            steps.validate_inputs(["k"] * steps.MAX_INPUTS)

    def test_more_than_the_cap_is_refused(self) -> None:
        over = [f"n{index}" for index in range(steps.MAX_INPUTS + 1)]
        with self.assertRaises(ValueError):
            steps.validate_inputs(over)
        self.assertEqual(len(steps.validate_inputs(over[:-1])), steps.MAX_INPUTS)


class WhatOneRequestMayBeTests(unittest.TestCase):
    def test_a_path_starts_with_a_slash_or_a_substitution(self) -> None:
        self.assertEqual(steps.validate_request({"path": "/a"}, "x")["path"], "/a")
        self.assertEqual(
            steps.validate_request({"path": "{{route}}/a"}, "x")["path"], "{{route}}/a"
        )
        with self.assertRaises(ValueError) as refused:
            steps.validate_request({"path": "https://elsewhere/a"}, "x")
        self.assertIn("must start with /", str(refused.exception))

    def test_a_substitution_a_path_opens_has_to_be_a_whole_name(self) -> None:
        """The exception is a route the operator names, not an open brace.

        The rule was spelled startswith("{{"), which the bare string "{{"
        satisfies, and setup could not catch it either: there is no name
        inside it to be reported missing. Nothing would notice until the
        shipped script refused "request path must be relative" at run time,
        on a path no substitution could ever have filled.
        """
        for path in ("{{", "{{}}", "{{route", "{{1st}}", "{{a-b}}", "x{{route}}"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError) as refused:
                    steps.validate_request({"path": path}, "x")
                self.assertIn("must start with /", str(refused.exception))
        with self.assertRaises(ValueError):
            steps.validate_setup([{"path": "{{"}], [])
        # A whole name still passes, alone or with a route after it.
        for path in ("{{route}}", "{{route}}/a", "{{oauthState}}?a=1"):
            with self.subTest(path=path):
                self.assertEqual(
                    steps.validate_request({"path": path}, "x")["path"], path
                )

    def test_a_json_body_is_serialised_to_the_one_string_that_is_sent(self) -> None:
        self.assertEqual(
            steps.validate_request({"path": "/a", "body": {"k": [1, 2]}}, "x")["body"],
            '{"k": [1, 2]}',
        )
        with self.assertRaises(ValueError):
            steps.validate_request({"path": "/a", "body": 7}, "x")

    def test_a_request_carries_a_body_or_an_upload_and_not_both(self) -> None:
        with self.assertRaises(ValueError) as refused:
            steps.validate_request(
                {"path": "/a", "body": "x",
                 "upload": [{"name": "f", "text": "t"}]}, "x",
            )
        self.assertIn("not both", str(refused.exception))

    def test_an_upload_part_is_a_form_field_or_exactly_one_kind_of_file(self) -> None:
        built = steps.validate_request(
            {"path": "/a", "method": "POST", "upload": [
                {"name": "note", "value": "hello"},
                {"name": "f", "filename": "r.dat", "tar_gz": {"a/b": "text"}},
            ]}, "x",
        )["upload"]
        self.assertEqual(built[0], {"name": "note", "value": "hello"})
        self.assertEqual(built[1]["kind"], "tar_gz")
        self.assertEqual(built[1]["filename"], "r.dat")
        for part in ({"name": "f"},
                     {"name": "f", "text": "t", "zip": {"a": "b"}},
                     {"name": "f", "base64": "!!"},
                     {"name": "f", "base64": steps.MARKER_TOKEN}):
            with self.subTest(part=part):
                with self.assertRaises(ValueError):
                    steps.validate_request({"path": "/a", "upload": [part]}, "x")


class TheRecordedSpecsStillPassTheMovedValidatorsTests(unittest.TestCase):
    """The specs a model has actually written, through the module directly.

    tests/fixtures/recorded-specs.json is the same corpus validate_spec is
    held to. Here the moved validators are called on their own, so a change
    to one of them is caught even if the field mode stopped calling it.
    """

    def _recorded(self) -> list[tuple[str, dict[str, Any]]]:
        held = Path(__file__).parent / "fixtures" / "recorded-specs.json"
        return [(row["from"], row["spec"]) for row in json.loads(held.read_text())]

    def test_their_inputs_and_setup_steps_still_validate(self) -> None:
        for where, spec in self._recorded():
            with self.subTest(spec=where):
                declared = steps.validate_inputs(spec.get("inputs"))
                if spec.get("setup") is not None:
                    once = steps.validate_setup(spec["setup"], declared)
                    self.assertEqual(steps.validate_setup(once, declared), once)

    def test_their_requests_and_extractors_still_validate(self) -> None:
        for where, spec in self._recorded():
            with self.subTest(spec=where):
                for check in spec.get("checks") or [spec]:
                    for key in ("probe", "control", "baseline", "observe"):
                        if check.get(key) is not None and spec.get("transport", "http") == "http":
                            steps.validate_sequence(check[key], f"{where}.{key}")
                    if check.get("extract") is not None:
                        steps.validate_extractor(check["extract"])

    def test_the_corpus_is_still_the_answers_it_was(self) -> None:
        """So an emptied fixture cannot make the two checks above vacuous."""
        self.assertGreaterEqual(len(self._recorded()), 9)


class HowASequenceIsValidatedTests(unittest.TestCase):
    def test_the_default_entry_is_an_http_request(self) -> None:
        self.assertEqual(
            steps.validate_sequence([{"path": "/a"}], "spec.query"),
            [{"method": "GET", "path": "/a", "headers": {}, "body": None}],
        )

    def test_an_empty_list_and_an_over_long_one_are_refused(self) -> None:
        for value in (None, [], "x",
                      [{"path": "/a"}] * (steps.MAX_REQUESTS + 1)):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    steps.validate_sequence(value, "spec.query")

    def test_a_caller_may_bring_its_own_entry_validator(self) -> None:
        """Which is how the field mode keeps its socket transports."""
        seen: list[str] = []

        def one(item: Any, at: str) -> dict[str, Any]:
            seen.append(at)
            return {"saw": item}

        self.assertEqual(
            steps.validate_sequence(["a", "b"], "spec.probe", one),
            [{"saw": "a"}, {"saw": "b"}],
        )
        self.assertEqual(seen, ["spec.probe[0]", "spec.probe[1]"])


class _Seeding(BaseHTTPRequestHandler):
    """A seeding route that hands its key back in a header.

    The shape a header bind exists for: a value the lab generates per boot,
    so no fixed lab value can stand in for it, returned where a token
    usually is rather than in a JSON body.
    """

    protocol_version = "HTTP/1.1"
    key = "fresh-per-boot-7f3"
    #: The name as the server spells it, which is not how the spec asks for
    #: it. A header name is case-insensitive and servers disagree in
    #: practice, so the runner has to match the way the rest of the mode does.
    key_header = "x-admin-token"
    refuse = False
    seen: list[tuple[str, dict[str, str]]] = []

    def log_message(self, *_args: Any) -> None:
        pass

    def _answer(self) -> None:
        type(self).seen.append((self.path, dict(self.headers)))
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        if self.path == "/lab/session":
            self.send_response(403 if self.refuse else 200)
            self.send_header(self.key_header, self.key)
        else:
            self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _answer
    do_POST = _answer


class TheSetupBoundCountsWhatItSaysItCountsTests(unittest.TestCase):
    """The bound is named for requests and its docstring justifies itself in
    requests, but it counted entries, and a binding entry holds a whole
    sequence. Ten entries each carrying the per-sequence maximum validated
    clean and would have sent 250 requests -- the workflow the bound exists
    to refuse, twenty-five times over.
    """

    def test_ten_full_sequences_are_refused(self) -> None:
        entry = {
            "bind": "k",
            "query": [{"path": f"/r{i}"} for i in range(steps.MAX_REQUESTS)],
            "extract": {"status": True},
        }
        spec = [dict(entry, bind=f"k{i}") for i in range(steps.MAX_SETUP_REQUESTS)]
        names = [f"k{i}" for i in range(steps.MAX_SETUP_REQUESTS)]
        with self.assertRaises(ValueError) as caught:
            steps.validate_setup(spec, names)
        self.assertIn("250 requests", str(caught.exception))

    def test_seeding_that_really_is_seeding_still_validates(self) -> None:
        """The fix must not make the ordinary shape unusable: a bind that
        needs a couple of requests to reach the value, then a step that uses
        it.
        """
        spec = [
            {"bind": "token", "query": [{"path": "/login"}, {"path": "/csrf"}],
             "extract": {"header": "X-CSRF"}},
            {"method": "POST", "path": "/seed", "headers": {"X-CSRF": "{{token}}"}},
        ]
        out = steps.validate_setup(spec, ["token"])
        self.assertEqual(len(out), 2)

    def test_the_request_total_is_what_is_counted_not_the_entries(self) -> None:
        """Two entries, eleven requests between them: under the entry count,
        over the bound. This is the case the old check could not see.
        """
        spec = [
            {"bind": "k", "query": [{"path": f"/r{i}"} for i in range(10)],
             "extract": {"status": True}},
            {"path": "/one-too-many"},
        ]
        with self.assertRaises(ValueError) as caught:
            steps.validate_setup(spec, ["k"])
        self.assertIn("11 requests", str(caught.exception))


class ASetupStepBindsFromAResponseHeaderTests(unittest.TestCase):
    """The fourth extractor, through the runner that has to honour it.

    validate_setup has accepted all four of EXTRACTORS since header was
    added for the two labs that were unprovable without it, and the runner
    dispatched on three. So a spec declaring extract.header validated clean
    and then failed with "nothing to bind from the response" -- a refusal
    that blames the response for a branch that was not written.

    The runner lives in field.py because running the steps needs a route to
    the lab, so this drives the real program in a subprocess against a
    loopback server, which is what the sidecar does with a container.
    """

    def setUp(self) -> None:
        _Seeding.seen = []
        _Seeding.refuse = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Seeding)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def _run(self, setup: list[dict[str, Any]]) -> tuple[int, dict[str, Any], str]:
        done = subprocess.run(
            [sys.executable, "-c", field._SETUP_RUNNER],
            cwd=REPO, capture_output=True, text=True, timeout=120,
            env=dict(
                os.environ,
                CVELAB_BASE=f"http://127.0.0.1:{self.server.server_port}",
                CVELAB_SETUP=json.dumps(setup),
                CVELAB_INPUTS="{}",
            ),
        )
        tail = done.stdout.strip().splitlines()[-1:] or [""]
        try:
            reported = json.loads(tail[0])
        except json.JSONDecodeError:
            reported = {}
        return done.returncode, reported, done.stdout + done.stderr

    def _spec(self, asked_for: str) -> list[dict[str, Any]]:
        """Validated here, so the runner is handed what the grammar emits."""
        return steps.validate_setup(
            [
                {"bind": "admin_key", "query": [{"path": "/lab/session"}],
                 "extract": {"header": asked_for}},
                {"method": "POST", "path": "/lab/seed",
                 "headers": {"Authorization": "Bearer {{admin_key}}"}},
            ],
            steps.validate_inputs(["admin_key"]),
        )

    def test_the_value_is_read_out_and_filled_into_what_follows(self) -> None:
        code, reported, output = self._run(self._spec("X-Admin-Token"))
        self.assertEqual(code, 0, output)
        self.assertEqual(reported["bound"], {"admin_key": _Seeding.key})
        self.assertEqual(
            [(row["method"], row["path"], row["status"]) for row in reported["requests"]],
            [("GET", "/lab/session", 200), ("POST", "/lab/seed", 201)],
        )
        asked = [headers for path, headers in _Seeding.seen if path == "/lab/seed"]
        self.assertEqual(asked[0]["Authorization"], f"Bearer {_Seeding.key}")

    def test_the_name_is_matched_whatever_its_case(self) -> None:
        """The server sends x-admin-token; three spellings have to find it."""
        for asked_for in ("X-Admin-Token", "x-admin-token", "X-ADMIN-TOKEN"):
            with self.subTest(asked_for=asked_for):
                _Seeding.seen = []
                code, reported, output = self._run(self._spec(asked_for))
                self.assertEqual(code, 0, output)
                self.assertEqual(reported["bound"], {"admin_key": _Seeding.key})

    def test_a_refusal_is_a_response_and_its_headers_are_read(self) -> None:
        """A 403 that still carries the token is the shape this is for."""
        _Seeding.refuse = True
        code, reported, output = self._run(self._spec("X-Admin-Token"))
        self.assertEqual(code, 0, output)
        self.assertEqual(reported["bound"], {"admin_key": _Seeding.key})
        self.assertEqual(reported["requests"][0]["status"], 403)

    def test_a_header_that_is_not_there_still_says_so(self) -> None:
        """The old failure, which is the right one when the header is absent."""
        code, reported, output = self._run(self._spec("X-Absent"))
        self.assertEqual(code, 1, output)
        self.assertEqual(reported.get("bind"), "admin_key")
        self.assertIn("nothing to bind", reported.get("error", ""))

    def test_every_extractor_the_grammar_accepts_has_a_branch_in_the_runner(self) -> None:
        """The gap this closes, stated so a fifth extractor cannot repeat it."""
        for name in steps.EXTRACTORS:
            with self.subTest(extractor=name):
                self.assertIn(f"'{name}' in taken", field._SETUP_RUNNER)


if __name__ == "__main__":
    unittest.main()
