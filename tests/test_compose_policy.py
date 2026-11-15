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

"""A lab's Compose file is checked on what Docker will run, not on its text.

The old checks were substrings: "privileged:", "internal: true". A quoted
key, flow style, a second network, a service with no networks: at all, or
"internal: true" in a comment all passed. The models below have the shape
`docker compose config --format json --no-env-resolution` produces, taken
from Compose 5.5.1; DockerComposeTests runs the real thing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock as mock
import urllib.request
from pathlib import Path

import pytest
from cvelab import policy
from cvelab.core import (
    CPU_PERIOD,
    compose_command,
    docker_environment,
    run_lab,
    runtime_flags,
    runtime_limits,
)

LAB = Path(tempfile.gettempdir()) / "labs" / "CVE-2026-0001"


def service(**extra) -> dict:
    """A service the way the generator writes one, after resolution."""
    value = {
        "build": {"context": str(LAB), "dockerfile": "vulnerable/Dockerfile"},
        "command": None,
        "entrypoint": None,
        "networks": {"lab": None},
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        "user": "10001:10001",
        "healthcheck": {"test": ["CMD", "true"], "interval": "2s"},
    }
    value.update(extra)
    return value


def model(**services) -> dict:
    return {
        "name": "cve-2026-0001",
        "networks": {"lab": {"name": "cve-2026-0001_lab", "ipam": {}, "internal": True}},
        "services": services or {
            "vulnerable": service(),
            "patched": service(build={"context": str(LAB), "dockerfile": "patched/Dockerfile"}),
            "validator": service(
                build={"context": str(LAB / "validator"), "dockerfile": "Dockerfile"},
                profiles=["tools"],
                environment={"CVELAB_MANUAL_ACTION": "", "CVELAB_TARGET": ""},
                depends_on={"vulnerable": {"condition": "service_healthy", "required": True}},
            ),
        },
    }


class ModelPolicyTests(unittest.TestCase):
    def problems(self, value: dict) -> list[str]:
        return policy.check_model(value, LAB)

    def assertRefused(self, value: dict, *fragments: str) -> None:
        found = "\n".join(self.problems(value))
        self.assertTrue(found, "expected the model to be refused")
        for fragment in fragments:
            self.assertIn(fragment, found)

    def test_an_honest_lab_passes(self) -> None:
        self.assertEqual(self.problems(model()), [])

    def test_privileged_is_refused_however_it_was_spelled(self) -> None:
        # `"privileged": true`, flow style and a merge key all resolve to this.
        self.assertRefused(model(vulnerable=service(privileged=True)), "service 'vulnerable'", "privileged")

    def test_host_namespaces_and_mounts_are_refused(self) -> None:
        for key, value in (
            ("network_mode", "host"), ("pid", "host"), ("ipc", "host"), ("uts", "host"),
            ("userns_mode", "host"), ("cgroup", "host"), ("cgroup_parent", "x"),
            ("volumes", [{"type": "bind", "source": "/", "target": "/host"}]),
            ("volumes_from", ["other"]), ("ports", [{"target": 80, "published": "8080"}]),
            ("cap_add", ["SYS_ADMIN"]), ("devices", [{"source": "/dev/kvm"}]),
            ("device_cgroup_rules", ["a *:* rwm"]), ("extra_hosts", ["a=1.2.3.4"]),
            ("dns", ["1.1.1.1"]), ("dns_search", ["x"]), ("dns_opt", ["x"]),
            ("runtime", "runc"), ("gpus", [{"count": -1}]), ("sysctls", {"a": "1"}),
            ("env_file", [{"path": "/home/u/.config/cvelab/token"}]),
            ("label_file", ["/etc/hostname"]), ("secrets", [{"source": "s"}]),
            ("configs", [{"source": "c"}]), ("use_api_socket", True),
            ("provider", {"type": "x"}), ("post_start", [{"command": "id", "privileged": True}]),
            ("logging", {"driver": "syslog"}), ("develop", {"watch": []}),
            ("external_links", ["db"]), ("oom_score_adj", -1000), ("something_new", 1),
        ):
            with self.subTest(key=key):
                self.assertRefused(model(vulnerable=service(**{key: value})), "service 'vulnerable'", key)

    def test_a_service_off_the_internal_network_is_refused(self) -> None:
        # No networks: at all puts a service on `default`, the ordinary bridge.
        loose = model(vulnerable=service(networks={"default": None}))
        loose["networks"]["default"] = {"name": "cve-2026-0001_default", "ipam": {}}
        self.assertRefused(loose, "joins the default network")

    def test_a_default_network_declared_internal_is_fine(self) -> None:
        value = model(vulnerable=service(networks={"default": None}))
        value["networks"] = {"default": {"name": "cve-2026-0001_default", "ipam": {}, "internal": True}}
        self.assertEqual(self.problems(value), [])

    def test_a_second_network_must_be_internal_too(self) -> None:
        value = model(vulnerable=service(networks={"lab": None, "out": None}))
        value["networks"]["out"] = {"name": "cve-2026-0001_out", "ipam": {}}
        self.assertRefused(value, "network 'out': must declare internal: true", "joins network 'out'")

    def test_internal_in_a_comment_is_not_internal(self) -> None:
        value = model()
        del value["networks"]["lab"]["internal"]
        self.assertRefused(value, "network 'lab': must declare internal: true")

    def test_external_named_and_foreign_driver_networks_are_refused(self) -> None:
        for change, fragment in (
            ({"external": True}, "external"),
            ({"name": "bridge"}, "may not set its own name"),
            ({"driver": "host"}, "driver 'host'"),
            ({"driver_opts": {"x": "y"}}, "driver_opts"),
            ({"ipam": {"driver": "other"}}, "ipam driver"),
        ):
            with self.subTest(change=change):
                value = model()
                value["networks"]["lab"].update(change)
                self.assertRefused(value, fragment)

    def test_an_ipam_subnet_and_bridge_driver_are_fine(self) -> None:
        value = model()
        value["networks"]["lab"].update(
            driver="bridge", ipam={"config": [{"subnet": "10.77.0.0/24"}]}
        )
        self.assertEqual(self.problems(value), [])

    def test_a_build_must_stay_inside_the_lab(self) -> None:
        for build, fragment in (
            ({"context": str(LAB.parent.parent)}, "outside the lab directory"),
            ({"context": "https://github.com/x/y.git"}, "must be a directory inside the lab"),
            ({"context": "git@github.com:x/y.git"}, "must be a directory inside the lab"),
            ({"context": str(LAB), "dockerfile": "../../../etc/passwd"}, "outside its build context"),
            ({"context": str(LAB), "dockerfile": "/etc/passwd"}, "outside its build context"),
        ):
            with self.subTest(build=build):
                self.assertRefused(model(vulnerable=service(build=build)), "service 'vulnerable' build", fragment)

    def test_build_features_that_reach_the_host_are_refused(self) -> None:
        for key, value in (
            ("additional_contexts", {"x": "/"}), ("dockerfile_inline", "FROM alpine"),
            ("network", "host"), ("ssh", ["default"]), ("secrets", [{"source": "s"}]),
            ("extra_hosts", ["a=1"]), ("privileged", True), ("entitlements", ["network.host"]),
            ("cache_from", ["type=local,src=/"]), ("cache_to", ["type=local,dest=/"]),
        ):
            with self.subTest(key=key):
                build = {"context": str(LAB), "dockerfile": "vulnerable/Dockerfile", key: value}
                self.assertRefused(model(vulnerable=service(build=build)), "build", key)

    def test_build_args_are_fine(self) -> None:
        build = {"context": str(LAB), "dockerfile": "vulnerable/Dockerfile", "args": {"SOURCE_DIR": "x"}}
        self.assertEqual(self.problems(model(vulnerable=service(build=build))), [])

    def test_only_no_new_privileges_is_a_security_option(self) -> None:
        for option in ("seccomp=unconfined", "apparmor:unconfined", "label=disable",
                       "label:disable", "systempaths=unconfined", "label=type:spc_t",
                       "seccomp=/host/profile.json"):
            with self.subTest(option=option):
                self.assertRefused(model(vulnerable=service(security_opt=[option])), option)
        for option in ("no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"):
            with self.subTest(option=option):
                self.assertEqual(self.problems(model(vulnerable=service(security_opt=[option]))), [])

    def test_top_level_volumes_secrets_and_configs_are_refused(self) -> None:
        for key in ("volumes", "secrets", "configs", "models"):
            with self.subTest(key=key):
                value = model()
                value[key] = {"x": {"file": "/etc/hostname"}}
                self.assertRefused(value, f"top level: {key}")

    def test_deploy_may_bound_resources_but_not_reserve_devices(self) -> None:
        bounded = service(deploy={"resources": {"limits": {"memory": "1073741824"}}, "placement": {}})
        self.assertEqual(self.problems(model(vulnerable=bounded)), [])
        gpu = service(deploy={"resources": {"reservations": {"devices": [{"capabilities": ["gpu"]}]}}})
        self.assertRefused(model(vulnerable=gpu), "devices")

    def test_extension_fields_are_inert(self) -> None:
        value = model(vulnerable=service(**{"x-note": "anything"}))
        value["x-common"] = {"privileged": True}
        self.assertEqual(self.problems(value), [])

    def test_every_problem_is_reported_at_once(self) -> None:
        # One repair attempt can fix all of them.
        found = self.problems(model(vulnerable=service(privileged=True, ports=[{"target": 1}])))
        self.assertEqual(len(found), 2)


class SourcePolicyTests(unittest.TestCase):
    """What `config` merges away has to be refused in the raw text."""

    def test_include_and_extends_are_refused(self) -> None:
        for text in (
            "include:\n  - ../other.yml\nservices: {}\n",
            '"include": [../other.yml]\n',
            "services:\n  a:\n    extends: {file: /etc/x.yml, service: b}\n",
            "x-a: &a include\n*a : [x.yml]\n",
            "'include' : [x.yml]\n",
            "&top include: [x.yml]\n",
            "!!str include: [x.yml]\n",
            "{services: {}, include: [x.yml]}\n",
            "[include: x.yml]\n",
            '{\n  "include": ["x.yml"]\n}\n',
            "services:\n  a:\n    - extends: b\n",
            "services:\n  a: {image: x, extends: {service: b}}\n",
        ):
            with self.subTest(text=text):
                problems = policy.check_source(text)
                self.assertTrue(problems)
                self.assertIn("is not allowed", problems[0])

    def test_the_words_elsewhere_are_not_keys(self) -> None:
        # A PHP lab names include files; a comment may say "extends".
        for text in (
            "services:\n  v:\n    command: [php, /app/include.php]\n",
            "# this lab extends the template\nservices: {}\n",
            "services:\n  v:\n    healthcheck:\n      test: curl -f http://v/include/ok\n",
            "services:\n  v:\n    environment:\n      INCLUDE_PATH: /app/include\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(policy.check_source(text), [])

    def test_keys_spelled_without_their_letters_are_refused(self) -> None:
        for text, fragment in (
            ('"\\x69nclude": [x.yml]\n', "escape"),
            ('{"\\u0069nclude": ["x.yml"]}', "escape"),
            ("!!binary aW5jbHVkZQ==: [x.yml]\n", "binary"),
            ('? "inc\\\n  lude"\n: [x.yml]\n', "explicit"),
            ("{? a : b}\n", "explicit"),
        ):
            with self.subTest(text=text):
                self.assertIn(fragment, "\n".join(policy.check_source(text)))

    def test_the_line_is_named(self) -> None:
        self.assertIn("line 3", policy.check_source("services:\n  a:\n    extends: x\n")[0])


class VariablePolicyTests(unittest.TestCase):
    def test_a_host_value_is_refused_and_a_default_is_not(self) -> None:
        variables = {"HOME": {}, "HTTP_PROXY": {}, "CVELAB_TARGET": {"DefaultValue": ""}}
        problems = policy.check_variables(variables, {"HOME", "HTTP_PROXY", "PATH"})
        self.assertEqual(len(problems), 2)
        self.assertIn("${HOME}", problems[0])
        self.assertIn("${HTTP_PROXY}", problems[1])


def completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["docker"], returncode, stdout, "")


class EnforceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.lab = Path(temporary.name) / "CVE-2026-0001"
        self.lab.mkdir()
        (self.lab / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    def fake_compose(self, resolved: dict, variables: dict | None = None, environment: str = ""):
        def run(command, **kwargs):
            if "--variables" in command:
                return completed(json.dumps(variables or {}))
            if "--environment" in command:
                return completed(environment)
            return completed(json.dumps(resolved))
        return run

    def test_every_profile_is_checked_with_env_files_unresolved(self) -> None:
        resolved = model()
        for name, value in resolved["services"].items():
            value["build"]["context"] = str(self.lab / ("validator" if name == "validator" else ""))
        with mock.patch("subprocess.run", side_effect=self.fake_compose(resolved)) as run:
            self.assertEqual(policy.enforce(["docker", "compose"], self.lab, {}), resolved)
        commands = [call.args[0] for call in run.call_args_list]
        for command in commands:
            # The validator sits behind a profile, and `config` hides it otherwise.
            self.assertEqual(command[2:5], ["--profile", "*", "config"])
        self.assertIn("--no-env-resolution", commands[0])

    def test_a_refusal_names_what_failed(self) -> None:
        resolved = model(vulnerable=service(privileged=True))
        resolved["services"]["vulnerable"]["build"]["context"] = str(self.lab)
        with mock.patch("subprocess.run", side_effect=self.fake_compose(resolved, {"HOME": {}}, "HOME=/x\n")):
            with self.assertRaises(policy.PolicyError) as raised:
                policy.enforce(["docker", "compose"], self.lab, {})
        self.assertIn("service 'vulnerable': privileged", str(raised.exception))
        self.assertIn("${HOME}", str(raised.exception))

    def test_include_is_refused_before_compose_opens_anything(self) -> None:
        (self.lab / "docker-compose.yml").write_text("include: [/etc/other.yml]\n", encoding="utf-8")
        with mock.patch("subprocess.run") as run, self.assertRaises(policy.PolicyError):
            policy.enforce(["docker", "compose"], self.lab, {})
        run.assert_not_called()

    def test_a_compose_error_is_a_preflight_failure(self) -> None:
        with mock.patch("subprocess.run", return_value=completed("", 1)):
            with self.assertRaisesRegex(RuntimeError, "Compose preflight failed"):
                policy.enforce(["docker", "compose"], self.lab, {})


class RuntimeLimitTests(unittest.TestCase):
    def test_roomy_defaults(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            limits = runtime_limits()
        self.assertEqual(limits["mem_limit"], "2g")
        self.assertEqual(limits["cpu_quota"], 2 * CPU_PERIOD)
        self.assertEqual(limits["pids_limit"], 1024)

    def test_the_environment_overrides_and_removes_them(self) -> None:
        with mock.patch.dict("os.environ", {
            "CVELAB_RUNTIME_MEMORY": "512m", "CVELAB_RUNTIME_CPUS": "0.5", "CVELAB_RUNTIME_PIDS": "",
        }):
            limits = runtime_limits()
        self.assertEqual(limits, {"mem_limit": "512m", "cpu_period": CPU_PERIOD, "cpu_quota": CPU_PERIOD // 2})

    def test_nonsense_is_refused(self) -> None:
        for variable, value in (
            ("CVELAB_RUNTIME_MEMORY", "lots"), ("CVELAB_RUNTIME_CPUS", "many"),
            ("CVELAB_RUNTIME_CPUS", "0"), ("CVELAB_RUNTIME_CPUS", "inf"), ("CVELAB_RUNTIME_CPUS", "nan"),
            ("CVELAB_RUNTIME_PIDS", "0"), ("CVELAB_RUNTIME_PIDS", "x"),
        ):
            with self.subTest(variable=variable, value=value):
                with mock.patch.dict("os.environ", {variable: value}):
                    with self.assertRaisesRegex(ValueError, variable):
                        runtime_limits()

    def test_cpus_are_bounded_by_quota_not_by_cpus(self) -> None:
        # The daemon refuses `cpus` above the engine's core count; a quota it
        # accepts on any machine.
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertNotIn("cpus", runtime_limits())
            flags = runtime_flags()
        self.assertEqual(
            flags,
            ["--memory", "2g", "--cpu-period", str(CPU_PERIOD), "--cpu-quota", str(2 * CPU_PERIOD),
             "--pids-limit", "1024"],
        )

    def test_only_what_a_service_leaves_unset_is_added(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            limits = runtime_limits()
        value = model(
            vulnerable=service(mem_limit="134217728", cpus=0.5),
            patched=service(deploy={"resources": {"limits": {"memory": "1", "cpus": 1, "pids": 5}}}),
            validator=service(),
        )
        added = policy.limits_override(value, limits)["services"]
        self.assertEqual(added["vulnerable"], {"pids_limit": 1024})
        self.assertNotIn("patched", added)
        self.assertEqual(
            added["validator"],
            {"mem_limit": "2g", "cpu_period": CPU_PERIOD, "cpu_quota": 2 * CPU_PERIOD, "pids_limit": 1024},
        )


class ManualPortTests(unittest.TestCase):
    """The one exception to the `ports` refusal, and the refusal it leaves intact."""

    def override(self, name: str = "vulnerable", port: int = 8080, **services) -> dict:
        return policy.manual_port_override(model(**services), name, port)

    def published(self, **kwargs) -> list[str]:
        return self.override(**kwargs)["services"]["vulnerable"]["ports"]

    def test_the_port_is_published_on_loopback_and_is_ephemeral(self) -> None:
        # No host-side number: the kernel assigns one, so nothing collides
        # and nothing the model wrote chose it.
        self.assertEqual(self.published(), ["127.0.0.1::8080"])
        self.assertEqual(policy.MANUAL_BIND, "127.0.0.1")

    def test_only_that_one_service_is_touched_and_only_the_two_keys(self) -> None:
        # Compose merges this over the lab; anything else here would be
        # CVELab quietly rewriting a service the owner did not ask about.
        # The network is the second key because the first one does nothing
        # without it -- measured on a generated lab, where `ports` alone
        # survived the merge and `compose port vulnerable 8080` still printed
        # ":0" because every network the service had was internal.
        self.assertEqual(
            self.override(),
            {
                "networks": {"cvelab-manual": {
                    "internal": False,
                    "driver_opts": {
                        "com.docker.network.bridge.enable_ip_masquerade": "false"
                    },
                }},
                "services": {"vulnerable": {
                    "networks": {"lab": None, "cvelab-manual": None},
                    "ports": ["127.0.0.1::8080"],
                }},
            },
        )

    def test_the_publishing_network_is_the_only_one_not_internal(self) -> None:
        """What the exception costs, held to what was measured.

        A plain bridge here reached `1.1.1.1:443` and port 80 on the gateway
        of the laptop's own LAN from inside the published build. Without the
        masquerade rule both timed out and the published port still answered
        200, so the option is what keeps the exception one-directional.
        """
        added = self.override()["networks"]["cvelab-manual"]
        self.assertIs(added["internal"], False)
        self.assertEqual(added["driver_opts"], policy.MANUAL_NETWORK_DRIVER_OPTS)
        self.assertEqual(
            policy.MANUAL_NETWORK_DRIVER_OPTS,
            {"com.docker.network.bridge.enable_ip_masquerade": "false"},
        )
        # And the lab's own network is not reshaped on the way past: the
        # override names one network, and it is not the lab's.
        self.assertEqual(list(self.override()["networks"]), [policy.MANUAL_NETWORK])
        self.assertNotIn("lab", self.override()["networks"])

    def test_the_labs_own_networks_are_read_rather_than_assumed(self) -> None:
        """`lab` is this generator's name for it, not a lab's only choice.

        A lab copied from someone else names its network whatever it likes,
        and a service can be on more than one. Compose merges `networks` as a
        mapping -- measured on 5.6.1, which normalises the short list form
        first -- but an override that named only its own network would be
        wrong the moment a Compose version replaced the key instead, so the
        whole set is written.
        """
        value = model(
            vulnerable=service(networks={"frontend": None, "backend": None}),
            patched=service(),
        )
        value["networks"] = {
            "frontend": {"internal": True}, "backend": {"internal": True},
        }
        self.assertEqual(
            policy.manual_port_override(value, "vulnerable", 8080)["services"],
            {"vulnerable": {
                "networks": {"frontend": None, "backend": None, "cvelab-manual": None},
                "ports": ["127.0.0.1::8080"],
            }},
        )

    def test_an_endpoint_the_lab_configured_survives(self) -> None:
        # Copied out of the model whole rather than rewritten as a null,
        # because an alias is how a validator reaches the stand-in endpoint a
        # request-forgery finding is observed through, and losing it reads as
        # a lab that did not reproduce.
        value = model(
            vulnerable=service(networks={"lab": {"aliases": ["upstream.invalid"]}}),
            patched=service(),
        )
        self.assertEqual(
            policy.manual_port_override(value, "vulnerable", 8080)["services"],
            {"vulnerable": {
                "networks": {"lab": {"aliases": ["upstream.invalid"]}, "cvelab-manual": None},
                "ports": ["127.0.0.1::8080"],
            }},
        )

    def test_a_lab_that_claims_the_publishing_name_is_refused(self) -> None:
        # The one thing this override must never do is reshape a network of
        # the lab's. A lab declaring CVELab's name for its own network would
        # have internal: false and a driver option written onto it, so the
        # collision is refused instead of resolved.
        value = model()
        value["networks"][policy.MANUAL_NETWORK] = {"internal": True}
        with self.assertRaises(policy.PolicyError) as raised:
            policy.manual_port_override(value, "vulnerable", 8080)
        self.assertIn(policy.MANUAL_NETWORK, str(raised.exception))
        self.assertIn("internal: false", str(raised.exception))

    def test_any_service_the_lab_defines_may_be_published(self) -> None:
        for name in ("vulnerable", "patched", "validator"):
            with self.subTest(name=name):
                self.assertEqual(
                    policy.manual_port_override(model(), name, 3000)["services"],
                    {name: {
                        "networks": {"lab": None, "cvelab-manual": None},
                        "ports": ["127.0.0.1::3000"],
                    }},
                )

    def test_a_service_the_lab_does_not_define_is_refused(self) -> None:
        with self.assertRaises(policy.PolicyError) as raised:
            self.override(name="database")
        self.assertIn("no service 'database'", str(raised.exception))
        # The refusal names what there is, so the caller can see the typo.
        self.assertIn("vulnerable", str(raised.exception))

    def test_cvelabs_own_injected_service_is_refused(self) -> None:
        # Refused for the reason that applies -- it runs CVELab's program --
        # rather than as a service the lab happens not to define, and
        # refused whether or not it is in the model handed in.
        for value in (model(), model(**{policy.SETUP_SERVICE: service()})):
            with self.subTest(declared=policy.SETUP_SERVICE in value["services"]):
                with self.assertRaises(policy.PolicyError) as raised:
                    policy.manual_port_override(value, policy.SETUP_SERVICE, 8080)
                self.assertIn("is CVELab's own", str(raised.exception))

    def test_a_port_that_is_not_a_port_is_refused(self) -> None:
        for port in (0, -1, 65536, 99999, "8080", 8080.0, None, True, False, [8080]):
            with self.subTest(port=port):
                with self.assertRaises(policy.PolicyError) as raised:
                    policy.manual_port_override(model(), "vulnerable", port)
                self.assertIn("is not a port", str(raised.exception))

    def test_the_edges_of_the_range_are_ports(self) -> None:
        for port in (1, 80, 65535):
            with self.subTest(port=port):
                self.assertEqual(self.published(port=port), [f"127.0.0.1::{port}"])

    def test_the_argument_wins_over_a_disagreeing_expose(self) -> None:
        # expose publishes nothing and is written by almost no lab, so it is
        # the model's note about itself, not evidence. Nothing is refused.
        value = model(vulnerable=service(expose=["9000"]), patched=service(), validator=service())
        self.assertEqual(
            policy.manual_port_override(value, "vulnerable", 8080)["services"],
            {"vulnerable": {
                "networks": {"lab": None, "cvelab-manual": None},
                "ports": ["127.0.0.1::8080"],
            }},
        )

    def test_a_model_written_ports_is_still_refused(self) -> None:
        """The regression that would matter most.

        The exception is a separate override of CVELab's. It must not have
        become a key a lab may write, in any of the spellings Compose
        resolves one to -- including the loopback short form this very
        function emits, which a lab writing it for itself would be choosing
        to publish unattended.
        """
        for declared in (
            ["8080:80"],
            ["127.0.0.1::8080"],
            ["0.0.0.0:8080:8080"],
            ["8000-8010:8000-8010"],
            [{"target": 80, "published": "8080", "host_ip": "127.0.0.1"}],
            [{"target": 80, "published": "8080", "mode": "host"}],
        ):
            with self.subTest(declared=declared):
                problems = policy.check_model(model(vulnerable=service(ports=declared)), LAB)
                self.assertIn("service 'vulnerable': ports is not allowed", "\n".join(problems))
        # And the refusal still says why, in the lab's own vocabulary.
        self.assertEqual(policy.SERVICE_REASONS["ports"], "published host ports")
        self.assertNotIn("ports", policy.SERVICE_KEYS)

    def test_the_override_is_what_enforce_refuses_and_never_sees(self) -> None:
        # Proof the two cannot be reconciled by accident: feed the override
        # back through the lab's own policy and it is refused. It reaches
        # Compose as a second -f, the way the limits do, never as lab text.
        #
        # Both halves of it now, and each for its own reason: the port
        # because `ports` is not a key a lab may write, and the network
        # because every network in a lab's own file must be internal and
        # may not set driver options. A lab that wrote this file's contents
        # into its docker-compose.yml is refused three times over.
        override = self.override()
        merged = model()
        merged["services"]["vulnerable"].update(override["services"]["vulnerable"])
        merged["networks"].update(override["networks"])
        refused = "\n".join(policy.check_model(merged, LAB))
        self.assertIn("service 'vulnerable': ports is not allowed", refused)
        self.assertIn(
            f"network '{policy.MANUAL_NETWORK}': must declare internal: true", refused
        )
        self.assertIn(
            f"network '{policy.MANUAL_NETWORK}': driver_opts is not allowed", refused
        )
        # And the service is refused for being on it, so there is no reading
        # of the lab's own file under which this network is acceptable.
        self.assertIn(
            f"service 'vulnerable': joins network '{policy.MANUAL_NETWORK}', which is "
            "not an internal lab network",
            refused,
        )


class ComposeCommandTests(unittest.TestCase):
    def test_the_project_is_named_after_the_lab_not_the_file(self) -> None:
        # Teardown removes the project's volumes; a `name:` must not be
        # able to point that at one of the user's own projects.
        command = compose_command("docker", Path("/labs/CVE-2026-0001"))
        self.assertEqual(command[2:4], ["-p", "cve-2026-0001"])
        self.assertEqual(command[-1], str(Path("/labs/CVE-2026-0001/docker-compose.yml")))


class RunLabOrderTests(unittest.TestCase):
    """The policy runs before any build, and the limits reach every stage."""

    def test_a_refused_lab_is_never_built(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary) / "CVE-2026-0001"
            lab.mkdir()
            (lab / "plan.json").write_text(json.dumps({"cwe": "CWE-22", "lab_type": "SYNTHETIC_CLASS_LAB"}))
            with mock.patch("cvelab.core.docker_executable", return_value="docker"), \
                    mock.patch("cvelab.core.ensure_docker"), \
                    mock.patch("cvelab.core.policy.enforce", side_effect=policy.PolicyError("refused")), \
                    mock.patch("cvelab.core.run_docker_stage") as stage, \
                    mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(policy.PolicyError, "refused"):
                    run_lab("CVE-2026-0001", Path(temporary), keep=False)
        stage.assert_not_called()
        run.assert_not_called()

    def test_every_stage_gets_the_limits_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lab = Path(temporary) / "CVE-2026-0001"
            lab.mkdir()
            (lab / "plan.json").write_text(json.dumps({"cwe": "CWE-22", "lab_type": "SYNTHETIC_CLASS_LAB"}))
            seen: list[list[str]] = []

            def run(command, **kwargs):
                seen.append(command)
                if "run" in command and "-d" in command:
                    return completed("abc\n")
                if command[1] == "wait":
                    return completed("2\n")
                return completed("{}")

            with mock.patch("cvelab.core.docker_executable", return_value="docker"), \
                    mock.patch("cvelab.core.ensure_docker"), \
                    mock.patch("cvelab.core.policy.enforce", return_value=model()), \
                    mock.patch("cvelab.core.run_docker_stage", side_effect=lambda command, **_: seen.append(command)), \
                    mock.patch("subprocess.run", side_effect=run):
                run_lab("CVE-2026-0001", Path(temporary), keep=False)
            compose_calls = [command for command in seen if command[1] == "compose"]
            self.assertTrue(compose_calls)
            override = compose_calls[0][compose_calls[0].index("-f", 5) + 1]
            for command in compose_calls:
                self.assertIn(override, command, command)
            self.assertIn("down", compose_calls[-1])
            self.assertFalse(Path(override).exists(), "the override is removed after teardown")


@pytest.mark.docker
@unittest.skipUnless(shutil.which("docker"), "needs the Docker CLI")
class DockerComposeTests(unittest.TestCase):
    """Against the installed Compose: what it resolves, the policy sees."""

    def enforce(self, text: str) -> dict:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab = Path(temporary.name) / "CVE-2026-0001"
        lab.mkdir()
        (lab / "docker-compose.yml").write_text(text, encoding="utf-8")
        docker = shutil.which("docker") or "docker"
        return policy.enforce(compose_command(docker, lab), lab, docker_environment(docker))

    def test_spellings_the_substring_checks_missed_are_refused(self) -> None:
        base = "services:\n  vulnerable:\n    image: alpine\n    networks: [lab]\n{extra}networks:\n  lab: {{internal: true}}\n"
        for extra in (
            '    "privileged": true\n',
            '    "volumes": ["/:/host"]\n',
            '    "ports": ["8080:80"]\n',
            "  other:\n    image: alpine\n",
            "    env_file: /etc/hostname\n",
            '    environment: {H: "${HOME}"}\n',
        ):
            with self.subTest(extra=extra):
                with self.assertRaises(policy.PolicyError):
                    self.enforce(base.format(extra=extra))

    def test_the_lab_env_file_is_not_read(self) -> None:
        text = (
            "name: victim\nservices:\n  vulnerable:\n    image: alpine\n"
            "    environment: {A: '${FROM_DOTENV:-default}'}\n    networks: [lab]\n"
            "networks:\n  lab: {internal: true}\n"
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lab = Path(temporary.name) / "CVE-2026-0001"
        lab.mkdir()
        (lab / "docker-compose.yml").write_text(text, encoding="utf-8")
        (lab / ".env").write_text("FROM_DOTENV=leaked\nCOMPOSE_PROJECT_NAME=victim\n", encoding="utf-8")
        docker = shutil.which("docker") or "docker"
        resolved = policy.enforce(compose_command(docker, lab), lab, docker_environment(docker))
        self.assertEqual(resolved["name"], "cve-2026-0001")
        self.assertEqual(resolved["services"]["vulnerable"]["environment"], {"A": "default"})


@pytest.mark.docker
class PublishedPortTests(unittest.TestCase):
    """The defect no assertion about the override could have failed.

    `manual_port_override` emitted a loopback `ports` entry for a service
    whose only network was `internal: true`, and everything checkable about
    it was correct: the entry was in the override, Compose carried it through
    the merge, and `config` resolved it to `{mode: ingress, host_ip:
    127.0.0.1, target: 8080, protocol: tcp}`. Docker then discarded the
    publication at `up` without a word -- `ps` showed `8080/tcp` with no
    mapping, `docker compose port` printed `:0`, and `manual.sh` printed that
    as the address to hand the PoC. Nothing short of starting a container
    could tell, so these start one.
    """

    PROJECT = "cvelab-manual-port-check"
    # Enough of a server to answer once per connection, from an image with no
    # build: busybox nc, reopened in a loop.
    LISTENER = (
        "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 3\\r\\n"
        "Connection: close\\r\\n\\r\\nok\\n' | nc -l -p 8080; done"
    )
    LAB_YAML = (
        "services:\n"
        "  vulnerable:\n"
        "    image: alpine:3.20\n"
        '    command: ["sh", "-c", "' + LISTENER + '"]\n'
        "    networks:\n"
        "      lab:\n"
        "        aliases: [product.canary.local]\n"
        "networks:\n"
        "  lab:\n"
        "    internal: true\n"
    )

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.lab = Path(temporary.name) / "manual-port"
        self.lab.mkdir()
        (self.lab / "docker-compose.yml").write_text(self.LAB_YAML, encoding="utf-8")
        self.docker = shutil.which("docker") or "docker"

    def started(self, override: dict) -> list[str]:
        """The lab up with that override merged, torn down afterwards."""
        path = self.lab / "override.json"
        path.write_text(json.dumps(override), encoding="utf-8")
        command = [
            self.docker, "compose", "-p", self.PROJECT,
            "-f", str(self.lab / "docker-compose.yml"), "-f", str(path),
            "--project-directory", str(self.lab),
        ]
        self.addCleanup(
            subprocess.run, [*command, "down", "--remove-orphans"],
            capture_output=True, timeout=300, check=False,
        )
        done = self.ran(command, "up", "-d")
        self.assertEqual(done.returncode, 0, done.stderr)
        return command

    def ran(self, command: list[str], *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [*command, *arguments], cwd=self.lab, capture_output=True, text=True,
            timeout=300, check=False,
        )

    def resolved(self, command: list[str]) -> dict:
        done = self.ran(command, "config", "--format", "json")
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    def test_the_override_publishes_a_port_the_host_can_reach(self) -> None:
        command = self.started(
            policy.manual_port_override(
                self.resolved([
                    self.docker, "compose", "-p", self.PROJECT,
                    "-f", str(self.lab / "docker-compose.yml"),
                    "--project-directory", str(self.lab),
                ]),
                "vulnerable",
                8080,
            )
        )
        published = self.ran(command, "port", "vulnerable", "8080").stdout.strip()
        # The whole measurement in one line: a host address, with a port the
        # kernel assigned, where `:0` used to be.
        self.assertRegex(published, r"^127\.0\.0\.1:[1-9]\d{3,4}$")
        self.assertIn(f"{published}->8080/tcp", self.ran(command, "ps").stdout)
        answered = ""
        for _ in range(40):
            try:
                with urllib.request.urlopen(f"http://{published}/", timeout=2) as reply:
                    answered = reply.read().decode("utf-8", "replace").strip()
                break
            except OSError:
                time.sleep(0.5)
        self.assertEqual(answered, "ok")
        # The alias the lab declared on its own network is still there: the
        # override copies the endpoint out of the model rather than replacing
        # the key with its own network alone.
        self.assertEqual(
            self.resolved(command)["services"]["vulnerable"]["networks"]["lab"],
            {"aliases": ["product.canary.local"]},
        )

    def test_ports_alone_resolve_correctly_and_publish_nothing(self) -> None:
        """Why the network is in the override, kept measurable.

        This is the override as it was: correct `ports`, no network. If a
        Docker release ever starts publishing for an internal-only service,
        or refusing instead of discarding, this is the test that says so.

        WHAT `port` IS READ FOR, AND WHY NOT THE WHOLE LINE

        It pinned the exact string `:0` and fired on a release that printed
        `invalid IP:0` for the same discarded publication -- the behaviour had
        not changed, only the words Docker uses for "there is no address
        here". So only the port side is read now, which is where the meaning
        is. 0 is the absence of a publication: a release that started
        publishing for an internal-only service would print the host port the
        kernel assigned there, and this fails on that -- the canary's first
        half is intact. A release that refused instead of discarding fails it
        too, from the other direction: `up` above would not have returned 0,
        or `port` prints no address at all and an empty port side does not
        read 0 either. What is given up is only the host side, which has
        already drifted once and says nothing the `ps` line below does not say
        better: that is where "nothing is published" is read, in Docker's own
        mapping column, whatever `port` chooses to call it.
        """
        command = self.started(
            {"services": {"vulnerable": {"ports": [f"{policy.MANUAL_BIND}::8080"]}}}
        )
        self.assertEqual(
            self.resolved(command)["services"]["vulnerable"]["ports"],
            [{"mode": "ingress", "host_ip": "127.0.0.1", "target": 8080, "protocol": "tcp"}],
        )
        published = self.ran(command, "port", "vulnerable", "8080").stdout.strip()
        self.assertEqual(published.rsplit(":", 1)[-1], "0", published)
        self.assertNotIn("->", self.ran(command, "ps").stdout)


if __name__ == "__main__":
    unittest.main()
