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

"""Docker gets what it needs from the environment, and no secrets.

Compose interpolates `${VAR}` from the environment it runs in. When that was
all of os.environ, `args: {K: "${ANTHROPIC_API_KEY}"}` in a generated lab put
the real key into a build with network access.
"""

from __future__ import annotations

import os
import unittest
import unittest.mock as mock

from cvelab.core import docker_environment

SECRETS = {
    "ANTHROPIC_API_KEY": "sk-ant-secret-000000000000",
    "OPENAI_API_KEY": "sk-secret-000000000000",
    "DEEPSEEK_API_KEY": "sk-secret-000000000001",
    "CVELAB_TOKEN": "cvelab_secret_0000000000",
    "GITHUB_TOKEN": "ghp_secret0000000000000",
    "AWS_SECRET_ACCESS_KEY": "aws-secret-0000000000",
}

NEEDED = {
    "PATH": "/usr/bin",
    "HOME": "/home/user",
    "USER": "user",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TMPDIR": "/tmp",
    "XDG_RUNTIME_DIR": "/run/user/1000",
    "DOCKER_HOST": "unix:///run/user/1000/docker.sock",
    "DOCKER_CONTEXT": "rootless",
    "DOCKER_CONFIG": "/home/user/.docker",
    "DOCKER_CERT_PATH": "/certs",
    "DOCKER_TLS_VERIFY": "1",
    "DOCKER_BUILDKIT": "1",
    "BUILDKIT_PROGRESS": "plain",
    "BUILDX_BUILDER": "lab",
    "COMPOSE_BAKE": "false",
    "HTTPS_PROXY": "http://proxy:3128",
    "http_proxy": "http://proxy:3128",
    "NO_PROXY": "localhost",
}


class DockerEnvironmentTests(unittest.TestCase):
    def environment(self, extra: dict[str, str]) -> dict[str, str]:
        with mock.patch.dict("os.environ", {**NEEDED, **extra}, clear=True):
            return docker_environment("/usr/bin/docker")

    def test_no_secret_reaches_docker(self) -> None:
        environment = self.environment(SECRETS)
        for name in SECRETS:
            self.assertNotIn(name, environment)
        for value in SECRETS.values():
            self.assertNotIn(value, "".join(environment.values()))

    def test_what_docker_needs_is_kept(self) -> None:
        environment = self.environment({})
        if os.name == "nt":
            # Windows environment names are case-insensitive and os.environ
            # hands them back upper-cased: http_proxy arrives as HTTP_PROXY.
            environment = {name.upper(): value for name, value in environment.items()}
        for name in NEEDED:
            if name == "PATH" or (os.name == "nt" and name in {"DOCKER_HOST", "DOCKER_CONTEXT", "COMPOSE_BAKE", "BUILDX_BUILDER"}):
                continue
            with self.subTest(name=name):
                key = name.upper() if os.name == "nt" else name
                self.assertEqual(environment[key], NEEDED[name])

    def test_the_docker_binary_directory_leads_path(self) -> None:
        environment = self.environment({})
        self.assertTrue(environment["PATH"].endswith(os.pathsep + "/usr/bin"))

    def test_nothing_that_adds_compose_files_is_passed(self) -> None:
        environment = self.environment({
            "COMPOSE_FILE": "/elsewhere/evil.yml",
            "COMPOSE_ENV_FILES": "/home/user/.config/cvelab/token",
            "COMPOSE_PATH_SEPARATOR": ":",
            "COMPOSE_EXPERIMENTAL_GIT_REMOTE": "1",
            "COMPOSE_EXPERIMENTAL_OCI_REMOTE": "1",
        })
        for name in ("COMPOSE_FILE", "COMPOSE_ENV_FILES", "COMPOSE_PATH_SEPARATOR",
                     "COMPOSE_EXPERIMENTAL_GIT_REMOTE", "COMPOSE_EXPERIMENTAL_OCI_REMOTE"):
            self.assertNotIn(name, environment)

    def test_the_lab_env_file_is_switched_off(self) -> None:
        # A lab's .env could set COMPOSE_* for Compose itself, and values to
        # interpolate; it is the lab's input, not the user's configuration.
        environment = self.environment({"COMPOSE_DISABLE_ENV_FILE": "0"})
        self.assertEqual(environment["COMPOSE_DISABLE_ENV_FILE"], "1")

    def test_an_unrelated_variable_is_dropped(self) -> None:
        self.assertNotIn("EDITOR", self.environment({"EDITOR": "vim", "DBUS_SESSION_BUS_ADDRESS": "x"}))


if __name__ == "__main__":
    unittest.main()
