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

"""What a lab's Compose file may ask Docker to do.

A generated lab is model output, and a lab copied from someone else is
whatever they wrote; either way docker-compose.yml is untrusted input handed
to a daemon that runs as root. The checks used to be substrings of the raw
text, and YAML has too many spellings for that: a quoted `"privileged":`,
`network_mode: "host"`, flow-style `"volumes": [...]`, a second network that
is not internal, a service with no `networks:` at all (it lands on the
default bridge), and `internal: true` written in a comment all passed.

So the policy is checked on what Docker will actually run: the model
`docker compose config` resolves, with the environment the build and the run
get. It is an allowlist. A key not named below is refused, so a Compose
feature added next year stays refused until someone decides it is safe.

What `config` resolves away, checked against Compose 5.5.1 rather than
assumed:

- `include` and `extends` are merged into the model in every mode, even with
  --no-interpolate --no-normalize --no-path-resolution, and nothing in the
  output says a service came from another file. Both can read Compose and
  .env files anywhere on the host -- `include` takes an `env_file` of its
  own -- so the raw text is refused when it uses them (check_source).
- `env_file` is merged into `environment` and vanishes: a host file such as
  ~/.config/cvelab/token would reach the container looking like a literal.
  --no-env-resolution keeps it as a key, so that is the pass checked.
- `${VAR}` is replaced by its value. `config --variables` names every
  reference and `config --environment` what it resolves against; a reference
  the host would fill is refused, so a lab can interpolate only its own
  defaults, as `${CVELAB_TARGET:-}` does.
- `secrets`, `configs`, `label_file`, `build.additional_contexts`,
  `dockerfile_inline`, a git URL context, and `context: ../../..` (made
  absolute) all survive resolution, and are refused as keys or paths.
- A lab's .env file can set COMPOSE_* variables for Compose itself;
  docker_environment() sets COMPOSE_DISABLE_ENV_FILE so it is never read.
- A service behind a profile -- the validator -- is left out of `config`
  unless `--profile '*'` is passed.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

#: Service keys a lab may use. Everything else is refused.
SERVICE_KEYS = frozenset({
    "attach", "build", "cap_drop", "command", "container_name", "cpu_count",
    "cpu_percent", "cpu_period", "cpu_quota", "cpu_shares", "cpus", "cpuset",
    "depends_on", "deploy", "domainname", "entrypoint", "environment", "expose",
    "group_add", "healthcheck", "hostname", "image", "init", "labels", "links",
    "mem_limit", "mem_reservation", "mem_swappiness", "memswap_limit", "networks",
    "pids_limit", "platform", "profiles", "pull_policy", "read_only", "restart",
    "scale", "security_opt", "shm_size", "stdin_open", "stop_grace_period",
    "stop_signal", "tmpfs", "tty", "ulimits", "user", "working_dir",
})

#: Why the keys a lab is most likely to reach for are refused. Only the
#: wording: a key is refused because it is missing from SERVICE_KEYS.
SERVICE_REASONS = {
    "privileged": "privileged containers",
    "cap_add": "additional Linux capabilities",
    "devices": "host devices",
    "device_cgroup_rules": "host devices",
    "blkio_config": "host block devices",
    "gpus": "host GPUs",
    "runtime": "an alternative container runtime",
    "network_mode": "a network other than the lab's internal one",
    "pid": "the host or another container's PID namespace",
    "ipc": "the host or another container's IPC namespace",
    "uts": "the host UTS namespace",
    "userns_mode": "the host user namespace",
    "cgroup": "the host cgroup namespace",
    "cgroup_parent": "a cgroup outside Docker's",
    "sysctls": "kernel parameters",
    "volumes": "host or shared mounts",
    "volumes_from": "another container's mounts",
    "ports": "published host ports",
    "extra_hosts": "name resolution outside the lab",
    "dns": "name resolution outside the lab",
    "dns_opt": "name resolution outside the lab",
    "dns_search": "name resolution outside the lab",
    "external_links": "containers outside the lab",
    "env_file": "a host file read into the environment",
    "label_file": "a host file read into labels",
    "secrets": "host files or variables passed as secrets",
    "configs": "host files passed as configs",
    "credential_spec": "host credential files",
    "extends": "a service defined in another file",
    "use_api_socket": "the Docker API socket",
    "provider": "a provider service, which runs a host binary",
    "models": "model runners",
    "post_start": "lifecycle hooks, which can run privileged",
    "pre_stop": "lifecycle hooks, which can run privileged",
    "develop": "file sync from the host",
    "logging": "a log driver that can ship output off the lab network",
    "storage_opt": "storage driver options",
    "oom_kill_disable": "exemption from the OOM killer",
    "oom_score_adj": "OOM priority over host processes",
    "annotations": "runtime annotations",
    "isolation": "a different isolation technology",
}

BUILD_KEYS = frozenset({
    "context", "dockerfile", "args", "target", "labels", "no_cache", "pull",
    "shm_size", "platforms", "tags",
})

BUILD_REASONS = {
    "additional_contexts": "extra build contexts, which can name any host directory",
    "dockerfile_inline": "an inline Dockerfile; it must be a file in the lab",
    "network": "a build network other than the default",
    "ssh": "the host's SSH agent",
    "secrets": "host files or variables passed as build secrets",
    "extra_hosts": "name resolution outside the lab",
    "privileged": "a privileged build",
    "entitlements": "build entitlements",
    "cache_from": "a build cache outside the lab",
    "cache_to": "writing a build cache outside the lab",
    "isolation": "a different isolation technology",
}

NETWORK_KEYS = frozenset({
    "name", "internal", "driver", "ipam", "labels", "enable_ipv4", "enable_ipv6", "attachable",
})
NETWORK_REASONS = {"external": "a network CVELab did not create", "driver_opts": "driver options"}
IPAM_KEYS = frozenset({"config", "driver"})
IPAM_POOL_KEYS = frozenset({"subnet", "gateway", "ip_range", "aux_addresses"})
ENDPOINT_KEYS = frozenset({
    "aliases", "ipv4_address", "ipv6_address", "link_local_ips", "priority",
    "gw_priority", "mac_address", "interface_name",
})

DEPLOY_KEYS = frozenset({
    "resources", "restart_policy", "replicas", "placement", "labels", "mode",
    "update_config", "rollback_config", "endpoint_mode",
})
RESOURCE_KEYS = {
    "limits": frozenset({"cpus", "memory", "pids"}),
    "reservations": frozenset({"cpus", "memory"}),
}
RESOURCE_REASONS = {"devices": "host devices or GPUs", "generic_resources": "host devices or GPUs"}

TOP_LEVEL_KEYS = frozenset({"name", "services", "networks"})
TOP_LEVEL_REASONS = {
    "volumes": "named volumes",
    "secrets": "host files or variables passed as secrets",
    "configs": "host files passed as configs",
    "models": "model runners",
    "include": "other Compose files",
}

#: Only no-new-privileges. Every other option loosens confinement --
#: seccomp=unconfined, apparmor=unconfined, label=disable,
#: systempaths=unconfined, label=type:spc_t -- or loads a profile from a host
#: path.
SECURITY_OPT = re.compile(r"no-new-privileges(?:[:=](?:true|false))?", re.IGNORECASE)

# Compose merges these files before anything can be inspected, so their
# names are refused wherever YAML could read them as a key: at the start of
# a line or after a sequence dash, or after `{`, `[` or `,` in a flow
# collection, plain or quoted, behind any anchor or tag. Refusing the bare
# word anywhere refused honest PHP labs too -- `/app/include.php` in a
# healthcheck -- and a key cannot be anywhere else: an implicit key is one
# line, and the forms that are not (explicit `?`, escapes) are refused
# below. An alias used as a key could carry the word from a value, so that
# is refused as well.
_KEY_START = r"(?:^[ \t]*(?:-[ \t]+)*|[{\[,][ \t]*)(?:(?:&\S+|!\S*)[ \t]+)*"
_OTHER_FILES = re.compile(
    _KEY_START + r"""(?:"(include|extends)"|'(include|extends)'|(include|extends))[ \t]*:""",
    re.MULTILINE,
)
_ALIAS_KEY = re.compile(_KEY_START + r"\*\S+[ \t]*:", re.MULTILINE)
# The ways YAML can spell a key without writing it out: hex and Unicode
# escapes in a double-quoted scalar, a base64 !!binary scalar, a verbatim
# tag, and explicit `? key` syntax, the only form a key can span lines in.
_HIDDEN_KEY = (
    (re.compile(r"\\[xuU]"), "a \\x or \\u escape"),
    (re.compile(r"!!binary|tag:yaml\.org,2002:binary|!<"), "a binary or verbatim YAML tag"),
    (re.compile(r"(?m)(?:^[ \t]*(?:-[ \t]+)*|[{,][ \t]*)\?(?:[ \t]|$)"), "an explicit `? key`"),
)


class PolicyError(RuntimeError):
    """The lab asks Docker for something CVELab does not allow."""


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def check_source(text: str) -> list[str]:
    """What the raw docker-compose.yml uses that resolution would hide."""
    problems = []
    for match in _OTHER_FILES.finditer(text):
        word = next(group for group in match.groups() if group)
        problems.append(
            f"docker-compose.yml line {_line(text, match.end())}: '{word}' is not allowed; "
            "Compose merges include and extends files before they can be checked"
        )
    for match in _ALIAS_KEY.finditer(text):
        problems.append(
            f"docker-compose.yml line {_line(text, match.end())}: an alias used as a key is not "
            "allowed; write keys out plainly"
        )
    for pattern, what in _HIDDEN_KEY:
        hidden = pattern.search(text)
        if hidden:
            problems.append(
                f"docker-compose.yml line {_line(text, hidden.start())}: {what} is not allowed; "
                "write keys out plainly"
            )
    return problems


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def _unknown(keys, allowed, reasons: dict[str, str], where: str) -> list[str]:
    problems = []
    for key in sorted(keys):
        if key in allowed or key.startswith("x-"):
            continue
        reason = reasons.get(key)
        problems.append(
            f"{where}: {key} is not allowed" + (f" ({reason})" if reason else " in a lab")
        )
    return problems


def _check_build(name: str, build: object, lab_dir: Path) -> list[str]:
    where = f"service '{name}' build"
    if not isinstance(build, dict):
        return [f"{where}: must be a mapping"]
    problems = _unknown(build, BUILD_KEYS, BUILD_REASONS, where)
    context = build.get("context")
    # Compose makes a local context absolute and leaves a URL alone, so a
    # context that is not an absolute path is not a directory on this disk.
    if not isinstance(context, str) or "://" in context or not Path(context).is_absolute():
        problems.append(f"{where}: context {context!r} must be a directory inside the lab")
        return problems
    root = Path(context)
    if not _inside(root, lab_dir):
        problems.append(f"{where}: context {context} is outside the lab directory")
    dockerfile = build.get("dockerfile") or "Dockerfile"
    if not isinstance(dockerfile, str) or not _inside(root / dockerfile, root):
        problems.append(f"{where}: dockerfile {dockerfile!r} is outside its build context")
    return problems


def _check_deploy(name: str, deploy: object) -> list[str]:
    where = f"service '{name}' deploy"
    if not isinstance(deploy, dict):
        return [f"{where}: must be a mapping"]
    problems = _unknown(deploy, DEPLOY_KEYS, {}, where)
    resources = deploy.get("resources") or {}
    if not isinstance(resources, dict):
        return problems + [f"{where}.resources: must be a mapping"]
    for section, value in resources.items():
        allowed = RESOURCE_KEYS.get(section)
        if allowed is None:
            problems.append(f"{where}.resources: {section} is not allowed in a lab")
            continue
        if not isinstance(value, dict):
            problems.append(f"{where}.resources.{section}: must be a mapping")
            continue
        problems.extend(_unknown(value, allowed, RESOURCE_REASONS, f"{where}.resources.{section}"))
    return problems


def _check_networks(project: str, networks: object) -> tuple[set[str], list[str]]:
    """The names of the networks a service may join, and what is wrong with the rest."""
    if not isinstance(networks, dict):
        return set(), ["networks: must be a mapping"]
    usable, problems = set(), []
    for key, network in networks.items():
        where = f"network '{key}'"
        if not isinstance(network, dict):
            problems.append(f"{where}: must be a mapping")
            continue
        found = _unknown(network, NETWORK_KEYS, NETWORK_REASONS, where)
        if network.get("internal") is not True:
            found.append(f"{where}: must declare internal: true")
        if network.get("driver") not in (None, "bridge"):
            found.append(f"{where}: driver {network.get('driver')!r} is not allowed; use bridge")
        # Compose names a network <project>_<key> unless told otherwise. An
        # explicit name can point at a network that already exists -- the
        # default `bridge`, or one of the user's -- and teardown removes it.
        if network.get("name") not in (None, f"{project}_{key}"):
            found.append(f"{where}: may not set its own name ({network.get('name')!r})")
        ipam = network.get("ipam") or {}
        if not isinstance(ipam, dict):
            found.append(f"{where}: ipam must be a mapping")
        else:
            found.extend(_unknown(ipam, IPAM_KEYS, {}, f"{where} ipam"))
            if ipam.get("driver") not in (None, "default"):
                found.append(f"{where}: ipam driver {ipam.get('driver')!r} is not allowed")
            for pool in ipam.get("config") or []:
                if isinstance(pool, dict):
                    found.extend(_unknown(pool, IPAM_POOL_KEYS, {}, f"{where} ipam config"))
                else:
                    found.append(f"{where}: ipam config entries must be mappings")
        if not found:
            usable.add(key)
        problems.extend(found)
    return usable, problems


def _check_service(name: str, service: object, usable_networks: set[str], lab_dir: Path) -> list[str]:
    where = f"service '{name}'"
    if not isinstance(service, dict):
        return [f"{where}: must be a mapping"]
    problems = _unknown(service, SERVICE_KEYS, SERVICE_REASONS, where)
    if "build" in service:
        problems.extend(_check_build(name, service["build"], lab_dir))
    if "deploy" in service:
        problems.extend(_check_deploy(name, service["deploy"]))
    for option in service.get("security_opt") or []:
        if not isinstance(option, str) or not SECURITY_OPT.fullmatch(option.strip()):
            problems.append(f"{where}: security_opt {option!r} is not allowed; only no-new-privileges is")
    attached = service.get("networks")
    # Normalisation puts a service without networks: on `default`, which is
    # the ordinary bridge unless the lab itself declares it internal.
    if not isinstance(attached, dict) or not attached:
        problems.append(f"{where}: must join one of the lab's internal networks")
        return problems
    for network, endpoint in attached.items():
        if network not in usable_networks:
            problems.append(
                f"{where}: joins the default network, which is not internal"
                if network == "default"
                else f"{where}: joins network '{network}', which is not an internal lab network"
            )
        if endpoint is not None:
            if isinstance(endpoint, dict):
                problems.extend(_unknown(endpoint, ENDPOINT_KEYS, {}, f"{where} on network '{network}'"))
            else:
                problems.append(f"{where} on network '{network}': must be a mapping")
    return problems


def check_model(model: dict, lab_dir: Path) -> list[str]:
    """Every way the resolved model breaks the policy, each naming its service and key."""
    if not isinstance(model, dict):
        return ["the resolved Compose model is not a mapping"]
    problems = _unknown(model, TOP_LEVEL_KEYS, TOP_LEVEL_REASONS, "top level")
    project = str(model.get("name") or "")
    usable, network_problems = _check_networks(project, model.get("networks") or {})
    problems.extend(network_problems)
    services = model.get("services")
    if not isinstance(services, dict) or not services:
        return problems + ["the Compose file defines no services"]
    for name, service in services.items():
        problems.extend(_check_service(name, service, usable, lab_dir))
    return problems


def check_variables(variables: dict, resolvable: set[str]) -> list[str]:
    """Interpolations the host environment would fill in."""
    return [
        f"docker-compose.yml interpolates ${{{name}}} from the host environment; "
        "use a literal or a default such as ${NAME:-}"
        for name in sorted(variables)
        if name in resolvable
    ]


def _config(compose: list[str], lab_dir: Path, environment: dict[str, str], *options: str) -> str:
    completed = subprocess.run(
        [*compose, "--profile", "*", "config", *options],
        cwd=lab_dir,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"Compose preflight failed: {detail}")
    return completed.stdout


def enforce(compose: list[str], lab_dir: Path, environment: dict[str, str]) -> dict:
    """Refuse a lab that asks for more than isolation allows; return the resolved model.

    `compose` is the `docker compose -p ... -f ...` prefix every later stage
    uses, so what is checked is what is built and run.
    """
    try:
        source = (lab_dir / "docker-compose.yml").read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise RuntimeError(f"Compose preflight failed: {error}") from error
    problems = check_source(source)
    if problems:
        # Before Compose runs at all: it would open the included files.
        raise PolicyError(
            "Compose policy refused this lab:\n" + "\n".join(f"  - {problem}" for problem in problems)
        )
    model = json.loads(
        _config(compose, lab_dir, environment, "--format", "json", "--no-env-resolution")
    )
    variables = json.loads(
        _config(compose, lab_dir, environment, "--variables", "--format", "json").strip() or "{}"
    )
    resolvable = {
        line.split("=", 1)[0]
        for line in _config(compose, lab_dir, environment, "--environment").splitlines()
        if "=" in line
    }
    problems.extend(check_model(model, lab_dir))
    problems.extend(check_variables(variables, resolvable))
    if problems:
        raise PolicyError(
            "Compose policy refused this lab:\n" + "\n".join(f"  - {problem}" for problem in problems)
        )
    return model


def limits_override(model: dict, limits: dict[str, object]) -> dict:
    """A Compose override that gives each service the default limits it lacks.

    Only what a service leaves unset: a lab that asks for less keeps it, and
    setting mem_limit beside deploy.resources.limits.memory is a Compose
    error, so either spelling counts as set.
    """
    services = {}
    for name, service in (model.get("services") or {}).items():
        resources = ((service.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        added: dict[str, object] = {}
        if "mem_limit" in limits and not (service.get("mem_limit") or resources.get("memory")):
            added["mem_limit"] = limits["mem_limit"]
        if "cpu_quota" in limits and not any(
            service.get(key) for key in ("cpus", "cpu_quota", "cpu_period")
        ) and not resources.get("cpus"):
            added["cpu_period"] = limits["cpu_period"]
            added["cpu_quota"] = limits["cpu_quota"]
        if "pids_limit" in limits and not (service.get("pids_limit") or resources.get("pids")):
            added["pids_limit"] = limits["pids_limit"]
        if added:
            services[name] = added
    return {"services": services}
