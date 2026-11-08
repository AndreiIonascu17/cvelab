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


_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
_DURATION_SECONDS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600}


def duration_seconds(value: object) -> float | None:
    """Seconds in a Compose duration such as 2s, 1m30s or 500ms; None when unset or unreadable."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value) / 1e9  # Compose resolves a bare number to nanoseconds
    text = str(value).strip()
    parts = _DURATION_PART.findall(text)
    if not parts or "".join(number + unit for number, unit in parts) != text:
        return None
    return sum(float(number) * _DURATION_SECONDS[unit] for number, unit in parts)


def startup_grace_override(model: dict, grace_seconds: int) -> dict:
    """Give every health-checked service a start period of at least grace_seconds.

    A generated healthcheck usually probes every two seconds and gives up
    after thirty tries, so a product that compiles assets or migrates a
    database on first boot is marked unhealthy before it ever listened, and
    the validator never runs. Failures during the start period do not count
    against the retries, while a healthy answer still ends it at once, so a
    fast service is not slowed down. A service with no healthcheck, or with a
    longer start period of its own, is left alone.
    """
    services: dict[str, object] = {}
    if grace_seconds <= 0:
        return {"services": services}
    for name, service in (model.get("services") or {}).items():
        check = service.get("healthcheck") or {}
        test = check.get("test")
        if not test or check.get("disable") or (isinstance(test, list) and test[:1] == ["NONE"]):
            continue
        current = duration_seconds(check.get("start_period"))
        if current is None or current < grace_seconds:
            services[name] = {"healthcheck": {"start_period": f"{grace_seconds}s"}}
    return {"services": services}


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


#: The one service CVELab adds to a lab's own Compose project.
#:
#: Hyphenated, and checked against the lab's own names rather than trusted to
#: be unusual: Compose merges two definitions of one service key across `-f`
#: files instead of refusing them, so a lab that happened to declare a
#: service of this name would have CVELab's image, command and environment
#: merged into it -- and the lab would then be running something nobody
#: wrote, with the lab's own build still in place. Refused instead, by
#: `setup_override`, and refused earlier still at generation time where the
#: support-service names are checked.
SETUP_SERVICE = "cvelab-setup"


def setup_override(
    model: dict,
    *,
    image: str,
    program: str,
    environment: dict[str, str],
    limits: dict[str, object] | None = None,
    service: str = SETUP_SERVICE,
    beside: str = "validator",
) -> dict:
    """A Compose override that adds the service CVELab puts the lab in state with.

    WHY A COMPOSE SERVICE AND NOT A SIDECAR

    The single-target path runs its setup from `docker run --network
    container:<id>`, which is available to it because a field lab is one
    container. A generated source lab is a Compose project: an internal
    network, two builds of the product on it under the names the validator
    resolves, and no single container whose namespace is the right place to
    stand. The route that does exist is the one CVELab already uses for the
    runtime limits -- a JSON Compose file appended with a second `-f`, which
    Compose merges -- so the setup travels the same way.

    WHAT IT MAY ASK FOR

    Only keys in SERVICE_KEYS, so the injected service is held to the policy
    the lab is held to: no volumes, no ports, no build context of CVELab's.
    That is why the program travels in `command` rather than as a file; there
    is nowhere to put a file, and a lab that allowed one would allow a lab to
    mount one too.

    `networks` and `depends_on` are read from the resolved model rather than
    invented. The networks because a service that joins none lands on the
    default bridge and the policy refuses it; the dependencies because the
    setup runs before the first thing in a lab that waits for health, and the
    lab's own validator already declares exactly the wait that is wanted.
    """
    services = model.get("services") or {}
    if service in services:
        raise PolicyError(
            f"Compose policy refused this lab:\n  - service '{service}' is CVELab's own, "
            "and a lab may not declare it: Compose would merge the two definitions "
            "rather than refuse them"
        )
    alongside = services.get(beside) or {}
    attached = alongside.get("networks")
    if not isinstance(attached, dict) or not attached:
        attached = {
            name: None
            for held in services.values()
            for name in (held.get("networks") or {})
            if isinstance(held, dict)
        }
    if not attached:
        raise PolicyError(
            "Compose policy refused this lab:\n  - no internal network for the setup "
            "service to join; the lab's services declare none"
        )
    # The names only. An endpoint can carry a fixed address or an alias, and
    # a second service claiming either is a Compose conflict rather than a
    # setup that ran.
    definition: dict[str, object] = {
        "image": image,
        # Left out of `up -d <startup services>` exactly as the validator is,
        # so a lab with a setup still starts the same services it starts
        # today and this one runs only when CVELab asks for it by name.
        "profiles": ["tools"],
        "networks": dict.fromkeys(attached),
        "environment": dict(environment),
        "command": ["python", "-c", program],
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
    }
    depends_on = alongside.get("depends_on")
    if isinstance(depends_on, dict) and depends_on:
        definition["depends_on"] = depends_on
    # limits_override is built from the resolved model, which cannot contain
    # a service that is being added to it, so the ceilings are applied here.
    for key, value in (limits or {}).items():
        definition.setdefault(key, value)
    return {"services": {service: definition}}


#: The only address a lab's port may be published on.
#:
#: Never 0.0.0.0, which is what Compose binds when a short form names no
#: address: that would put a build whose whole purpose is to be exploitable
#: on every interface the host has, including whatever network the owner's
#: laptop is on at a client site. Loopback keeps the reachable surface to
#: processes already on the machine.
MANUAL_BIND = "127.0.0.1"

#: The network the published port lands on, added in manual mode and nowhere else.
#:
#: Without it the publication is discarded and nothing says so. Every network
#: a lab may declare is `internal: true` -- _check_networks refuses any other
#: kind -- and Docker will not publish a host port for a service whose
#: networks are all internal: it drops the mapping and leaves the container
#: running as though nothing had been asked. Measured on a generated
#: lab: `docker compose config` over the lab plus this override showed the
#: entry surviving the merge intact, `{mode: ingress, host_ip: 127.0.0.1,
#: target: 8080, protocol: tcp}`, while `docker compose ps` reported
#: `8080/tcp` with no mapping and `docker compose port vulnerable 8080`
#: printed `:0`, which is what `manual.sh` then printed as the address. All
#: three port forms did the same thing -- the ephemeral short form, a long
#: form with `published: "0"`, and an explicit `127.0.0.1:18080:8080` -- so
#: neither the merge nor the form was ever the fault. With this network added
#: and the published service joined to it beside the lab's own, the same lab
#: reported `127.0.0.1:32768->8080/tcp` and the carried PoC printed
#: REPRODUCED against that address.
MANUAL_NETWORK = "cvelab-manual"

#: Why that network carries no NAT.
#:
#: A plain bridge does not only let the host in, it lets the lab out.
#: Measured from the published build on one: `1.1.1.1:443` connected, so did
#: port 80 on the gateway of the laptop's own LAN, and `example.com`
#: resolved -- a build whose whole purpose is to be exploitable, holding a
#: route into whatever network the owner is sitting on, which at a client site
#: is the client's. Dropping the masquerade rule leaves the inbound DNAT
#: alone: on the same lab the assigned port still answered 200 on
#: `/health` and the PoC still printed REPRODUCED, while both of those
#: outbound probes timed out. `gw_priority: -100` on this endpoint was tried
#: first and does nothing -- an internal network offers no gateway, so Docker
#: takes the default route from this one however the priority is written.
#:
#: It narrows the exception rather than closing it, and `manual_port_override`
#: says below what stays open.
#:
#: `driver_opts` is refused in a lab's own network definition
#: (NETWORK_REASONS) and stays refused, for the reason `ports` is: the lab
#: does not choose driver options. This is CVELab choosing one, for a network
#: CVELab creates, in a file only a person's `manual.sh` run merges.
MANUAL_NETWORK_DRIVER_OPTS = {"com.docker.network.bridge.enable_ip_masquerade": "false"}


def manual_port_override(model: dict, service: str, container_port: int) -> dict:
    """A Compose override publishing one service's port on loopback, for manual mode.

    WHY THIS IS NOT THE HOLE THE `ports` REFUSAL EXISTS TO PREVENT

    `ports` is refused in a lab's own definition (SERVICE_REASONS) and stays
    refused: `enforce` never sees this override, which Compose merges over
    the lab exactly as the runtime limits and the setup service are merged.
    The refusal is not a claim that a published port is unsafe in the
    abstract. It is a claim about who is present when it opens. The automatic
    path builds and runs model-written code unattended, on the owner's
    machine, as part of a batch nobody is watching; a `ports:` the model
    wrote there would be an exploitable service listening on an interface at
    a time and for a duration no person chose, and the model would be the one
    choosing both. Manual mode inverts every term of that: a person asks for
    one lab by name, stays at the keyboard while it runs, and tears it down
    when the demonstration is over. The exception is held to that difference
    by construction -- it is a separate override, written by CVELab for a
    service the caller names, never a key a lab can put in its own file.

    WHAT IT MAY ASK FOR

    One short-form entry, `127.0.0.1::<container port>`, for one service, and
    the one network that entry needs in order to mean anything. The address is
    fixed (MANUAL_BIND) and the host side is left empty, so the kernel assigns
    an ephemeral port: nothing collides with a port the owner is already
    using, and nothing the model wrote picks a host-side number. The caller
    reads the assignment back with `docker compose port <service> <container
    port>` and hands it to the PoC as its argument. A host-side number, a
    range, and any other address are all absent from what this builds rather
    than validated out of it.

    The network is MANUAL_NETWORK, and the published service joins it BESIDE
    the networks it already declares, read back out of the model: a lab's own
    network is not necessarily called `lab`, and its endpoint can carry the
    aliases the lab reaches itself by. Why a second network is needed at all,
    and why it carries no NAT, is recorded on those two constants; both
    answers were measured, and the first is why this function published
    nothing for as long as it emitted `ports` alone.

    WHAT IT GIVES UP

    A real one, and more than the first version of this said. For as long as
    the lab is up, any process on the host -- every browser tab, every other
    container with a host-gateway route, anything else running as the owner --
    can reach the vulnerable build through loopback, and reach it
    unauthenticated, because being reachable without credentials is usually
    the point of the lab. The isolation the rest of this module maintains is
    that the lab can be reached only from inside its own internal network;
    that is now untrue of one port of one service, by request.

    The second network is the part that cannot be waved through, because
    attaching a service to a network changes what that service can reach, and
    this one is a service built around a working weakness. Measured, with the
    options above: the lab's own network stays `internal: true` and nothing
    about the lab's own file changes; outbound TCP along an ordinary route is
    as dead as it was -- the internet and the owner's LAN both timed out,
    where a plain bridge had reached both -- and the host's own address on the
    new bridge is on-link, so whatever the host's input policy allows there is
    now reachable from the lab (on the machine this was measured on, nothing:
    a listener on 0.0.0.0 was never reached). What is genuinely new is
    external name resolution: on the internal network alone `example.com`
    fails with EAI_AGAIN, and through this one it resolves, which is a channel
    out of the lab for anything that can be spelled into a hostname.

    That trade is for a demonstration a person starts, watches, and tears
    down -- the same person-at-the-keyboard argument the `ports` exception
    itself rests on, and `cleanup` removes the network with the project. It is
    not a posture to leave running, and the automatic path still never merges
    any of it.

    WHERE THE PORT COMES FROM

    From the caller, as an argument, because the resolved model does not
    reliably say. `expose` is in SERVICE_KEYS but nothing in CVELab's
    generation writes it, so almost no lab declares it; a generated lab
    records the port it listens on only incidentally, inside a healthcheck
    command or a URL in `environment`, where reading it back means parsing
    strings. The closed path has the same argument for the same reason
    (`closed._run_poc_script` takes its port). This function therefore
    depends on the caller knowing, and the durable fix is a declared port in
    the generation contract -- a schema change in sourcegen, not here.

    When a lab does declare `expose` and it disagrees with the argument, the
    argument wins and nothing is refused. `expose` publishes nothing and
    changes nothing at runtime, so it is the model's note about itself rather
    than evidence; measured against real labs it is absent far more often
    than it is wrong, which makes it incomplete by nature, and a list that is
    incomplete cannot be read as exhaustive enough to contradict. A
    disagreement also costs nothing that policy protects: publishing a port
    nothing listens on is inert, and the PoC fails to connect, which is
    diagnosable in a second. Refusing would turn a cosmetic mismatch into a
    hard stop in front of a client, and would do it only for the few labs
    that declare anything at all while waving every other lab through, which
    is a guardrail too arbitrary to learn. Which port is correct is a question
    about the lab, not about the host, and this module only answers the
    second kind.
    """
    services = model.get("services") or {}
    # Before the membership check, so CVELab's own name is refused with the
    # reason that actually applies: it is absent from the resolved model
    # because CVELab injects it, not because the lab forgot it.
    if service == SETUP_SERVICE:
        raise PolicyError(
            f"Compose policy refused this lab:\n  - service '{service}' is CVELab's own, "
            "and its port may not be published: it runs CVELab's program, not the "
            "product the PoC is written against"
        )
    if service not in services:
        raise PolicyError(
            f"Compose policy refused this lab:\n  - no service '{service}' to publish a "
            "port for; the lab defines " + (", ".join(sorted(services)) or "no services")
        )
    if (
        not isinstance(container_port, int)
        or isinstance(container_port, bool)
        or not 1 <= container_port <= 65535
    ):
        raise PolicyError(
            "Compose policy refused this lab:\n  - container port "
            f"{container_port!r} is not a port; it must be an integer from 1 to 65535"
        )
    attached = (services.get(service) or {}).get("networks")
    if isinstance(attached, dict):
        attached = dict(attached)
    elif isinstance(attached, (list, tuple)):
        attached = dict.fromkeys(attached)
    else:
        attached = {}
    # The one name in this file that is CVELab's rather than the lab's. A lab
    # that declares a network under it would have `internal: false` and a
    # driver option written onto a network of its own by the lines below,
    # which is the one thing this override must never do -- so it is refused
    # instead, and the refusal says which name is taken.
    if MANUAL_NETWORK in attached or MANUAL_NETWORK in (model.get("networks") or {}):
        raise PolicyError(
            "Compose policy refused this lab:\n  - the lab declares a network named "
            f"'{MANUAL_NETWORK}', which is the name manual mode publishes through; "
            "CVELab would be setting internal: false on a network of the lab's instead "
            "of adding one of its own"
        )
    return {
        "networks": {MANUAL_NETWORK: {
            # Spelled out rather than left to default, because this is the
            # line the whole exception turns on and a reader of the shipped
            # file should not have to know Compose's default to see it.
            "internal": False,
            "driver_opts": dict(MANUAL_NETWORK_DRIVER_OPTS),
        }},
        "services": {service: {
            # The endpoints the service already has, copied out of the
            # resolved model rather than named: `lab` is this generator's name
            # for it, a lab copied from someone else can call it anything, and
            # an endpoint can carry the aliases a validator's canary is
            # reached by. Copied whole rather than rewritten as nulls so the
            # entry says the same thing under either merge rule -- measured on
            # Compose 5.6.1, which normalises the short list form to a mapping
            # before merging and so keeps an alias that a `null` of ours sat
            # beside, while an older Compose that replaced the key outright is
            # still handed the complete set.
            "networks": {**attached, MANUAL_NETWORK: None},
            # A sequence, which Compose appends to across `-f` files rather
            # than replacing -- the merge hazard setup_override is written
            # around. Safe here only because `enforce` has already refused a
            # `ports:` of the lab's own, so there is nothing for this to be
            # appended to.
            "ports": [f"{MANUAL_BIND}::{container_port}"],
        }},
    }
