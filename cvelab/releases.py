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

"""The published releases a fix shipped in, for labs that install them.

Building a large repository from source is where most labs for framework
CVEs failed: Next.js, Nuxt, Storybook, Astro and Sentry are monorepos with
their own toolchains. When the fix also shipped in a release, installing the
last vulnerable and the first patched version from the registry runs the
same vendor code without that build. A lodash lab that did so validated.

Everything here is best effort and never fails a run: no advisory, an
unknown ecosystem or an unreachable registry simply yields no releases.
CVELAB_PUBLISHED_RELEASES=off turns the lookup off.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from .core import GITHUB_ADVISORY_URL

REGISTRIES = {
    "npm": "https://registry.npmjs.org/{name}",
    "pip": "https://pypi.org/pypi/{name}/json",
}

#: The npm document of a package with thousands of versions is large even
#: abbreviated; past this, the lookup is skipped rather than held in memory.
MAX_REGISTRY_BYTES = 64 * 1024 * 1024
TIMEOUT_SECONDS = 30

_CONSTRAINT = re.compile(r"(>=|<=|>|<|=)\s*v?([0-9][^\s,]*)")
_RELEASE = re.compile(r"^v?(\d+(?:\.\d+)*)$")


def version_key(version: str) -> tuple[int, ...] | None:
    """A comparable key for a final release; None for a pre-release or anything unparsed."""
    match = _RELEASE.match(version.strip())
    if not match:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def in_range(version: str, vulnerable_range: str) -> bool:
    """Whether a release satisfies a GitHub advisory range such as '>= 1.2, < 1.4.1'."""
    key = version_key(version)
    if key is None:
        return False
    constraints = _CONSTRAINT.findall(vulnerable_range or "")
    if not constraints:
        return False
    for operator, bound_text in constraints:
        bound = version_key(bound_text)
        if bound is None:
            return False
        if operator == ">=" and not key >= bound:
            return False
        if operator == ">" and not key > bound:
            return False
        if operator == "<=" and not key <= bound:
            return False
        if operator == "<" and not key < bound:
            return False
        if operator == "=" and key != bound:
            return False
    return True


def _get(url: str, headers: dict[str, str]) -> object | None:
    request = urllib.request.Request(url, headers={"User-Agent": "cvelab", **headers})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_REGISTRY_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if len(body) > MAX_REGISTRY_BYTES:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def advisory_packages(cve: str) -> list[dict]:
    """The packages, ranges and first patched versions of the CVE's reviewed GitHub advisory."""
    document = _get(GITHUB_ADVISORY_URL.format(cve=cve), {"Accept": "application/vnd.github+json"})
    if not isinstance(document, list):
        return []
    packages = []
    for advisory in document:
        if not isinstance(advisory, dict) or str(advisory.get("cve_id") or "").upper() != cve:
            continue
        if advisory.get("withdrawn_at"):
            continue
        for vulnerability in advisory.get("vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            package = vulnerability.get("package") or {}
            packages.append({
                "ecosystem": package.get("ecosystem"),
                "package": package.get("name"),
                "vulnerable_range": vulnerability.get("vulnerable_version_range"),
                "first_patched": vulnerability.get("first_patched_version"),
            })
    return packages


def published_versions(ecosystem: str, name: str) -> list[str]:
    """Every version the registry lists for a package; empty when it cannot be read."""
    template = REGISTRIES.get(ecosystem)
    if not template or not name:
        return []
    if ecosystem == "npm":
        document = _get(
            template.format(name=urllib.parse.quote(name, safe="@")),
            {"Accept": "application/vnd.npm.install-v1+json"},
        )
        versions = document.get("versions") if isinstance(document, dict) else None
    else:
        document = _get(template.format(name=urllib.parse.quote(name)), {"Accept": "application/json"})
        versions = document.get("releases") if isinstance(document, dict) else None
    return list(versions) if isinstance(versions, dict) else []


def pick_release(entry: dict, versions: list[str]) -> dict | None:
    """The last vulnerable and first patched release for one advisory entry, or None."""
    patched = str(entry.get("first_patched") or "")
    patched_key = version_key(patched)
    if patched_key is None or patched not in versions:
        return None
    candidates = [
        version for version in versions
        if in_range(version, str(entry.get("vulnerable_range") or ""))
        and (version_key(version) or ()) < patched_key
    ]
    if not candidates:
        return None
    last = max(candidates, key=lambda version: version_key(version) or ())
    return {
        "ecosystem": entry["ecosystem"],
        "package": entry["package"],
        "last_vulnerable": last,
        "first_patched": patched,
    }


def find_releases(cve: str) -> list[dict]:
    """One vulnerable and patched release pair per package the registries can resolve."""
    if os.getenv("CVELAB_PUBLISHED_RELEASES", "").strip().lower() in {"0", "off", "false", "no"}:
        return []
    best: dict[tuple[str, str], dict] = {}
    for entry in advisory_packages(cve):
        if entry.get("ecosystem") not in REGISTRIES or not entry.get("package"):
            continue
        release = pick_release(entry, published_versions(entry["ecosystem"], entry["package"]))
        if not release:
            continue
        key = (release["ecosystem"], release["package"])
        # Several advisory entries for one package are release lines; the
        # newest line is the one the repository's fix commit belongs to.
        current = best.get(key)
        if current is None or (version_key(release["first_patched"]) or ()) > (
            version_key(current["first_patched"]) or ()
        ):
            best[key] = release
    return list(best.values())


def render(releases: list[dict]) -> str:
    """The prompt section that offers the release pair, or nothing."""
    if not releases:
        return ""
    lines = [
        f"- {item['ecosystem']} {item['package']}: last vulnerable {item['last_vulnerable']}, "
        f"first patched {item['first_patched']}"
        for item in releases
    ]
    return (
        "\n\n--- PUBLISHED RELEASES ---\n"
        "The fix also shipped in published releases, resolved from GitHub's reviewed advisory and the "
        "package registry:\n" + "\n".join(lines) + "\n"
        "For a large repository or a monorepo, prefer installing these two versions from the registry "
        "over building the source; this is the one exception to building from the snapshots. "
        "vulnerable/Dockerfile installs the last vulnerable version and patched/Dockerfile the first "
        "patched one, with everything else identical. The pair carries the fix and whatever else that "
        "release changed, so the snapshots stay the reference for what the fix does.\n"
    )
