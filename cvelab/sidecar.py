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

"""The image a single-target script is proved from, and the consent to build it.

Most transports need nothing: a sidecar runs `python:3.13-alpine` and the
script speaks HTTP or a socket with the standard library alone. A protocol
with a real handshake does not fit that -- SSH negotiates keys and SMB
negotiates a dialect, neither of which can be written as bytes to send -- so
those transports need a library, and the library has to be inside the sidecar.

It cannot be installed when the sidecar runs. The sidecar joins the lab
container's network namespace, and a lab's network is `internal: true`, so at
that moment there is no route to an index. The packages are therefore baked
into an image beforehand, on the host, where there is one.

Nothing here installs anything without being told to. CVELab's own core has no
runtime dependencies and keeps none; these are asked for, once, for the
transports that cannot work without them, and the person running it says yes
first. No part of this needs root: the image is built through the Docker
daemon the user already has access to, and nothing is written outside it.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from . import progress

#: Transports that cannot be spoken with the standard library, and what each
#: needs. Pinned at a floor rather than exactly: these are read by a human
#: before they agree to the build, and a floor is what the extras declare.
PROTOCOL_PACKAGES: dict[str, tuple[str, ...]] = {
    "ssh": ("paramiko>=3.4",),
    "smb": ("impacket>=0.12",),
}

#: The plain sidecar, for every transport the standard library covers.
BASE_IMAGE = "python:3.13-alpine"

#: The prepared one. Tagged by what is in it, so a changed package list builds
#: a new image instead of silently reusing one that lacks something.
IMAGE_PREFIX = "cvelab/protocol-sidecar"


class ConsentRequired(RuntimeError):
    """The run needs something installed and nobody has agreed to it."""


def packages_for(transports: set[str]) -> tuple[str, ...]:
    """What has to be in the sidecar for these transports, in a stable order."""
    needed: list[str] = []
    for transport in sorted(transports):
        for package in PROTOCOL_PACKAGES.get(transport, ()):
            if package not in needed:
                needed.append(package)
    return tuple(needed)


def image_tag(packages: tuple[str, ...]) -> str:
    slug = "-".join(
        package.split(">=")[0].split("==")[0].strip().lower() for package in packages
    )
    return f"{IMAGE_PREFIX}:{slug}"


def _image_exists(image: str) -> bool:
    found = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True, text=True, check=False,
    )
    return found.returncode == 0


def ask(packages: tuple[str, ...], image: str, assume_yes: bool) -> None:
    """Say exactly what would be installed and where, and get a yes.

    Printed in full every time, because the point is that the person knows
    what is about to be downloaded and run. `assume_yes` is for a script that
    has already decided; without a terminal and without it, the run stops
    rather than guessing that silence means consent.
    """
    listed = ", ".join(packages)
    message = (
        f"This PoC speaks a protocol the standard library cannot, so it is proved "
        f"from a prepared container image.\n\n"
        f"  build      {image}\n"
        f"  from       {BASE_IMAGE}\n"
        f"  installing {listed}\n"
        f"             downloaded from PyPI by pip, inside that image\n\n"
        f"Nothing is installed on this machine outside Docker, nothing needs root, and "
        f"the lab itself is untouched. The image is built once and reused."
    )
    if assume_yes:
        progress.step(f"building {image} with {listed} (--yes was given)")
        return
    if not sys.stdin.isatty():
        raise ConsentRequired(
            message + "\n\nThere is no terminal to ask on. Re-run with --yes to agree, "
            f"or build it yourself:\n  docker build -t {image} -"
        )
    print(message, file=sys.stderr)
    answer = input("Type yes to build it: ").strip().lower()
    if answer != "yes":
        raise ConsentRequired("Not built, so nothing was proved. Nothing was installed.")


def ensure_image(transports: set[str], assume_yes: bool = False) -> str:
    """The image to prove from, built with consent if it is not there yet.

    Returns the plain sidecar when these transports need nothing extra, which
    is the common case and asks nobody anything.
    """
    packages = packages_for(transports)
    if not packages:
        return BASE_IMAGE
    image = image_tag(packages)
    if _image_exists(image):
        return image
    ask(packages, image, assume_yes)
    dockerfile = (
        f"FROM {BASE_IMAGE}\n"
        "RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev python3-dev "
        "&& pip install --no-cache-dir " + " ".join(f"'{p}'" for p in packages) + " "
        "&& apk del gcc musl-dev libffi-dev openssl-dev python3-dev\n"
    )
    with progress.stage(f"building {image}"):
        scratch = Path(tempfile.mkdtemp(prefix="cvelab-sidecar-"))
        try:
            (scratch / "Dockerfile").write_text(dockerfile, encoding="utf-8")
            built = subprocess.run(
                ["docker", "build", "-t", image, str(scratch)],
                capture_output=True, text=True, check=False,
            )
        finally:
            for leftover in scratch.iterdir():
                leftover.unlink()
            scratch.rmdir()
    if built.returncode != 0:
        detail = (built.stderr or built.stdout).strip()[-2000:]
        raise RuntimeError(f"could not build {image}: {detail}")
    return image
