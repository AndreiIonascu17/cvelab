#!/usr/bin/env python3
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

"""Build cvelab.pyz, a single file that runs on any Python 3.11 or newer.

CVELab imports nothing outside the standard library, which is what makes this
possible: there is no wheel to resolve, no virtual environment to create and
no index to reach. One file is copied to a machine and run.

The output is generated, not committed. The deploy workflow builds it next to
the site so the download and the source it came from cannot drift apart.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
import tomllib
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "cvelab"


def project_version() -> str:
    """The one in pyproject.toml, which is what a release is cut from."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def build(destination: Path, interpreter: str = "/usr/bin/env python3") -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as workspace:
        staged = Path(workspace) / "cvelab"
        # Caches hold absolute paths from this machine and bytecode for one
        # Python version, neither of which belongs in something shipped.
        shutil.copytree(
            PACKAGE, staged, ignore=shutil.ignore_patterns("__pycache__", "*.py[cod]")
        )
        # importlib.metadata cannot see a zipapp, so the version travels
        # inside it rather than being guessed at runtime.
        (staged / "_version.py").write_text(
            f'__version__ = "{project_version()}"\n', encoding="utf-8"
        )
        # Apache-2.0 section 4 requires that a recipient of a distribution
        # gets a copy of the licence and carries the NOTICE. The per-file
        # headers travel with the sources already; these two did not, and an
        # archive served from a website is a distribution.
        for name in ("LICENSE", "NOTICE"):
            shutil.copyfile(ROOT / name, Path(workspace) / name)

        zipapp.create_archive(
            Path(workspace),
            target=destination,
            main="cvelab.cli:main",
            interpreter=interpreter,
        )
    destination.chmod(0o755)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "cvelab.pyz",
        help="Where to write the archive (default: dist/cvelab.pyz)",
    )
    arguments = parser.parse_args(argv)

    archive = build(arguments.output)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    # Written beside the archive so a download can be checked without
    # trusting the page that offered it.
    archive.with_suffix(".pyz.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    print(f"{archive}  {archive.stat().st_size:,} bytes")
    print(f"sha256  {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
