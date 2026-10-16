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

"""Progress reporting for operations that take minutes.

A run clones repositories, builds images and waits on containers. Without
reporting it prints nothing until it is finished, and a user cannot tell a
slow clone from a hung one.

Progress goes to stderr so stdout stays a clean JSON document that can be
piped. It is a module-level reporter rather than a callback threaded through
every signature, because the slow operations sit several layers below the
command that wants to report them.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable

Reporter = Callable[[str], None]


def _write(message: str) -> None:
    print(f"[cvelab] {message}", file=sys.stderr, flush=True)


_reporter: Reporter | None = None if os.getenv("CVELAB_QUIET") else _write


def set_reporter(reporter: Reporter | None) -> None:
    """Replace the reporter, or pass None to silence progress entirely."""
    global _reporter
    _reporter = reporter


def silence() -> None:
    set_reporter(None)


def step(message: str) -> None:
    if _reporter is not None:
        _reporter(message)


class stage:
    """Report the start of a slow operation and how long it took.

    Only reports the duration for operations slow enough that the user was
    left waiting; a fast one would add noise without telling them anything.
    """

    REPORT_AFTER_SECONDS = 3.0

    def __init__(self, message: str) -> None:
        self.message = message
        self.started = 0.0

    def __enter__(self) -> stage:
        self.started = time.monotonic()
        step(f"{self.message}...")
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        elapsed = time.monotonic() - self.started
        if exc_type is None:
            if elapsed >= self.REPORT_AFTER_SECONDS:
                step(f"{self.message}: done in {elapsed:.0f}s")
        else:
            step(f"{self.message}: failed after {elapsed:.0f}s")
        return False
