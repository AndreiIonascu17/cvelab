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

from __future__ import annotations

import unittest

from tests.fixtures.lighthouse import LIGHTHOUSE_E2E_RUN_SH, LIGHTHOUSE_MANUAL_POC_SH


class ShipyardTemplateTests(unittest.TestCase):
    def test_runners_isolate_dapper_from_user_docker_config(self) -> None:
        for script in (LIGHTHOUSE_E2E_RUN_SH, LIGHTHOUSE_MANUAL_POC_SH):
            self.assertIn('export HOME="$WORK_ROOT/runner-home"', script)
            self.assertIn('export DOCKER_CONFIG="$WORK_ROOT/docker-config-$variant"', script)

    def test_automatic_runner_uses_current_git_branch_for_dapper_image(self) -> None:
        self.assertIn('dapper_image="$variant:$(git branch --show-current)"', LIGHTHOUSE_E2E_RUN_SH)
        self.assertIn('"$dapper_image" "$@"', LIGHTHOUSE_E2E_RUN_SH)
        self.assertNotIn('"$variant:master"', LIGHTHOUSE_E2E_RUN_SH)

    def test_manual_runner_uses_current_git_branch_for_dapper_image(self) -> None:
        self.assertIn('branch="$(git -C "$work" branch --show-current)"', LIGHTHOUSE_MANUAL_POC_SH)
        self.assertIn('"$dapper_image" "$@"', LIGHTHOUSE_MANUAL_POC_SH)
        self.assertNotIn('"$variant:master"', LIGHTHOUSE_MANUAL_POC_SH)


if __name__ == "__main__":
    unittest.main()
