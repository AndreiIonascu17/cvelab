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

import os
import unittest
from unittest import mock

from cvelab import sourcegen
from cvelab.sourcegen import _answer_until_valid, contract_retries


class ContractRetryTests(unittest.TestCase):
    """An answer refused before the build is asked for again, not counted as a failed attempt."""

    def setUp(self) -> None:
        patcher = mock.patch.object(sourcegen.progress, "step")
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_with(self, verdicts: list[str | None], retries: str | None = None):
        asked: list[str] = []

        def ask(refused: str) -> dict:
            asked.append(refused)
            return {"answer": len(asked)}

        def check(generation: dict) -> list[dict]:
            verdict = verdicts[generation["answer"] - 1]
            if verdict:
                raise RuntimeError(verdict)
            return [{"path": "docker-compose.yml", "content": ""}]

        env = {} if retries is None else {"CVELAB_CONTRACT_RETRIES": retries}
        with mock.patch.dict(os.environ, env, clear=False):
            if retries is None:
                os.environ.pop("CVELAB_CONTRACT_RETRIES", None)
            result = _answer_until_valid(ask, check)
        return result, asked

    def test_a_valid_answer_is_used_at_once(self) -> None:
        (generation, files, refusals), asked = self.run_with([None])
        self.assertEqual(generation, {"answer": 1})
        self.assertEqual(refusals, [])
        self.assertEqual(asked, [""])

    def test_a_refused_answer_is_asked_for_again_with_the_reason(self) -> None:
        (generation, _files, refusals), asked = self.run_with(["validator/Dockerfile copies adapter/x", None])
        self.assertEqual(generation, {"answer": 2})
        self.assertEqual(refusals, ["validator/Dockerfile copies adapter/x"])
        self.assertEqual(asked[0], "")
        self.assertIn("REFUSED BEFORE ANY BUILD", asked[1])
        self.assertIn("validator/Dockerfile copies adapter/x", asked[1])

    def test_the_last_refusal_is_raised_once_retries_run_out(self) -> None:
        with self.assertRaises(RuntimeError) as caught:
            self.run_with(["first", "second", "third", "fourth"])
        self.assertEqual(str(caught.exception), "fourth")

    def test_retries_can_be_turned_off(self) -> None:
        with self.assertRaises(RuntimeError):
            self.run_with(["refused", None], retries="0")

    def test_the_retry_count_is_bounded(self) -> None:
        for raw, expected in (("", 3), ("junk", 3), ("-3", 0), ("4", 4), ("50", 5)):
            with mock.patch.dict(os.environ, {"CVELAB_CONTRACT_RETRIES": raw}):
                self.assertEqual(contract_retries(), expected, raw)

    def test_the_default_budget_covers_every_check_before_the_build(self) -> None:
        """Three, raised from two when the base image check joined the contract.

        Pinned on its own because the number is the point of that check and not
        a detail of it. A refusal path added without budget for it moves a late
        build failure to an early refused generation -- a different failure
        class, not a better rate -- and the measurement reads flat while the
        generation is lost one step sooner.
        """
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CVELAB_CONTRACT_RETRIES", None)
            self.assertEqual(contract_retries(), 3)

    def test_a_base_image_refusal_still_leaves_room_for_a_layout_refusal(self) -> None:
        """The budget's whole purpose: two different checks can each refuse once.

        With two retries this sequence raised, and the lab was lost at
        generation rather than at the build it used to reach.
        """
        (generation, _files, refusals), _asked = self.run_with([
            "A Dockerfile COPY cannot work as written: vulnerable/Dockerfile copies adapter/x",
            "A Dockerfile base image does not exist: vulnerable/Dockerfile starts FROM x:y",
            None,
        ])
        self.assertEqual(generation, {"answer": 3})
        self.assertEqual(len(refusals), 2)


if __name__ == "__main__":
    unittest.main()
