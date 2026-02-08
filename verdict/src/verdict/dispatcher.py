# Copyright (c) 2026 John Earle
#
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://github.com/yourusername/bcem/blob/main/LICENSE
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
BCEM Verdict Worker — Dispatcher

Routes verdicts to actions based on analyzer score thresholds.

Score thresholds:
- max_score >= 70 → quarantine (move to junk)
- max_score >= 30 → tag (flag in inbox)
- max_score <  30 → no action (log only)
"""
import logging
from typing import Optional

from verdict.models import VerdictEvent
from verdict.actions import discover_actions

logger = logging.getLogger(__name__)

# Score thresholds for action routing
QUARANTINE_THRESHOLD = 70
TAG_THRESHOLD = 30


class Dispatcher:
    """
    Routes verdict results to the appropriate action based on score thresholds.

    Computes the max score across all analyzer results and invokes the
    matching action (quarantine > tag > none).
    """

    def __init__(self):
        self.actions = discover_actions()
        logger.info(
            "Dispatcher loaded %d actions: %s",
            len(self.actions), list(self.actions.keys()),
        )

    def dispatch(self, verdict: VerdictEvent) -> Optional[dict]:
        """
        Process a verdict's analyzer results and invoke the appropriate action.

        Args:
            verdict: The verdict from the analysis engine.

        Returns:
            A dict with the action request and summary, or None if no results.
        """
        if not verdict.results:
            logger.info("No analyzer results for %s", verdict.message_id)
            return None

        # Log each analyzer's result
        max_score = 0
        for result in verdict.results:
            logger.info(
                "Result for %s: analyzer=%s score=%d provider=%s category=%s findings=%d",
                verdict.message_id,
                result.analyzer,
                result.score,
                result.provider or "-",
                result.category or "-",
                len(result.findings),
            )
            if result.score > max_score:
                max_score = result.score

        # Build the summary
        summary = {
            "message_id": verdict.message_id,
            "max_score": max_score,
            "results": [
                {
                    "analyzer": r.analyzer,
                    "score": r.score,
                    "provider": r.provider,
                    "category": r.category,
                    "findings": r.findings,
                }
                for r in verdict.results
            ],
        }

        # Route to action based on max score
        action_request = None
        if max_score >= QUARANTINE_THRESHOLD and "quarantine" in self.actions:
            action = self.actions["quarantine"]
            action_request = action.build_request(verdict)
            summary["action"] = "quarantine"
            logger.info(
                "Action: QUARANTINE message %s (max_score=%d)",
                verdict.message_id, max_score,
            )
        elif max_score >= TAG_THRESHOLD and "tag" in self.actions:
            action = self.actions["tag"]
            action_request = action.build_request(verdict)
            summary["action"] = "tag"
            logger.info(
                "Action: TAG message %s (max_score=%d)",
                verdict.message_id, max_score,
            )
        else:
            summary["action"] = "none"
            logger.info(
                "Action: NONE for message %s (max_score=%d)",
                verdict.message_id, max_score,
            )

        if action_request:
            summary["request"] = action_request

        return summary

