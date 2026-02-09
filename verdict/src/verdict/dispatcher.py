# Copyright (c) 2026 John Earle
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

"""
BlackChamber ICES Verdict Worker — Dispatcher

Routes verdicts to actions based on policy engine decisions.
"""
import logging
import uuid
from typing import Optional

from verdict.actions import discover_actions
from verdict.actions._base import BaseAction
from verdict.models import VerdictEvent
from verdict.policy_engine import PolicyEngine, PolicyDecision

logger = logging.getLogger(__name__)


class Dispatcher:
    """Discover available actions and dispatch based on policy decisions."""

    def __init__(self, policy_engine: PolicyEngine):
        self.policy_engine = policy_engine
        self.actions: dict[str, BaseAction] = discover_actions()
        logger.info(
            "Dispatcher ready: %d action(s), %d policy rule(s)",
            len(self.actions), len(policy_engine.policies),
        )

    def dispatch(self, verdict: VerdictEvent) -> Optional[dict]:
        """Evaluate policies and invoke matching action.

        Returns the Graph API request dict or None.
        """
        decision = self.policy_engine.evaluate(verdict)

        if decision.action == "none":
            logger.info(
                "No policy matched for message %s — no action",
                verdict.message_id,
            )
            return None

        action = self.actions.get(decision.action)
        if action is None:
            logger.warning(
                "Policy '%s' requested action '%s' but no handler found",
                decision.policy_name, decision.action,
            )
            return None

        request = action.build_request(verdict)
        request["id"] = str(uuid.uuid4())

        logger.info(
            "Policy '%s' → action '%s' for message %s",
            decision.policy_name, decision.action, verdict.message_id,
        )

        return {
            "request": request,
            "decision": {
                "policy_name": decision.policy_name,
                "action": decision.action,
                "matched_analyzer": decision.matched_analyzer,
                "matched_observations": decision.matched_observations,
            },
        }
