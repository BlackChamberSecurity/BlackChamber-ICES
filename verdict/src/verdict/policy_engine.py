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
BlackChamber ICES Policy Engine

Evaluates configurable YAML rules against analysis observations.
Supports matching by:
  - tenant (exact or "*")
  - sender (exact, domain wildcard like "*@*.xyz", or "*")
  - recipients (exact, list of emails, or "*")
  - observation key + value (equals, gte, lte, contains, exists)
"""
import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Any

from verdict.models import VerdictEvent, VerdictResult, Observation

logger = logging.getLogger(__name__)

# Action priority: higher wins when multiple policies match
ACTION_PRIORITY = {
    "delete": 4,
    "quarantine": 3,
    "tag": 2,
    "none": 1,
}


@dataclass
class PolicyDecision:
    """The outcome of policy evaluation."""
    policy_name: str = ""
    action: str = "none"
    matched_analyzer: str = ""
    matched_observations: list = field(default_factory=list)


class PolicyEngine:
    """Evaluate rules from config against analysis results."""

    def __init__(self, policies: list[dict]):
        self.policies = policies
        logger.info("PolicyEngine loaded %d rule(s)", len(policies))

    def evaluate(self, verdict: VerdictEvent) -> PolicyDecision:
        """Evaluate all policies against a verdict. Highest-priority action wins."""
        best: PolicyDecision | None = None

        for policy in self.policies:
            decision = self._evaluate_one(policy, verdict)
            if decision is None:
                continue
            if best is None or ACTION_PRIORITY.get(decision.action, 0) > ACTION_PRIORITY.get(best.action, 0):
                best = decision

        if best:
            logger.info(
                "Policy '%s' matched: action=%s for message=%s",
                best.policy_name, best.action, verdict.message_id,
            )
            return best

        return PolicyDecision(policy_name="", action="none")

    def _evaluate_one(self, policy: dict, verdict: VerdictEvent) -> PolicyDecision | None:
        """Evaluate a single policy rule. Returns None if no match."""
        # --- Scope checks ---
        if not self._match_tenant(policy, verdict):
            return None
        if not self._match_sender(policy, verdict):
            return None
        if not self._match_recipients(policy, verdict):
            return None

        # --- Observation check ---
        when = policy.get("when", {})
        target_analyzers = when.get("analyzer", [])
        if isinstance(target_analyzers, str):
            target_analyzers = [target_analyzers]

        obs_key = when.get("observation", "")
        if not obs_key:
            return None

        for result in verdict.results:
            if target_analyzers and result.analyzer not in target_analyzers:
                continue

            for obs in result.observations:
                if obs.key != obs_key:
                    continue

                if self._match_observation(when, obs):
                    return PolicyDecision(
                        policy_name=policy.get("name", ""),
                        action=policy.get("action", "none"),
                        matched_analyzer=result.analyzer,
                        matched_observations=[obs.to_dict()],
                    )

        return None

    # --- Scope matchers ---

    def _match_tenant(self, policy: dict, verdict: VerdictEvent) -> bool:
        tenant_filter = policy.get("tenant", "*")
        if tenant_filter == "*":
            return True
        return verdict.tenant_alias == tenant_filter or verdict.tenant_id == tenant_filter

    def _match_sender(self, policy: dict, verdict: VerdictEvent) -> bool:
        sender_filter = policy.get("sender", "*")
        if sender_filter == "*":
            return True
        return fnmatch.fnmatch(verdict.sender.lower(), sender_filter.lower())

    def _match_recipients(self, policy: dict, verdict: VerdictEvent) -> bool:
        recipients_filter = policy.get("recipients", "*")
        if recipients_filter == "*":
            return True
        if isinstance(recipients_filter, str):
            recipients_filter = [recipients_filter]
        # Match if ANY recipient matches ANY filter pattern
        for recipient in verdict.recipients:
            for pattern in recipients_filter:
                if fnmatch.fnmatch(recipient.lower(), pattern.lower()):
                    return True
        return False

    # --- Observation matchers ---

    def _match_observation(self, when: dict, obs: Observation) -> bool:
        """Check if an observation matches the policy's when clause."""
        # equals — exact match
        if "equals" in when:
            expected = when["equals"]
            if isinstance(obs.value, bool):
                return obs.value == (expected in (True, "true", "True", 1))
            return str(obs.value).lower() == str(expected).lower()

        # gte — numeric greater-than-or-equal
        if "gte" in when:
            try:
                return float(obs.value) >= float(when["gte"])
            except (ValueError, TypeError):
                return False

        # lte — numeric less-than-or-equal
        if "lte" in when:
            try:
                return float(obs.value) <= float(when["lte"])
            except (ValueError, TypeError):
                return False

        # contains — substring or list membership
        if "contains" in when:
            val = str(obs.value).lower()
            return str(when["contains"]).lower() in val

        # exists — just check the key is present (always true if we got here)
        if "exists" in when:
            return when["exists"] is True

        return False
