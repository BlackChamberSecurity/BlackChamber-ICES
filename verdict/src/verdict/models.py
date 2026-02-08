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
BCEM Verdict Worker — Data Models

These match the Verdict output from the analysis engine.
"""
from dataclasses import dataclass, field


@dataclass
class VerdictResult:
    """A single analyzer's contribution to the verdict."""
    analyzer: str = ""
    score: int = 0
    findings: list = field(default_factory=list)
    provider: str = ""
    category: str = ""


@dataclass
class VerdictEvent:
    """
    A verdict received from the analysis engine.

    Each analyzer's result is returned individually — no aggregated score.

    Fields:
    - message_id:  M365 message ID (needed for Graph API actions)
    - user_id:     mailbox owner (needed for Graph API path)
    - tenant_id:   M365 tenant
    - results:     individual analyzer results (each with its own score/findings)
    """
    message_id: str = ""
    user_id: str = ""
    tenant_id: str = ""
    tenant_alias: str = ""
    results: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "VerdictEvent":
        """Deserialise from the queue JSON."""
        return cls(
            message_id=data.get("message_id", ""),
            user_id=data.get("user_id", ""),
            tenant_id=data.get("tenant_id", ""),
            tenant_alias=data.get("tenant_alias", ""),
            results=[
                VerdictResult(**r) for r in data.get("results", [])
            ],
        )

