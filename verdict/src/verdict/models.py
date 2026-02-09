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
BlackChamber ICES Verdict Worker — Data Models

These models represent the analysis results as they arrive from the
analysis worker via the Redis queue for policy evaluation.
"""

from dataclasses import dataclass, field
from typing import Any

from ices_shared.models import Observation, AnalysisResult

# Backward-compatible alias — existing code references VerdictResult
VerdictResult = AnalysisResult


@dataclass
class VerdictEvent:
    """A complete analysis result arriving for policy evaluation.

    This is deserialized from the Redis queue and contains everything
    the policy engine needs to make a decision.
    """

    message_id: str = ""
    user_id: str = ""
    tenant_id: str = ""
    tenant_alias: str = ""
    sender: str = ""
    recipients: list = field(default_factory=list)
    results: list = field(default_factory=list)  # list[VerdictResult]

    @classmethod
    def from_dict(cls, data: dict) -> "VerdictEvent":
        return cls(
            message_id=data.get("message_id", ""),
            user_id=data.get("user_id", ""),
            tenant_id=data.get("tenant_id", ""),
            tenant_alias=data.get("tenant_alias", ""),
            sender=data.get("sender", ""),
            recipients=data.get("recipients", []),
            results=[
                VerdictResult.from_dict(r)
                for r in data.get("results", [])
            ],
        )
