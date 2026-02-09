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
Shared data models for inter-service communication.

These dataclasses define the canonical shapes that flow between the analysis
and verdict services via the Redis message queue. Both services import from
this single source of truth.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Observation:
    """A single fact discovered by an analyzer.

    Observations use a typed key-value pattern so the policy engine can
    match on them generically without knowing which analyzer produced them.

    Attributes:
        key:   What was observed (e.g. "spf", "ip_urls_found").
        value: The observed value — string, number, or boolean.
        type:  Semantic type hint for the policy engine ("text", "numeric",
               "boolean", "pass_fail").
    """

    key: str = ""
    value: Any = ""
    type: str = "text"

    def to_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "type": self.type}

    @classmethod
    def from_dict(cls, data: dict) -> "Observation":
        return cls(
            key=data.get("key", ""),
            value=data.get("value", ""),
            type=data.get("type", "text"),
        )


@dataclass
class AnalysisResult:
    """Output of a single analyzer run.

    Each analyzer produces exactly one AnalysisResult containing zero or
    more Observations. The result is keyed by the analyzer's name so the
    policy engine can route rules to specific analyzers.

    Attributes:
        analyzer:     Name of the analyzer that produced this result.
        observations: List of facts discovered during analysis.
    """

    analyzer: str = ""
    observations: list[Observation] = field(default_factory=list)
    processing_time_ms: float = 0.0

    def get(self, key: str, default: Any = None) -> Any:
        """Look up an observation value by key."""
        for obs in self.observations:
            if obs.key == key:
                return obs.value
        return default

    def to_dict(self) -> dict:
        return {
            "analyzer": self.analyzer,
            "observations": [o.to_dict() for o in self.observations],
            "processing_time_ms": self.processing_time_ms,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisResult":
        return cls(
            analyzer=data.get("analyzer", ""),
            observations=[
                Observation.from_dict(o)
                for o in data.get("observations", [])
            ],
            processing_time_ms=data.get("processing_time_ms", 0.0),
        )
