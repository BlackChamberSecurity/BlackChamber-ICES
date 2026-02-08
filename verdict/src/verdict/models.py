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
BCEM Verdict Worker — Data Models

Mirrors the analysis engine's Observation model for deserialization.
"""
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Observation:
    """A single typed fact from an analyzer."""
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
class VerdictResult:
    """A single analyzer's observations."""
    analyzer: str = ""
    observations: list = field(default_factory=list)  # list[Observation]

    def get(self, key: str, default: Any = None) -> Any:
        """Get the value of an observation by key."""
        for obs in self.observations:
            if obs.key == key:
                return obs.value
        return default

    def get_all(self, key: str) -> list:
        """Get all values for a given observation key."""
        return [obs.value for obs in self.observations if obs.key == key]


@dataclass
class VerdictEvent:
    """
    A verdict received from the analysis engine.

    Now carries sender and recipients for policy engine matching.
    """
    message_id: str = ""
    user_id: str = ""
    tenant_id: str = ""
    tenant_alias: str = ""
    sender: str = ""
    recipients: list = field(default_factory=list)  # list[str]
    results: list = field(default_factory=list)      # list[VerdictResult]

    @classmethod
    def from_dict(cls, data: dict) -> "VerdictEvent":
        """Deserialise from the queue JSON."""
        return cls(
            message_id=data.get("message_id", ""),
            user_id=data.get("user_id", ""),
            tenant_id=data.get("tenant_id", ""),
            tenant_alias=data.get("tenant_alias", ""),
            sender=data.get("sender", ""),
            recipients=data.get("recipients", []),
            results=[
                VerdictResult(
                    analyzer=r.get("analyzer", ""),
                    observations=[
                        Observation.from_dict(o)
                        for o in r.get("observations", [])
                    ],
                )
                for r in data.get("results", [])
            ],
        )
