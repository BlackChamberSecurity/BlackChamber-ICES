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
Action: Tag

Adds a category label to a suspicious email so users can see it's been
flagged. The email stays in the inbox but is visually marked.

The tag label is derived from the highest analyzer score in the verdict.
"""
import uuid
from verdict.actions._base import BaseAction
from verdict.models import VerdictEvent


def _score_to_label(verdict: VerdictEvent) -> str:
    """Derive a human-readable risk label from the highest analyzer score."""
    max_score = max((r.score for r in verdict.results), default=0)
    if max_score >= 70:
        return "High Risk"
    elif max_score >= 30:
        return "Suspicious"
    return "Low Risk"


class TagAction(BaseAction):
    """Add a warning category to the message."""

    name = "tag"
    description = "Tags the email with a 'BCEM: <risk level>' category"

    def build_request(self, verdict: VerdictEvent) -> dict:
        label = _score_to_label(verdict)
        return {
            "id": str(uuid.uuid4()),
            "method": "PATCH",
            "url": f"/users/{verdict.user_id}/messages/{verdict.message_id}",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "categories": [f"BCEM: {label}"],
                "flag": {
                    "flagStatus": "flagged",
                },
            },
        }
