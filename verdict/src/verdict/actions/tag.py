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
Action: Tag

Adds a "BCEM: Flagged" category to a suspicious email so users can see
it's been flagged. The email stays in the inbox but is visually marked.
"""
import uuid
from verdict.actions._base import BaseAction
from verdict.models import VerdictEvent


class TagAction(BaseAction):
    """Add a warning category to the message."""

    action_name = "tag"
    description = "Tags the email with a 'BCEM: Flagged' category"

    def build_request(self, verdict: VerdictEvent) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "method": "PATCH",
            "url": f"/users/{verdict.user_id}/messages/{verdict.message_id}",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "categories": ["BCEM: Flagged"],
                "flag": {
                    "flagStatus": "flagged",
                },
            },
        }
