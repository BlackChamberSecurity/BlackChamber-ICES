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
Action: Delete

Soft-deletes a malicious email (moves to Deleted Items).
The email can still be recovered by the user from the Deleted Items folder.
"""
import uuid
from verdict.actions._base import BaseAction
from verdict.models import VerdictEvent


class DeleteAction(BaseAction):
    """Soft-delete the message (move to Deleted Items)."""

    name = "delete"
    description = "Moves the email to Deleted Items folder"

    def build_request(self, verdict: VerdictEvent) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "method": "POST",
            "url": f"/users/{verdict.user_id}/messages/{verdict.message_id}/move",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "destinationId": "deleteditems",
            },
        }
