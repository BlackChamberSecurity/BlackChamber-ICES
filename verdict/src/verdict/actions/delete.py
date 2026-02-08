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
Action: Delete

Soft-deletes a malicious email (moves to Deleted Items).
The email can still be recovered by the user from the Deleted Items folder.
"""
import uuid
from verdict.actions._base import BaseAction
from verdict.models import VerdictEvent


class DeleteAction(BaseAction):
    """Soft-delete the message (move to Deleted Items)."""

    action_name = "delete"
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
