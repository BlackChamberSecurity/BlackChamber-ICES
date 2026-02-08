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
Action: Quarantine

Moves a malicious email to a quarantine folder in the user's mailbox.
Uses the Graph API "move message" endpoint.
"""
import uuid
import os
from verdict.actions._base import BaseAction
from verdict.models import VerdictEvent

# The folder to move quarantined messages to.
# You can use a well-known folder name or a custom folder ID.
QUARANTINE_FOLDER = os.environ.get("QUARANTINE_FOLDER_ID", "junkemail")


class QuarantineAction(BaseAction):
    """Move message to quarantine folder."""

    action_name = "quarantine"
    description = "Moves the email to a quarantine/junk folder"

    def build_request(self, verdict: VerdictEvent) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "method": "POST",
            "url": f"/users/{verdict.user_id}/messages/{verdict.message_id}/move",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "destinationId": QUARANTINE_FOLDER,
            },
        }
