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
BlackChamber ICES Analysis Engine — Data Models

All canonical data models live in ices_shared.models. This module
re-exports them for backward compatibility and adds the pipeline-specific
EmailEvent dataclass.
"""
from dataclasses import dataclass, field

from ices_shared.models import (
    Observation,
    AnalysisResult,
    EmailAddress,
    EmailBody,
    Attachment,
    Verdict,
)


# ---------------------------------------------------------------------------
# EmailEvent — pipeline-specific input model
# ---------------------------------------------------------------------------

@dataclass
class EmailEvent:
    """
    A fully parsed email entering the analysis pipeline.
    """
    message_id: str = ""
    user_id: str = ""
    tenant_id: str = ""
    tenant_alias: str = ""
    received_at: str = ""
    sender: str = ""
    sender_name: str = ""
    to: list = field(default_factory=list)
    subject: str = ""
    body: EmailBody = field(default_factory=EmailBody)
    headers: dict = field(default_factory=dict)
    attachments: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "EmailEvent":
        """Create an EmailEvent from the JSON dict off the queue.

        Handles two sender formats:
        - Go ingestion: {"sender": "user@example.com"}
        - JSON schema:  {"from": {"address": "user@example.com", "name": "..."}}
        """
        from_data = data.get("from", {})
        to_data = data.get("to", [])
        body_data = data.get("body", {})
        attachments_data = data.get("attachments", [])

        # Sender: prefer 'from.address' (schema), fall back to flat 'sender' (Go)
        sender = from_data.get("address", "") or data.get("sender", "")
        sender_name = from_data.get("name", "") or data.get("sender_name", "")

        return cls(
            message_id=data.get("message_id", ""),
            user_id=data.get("user_id", ""),
            tenant_id=data.get("tenant_id", ""),
            tenant_alias=data.get("tenant_alias", ""),
            received_at=data.get("received_at", ""),
            sender=sender,
            sender_name=sender_name,
            to=[EmailAddress(**r) for r in to_data],
            subject=data.get("subject", ""),
            body=EmailBody(
                content_type=body_data.get("content_type", "text"),
                content=body_data.get("content", ""),
            ),
            headers=data.get("headers", {}),
            attachments=[Attachment(**a) for a in attachments_data],
        )
