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
BCEM Analysis Engine — Data Models

These dataclasses define the data structures flowing through the analysis
pipeline. They match the shared JSON schema in shared/schemas/email_event.json.

For beginners:
- EmailEvent   = the email that came in (input)
- AnalysisResult = what one analyzer found (intermediate)
- Verdict      = the final decision (output)
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EmailAddress:
    """An email sender or recipient."""
    address: str
    name: str = ""


@dataclass
class EmailBody:
    """The content of an email."""
    content_type: str = "text"   # "text" or "html"
    content: str = ""


@dataclass
class Attachment:
    """An email attachment."""
    name: str = ""
    content_type: str = ""
    size: int = 0
    content_bytes: str = ""      # Base64-encoded


@dataclass
class EmailEvent:
    """
    A fully parsed email entering the analysis pipeline.

    This is what each analyzer receives. Key fields:
    - sender:      who sent the email (email address string)
    - subject:     email subject line
    - body:        email body content
    - headers:     raw internet message headers (dict)
    - attachments: list of file attachments
    """
    message_id: str = ""
    user_id: str = ""
    tenant_id: str = ""
    tenant_alias: str = ""
    received_at: str = ""
    sender: str = ""             # Flattened from.address for convenience
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


@dataclass
class AnalysisResult:
    """
    The output of a single analyzer.

    Fields:
    - analyzer:  name of the analyzer that produced this result
    - score:     0-100 scale (meaning depends on the analyzer)
    - findings:  human-readable list of what was found
    - provider:  SaaS provider name (e.g. "Dropbox") — set by saas_usage analyzer
    - category:  email category (e.g. "transactional", "marketing") — set by saas_usage analyzer
    """
    analyzer: str = ""
    score: int = 0
    findings: list = field(default_factory=list)
    provider: str = ""
    category: str = ""


@dataclass
class Verdict:
    """
    The collection of all analyzer results for an email.

    No aggregated score — each analyzer's result is returned individually.

    Fields:
    - message_id:    which email this verdict is for
    - user_id:       whose mailbox it was in
    - tenant_id:     which M365 tenant
    - tenant_alias:  human-readable tenant name (e.g. "mainmethod")
    - results:       list of individual analyzer results
    """
    message_id: str = ""
    user_id: str = ""
    tenant_id: str = ""
    tenant_alias: str = ""
    results: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise verdict to a JSON-safe dict for the queue."""
        return {
            "message_id": self.message_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "tenant_alias": self.tenant_alias,
            "results": [
                {
                    "analyzer": r.analyzer,
                    "score": r.score,
                    "findings": r.findings,
                    "provider": r.provider,
                    "category": r.category,
                }
                for r in self.results
            ],
        }
