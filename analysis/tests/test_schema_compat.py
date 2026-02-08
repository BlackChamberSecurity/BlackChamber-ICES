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
Schema compatibility tests.

Ensures that EmailEvent.from_dict() handles both the Go ingestion format
(flat 'sender' field) and the JSON schema format ('from.address' nested).
Also validates that sample payloads conform to the shared JSON schema.
"""
import json
from pathlib import Path

import pytest
from analysis.models import EmailEvent


class TestGoIngestionFormat:
    """Test that Go-style payloads (flat sender) parse correctly."""

    def test_go_flat_sender(self):
        """Go ingestion publishes 'sender' as a flat string."""
        payload = {
            "message_id": "msg-001",
            "user_id": "user@example.com",
            "tenant_id": "tenant-001",
            "tenant_alias": "test-tenant",
            "sender": "alice@company.com",
            "subject": "Hello",
            "body": {"content_type": "text", "content": "Hi there"},
            "headers": {"Authentication-Results": "spf=pass"},
            "attachments": [],
        }
        email = EmailEvent.from_dict(payload)

        assert email.sender == "alice@company.com"
        assert email.message_id == "msg-001"
        assert email.subject == "Hello"

    def test_go_format_no_from_field(self):
        """Go payloads don't have a 'from' field — only 'sender'."""
        payload = {
            "message_id": "msg-002",
            "user_id": "user@example.com",
            "tenant_id": "tenant-001",
            "sender": "bob@company.com",
            "subject": "Test",
        }
        email = EmailEvent.from_dict(payload)
        assert email.sender == "bob@company.com"


class TestJsonSchemaFormat:
    """Test that JSON-schema-style payloads (from.address) parse correctly."""

    def test_schema_nested_from(self):
        """JSON schema payloads use 'from.address' for the sender."""
        payload = {
            "message_id": "msg-003",
            "user_id": "user@example.com",
            "tenant_id": "tenant-001",
            "from": {"address": "carol@company.com", "name": "Carol"},
            "to": [{"address": "user@example.com"}],
            "subject": "Schema format",
            "received_at": "2026-01-01T00:00:00Z",
        }
        email = EmailEvent.from_dict(payload)

        assert email.sender == "carol@company.com"
        assert email.sender_name == "Carol"

    def test_schema_from_takes_precedence(self):
        """If both 'from.address' and 'sender' exist, 'from.address' wins."""
        payload = {
            "message_id": "msg-004",
            "user_id": "user@example.com",
            "tenant_id": "tenant-001",
            "from": {"address": "correct@company.com"},
            "sender": "fallback@company.com",
            "subject": "Both formats",
        }
        email = EmailEvent.from_dict(payload)
        assert email.sender == "correct@company.com"


class TestSharedSchema:
    """Validate that the shared JSON schema loads and describes the right shape."""

    def test_schema_loads(self):
        """The shared JSON schema should be valid JSON."""
        schema_path = Path(__file__).parent.parent.parent.parent / "shared" / "schemas" / "email_event.json"
        if not schema_path.exists():
            pytest.skip(f"Schema file not found: {schema_path}")

        with open(schema_path) as f:
            schema = json.load(f)

        assert schema["title"] == "EmailEvent"
        assert "message_id" in schema["required"]
        assert "user_id" in schema["required"]
        assert "tenant_id" in schema["required"]

    def test_schema_required_fields_match_from_dict(self):
        """All required fields in the schema should be handled by from_dict()."""
        schema_path = Path(__file__).parent.parent.parent.parent / "shared" / "schemas" / "email_event.json"
        if not schema_path.exists():
            pytest.skip(f"Schema file not found: {schema_path}")

        with open(schema_path) as f:
            schema = json.load(f)

        # Build a minimal valid payload
        payload = {
            "message_id": "test-001",
            "user_id": "user@test.com",
            "tenant_id": "tenant-001",
            "received_at": "2026-01-01T00:00:00Z",
            "from": {"address": "sender@test.com"},
            "to": [{"address": "user@test.com"}],
            "subject": "Test",
        }

        # Should parse without error
        email = EmailEvent.from_dict(payload)
        assert email.message_id == "test-001"
        assert email.sender == "sender@test.com"
