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
Tests for database-level deduplication.

Validates that:
1. store_email_event is idempotent per message_id
2. store_policy_outcome upserts on (message_id, policy_name)
3. is_message_processed correctly detects existing outcomes
"""
import os
import json
import pytest

# Skip entire module if no Postgres connection available
pytestmark = pytest.mark.skipif(
    not os.getenv("DATABASE_URL"),
    reason="DATABASE_URL not set — skipping DB integration tests",
)


@pytest.fixture(scope="module")
def db_conn():
    """Provide a Postgres connection with a clean schema."""
    from ices_shared.db import get_connection, init_schema
    init_schema()

    with get_connection() as conn:
        # Clean tables before test run
        conn.execute("DELETE FROM policy_outcomes")
        conn.execute("DELETE FROM analysis_results")
        conn.execute("DELETE FROM email_events")
        conn.commit()
        yield conn
        # Clean up after tests
        conn.execute("DELETE FROM policy_outcomes")
        conn.execute("DELETE FROM analysis_results")
        conn.execute("DELETE FROM email_events")
        conn.commit()


class TestStoreEmailEventDedup:
    """store_email_event should be idempotent per message_id."""

    def test_first_insert_returns_id(self, db_conn):
        from ices_shared.db import store_email_event

        event = {
            "message_id": "dedup-test-001",
            "user_id": "user@test.com",
            "tenant_id": "t-1",
            "tenant_alias": "test",
            "sender": "a@b.com",
            "recipients": ["c@d.com"],
            "subject": "Test",
        }
        event_id = store_email_event(db_conn, event)
        db_conn.commit()
        assert isinstance(event_id, int)
        assert event_id > 0

    def test_duplicate_returns_same_id(self, db_conn):
        from ices_shared.db import store_email_event

        event = {
            "message_id": "dedup-test-002",
            "user_id": "user@test.com",
            "tenant_id": "t-1",
            "tenant_alias": "test",
            "sender": "a@b.com",
            "recipients": [],
            "subject": "Dup Test",
        }
        id1 = store_email_event(db_conn, event)
        db_conn.commit()
        id2 = store_email_event(db_conn, event)
        db_conn.commit()
        assert id1 == id2

    def test_no_duplicate_rows(self, db_conn):
        """Inserting the same message_id twice should leave exactly one row."""
        row = db_conn.execute(
            "SELECT COUNT(*) AS cnt FROM email_events WHERE message_id = 'dedup-test-002'"
        ).fetchone()
        assert row["cnt"] == 1


class TestStorePolicyOutcomeDedup:
    """store_policy_outcome should upsert on (message_id, policy_name)."""

    def test_first_outcome_inserts(self, db_conn):
        from ices_shared.db import store_policy_outcome

        store_policy_outcome(
            db_conn,
            message_id="dedup-test-001",
            tenant_id="t-1",
            policy_name="quarantine-dmarc",
            action="quarantine",
            details={"action": "quarantine", "policy_name": "quarantine-dmarc"},
        )
        db_conn.commit()

        row = db_conn.execute(
            "SELECT action_taken FROM policy_outcomes WHERE message_id = 'dedup-test-001'"
        ).fetchone()
        assert row["action_taken"] == "quarantine"

    def test_duplicate_updates_in_place(self, db_conn):
        from ices_shared.db import store_policy_outcome

        # Update the same message+policy with a different action
        store_policy_outcome(
            db_conn,
            message_id="dedup-test-001",
            tenant_id="t-1",
            policy_name="quarantine-dmarc",
            action="tag",
            details={"action": "tag", "policy_name": "quarantine-dmarc"},
        )
        db_conn.commit()

        rows = db_conn.execute(
            "SELECT * FROM policy_outcomes WHERE message_id = 'dedup-test-001' AND policy_name = 'quarantine-dmarc'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["action_taken"] == "tag"


class TestIsMessageProcessed:
    """is_message_processed should detect existing outcomes."""

    def test_unprocessed_returns_false(self, db_conn):
        from ices_shared.db import is_message_processed

        assert is_message_processed(db_conn, "nonexistent-msg") is False

    def test_processed_returns_true(self, db_conn):
        from ices_shared.db import is_message_processed

        # dedup-test-001 was given an outcome in previous tests
        assert is_message_processed(db_conn, "dedup-test-001") is True
