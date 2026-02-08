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
BCEM Shared Database Module

Provides connection management and schema initialisation for Postgres.
Used by both analysis and verdict workers.
"""
import json
import logging
import os

import psycopg
from psycopg.rows import dict_row

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://bcem:bcem_dev@postgres:5432/bcem")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS email_events (
    id              BIGSERIAL PRIMARY KEY,
    message_id      TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    tenant_alias    TEXT DEFAULT '',
    sender          TEXT DEFAULT '',
    subject         TEXT DEFAULT '',
    received_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id              BIGSERIAL PRIMARY KEY,
    email_event_id  BIGINT REFERENCES email_events(id),
    message_id      TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    analyzer        TEXT NOT NULL,
    observations    JSONB DEFAULT '[]',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_outcomes (
    id              BIGSERIAL PRIMARY KEY,
    message_id      TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    policy_name     TEXT DEFAULT '',
    action_taken    TEXT DEFAULT 'none',
    matched_observations JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_results_tenant_analyzer
    ON analysis_results(tenant_id, analyzer);
CREATE INDEX IF NOT EXISTS idx_results_message
    ON analysis_results(message_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_tenant
    ON policy_outcomes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_events_tenant
    ON email_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_events_message
    ON email_events(message_id);
"""


def get_connection() -> psycopg.Connection:
    """Return a new Postgres connection."""
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_schema():
    """Create tables if they don't exist. Safe to call on every startup."""
    try:
        with get_connection() as conn:
            conn.execute(_SCHEMA_SQL)
            conn.commit()
        logger.info("Database schema initialised")
    except Exception as exc:
        logger.warning("Database schema init failed (will retry): %s", exc)


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def store_email_event(conn, verdict_dict: dict) -> int:
    """Insert an email_events row and return the generated id."""
    cur = conn.execute(
        """
        INSERT INTO email_events (message_id, user_id, tenant_id, tenant_alias, sender, subject)
        VALUES (%(message_id)s, %(user_id)s, %(tenant_id)s, %(tenant_alias)s, %(sender)s, %(subject)s)
        RETURNING id
        """,
        {
            "message_id": verdict_dict.get("message_id", ""),
            "user_id": verdict_dict.get("user_id", ""),
            "tenant_id": verdict_dict.get("tenant_id", ""),
            "tenant_alias": verdict_dict.get("tenant_alias", ""),
            "sender": verdict_dict.get("sender", ""),
            "subject": verdict_dict.get("subject", ""),
        },
    )
    row = cur.fetchone()
    return row["id"]


def store_analysis_results(conn, email_event_id: int, verdict_dict: dict):
    """Insert analysis_results rows for each analyzer result."""
    message_id = verdict_dict.get("message_id", "")
    tenant_id = verdict_dict.get("tenant_id", "")

    for result in verdict_dict.get("results", []):
        conn.execute(
            """
            INSERT INTO analysis_results
                (email_event_id, message_id, tenant_id, analyzer, observations)
            VALUES (%(eid)s, %(mid)s, %(tid)s, %(analyzer)s, %(observations)s)
            """,
            {
                "eid": email_event_id,
                "mid": message_id,
                "tid": tenant_id,
                "analyzer": result.get("analyzer", ""),
                "observations": json.dumps(result.get("observations", [])),
            },
        )


def store_policy_outcome(conn, message_id: str, tenant_id: str,
                         policy_name: str, action: str, details: dict):
    """Insert a policy_outcomes row."""
    conn.execute(
        """
        INSERT INTO policy_outcomes
            (message_id, tenant_id, policy_name, action_taken, matched_observations)
        VALUES (%(mid)s, %(tid)s, %(pname)s, %(action)s, %(details)s)
        """,
        {
            "mid": message_id,
            "tid": tenant_id,
            "pname": policy_name,
            "action": action,
            "details": json.dumps(details),
        },
    )
