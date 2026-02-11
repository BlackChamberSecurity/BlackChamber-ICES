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
BlackChamber ICES Shared Database Module

Provides connection management and schema initialisation for Postgres.
Used by both analysis and verdict workers.
"""
import json
import logging
import os

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://ices:ices_dev@postgres:5432/ices")

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
    recipients      JSONB DEFAULT '[]',
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
    processing_time_ms DOUBLE PRECISION DEFAULT 0.0,
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
# ---------------------------------------------------------------------------
# Connection pool (singleton, created on first use)
# ---------------------------------------------------------------------------
_pool: ConnectionPool | None = None


def _get_pool() -> ConnectionPool:
    """Return (and lazily create) the shared connection pool."""
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=DATABASE_URL,
            min_size=2,
            max_size=10,
            kwargs={"row_factory": dict_row},
        )
    return _pool


def get_connection():
    """Borrow a connection from the pool (use as context manager).

    Usage:
        with get_connection() as conn:
            conn.execute(...)
    """
    return _get_pool().connection()


_DEDUP_SQL = """
-- Remove duplicate email_events (keep lowest id per message_id)
DELETE FROM email_events
WHERE id NOT IN (
    SELECT MIN(id) FROM email_events GROUP BY message_id
);

-- Remove duplicate policy_outcomes (keep latest per message_id + policy_name)
DELETE FROM policy_outcomes
WHERE id NOT IN (
    SELECT MAX(id) FROM policy_outcomes GROUP BY message_id, policy_name
);

-- Unique constraints — prevent future duplicates
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_message_unique
    ON email_events(message_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_outcomes_message_policy_unique
    ON policy_outcomes(message_id, policy_name);
"""


def init_schema():
    """Create tables if they don't exist. Safe to call on every startup."""
    try:
        with get_connection() as conn:
            conn.execute(_SCHEMA_SQL)
            conn.execute(_DEDUP_SQL)
            conn.commit()
        logger.info("Database schema initialised")
    except Exception as exc:
        logger.warning("Database schema init failed (will retry): %s", exc)


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def is_message_processed(conn, message_id: str) -> bool:
    """Return True if this message already has a policy outcome."""
    row = conn.execute(
        "SELECT 1 FROM policy_outcomes WHERE message_id = %(mid)s LIMIT 1",
        {"mid": message_id},
    ).fetchone()
    return row is not None


def store_email_event(conn, verdict_dict: dict) -> int:
    """Insert an email_events row and return the generated id.

    Uses ON CONFLICT to avoid duplicates — if the message already exists,
    the existing row's id is returned instead.
    """
    params = {
        "message_id": verdict_dict.get("message_id", ""),
        "user_id": verdict_dict.get("user_id", ""),
        "tenant_id": verdict_dict.get("tenant_id", ""),
        "tenant_alias": verdict_dict.get("tenant_alias", ""),
        "sender": verdict_dict.get("sender", ""),
        "recipients": json.dumps(verdict_dict.get("recipients", [])),
        "subject": verdict_dict.get("subject", ""),
        "received_at": verdict_dict.get("received_at") or None,
    }
    cur = conn.execute(
        """
        INSERT INTO email_events (message_id, user_id, tenant_id, tenant_alias, sender, recipients, subject, received_at)
        VALUES (%(message_id)s, %(user_id)s, %(tenant_id)s, %(tenant_alias)s, %(sender)s, %(recipients)s, %(subject)s, %(received_at)s)
        ON CONFLICT (message_id) DO NOTHING
        RETURNING id
        """,
        params,
    )
    row = cur.fetchone()
    if row:
        return row["id"]
    # Conflict — fetch existing row
    row = conn.execute(
        "SELECT id FROM email_events WHERE message_id = %(message_id)s",
        {"message_id": params["message_id"]},
    ).fetchone()
    return row["id"]


def store_analysis_results(conn, email_event_id: int, verdict_dict: dict):
    """Insert analysis_results rows for each analyzer result."""
    message_id = verdict_dict.get("message_id", "")
    tenant_id = verdict_dict.get("tenant_id", "")

    for result in verdict_dict.get("results", []):
        conn.execute(
            """
            INSERT INTO analysis_results
                (email_event_id, message_id, tenant_id, analyzer, observations, processing_time_ms)
            VALUES (%(eid)s, %(mid)s, %(tid)s, %(analyzer)s, %(observations)s, %(ptms)s)
            """,
            {
                "eid": email_event_id,
                "mid": message_id,
                "tid": tenant_id,
                "analyzer": result.get("analyzer", ""),
                "observations": json.dumps(result.get("observations", [])),
                "ptms": result.get("processing_time_ms", 0.0),
            },
        )


def store_policy_outcome(conn, message_id: str, tenant_id: str,
                         policy_name: str, action: str, details: dict):
    """Insert or update a policy_outcomes row.

    Uses ON CONFLICT to upsert — if a verdict already exists for this
    message + policy, update it with the latest decision.
    """
    conn.execute(
        """
        INSERT INTO policy_outcomes
            (message_id, tenant_id, policy_name, action_taken, matched_observations)
        VALUES (%(mid)s, %(tid)s, %(pname)s, %(action)s, %(details)s)
        ON CONFLICT (message_id, policy_name) DO UPDATE SET
            action_taken = EXCLUDED.action_taken,
            matched_observations = EXCLUDED.matched_observations,
            created_at = NOW()
        """,
        {
            "mid": message_id,
            "tid": tenant_id,
            "pname": policy_name,
            "action": action,
            "details": json.dumps(details),
        },
    )
