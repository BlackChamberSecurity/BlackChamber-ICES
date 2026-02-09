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
BlackChamber ICES WebUI — Database Queries

Read-only queries for the message trip dashboard.
Uses ``ices_shared.db.get_connection()`` for pooled connections.
"""

import json
from ices_shared.db import get_connection


# ---------------------------------------------------------------------------
# Message list
# ---------------------------------------------------------------------------

def list_messages(limit: int = 50, offset: int = 0, tenant: str | None = None) -> dict:
    """Return a paginated list of email events with analysis/verdict summary."""
    where = ""
    params: dict = {"limit": limit, "offset": offset}

    if tenant:
        where = "WHERE e.tenant_alias = %(tenant)s"
        params["tenant"] = tenant

    sql = f"""
        SELECT
            e.id,
            e.message_id,
            e.sender,
            e.recipients,
            e.subject,
            e.tenant_alias,
            e.created_at,
            COUNT(DISTINCT ar.analyzer) AS analyzer_count,
            COALESCE(
                (SELECT po.action_taken
                 FROM policy_outcomes po
                 WHERE po.message_id = e.message_id
                 ORDER BY po.created_at DESC LIMIT 1),
                'pending'
            ) AS verdict_action
        FROM email_events e
        LEFT JOIN analysis_results ar ON ar.email_event_id = e.id
        {where}
        GROUP BY e.id
        ORDER BY e.created_at DESC
        LIMIT %(limit)s OFFSET %(offset)s
    """

    count_sql = f"""
        SELECT COUNT(*) AS total FROM email_events e {where}
    """

    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
        total = conn.execute(count_sql, params).fetchone()["total"]

    return {
        "messages": [_serialize_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------
# Message trip detail
# ---------------------------------------------------------------------------

def get_message_trip(message_id: str) -> dict | None:
    """Return the full processing trip for a single message."""
    with get_connection() as conn:
        # Email event
        event = conn.execute(
            """
            SELECT id, message_id, user_id, tenant_id, tenant_alias,
                   sender, recipients, subject, received_at, created_at
            FROM email_events
            WHERE message_id = %(mid)s
            """,
            {"mid": message_id},
        ).fetchone()

        if not event:
            return None

        # Analysis results
        results = conn.execute(
            """
            SELECT analyzer, observations, processing_time_ms, created_at
            FROM analysis_results
            WHERE email_event_id = %(eid)s
            ORDER BY created_at
            """,
            {"eid": event["id"]},
        ).fetchall()

        # Policy outcomes
        outcomes = conn.execute(
            """
            SELECT policy_name, action_taken, matched_observations, created_at
            FROM policy_outcomes
            WHERE message_id = %(mid)s
            ORDER BY created_at
            """,
            {"mid": message_id},
        ).fetchall()

    return {
        "ingestion": _serialize_row(event),
        "analysis": [_serialize_row(r) for r in results],
        "verdict": [_serialize_row(r) for r in outcomes],
    }


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def get_stats() -> dict:
    """Return aggregate dashboard stats."""
    with get_connection() as conn:
        row = conn.execute("""
            SELECT
                (SELECT COUNT(*) FROM email_events) AS total_messages,
                (SELECT COUNT(DISTINCT analyzer) FROM analysis_results) AS active_analyzers,
                (SELECT COUNT(*) FROM policy_outcomes WHERE action_taken != 'none') AS actions_taken,
                (SELECT COUNT(*) FROM policy_outcomes WHERE action_taken = 'none') AS clean_messages
        """).fetchone()

    return _serialize_row(row)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_row(row: dict) -> dict:
    """Convert a psycopg dict row to JSON-safe dict."""
    out = {}
    for k, v in row.items():
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        elif isinstance(v, (list, dict)):
            out[k] = v  # JSONB comes back as native Python
        else:
            out[k] = v
    return out
