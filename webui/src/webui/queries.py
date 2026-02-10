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
# SaaS analytics
# ---------------------------------------------------------------------------

def get_saas_analytics(
    days: int = 30,
    tenant: str | None = None,
    user: str | None = None,
    provider: str | None = None,
) -> dict:
    """Return aggregated SaaS usage analytics from analysis results."""
    where_parts = [
        "ar.analyzer = 'saas_usage'",
        "COALESCE(e.received_at, e.created_at) >= NOW() - make_interval(days => %(days)s)",
    ]
    params: dict = {"days": days}

    if tenant:
        where_parts.append("e.tenant_alias = %(tenant)s")
        params["tenant"] = tenant

    if user:
        where_parts.append("e.user_id = %(user_filter)s")
        params["user_filter"] = user

    # Optional provider filter — applied as an extra predicate on provider obs
    prov_filter_sql = ""
    if provider:
        prov_filter_sql = "AND obs_pf->>'value' = %(provider_filter)s"
        params["provider_filter"] = provider

    where = " AND ".join(where_parts)

    # When provider filter is set, we need an additional JOIN to restrict rows
    provider_join = ""
    if provider:
        provider_join = f"""
            JOIN LATERAL (
                SELECT val FROM jsonb_array_elements(ar.observations) AS val
                WHERE val->>'key' = 'provider'
                  AND val->>'value' = %(provider_filter)s
                LIMIT 1
            ) obs_pf ON TRUE
        """

    with get_connection() as conn:
        # --- Provider breakdown (top 20) ---
        providers = conn.execute(f"""
            SELECT
                obs->>'value' AS provider,
                COUNT(*) AS count
            FROM analysis_results ar
            JOIN email_events e ON e.id = ar.email_event_id
            {provider_join}
            , LATERAL jsonb_array_elements(ar.observations) AS obs
            WHERE {where}
              AND obs->>'key' = 'provider'
              AND obs->>'value' IS NOT NULL
            GROUP BY obs->>'value'
            ORDER BY count DESC
            LIMIT 20
        """, params).fetchall()

        # --- Category breakdown ---
        categories = conn.execute(f"""
            SELECT
                obs->>'value' AS category,
                COUNT(*) AS count
            FROM analysis_results ar
            JOIN email_events e ON e.id = ar.email_event_id
            {provider_join}
            , LATERAL jsonb_array_elements(ar.observations) AS obs
            WHERE {where}
              AND obs->>'key' = 'category'
              AND obs->>'value' IS NOT NULL
            GROUP BY obs->>'value'
            ORDER BY count DESC
        """, params).fetchall()

        # --- Usage vs Marketing split ---
        classification = conn.execute(f"""
            SELECT
                obs->>'value' AS category,
                COUNT(*) AS count
            FROM analysis_results ar
            JOIN email_events e ON e.id = ar.email_event_id
            {provider_join}
            , LATERAL jsonb_array_elements(ar.observations) AS obs
            WHERE {where}
              AND obs->>'key' = 'category'
              AND obs->>'value' IS NOT NULL
            GROUP BY obs->>'value'
        """, params).fetchall()

        # --- Daily timeline ---
        timeline = conn.execute(f"""
            SELECT
                DATE(COALESCE(e.received_at, e.created_at)) AS day,
                COUNT(*) AS count
            FROM analysis_results ar
            JOIN email_events e ON e.id = ar.email_event_id
            {provider_join}
            WHERE {where}
            GROUP BY DATE(COALESCE(e.received_at, e.created_at))
            ORDER BY day
        """, params).fetchall()

        # --- Provider → Users mapping (top 20 providers, up to 10 users each) ---
        provider_users = conn.execute(f"""
            SELECT
                obs->>'value' AS provider,
                e.user_id,
                COUNT(*) AS count
            FROM analysis_results ar
            JOIN email_events e ON e.id = ar.email_event_id
            {provider_join}
            , LATERAL jsonb_array_elements(ar.observations) AS obs
            WHERE {where}
              AND obs->>'key' = 'provider'
              AND obs->>'value' IS NOT NULL
            GROUP BY obs->>'value', e.user_id
            ORDER BY obs->>'value', count DESC
        """, params).fetchall()

        # --- Distinct users list ---
        users_rows = conn.execute(f"""
            SELECT DISTINCT e.user_id
            FROM analysis_results ar
            JOIN email_events e ON e.id = ar.email_event_id
            {provider_join}
            WHERE {where}
            ORDER BY e.user_id
        """, params).fetchall()

        # --- Totals ---
        totals = conn.execute(f"""
            SELECT
                COUNT(*) AS total_saas_emails,
                (SELECT COUNT(DISTINCT obs->>'value')
                 FROM analysis_results ar2
                 JOIN email_events e2 ON e2.id = ar2.email_event_id,
                 LATERAL jsonb_array_elements(ar2.observations) AS obs
                 WHERE ar2.analyzer = 'saas_usage'
                   AND ar2.created_at >= NOW() - make_interval(days => %(days)s)
                   AND obs->>'key' = 'provider'
                   {"AND e2.tenant_alias = %(tenant)s" if tenant else ""}
                   {"AND e2.user_id = %(user_filter)s" if user else ""}
                ) AS unique_providers,
                (SELECT COUNT(DISTINCT obs->>'value')
                 FROM analysis_results ar3
                 JOIN email_events e3 ON e3.id = ar3.email_event_id,
                 LATERAL jsonb_array_elements(ar3.observations) AS obs
                 WHERE ar3.analyzer = 'saas_usage'
                   AND ar3.created_at >= NOW() - make_interval(days => %(days)s)
                   AND obs->>'key' = 'category'
                   {"AND e3.tenant_alias = %(tenant)s" if tenant else ""}
                   {"AND e3.user_id = %(user_filter)s" if user else ""}
                ) AS unique_categories,
                COUNT(DISTINCT e.user_id) AS unique_users
            FROM analysis_results ar
            JOIN email_events e ON e.id = ar.email_event_id
            {provider_join}
            WHERE {where}
        """, params).fetchone()

    # Compute usage percentage
    usage_count = sum(r["count"] for r in classification if r["category"] == "usage")
    marketing_count = sum(r["count"] for r in classification if r["category"] == "marketing")
    total_classified = usage_count + marketing_count

    # Group users by provider
    provider_users_map: dict[str, list] = {}
    for row in provider_users:
        prov = row["provider"]
        if prov not in provider_users_map:
            provider_users_map[prov] = []
        provider_users_map[prov].append({
            "user_id": row["user_id"],
            "count": row["count"],
        })

    return {
        "providers": [_serialize_row(r) for r in providers],
        "categories": [_serialize_row(r) for r in categories],
        "classification": {
            "usage": usage_count,
            "marketing": marketing_count,
            "usage_pct": round(usage_count / total_classified * 100) if total_classified else 0,
        },
        "timeline": [_serialize_row(r) for r in timeline],
        "provider_users": provider_users_map,
        "users": [r["user_id"] for r in users_rows],
        "totals": _serialize_row(totals) if totals else {
            "total_saas_emails": 0,
            "unique_providers": 0,
            "unique_categories": 0,
            "unique_users": 0,
        },
        "days": days,
    }



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

