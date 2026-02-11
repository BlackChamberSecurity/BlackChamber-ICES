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
BEC Analyzer — Self-Contained Database Layer

Owns the ``sender_profiles`` and ``sender_recipient_pairs`` tables.
Uses only ``get_connection()`` from ices_shared.db (the connection pool);
no schema modifications are made to the shared module.

Schema is initialised lazily on first use and is idempotent.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from analysis.analyzers.bec.models import SenderProfile, SenderRecipientPair

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema DDL — owned entirely by this module
# ---------------------------------------------------------------------------

_BEC_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sender_profiles (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    sender_domain       TEXT NOT NULL,
    email_count         INT DEFAULT 0,
    first_seen_at       TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ,
    known_display_names JSONB DEFAULT '[]',
    typical_categories  JSONB DEFAULT '{}',
    typical_send_hours  JSONB DEFAULT '{}',
    reply_to_domains    JSONB DEFAULT '[]',
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, sender_domain)
);

CREATE TABLE IF NOT EXISTS sender_recipient_pairs (
    id                    BIGSERIAL PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    sender_addr           TEXT NOT NULL,
    sender_domain         TEXT NOT NULL,
    recipient_addr        TEXT NOT NULL,
    message_count         INT DEFAULT 0,
    first_contact_at      TIMESTAMPTZ,
    last_contact_at       TIMESTAMPTZ,
    category_distribution JSONB DEFAULT '{}',
    updated_at            TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, sender_addr, recipient_addr)
);

CREATE INDEX IF NOT EXISTS idx_sp_tenant_domain
    ON sender_profiles(tenant_id, sender_domain);
CREATE INDEX IF NOT EXISTS idx_srp_tenant_sender_recip
    ON sender_recipient_pairs(tenant_id, sender_addr, recipient_addr);
CREATE INDEX IF NOT EXISTS idx_srp_tenant_domain_recip
    ON sender_recipient_pairs(tenant_id, sender_domain, recipient_addr);
"""

_schema_initialised = False


def init_bec_schema() -> None:
    """Create BEC tables if they don't exist.  Safe to call repeatedly."""
    global _schema_initialised
    if _schema_initialised:
        return
    try:
        from ices_shared.db import get_connection
        with get_connection() as conn:
            conn.execute(_BEC_SCHEMA_SQL)
            conn.commit()
        _schema_initialised = True
        logger.info("BEC schema initialised")
    except Exception as exc:
        logger.warning("BEC schema init failed (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# Sender profile helpers
# ---------------------------------------------------------------------------

def get_sender_profile(
    conn, tenant_id: str, sender_domain: str,
) -> Optional[SenderProfile]:
    """Fetch the sender profile, or None if not yet seen."""
    row = conn.execute(
        """
        SELECT tenant_id, sender_domain, email_count,
               first_seen_at, last_seen_at,
               known_display_names, typical_categories,
               typical_send_hours, reply_to_domains
        FROM sender_profiles
        WHERE tenant_id = %(tid)s AND sender_domain = %(sd)s
        """,
        {"tid": tenant_id, "sd": sender_domain},
    ).fetchone()

    if row is None:
        return None

    return SenderProfile(
        tenant_id=row["tenant_id"],
        sender_domain=row["sender_domain"],
        email_count=row["email_count"],
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
        known_display_names=row["known_display_names"] or [],
        typical_categories=row["typical_categories"] or {},
        typical_send_hours=row["typical_send_hours"] or {},
        reply_to_domains=row["reply_to_domains"] or [],
    )


def upsert_sender_profile(
    conn,
    tenant_id: str,
    sender_domain: str,
    *,
    display_name: str = "",
    category: str = "",
    send_hour: int = -1,
    reply_to_domain: str = "",
    now: Optional[datetime] = None,
) -> None:
    """Insert or update the sender profile with new observation data.

    Uses Postgres JSONB operators to append to arrays and increment
    counters atomically.
    """
    now = now or datetime.now(timezone.utc)

    # --- upsert base row ---
    conn.execute(
        """
        INSERT INTO sender_profiles
            (tenant_id, sender_domain, email_count, first_seen_at, last_seen_at,
             known_display_names, typical_categories, typical_send_hours,
             reply_to_domains, updated_at)
        VALUES
            (%(tid)s, %(sd)s, 1, %(now)s, %(now)s,
             '[]'::jsonb, '{}'::jsonb, '{}'::jsonb, '[]'::jsonb, %(now)s)
        ON CONFLICT (tenant_id, sender_domain) DO UPDATE SET
            email_count = sender_profiles.email_count + 1,
            last_seen_at = %(now)s,
            updated_at = %(now)s
        """,
        {"tid": tenant_id, "sd": sender_domain, "now": now},
    )

    # --- append display name if new ---
    if display_name:
        conn.execute(
            """
            UPDATE sender_profiles
            SET known_display_names = (
                SELECT jsonb_agg(DISTINCT elem)
                FROM jsonb_array_elements(
                    known_display_names || %(dn)s::jsonb
                ) AS elem
            )
            WHERE tenant_id = %(tid)s AND sender_domain = %(sd)s
            """,
            {
                "tid": tenant_id,
                "sd": sender_domain,
                "dn": json.dumps(display_name),
            },
        )

    # --- increment category counter ---
    if category:
        conn.execute(
            """
            UPDATE sender_profiles
            SET typical_categories = jsonb_set(
                typical_categories,
                %(path)s,
                to_jsonb(COALESCE((typical_categories->>%(cat)s)::int, 0) + 1)
            )
            WHERE tenant_id = %(tid)s AND sender_domain = %(sd)s
            """,
            {
                "tid": tenant_id,
                "sd": sender_domain,
                "path": "{" + category + "}",
                "cat": category,
            },
        )

    # --- increment send-hour counter ---
    if send_hour >= 0:
        hour_key = str(send_hour)
        conn.execute(
            """
            UPDATE sender_profiles
            SET typical_send_hours = jsonb_set(
                typical_send_hours,
                %(path)s,
                to_jsonb(COALESCE((typical_send_hours->>%(hk)s)::int, 0) + 1)
            )
            WHERE tenant_id = %(tid)s AND sender_domain = %(sd)s
            """,
            {
                "tid": tenant_id,
                "sd": sender_domain,
                "path": "{" + hour_key + "}",
                "hk": hour_key,
            },
        )

    # --- append reply-to domain if new ---
    if reply_to_domain:
        conn.execute(
            """
            UPDATE sender_profiles
            SET reply_to_domains = (
                SELECT jsonb_agg(DISTINCT elem)
                FROM jsonb_array_elements(
                    reply_to_domains || %(rd)s::jsonb
                ) AS elem
            )
            WHERE tenant_id = %(tid)s AND sender_domain = %(sd)s
            """,
            {
                "tid": tenant_id,
                "sd": sender_domain,
                "rd": json.dumps(reply_to_domain),
            },
        )


# ---------------------------------------------------------------------------
# Sender-recipient pair helpers
# ---------------------------------------------------------------------------

def get_sender_recipient_pair(
    conn, tenant_id: str, sender_addr: str, recipient_addr: str,
) -> Optional[SenderRecipientPair]:
    """Fetch the pair record by exact sender address, or None."""
    row = conn.execute(
        """
        SELECT tenant_id, sender_addr, sender_domain, recipient_addr,
               message_count, first_contact_at, last_contact_at,
               category_distribution
        FROM sender_recipient_pairs
        WHERE tenant_id = %(tid)s
          AND sender_addr = %(sa)s
          AND recipient_addr = %(ra)s
        """,
        {"tid": tenant_id, "sa": sender_addr, "ra": recipient_addr},
    ).fetchone()

    if row is None:
        return None

    return SenderRecipientPair(
        tenant_id=row["tenant_id"],
        sender_addr=row["sender_addr"],
        sender_domain=row["sender_domain"],
        recipient_addr=row["recipient_addr"],
        message_count=row["message_count"],
        first_contact_at=row["first_contact_at"],
        last_contact_at=row["last_contact_at"],
        category_distribution=row["category_distribution"] or {},
    )


def get_domain_pair_summary(
    conn, tenant_id: str, sender_domain: str, recipient_addr: str,
) -> Optional[SenderRecipientPair]:
    """Aggregate all pair history from a domain to a recipient.

    Returns a synthetic SenderRecipientPair whose message_count and
    category_distribution are the sum across all individual senders
    from the given domain.
    """
    row = conn.execute(
        """
        SELECT COALESCE(SUM(message_count), 0) AS total_count,
               MIN(first_contact_at)            AS first_contact,
               MAX(last_contact_at)             AS last_contact
        FROM sender_recipient_pairs
        WHERE tenant_id = %(tid)s
          AND sender_domain = %(sd)s
          AND recipient_addr = %(ra)s
        """,
        {"tid": tenant_id, "sd": sender_domain, "ra": recipient_addr},
    ).fetchone()

    if row is None or row["total_count"] == 0:
        return None

    return SenderRecipientPair(
        tenant_id=tenant_id,
        sender_addr="*@" + sender_domain,
        sender_domain=sender_domain,
        recipient_addr=recipient_addr,
        message_count=row["total_count"],
        first_contact_at=row["first_contact"],
        last_contact_at=row["last_contact"],
    )


def upsert_sender_recipient_pair(
    conn,
    tenant_id: str,
    sender_addr: str,
    sender_domain: str,
    recipient_addr: str,
    *,
    category: str = "",
    now: Optional[datetime] = None,
) -> None:
    """Insert or update the sender-recipient pair."""
    now = now or datetime.now(timezone.utc)

    conn.execute(
        """
        INSERT INTO sender_recipient_pairs
            (tenant_id, sender_addr, sender_domain, recipient_addr,
             message_count, first_contact_at, last_contact_at,
             category_distribution, updated_at)
        VALUES
            (%(tid)s, %(sa)s, %(sd)s, %(ra)s, 1,
             %(now)s, %(now)s, '{}'::jsonb, %(now)s)
        ON CONFLICT (tenant_id, sender_addr, recipient_addr) DO UPDATE SET
            message_count = sender_recipient_pairs.message_count + 1,
            last_contact_at = %(now)s,
            updated_at = %(now)s
        """,
        {
            "tid": tenant_id, "sa": sender_addr,
            "sd": sender_domain, "ra": recipient_addr, "now": now,
        },
    )

    if category:
        conn.execute(
            """
            UPDATE sender_recipient_pairs
            SET category_distribution = jsonb_set(
                category_distribution,
                %(path)s,
                to_jsonb(COALESCE((category_distribution->>%(cat)s)::int, 0) + 1)
            )
            WHERE tenant_id = %(tid)s
              AND sender_addr = %(sa)s
              AND recipient_addr = %(ra)s
            """,
            {
                "tid": tenant_id,
                "sa": sender_addr,
                "ra": recipient_addr,
                "path": "{" + category + "}",
                "cat": category,
            },
        )
