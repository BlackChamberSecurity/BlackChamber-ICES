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
Analyzer: Business Email Compromise (BEC) Detection

Combines behavioral analysis (sender history, relationship strength, writing style)
with NLP-based intent classification to detect BEC attacks.

Features:
  - **New Sender Detection**: Flags if a sender has never emailed this tenant before.
  - **New Relationship**: Flags if sender has never emailed this specific recipient.
  - **Style Mismatch**: Flags if message length deviates significantly from sender's average.
  - **Intent Analysis**: Uses zero-shot NLP to detect "urgent", "financial", or "threat" language.
  - **Self-contained State**: Manages its own 'bec_sender_profiles' and 'bec_relationships' tables.

Observations produced:
    bec_intent          (text)     — Detected intent (financial, urgent, threat, etc.)
    bec_confidence      (numeric)  — Confidence of the intent (0-100)
    is_new_sender       (boolean)  — True if sender is new to the tenant
    is_new_relationship (boolean)  — True if sender-recipient pair is new
    sender_days_active  (numeric)  — Days since first seen (0 for new)
    relationship_count  (numeric)  — Number of prior emails between pair
    style_mismatch      (text)     — "unusually_short" if applicable
"""
import logging
import re
from datetime import datetime, timezone

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent, Observation
from analysis.nlp import get_nlp_classifier
from ices_shared.db import get_connection

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema & DB Helpers
# ---------------------------------------------------------------------------
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS bec_sender_profiles (
    sender          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    message_count   INTEGER DEFAULT 1,
    avg_chars       INTEGER DEFAULT 0,
    PRIMARY KEY (sender, tenant_id)
);

CREATE TABLE IF NOT EXISTS bec_relationships (
    sender          TEXT NOT NULL,
    recipient       TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    interaction_count INTEGER DEFAULT 1,
    PRIMARY KEY (sender, recipient, tenant_id)
);
"""

_schema_initialized = False

def _ensure_schema():
    """Idempotent schema initialization."""
    global _schema_initialized
    if _schema_initialized:
        return

    try:
        with get_connection() as conn:
            conn.execute(_SCHEMA_SQL)
            # Add column if missing (simple migration for dev/test environments)
            try:
                conn.execute("ALTER TABLE bec_sender_profiles ADD COLUMN IF NOT EXISTS avg_chars INTEGER DEFAULT 0")
            except Exception:
                pass # Column likely exists or table not created yet (handled by CREATE)
            conn.commit()
        _schema_initialized = True
        logger.info("BEC Analyzer schema initialized")
    except Exception as exc:
        logger.error("Failed to init BEC schema: %s", exc)

def _get_sender_profile(conn, sender: str, tenant_id: str) -> dict | None:
    """Fetch sender profile from DB."""
    row = conn.execute(
        "SELECT first_seen, message_count, avg_chars FROM bec_sender_profiles WHERE sender = %s AND tenant_id = %s",
        (sender, tenant_id)
    ).fetchone()
    return row

def _get_relationship(conn, sender: str, recipient: str, tenant_id: str) -> dict | None:
    """Fetch relationship stats from DB."""
    row = conn.execute(
        "SELECT interaction_count FROM bec_relationships WHERE sender = %s AND recipient = %s AND tenant_id = %s",
        (sender, recipient, tenant_id)
    ).fetchone()
    return row

def _update_stats(sender: str, recipients: list[str], tenant_id: str, msg_len: int):
    """Update sender profile and relationships (fire-and-forget style)."""
    try:
        with get_connection() as conn:
            # Upsert sender profile with running average calculation
            # NewAvg = (OldAvg * Count + NewLen) / (Count + 1)
            # Since we can't easily do this in one SQL statement without reading first or complex CTE,
            # we'll approximate or use a simplified update logic.
            # Here we use a CASE statement to handle the insert vs update logic slightly differently if possible,
            # but ON CONFLICT makes it tricky to reference the 'old' values directly in a simple way for average.
            # Standard pattern:
            conn.execute(
                """
                INSERT INTO bec_sender_profiles (sender, tenant_id, first_seen, last_seen, message_count, avg_chars)
                VALUES (%s, %s, NOW(), NOW(), 1, %s)
                ON CONFLICT (sender, tenant_id) DO UPDATE SET
                    last_seen = NOW(),
                    avg_chars = (bec_sender_profiles.avg_chars * bec_sender_profiles.message_count + EXCLUDED.avg_chars) / (bec_sender_profiles.message_count + 1),
                    message_count = bec_sender_profiles.message_count + 1
                """,
                (sender, tenant_id, msg_len)
            )

            # Upsert relationships
            for rcpt in recipients:
                conn.execute(
                    """
                    INSERT INTO bec_relationships (sender, recipient, tenant_id, first_seen, last_seen, interaction_count)
                    VALUES (%s, %s, %s, NOW(), NOW(), 1)
                    ON CONFLICT (sender, recipient, tenant_id) DO UPDATE SET
                        last_seen = NOW(),
                        interaction_count = bec_relationships.interaction_count + 1
                    """,
                    (sender, rcpt, tenant_id)
                )
            conn.commit()
    except Exception as exc:
        logger.warning("Failed to update BEC stats for %s: %s", sender, exc)

# ---------------------------------------------------------------------------
# Text Extraction Helper
# ---------------------------------------------------------------------------
def _extract_text(email: EmailEvent) -> str:
    """Combine subject and body for NLP."""
    content = email.body.content or ""
    # Simple HTML strip if needed
    if email.body.content_type == "html" or "<" in content[:50]:
        content = re.sub(r"<[^>]+>", " ", content)

    text = f"{email.subject}\n\n{content}"
    return re.sub(r"\s+", " ", text).strip()[:1000]  # Limit to 1000 chars

# ---------------------------------------------------------------------------
# BEC Analyzer
# ---------------------------------------------------------------------------
class BECAnalyzer(BaseAnalyzer):
    """
    Advanced Business Email Compromise detection.

    Combines:
    1. Behavioral anomalies (new sender, new relationship, style mismatch)
    2. Intent classification (financial request, urgency, threat)
    """
    name = "bec_analyzer"
    description = "Behavioral + NLP analysis for BEC detection"
    order = 60  # Run after standard checks

    def __init__(self):
        # Ensure tables exist when worker starts (or on first run)
        _ensure_schema()

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        observations = []

        sender = email.sender.lower()
        tenant_id = email.tenant_id
        primary_rcpt = email.to[0].address.lower() if email.to else ""

        # Calculate message length for style analysis
        msg_text = _extract_text(email)
        msg_len = len(msg_text)

        # --- 1. Behavioral Analysis (DB Lookup) ---
        is_new_sender = True
        days_active = 0
        is_new_relationship = True
        rel_count = 0
        style_mismatch = None

        try:
            with get_connection() as conn:
                # Check Sender Profile
                profile = _get_sender_profile(conn, sender, tenant_id)
                if profile:
                    is_new_sender = False
                    first_seen = profile["first_seen"]
                    msg_count = profile["message_count"]
                    avg_chars = profile.get("avg_chars", 0) or 0

                    # Calculate days active
                    if first_seen:
                        now = datetime.now(timezone.utc)
                        if first_seen.tzinfo is None:
                            first_seen = first_seen.replace(tzinfo=timezone.utc)
                        delta = now - first_seen
                        days_active = delta.days

                    # Check Style (Length) Mismatch
                    # Only check if we have enough history (e.g., > 5 messages)
                    if msg_count > 5 and avg_chars > 100:
                        # If current message is very short (< 20% of average)
                        if msg_len < (avg_chars * 0.2):
                            style_mismatch = "unusually_short"

                # Check Relationship
                if primary_rcpt:
                    rel = _get_relationship(conn, sender, primary_rcpt, tenant_id)
                    if rel:
                        is_new_relationship = False
                        rel_count = rel["interaction_count"]

        except Exception as exc:
            logger.error("DB lookup failed in BEC analyzer: %s", exc)
            # Fail open
            is_new_sender = False
            is_new_relationship = False

        observations.append(Observation(key="is_new_sender", value=is_new_sender, type="boolean"))
        observations.append(Observation(key="sender_days_active", value=days_active, type="numeric"))
        observations.append(Observation(key="is_new_relationship", value=is_new_relationship, type="boolean"))
        observations.append(Observation(key="relationship_count", value=rel_count, type="numeric"))

        if style_mismatch:
            observations.append(Observation(key="style_mismatch", value=style_mismatch, type="text"))

        # --- 2. NLP Intent Analysis ---
        intent = "neutral"
        confidence = 0

        classifier = get_nlp_classifier()
        if classifier:
            labels = [
                "urgent request",
                "financial transaction",
                "gift card request",
                "payroll change",
                "routine communication",
                "marketing",
                "personal discussion"
            ]
            try:
                # Use msg_text extracted earlier
                result = classifier(msg_text, labels, multi_label=False)
                top_label = result["labels"][0]
                top_score = result["scores"][0]

                if top_score > 0.4:
                    if top_label in ("urgent request", "financial transaction", "gift card request", "payroll change"):
                        intent = top_label
                        confidence = int(top_score * 100)
                    else:
                        intent = "safe"
            except Exception as exc:
                logger.warning("BEC NLP failed: %s", exc)

        if intent != "safe" and intent != "neutral":
            observations.append(Observation(key="bec_intent", value=intent, type="text"))
            observations.append(Observation(key="bec_confidence", value=confidence, type="numeric"))

        # --- 3. Update History (Side Effect) ---
        recipients = [r.address.lower() for r in email.to]
        _update_stats(sender, recipients, tenant_id, msg_len)

        return AnalysisResult(analyzer=self.name, observations=observations)
