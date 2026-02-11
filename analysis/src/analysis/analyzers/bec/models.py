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
BEC Analyzer — Data Models

Self-contained dataclasses for the BEC detection analyzer's behavioral
profiles and anomaly signals.  These are internal to the BEC module and
are NOT shared with other services.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Sentiment / intent categories
# ---------------------------------------------------------------------------

#: Intent labels ordered from highest BEC risk to lowest.
INTENT_CATEGORIES: list[str] = [
    "urgent_action",
    "financial_request",
    "credential_request",
    "authority_impersonation",
    "relationship_building",
    "informational",
    "transactional",
]

#: NLP candidate labels mapped 1-to-1 with INTENT_CATEGORIES.
#: Each string is a natural-language hypothesis for zero-shot classification.
NLP_CANDIDATE_LABELS: list[str] = [
    "urgent request requiring immediate action such as wire transfer or emergency",
    "financial request involving invoices, payments, bank account details, or tax forms",
    "credential or account verification request asking for passwords or login",
    "message from a senior executive, CEO, CFO, legal, or HR authority figure",
    "casual conversation, rapport building, or friendly greeting",
    "informational update, status report, meeting notes, or FYI",
    "automated transactional notification, receipt, or system alert",
]

#: Risk weight per category for composite scoring (0.0 – 1.0).
CATEGORY_RISK_WEIGHTS: dict[str, float] = {
    "urgent_action": 1.0,
    "financial_request": 1.0,
    "credential_request": 0.9,
    "authority_impersonation": 0.7,
    "relationship_building": 0.4,
    "informational": 0.1,
    "transactional": 0.05,
}

#: Categories considered "high-risk" for anomaly flag purposes.
HIGH_RISK_CATEGORIES: frozenset[str] = frozenset({
    "urgent_action",
    "financial_request",
    "credential_request",
})


# ---------------------------------------------------------------------------
# Sender profile (90-day rolling window)
# ---------------------------------------------------------------------------

@dataclass
class SenderProfile:
    """Behavioural baseline for a sender domain within a tenant."""

    tenant_id: str = ""
    sender_domain: str = ""
    email_count: int = 0
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    known_display_names: list[str] = field(default_factory=list)
    typical_categories: dict[str, int] = field(default_factory=dict)
    typical_send_hours: dict[str, int] = field(default_factory=dict)
    reply_to_domains: list[str] = field(default_factory=list)

    # -- derived helpers --

    @property
    def tenure_days(self) -> float:
        """Days since the sender was first seen (0 if unknown)."""
        if not self.first_seen_at:
            return 0.0
        delta = datetime.now(timezone.utc) - self.first_seen_at
        return max(delta.total_seconds() / 86400, 0.0)

    @property
    def is_new(self) -> bool:
        """True if sender has been seen for fewer than 7 days."""
        return self.tenure_days < 7

    @property
    def dominant_category(self) -> Optional[str]:
        """Most frequently observed intent category, or None."""
        if not self.typical_categories:
            return None
        return max(self.typical_categories, key=self.typical_categories.get)


# ---------------------------------------------------------------------------
# Sender ↔ recipient pair
# ---------------------------------------------------------------------------

@dataclass
class SenderRecipientPair:
    """Communication history between one sender and one recipient.

    Keyed by full sender address for individual tracking, with
    sender_domain stored for domain-level aggregation queries.
    """

    tenant_id: str = ""
    sender_addr: str = ""
    sender_domain: str = ""
    recipient_addr: str = ""
    message_count: int = 0
    first_contact_at: Optional[datetime] = None
    last_contact_at: Optional[datetime] = None
    category_distribution: dict[str, int] = field(default_factory=dict)

    @property
    def is_first_contact(self) -> bool:
        return self.message_count == 0


# ---------------------------------------------------------------------------
# Aggregated anomaly signals
# ---------------------------------------------------------------------------

@dataclass
class BECSignals:
    """Anomaly flags computed per email, used to derive the risk score."""

    intent_category: str = "informational"
    intent_confidence: int = 0

    # sender-level
    is_new_sender: bool = False
    sender_tenure_days: float = 0.0
    display_name_anomaly: bool = False
    category_shift: bool = False
    time_anomaly: bool = False
    reply_to_mismatch: bool = False

    # pair-level (worst-case across all recipients)
    is_first_contact: bool = False
    low_volume_sensitive_request: bool = False
    context_escalation: bool = False


# ---------------------------------------------------------------------------
# Granular content signals (Abnormal-style)
# ---------------------------------------------------------------------------

@dataclass
class ContentSignals:
    """Fine-grained content analysis signals extracted via regex + NLP.

    These complement the document-level intent classification with
    keyword-level evidence that boosts confidence and catches things
    NLP misses (e.g. routing numbers, explicit payment instructions).
    """

    has_financial_entities: bool = False
    has_payment_instructions: bool = False
    has_urgency_language: bool = False
    has_credential_request: bool = False
    has_personal_info_request: bool = False
    urgency_score: int = 0           # 0-100 keyword density score
    formality_score: int = 50        # 0-100 (0=very informal, 100=very formal)
    financial_entities: list[str] = field(default_factory=list)
    topics_detected: list[str] = field(default_factory=list)
