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

Abnormal Security-style behavioural analysis that compares each inbound
email against learned sender and sender↔recipient baselines.

Pipeline:
  1. Classify intent  — zero-shot NLP into 7 categories
  2. Query profiles   — sender baseline + per-recipient pair history
  3. Compute anomalies — flag deviations from learned behaviour
  4. Score risk       — weighted composite 0–100

Observations produced (13):
    bec_risk_score              (numeric)   0–100
    bec_risk_level              (text)      low / medium / high / critical
    intent_category             (text)      detected intent
    intent_confidence           (numeric)   NLP confidence 0–100
    sender_tenure_days          (numeric)   days since first seen
    is_new_sender               (boolean)   first seen < 7 days
    display_name_anomaly        (boolean)   unknown display name
    category_shift              (boolean)   intent differs from baseline
    time_anomaly                (boolean)   sent outside typical hours
    reply_to_mismatch           (boolean)   Reply-To ≠ sender domain
    is_first_contact            (boolean)   sender→recipient never seen
    low_volume_sensitive_request(boolean)   few msgs + high-risk intent
    context_escalation          (boolean)   unusual category for this pair
"""
import logging
import math
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Optional

from analysis.analyzers._base import BaseAnalyzer
from analysis.analyzers.bec_models import (
    BECSignals,
    CATEGORY_RISK_WEIGHTS,
    HIGH_RISK_CATEGORIES,
    INTENT_CATEGORIES,
    NLP_CANDIDATE_LABELS,
    SenderProfile,
    SenderRecipientPair,
)
from analysis.models import AnalysisResult, EmailEvent, Observation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTML text extraction (shared utility)
# ---------------------------------------------------------------------------
class _HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._text: list[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script", "head"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("style", "script", "head"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self._text.append(data)

    def get_text(self) -> str:
        return " ".join(self._text)


def _strip_html(html: str) -> str:
    extractor = _HTMLTextExtractor()
    try:
        extractor.feed(html)
        text = extractor.get_text()
    except Exception:
        text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# NLP classifier — lazy-loaded singleton (shared with SaaS analyzer process)
# ---------------------------------------------------------------------------
_nlp_classifier = None


def _get_nlp_classifier():
    global _nlp_classifier
    if _nlp_classifier is None:
        try:
            from transformers import pipeline
            logger.info("BEC: loading zero-shot classifier...")
            _nlp_classifier = pipeline(
                "zero-shot-classification",
                model="cross-encoder/nli-distilroberta-base",
                device=-1,
            )
            logger.info("BEC: NLP model loaded")
        except Exception as exc:
            logger.warning("BEC: NLP model load failed: %s", exc)
            _nlp_classifier = False
    return _nlp_classifier if _nlp_classifier is not False else None


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------
def _sender_domain(sender: str) -> str:
    """Extract domain from an email address."""
    if "@" in sender:
        return sender.split("@")[-1].strip().lower()
    return sender.strip().lower()


# ---------------------------------------------------------------------------
# Anomaly detection helpers
# ---------------------------------------------------------------------------

def _detect_category_shift(
    profile: SenderProfile, current_category: str,
) -> bool:
    """True if the current category is high-risk but rare for this sender."""
    if current_category not in HIGH_RISK_CATEGORIES:
        return False
    total = sum(profile.typical_categories.values())
    if total < 5:
        # Not enough history to judge
        return False
    cat_count = profile.typical_categories.get(current_category, 0)
    ratio = cat_count / total
    # High-risk category seen in < 5% of historical mail → shift
    return ratio < 0.05


def _detect_time_anomaly(
    profile: SenderProfile, send_hour: int,
) -> bool:
    """True if the send hour is >2σ from the sender's typical distribution."""
    hours = profile.typical_send_hours
    if not hours:
        return False
    total = sum(hours.values())
    if total < 10:
        return False  # not enough data

    # Mean and std dev of send hours
    mean_hour = sum(int(h) * c for h, c in hours.items()) / total
    variance = sum(c * (int(h) - mean_hour) ** 2 for h, c in hours.items()) / total
    std_dev = math.sqrt(variance) if variance > 0 else 1.0

    return abs(send_hour - mean_hour) > 2 * std_dev


def _detect_context_escalation(
    pair: SenderRecipientPair, current_category: str,
) -> bool:
    """True if current category is high-risk but uncommon for this pair."""
    if current_category not in HIGH_RISK_CATEGORIES:
        return False
    total = sum(pair.category_distribution.values())
    if total < 3:
        return False
    cat_count = pair.category_distribution.get(current_category, 0)
    ratio = cat_count / total
    return ratio < 0.1


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

#: Weights for each anomaly signal in the composite score.
_SIGNAL_WEIGHTS = {
    "is_new_sender": 15,
    "display_name_anomaly": 10,
    "category_shift": 20,
    "time_anomaly": 10,
    "reply_to_mismatch": 15,
    "is_first_contact": 10,
    "low_volume_sensitive_request": 15,
    "context_escalation": 15,
}


def _compute_risk_score(signals: BECSignals) -> int:
    """Weighted composite BEC risk score 0–100."""
    raw = 0.0

    # Category base risk (0–30 points)
    cat_weight = CATEGORY_RISK_WEIGHTS.get(signals.intent_category, 0.1)
    raw += cat_weight * 30

    # Anomaly flag contributions
    for flag_name, weight in _SIGNAL_WEIGHTS.items():
        if getattr(signals, flag_name, False):
            raw += weight

    # Scale by intent confidence (low confidence → dampen score)
    confidence_factor = max(signals.intent_confidence / 100.0, 0.3)
    raw *= confidence_factor

    return min(int(round(raw)), 100)


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class BECAnalyzer(BaseAnalyzer):
    """Behavioural BEC detection via sender profiling and intent analysis."""

    name = "bec_detector"
    description = "Behavioral BEC detection via sender profiling and sentiment analysis"
    order = 45  # after headers/URLs/attachments, before SaaS NLP

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        """Read-only analysis: query profiles, classify intent, emit observations."""
        signals = BECSignals()

        # --- 1. Classify intent ---
        signals.intent_category, signals.intent_confidence = self._classify_intent(email)

        # --- 2. Query sender profile ---
        domain = _sender_domain(email.sender)
        profile = self._get_profile(email.tenant_id, domain)

        if profile is None:
            # First time seeing this sender domain
            signals.is_new_sender = True
            signals.sender_tenure_days = 0.0
        else:
            signals.is_new_sender = profile.is_new
            signals.sender_tenure_days = profile.tenure_days

            # Display name anomaly
            if email.sender_name and profile.known_display_names:
                signals.display_name_anomaly = (
                    email.sender_name not in profile.known_display_names
                )

            # Category shift
            signals.category_shift = _detect_category_shift(
                profile, signals.intent_category,
            )

            # Time anomaly
            send_hour = self._extract_send_hour(email)
            if send_hour is not None:
                signals.time_anomaly = _detect_time_anomaly(profile, send_hour)

            # Reply-To mismatch
            reply_to = email.headers.get("Reply-To", "")
            if reply_to:
                rt_domain = _sender_domain(reply_to)
                if rt_domain and rt_domain != domain:
                    if rt_domain not in profile.reply_to_domains:
                        signals.reply_to_mismatch = True

        # --- 3. Query sender-recipient pairs (dual-level) ---
        sender_addr = email.sender.strip().lower()
        recipients = [r.address for r in email.to] if email.to else []
        for recip in recipients:
            # Address-level: has THIS exact sender emailed this recipient?
            addr_pair = self._get_pair(email.tenant_id, sender_addr, recip)
            # Domain-level: has ANYONE from this domain emailed this recipient?
            domain_pair = self._get_domain_pair(
                email.tenant_id, domain, recip,
            )

            # First contact = neither address nor domain has history
            addr_first = addr_pair is None or addr_pair.is_first_contact
            domain_first = domain_pair is None or domain_pair.is_first_contact

            if addr_first:
                # Address-level first contact
                if domain_first:
                    # Completely new: no one from this domain ever emailed
                    signals.is_first_contact = True
                    if signals.intent_category in HIGH_RISK_CATEGORIES:
                        signals.low_volume_sensitive_request = True
                else:
                    # Domain has history but this specific sender is new
                    # Still flag as first contact at address level
                    signals.is_first_contact = True
                    if signals.intent_category in HIGH_RISK_CATEGORIES:
                        signals.low_volume_sensitive_request = True
            elif addr_pair.message_count < 5 and signals.intent_category in HIGH_RISK_CATEGORIES:
                signals.low_volume_sensitive_request = True

            # Context escalation — check at both levels
            if addr_pair and not addr_pair.is_first_contact:
                if _detect_context_escalation(addr_pair, signals.intent_category):
                    signals.context_escalation = True
            elif domain_pair and not domain_pair.is_first_contact:
                if _detect_context_escalation(domain_pair, signals.intent_category):
                    signals.context_escalation = True

        # --- 4. Score and emit ---
        score = _compute_risk_score(signals)
        level = _risk_level(score)

        observations = [
            Observation(key="bec_risk_score", value=score, type="numeric"),
            Observation(key="bec_risk_level", value=level, type="text"),
            Observation(key="intent_category", value=signals.intent_category, type="text"),
            Observation(key="intent_confidence", value=signals.intent_confidence, type="numeric"),
            Observation(key="sender_tenure_days", value=round(signals.sender_tenure_days, 1), type="numeric"),
            Observation(key="is_new_sender", value=signals.is_new_sender, type="boolean"),
            Observation(key="display_name_anomaly", value=signals.display_name_anomaly, type="boolean"),
            Observation(key="category_shift", value=signals.category_shift, type="boolean"),
            Observation(key="time_anomaly", value=signals.time_anomaly, type="boolean"),
            Observation(key="reply_to_mismatch", value=signals.reply_to_mismatch, type="boolean"),
            Observation(key="is_first_contact", value=signals.is_first_contact, type="boolean"),
            Observation(key="low_volume_sensitive_request", value=signals.low_volume_sensitive_request, type="boolean"),
            Observation(key="context_escalation", value=signals.context_escalation, type="boolean"),
        ]

        return AnalysisResult(analyzer=self.name, observations=observations)

    # ----- Intent classification -----

    def _classify_intent(self, email: EmailEvent) -> tuple[str, int]:
        """Zero-shot classify the email into one of 7 intent categories."""
        classifier = _get_nlp_classifier()
        if classifier is None:
            return "informational", 0

        body_text = email.body.content or ""
        if email.body.content_type == "html" or "<" in body_text[:50]:
            body_text = _strip_html(body_text)

        text = f"Subject: {email.subject or '(no subject)'}\n\n"
        text += body_text[:500]

        try:
            result = classifier(text, NLP_CANDIDATE_LABELS, multi_label=False)
            top_idx = NLP_CANDIDATE_LABELS.index(result["labels"][0])
            top_score = result["scores"][0]
            return INTENT_CATEGORIES[top_idx], int(top_score * 100)
        except Exception as exc:
            logger.warning("BEC intent classification failed: %s", exc)
            return "informational", 0

    # ----- Profile queries (read-only, best-effort) -----

    def _get_profile(
        self, tenant_id: str, sender_domain: str,
    ) -> Optional[SenderProfile]:
        try:
            from analysis.analyzers.bec_db import init_bec_schema, get_sender_profile
            from ices_shared.db import get_connection
            init_bec_schema()
            with get_connection() as conn:
                return get_sender_profile(conn, tenant_id, sender_domain)
        except Exception as exc:
            logger.debug("BEC: profile lookup failed (non-fatal): %s", exc)
            return None

    def _get_pair(
        self, tenant_id: str, sender_addr: str, recipient: str,
    ) -> Optional[SenderRecipientPair]:
        try:
            from analysis.analyzers.bec_db import init_bec_schema, get_sender_recipient_pair
            from ices_shared.db import get_connection
            init_bec_schema()
            with get_connection() as conn:
                return get_sender_recipient_pair(
                    conn, tenant_id, sender_addr, recipient,
                )
        except Exception as exc:
            logger.debug("BEC: pair lookup failed (non-fatal): %s", exc)
            return None

    def _get_domain_pair(
        self, tenant_id: str, sender_domain: str, recipient: str,
    ) -> Optional[SenderRecipientPair]:
        try:
            from analysis.analyzers.bec_db import init_bec_schema, get_domain_pair_summary
            from ices_shared.db import get_connection
            init_bec_schema()
            with get_connection() as conn:
                return get_domain_pair_summary(
                    conn, tenant_id, sender_domain, recipient,
                )
        except Exception as exc:
            logger.debug("BEC: domain pair lookup failed (non-fatal): %s", exc)
            return None

    # ----- Helpers -----

    @staticmethod
    def _extract_send_hour(email: EmailEvent) -> Optional[int]:
        """Parse hour (0-23 UTC) from the received_at timestamp."""
        if not email.received_at:
            return None
        try:
            dt = datetime.fromisoformat(email.received_at.replace("Z", "+00:00"))
            return dt.hour
        except (ValueError, AttributeError):
            return None


# ---------------------------------------------------------------------------
# Post-analysis profile update (called from tasks.py, NOT from analyze())
# ---------------------------------------------------------------------------

def update_behavioral_profiles(email: EmailEvent, verdict) -> None:
    """Write updated sender and pair profiles after analysis completes.

    This runs as a best-effort side-effect AFTER the verdict is produced,
    keeping the analyze() path read-only.
    """
    from analysis.analyzers.bec_db import (
        init_bec_schema,
        upsert_sender_profile,
        upsert_sender_recipient_pair,
    )
    from ices_shared.db import get_connection

    init_bec_schema()

    domain = _sender_domain(email.sender)
    tenant_id = email.tenant_id

    # Find intent category from the BEC analyzer's results
    intent_category = "informational"
    for result in (verdict.results if hasattr(verdict, "results") else []):
        if getattr(result, "analyzer", "") == "bec_detector":
            cat = result.get("intent_category") if hasattr(result, "get") else None
            if cat:
                intent_category = cat
            break

    # Extract send hour
    send_hour = -1
    if email.received_at:
        try:
            dt = datetime.fromisoformat(email.received_at.replace("Z", "+00:00"))
            send_hour = dt.hour
        except (ValueError, AttributeError):
            pass

    # Reply-To domain
    reply_to = email.headers.get("Reply-To", "")
    rt_domain = ""
    if reply_to:
        rt_domain = _sender_domain(reply_to)
        if rt_domain == domain:
            rt_domain = ""  # same domain, not interesting

    with get_connection() as conn:
        # Update sender profile
        upsert_sender_profile(
            conn,
            tenant_id,
            domain,
            display_name=email.sender_name or "",
            category=intent_category,
            send_hour=send_hour,
            reply_to_domain=rt_domain,
        )

        # Update sender-recipient pairs (keyed by full address)
        sender_addr = email.sender.strip().lower()
        recipients = [r.address for r in email.to] if email.to else []
        for recip in recipients:
            upsert_sender_recipient_pair(
                conn, tenant_id, sender_addr, domain, recip,
                category=intent_category,
            )

        conn.commit()

    logger.info(
        "BEC profiles updated: sender=%s domain=%s recipients=%d",
        sender_addr, domain, len(recipients),
    )
