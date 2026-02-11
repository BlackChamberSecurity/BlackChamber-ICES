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

"""Tests for the BEC detection analyzer — all DB and NLP calls mocked."""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from analysis.models import EmailEvent, EmailBody, EmailAddress, Observation
from analysis.analyzers.bec.models import (
    SenderProfile,
    SenderRecipientPair,
    BECSignals,
    ContentSignals,
    INTENT_CATEGORIES,
    NLP_CANDIDATE_LABELS,
    CATEGORY_RISK_WEIGHTS,
    HIGH_RISK_CATEGORIES,
)
from analysis.analyzers.bec.analyzer import (
    BECAnalyzer,
    _compute_risk_score,
    _risk_level,
    _detect_category_shift,
    _detect_time_anomaly,
    _detect_context_escalation,
    _sender_domain,
)
from analysis.analyzers.bec.signals import _scan_content_signals


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_email(**kwargs) -> EmailEvent:
    defaults = {
        "message_id": "bec-test-001",
        "user_id": "user@test.com",
        "tenant_id": "tenant-001",
        "sender": "ceo@example.com",
        "sender_name": "John Smith",
        "to": [EmailAddress(address="finance@company.com", name="Finance Team")],
        "subject": "Test email",
        "body": EmailBody(content_type="text", content="Hello"),
        "headers": {},
        "received_at": "2026-02-10T15:00:00+00:00",
    }
    defaults.update(kwargs)
    return EmailEvent(**defaults)


def _make_profile(**kwargs) -> SenderProfile:
    defaults = {
        "tenant_id": "tenant-001",
        "sender_domain": "example.com",
        "email_count": 100,
        "first_seen_at": datetime.now(timezone.utc) - timedelta(days=90),
        "last_seen_at": datetime.now(timezone.utc) - timedelta(hours=2),
        "known_display_names": ["John Smith", "J. Smith"],
        "typical_categories": {"informational": 80, "transactional": 15, "financial_request": 5},
        "typical_send_hours": {"9": 30, "10": 25, "11": 20, "14": 15, "15": 10},
        "reply_to_domains": [],
    }
    defaults.update(kwargs)
    return SenderProfile(**defaults)


def _make_pair(**kwargs) -> SenderRecipientPair:
    defaults = {
        "tenant_id": "tenant-001",
        "sender_addr": "ceo@example.com",
        "sender_domain": "example.com",
        "recipient_addr": "finance@company.com",
        "message_count": 50,
        "first_contact_at": datetime.now(timezone.utc) - timedelta(days=60),
        "last_contact_at": datetime.now(timezone.utc) - timedelta(days=1),
        "category_distribution": {"informational": 40, "transactional": 8, "financial_request": 2},
    }
    defaults.update(kwargs)
    return SenderRecipientPair(**defaults)


# ---------------------------------------------------------------------------
# Unit tests — pure logic (no mocking needed)
# ---------------------------------------------------------------------------

class TestSenderDomain:
    def test_extracts_domain(self):
        assert _sender_domain("user@example.com") == "example.com"

    def test_bare_domain(self):
        assert _sender_domain("example.com") == "example.com"

    def test_uppercase(self):
        assert _sender_domain("User@EXAMPLE.COM") == "example.com"


class TestCategoryShift:
    def test_no_shift_for_low_risk(self):
        profile = _make_profile()
        assert _detect_category_shift(profile, "informational") is False

    def test_shift_for_rare_high_risk(self):
        profile = _make_profile(
            typical_categories={"informational": 95, "financial_request": 1},
        )
        assert _detect_category_shift(profile, "financial_request") is True

    def test_no_shift_when_common(self):
        profile = _make_profile(
            typical_categories={"financial_request": 50, "informational": 50},
        )
        assert _detect_category_shift(profile, "financial_request") is False

    def test_no_shift_insufficient_data(self):
        profile = _make_profile(typical_categories={"informational": 3})
        assert _detect_category_shift(profile, "urgent_action") is False


class TestTimeAnomaly:
    def test_normal_hour(self):
        profile = _make_profile(
            typical_send_hours={"9": 30, "10": 25, "11": 20, "14": 15, "15": 10},
        )
        assert _detect_time_anomaly(profile, 10) is False

    def test_anomalous_hour(self):
        profile = _make_profile(
            typical_send_hours={"9": 30, "10": 25, "11": 20, "14": 15, "15": 10},
        )
        # 3 AM is far from the 9-15 cluster
        assert _detect_time_anomaly(profile, 3) is True

    def test_insufficient_data(self):
        profile = _make_profile(typical_send_hours={"10": 3})
        assert _detect_time_anomaly(profile, 3) is False


class TestContextEscalation:
    def test_no_escalation_low_risk(self):
        pair = _make_pair()
        assert _detect_context_escalation(pair, "informational") is False

    def test_escalation_rare_high_risk(self):
        pair = _make_pair(
            category_distribution={"informational": 45, "urgent_action": 0},
        )
        assert _detect_context_escalation(pair, "urgent_action") is True

    def test_no_escalation_when_common(self):
        pair = _make_pair(
            category_distribution={"financial_request": 20, "informational": 30},
        )
        assert _detect_context_escalation(pair, "financial_request") is False


class TestRiskScoring:
    def test_low_risk_informational(self):
        signals = BECSignals(intent_category="informational", intent_confidence=80)
        score = _compute_risk_score(signals)
        assert score < 25
        assert _risk_level(score) == "low"

    def test_high_risk_new_sender_financial(self):
        signals = BECSignals(
            intent_category="financial_request",
            intent_confidence=85,
            is_new_sender=True,
            category_shift=True,
            is_first_contact=True,
        )
        score = _compute_risk_score(signals)
        assert score >= 50
        assert _risk_level(score) in ("high", "critical")

    def test_low_confidence_dampens_score(self):
        signals_high = BECSignals(
            intent_category="urgent_action",
            intent_confidence=90,
            is_new_sender=True,
        )
        signals_low = BECSignals(
            intent_category="urgent_action",
            intent_confidence=20,
            is_new_sender=True,
        )
        assert _compute_risk_score(signals_high) > _compute_risk_score(signals_low)

    def test_critical_threshold(self):
        assert _risk_level(75) == "critical"
        assert _risk_level(100) == "critical"

    def test_medium_threshold(self):
        assert _risk_level(25) == "medium"
        assert _risk_level(49) == "medium"


class TestSenderProfile:
    def test_tenure_days(self):
        profile = _make_profile(
            first_seen_at=datetime.now(timezone.utc) - timedelta(days=30),
        )
        assert 29 < profile.tenure_days < 31

    def test_is_new(self):
        profile = _make_profile(
            first_seen_at=datetime.now(timezone.utc) - timedelta(days=2),
        )
        assert profile.is_new is True

    def test_is_not_new(self):
        profile = _make_profile(
            first_seen_at=datetime.now(timezone.utc) - timedelta(days=30),
        )
        assert profile.is_new is False

    def test_dominant_category(self):
        profile = _make_profile(
            typical_categories={"informational": 80, "transactional": 15},
        )
        assert profile.dominant_category == "informational"

    def test_dominant_category_empty(self):
        profile = _make_profile(typical_categories={})
        assert profile.dominant_category is None


class TestSenderRecipientPair:
    def test_first_contact_zero(self):
        pair = SenderRecipientPair(message_count=0)
        assert pair.is_first_contact is True

    def test_not_first_contact(self):
        pair = _make_pair(message_count=10)
        assert pair.is_first_contact is False


# ---------------------------------------------------------------------------
# Analyzer integration tests (NLP + DB mocked)
# ---------------------------------------------------------------------------

class TestBECAnalyzer:

    def setup_method(self):
        self.analyzer = BECAnalyzer()

    @patch.object(BECAnalyzer, "_get_domain_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_profile", return_value=None)
    @patch(
        "analysis.analyzers.bec.analyzer._get_nlp_classifier",
        return_value=None,
    )
    def test_new_sender_no_nlp(self, mock_nlp, mock_profile, mock_pair, mock_dpair):
        """No NLP model + no profile → new sender, low confidence."""
        email = _make_email()
        result = self.analyzer.analyze(email)
        assert result.get("is_new_sender") is True
        assert result.get("intent_category") == "informational"
        assert result.get("intent_confidence") == 0
        assert result.get("bec_risk_level") is not None

    @patch.object(BECAnalyzer, "_get_domain_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_profile")
    @patch(
        "analysis.analyzers.bec_analyzer._get_nlp_classifier",
        return_value=None,
    )
    def test_known_sender_normal_email(self, mock_nlp, mock_profile, mock_pair, mock_dpair):
        """Known sender, no NLP → low risk."""
        mock_profile.return_value = _make_profile()
        email = _make_email()
        result = self.analyzer.analyze(email)
        assert result.get("is_new_sender") is False
        assert result.get("sender_tenure_days") > 0
        assert result.get("bec_risk_level") == "low"

    @patch.object(BECAnalyzer, "_get_domain_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_profile")
    @patch("analysis.analyzers.bec_analyzer._get_nlp_classifier")
    def test_category_shift_detected(self, mock_nlp_fn, mock_profile, mock_pair, mock_dpair):
        """Known sender sends a rare financial request → category shift."""
        # NLP returns "financial_request"
        mock_classifier = MagicMock()
        mock_classifier.return_value = {
            "labels": [NLP_CANDIDATE_LABELS[1]],  # financial_request
            "scores": [0.92],
        }
        mock_nlp_fn.return_value = mock_classifier

        mock_profile.return_value = _make_profile(
            typical_categories={"informational": 95, "financial_request": 1},
        )
        email = _make_email(subject="Urgent: please update bank details")
        result = self.analyzer.analyze(email)
        assert result.get("intent_category") == "financial_request"
        assert result.get("category_shift") is True
        assert result.get("bec_risk_score") > 25

    @patch.object(BECAnalyzer, "_get_domain_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_profile")
    @patch(
        "analysis.analyzers.bec_analyzer._get_nlp_classifier",
        return_value=None,
    )
    def test_display_name_anomaly(self, mock_nlp, mock_profile, mock_pair, mock_dpair):
        """Sender uses an unknown display name."""
        mock_profile.return_value = _make_profile(
            known_display_names=["John Smith", "J. Smith"],
        )
        email = _make_email(sender_name="CEO John")
        result = self.analyzer.analyze(email)
        assert result.get("display_name_anomaly") is True

    @patch.object(BECAnalyzer, "_get_domain_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_profile")
    @patch(
        "analysis.analyzers.bec_analyzer._get_nlp_classifier",
        return_value=None,
    )
    def test_reply_to_mismatch(self, mock_nlp, mock_profile, mock_pair, mock_dpair):
        """Reply-To domain differs from sender and is unseen."""
        mock_profile.return_value = _make_profile(reply_to_domains=[])
        email = _make_email(
            headers={"Reply-To": "attacker@evil.com"},
        )
        result = self.analyzer.analyze(email)
        assert result.get("reply_to_mismatch") is True

    @patch.object(BECAnalyzer, "_get_domain_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_pair")
    @patch.object(BECAnalyzer, "_get_profile", return_value=None)
    @patch("analysis.analyzers.bec_analyzer._get_nlp_classifier")
    def test_first_contact_sensitive_request(self, mock_nlp_fn, mock_profile, mock_pair, mock_dpair):
        """First contact + urgent intent → low_volume_sensitive_request."""
        mock_classifier = MagicMock()
        mock_classifier.return_value = {
            "labels": [NLP_CANDIDATE_LABELS[0]],  # urgent_action
            "scores": [0.88],
        }
        mock_nlp_fn.return_value = mock_classifier
        mock_pair.return_value = None  # first contact

        email = _make_email(subject="URGENT: wire transfer needed now")
        result = self.analyzer.analyze(email)
        assert result.get("is_first_contact") is True
        assert result.get("low_volume_sensitive_request") is True
        assert result.get("bec_risk_level") in ("high", "critical")

    @patch.object(BECAnalyzer, "_get_domain_pair")
    @patch.object(BECAnalyzer, "_get_pair")
    @patch.object(BECAnalyzer, "_get_profile")
    @patch(
        "analysis.analyzers.bec_analyzer._get_nlp_classifier",
        return_value=None,
    )
    def test_context_escalation(self, mock_nlp, mock_profile, mock_pair, mock_dpair):
        """Known pair with mostly informational history gets a credential request."""
        mock_profile.return_value = _make_profile()
        mock_pair.return_value = _make_pair(
            category_distribution={"informational": 45, "credential_request": 0},
        )
        mock_dpair.return_value = None
        # Manually set intent to credential_request (NLP is off, so we patch)
        with patch.object(
            self.analyzer, "_classify_intent_multilabel",
            return_value=("credential_request", 85, ["credential_request"]),
        ):
            email = _make_email(subject="Verify your account credentials")
            result = self.analyzer.analyze(email)
            assert result.get("context_escalation") is True

    def test_analyzer_metadata(self):
        assert self.analyzer.name == "bec_detector"
        assert self.analyzer.order == 45

    @patch.object(BECAnalyzer, "_get_domain_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_profile", return_value=None)
    @patch(
        "analysis.analyzers.bec_analyzer._get_nlp_classifier",
        return_value=None,
    )
    def test_emits_all_21_observations(self, mock_nlp, mock_profile, mock_pair, mock_dpair):
        """Verify the analyzer always emits exactly 21 observations."""
        email = _make_email()
        result = self.analyzer.analyze(email)
        keys = {o.key for o in result.observations}
        expected = {
            "bec_risk_score", "bec_risk_level", "intent_category",
            "intent_confidence", "sender_tenure_days", "is_new_sender",
            "display_name_anomaly", "category_shift", "time_anomaly",
            "reply_to_mismatch", "is_first_contact",
            "low_volume_sensitive_request", "context_escalation",
            # Content signals
            "content_has_financial_entities", "content_has_payment_instructions",
            "content_has_urgency_language", "content_urgency_score",
            "content_formality_score", "content_financial_entities",
            "topics_detected", "content_has_personal_info",
        }
        assert keys == expected
        assert len(result.observations) == 21

    @patch.object(BECAnalyzer, "_get_domain_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_pair", return_value=None)
    @patch.object(BECAnalyzer, "_get_profile", return_value=None)
    @patch(
        "analysis.analyzers.bec_analyzer._get_nlp_classifier",
        return_value=None,
    )
    def test_serialization_round_trip(self, mock_nlp, mock_profile, mock_pair, mock_dpair):
        """Observations serialise and deserialise correctly."""
        email = _make_email()
        result = self.analyzer.analyze(email)
        d = result.to_dict()
        assert d["analyzer"] == "bec_detector"
        assert isinstance(d["observations"], list)
        assert len(d["observations"]) == 21
        # Verify round-trip
        for obs_dict in d["observations"]:
            obs = Observation.from_dict(obs_dict)
            assert obs.key in {o.key for o in result.observations}


# ---------------------------------------------------------------------------
# Content signal tests
# ---------------------------------------------------------------------------

class TestContentSignals:

    def test_financial_entity_extraction(self):
        text = (
            "Bank: Green Dot\n"
            "Routing Number: 061000052\n"
            "Account Number: 334070299722"
        )
        cs = _scan_content_signals(text)
        assert cs.has_financial_entities is True
        assert any("routing:061000052" in e for e in cs.financial_entities)
        assert any("account:334070299722" in e for e in cs.financial_entities)
        assert any("bank:" in e for e in cs.financial_entities)

    def test_urgency_keywords(self):
        text = "This is very urgent! Please act immediately, ASAP."
        cs = _scan_content_signals(text)
        assert cs.has_urgency_language is True
        assert cs.urgency_score >= 40  # at least 2 hits × 20

    def test_no_urgency(self):
        text = "Here is the quarterly report for your review."
        cs = _scan_content_signals(text)
        assert cs.has_urgency_language is False
        assert cs.urgency_score == 0

    def test_payment_instructions(self):
        text = (
            "Please update the wire transfer details."
            " New bank account number for payment."
        )
        cs = _scan_content_signals(text)
        assert cs.has_payment_instructions is True

    def test_credential_request(self):
        text = "Please verify your account by entering your password."
        cs = _scan_content_signals(text)
        assert cs.has_credential_request is True

    def test_personal_info_request(self):
        text = "We need your SSN and date of birth to process the W-2."
        cs = _scan_content_signals(text)
        assert cs.has_personal_info_request is True

    def test_formality_scoring(self):
        formal_text = "Dear Sir, Please find attached. Sincerely, J."
        cs = _scan_content_signals(formal_text)
        assert cs.formality_score > 50

        informal_text = "Hey! What's up, gonna send that btw lol"
        cs2 = _scan_content_signals(informal_text)
        assert cs2.formality_score < 50

    def test_content_signals_boost_risk_score(self):
        """Content signals add to risk score independently of NLP confidence."""
        signals = BECSignals(
            intent_category="informational", intent_confidence=50,
        )
        content = ContentSignals(
            has_financial_entities=True,
            has_payment_instructions=True,
            has_urgency_language=True,
        )
        score_with = _compute_risk_score(signals, content)
        score_without = _compute_risk_score(signals)
        assert score_with > score_without
        assert score_with - score_without >= 40  # 20 + 15 + 10 (minus rounding)

    def test_neutral_text_no_flags(self):
        text = "Meeting tomorrow at 3pm in conference room B."
        cs = _scan_content_signals(text)
        assert cs.has_financial_entities is False
        assert cs.has_payment_instructions is False
        assert cs.has_urgency_language is False
        assert cs.has_credential_request is False
        assert cs.has_personal_info_request is False
