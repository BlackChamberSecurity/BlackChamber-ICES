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

"""Tests for BEC Analyzer."""
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from analysis.models import EmailEvent, EmailBody, EmailAddress, AnalysisResult
from analysis.analyzers.bec_analyzer import BECAnalyzer

def _make_email(**kwargs) -> EmailEvent:
    defaults = {
        "message_id": "test-bec-001",
        "user_id": "user@test.com",
        "tenant_id": "tenant-001",
        "sender": "new.sender@example.com",
        "subject": "Urgent Wire Transfer",
        "to": [EmailAddress(address="ceo@test.com", name="CEO")],
        "body": EmailBody(content_type="text", content="Please process this wire transfer immediately."),
        "headers": {},
        "attachments": [],
    }
    defaults.update(kwargs)
    return EmailEvent(**defaults)

class TestBECAnalyzer:

    @pytest.fixture
    def mock_db(self):
        with patch("analysis.analyzers.bec_analyzer.get_connection") as mock_conn_ctx:
            mock_conn = MagicMock()
            mock_conn_ctx.return_value.__enter__.return_value = mock_conn
            yield mock_conn

    @pytest.fixture
    def mock_nlp(self):
        with patch("analysis.analyzers.bec_analyzer.get_nlp_classifier") as mock_get_nlp:
            mock_pipeline = MagicMock()
            mock_get_nlp.return_value = mock_pipeline
            yield mock_pipeline

    def test_new_sender_detection(self, mock_db, mock_nlp):
        # Setup: DB returns None for sender profile (new sender)
        mock_db.execute.return_value.fetchone.return_value = None

        # Setup: NLP returns neutral
        mock_nlp.return_value = {"labels": ["routine communication"], "scores": [0.9]}

        analyzer = BECAnalyzer()
        email = _make_email(sender="brand.new@example.com")

        result = analyzer.analyze(email)

        # Verify observations
        obs = {o.key: o.value for o in result.observations}
        assert obs["is_new_sender"] is True
        assert obs["sender_days_active"] == 0
        assert obs.get("bec_intent") is None

    def test_known_sender_detection(self, mock_db, mock_nlp):
        # Setup: DB returns a profile (known sender, seen 10 days ago)
        mock_profile = {
            "first_seen": datetime.now(timezone.utc) - timedelta(days=10),
            "message_count": 5,
            "avg_chars": 500  # Normal length
        }
        # First call is for sender profile, second for relationship
        mock_db.execute.return_value.fetchone.side_effect = [
            mock_profile, # sender profile
            None          # relationship (new relationship)
        ]

        mock_nlp.return_value = {"labels": ["routine communication"], "scores": [0.9]}

        analyzer = BECAnalyzer()
        email = _make_email(sender="known.sender@example.com")

        result = analyzer.analyze(email)

        obs = {o.key: o.value for o in result.observations}
        assert obs["is_new_sender"] is False
        assert obs["sender_days_active"] == 10
        assert obs["is_new_relationship"] is True

    def test_bec_intent_urgent_financial(self, mock_db, mock_nlp):
        # Setup: DB returns None (new sender)
        mock_db.execute.return_value.fetchone.return_value = None

        # Setup: NLP detects financial intent
        mock_nlp.return_value = {
            "labels": ["urgent request"],
            "scores": [0.95]
        }

        analyzer = BECAnalyzer()
        email = _make_email(
            subject="Urgent Invoice",
            body=EmailBody(content="Please pay attached invoice ASAP")
        )

        result = analyzer.analyze(email)

        obs = {o.key: o.value for o in result.observations}
        assert obs["bec_intent"] == "urgent request"
        assert obs["bec_confidence"] == 95

    def test_style_mismatch_short_message(self, mock_db, mock_nlp):
        """Test that a very short message from a sender who usually sends long emails is flagged."""
        # Setup: DB returns a profile with high avg_chars and high message count
        mock_profile = {
            "first_seen": datetime.now(timezone.utc) - timedelta(days=100),
            "message_count": 50,
            "avg_chars": 2000  # Usually sends 2000 char emails
        }
        mock_db.execute.return_value.fetchone.side_effect = [
            mock_profile,
            None
        ]

        mock_nlp.return_value = {"labels": ["routine"], "scores": [0.9]}

        analyzer = BECAnalyzer()
        # Message is ~20 chars ("Wire me money now") << 2000 * 0.2 (400)
        email = _make_email(
            sender="boss@company.com",
            body=EmailBody(content="Wire me money now")
        )

        result = analyzer.analyze(email)

        obs = {o.key: o.value for o in result.observations}
        assert obs.get("style_mismatch") == "unusually_short"

    def test_db_update_called(self, mock_db, mock_nlp):
        # Verify that we attempt to update DB stats
        mock_db.execute.return_value.fetchone.return_value = None
        mock_nlp.return_value = {"labels": ["routine"], "scores": [0.9]}

        analyzer = BECAnalyzer()
        email = _make_email(sender="test@sender.com", tenant_id="t1")

        analyzer.analyze(email)

        # Verify execute calls. We expect inserts for profile and relationships.
        # We can inspect the calls to see if they contain the SQL we expect
        assert mock_db.execute.call_count >= 4
