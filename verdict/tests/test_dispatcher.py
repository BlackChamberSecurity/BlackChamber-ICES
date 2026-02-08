# Copyright (c) 2026 John Earle
#
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://github.com/yourusername/bcem/blob/main/LICENSE
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the verdict dispatcher — action routing by score threshold."""
import pytest
from verdict.models import VerdictEvent, VerdictResult
from verdict.dispatcher import Dispatcher, QUARANTINE_THRESHOLD, TAG_THRESHOLD


def _make_verdict(scores: list[int], **kwargs) -> VerdictEvent:
    """Helper to create verdicts with analyzer results at given scores."""
    results = [
        VerdictResult(analyzer=f"analyzer_{i}", score=s, findings=[f"finding_{i}"])
        for i, s in enumerate(scores)
    ]
    defaults = {
        "message_id": "test-msg-001",
        "user_id": "user@example.com",
        "tenant_id": "test-tenant",
        "results": results,
    }
    defaults.update(kwargs)
    return VerdictEvent(**defaults)


class TestDispatcher:

    def setup_method(self):
        self.dispatcher = Dispatcher()

    def test_all_actions_discovered(self):
        """All built-in actions should be discovered."""
        assert "quarantine" in self.dispatcher.actions
        assert "tag" in self.dispatcher.actions
        assert "delete" in self.dispatcher.actions

    def test_no_results_returns_none(self):
        """Verdicts with no results should return None."""
        verdict = _make_verdict(scores=[])
        result = self.dispatcher.dispatch(verdict)
        assert result is None

    def test_clean_email_no_action(self):
        """Low-scoring emails should have action='none'."""
        verdict = _make_verdict(scores=[5, 10, 0])
        result = self.dispatcher.dispatch(verdict)

        assert result is not None
        assert result["action"] == "none"
        assert "request" not in result
        assert result["max_score"] == 10

    def test_suspicious_email_tags(self):
        """Emails with max_score >= TAG_THRESHOLD but < QUARANTINE should be tagged."""
        verdict = _make_verdict(scores=[10, 45, 20])
        result = self.dispatcher.dispatch(verdict)

        assert result is not None
        assert result["action"] == "tag"
        assert "request" in result
        assert result["request"]["method"] == "PATCH"
        assert "user@example.com" in result["request"]["url"]
        assert "BCEM" in str(result["request"]["body"])

    def test_malicious_email_quarantines(self):
        """Emails with max_score >= QUARANTINE_THRESHOLD should be quarantined."""
        verdict = _make_verdict(scores=[10, 85, 20])
        result = self.dispatcher.dispatch(verdict)

        assert result is not None
        assert result["action"] == "quarantine"
        assert "request" in result
        assert result["request"]["method"] == "POST"
        assert "move" in result["request"]["url"]
        assert "destinationId" in result["request"]["body"]

    def test_request_has_user_and_message_id(self):
        """Action requests should reference the correct user and message."""
        verdict = _make_verdict(
            scores=[80],
            user_id="alice@contoso.com",
            message_id="msg-abc-123",
        )
        result = self.dispatcher.dispatch(verdict)

        assert "alice@contoso.com" in result["request"]["url"]
        assert "msg-abc-123" in result["request"]["url"]

    def test_request_has_unique_id(self):
        """Each request should have a unique batch ID."""
        verdict = _make_verdict(scores=[50])
        r1 = self.dispatcher.dispatch(verdict)
        r2 = self.dispatcher.dispatch(verdict)

        assert r1["request"]["id"] != r2["request"]["id"]

    def test_threshold_boundary_tag(self):
        """Score exactly at TAG_THRESHOLD should trigger tag."""
        verdict = _make_verdict(scores=[TAG_THRESHOLD])
        result = self.dispatcher.dispatch(verdict)
        assert result["action"] == "tag"

    def test_threshold_boundary_quarantine(self):
        """Score exactly at QUARANTINE_THRESHOLD should trigger quarantine."""
        verdict = _make_verdict(scores=[QUARANTINE_THRESHOLD])
        result = self.dispatcher.dispatch(verdict)
        assert result["action"] == "quarantine"

    def test_threshold_boundary_below_tag(self):
        """Score just below TAG_THRESHOLD should trigger no action."""
        verdict = _make_verdict(scores=[TAG_THRESHOLD - 1])
        result = self.dispatcher.dispatch(verdict)
        assert result["action"] == "none"
