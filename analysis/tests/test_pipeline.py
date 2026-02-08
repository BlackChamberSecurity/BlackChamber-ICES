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

"""Tests for the analysis pipeline."""
import pytest
from analysis.models import EmailEvent, EmailBody, Attachment, AnalysisResult
from analysis.pipeline import run_pipeline


def _make_email(**kwargs) -> EmailEvent:
    """Helper to create test emails with sensible defaults."""
    defaults = {
        "message_id": "test-msg-001",
        "user_id": "user@example.com",
        "tenant_id": "test-tenant",
        "received_at": "2026-01-01T00:00:00Z",
        "sender": "sender@example.com",
        "sender_name": "Test Sender",
        "subject": "Test email",
        "body": EmailBody(content_type="text", content="Hello world"),
        "headers": {},
        "attachments": [],
    }
    defaults.update(kwargs)
    return EmailEvent(**defaults)


class TestPipeline:
    """Test the analysis pipeline with various email scenarios."""

    def test_clean_email_runs_all_analyzers(self):
        """A normal email should produce results from every analyzer."""
        email = _make_email(
            headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        )
        verdict = run_pipeline(email)

        # No aggregated severity/score — just individual results
        assert len(verdict.results) >= 4  # header, url, attachment, saas_usage
        analyzer_names = {r.analyzer for r in verdict.results}
        assert "header_auth" in analyzer_names
        assert "url_check" in analyzer_names
        assert "attachment_check" in analyzer_names
        assert "saas_usage" in analyzer_names

    def test_suspicious_headers(self):
        """An email with failed SPF/DKIM should be scored by header analyzer."""
        email = _make_email(
            headers={"Authentication-Results": "spf=fail dkim=fail dmarc=pass"},
        )
        verdict = run_pipeline(email)

        header_results = [r for r in verdict.results if r.analyzer == "header_auth"]
        assert len(header_results) == 1
        assert header_results[0].score > 0
        assert len(header_results[0].findings) > 0

    def test_malicious_url(self):
        """An email with a phishing URL should be flagged by URL analyzer."""
        email = _make_email(
            body=EmailBody(
                content_type="text",
                content="Click here: http://192.168.1.1/login.php",
            ),
        )
        verdict = run_pipeline(email)

        url_results = [r for r in verdict.results if r.analyzer == "url_check"]
        assert len(url_results) == 1
        assert url_results[0].score > 0
        assert any("IP address" in f for f in url_results[0].findings)

    def test_dangerous_attachment(self):
        """An email with a .exe attachment should be flagged by attachment analyzer."""
        email = _make_email(
            attachments=[Attachment(
                name="invoice.exe",
                content_type="application/octet-stream",
                size=1024,
            )],
        )
        verdict = run_pipeline(email)

        att_results = [r for r in verdict.results if r.analyzer == "attachment_check"]
        assert len(att_results) == 1
        assert att_results[0].score >= 50
        assert any(".exe" in f for f in att_results[0].findings)

    def test_saas_provider_identified(self):
        """An email from a known SaaS provider should identify the provider."""
        email = _make_email(
            sender="noreply@dropbox.com",
            subject="Your Dropbox storage is 90% full",
        )
        verdict = run_pipeline(email)

        saas_results = [r for r in verdict.results if r.analyzer == "saas_usage"]
        assert len(saas_results) == 1
        assert saas_results[0].provider == "Dropbox"
        assert saas_results[0].score > 50  # Storage warning = transactional

    def test_marketing_email_low_score(self):
        """A marketing email should score low on SaaS usage."""
        email = _make_email(
            sender="newsletter@somecompany.com",
            subject="What's new in our product - Monthly Newsletter",
            headers={"List-Unsubscribe": "<mailto:unsub@somecompany.com>", "Precedence": "bulk"},
            body=EmailBody(content="Check out our latest features! Unsubscribe from these emails."),
        )
        verdict = run_pipeline(email)

        saas_results = [r for r in verdict.results if r.analyzer == "saas_usage"]
        assert len(saas_results) == 1
        assert saas_results[0].category == "marketing"
        assert saas_results[0].score < 30

    def test_each_result_independent(self):
        """Each analyzer result should have its own score/findings."""
        email = _make_email()
        verdict = run_pipeline(email)

        for result in verdict.results:
            assert hasattr(result, "analyzer")
            assert hasattr(result, "score")
            assert hasattr(result, "findings")
            assert hasattr(result, "provider")
            assert hasattr(result, "category")

    def test_verdict_has_required_fields(self):
        """Verdict should always have message_id, user_id, and tenant_id."""
        email = _make_email()
        verdict = run_pipeline(email)

        assert verdict.message_id == "test-msg-001"
        assert verdict.user_id == "user@example.com"
        assert verdict.tenant_id == "test-tenant"

    def test_verdict_to_dict(self):
        """Verdict.to_dict() should produce a JSON-safe dictionary."""
        email = _make_email()
        verdict = run_pipeline(email)
        d = verdict.to_dict()

        assert isinstance(d, dict)
        assert "message_id" in d
        assert "results" in d
        assert isinstance(d["results"], list)
        # No aggregated severity/score
        assert "severity" not in d
        assert "action" not in d
