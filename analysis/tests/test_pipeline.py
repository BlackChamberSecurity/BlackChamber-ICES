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

"""Tests for the analysis pipeline — observation model."""
import pytest
from analysis.models import EmailEvent, EmailBody, Attachment, AnalysisResult, Observation
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
    """Test the analysis pipeline with observation model."""

    def test_clean_email_runs_all_analyzers(self):
        """A normal email should produce results from every analyzer."""
        email = _make_email(
            headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        )
        verdict = run_pipeline(email)

        assert len(verdict.results) >= 4
        analyzer_names = {r.analyzer for r in verdict.results}
        assert "header_auth" in analyzer_names
        assert "url_check" in analyzer_names
        assert "attachment_check" in analyzer_names
        assert "saas_usage" in analyzer_names

    def test_analyzers_run_in_order(self):
        """Analyzers should execute in order: header(10), url(20), attachment(30), saas(50)."""
        email = _make_email(
            headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        )
        verdict = run_pipeline(email)
        names = [r.analyzer for r in verdict.results]
        assert names.index("header_auth") < names.index("url_check")
        assert names.index("url_check") < names.index("attachment_check")
        assert names.index("attachment_check") < names.index("saas_usage")

    def test_suspicious_headers(self):
        """Failed SPF should produce a 'fail' observation."""
        email = _make_email(
            headers={"Authentication-Results": "spf=fail dkim=fail dmarc=pass"},
        )
        verdict = run_pipeline(email)

        header_results = [r for r in verdict.results if r.analyzer == "header_auth"]
        assert len(header_results) == 1
        assert header_results[0].get("spf") == "fail"
        assert header_results[0].get("dkim") == "fail"
        assert len(header_results[0].observations) > 0

    def test_malicious_url(self):
        """An email with an IP URL should produce ip_urls_found observation."""
        email = _make_email(
            body=EmailBody(
                content_type="text",
                content="Click here: http://192.168.1.1/login.php",
            ),
        )
        verdict = run_pipeline(email)

        url_results = [r for r in verdict.results if r.analyzer == "url_check"]
        assert len(url_results) == 1
        assert url_results[0].get("ip_urls_found") >= 1

    def test_dangerous_attachment(self):
        """A .exe attachment should produce dangerous_extensions observation."""
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
        assert ".exe" in att_results[0].get("dangerous_extensions", "")

    def test_saas_provider_identified(self):
        """A known SaaS sender should produce provider observation."""
        email = _make_email(
            sender="noreply@dropbox.com",
            subject="Your Dropbox storage is 90% full",
        )
        verdict = run_pipeline(email)

        saas_results = [r for r in verdict.results if r.analyzer == "saas_usage"]
        assert len(saas_results) == 1
        assert saas_results[0].get("provider") == "Dropbox"
        assert saas_results[0].get("confidence") is not None

    def test_each_result_has_observations(self):
        """Each analyzer result should have an observations list."""
        email = _make_email()
        verdict = run_pipeline(email)

        for result in verdict.results:
            assert hasattr(result, "analyzer")
            assert hasattr(result, "observations")
            assert isinstance(result.observations, list)

    def test_verdict_has_required_fields(self):
        """Verdict should always have message_id, user_id, tenant_id, sender."""
        email = _make_email()
        verdict = run_pipeline(email)

        assert verdict.message_id == "test-msg-001"
        assert verdict.user_id == "user@example.com"
        assert verdict.tenant_id == "test-tenant"
        assert verdict.sender == "sender@example.com"

    def test_verdict_to_dict(self):
        """Verdict.to_dict() should produce a JSON-safe dictionary."""
        email = _make_email()
        verdict = run_pipeline(email)
        d = verdict.to_dict()

        assert isinstance(d, dict)
        assert "message_id" in d
        assert "sender" in d
        assert "recipients" in d
        assert "results" in d
        assert isinstance(d["results"], list)
        # Each result should have observations
        for r in d["results"]:
            assert "observations" in r
            assert isinstance(r["observations"], list)

    def test_observation_round_trip(self):
        """Observation should serialize and deserialize correctly."""
        obs = Observation(key="spf", value="fail", type="pass_fail")
        d = obs.to_dict()
        restored = Observation.from_dict(d)
        assert restored.key == "spf"
        assert restored.value == "fail"
        assert restored.type == "pass_fail"

    def test_analysis_result_round_trip(self):
        """AnalysisResult should serialize and deserialize correctly."""
        result = AnalysisResult(
            analyzer="test",
            observations=[
                Observation(key="a", value=1, type="numeric"),
                Observation(key="b", value="pass", type="pass_fail"),
            ],
        )
        d = result.to_dict()
        restored = AnalysisResult.from_dict(d)
        assert restored.analyzer == "test"
        assert len(restored.observations) == 2
        assert restored.get("a") == 1
        assert restored.get("b") == "pass"
