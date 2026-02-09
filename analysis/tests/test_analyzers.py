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

"""Tests for individual analyzers — observation model."""
import pytest
from analysis.models import EmailEvent, EmailBody, Attachment, Observation
from analysis.analyzers.header_analyzer import HeaderAnalyzer
from analysis.analyzers.url_analyzer import URLAnalyzer
from analysis.analyzers.attachment_analyzer import AttachmentAnalyzer


def _make_email(**kwargs) -> EmailEvent:
    """Helper to create test emails."""
    defaults = {
        "message_id": "test-001",
        "user_id": "user@test.com",
        "tenant_id": "tenant-001",
        "sender": "sender@example.com",
        "subject": "Test",
        "body": EmailBody(content_type="text", content=""),
        "headers": {},
        "attachments": [],
    }
    defaults.update(kwargs)
    return EmailEvent(**defaults)


def _obs_dict(result, key):
    """Get the value of an observation by key from a result."""
    return result.get(key)


class TestHeaderAnalyzer:

    def setup_method(self):
        self.analyzer = HeaderAnalyzer()

    def test_order(self):
        assert self.analyzer.order == 10

    def test_all_pass(self):
        email = _make_email(headers={
            "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
        })
        result = self.analyzer.analyze(email)
        assert result.get("spf") == "pass"
        assert result.get("dkim") == "pass"
        assert result.get("dmarc") == "pass"

    def test_spf_fail(self):
        email = _make_email(headers={
            "Authentication-Results": "spf=fail dkim=pass dmarc=pass"
        })
        result = self.analyzer.analyze(email)
        assert result.get("spf") == "fail"
        assert result.get("dkim") == "pass"

    def test_dmarc_fail(self):
        email = _make_email(headers={
            "Authentication-Results": "spf=pass dkim=pass dmarc=fail"
        })
        result = self.analyzer.analyze(email)
        assert result.get("dmarc") == "fail"

    def test_sender_mismatch(self):
        email = _make_email(
            sender="user@legitimate.com",
            headers={
                "Return-Path": "<user@spoofed.com>",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
            },
        )
        result = self.analyzer.analyze(email)
        assert result.get("sender_mismatch") is True
        assert result.get("envelope_domain") == "spoofed.com"

    def test_no_mismatch(self):
        email = _make_email(
            sender="user@example.com",
            headers={
                "Return-Path": "<user@example.com>",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
            },
        )
        result = self.analyzer.analyze(email)
        assert result.get("sender_mismatch") is False

    def test_observations_serialization(self):
        email = _make_email(headers={
            "Authentication-Results": "spf=fail dkim=pass dmarc=pass"
        })
        result = self.analyzer.analyze(email)
        d = result.to_dict()
        assert d["analyzer"] == "header_auth"
        assert isinstance(d["observations"], list)
        spf_obs = [o for o in d["observations"] if o["key"] == "spf"]
        assert len(spf_obs) == 1
        assert spf_obs[0]["value"] == "fail"
        assert spf_obs[0]["type"] == "pass_fail"


class TestURLAnalyzer:

    def setup_method(self):
        self.analyzer = URLAnalyzer()

    def test_order(self):
        assert self.analyzer.order == 20

    def test_no_urls(self):
        email = _make_email(body=EmailBody(content="No links here"))
        result = self.analyzer.analyze(email)
        assert result.get("urls_found") == 0

    def test_ip_address_url(self):
        email = _make_email(body=EmailBody(
            content="Visit http://192.168.1.1/login"
        ))
        result = self.analyzer.analyze(email)
        assert result.get("ip_urls_found") >= 1

    def test_suspicious_tld(self):
        email = _make_email(body=EmailBody(
            content="Click http://login-verify.xyz/account"
        ))
        result = self.analyzer.analyze(email)
        assert ".xyz" in result.get("suspicious_tlds", "")

    def test_url_shortener(self):
        email = _make_email(body=EmailBody(
            content="See http://bit.ly/abc123"
        ))
        result = self.analyzer.analyze(email)
        assert result.get("shorteners_found") >= 1

    def test_clean_url(self):
        email = _make_email(body=EmailBody(
            content="Visit https://www.google.com"
        ))
        result = self.analyzer.analyze(email)
        assert result.get("ip_urls_found") == 0
        assert result.get("suspicious_tlds") is None
        assert result.get("shorteners_found") == 0


class TestAttachmentAnalyzer:

    def setup_method(self):
        self.analyzer = AttachmentAnalyzer()

    def test_order(self):
        assert self.analyzer.order == 30

    def test_no_attachments(self):
        email = _make_email()
        result = self.analyzer.analyze(email)
        assert result.get("attachment_count") == 0

    def test_exe_attachment(self):
        email = _make_email(attachments=[
            Attachment(name="setup.exe", content_type="application/octet-stream", size=50000)
        ])
        result = self.analyzer.analyze(email)
        assert ".exe" in result.get("dangerous_extensions", "")

    def test_safe_attachment(self):
        email = _make_email(attachments=[
            Attachment(name="document.pdf", content_type="application/pdf", size=100000)
        ])
        result = self.analyzer.analyze(email)
        assert result.get("dangerous_extensions") is None

    def test_script_attachment(self):
        email = _make_email(attachments=[
            Attachment(name="script.ps1", content_type="text/plain", size=500)
        ])
        result = self.analyzer.analyze(email)
        assert ".ps1" in result.get("dangerous_extensions", "")

    def test_macro_document(self):
        email = _make_email(attachments=[
            Attachment(name="invoice.docm", content_type="application/vnd.ms-word", size=80000)
        ])
        result = self.analyzer.analyze(email)
        assert ".docm" in result.get("dangerous_extensions", "")


class TestSaaSUsageAnalyzer:
    """Tests for the refactored domain-first SaaS usage analyzer."""

    def setup_method(self):
        from analysis.analyzers.saas_usage_analyzer import SaaSUsageAnalyzer
        self.analyzer = SaaSUsageAnalyzer()

    def test_known_vendor_sets_is_saas(self):
        """A known vendor domain should emit is_saas=true, saas_confidence=known."""
        email = _make_email(
            sender="noreply@github.com",
            subject="[GitHub] Your push to main was successful",
        )
        result = self.analyzer.analyze(email)
        assert result.get("is_saas") is True
        assert result.get("saas_confidence") == "known"
        assert result.get("provider") == "GitHub"

    def test_unknown_personal_sender_not_saas(self):
        """A random personal email should emit is_saas=false, no category."""
        email = _make_email(
            sender="john@personal-domain.com",
            subject="Hey, lunch tomorrow?",
        )
        result = self.analyzer.analyze(email)
        assert result.get("is_saas") is False
        assert result.get("category") is None
        assert result.get("confidence") is None

    def test_unknown_domain_not_saas_despite_signals(self):
        """Unknown domain should NOT be SaaS even with noreply@ + Auto-Submitted (no heuristic path)."""
        email = _make_email(
            sender="noreply@unknown-saas-platform.io",
            subject="Your account has been updated",
            headers={"Auto-Submitted": "auto-generated"},
        )
        result = self.analyzer.analyze(email)
        assert result.get("is_saas") is False
        assert result.get("saas_confidence") is None
        assert result.get("category") is None

    def test_category_only_for_saas(self):
        """Non-SaaS emails should NOT have category or confidence observations."""
        email = _make_email(
            sender="friend@randomdomain.com",
            subject="Weekend plans",
            body=EmailBody(content_type="text", content="Are you free Saturday?"),
        )
        result = self.analyzer.analyze(email)
        assert result.get("is_saas") is False
        # No category or confidence for non-SaaS
        assert result.get("category") is None
        assert result.get("confidence") is None

