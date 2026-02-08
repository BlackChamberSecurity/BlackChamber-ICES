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

"""Tests for individual analyzers."""
import pytest
from analysis.models import EmailEvent, EmailBody, Attachment
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


class TestHeaderAnalyzer:

    def setup_method(self):
        self.analyzer = HeaderAnalyzer()

    def test_all_pass(self):
        email = _make_email(headers={
            "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
        })
        result = self.analyzer.analyze(email)
        assert result.score == 0

    def test_spf_fail(self):
        email = _make_email(headers={
            "Authentication-Results": "spf=fail dkim=pass dmarc=pass"
        })
        result = self.analyzer.analyze(email)
        assert result.score > 0
        assert any("SPF" in f for f in result.findings)

    def test_dmarc_fail(self):
        email = _make_email(headers={
            "Authentication-Results": "spf=pass dkim=pass dmarc=fail"
        })
        result = self.analyzer.analyze(email)
        assert result.score >= 40
        assert any("DMARC" in f for f in result.findings)

    def test_sender_mismatch(self):
        email = _make_email(
            sender="user@legitimate.com",
            headers={
                "Return-Path": "<user@spoofed.com>",
                "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
            },
        )
        result = self.analyzer.analyze(email)
        assert any("match" in f.lower() for f in result.findings)


class TestURLAnalyzer:

    def setup_method(self):
        self.analyzer = URLAnalyzer()

    def test_no_urls(self):
        email = _make_email(body=EmailBody(content="No links here"))
        result = self.analyzer.analyze(email)
        assert result.score == 0

    def test_ip_address_url(self):
        email = _make_email(body=EmailBody(
            content="Visit http://192.168.1.1/login"
        ))
        result = self.analyzer.analyze(email)
        assert result.score > 0

    def test_suspicious_tld(self):
        email = _make_email(body=EmailBody(
            content="Click http://login-verify.xyz/account"
        ))
        result = self.analyzer.analyze(email)
        assert result.score > 0

    def test_url_shortener(self):
        email = _make_email(body=EmailBody(
            content="See http://bit.ly/abc123"
        ))
        result = self.analyzer.analyze(email)
        assert any("shortener" in f.lower() for f in result.findings)

    def test_clean_url(self):
        email = _make_email(body=EmailBody(
            content="Visit https://www.google.com"
        ))
        result = self.analyzer.analyze(email)
        assert result.score == 0


class TestAttachmentAnalyzer:

    def setup_method(self):
        self.analyzer = AttachmentAnalyzer()

    def test_no_attachments(self):
        email = _make_email()
        result = self.analyzer.analyze(email)
        assert result.score == 0

    def test_exe_attachment(self):
        email = _make_email(attachments=[
            Attachment(name="setup.exe", content_type="application/octet-stream", size=50000)
        ])
        result = self.analyzer.analyze(email)
        assert result.score >= 50

    def test_safe_attachment(self):
        email = _make_email(attachments=[
            Attachment(name="document.pdf", content_type="application/pdf", size=100000)
        ])
        result = self.analyzer.analyze(email)
        assert result.score == 0

    def test_script_attachment(self):
        email = _make_email(attachments=[
            Attachment(name="script.ps1", content_type="text/plain", size=500)
        ])
        result = self.analyzer.analyze(email)
        assert result.score >= 50

    def test_macro_document(self):
        email = _make_email(attachments=[
            Attachment(name="invoice.docm", content_type="application/vnd.ms-word", size=80000)
        ])
        result = self.analyzer.analyze(email)
        assert result.score >= 50
