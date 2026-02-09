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

"""Tests for the Spamhaus reputation analyzer."""
from unittest.mock import patch
import socket

import pytest
from analysis.models import EmailEvent, EmailBody, Observation
from analysis.analyzers.spamhaus_analyzer import (
    SpamhausAnalyzer,
    _extract_sender_ip,
    _check_ip,
    _check_domain,
    _dnsbl_lookup,
)


def _make_email(**kwargs) -> EmailEvent:
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


class TestExtractSenderIP:
    """Tests for IP extraction from Received headers."""

    def test_extracts_public_ip(self):
        headers = {
            "Received": "from mx.example.com (93.184.216.34) by mail.local (127.0.0.1)"
        }
        assert _extract_sender_ip(headers) == "93.184.216.34"

    def test_skips_private_ips(self):
        headers = {"Received": "from internal (10.0.0.1) by mail (192.168.1.1)"}
        assert _extract_sender_ip(headers) is None

    def test_skips_loopback(self):
        headers = {"Received": "from localhost (127.0.0.1) by mail (127.0.0.2)"}
        assert _extract_sender_ip(headers) is None

    def test_no_received_header(self):
        assert _extract_sender_ip({}) is None

    def test_list_of_received_headers(self):
        headers = {
            "Received": [
                "from mx2 (10.0.0.5) by mail",
                "from edge (185.199.108.10) by mx2",
            ]
        }
        assert _extract_sender_ip(headers) == "185.199.108.10"

    def test_first_public_ip_returned(self):
        headers = {
            "Received": "from a (185.199.108.1) by b (93.184.216.2)"
        }
        assert _extract_sender_ip(headers) == "185.199.108.1"


class TestDNSBLLookup:
    """Tests for raw DNSBL DNS queries."""

    @patch("analysis.analyzers.spamhaus_analyzer.socket.gethostbyname")
    def test_listed_returns_ip(self, mock_dns):
        mock_dns.return_value = "127.0.0.2"
        assert _dnsbl_lookup("2.0.0.127.zen.spamhaus.org") == "127.0.0.2"

    @patch("analysis.analyzers.spamhaus_analyzer.socket.gethostbyname")
    def test_not_listed_returns_none(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("NXDOMAIN")
        assert _dnsbl_lookup("2.0.0.127.zen.spamhaus.org") is None

    @patch("analysis.analyzers.spamhaus_analyzer.socket.gethostbyname")
    def test_timeout_returns_none(self, mock_dns):
        mock_dns.side_effect = socket.timeout("timed out")
        assert _dnsbl_lookup("2.0.0.127.zen.spamhaus.org") is None


class TestCheckIP:
    """Tests for Spamhaus ZEN IP lookups."""

    @patch("analysis.analyzers.spamhaus_analyzer._dnsbl_lookup")
    def test_listed_sbl(self, mock_lookup):
        mock_lookup.return_value = "127.0.0.2"
        listed, label = _check_ip("1.2.3.4")
        assert listed is True
        assert label == "SBL"
        # Verify reversed IP query
        mock_lookup.assert_called_once_with("4.3.2.1.zen.spamhaus.org")

    @patch("analysis.analyzers.spamhaus_analyzer._dnsbl_lookup")
    def test_listed_xbl(self, mock_lookup):
        mock_lookup.return_value = "127.0.0.4"
        listed, label = _check_ip("10.20.30.40")
        assert listed is True
        assert label == "XBL-CBL"

    @patch("analysis.analyzers.spamhaus_analyzer._dnsbl_lookup")
    def test_listed_pbl(self, mock_lookup):
        mock_lookup.return_value = "127.0.0.10"
        listed, label = _check_ip("5.6.7.8")
        assert listed is True
        assert label == "PBL"

    @patch("analysis.analyzers.spamhaus_analyzer._dnsbl_lookup")
    def test_not_listed(self, mock_lookup):
        mock_lookup.return_value = None
        listed, label = _check_ip("8.8.8.8")
        assert listed is False
        assert label == ""

    @patch("analysis.analyzers.spamhaus_analyzer._dnsbl_lookup")
    def test_unknown_code(self, mock_lookup):
        mock_lookup.return_value = "127.0.0.99"
        listed, label = _check_ip("1.1.1.1")
        assert listed is True
        assert "unknown" in label


class TestCheckDomain:
    """Tests for Spamhaus DBL domain lookups."""

    @patch("analysis.analyzers.spamhaus_analyzer._dnsbl_lookup")
    def test_spam_domain(self, mock_lookup):
        mock_lookup.return_value = "127.0.1.2"
        listed, category = _check_domain("spammy.example")
        assert listed is True
        assert category == "spam-domain"
        mock_lookup.assert_called_once_with("spammy.example.dbl.spamhaus.org")

    @patch("analysis.analyzers.spamhaus_analyzer._dnsbl_lookup")
    def test_phish_domain(self, mock_lookup):
        mock_lookup.return_value = "127.0.1.4"
        listed, category = _check_domain("phish.example")
        assert listed is True
        assert category == "phish-domain"

    @patch("analysis.analyzers.spamhaus_analyzer._dnsbl_lookup")
    def test_clean_domain(self, mock_lookup):
        mock_lookup.return_value = None
        listed, category = _check_domain("clean.example")
        assert listed is False
        assert category == ""


class TestSpamhausAnalyzer:
    """Integration tests for the full analyzer."""

    def setup_method(self):
        self.analyzer = SpamhausAnalyzer()

    def test_order(self):
        assert self.analyzer.order == 15

    def test_name(self):
        assert self.analyzer.name == "spamhaus"

    @patch("analysis.analyzers.spamhaus_analyzer._check_domain")
    @patch("analysis.analyzers.spamhaus_analyzer._check_ip")
    def test_clean_email(self, mock_ip, mock_domain):
        mock_ip.return_value = (False, "")
        mock_domain.return_value = (False, "")

        email = _make_email(
            sender="user@clean.example",
            headers={"Received": "from mx (93.184.216.1) by local"},
        )
        result = self.analyzer.analyze(email)

        assert result.analyzer == "spamhaus"
        assert result.get("sender_ip") == "93.184.216.1"
        assert result.get("ip_listed") is False
        assert result.get("domain_listed") is False
        # Should not have ip_list or domain_list observations
        assert result.get("ip_list") is None
        assert result.get("domain_list") is None

    @patch("analysis.analyzers.spamhaus_analyzer._check_domain")
    @patch("analysis.analyzers.spamhaus_analyzer._check_ip")
    def test_listed_ip_and_domain(self, mock_ip, mock_domain):
        mock_ip.return_value = (True, "SBL")
        mock_domain.return_value = (True, "spam-domain")

        email = _make_email(
            sender="bad@spam.example",
            headers={"Received": "from evil (185.199.108.50) by us"},
        )
        result = self.analyzer.analyze(email)

        assert result.get("ip_listed") is True
        assert result.get("ip_list") == "SBL"
        assert result.get("domain_listed") is True
        assert result.get("domain_list") == "spam-domain"

    @patch("analysis.analyzers.spamhaus_analyzer._check_domain")
    @patch("analysis.analyzers.spamhaus_analyzer._check_ip")
    def test_no_ip_found(self, mock_ip, mock_domain):
        mock_domain.return_value = (False, "")

        email = _make_email(
            sender="user@example.com",
            headers={},
        )
        result = self.analyzer.analyze(email)

        assert result.get("sender_ip") == "not_found"
        mock_ip.assert_not_called()

    @patch("analysis.analyzers.spamhaus_analyzer._check_domain")
    @patch("analysis.analyzers.spamhaus_analyzer._check_ip")
    def test_no_sender_domain(self, mock_ip, mock_domain):
        mock_ip.return_value = (False, "")

        email = _make_email(
            sender="",
            headers={"Received": "from mx (93.184.216.1) by local"},
        )
        result = self.analyzer.analyze(email)

        assert result.get("ip_listed") is False
        mock_domain.assert_not_called()

    @patch("analysis.analyzers.spamhaus_analyzer._check_domain")
    @patch("analysis.analyzers.spamhaus_analyzer._check_ip")
    def test_ip_lookup_error_produces_observation(self, mock_ip, mock_domain):
        mock_ip.side_effect = Exception("DNS failure")
        mock_domain.return_value = (False, "")

        email = _make_email(
            sender="user@example.com",
            headers={"Received": "from mx (93.184.216.1) by local"},
        )
        result = self.analyzer.analyze(email)

        err = result.get("spamhaus_error")
        assert err is not None
        assert "zen" in err

    @patch("analysis.analyzers.spamhaus_analyzer._check_domain")
    @patch("analysis.analyzers.spamhaus_analyzer._check_ip")
    def test_domain_lookup_error_produces_observation(self, mock_ip, mock_domain):
        mock_ip.return_value = (False, "")
        mock_domain.side_effect = Exception("DNS failure")

        email = _make_email(
            sender="user@example.com",
            headers={"Received": "from mx (93.184.216.1) by local"},
        )
        result = self.analyzer.analyze(email)

        err = result.get("spamhaus_error")
        assert err is not None
        assert "dbl" in err

    @patch("analysis.analyzers.spamhaus_analyzer._check_domain")
    @patch("analysis.analyzers.spamhaus_analyzer._check_ip")
    def test_result_serialization(self, mock_ip, mock_domain):
        mock_ip.return_value = (True, "XBL-CBL")
        mock_domain.return_value = (False, "")

        email = _make_email(
            sender="user@example.com",
            headers={"Received": "from mx (93.184.216.1) by local"},
        )
        result = self.analyzer.analyze(email)
        d = result.to_dict()

        assert d["analyzer"] == "spamhaus"
        assert isinstance(d["observations"], list)
        assert d["processing_time_ms"] == 0.0  # not set by analyzer itself
