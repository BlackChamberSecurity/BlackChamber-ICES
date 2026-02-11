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

"""Tests for the Reputation analyzer."""
from unittest.mock import patch, MagicMock
import socket

import pytest
from analysis.models import EmailEvent, EmailBody, Observation
from analysis.analyzers.reputation.analyzer import (
    ReputationAnalyzer,
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


class TestDNSBLLookup:
    """Tests for raw DNSBL DNS queries and caching."""

    @patch("analysis.analyzers.reputation.analyzer._get_redis_client")
    @patch("analysis.analyzers.reputation.analyzer.socket.gethostbyname")
    def test_lookup_no_cache(self, mock_dns, mock_redis):
        mock_redis.return_value = None
        mock_dns.return_value = "127.0.0.2"

        assert _dnsbl_lookup("query.example.com", "cache_key") == "127.0.0.2"
        mock_dns.assert_called_once()

    @patch("analysis.analyzers.reputation.analyzer._get_redis_client")
    @patch("analysis.analyzers.reputation.analyzer.socket.gethostbyname")
    def test_lookup_cache_hit(self, mock_dns, mock_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = "127.0.0.5"
        mock_redis.return_value = mock_r

        assert _dnsbl_lookup("query.example.com", "cache_key") == "127.0.0.5"
        mock_dns.assert_not_called()

    @patch("analysis.analyzers.reputation.analyzer._get_redis_client")
    @patch("analysis.analyzers.reputation.analyzer.socket.gethostbyname")
    def test_lookup_cache_miss_and_store(self, mock_dns, mock_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = None
        mock_redis.return_value = mock_r
        mock_dns.return_value = "127.0.0.2"

        assert _dnsbl_lookup("query.example.com", "cache_key") == "127.0.0.2"
        mock_dns.assert_called_once()
        mock_r.setex.assert_called_with("cache_key", 3600, "127.0.0.2")

    @patch("analysis.analyzers.reputation.analyzer._get_redis_client")
    @patch("analysis.analyzers.reputation.analyzer.socket.gethostbyname")
    def test_lookup_nxdomain_caching(self, mock_dns, mock_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = None
        mock_redis.return_value = mock_r
        mock_dns.side_effect = socket.gaierror("NXDOMAIN")

        assert _dnsbl_lookup("query.example.com", "cache_key") is None
        mock_r.setex.assert_called_with("cache_key", 3600, "NXDOMAIN")

    @patch("analysis.analyzers.reputation.analyzer._get_redis_client")
    def test_lookup_cached_nxdomain(self, mock_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = "NXDOMAIN"
        mock_redis.return_value = mock_r

        assert _dnsbl_lookup("query.example.com", "cache_key") is None


class TestReputationAnalyzer:
    """Integration tests for the reputation analyzer."""

    def setup_method(self):
        self.analyzer = ReputationAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "reputation"

    @patch("analysis.analyzers.reputation.analyzer._check_domain")
    @patch("analysis.analyzers.reputation.analyzer._check_ip")
    def test_clean_email(self, mock_ip, mock_domain):
        mock_ip.return_value = (False, "")
        mock_domain.return_value = (False, "")

        email = _make_email(
            sender="user@clean.example",
            headers={"Received": "from mx (93.184.216.1) by local"},
        )
        result = self.analyzer.analyze(email)

        assert result.analyzer == "reputation"
        assert result.get("ip_listed") is False
        assert result.get("domain_listed") is False

    @patch("analysis.analyzers.reputation.analyzer._check_domain")
    @patch("analysis.analyzers.reputation.analyzer._check_ip")
    def test_listed_ip_multiple_providers(self, mock_ip, mock_domain):
        # Mock responses based on provider arg
        def side_effect(ip, provider):
            if provider["id"] == "spamhaus_zen":
                return (True, "SBL")
            if provider["id"] == "spamcop":
                return (True, "Listed")
            return (False, "")

        mock_ip.side_effect = side_effect
        mock_domain.return_value = (False, "")

        email = _make_email(
            sender="user@example.com",
            headers={"Received": "from mx (1.2.3.4) by local"},
        )
        result = self.analyzer.analyze(email)

        assert result.get("ip_listed") is True
        # Verify provider-specific observations
        obs = result.to_dict()["observations"]

        spamhaus_listed = next((o for o in obs if o["key"] == "spamhaus_zen_listed"), None)
        assert spamhaus_listed and spamhaus_listed["value"] is True

        spamcop_listed = next((o for o in obs if o["key"] == "spamcop_listed"), None)
        assert spamcop_listed and spamcop_listed["value"] is True

        nix_listed = next((o for o in obs if o["key"] == "nix_spam_listed"), None)
        assert nix_listed is None  # Not listed

    @patch("analysis.analyzers.reputation.analyzer._check_domain")
    @patch("analysis.analyzers.reputation.analyzer._check_ip")
    def test_listed_domain(self, mock_ip, mock_domain):
        mock_ip.return_value = (False, "")
        mock_domain.return_value = (True, "spam-domain")

        email = _make_email(
            sender="spammer@bad-domain.com",
            headers={},
        )
        result = self.analyzer.analyze(email)

        assert result.get("domain_listed") is True
        obs = result.to_dict()["observations"]

        dbl_listed = next((o for o in obs if o["key"] == "spamhaus_dbl_listed"), None)
        assert dbl_listed and dbl_listed["value"] is True

    @patch("analysis.analyzers.reputation.analyzer._check_domain")
    @patch("analysis.analyzers.reputation.analyzer._check_ip")
    def test_error_handling(self, mock_ip, mock_domain):
        mock_ip.side_effect = Exception("DNS timeout")
        mock_domain.return_value = (False, "")

        email = _make_email(
            sender="user@example.com",
            headers={"Received": "from mx (1.2.3.4) by local"},
        )
        result = self.analyzer.analyze(email)

        # Should catch exception and log error observation
        err = result.get("reputation_error")
        assert err is not None
        assert "DNS timeout" in err
