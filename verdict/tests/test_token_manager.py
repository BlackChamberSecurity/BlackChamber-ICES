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

"""Tests for the multi-tenant TokenManager."""

import time
import threading
from unittest.mock import patch, MagicMock

import pytest
from verdict.token_manager import TokenManager, TenantCredentials, REFRESH_BUFFER_SECONDS


def _make_creds(tenant_id="t-1", client_id="c-1", client_secret="s-1"):
    return TenantCredentials(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


class TestTokenManagerInit:
    """Test initialisation and tenant configuration."""

    def test_explicit_tenants(self):
        mgr = TokenManager(tenants={"t-1": _make_creds()})
        assert "t-1" in mgr._tenants

    @patch.dict("os.environ", {
        "M365_TENANT_ID": "env-tenant",
        "M365_CLIENT_ID": "env-client",
        "M365_CLIENT_SECRET": "env-secret",
    })
    def test_env_fallback(self):
        """When no tenants dict is given, env vars are used."""
        mgr = TokenManager()
        assert "env-tenant" in mgr._tenants
        creds = mgr._tenants["env-tenant"]
        assert creds.client_id == "env-client"

    @patch.dict("os.environ", {}, clear=True)
    def test_no_tenants_raises(self):
        """get_token() raises ValueError if no tenants configured."""
        mgr = TokenManager()
        with pytest.raises(ValueError, match="No tenants configured"):
            mgr.get_token()

    def test_unknown_tenant_raises(self):
        mgr = TokenManager(tenants={"t-1": _make_creds()})
        with pytest.raises(ValueError, match="No credentials configured"):
            mgr.get_token("unknown-tenant")


class TestTokenAcquisition:
    """Test token acquisition and caching."""

    def _mock_response(self, access_token="tok-123", expires_in=3600):
        """Create a mock httpx response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": access_token,
            "expires_in": expires_in,
        }
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    @patch("verdict.token_manager.httpx.Client")
    def test_acquires_token(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = self._mock_response()
        mock_client_cls.return_value = mock_client

        mgr = TokenManager(tenants={"t-1": _make_creds()})
        token = mgr.get_token("t-1")

        assert token == "tok-123"
        mock_client.post.assert_called_once()

    @patch("verdict.token_manager.httpx.Client")
    def test_caches_token(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = self._mock_response()
        mock_client_cls.return_value = mock_client

        mgr = TokenManager(tenants={"t-1": _make_creds()})

        token1 = mgr.get_token("t-1")
        token2 = mgr.get_token("t-1")

        assert token1 == token2
        # Only one HTTP call — second call uses cache
        assert mock_client.post.call_count == 1

    @patch("verdict.token_manager.httpx.Client")
    def test_default_tenant(self, mock_client_cls):
        """get_token() with no arg uses the first configured tenant."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = self._mock_response()
        mock_client_cls.return_value = mock_client

        mgr = TokenManager(tenants={"t-1": _make_creds()})
        token = mgr.get_token()  # No tenant_id

        assert token == "tok-123"

    @patch("verdict.token_manager.httpx.Client")
    def test_multi_tenant_isolation(self, mock_client_cls):
        """Different tenants get different tokens."""
        call_count = 0
        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.json.return_value = {
                "access_token": f"tok-{call_count}",
                "expires_in": 3600,
            }
            resp.raise_for_status = MagicMock()
            return resp

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = mock_post
        mock_client_cls.return_value = mock_client

        mgr = TokenManager(tenants={
            "t-1": _make_creds("t-1"),
            "t-2": _make_creds("t-2", "c-2", "s-2"),
        })

        tok1 = mgr.get_token("t-1")
        tok2 = mgr.get_token("t-2")

        assert tok1 != tok2
        assert mock_client.post.call_count == 2
