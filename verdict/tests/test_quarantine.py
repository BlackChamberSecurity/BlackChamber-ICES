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

"""Tests for the Defender QuarantineAction."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from verdict.models import VerdictEvent
from verdict.actions.quarantine import QuarantineAction


def _make_verdict(**overrides) -> VerdictEvent:
    defaults = {
        "message_id": "test-msg-001",
        "user_id": "user@example.com",
        "tenant_id": "test-tenant-id",
        "sender": "attacker@evil.xyz",
        "recipients": ["victim@example.com", "cfo@example.com"],
        "results": [],
    }
    defaults.update(overrides)
    return VerdictEvent(**defaults)


class TestQuarantineAction:
    """Tests for the Defender quarantine action."""

    def test_action_name(self):
        action = QuarantineAction()
        assert action.action_name == "quarantine"

    def test_is_direct(self):
        action = QuarantineAction()
        assert action.is_direct is True

    @patch("verdict.actions.quarantine.httpx.post")
    def test_calls_remediate_endpoint(self, mock_post):
        """execute() posts to the Defender remediate endpoint."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        action = QuarantineAction()
        verdict = _make_verdict()
        token_provider = MagicMock(return_value="fake-token")

        result = action.execute(verdict, token_provider)

        # Verify HTTP call
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        url = call_kwargs.args[0] if call_kwargs.args else call_kwargs.kwargs.get("url")
        assert "/security/collaboration/analyzedEmails/remediate" in url

        # Verify request body
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["action"] == "softDelete"
        assert body["remediateBy"] == "automation"
        assert len(body["analyzedEmails"]) == 2
        assert body["analyzedEmails"][0]["networkMessageId"] == "test-msg-001"
        assert body["analyzedEmails"][0]["recipientEmailAddress"] == "victim@example.com"
        assert body["analyzedEmails"][1]["recipientEmailAddress"] == "cfo@example.com"

        # Verify auth header
        headers = call_kwargs.kwargs.get("headers")
        assert headers["Authorization"] == "Bearer fake-token"

        # Verify result
        assert result["status"] == "quarantined"
        assert result["recipients"] == 2

    @patch("verdict.actions.quarantine.httpx.post")
    def test_token_provider_receives_tenant_id(self, mock_post):
        """Token provider is called with tenant_id from verdict."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        action = QuarantineAction()
        verdict = _make_verdict(tenant_id="my-tenant-123")
        token_provider = MagicMock(return_value="tok")

        action.execute(verdict, token_provider)

        token_provider.assert_called_once_with("my-tenant-123")

    @patch("verdict.actions.quarantine.httpx.post")
    def test_fallback_to_user_id_when_no_recipients(self, mock_post):
        """If no recipients, uses user_id as the recipient."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        action = QuarantineAction()
        verdict = _make_verdict(recipients=[])
        token_provider = MagicMock(return_value="tok")

        action.execute(verdict, token_provider)

        body = mock_post.call_args.kwargs["json"]
        assert len(body["analyzedEmails"]) == 1
        assert body["analyzedEmails"][0]["recipientEmailAddress"] == "user@example.com"

    @patch("verdict.actions.quarantine.httpx.post")
    def test_http_error_raises(self, mock_post):
        """HTTP errors from Defender are propagated."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Forbidden", request=MagicMock(), response=mock_resp,
        )
        mock_post.return_value = mock_resp

        action = QuarantineAction()
        verdict = _make_verdict()
        token_provider = MagicMock(return_value="tok")

        with pytest.raises(httpx.HTTPStatusError):
            action.execute(verdict, token_provider)


class TestQuarantineDispatcherIntegration:
    """Test that the Dispatcher correctly routes to Quarantine as a direct action."""

    @patch("verdict.actions.quarantine.httpx.post")
    def test_dispatcher_executes_quarantine_directly(self, mock_post):
        from verdict.dispatcher import Dispatcher
        from verdict.policy_engine import PolicyEngine
        from verdict.models import Observation, VerdictResult

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        policies = [{
            "name": "quarantine-dmarc",
            "tenant": "*",
            "when": {"analyzer": "header_auth", "observation": "dmarc", "equals": "fail"},
            "action": "quarantine",
        }]

        engine = PolicyEngine(policies)
        token_provider = MagicMock(return_value="test-token")
        dispatcher = Dispatcher(engine, token_provider=token_provider)

        verdict = _make_verdict(results=[
            VerdictResult(
                analyzer="header_auth",
                observations=[
                    Observation(key="dmarc", value="fail", type="pass_fail"),
                ],
            ),
        ])

        result = dispatcher.dispatch(verdict)

        # Should have executed directly (not returned a request for batching)
        assert result is not None
        assert "result" in result  # direct action returns "result", not "request"
        assert "request" not in result
        assert result["decision"]["action"] == "quarantine"
        assert result["result"]["status"] == "quarantined"

        # Verify the HTTP call was made
        mock_post.assert_called_once()
