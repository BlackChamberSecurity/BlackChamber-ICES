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

"""Tests for the policy engine and dispatcher — observation model."""
import pytest
from verdict.models import VerdictEvent, VerdictResult, Observation
from verdict.policy_engine import PolicyEngine, PolicyDecision


def _make_verdict(results: list[VerdictResult] = None, **kwargs) -> VerdictEvent:
    """Helper to create verdicts with typed observations."""
    defaults = {
        "message_id": "test-msg-001",
        "user_id": "user@example.com",
        "tenant_id": "test-tenant",
        "tenant_alias": "mainmethod",
        "sender": "sender@example.com",
        "recipients": ["recipient@example.com"],
        "results": results or [],
    }
    defaults.update(kwargs)
    return VerdictEvent(**defaults)


def _header_result(spf="pass", dkim="pass", dmarc="pass") -> VerdictResult:
    """Helper: header analyzer result."""
    return VerdictResult(
        analyzer="header_auth",
        observations=[
            Observation(key="spf", value=spf, type="pass_fail"),
            Observation(key="dkim", value=dkim, type="pass_fail"),
            Observation(key="dmarc", value=dmarc, type="pass_fail"),
        ],
    )


def _url_result(ip_urls=0, shorteners=0) -> VerdictResult:
    """Helper: URL analyzer result."""
    return VerdictResult(
        analyzer="url_check",
        observations=[
            Observation(key="urls_found", value=1, type="numeric"),
            Observation(key="ip_urls_found", value=ip_urls, type="numeric"),
            Observation(key="shorteners_found", value=shorteners, type="numeric"),
        ],
    )


def _attachment_result(dangerous=None) -> VerdictResult:
    """Helper: attachment analyzer result."""
    obs = [Observation(key="attachment_count", value=1, type="numeric")]
    if dangerous:
        obs.append(
            Observation(key="dangerous_extensions", value=dangerous, type="text")
        )
    return VerdictResult(analyzer="attachment_check", observations=obs)


# ---- PolicyEngine Tests ----

class TestPolicyEngine:

    def test_no_policies(self):
        engine = PolicyEngine([])
        verdict = _make_verdict([_header_result(dmarc="fail")])
        decision = engine.evaluate(verdict)
        assert decision.action == "none"

    def test_dmarc_fail_quarantine(self):
        policies = [
            {
                "name": "quarantine-dmarc",
                "tenant": "*",
                "when": {"analyzer": "header_auth", "observation": "dmarc", "equals": "fail"},
                "action": "quarantine",
            }
        ]
        engine = PolicyEngine(policies)
        verdict = _make_verdict([_header_result(dmarc="fail")])
        decision = engine.evaluate(verdict)
        assert decision.action == "quarantine"
        assert decision.policy_name == "quarantine-dmarc"
        assert decision.matched_analyzer == "header_auth"

    def test_dmarc_pass_no_match(self):
        policies = [
            {
                "name": "quarantine-dmarc",
                "tenant": "*",
                "when": {"analyzer": "header_auth", "observation": "dmarc", "equals": "fail"},
                "action": "quarantine",
            }
        ]
        engine = PolicyEngine(policies)
        verdict = _make_verdict([_header_result(dmarc="pass")])
        decision = engine.evaluate(verdict)
        assert decision.action == "none"

    def test_gte_match(self):
        policies = [
            {
                "name": "tag-ip-urls",
                "when": {"analyzer": "url_check", "observation": "ip_urls_found", "gte": 1},
                "action": "tag",
            }
        ]
        engine = PolicyEngine(policies)
        verdict = _make_verdict([_url_result(ip_urls=2)])
        decision = engine.evaluate(verdict)
        assert decision.action == "tag"

    def test_gte_no_match(self):
        policies = [
            {
                "name": "tag-ip-urls",
                "when": {"analyzer": "url_check", "observation": "ip_urls_found", "gte": 1},
                "action": "tag",
            }
        ]
        engine = PolicyEngine(policies)
        verdict = _make_verdict([_url_result(ip_urls=0)])
        decision = engine.evaluate(verdict)
        assert decision.action == "none"

    def test_exists_match(self):
        policies = [
            {
                "name": "quarantine-attachment",
                "when": {"analyzer": "attachment_check", "observation": "dangerous_extensions", "exists": True},
                "action": "quarantine",
            }
        ]
        engine = PolicyEngine(policies)
        verdict = _make_verdict([_attachment_result(dangerous=".exe")])
        decision = engine.evaluate(verdict)
        assert decision.action == "quarantine"

    def test_exists_no_match(self):
        policies = [
            {
                "name": "quarantine-attachment",
                "when": {"analyzer": "attachment_check", "observation": "dangerous_extensions", "exists": True},
                "action": "quarantine",
            }
        ]
        engine = PolicyEngine(policies)
        verdict = _make_verdict([_attachment_result()])
        decision = engine.evaluate(verdict)
        assert decision.action == "none"

    def test_highest_priority_wins(self):
        """When multiple policies match, highest priority action wins."""
        policies = [
            {
                "name": "tag-rule",
                "when": {"analyzer": "header_auth", "observation": "spf", "equals": "fail"},
                "action": "tag",
            },
            {
                "name": "quarantine-rule",
                "when": {"analyzer": "header_auth", "observation": "dmarc", "equals": "fail"},
                "action": "quarantine",
            },
        ]
        engine = PolicyEngine(policies)
        verdict = _make_verdict([_header_result(spf="fail", dmarc="fail")])
        decision = engine.evaluate(verdict)
        assert decision.action == "quarantine"

    def test_tenant_filter(self):
        policies = [
            {
                "name": "specific-tenant",
                "tenant": "mainmethod",
                "when": {"analyzer": "header_auth", "observation": "spf", "equals": "fail"},
                "action": "tag",
            }
        ]
        engine = PolicyEngine(policies)

        # Matching tenant
        verdict = _make_verdict([_header_result(spf="fail")], tenant_alias="mainmethod")
        assert engine.evaluate(verdict).action == "tag"

        # Non-matching tenant
        verdict = _make_verdict([_header_result(spf="fail")], tenant_alias="other")
        assert engine.evaluate(verdict).action == "none"

    def test_sender_wildcard(self):
        policies = [
            {
                "name": "xyz-sender",
                "sender": "*@*.xyz",
                "when": {"analyzer": "header_auth", "observation": "spf", "equals": "fail"},
                "action": "quarantine",
            }
        ]
        engine = PolicyEngine(policies)

        verdict = _make_verdict(
            [_header_result(spf="fail")],
            sender="phish@evil.xyz",
        )
        assert engine.evaluate(verdict).action == "quarantine"

        verdict = _make_verdict(
            [_header_result(spf="fail")],
            sender="legit@company.com",
        )
        assert engine.evaluate(verdict).action == "none"

    def test_recipients_filter(self):
        policies = [
            {
                "name": "protect-exec",
                "recipients": ["ceo@co.com", "cfo@co.com"],
                "when": {"analyzer": "header_auth", "observation": "spf", "equals": "fail"},
                "action": "quarantine",
            }
        ]
        engine = PolicyEngine(policies)

        verdict = _make_verdict(
            [_header_result(spf="fail")],
            recipients=["ceo@co.com", "assistant@co.com"],
        )
        assert engine.evaluate(verdict).action == "quarantine"

        verdict = _make_verdict(
            [_header_result(spf="fail")],
            recipients=["nobody@co.com"],
        )
        assert engine.evaluate(verdict).action == "none"

    def test_contains_match(self):
        policies = [
            {
                "name": "contains-test",
                "when": {"analyzer": "url_check", "observation": "suspicious_tlds", "contains": ".xyz"},
                "action": "tag",
            }
        ]
        engine = PolicyEngine(policies)
        result = VerdictResult(
            analyzer="url_check",
            observations=[
                Observation(key="suspicious_tlds", value=".xyz,.tk", type="text"),
            ],
        )
        verdict = _make_verdict([result])
        assert engine.evaluate(verdict).action == "tag"

    def test_verdict_from_dict(self):
        """VerdictEvent.from_dict should correctly deserialize."""
        data = {
            "message_id": "msg-1",
            "user_id": "user-1",
            "tenant_id": "t-1",
            "sender": "a@b.com",
            "recipients": ["c@d.com"],
            "results": [
                {
                    "analyzer": "header_auth",
                    "observations": [
                        {"key": "spf", "value": "fail", "type": "pass_fail"},
                    ],
                }
            ],
        }
        event = VerdictEvent.from_dict(data)
        assert event.sender == "a@b.com"
        assert len(event.results) == 1
        assert event.results[0].observations[0].key == "spf"
