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

"""
Action: Quarantine (Microsoft Defender)

Remediates a malicious email via the Defender for Office 365
``analyzedEmails/remediate`` API.  This soft-deletes the message from
the user's mailbox — it can be recovered by an admin from the Defender
quarantine console.

API: POST /beta/security/collaboration/analyzedEmails/remediate
Perm: SecurityAnalyzedMessage.ReadWrite.All (application)
"""
import logging
import os
from typing import Callable

import httpx

from verdict.actions._base import BaseAction
from verdict.models import VerdictEvent

logger = logging.getLogger(__name__)

GRAPH_BETA_BASE = os.environ.get(
    "GRAPH_API_BETA_BASE", "https://graph.microsoft.com/beta",
)
REMEDIATE_URL = f"{GRAPH_BETA_BASE}/security/collaboration/analyzedEmails/remediate"

# Default remediation severity — can be overridden via env
REMEDIATE_SEVERITY = os.environ.get("DEFENDER_REMEDIATE_SEVERITY", "high")


class QuarantineAction(BaseAction):
    """Quarantine email via Defender's analyzedEmails/remediate API."""

    action_name = "quarantine"
    description = "Soft-deletes email via Microsoft Defender quarantine"
    is_direct = True  # calls API directly, NOT through $batch

    def execute(
        self,
        verdict: VerdictEvent,
        token_provider: Callable[..., str],
    ) -> dict:
        """POST to the Defender remediate endpoint.

        Uses ``verdict.message_id`` as the ``networkMessageId`` and
        ``verdict.recipients`` for ``recipientEmailAddress``.
        """
        # Build the list of target emails
        analyzed_emails = []
        for recipient in verdict.recipients:
            analyzed_emails.append({
                "networkMessageId": verdict.message_id,
                "recipientEmailAddress": recipient,
            })

        if not analyzed_emails:
            # Fallback: use user_id as the recipient
            analyzed_emails.append({
                "networkMessageId": verdict.message_id,
                "recipientEmailAddress": verdict.user_id,
            })

        body = {
            "displayName": "ICES Quarantine",
            "description": "BlackChamber ICES automated quarantine",
            "severity": REMEDIATE_SEVERITY,
            "action": "softDelete",
            "remediateBy": "automation",
            "analyzedEmails": analyzed_emails,
        }

        # Get token — pass tenant_id if available
        try:
            token = token_provider(verdict.tenant_id)
        except TypeError:
            # Fallback for single-arg providers
            token = token_provider()

        try:
            response = httpx.post(
                REMEDIATE_URL,
                json=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
            response.raise_for_status()

            logger.info(
                "Defender quarantine triggered: message_id=%s recipients=%d status=%d",
                verdict.message_id, len(analyzed_emails), response.status_code,
            )

            return {
                "status": "quarantined",
                "http_status": response.status_code,
                "recipients": len(analyzed_emails),
            }

        except httpx.HTTPStatusError as exc:
            logger.error(
                "Defender quarantine failed: message_id=%s status=%d body=%s",
                verdict.message_id, exc.response.status_code,
                exc.response.text[:500],
            )
            raise

        except httpx.HTTPError as exc:
            logger.error(
                "Defender quarantine request failed: message_id=%s error=%s",
                verdict.message_id, exc,
            )
            raise
