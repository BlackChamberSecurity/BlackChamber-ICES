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
BlackChamber ICES Analysis Engine — Celery Tasks

Dual-write: analysis results go to both Redis (for real-time policy eval)
and Postgres (for reporting/audit).
"""
import json
import logging

from analysis.celery_app import app
from analysis.models import EmailEvent
from analysis.pipeline import run_pipeline

logger = logging.getLogger(__name__)


@app.task(
    name="analysis.tasks.analyze_email",
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    acks_late=True,
)
def analyze_email(self, email_event_json: str):
    """
    Analyze an email event, persist results, and publish for policy evaluation.

    Dual-write:
    1. Postgres — system of record (email_events + analysis_results)
    2. Redis queue — real-time policy evaluation
    """
    try:
        event_data = json.loads(email_event_json)
        email = EmailEvent.from_dict(event_data)

        logger.info(
            "Analyzing email: message_id=%s tenant=%s from=%s subject=%s",
            email.message_id, email.tenant_alias or email.tenant_id,
            email.sender, email.subject,
        )

        # Skip if already processed — saves bandwidth
        try:
            from ices_shared.db import get_connection, is_message_processed
            with get_connection() as conn:
                if is_message_processed(conn, email.message_id):
                    logger.info("Skipping already-processed message: %s", email.message_id)
                    return {"message_id": email.message_id, "status": "already_processed"}
        except Exception:
            pass  # If DB check fails, proceed with processing

        # Run all analyzers
        verdict = run_pipeline(email)
        verdict_dict = verdict.to_dict()

        # Include subject in dict for Postgres storage
        verdict_dict["subject"] = email.subject

        # --- Dual-write: Postgres (best-effort) ---
        try:
            from ices_shared.db import get_connection, store_email_event, store_analysis_results
            with get_connection() as conn:
                event_id = store_email_event(conn, verdict_dict)
                store_analysis_results(conn, event_id, verdict_dict)
                conn.commit()
            logger.info("Persisted results to Postgres (event_id=%d)", event_id)
        except Exception as db_exc:
            logger.warning("Postgres write failed (non-fatal): %s", db_exc)

        # --- Update BEC behavioral models (best-effort, non-fatal) ---
        try:
            from analysis.analyzers.bec.analyzer import update_behavioral_profiles
            update_behavioral_profiles(email, verdict)
        except Exception as bec_exc:
            logger.warning("BEC profile update failed (non-fatal): %s", bec_exc)

        # --- Dual-write: Redis queue ---
        app.send_task(
            "verdict.tasks.execute_verdict",
            args=[json.dumps(verdict_dict)],
            queue="verdicts",
        )

        logger.info(
            "Verdict published: message_id=%s results=%d",
            verdict.message_id, len(verdict.results),
        )

        return {
            "message_id": verdict.message_id,
            "analyzers": [r.analyzer for r in verdict.results],
        }

    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in email event: %s", exc)
        raise

    except Exception as exc:
        logger.exception("Failed to analyze email: %s", exc)
        raise self.retry(exc=exc)
