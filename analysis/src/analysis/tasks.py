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

"""
BCEM Analysis Engine — Celery Tasks

This module defines the Celery tasks that workers execute. The main task
is `analyze_email`, which receives a JSON-serialised email event from
the Go ingestion service, runs the analysis pipeline, and publishes
the verdict to the verdict queue.
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
    Analyze an email event and publish the verdict.

    This task is triggered by the Go ingestion service pushing a Celery
    message to Redis. It:
    1. Deserialises the email event JSON
    2. Runs the analysis pipeline (all registered analyzers)
    3. Publishes the verdict to the verdict queue

    Args:
        email_event_json: JSON string matching the EmailEvent schema.
    """
    try:
        # Parse the incoming email event
        event_data = json.loads(email_event_json)
        email = EmailEvent.from_dict(event_data)

        logger.info(
            "Analyzing email: message_id=%s tenant=%s from=%s subject=%s",
            email.message_id, email.tenant_alias or email.tenant_id,
            email.sender, email.subject,
        )

        # Run all analyzers
        verdict = run_pipeline(email)

        # Publish verdict to the verdict queue
        from analysis.celery_app import app as celery_app
        celery_app.send_task(
            "verdict.tasks.execute_verdict",
            args=[json.dumps(verdict.to_dict())],
            queue="verdicts",
        )

        logger.info(
            "Verdict published: message_id=%s results=%d",
            verdict.message_id, len(verdict.results),
        )

        return {
            "message_id": verdict.message_id,
            "results": [
                {"analyzer": r.analyzer, "score": r.score, "provider": r.provider, "category": r.category}
                for r in verdict.results
            ],
        }

    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in email event: %s", exc)
        raise  # Don't retry on bad data

    except Exception as exc:
        logger.exception("Failed to analyze email: %s", exc)
        raise self.retry(exc=exc)
