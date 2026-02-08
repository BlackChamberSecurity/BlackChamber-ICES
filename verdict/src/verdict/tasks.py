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
BCEM Verdict Worker — Celery Tasks

Two tasks:
1. execute_verdict: Process a single verdict (route to action, buffer for batch)
2. flush_batch:     Periodic task (Celery Beat) to flush the batch buffer
"""
import json
import logging
import os

from verdict.celery_app import app
from verdict.models import VerdictEvent
from verdict.dispatcher import Dispatcher
from verdict.batch_client import BatchClient
from verdict.token_manager import TokenManager

logger = logging.getLogger(__name__)

# Lazy-initialised singletons (created on first use by each worker process)
_dispatcher = None
_batch_client = None
_token_manager = None


def _get_dispatcher() -> Dispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = Dispatcher()
    return _dispatcher


def _get_token_manager() -> TokenManager:
    """Get or create the token manager (one per worker process)."""
    global _token_manager
    if _token_manager is None:
        _token_manager = TokenManager()
    return _token_manager


def _get_batch_client() -> BatchClient:
    """
    Get or create the batch client.

    Uses the TokenManager for automatic token acquisition and refresh
    via the OAuth2 client credentials flow.
    """
    global _batch_client
    if _batch_client is None:
        manager = _get_token_manager()
        _batch_client = BatchClient(token_provider=manager.get_token)
    return _batch_client


@app.task(
    name="verdict.tasks.execute_verdict",
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    acks_late=True,
)
def execute_verdict(self, verdict_json: str):
    """
    Process a verdict from the analysis engine.

    1. Deserialise the verdict
    2. Determine the action via the dispatcher
    3. Add the action to the batch buffer
    4. The batch client auto-flushes when the buffer is full (20 items)

    Args:
        verdict_json: JSON string from the analysis engine.
    """
    try:
        verdict_data = json.loads(verdict_json)
        verdict = VerdictEvent.from_dict(verdict_data)

        logger.info(
            "Processing verdict: message_id=%s results=%d",
            verdict.message_id, len(verdict.results),
        )

        dispatcher = _get_dispatcher()
        summary = dispatcher.dispatch(verdict)

        if summary is None:
            return {"message_id": verdict.message_id, "results": []}

        return summary

    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in verdict: %s", exc)
        raise  # Don't retry bad data

    except Exception as exc:
        logger.exception("Failed to process verdict: %s", exc)
        raise self.retry(exc=exc)


@app.task(name="verdict.tasks.flush_batch")
def flush_batch():
    """
    Periodic task to flush the batch buffer.

    Called by Celery Beat every N seconds (configured in celery_app.py).
    Ensures actions don't sit in the buffer too long during low-volume periods.
    """
    batch_client = _get_batch_client()
    buffer_size = batch_client.buffer_size()

    if buffer_size == 0:
        return {"flushed": 0}

    logger.info("Timer flush: %d actions in buffer", buffer_size)
    responses = batch_client.flush()

    return {"flushed": len(responses)}
