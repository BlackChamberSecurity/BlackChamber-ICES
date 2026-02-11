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
BlackChamber ICES Verdict Worker — Celery Tasks

Two tasks:
1. execute_verdict: Process a verdict (evaluate policies, buffer action for batch)
2. flush_batch:     Periodic task (Celery Beat) to flush the batch buffer
"""
import json
import logging


from verdict.celery_app import app
from verdict.models import VerdictEvent
from verdict.dispatcher import Dispatcher
from verdict.policy_engine import PolicyEngine
from verdict.batch_client import BatchClient
from verdict.token_manager import TokenManager

logger = logging.getLogger(__name__)

# Lazy-initialised singletons (created on first use by each worker process)
_dispatcher = None
_batch_client = None
_token_manager = None


def _load_policies() -> list[dict]:
    """Load policies from config.yaml via shared config loader."""
    from ices_shared.config import get_policies
    policies = get_policies()
    logger.info("Loaded %d policies", len(policies))
    return policies


def _get_dispatcher() -> Dispatcher:
    global _dispatcher
    if _dispatcher is None:
        policies = _load_policies()
        engine = PolicyEngine(policies)
        _dispatcher = Dispatcher(engine)
    return _dispatcher


def _get_token_manager() -> TokenManager:
    """Get or create the token manager (one per worker process).

    Loads tenant credentials from config.yaml via the shared config loader.
    Falls back to env vars for single-tenant setups.
    """
    global _token_manager
    if _token_manager is None:
        from verdict.token_manager import TenantCredentials
        from ices_shared.config import get_tenants

        tenants = {}
        for t in get_tenants():
            tid = t.get("tenant_id", "")
            cid = t.get("client_id", "")
            csecret = t.get("client_secret", "")
            if tid and cid and csecret:
                tenants[tid] = TenantCredentials(
                    tenant_id=tid,
                    client_id=cid,
                    client_secret=csecret,
                )
        _token_manager = TokenManager(tenants=tenants if tenants else None)
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
    2. Evaluate policies via the dispatcher
    3. If action required, add to batch buffer
    4. Persist policy outcome to Postgres

    Args:
        verdict_json: JSON string from the analysis engine.
    """
    try:
        verdict_data = json.loads(verdict_json)
        verdict = VerdictEvent.from_dict(verdict_data)

        logger.info(
            "Processing verdict: message_id=%s results=%d sender=%s",
            verdict.message_id, len(verdict.results), verdict.sender,
        )

        # Skip if already processed — prevents duplicate Graph API actions
        try:
            from ices_shared.db import get_connection, is_message_processed
            with get_connection() as conn:
                if is_message_processed(conn, verdict.message_id):
                    logger.info("Skipping already-processed verdict: %s", verdict.message_id)
                    return {"message_id": verdict.message_id, "status": "already_processed"}
        except Exception:
            pass  # If DB check fails, proceed with processing

        dispatcher = _get_dispatcher()
        result = dispatcher.dispatch(verdict)

        # --- Persist policy outcome to Postgres ---
        decision = result.get("decision", {}) if result else {}
        try:
            from ices_shared.db import get_connection, store_policy_outcome
            with get_connection() as conn:
                store_policy_outcome(
                    conn,
                    message_id=verdict.message_id,
                    tenant_id=verdict.tenant_id,
                    policy_name=decision.get("policy_name", ""),
                    action=decision.get("action", "none"),
                    details=decision,
                )
                conn.commit()
        except Exception as db_exc:
            logger.warning("Postgres write failed (non-fatal): %s", db_exc)

        if result is None:
            return {"message_id": verdict.message_id, "action": "none"}

        # Buffer the request for batch execution
        request = result.get("request")
        if request:
            batch_client = _get_batch_client()
            batch_client.add_action(request)

        return {
            "message_id": verdict.message_id,
            "action": decision.get("action", "none"),
            "policy": decision.get("policy_name", ""),
        }

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
