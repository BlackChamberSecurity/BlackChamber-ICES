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
BCEM Verdict Worker — Graph API Batch Client

This module handles batching multiple Graph API actions (quarantine, tag,
delete) into a single HTTP call using the Graph API $batch endpoint.

How it works:
1. Verdict actions are accumulated in a Redis list as individual requests
2. When the buffer reaches 20 items (Graph API max) or a timer fires,
   all buffered requests are sent as a single POST /$batch call
3. Partial failures are handled — each sub-request gets its own status
4. 429 (rate limited) sub-requests are re-queued for retry

This reduces API calls by up to 20x at high volume.
"""
import json
import logging
import os
from typing import Callable, Optional

import httpx
import redis

logger = logging.getLogger(__name__)

GRAPH_API_BASE = os.environ.get("GRAPH_API_BASE", "https://graph.microsoft.com/v1.0")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
BATCH_SIZE = int(os.environ.get("VERDICT_BATCH_SIZE", "20"))
BATCH_BUFFER_KEY = "verdict:batch_buffer"


class BatchClient:
    """
    Accumulates Graph API actions and sends them in batches.

    Usage:
        client = BatchClient(token_provider=manager.get_token)
        client.add_action({...})     # Add individual Graph API request
        client.flush()               # Send all buffered actions as one $batch call
    """

    def __init__(
        self,
        token_provider: Callable[[], str],
        redis_client: Optional[redis.Redis] = None,
        # Legacy: accept access_token for backward compat
        access_token: str = "",
    ):
        if token_provider is not None:
            self._token_provider = token_provider
        else:
            # Fallback for backward compat: static token
            self._token_provider = lambda: access_token
        self.redis_client = redis_client or redis.from_url(REDIS_URL)
        self.batch_url = f"{GRAPH_API_BASE}/$batch"

    def add_action(self, action: dict) -> None:
        """
        Add a Graph API action to the batch buffer.

        Args:
            action: A dict representing a single Graph API request:
                {
                    "id": "unique-id",
                    "method": "POST",
                    "url": "/users/{user_id}/messages/{msg_id}/move",
                    "headers": {"Content-Type": "application/json"},
                    "body": {"destinationId": "quarantine-folder-id"}
                }
        """
        self.redis_client.lpush(BATCH_BUFFER_KEY, json.dumps(action))

        # Auto-flush if buffer is full
        buffer_size = self.redis_client.llen(BATCH_BUFFER_KEY)
        if buffer_size >= BATCH_SIZE:
            logger.info("Batch buffer full (%d items), flushing", buffer_size)
            self.flush()

    def flush(self) -> list[dict]:
        """
        Send all buffered actions as a single $batch request to Graph API.

        Returns:
            List of individual response dicts from the batch response.
        """
        # Pop up to BATCH_SIZE items from the buffer
        pipe = self.redis_client.pipeline()
        pipe.lrange(BATCH_BUFFER_KEY, -BATCH_SIZE, -1)
        pipe.ltrim(BATCH_BUFFER_KEY, 0, -(BATCH_SIZE + 1))
        results = pipe.execute()

        raw_actions = results[0]
        if not raw_actions:
            return []

        # Parse buffered actions
        requests = []
        for i, raw in enumerate(raw_actions):
            try:
                action = json.loads(raw)
                if "id" not in action:
                    action["id"] = str(i)
                requests.append(action)
            except json.JSONDecodeError:
                logger.error("Invalid action in batch buffer: %s", raw)

        if not requests:
            return []

        logger.info("Sending batch of %d Graph API requests", len(requests))

        # Send $batch request
        try:
            response = httpx.post(
                self.batch_url,
                json={"requests": requests},
                headers={
                    "Authorization": f"Bearer {self._token_provider()}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Batch request failed: %s", exc)
            # Re-queue all actions for retry
            for action in requests:
                self.redis_client.lpush(BATCH_BUFFER_KEY, json.dumps(action))
            return []

        # Parse batch response
        batch_response = response.json()
        responses = batch_response.get("responses", [])

        # Handle partial failures
        failed = []
        for resp in responses:
            status = resp.get("status", 0)
            req_id = resp.get("id", "unknown")

            if status == 429:
                # Rate limited — re-queue for retry
                logger.warn("Sub-request %s rate limited (429), re-queuing", req_id)
                original = next((r for r in requests if r.get("id") == req_id), None)
                if original:
                    failed.append(original)
            elif status >= 400:
                logger.error(
                    "Sub-request %s failed (status %d): %s",
                    req_id, status, resp.get("body", {}),
                )

        # Re-queue failed items
        for action in failed:
            self.redis_client.lpush(BATCH_BUFFER_KEY, json.dumps(action))

        logger.info(
            "Batch complete: %d sent, %d succeeded, %d re-queued",
            len(requests), len(requests) - len(failed), len(failed),
        )

        return responses

    def buffer_size(self) -> int:
        """Return the current number of buffered actions."""
        return self.redis_client.llen(BATCH_BUFFER_KEY)
