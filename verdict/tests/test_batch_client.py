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

"""Tests for the Graph API BatchClient."""

import json
from unittest.mock import MagicMock, patch

import pytest


class TestBatchClientBuffer:
    """Test the buffering and flush mechanics."""

    def _make_client(self, batch_size=20, redis_mock=None, pipeline_result=None):
        """Create a BatchClient with mocked dependencies."""
        from verdict.batch_client import BatchClient

        if redis_mock is None:
            redis_mock = MagicMock()
            redis_mock.llen.return_value = 0
            redis_mock.lpush = MagicMock()

        # Mock the pipeline — flush() uses pipe.lrange / pipe.ltrim / pipe.execute
        pipe_mock = MagicMock()
        if pipeline_result is not None:
            pipe_mock.execute.return_value = pipeline_result
        else:
            pipe_mock.execute.return_value = [[], None]
        redis_mock.pipeline.return_value = pipe_mock

        token_provider = MagicMock(return_value="test-token")

        with patch("verdict.batch_client.redis.from_url", return_value=redis_mock):
            client = BatchClient(
                token_provider=token_provider,
                batch_size=batch_size,
            )

        return client, redis_mock, token_provider

    def test_add_pushes_to_redis(self):
        client, redis_mock, _ = self._make_client()
        redis_mock.llen.return_value = 1

        request = {"id": "1", "method": "POST", "url": "/test"}
        client.add(request)

        redis_mock.lpush.assert_called_once()

    def test_buffer_size(self):
        client, redis_mock, _ = self._make_client()
        redis_mock.llen.return_value = 5

        assert client.buffer_size() == 5

    def test_empty_flush_returns_empty(self):
        client, redis_mock, _ = self._make_client()
        redis_mock.llen.return_value = 0
        redis_mock.lrange.return_value = []

        result = client.flush()
        assert result == []

    @patch("verdict.batch_client.httpx.post")
    def test_flush_sends_batch(self, mock_post):
        """flush() sends buffered requests as a Graph API $batch call."""
        # Pre-populate buffer via pipeline mock
        buffered = [
            json.dumps({"id": "1", "method": "POST", "url": "/test1"}).encode(),
            json.dumps({"id": "2", "method": "PATCH", "url": "/test2"}).encode(),
        ]
        client, redis_mock, token_provider = self._make_client(
            pipeline_result=[buffered, None],
        )

        # Mock HTTP response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "responses": [
                {"id": "1", "status": 200},
                {"id": "2", "status": 200},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = client.flush()

        # Verify batch was sent
        mock_post.assert_called_once()

    @patch("verdict.batch_client.httpx.post")
    def test_429_requeue(self, mock_post):
        """Sub-requests that get 429 are re-queued."""
        buffered = [
            json.dumps({"id": "1", "method": "POST", "url": "/ok"}).encode(),
            json.dumps({"id": "2", "method": "POST", "url": "/throttled"}).encode(),
        ]
        client, redis_mock, _ = self._make_client(
            pipeline_result=[buffered, None],
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "responses": [
                {"id": "1", "status": 200},
                {"id": "2", "status": 429, "body": {"error": {"message": "throttled"}}},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = client.flush()

        # The 429 request should be re-queued
        # Check that lpush was called at least once for the re-queue
        assert redis_mock.lpush.call_count >= 1
