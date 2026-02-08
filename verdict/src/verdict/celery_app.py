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
BCEM Verdict Worker — Celery Application Configuration

Single source of truth for Celery config in the verdict service.
Includes Celery Beat schedule for periodic batch flushes.
"""
import os
from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
BATCH_FLUSH_INTERVAL = int(os.environ.get("VERDICT_BATCH_FLUSH_INTERVAL", "2"))

app = Celery("verdict")

app.config_from_object({
    # Broker
    "broker_url": REDIS_URL,
    "result_backend": REDIS_URL,

    # Serialisation
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],

    # Task routing
    "task_routes": {
        "verdict.tasks.execute_verdict": {"queue": "verdicts"},
        "verdict.tasks.flush_batch": {"queue": "verdicts"},
    },

    # Reliability
    "task_acks_late": True,
    "worker_prefetch_multiplier": 1,
    "task_reject_on_worker_lost": True,

    # Celery Beat schedule — periodic batch flush
    "beat_schedule": {
        "flush-verdict-batch": {
            "task": "verdict.tasks.flush_batch",
            "schedule": float(BATCH_FLUSH_INTERVAL),
        },
    },

    "timezone": "UTC",
})

app.autodiscover_tasks(["verdict"])
