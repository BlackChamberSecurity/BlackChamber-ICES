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
BCEM Analysis Engine — Celery Application Configuration

This is the single source of truth for Celery configuration in the analysis
service. All workers import this app instance.
"""
import os
from celery import Celery

# Redis URL from environment (matches docker-compose / .env)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

app = Celery("analysis")

app.config_from_object({
    # Broker (where tasks come from)
    "broker_url": REDIS_URL,

    # Result backend (where task results are stored)
    "result_backend": REDIS_URL,

    # Serialisation
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],

    # Task routing — analysis tasks go to the "emails" queue
    "task_routes": {
        "analysis.tasks.analyze_email": {"queue": "emails"},
    },

    # Reliability
    "task_acks_late": True,                # Acknowledge after processing (not before)
    "worker_prefetch_multiplier": 1,       # Don't hoard tasks; take one at a time
    "task_reject_on_worker_lost": True,    # Re-queue if worker crashes

    # Timezone
    "timezone": "UTC",
})

# Auto-discover tasks in the analysis package
app.autodiscover_tasks(["analysis"])
