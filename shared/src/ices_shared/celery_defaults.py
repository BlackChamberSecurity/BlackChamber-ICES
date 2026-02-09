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
Shared Celery configuration defaults for all BlackChamber ICES workers.

Both the analysis and verdict workers share the same broker, serialisation,
and reliability settings. Per-worker overrides (task routing, beat schedules)
are applied on top of these defaults in each service's celery_app.py.
"""

import os

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

CELERY_DEFAULTS = {
    # Broker
    "broker_url": REDIS_URL,
    "result_backend": REDIS_URL,

    # Serialization — JSON only, no pickle
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],

    # Reliability
    "task_acks_late": True,
    "worker_prefetch_multiplier": 1,
    "task_reject_on_worker_lost": True,

    # Timezone
    "timezone": "UTC",
    "enable_utc": True,
}
