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
BlackChamber ICES Verdict Worker — Celery Application

Configures the Celery worker for policy evaluation and Graph API actions.
Uses shared defaults from ices_shared.celery_defaults with
verdict-specific task routing and beat schedule.
"""
import os
from celery import Celery

from ices_shared.celery_defaults import CELERY_DEFAULTS

app = Celery("verdict")

# Batch flush interval (seconds) — configurable via env var
BATCH_FLUSH_INTERVAL = int(os.environ.get("VERDICT_BATCH_FLUSH_INTERVAL", "30"))

# Start with shared defaults, then apply verdict-specific overrides
config = {**CELERY_DEFAULTS}
config.update({
    # Task routing — verdict tasks go to the 'verdicts' queue
    "task_routes": {
        "verdict.tasks.execute_verdict": {"queue": "verdicts"},
    },

    # Periodic tasks — batch flush timer
    "beat_schedule": {
        "flush-graph-batch": {
            "task": "verdict.tasks.flush_batch",
            "schedule": BATCH_FLUSH_INTERVAL,
        },
    },
})

app.config_from_object(config)
app.autodiscover_tasks(["verdict"])
