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
BlackChamber ICES Analysis Engine — Celery Application

Configures the Celery worker that processes email analysis tasks.
Uses shared defaults from ices_shared.celery_defaults with
analysis-specific task routing.
"""
import os
from celery import Celery

from ices_shared.celery_defaults import CELERY_DEFAULTS

app = Celery("analysis")

# Start with shared defaults, then apply analysis-specific overrides
config = {**CELERY_DEFAULTS}
config.update({
    # Task routing — analysis tasks go to the 'emails' queue
    "task_routes": {
        "analysis.tasks.analyze_email": {"queue": "emails"},
    },
})

app.config_from_object(config)

# Auto-discover tasks in the analysis package
app.autodiscover_tasks(["analysis"])
