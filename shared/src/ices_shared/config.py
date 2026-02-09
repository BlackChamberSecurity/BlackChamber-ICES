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
BlackChamber ICES — Shared Configuration Loader

Provides a single, cached loader for config.yaml used by all Python
services. Eliminates duplicate YAML path-search logic across services.
"""

import logging
import os
from functools import lru_cache

import yaml

logger = logging.getLogger(__name__)

# Search paths for config.yaml (Docker mount, then relative to repo root)
_CONFIG_PATHS = [
    "/app/config/config.yaml",
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "config", "config.yaml"),
]


@lru_cache(maxsize=1)
def load_config() -> dict:
    """Load and cache config.yaml from known paths.

    Returns:
        The parsed YAML config as a dict, or an empty dict if no config found.
    """
    config_path = os.environ.get("ICES_CONFIG_PATH", "")
    search_paths = [config_path] + _CONFIG_PATHS if config_path else _CONFIG_PATHS

    for path in search_paths:
        if not path:
            continue
        try:
            with open(path) as f:
                config = yaml.safe_load(f) or {}
            logger.info("Configuration loaded from %s", path)
            return config
        except FileNotFoundError:
            continue

    logger.warning("No config.yaml found — using empty configuration")
    return {}


def get_policies() -> list[dict]:
    """Return the policies list from config."""
    return load_config().get("policies", [])


def get_tenants() -> list[dict]:
    """Return the tenants list from config."""
    return load_config().get("tenants", [])
