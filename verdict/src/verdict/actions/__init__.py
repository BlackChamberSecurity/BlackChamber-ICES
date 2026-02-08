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
Action auto-discovery.

Same pattern as analysis/analyzers/__init__.py.
Any .py file here with a BaseAction subclass is auto-discovered.
"""
import importlib
import inspect
import pkgutil
from pathlib import Path

from verdict.actions._base import BaseAction


def discover_actions() -> dict[str, BaseAction]:
    """
    Find all BaseAction subclasses in the actions/ directory.

    Returns:
        Dict mapping action name -> instantiated action object.
    """
    actions = {}
    package_dir = Path(__file__).parent

    for finder, module_name, is_pkg in pkgutil.iter_modules([str(package_dir)]):
        if module_name.startswith("_"):
            continue

        module = importlib.import_module(f"verdict.actions.{module_name}")

        for attr_name, attr_value in inspect.getmembers(module, inspect.isclass):
            if issubclass(attr_value, BaseAction) and attr_value is not BaseAction:
                instance = attr_value()
                actions[instance.name] = instance

    return actions
