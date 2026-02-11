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
Analyzer auto-discovery.

This module automatically finds and loads all analyzer classes in this
package **and its sub-packages**.  Any module containing a class that
inherits from BaseAnalyzer will be discovered and used by the analysis
pipeline.

You do NOT need to modify this file when adding new analyzers.
"""
import importlib
import inspect
import pkgutil

import analysis.analyzers as _self_pkg
from analysis.analyzers._base import BaseAnalyzer


def discover_analyzers() -> list[BaseAnalyzer]:
    """
    Recursively find all BaseAnalyzer subclasses in the analyzers/ tree.

    Returns:
        List of instantiated analyzer objects, ready to use.
    """
    analyzers: list[BaseAnalyzer] = []
    seen_classes: set[type] = set()

    for _importer, module_name, _is_pkg in pkgutil.walk_packages(
        _self_pkg.__path__, prefix=_self_pkg.__name__ + ".",
    ):
        # Skip private modules (like _base.py)
        leaf = module_name.rsplit(".", 1)[-1]
        if leaf.startswith("_"):
            continue

        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue

        for _attr_name, attr_value in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(attr_value, BaseAnalyzer)
                and attr_value is not BaseAnalyzer
                and attr_value not in seen_classes
            ):
                seen_classes.add(attr_value)
                analyzers.append(attr_value())

    analyzers.sort(key=lambda a: a.order)
    return analyzers
