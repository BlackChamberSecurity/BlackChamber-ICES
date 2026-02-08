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

This module automatically finds and loads all analyzer classes in this folder.
Any .py file containing a class that inherits from BaseAnalyzer will be
discovered and used by the analysis pipeline.

You do NOT need to modify this file when adding new analyzers.
"""
import importlib
import inspect
import pkgutil
from pathlib import Path

from analysis.analyzers._base import BaseAnalyzer


def discover_analyzers() -> list[BaseAnalyzer]:
    """
    Find all BaseAnalyzer subclasses in the analyzers/ directory.

    Returns:
        List of instantiated analyzer objects, ready to use.
    """
    analyzers = []
    package_dir = Path(__file__).parent

    # Walk all .py files in this directory
    for finder, module_name, is_pkg in pkgutil.iter_modules([str(package_dir)]):
        # Skip private modules (like _base.py)
        if module_name.startswith("_"):
            continue

        # Import the module
        module = importlib.import_module(f"analysis.analyzers.{module_name}")

        # Find all classes that inherit from BaseAnalyzer
        for attr_name, attr_value in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(attr_value, BaseAnalyzer)
                and attr_value is not BaseAnalyzer
            ):
                analyzers.append(attr_value())

    analyzers.sort(key=lambda a: a.order)
    return analyzers
