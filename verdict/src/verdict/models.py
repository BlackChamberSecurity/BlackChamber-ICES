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
BlackChamber ICES Verdict Worker — Data Models

All canonical data models live in ices_shared.models. This module
re-exports them for backward compatibility.
"""

from ices_shared.models import (
    Observation,
    AnalysisResult,
    Verdict,
)

# Backward-compatible aliases
VerdictResult = AnalysisResult
VerdictEvent = Verdict
