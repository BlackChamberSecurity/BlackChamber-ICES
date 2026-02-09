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
BlackChamber ICES Analyzer Base Class

To create a new analyzer:
1. Create a new .py file in this folder (e.g. my_check.py)
2. Import BaseAnalyzer, AnalysisResult, Observation from this file
3. Create a class that inherits from BaseAnalyzer
4. Set name, description, and order
5. Implement the analyze() method — return observations
6. Save and restart the workers — that's it!

Example:
    from analysis.analyzers._base import BaseAnalyzer, AnalysisResult, Observation

    class MyAnalyzer(BaseAnalyzer):
        name = "my_check"
        description = "What this analyzer does"
        order = 40              # lower runs first

        def analyze(self, email):
            return AnalysisResult(
                analyzer=self.name,
                observations=[
                    Observation(key="risk_score", value=0, type="numeric"),
                ],
            )
"""
from abc import ABC, abstractmethod
from analysis.models import AnalysisResult, EmailEvent, Observation


class BaseAnalyzer(ABC):
    """
    Base class for all email analyzers.

    Attributes:
        name:        Unique identifier for this analyzer (shown in logs)
        description: Human-readable description of what it checks
        order:       Execution order (lower = runs first, default 100)
    """

    name: str = "unnamed"
    description: str = ""
    order: int = 100

    @abstractmethod
    def analyze(self, email: EmailEvent) -> AnalysisResult:
        """
        Analyze an email and return observations.

        Returns:
            AnalysisResult with a list of Observation key-value pairs.
        """
        ...
