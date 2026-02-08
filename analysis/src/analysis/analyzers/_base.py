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
BCEM Analyzer Base Class

This is the ONLY file you need to understand to write a new analyzer.

To create a new analyzer:
1. Create a new .py file in this folder (e.g. my_check.py)
2. Import BaseAnalyzer and AnalysisResult from this file
3. Create a class that inherits from BaseAnalyzer
4. Set name, description, and severity_weight
5. Implement the analyze() method
6. Save and restart the workers — that's it!

Example:
    from analysis.analyzers._base import BaseAnalyzer, AnalysisResult

    class MyAnalyzer(BaseAnalyzer):
        name = "my_check"
        description = "What this analyzer does"
        severity_weight = 50

        def analyze(self, email):
            # Your logic here
            return AnalysisResult(analyzer=self.name, score=0, findings=[])
"""
from abc import ABC, abstractmethod
from analysis.models import AnalysisResult, EmailEvent


class BaseAnalyzer(ABC):
    """
    Base class for all email analyzers.

    Attributes:
        name:            Unique identifier for this analyzer (shown in logs)
        description:     Human-readable description of what it checks
        severity_weight: How heavily this analyzer's score counts (0-100)
                        Higher = this analyzer's findings matter more
    """

    name: str = "unnamed"
    description: str = ""
    severity_weight: int = 50

    @abstractmethod
    def analyze(self, email: EmailEvent) -> AnalysisResult:
        """
        Analyze an email and return a result.

        Args:
            email: The email to analyze. Has these useful fields:
                   - email.sender       (str)  "user@example.com"
                   - email.sender_name  (str)  "John Doe"
                   - email.subject      (str)  "Meeting tomorrow"
                   - email.body.content (str)  The email body text
                   - email.headers      (dict) Raw email headers
                   - email.attachments  (list) File attachments

        Returns:
            AnalysisResult with:
                - analyzer: your analyzer's name
                - score:    0 (clean) to 100 (definitely malicious)
                - findings: list of human-readable strings explaining what you found
        """
        ...
