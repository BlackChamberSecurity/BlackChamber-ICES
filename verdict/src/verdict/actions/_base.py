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
BCEM Action Base Class

Same drop-in pattern as the analysis engine's analyzers.
To create a new action:
1. Create a new .py file in this folder
2. Inherit from BaseAction
3. Implement the build_request() method
4. Save and restart — that's it!
"""
from abc import ABC, abstractmethod
from verdict.models import VerdictEvent


class BaseAction(ABC):
    """
    Base class for all verdict actions.

    Attributes:
        name:        Unique identifier for this action
        description: What this action does
    """

    name: str = "unnamed"
    description: str = ""

    @abstractmethod
    def build_request(self, verdict: VerdictEvent) -> dict:
        """
        Build a Graph API request dict for the $batch endpoint.

        Args:
            verdict: The verdict event with message_id, user_id, etc.

        Returns:
            A dict with the Graph API sub-request:
            {
                "id": "unique-request-id",
                "method": "POST" or "PATCH",
                "url": "/users/{user_id}/messages/{msg_id}/...",
                "headers": {"Content-Type": "application/json"},
                "body": { ... }
            }
        """
        ...
