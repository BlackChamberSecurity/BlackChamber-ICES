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
BlackChamber ICES Action Base Class

Same drop-in pattern as the analysis engine's analyzers.
To create a new action:
1. Create a new .py file in this folder
2. Inherit from BaseAction
3. Set action_name
4. Implement build_request() (for $batch actions) or execute() (for direct actions)
5. Save and restart — that's it!
"""
from abc import ABC, abstractmethod
from typing import Callable, Optional
from verdict.models import VerdictEvent


class BaseAction(ABC):
    """
    Base class for all verdict actions.

    Actions come in two flavours:
    - **Batch actions** (default): implement ``build_request()`` which returns
      a dict for the Graph ``$batch`` endpoint. The Dispatcher buffers these.
    - **Direct actions**: set ``is_direct = True`` and implement ``execute()``.
      The Dispatcher calls ``execute()`` immediately instead of buffering.

    Attributes:
        action_name: Unique identifier for this action (matches policy action value)
        description: What this action does
        is_direct: If True, this action calls an API directly (not via $batch)
    """

    action_name: str = "unnamed"
    description: str = ""
    is_direct: bool = False

    def build_request(self, verdict: VerdictEvent) -> dict:
        """
        Build a Graph API request dict for the $batch endpoint.

        Override this for batch-style actions (tag, delete).

        Args:
            verdict: The verdict event with message_id, user_id, etc.

        Returns:
            A dict with the Graph API sub-request.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement build_request() or execute()"
        )

    def execute(
        self,
        verdict: VerdictEvent,
        token_provider: Callable[..., str],
    ) -> dict:
        """
        Execute the action directly (not via $batch).

        Override this for direct actions (e.g. Defender remediate).

        Args:
            verdict: The verdict event.
            token_provider: Callable that returns a valid access token.

        Returns:
            A dict with the action result.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement execute() for direct actions"
        )
