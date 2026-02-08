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
BCEM Analysis Pipeline

This module orchestrates the analysis of an email:
1. Auto-discovers all analyzers in the analyzers/ folder
2. Runs each analyzer on the email
3. Returns individual results from each analyzer (no aggregation)
"""
import logging

from analysis.analyzers import discover_analyzers
from analysis.models import EmailEvent, AnalysisResult, Verdict

logger = logging.getLogger(__name__)


def run_pipeline(email: EmailEvent) -> Verdict:
    """
    Run all registered analyzers on an email and collect their results.

    Each analyzer runs independently and its result is returned as-is.
    No score aggregation — consumers decide how to interpret each result.

    Args:
        email: The email to analyze.

    Returns:
        Verdict containing individual results from every analyzer.
    """
    analyzers = discover_analyzers()
    logger.info(
        "Running %d analyzers on message %s",
        len(analyzers), email.message_id,
    )

    results: list[AnalysisResult] = []

    for analyzer in analyzers:
        try:
            result = analyzer.analyze(email)
            results.append(result)

            logger.info(
                "Analyzer '%s' scored %d with %d findings (provider=%s, category=%s)",
                analyzer.name, result.score, len(result.findings),
                result.provider or "-", result.category or "-",
            )
        except Exception as exc:
            logger.exception(
                "Analyzer '%s' failed: %s", analyzer.name, exc,
            )
            # Don't let one broken analyzer kill the whole pipeline
            results.append(AnalysisResult(
                analyzer=analyzer.name,
                score=0,
                findings=[f"Analyzer error: {exc}"],
            ))

    verdict = Verdict(
        message_id=email.message_id,
        user_id=email.user_id,
        tenant_id=email.tenant_id,
        tenant_alias=email.tenant_alias,
        results=results,
    )

    logger.info(
        "Analysis complete for message %s: %d analyzer(s) ran",
        email.message_id, len(results),
    )

    return verdict

