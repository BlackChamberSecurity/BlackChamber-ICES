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
BlackChamber ICES Analysis Pipeline

Orchestrates analysis of an email:
1. Auto-discovers all analyzers (sorted by order)
2. Runs each analyzer, collecting observations
3. Returns a Verdict with all results
"""
import logging
import time

from analysis.analyzers import discover_analyzers
from analysis.models import EmailEvent, AnalysisResult, Observation, Verdict

logger = logging.getLogger(__name__)


def run_pipeline(email: EmailEvent) -> Verdict:
    """
    Run all registered analyzers on an email and collect their observations.

    Each analyzer runs independently and returns typed observations.
    No score aggregation — consumers (policy engine) interpret results.
    """
    analyzers = discover_analyzers()
    logger.info(
        "Running %d analyzers on message %s (order: %s)",
        len(analyzers), email.message_id,
        ", ".join(f"{a.name}({a.order})" for a in analyzers),
    )

    results: list[AnalysisResult] = []

    for analyzer in analyzers:
        try:
            t0 = time.monotonic()
            result = analyzer.analyze(email)
            elapsed_ms = (time.monotonic() - t0) * 1000
            result.processing_time_ms = elapsed_ms
            results.append(result)

            obs_summary = ", ".join(
                f"{o.key}={o.value}" for o in result.observations
            )
            logger.info(
                "Analyzer '%s': %d observations [%s] (%.1fms)",
                analyzer.name, len(result.observations), obs_summary,
                elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000
            logger.exception(
                "Analyzer '%s' failed (%.1fms): %s", analyzer.name,
                elapsed_ms, exc,
            )
            results.append(AnalysisResult(
                analyzer=analyzer.name,
                observations=[
                    Observation(key="error", value=str(exc), type="text"),
                ],
                processing_time_ms=elapsed_ms,
            ))

    # Extract recipients for policy engine matching
    recipients = [r.address for r in email.to] if email.to else []

    verdict = Verdict(
        message_id=email.message_id,
        user_id=email.user_id,
        tenant_id=email.tenant_id,
        tenant_alias=email.tenant_alias,
        sender=email.sender,
        recipients=recipients,
        results=results,
    )

    logger.info(
        "Analysis complete for message %s: %d analyzer(s) ran",
        email.message_id, len(results),
    )

    return verdict
