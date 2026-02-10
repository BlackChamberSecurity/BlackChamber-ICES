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
Shared NLP Module

Provides a singleton instance of the zero-shot classification pipeline.
This ensures the heavy model is loaded only once per worker process.
"""
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_nlp_classifier: Optional[Any] = None
_load_attempted: bool = False

def get_nlp_classifier() -> Optional[Any]:
    """
    Get the shared zero-shot classification pipeline.
    Loads the model on the first call.

    Returns:
        Hugging Face pipeline object, or None if loading failed.
    """
    global _nlp_classifier, _load_attempted

    if _nlp_classifier is None and not _load_attempted:
        _load_attempted = True
        try:
            from transformers import pipeline
            logger.info("Loading zero-shot classification model (cross-encoder/nli-distilroberta-base)...")
            _nlp_classifier = pipeline(
                "zero-shot-classification",
                model="cross-encoder/nli-distilroberta-base",
                device=-1, # CPU
            )
            logger.info("NLP model loaded successfully")
        except Exception as exc:
            logger.warning("Failed to load NLP model: %s. Analyzers depending on NLP will be degraded.", exc)
            _nlp_classifier = None

    return _nlp_classifier
