FROM python:3.12-slim

WORKDIR /app

# Install shared package first (shared models, DB helpers, Celery defaults)
COPY shared/ /app/shared/
RUN pip install --no-cache-dir -e /app/shared

# Copy everything needed for install
COPY analysis/pyproject.toml .
COPY analysis/src/ src/
COPY analysis/tests/ tests/

# Install package and dev dependencies
RUN pip install --no-cache-dir -e ".[dev]"

# Pre-download the NLP model so it's cached in the image
RUN python -c "from transformers import pipeline; pipeline('zero-shot-classification', model='typeform/distilbert-base-uncased-mnli')"

# Default command (overridden by docker-compose)
CMD ["celery", "-A", "analysis.celery_app", "worker", "-Q", "emails", "-l", "info"]
