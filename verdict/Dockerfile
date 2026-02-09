FROM python:3.12-slim

WORKDIR /app

# Install shared package first (shared models, DB helpers, Celery defaults)
COPY shared/ /app/shared/
RUN pip install --no-cache-dir -e /app/shared

COPY verdict/pyproject.toml .
COPY verdict/src/ src/
COPY verdict/tests/ tests/

RUN pip install --no-cache-dir -e ".[dev]"

CMD ["celery", "-A", "verdict.celery_app", "worker", "-Q", "verdicts", "-l", "info"]
