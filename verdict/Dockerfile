FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY tests/ tests/

RUN pip install --no-cache-dir -e ".[dev]"

CMD ["celery", "-A", "verdict.celery_app", "worker", "-Q", "verdicts", "-l", "info"]
