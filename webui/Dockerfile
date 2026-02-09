# ===========================================================================
# Stage 1 — Build React SPA
# ===========================================================================
FROM node:20-alpine AS frontend

WORKDIR /frontend
COPY webui/frontend/package*.json ./
RUN npm ci --silent
COPY webui/frontend/ .
RUN npm run build

# ===========================================================================
# Stage 2 — Python runtime
# ===========================================================================
FROM python:3.12-slim

WORKDIR /app

# Install shared package first (models, DB helpers, Celery defaults)
COPY shared/ /app/shared/
RUN pip install --no-cache-dir -e /app/shared

# Install webui package
COPY webui/pyproject.toml .
COPY webui/src/ src/

RUN pip install --no-cache-dir -e .

# Copy React build output into the location FastAPI expects
COPY --from=frontend /frontend/dist /app/static

EXPOSE 8000

CMD ["uvicorn", "webui.main:app", "--host", "0.0.0.0", "--port", "8000"]
