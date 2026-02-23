## 2026-10-18 - [CRITICAL] Insecure Default Credentials
**Vulnerability:** The application was configured with hardcoded default credentials (`admin`/`changeme`) in both the Python code and Docker Compose configuration. This allowed anyone to access the admin dashboard if the user failed to set environment variables.
**Learning:** Default values in code (`os.environ.get("VAR", "default")`) and Docker Compose (`${VAR:-default}`) can silently introduce critical vulnerabilities. Users often skip configuration steps, leaving defaults active in production.
**Prevention:**
1. Never provide default values for sensitive credentials in code. Raise an error if they are missing (`os.environ["VAR"]`).
2. Remove defaults from `docker-compose.yml`.
3. Provide a clear `.env.example` with placeholders and fail fast if the actual `.env` is missing required values.
