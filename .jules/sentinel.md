## 2026-02-22 - Insecure Default Credentials
**Vulnerability:** The WebUI `auth.py` and `docker-compose.yml` contained hardcoded default credentials (`admin` / `changeme`) for the administrative user.
**Learning:** Hardcoded defaults for authentication, even if intended as placeholders, are a significant security risk because they often make it into production deployments unintentionally. Relying on users to override them is insufficient.
**Prevention:** Enforce the presence of authentication secrets via environment variables at application startup. Fail fast (crash the app) if they are missing, rather than falling back to insecure defaults.
