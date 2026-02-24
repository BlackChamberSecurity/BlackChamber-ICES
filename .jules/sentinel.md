## 2026-06-25 - Insecure Default Credentials
**Vulnerability:** The WebUI service (`webui/src/webui/auth.py`) and `docker-compose.yml` contained hardcoded default credentials ("admin" / "changeme"), allowing unauthorized administrative access if environment variables were not explicitly set.
**Learning:** The application prioritized ease of setup (defaults) over security, creating a "secure by configuration" model rather than "secure by default".
**Prevention:** Remove all default values for sensitive credentials in code and configuration files. Force the application to fail at startup if required secrets are missing. Use `.env.example` to guide users on required configuration without providing insecure working defaults.
