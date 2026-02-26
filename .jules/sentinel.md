## 2026-02-17 - Hardcoded Default Credentials
**Vulnerability:** The WebUI service defaulted to "admin" / "changeme" credentials when environment variables were missing, exposing the application to unauthorized access by default.
**Learning:** Providing fallback values for sensitive credentials in code (`os.environ.get(..., "default")`) and deployment config (`${VAR:-default}`) creates a silent failure mode where the application appears secure but is actually vulnerable.
**Prevention:** Mandate explicit configuration for all sensitive secrets. The application should fail to start (fail secure) if required credentials are not provided, rather than falling back to insecure defaults.
