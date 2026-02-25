# Sentinel's Journal

## 2026-06-25 - Hardcoded Default Credentials
**Vulnerability:** The WebUI service defaulted to `admin`/`changeme` if environment variables were missing.
**Learning:** Providing fallback values for sensitive credentials in `os.environ.get()` creates a "secure by default" failure. Developers might deploy without configuring secrets, unknowingly leaving the application vulnerable.
**Prevention:** Remove default values for sensitive configuration. Raise explicit errors (e.g., `ValueError`) during startup if required secrets are missing, forcing the operator to configure them.
