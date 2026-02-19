## 2024-05-23 - Hardcoded Default Credentials
**Vulnerability:** The application had a hardcoded default password "changeme" for the admin user, both in the Python code and in `docker-compose.yml`.
**Learning:** Relying on defaults in code for sensitive credentials is dangerous because users might deploy without configuring environment variables, unknowingly exposing their instance. Documentation is not a sufficient control.
**Prevention:** Always enforce required environment variables for secrets. Fail fast (crash on startup) if they are missing, rather than falling back to an insecure default.
