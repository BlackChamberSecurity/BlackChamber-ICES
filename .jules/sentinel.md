## 2026-05-22 - [Reusable Rate Limiter Pattern]
**Vulnerability:** Lack of rate limiting on critical endpoints (e.g. login) exposing them to brute force.
**Learning:** `FastAPI` dependencies are an effective way to inject security controls like rate limiting without modifying core logic. In-memory limiting is sufficient for single-instance deployments but has limitations in distributed environments.
**Prevention:** Use the `RateLimiter` class in `webui.security` as a dependency for any new sensitive endpoints.
