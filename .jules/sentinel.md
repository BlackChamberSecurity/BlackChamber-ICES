## 2026-05-24 - Rate Limiting in Restricted WebUI
**Vulnerability:** Missing rate limiting on sensitive endpoints (e.g., `/api/login`) allowed potential brute-force attacks.
**Learning:** The `webui` service lacks direct access to Redis and the test environment restricts `fastapi` installation. Standard solutions like `slowapi` or Redis-backed limiting were not viable.
**Prevention:** Implemented a lightweight, in-memory `RateLimiter` class with periodic cleanup to prevent memory leaks. Tests require mocking `fastapi` modules directly in `sys.modules` to bypass missing dependencies.
