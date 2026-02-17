## 2026-05-21 - [Rate Limiting Implementation]
**Vulnerability:** Missing rate limiting on sensitive `/api/login` endpoint allowed brute-force attacks.
**Learning:** Custom in-memory rate limiters must include memory management (e.g., max client limits) to prevent self-imposed Denial of Service via memory exhaustion.
**Prevention:** Always implement eviction policies or size caps when storing request history in memory. Consider using `slowapi` or Redis for distributed rate limiting in production.
