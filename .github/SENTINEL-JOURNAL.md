## 2026-02-03 – Hardening Core Limiter and Middleware
**Pattern discovered:** Algorithmic complexity in memory storage and implicit trust of proxy headers in middleware defaults.
**Business/project impact:** Vulnerable to DoS attacks and rate-limit bypasses which could lead to service instability or abuse.
**Constraint / future rule:** Always perform O(1) operations in the hot path of request processing; never trust user-controlled headers (X-Forwarded-For) by default in security controls.
**Recommended controls:** Use background janitors for state cleanup; default to secure-by-default RemoteAddr; mask internal errors from end-users while maintaining server-side observability.
