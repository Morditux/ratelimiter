## 2024-03-24 - Trusted Proxies for Rate Limiting
**Vulnerability:** IP Spoofing via X-Forwarded-For
**Learning:** `DefaultKeyFunc` blindly trusted the first IP in `X-Forwarded-For`, allowing attackers to spoof their IP by injecting a fake header. Standard `strings.Split(xff, ",")[0]` is vulnerable if the proxy appends to the list.
**Prevention:** Use `TrustedIPKeyFunc` which iterates backwards through the IP chain, trusting only configured proxies (CIDRs) and stopping at the first untrusted IP. This ensures the rate limit key is the true client IP or the last untrusted hop.

## 2024-05-24 - IPv6 Parsing Bypass in TrustedIPKeyFunc
**Vulnerability:** `getRemoteIP` failed to strip brackets from IPv6 addresses, causing `net.ParseIP` to return nil in `TrustedIPKeyFunc`. This led to the remote IP being skipped (implicitly trusted), allowing attackers to spoof `X-Forwarded-For` even if the remote IP was untrusted.
**Learning:** Custom parsing of IP addresses is error-prone. `net.SplitHostPort` is the robust standard for separating IP and port. Failure to parse an IP should not default to trusting the next hop in a trust chain.
**Prevention:** Use `net.SplitHostPort` to safely extract IPs from `RemoteAddr`. Ensure security controls handle parsing failures safely (fail closed or fallback to raw value if appropriate, but never skip validation).

## 2024-03-21 - Memory Store Unbounded Growth
**Vulnerability:** The in-memory store (`MemoryStore`) had no limit on the number of keys it could store. An attacker could generate millions of unique keys (e.g., spoofed IPs) to exhaust the server's memory (DoS), leading to a crash.
**Learning:** In-memory caches/stores must always have a capacity limit (e.g., MaxEntries or MaxBytes). Trusting that "cleanup" will handle it is insufficient if the attack rate exceeds cleanup rate or if keys don't expire quickly enough.
**Prevention:** Implemented a `MaxEntries` configuration with a safe default (1,000,000). The store now enforces this limit per-shard to maintain O(1) performance and prevent OOM. When the limit is reached, it fails safely by returning `ErrStoreFull` instead of crashing.

## 2024-10-18 - Fail Open vs Fail Closed on Input Validation
**Vulnerability:** `RateLimitMiddleware` treated all errors from `limiter.Allow` (including `ErrKeyTooLong` from the store) as system failures and failed open (allowed the request). This allowed attackers to bypass rate limiting by sending a key longer than `MaxKeySize`.
**Learning:** Distinguish between "system errors" (DB down) and "input errors" (invalid key). Input errors must fail closed (block request) to prevent bypasses, while system errors might fail open for availability.
**Prevention:** Check specific error types in middleware. If `errors.Is(err, store.ErrKeyTooLong)`, return 431 (Request Header Fields Too Large). For other errors, log and potentially allow.

## 2024-10-24 - Fail Open on Storage Capacity
**Vulnerability:** `RateLimitMiddleware` failed open (allowed requests) when the store was full (`ErrStoreFull`). The rate limit algorithms (`TokenBucket`, `SlidingWindow`) ignored the error when saving state, allowing attackers to bypass rate limits by filling the store, as the limit counters were never persisted.
**Learning:** Capacity errors (like storage full) must be treated as "Fail Closed" security events in rate limiters. If the system cannot record that a request happened, it cannot safely allow it.
**Prevention:** Algorithms now propagate storage errors. Middleware explicitly checks for `store.ErrStoreFull` and returns 503 Service Unavailable, preventing bypass during DoS conditions while maintaining fail-open for other system errors.

## 2024-10-25 - Inconsistent Fail Open Logic in Router
**Vulnerability:** While `RateLimitMiddleware` was patched to fail closed on `ErrStoreFull` and `ErrKeyTooLong`, the `Router` middleware handler still failed open on all errors. This allowed attackers to bypass rate limits specifically on routed endpoints by triggering storage or key length errors.
**Learning:** When multiple middleware components share logic (like handling rate limit results), security fixes must be applied to all of them. Inconsistent error handling across similar components creates hidden bypass vectors.
**Prevention:** Ensure that all entry points (middleware, router, etc.) that enforce a security control handle failure modes consistently. Prefer shared helper functions for error handling logic to avoid duplication and drift.
