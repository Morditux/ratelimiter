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

## 2024-10-26 - Memory Exhaustion via Header Bombing
**Vulnerability:** The `DefaultKeyFunc` and `TrustedIPKeyFunc` used `strings.Split` to parse the `X-Forwarded-For` header. An attacker could send a 1MB+ header filled with commas, causing the server to allocate massive string slices (8MB+ per request), leading to rapid Memory Exhaustion (DoS).
**Learning:** Avoid `strings.Split` on untrusted input when only specific elements are needed. Standard string splitting allocates a slice for *every* delimiter, which creates an amplification vector.
**Prevention:** Replaced `strings.Split` with manual iteration using `strings.IndexByte` (for first element) and a backwards loop (for trusted chain). This allows parsing arbitrary length headers with zero additional allocation.

## 2024-10-27 - Hash DoS on Sharding
**Vulnerability:** `MemoryStore`, `TokenBucket`, and `SlidingWindow` used `FNV-1a` (a non-cryptographic, unseeded hash) to map keys to shards/mutexes. An attacker could craft keys (e.g., via spoofed IPs) to target a specific shard, causing lock contention and degrading performance (Hash DoS).
**Learning:** Deterministic sharding functions without random seeds are vulnerable to collision attacks. Even if the underlying map is secure (Go maps are), the sharding layer itself can be a bottleneck if targeted.
**Prevention:** Replaced `FNV-1a` with `hash/maphash`, which provides a cryptographically secure, randomized seed per instance/process. This ensures that key-to-shard mapping is unpredictable to attackers.

## 2024-10-28 - Missing Security Headers in Error Responses
**Vulnerability:** Rate limit error responses (429) lacked basic security headers like `Content-Security-Policy` and `Referrer-Policy`. While the response body is JSON, the absence of these headers reduced defense-in-depth against potential content sniffing or context confusion attacks.
**Learning:** Security headers should be applied to *all* responses, including error pages. Defense in depth requires assuming that even simple error responses might be mishandled by some clients.
**Prevention:** Enhanced `DefaultOnLimited` to include `Content-Security-Policy: default-src 'none'`, `Referrer-Policy: no-referrer`, and `Permissions-Policy`.

## 2024-10-31 - Rate Limit Bypass via Port Rotation
**Vulnerability:** `DefaultKeyFunc` used the raw value of `X-Forwarded-For` or `X-Real-IP` as the rate limit key. If a proxy (or attacker) included a port in these headers (e.g., `1.2.3.4:12345`), the rate limiter treated it as a unique key. Attackers could bypass limits by rotating source ports for every request.
**Learning:** IP address strings from headers or `RemoteAddr` are not guaranteed to be just IPs; they often contain ports. Blindly trusting them as "unique user identifiers" allows trivial bypasses.
**Prevention:** Always canonicalize IP addresses by stripping ports and brackets before using them as keys. Implemented `stripIPPort` to enforce this normalization across all IP extraction paths.

## 2024-11-01 - Header Splitting Bypass
**Vulnerability:** `TrustedIPKeyFunc` retrieved only the first `X-Forwarded-For` header using `r.Header.Get()`, ignoring subsequent headers added by trusted proxies when header splitting occurred (e.g., via `Header.Add` instead of appending). This allowed attackers to spoof their IP by sending a fake header that shadowed the real one.
**Learning:** HTTP headers can be multi-valued. Using `Get()` (which returns only the first value) on headers like `X-Forwarded-For` that form a chain is dangerous if the chain is split across multiple header lines.
**Prevention:** Updated `TrustedIPKeyFunc` to use `r.Header.Values()` and iterate backwards through *all* header values to correctly reconstruct the trust chain, ensuring the true client IP (or last untrusted hop) is identified.

## 2024-12-05 - Storage Exhaustion via Garbage Keys
**Vulnerability:** `DefaultKeyFunc` blindly accepted arbitrary strings from `X-Forwarded-For` and `X-Real-IP` as rate limit keys. An attacker could send requests with random strings in these headers, causing the `MemoryStore` to fill up with unique garbage keys, eventually triggering `ErrStoreFull` and causing a Denial of Service for legitimate users.
**Learning:** When using external input (like headers) as keys for limited resources (storage), stricter validation is required. Trusting that input "looks like" an IP isn't enough; explicit validation ensures the keyspace is bounded to the expected domain.
**Prevention:** Added `net.ParseIP` validation to `DefaultKeyFunc`. If the extracted value is not a valid IP address, it is ignored, and the function falls back to a safer source (like `RemoteAddr`), preventing the injection of arbitrary strings into the store.
