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

## 2024-10-24 - Fail Closed on Store Capacity
**Vulnerability:** When the `MemoryStore` reached capacity (`MaxEntries`), it returned `ErrStoreFull`. The `TokenBucket` and `SlidingWindow` algorithms ignored this error when saving state, allowing requests to proceed without decrementing the quota. This allowed an attacker to bypass rate limits by filling the store with random keys.
**Learning:** Rate limiting algorithms must check for storage errors. If the state cannot be persisted (e.g., tokens consumed), the request must be denied to prevent unauthorized usage (Fail Closed).
**Prevention:** Modified `saveState` to return errors and updated `Allow` to return `false` if saving fails. Updated middleware to handle `ErrStoreFull` by returning 503 Service Unavailable.
