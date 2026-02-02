## 2024-05-23 - Sharded Locking for High Concurrency
**Learning:** Global mutexes in both the algorithm layer (`TokenBucket`) and storage layer (`MemoryStore`) created a double bottleneck. Optimizing only one layer was insufficient because the other layer would still serialize execution. Optimizing `TokenBucket` alone yielded no results because `MemoryStore` writes serialized everything. Optimizing `MemoryStore` alone would have been useless because `TokenBucket`'s global lock was the outer gate.
**Action:** When optimizing layered systems with locks, identify if locks are nested or sequential. If sequential (like Algorithm -> Store), you must optimize *both* (or the outer one if it completely wraps the inner one). In this case, `TokenBucket` wrapped `MemoryStore` calls in a critical section, so `TokenBucket` had to be sharded. But `TokenBucket` operations involved `MemoryStore` writes, so `MemoryStore` also had to be sharded to allow concurrent writes.

## 2024-05-24 - SlidingWindow Global Lock Removal
**Learning:** Even if the underlying `MemoryStore` is optimized with sharded locks, a global lock in the `SlidingWindow` algorithm layer serialized all requests, negating the store's concurrency benefits. Benchmark showed `SlidingWindow` (global lock) was significantly slower (1020ns/op) than `TokenBucket` (sharded locks, 303ns/op) under high concurrency with multiple keys.
**Action:** Always check the entire call stack for locks. If a lower layer is optimized for concurrency, ensure the upper layer doesn't serialize access unnecessarily. Implementing sharded locks in `SlidingWindow` (mirroring `TokenBucket`'s strategy) improved performance by ~3x (347ns/op) for concurrent workloads.

## 2024-05-24 - Reduce Hot Path Allocations
**Learning:** In the `TokenBucket` implementation, helper methods `getState` and `saveState` were both calling `storeKey` (which allocates a new string) separately. This resulted in redundant allocations inside the hot path `AllowN`.
**Action:** Hoist stateless calculations like key generation out of helper methods and repetitive loops. By calculating `storeKey` once in `AllowN` and passing it down, we reduced allocations from 3 to 2 per operation and improved throughput by ~10%.

## 2024-05-24 - Pre-calculate Invariants
**Learning:** In high-frequency hot paths like rate limiting checks (AllowN), repeated floating point divisions (e.g., rate / window) add measurable overhead. Pre-calculating these as multiplicative inverses or rates during initialization yields a consistent 2-5% CPU reduction.
**Action:** Identify loop-invariant calculations in hot paths. Move them to struct initialization and store them as fields (e.g., refillRate, invWindow).

## 2024-05-25 - Zero-Allocation IP Extraction
**Learning:** The standard library's `net.SplitHostPort` is robust but allocates strings on every call. In high-throughput middleware hot paths (like key extraction), replacing it with manual string slicing (using `IndexByte`/`LastIndexByte`) yielded a ~2-4x speedup (25ns -> 6ns) and eliminated allocations entirely for common IPv4/IPv6 cases.
**Action:** For string parsing in hot paths where input format is predictable (like `RemoteAddr` from `http.Server`), prefer direct string manipulation/slicing over generic standard library parsers to avoid allocations.

## 2024-05-25 - Zero-Allocation State Updates
**Learning:** Storing state structs by value in `MemoryStore` (via `interface{}`) causes heap allocation on every update because the struct must be boxed. By changing the internal state management to use pointers (`*tokenBucketState`), we reuse the heap-allocated struct across updates (since `MemoryStore` retains the pointer), eliminating allocations in the hot path.
**Action:** When using generic stores (accepting `interface{}`) for frequent updates of mutable state, prefer storing pointers to structs rather than values. This avoids repeated boxing allocations, provided the storage backend supports it (e.g. in-memory) or the serializer handles pointers correctly.

## 2024-05-25 - Safe In-Place Mutation with Sharded Locks
**Learning:** Extending the zero-allocation pointer pattern to `SlidingWindow` raised concerns about data races since multiple goroutines could theoretically access the same pointer. However, because the algorithm layer uses sharded locks (`sw.mu[idx]`) that wrap the entire read-modify-write cycle (including `getState`), in-place mutation of the shared state pointer is thread-safe.
**Action:** When implementing zero-allocation patterns that rely on shared mutable state, explicitly document the locking strategy that guarantees safety. This prevents false positives in code reviews and ensures future maintainers understand why the "unsafe" looking mutation is actually safe.

## 2024-05-25 - Conditional Path Cleaning
**Learning:** `path.Clean` is expensive because it often allocates a new string. In middleware hot paths, blindly calling it for features that might be disabled (like `ExcludePaths`) imposes a penalty on all requests.
**Action:** Guard expensive normalization or parsing logic with checks for the feature's configuration (e.g., `if len(options.ExcludePaths) > 0`). This saved ~170ns/op and 1 allocation per request in the default case.

## 2025-05-26 - Optimized Hashing for Sharding
**Learning:** In the `getLock` method, which is called on every request, initializing a `maphash.Hash` struct (even on the stack) and calling its methods introduced measurable overhead. Replacing it with `maphash.String` (available since Go 1.19) reduced this overhead, resulting in a ~3-6% throughput improvement in the rate limiter's hot path.
**Action:** Prefer `maphash.String` or `maphash.Bytes` over creating a new `maphash.Hash` instance when hashing a single string or byte slice in tight loops or hot paths, as it avoids the initialization cost of the Hash struct.

## 2025-05-26 - Optimized IP Parsing with netip
**Learning:** `net.ParseIP` (returning `net.IP` slice) and subsequent `.String()` call incurs 2 allocations. `net/netip.ParseAddr` (returning `netip.Addr` value) with `.String()` incurs only 1 allocation and is ~20% faster (96ns vs 121ns) for standard IPv4 addresses.
**Action:** Prefer `net/netip` over `net` for IP parsing and validation in hot paths (like middleware key extraction). When replacing `net.ParseIP`, remember to use `addr.Unmap()` to maintain backward compatibility for IPv4-mapped IPv6 addresses (e.g., `::ffff:1.2.3.4` -> `1.2.3.4`).

## 2025-05-27 - Hoisting Path Cleaning
**Learning:** `path.Clean` is CPU-intensive even when the path is already clean, as it must traverse the string to verify it. In a router loop matching against multiple endpoints, calling `path.Clean` inside the loop (N times) instead of once upfront caused a ~15% throughput penalty.
**Action:** Always hoist stateless normalization logic (like `path.Clean`) out of loops. Do it once per request, not once per candidate match.

## 2025-05-27 - strconv vs fmt.Sprintf for Headers
**Learning:** Using `fmt.Sprintf` to format integers for HTTP headers (`X-RateLimit-*`) is convenient but slower and more alloc-heavy than `strconv.Itoa` / `strconv.FormatInt`. Switching to `strconv` reduced allocations by ~2 per request and improved latency by ~8% in rate-limited scenarios.
**Action:** Prefer `strconv` functions over `fmt.Sprintf` for simple integer-to-string conversions, especially in middleware hot paths.
