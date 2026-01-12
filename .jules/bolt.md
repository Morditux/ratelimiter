## 2024-05-23 - Sharded Locking for High Concurrency
**Learning:** Global mutexes in both the algorithm layer (`TokenBucket`) and storage layer (`MemoryStore`) created a double bottleneck. Optimizing only one layer was insufficient because the other layer would still serialize execution. Optimizing `TokenBucket` alone yielded no results because `MemoryStore` writes serialized everything. Optimizing `MemoryStore` alone would have been useless because `TokenBucket`'s global lock was the outer gate.
**Action:** When optimizing layered systems with locks, identify if locks are nested or sequential. If sequential (like Algorithm -> Store), you must optimize *both* (or the outer one if it completely wraps the inner one). In this case, `TokenBucket` wrapped `MemoryStore` calls in a critical section, so `TokenBucket` had to be sharded. But `TokenBucket` operations involved `MemoryStore` writes, so `MemoryStore` also had to be sharded to allow concurrent writes.

## 2024-05-24 - SlidingWindow Global Lock Removal
**Learning:** Even if the underlying `MemoryStore` is optimized with sharded locks, a global lock in the `SlidingWindow` algorithm layer serialized all requests, negating the store's concurrency benefits. Benchmark showed `SlidingWindow` (global lock) was significantly slower (1020ns/op) than `TokenBucket` (sharded locks, 303ns/op) under high concurrency with multiple keys.
**Action:** Always check the entire call stack for locks. If a lower layer is optimized for concurrency, ensure the upper layer doesn't serialize access unnecessarily. Implementing sharded locks in `SlidingWindow` (mirroring `TokenBucket`'s strategy) improved performance by ~3x (347ns/op) for concurrent workloads.

## 2024-05-24 - Reduce Hot Path Allocations
**Learning:** In the `TokenBucket` implementation, helper methods `getState` and `saveState` were both calling `storeKey` (which allocates a new string) separately. This resulted in redundant allocations inside the hot path `AllowN`.
**Action:** Hoist stateless calculations like key generation out of helper methods and repetitive loops. By calculating `storeKey` once in `AllowN` and passing it down, we reduced allocations from 3 to 2 per operation and improved throughput by ~10%.

## 2024-05-24 - TokenBucket Write Optimization
**Learning:** `TokenBucket` was persisting state to storage even when requests were blocked. This was mathematically unnecessary because the state update (time passing) is deterministic and would be recalculated identically on the next request. This unnecessary write created significant overhead (locking + memory) during high-load scenarios like DDOS attacks.
**Action:** In rate limiting algorithms, analyze if state updates on failure paths are strictly necessary. If the next calculation can derive the same state from current time + old state, skip the write. This reduced blocked request latency by ~50% (516ns -> 270ns) and eliminated allocations.
