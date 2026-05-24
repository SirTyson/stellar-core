# H076: SorobanModuleCache `shallow_clone` Per-Worker FFI Cost Is Sub-Threshold

**Date**: 2026-05-24
**Subsystem**: crypto / rust
**Severity**: Low
**Impact**: Rust-bridge per-worker module-cache handle clone allocation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

If per-worker `SorobanModuleCache` shallow_clone calls were a Medium-tier soroswap apply bottleneck, the apply path would repeatedly cross the cxx FFI to allocate a fresh `Box<SorobanModuleCache>` containing four protocol-specific cache handles, returning it to C++ each time a worker thread or invocation entry needs a module-cache reference. Optimizing this — e.g., by handing each worker a borrowed reference (`&SorobanModuleCache`) instead of an owned `Box`, or by caching the per-worker box across ledger boundaries — should reduce `applyLedger` time without changing module-cache semantics or compilation behavior.

## Mechanism

`LedgerManagerImpl::getModuleCache()` (`src/ledger/LedgerManagerImpl.cpp:954-962`) returns `mApplyState.getModuleCache()->shallow_clone()`, which crosses the FFI into `SorobanModuleCache::shallow_clone` (`src/rust/src/soroban_module_cache.rs:54-61`). That allocates a new `Box<SorobanModuleCache>` and, for each of `p23_cache`, `p24_cache`, `p25_cache`, `p26_cache`, calls `ProtocolSpecificModuleCache::shallow_clone` (`src/rust/src/soroban_proto_any.rs:770-776`) which performs `self.module_cache.clone()` (an Arc/Rc bump on the underlying soroban-env-host cache) and creates a fresh `AtomicU64` mem-bytes counter. The end-to-end FFI roundtrip is at most a handful of small heap allocations + four refcount bumps per call.

The candidate optimization would either (a) replace `getModuleCache()` with a borrowed reference path so workers can use the parent box directly, or (b) cache the cloned box across ledgers on the worker state.

## Trigger

Run the protocol-27 soroswap apply-load benchmark with the canonical parallel-apply configuration (`APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS` = 8). Each `ThreadParallelApplyLedgerState` construction at `src/transactions/ParallelApplyUtils.cpp:995` calls `app.getModuleCache()`, which fires `shallow_clone`. Workers are recreated per-ledger, so the call happens 8× per ledger plus once per pre-V23 host invocation at `src/transactions/InvokeHostFunctionOpFrame.cpp:1342` (zero hits under p26 soroswap, since it uses the parallel path).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:954-962` — `getModuleCache()` calls `shallow_clone()` and returns by value.
- `src/transactions/ParallelApplyUtils.cpp:995` — `mModuleCache(app.getModuleCache())` invoked at each `ThreadParallelApplyLedgerState` construction.
- `src/rust/src/soroban_module_cache.rs:54-61` — `SorobanModuleCache::shallow_clone` allocates a new outer Box and four inner caches.
- `src/rust/src/soroban_proto_any.rs:770-776` — `ProtocolSpecificModuleCache::shallow_clone` does a single Rc/Arc clone plus an `AtomicU64::new(0)`.

## Evidence

The path is real and crosses the cxx boundary by-value (allocating an owned Box on the Rust side). Each call performs ~5 small allocations (1 outer Box + 4 protocol-specific structs) plus 4 Rc/Arc refcount bumps. There is a structural argument for either borrowing or caching the handle to avoid this work entirely.

## Anti-Evidence

The call count is bounded by parallel-worker setup: 8 worker constructions per ledger for p26 soroswap (Meta-Pattern 12 normalization does not even apply here, since this is serial setup before the parallel phase). Each call is a handful of small allocations — well under 1 µs even pessimistically. Total per-ledger cost is on the order of single-digit microseconds, fully bounded by Meta-Pattern 8 (~50ms total FFI bridge ceiling across the whole trace).

The accepted soroswap baseline is ~211 ms/ledger; the Medium floor requires ~6.3 ms/ledger savings. Eight `shallow_clone` calls per ledger × ~1 µs each = ~8 µs/ledger, which is ~0.004% of apply time — three orders of magnitude below the 1% Low floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — `shallow_clone` per-worker FFI cost was not separately recorded in `ai-summary/fail/crypto/summary.md`. The closest record (H070, `host-module-dispatch-cache-ffi`) covers per-invocation `get_host_module_for_protocol`, not per-worker `shallow_clone`.

### Why It Failed

The call happens only at parallel-worker setup (8× per ledger for p26 soroswap), not per-invocation or per-tx. Each call is a few small allocations and Rc bumps — single-digit-microsecond cost — yielding at most ~8 µs/ledger of removable work. This is bounded by Meta-Pattern 8 (FFI bridge ~50 ms total) and is roughly 1000× below the 1% Low floor on the 211 ms soroswap apply baseline.

### Lesson Learned

Per-worker setup work (rather than per-invocation or per-tx) has only 8 occurrences per ledger under the parallel-apply config. Any FFI optimization at that frequency is structurally bounded below noise even before invoking Meta-Pattern 8. Before proposing FFI handle-borrowing optimizations, count call sites against per-ledger invocation count, not aggregate work-thread count.
