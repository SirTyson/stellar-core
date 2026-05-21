# H001 (self-rejected): Replace ModuleCache Mutex<BTreeMap> with Lock-Free Map to Reduce Worker Contention

**Date**: 2026-05-21
**Subsystem**: soroban-env (vm/module_cache)
**Severity**: Low (rejected — below objective threshold)
**Impact**: parallel worker mutex contention during VM instantiation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When 8 parallel cluster workers concurrently instantiate Soroban VMs (each
invocation looks up the `ParsedModule` for its contract hash), the lookup
should not serialize across workers. The expected implementation:
`ModuleCacheMap` uses a lock-free or read-optimized concurrent map (e.g.
`parking_lot::RwLock<BTreeMap>` for read-dominant workloads, or `dashmap`
for sharded concurrency) so that the 8-way `instantiate_wasmi` path
proceeds in parallel without blocking on a global `std::sync::Mutex`.

## Mechanism

`ModuleCacheMap` (`vm/module_cache.rs:46`) is
`Arc<Mutex<BTreeMap<Hash, Arc<ParsedModule>>>>`. Every call to
`ModuleCache::get(hash)` (used by `Vm::instantiate_wasmi` to retrieve the
parsed module for a contract before building a fresh wasmi `Store`)
acquires the global mutex. With 8 worker threads each doing ~290
instantiations per ledger (20,389 total / 8 = ~2550 per worker), and the
critical-section work being `BTreeMap::get + Arc::clone` (sub-100ns), the
mutex acquire+release overhead and any actual contention waiting time
contribute to apply-path latency. The hypothesis: contention plus
acquire overhead is large enough to be worth eliminating.

## Trigger

Run the soroswap apply-load benchmark with `NUM_CLUSTERS=8`. The
benchmark's `applyLedger` zone executes 8 parallel cluster workers, each
of which invokes `Vm::instantiate_wasmi` multiple times per operation.
Each instantiation hits the `ModuleCacheMap::get` mutex.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:46-83`
  (`ModuleCacheMap`) — the `Mutex<BTreeMap>` wrapper.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs::get_module`
  (and call sites in `Vm::instantiate_wasmi`) — where the lock is acquired
  per VM creation.

## Evidence

- 20,389 `Vm::instantiate_wasmi - instantiate` calls in the soroswap
  trace, each requires a `ModuleCacheMap::get` (which locks the mutex).
- The mutex is shared across all 8 worker threads via `Arc<Mutex<...>>`.
- The shared `wasmi_engine` field (line 22) is known to use internal
  `RwLock::read` (per fail summary meta-pattern), not the same mutex.

## Anti-Evidence

- The critical section is *extremely* short: `BTreeMap::get` is O(log n)
  with n ≤ ~thousands of cached modules in this benchmark (more
  realistically ~50-100), so the in-lock work is sub-100ns. The Mutex
  acquire (uncontended) is ~25ns. Even with worst-case contention across
  8 threads, the *waiting* time per acquire is bounded.
- 20,389 calls × ~100ns (uncontended + contention) ≈ 2ms aggregate
  Tracy-time across all threads = ~0.25ms wall-time with 8 workers
  ≈ 0.1% of 272.9ms baseline.
- Even pathologically assuming 1µs per call (40× the uncontended
  estimate) gives 20ms aggregate / 8 = 2.5ms wall = ~0.9% — still below
  the objective's 1% noise floor and well below the Medium threshold.
- The Tracy trace does not show a distinct "ModuleCache lock wait" zone,
  and the `Vm::instantiate_wasmi` self-time of 1315M ns / 20,389 calls =
  64µs per call is dominated by wasmi `Module::instantiate` (linker
  resolution + InstancePre construction + check_contract_imports), not by
  the cache lookup that precedes it.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (ModuleCache shape never
explicitly proposed as a target; the closest prior investigation
"Shard module cache engines" targeted the wasmi `Engine` lock, not the
`ModuleCacheMap` BTreeMap mutex).

### Why It Failed

The critical section is too short (sub-100ns) for mutex contention to
add up to a Medium-class (3-10%) improvement at 8-way concurrency. Even
pessimistic estimates put the total contention cost at well under 1% of
apply time, below the objective's noise floor. The hypothesis fails the
SEVERITY_SCALE Medium threshold defined for this objective.

### Lesson Learned

A lock-contention hypothesis is only viable when the *critical section*
itself does meaningful work, OR the number of acquires per worker is
extreme. A short critical section + modest acquire count gives total
contention costs that vanish below benchmark noise no matter how clever
the lock-free replacement. Future hypothesis generation should
back-of-envelope the contention floor (acquires × worst-case wait) before
proposing this class of optimization.
