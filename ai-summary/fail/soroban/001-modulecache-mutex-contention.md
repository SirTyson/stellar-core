# H001: ModuleCache global Mutex<BTreeMap> serializes per-invocation lookups across Soroban worker threads

**Date**: 2026-04-30
**Subsystem**: soroban
**Severity**: Medium
**Impact**: parallel-apply throughput (Soroban Vm::instantiate path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`ModuleCache::get_module(wasm_hash)` is logically a read-mostly operation
during `closeLedger`: the cache is populated once at host construction (and
on rare `uploadContractWasm` ops) and then queried by every Soroban VM
instantiation. Lookups by 8 parallel worker threads (`NUM_CLUSTERS = 8`)
during `applySorobanStageClustersInParallel` should proceed concurrently
without serialization, because they are pure reads of an immutable map for
the duration of a stage.

## Mechanism

The cache map is implemented as `ModuleCacheMap(Arc<Mutex<BTreeMap<Hash,
Arc<ParsedModule>>>>)`
(`src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:46`). Every
`get`, `contains_key`, and `insert` takes the global `Mutex` via
`lock_map()` (`module_cache.rs:54-83`). `Host::instantiate_vm`
(`host/frame.rs:787-805`) calls `cache.get_module(wasm_hash)` once per VM
instantiation. The Tracy profile records ~15374 `Vm::instantiate_wasmi`
zones across 70 ledgers (~220 per ledger) with all 8 Soroban worker
threads issuing instantiations concurrently. Because the lock is global
and held for the full BTreeMap probe + Arc clone, lookups serialize on a
single critical section; the deviation is that what should be 8-way
parallel reads becomes a single-threaded queue, inflating per-call
latency under contention and adding pure wall-clock cost to a phase that
is already on the apply critical path.

## Trigger

Run the soroswap apply-load benchmark (8 worker threads, ~2000 tx/ledger,
each tx invoking 2-4 Soroban contracts). Every contract invocation that
goes through `Host::instantiate_vm` hits the global cache mutex; the
worker threads contend on the mutex throughout
`applySorobanStageClustersInParallel`. Repro is automatic by running
`scripts/run_apply_load_matrix.py` on the soroswap workload.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:46-83` —
  `ModuleCacheMap` definition (`Arc<Mutex<BTreeMap<...>>>`) and all access
  methods take the global mutex.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:153-203` —
  `ModuleCache::get_module` / `add_module` are the only callers; reads
  vastly outnumber writes during apply.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-805` —
  `instantiate_vm` is the per-invocation caller; runs from every Soroban
  worker thread.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` —
  `applySorobanStageClustersInParallel` launches 8 concurrent
  `applyThread` workers that each drive `instantiate_vm` repeatedly.

## Evidence

- Tracy `Vm::instantiate_wasmi` is ~12% self-time of `applyLedger`'s
  Soroban subtree on the soroswap trace, with ~15374 calls across 8
  workers per run. The global mutex sits on the hot path for every one
  of those calls.
- The cache is documented as "read-mostly" and explicitly notes "There
  is no metering of cache map operations"
  (`module_cache.rs:32-43`), confirming the lock is plain
  bookkeeping with no protocol-visible semantics — its data structure
  is freely changeable.
- `Mutex<BTreeMap>` is well-known to be a poor fit for the read-heavy
  workload: parking_lot/std `Mutex` does not allow shared readers, and
  `BTreeMap::get` is slower than `HashMap::get` on `Hash` (32-byte
  contract hashes).
- `add_module` writes happen only at host construction
  (`add_stored_contracts` once per host) and in the `UploadContractWasm`
  path (rare; not on soroswap critical path). The lock can be released
  immediately on successful `Arc::clone` of the value.

## Anti-Evidence

- The trace does not separately attribute the mutex acquisition (no
  dedicated zone). Without a perf/strace experiment we cannot directly
  measure the contention component; uncontended `Mutex<BTreeMap>::get`
  is ~150-300ns. Worst case, contention multiplies per-call latency by
  the number of waiting workers (up to 8x), which would be ~2-3ms wall
  per ledger on the trace numbers — borderline Medium (~3-4% of the
  278ms median).
- Switching to `RwLock<HashMap>` requires `Hash` to implement `Hash` and
  `Eq` (it does); the change is small but lives in a vendored
  `soroban-env-host` submodule (touching p26 host requires the vendored
  copy update + observation-tests refresh per stored memory on
  observe.rs).
- The `wasmi_linker` is also held inside `ModuleCache` and may have its
  own internal locking; eliminating just the map mutex may not unlock
  full 8-way scaling if downstream wasmi state is also serialized.
  However, `wasmi::Linker` is documented as `Sync` and read-only after
  construction, so this is unlikely to dominate.
- A simpler alternative — pre-resolve all `Arc<ParsedModule>` for a
  cluster's contract hashes once at `applyThread` entry into a
  thread-local `HashMap` — would also work and avoids modifying the
  vendored submodule. PoC should compare both approaches.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; nearby failures cover a different bucket timer mutex and wasmi `InstancePre` reuse, and success entries do not target `ModuleCache` map lookup contention
**Failed At**: reviewer

### Trace Summary

The close-ledger path launches one async worker per Soroban cluster, and each worker eventually calls `InvokeHostFunctionOpFrame::doParallelApply`, crosses the C++/Rust bridge, installs the shared protocol-specific `ModuleCache` into a fresh host, and invokes the contract. For Wasm contracts, `Host::call_contract_fn` calls `instantiate_vm`, which checks storage and then calls `ModuleCache::get_module`; that read does lock a shared `Mutex<BTreeMap<Hash, Arc<ParsedModule>>>` and clone the resulting `Arc` before entering `Vm::instantiate_wasmi`. The inefficiency is real and in scope, but the removable critical section is too small and too infrequent to plausibly produce a Medium-tier soroswap apply-time reduction.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches concurrent apply workers and waits for all futures before committing stage results.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1270-1280,1358-1378` — parallel invoke-host apply creates a helper from the thread state and delegates to the common apply helper.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-584` — the helper calls `rust_bridge::invoke_host_function` with the per-thread shallow-cloned `SorobanModuleCache`.
- `src/ledger/LedgerManagerImpl.cpp:954-962` — `getModuleCache` asserts no compilation is running and returns a shallow clone for apply-time transaction execution.
- `src/rust/src/soroban_proto_all.rs:95-129` — p26 invocation passes `Some(module_cache.p26_cache.module_cache.clone())` into the p26 host, sharing the underlying cache map.
- `src/rust/src/soroban_proto_any.rs:700-776` — `ProtocolSpecificModuleCache` documents that `ModuleCache` is thread-safe through internal locking and that shallow clones share the same underlying modules.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-480` — each invocation builds a fresh `Host`, installs the supplied module cache, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-775,787-804` — Wasm contract calls instantiate a VM by first checking storage, then calling `cache.get_module(wasm_hash)`, then constructing the VM from the parsed module and linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:45-83,185-195` — `ModuleCacheMap` is an `Arc<Mutex<BTreeMap<...>>>`; `get_module` locks the map, does a lookup, and clones the `Arc<ParsedModule>`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-206` — `Vm::instantiate_wasmi` starts after the module lookup and performs the much larger store creation, cost charging, import check, linker instantiation, start check, and memory lookup.
- `src/ledger/LedgerManagerImpl.cpp:3306-3356,3468-3492` — cache mutations for new contract code occur during ledger finalization/committing, not concurrently with the parallel worker lookup phase.

### Why It Failed

This fails the optimize-soroswap severity threshold. A Medium finding must plausibly save at least 3% of apply time; even using the hypothesis's faster 278 ms median, that is about 8.3 ms per ledger, and using the current ~596 ms accepted baseline it is about 17.9 ms per ledger. With the hypothesis's own call count of roughly 220 module-cache lookups per ledger, the lock/map change would need to remove roughly 38-81 microseconds per lookup to reach Medium.

The traced critical section cannot support that projection: it is only one uncontended-or-briefly-contended Rust mutex acquisition, a `BTreeMap` probe keyed by a 32-byte hash, and an `Arc` refcount increment. The expensive `Vm::instantiate_wasmi` Tracy zone cited as evidence is not the cache lookup; it begins after `get_module` returns and is dominated by store creation, instantiation/linker work, import validation, and memory setup. Replacing the map with `RwLock<HashMap>` or pre-resolving `Arc<ParsedModule>` values could be a correct low-level cleanup, but it is at best a Low/sub-threshold optimization for this objective, and Low findings are rejected here.

### Lesson Learned

Do not infer Medium impact from the presence of a global mutex unless the measured waiting time is isolated. For short read-side critical sections, multiply the actual lookup count by a realistic per-lookup saving and compare it to the objective floor; broad VM instantiation zones cannot be attributed to cache-map contention without a dedicated lock-wait or lookup-time measurement.
