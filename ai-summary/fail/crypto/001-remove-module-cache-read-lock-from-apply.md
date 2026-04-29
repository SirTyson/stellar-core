# H001: Remove shared module-cache read lock from apply-time VM instantiation

**Date**: 2026-04-29
**Subsystem**: crypto, rust, soroban-env
**Severity**: Medium
**Impact**: Apply-time reduction on soroswap by removing a hidden cross-cluster serialization point on cached Wasm-module lookup
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During parallel Soroban apply, cached Wasm module lookup should be a read-only operation that returns an immutable `Arc<ParsedModule>` without serializing all worker threads on one shared mutex. Module cache reads should not affect ledger determinism: every worker should observe the same per-ledger cache snapshot, and cache eviction or population should remain outside the transaction execution order.

## Mechanism

`ModuleCacheMap` stores modules in `Arc<Mutex<BTreeMap<Hash, Arc<ParsedModule>>>>`, and every cache hit in `Host::instantiate_vm` calls `cache.get_module(wasm_hash)`, which locks that shared map before cloning the `Arc`. The Rust bridge shallow-clones `SorobanModuleCache` for parallel use, but the shallow clone shares the same underlying `ModuleCacheMap`, so the soroswap workload's 10,061 apply-time VM instantiations all contend on the same read path across `NUM_CLUSTERS` workers. Replacing the mutex-protected map with an immutable read snapshot (for example `Arc<BTreeMap<...>>` swapped only at ledger/cache maintenance boundaries, or a per-ledger/per-worker cloned read map) would make cache hits lock-free while preserving deterministic module contents for the whole ledger.

## Trigger

Run the current soroswap apply-load Tracy benchmark (`/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`) and inspect VM instantiation under `applyLedger`. Unwrap-mode analysis found all 10,061 `Vm::instantiate_wasmi - instantiate` events inside the 69 `applyLedger` windows, with 678,102,145 ns total time, and these events are launched from the parallel Soroban stage workers. The module-cache lookup itself is not separately instrumented, making this a structural hypothesis: the lock sits immediately before every cache-hit instantiation and is shared by all cluster workers.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:45-83` — `ModuleCacheMap` wraps a `BTreeMap` in `Arc<Mutex<...>>`; `get` locks it for every read.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:185-194` — `ModuleCache::get_module` clones the cached `Arc<ParsedModule>` through the locked map.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — every cached Wasm contract call performs the module-cache read before VM instantiation.
- `src/rust/src/soroban_module_cache.rs:54-60` — bridge-level `SorobanModuleCache::shallow_clone` shares each protocol cache among parallel users.
- `src/ledger/LedgerManagerImpl.cpp:2537` — `applySorobanStageClustersInParallel` runs the worker clusters that converge on the shared cache.

## Evidence

The trace confirms the relevant VM-instantiation path is entirely inside `applyLedger` and frequent enough to matter: 10,061 cache-hit instantiations over a 5.774 s apply envelope. The code shows a single shared mutex on the module-cache read path despite modules being immutable after parsing and returned as `Arc<ParsedModule>`. This is a plausible Medium-tier target because lock contention in the per-call setup path can reduce effective cluster parallelism; removing the lock does not change VM execution, budget metering, contract call order, or ledger output.

## Anti-Evidence

The critical section is small (`BTreeMap::get` plus `Arc` clone), so if contention is low or the map has very few modules, lock-free reads may fall below the 3% Medium floor. The cache currently supports mutation, eviction, clear, and post-construction inserts; any snapshot design must preserve those semantics at ledger boundaries and must not allow a transaction to see different module availability than the storage footprint permits. A PoC should add Tracy instrumentation around `ModuleCacheMap::get` or compare lock-free and mutex builds before assuming the hidden contention is material.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/crypto` or `success/crypto`; cross-subsystem fail/success directories were absent
**Failed At**: reviewer

### Trace Summary

Parallel Soroban apply constructs one `ThreadParallelApplyLedgerState` per cluster, and each thread state obtains `app.getModuleCache()`, which shallow-clones the bridge cache handle while sharing the underlying protocol-specific `ModuleCache`. Each Soroban invocation passes that cache through `rust_bridge::invoke_host_function`, installs it into the `Host`, and `Host::call_contract_fn` reaches `Host::instantiate_vm` for Wasm contracts. On a cache hit, `instantiate_vm` checks storage liveness, then calls `ModuleCache::get_module`, which locks the shared `Arc<Mutex<BTreeMap<...>>>`, clones the cached `Arc<ParsedModule>`, and only then enters `Vm::from_parsed_module_and_wasmi_linker` / `Vm::instantiate_wasmi`. The lock is real and on the apply path, but it protects only a tiny read-side critical section and cache mutation is intentionally outside concurrent apply.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — launches parallel Soroban stage worker clusters with `std::async`.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — each `ThreadParallelApplyLedgerState` stores a module cache obtained via `app.getModuleCache()`.
- `src/ledger/LedgerManagerImpl.cpp:954-962` — `getModuleCache()` asserts compilation is not running during apply and returns `mApplyState.getModuleCache()->shallow_clone()`.
- `src/rust/src/soroban_module_cache.rs:54-60` and `src/rust/src/soroban_proto_any.rs:761-776` — bridge and protocol-specific shallow clones share the underlying `ModuleCache`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — operation application passes the thread-state module cache to `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:310-448` — bridge dispatch selects the protocol host module and calls the protocol-specific host invocation with the shared cache reference.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — host invocation constructs `Host`, installs the provided module cache with `set_module_cache`, and invokes the host function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-801` — Wasm contract calls retrieve the contract instance, call `instantiate_vm`, check storage liveness, and use `cache.get_module(wasm_hash)` before VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:45-83,185-194` — `ModuleCacheMap::get` locks the shared `Mutex<BTreeMap<...>>` and clones an `Arc<ParsedModule>`; `ModuleCache::get_module` clones the returned `Arc` again.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187,191-206` — the cache lookup precedes the measured wasmi store/instantiate work.
- `src/ledger/SharedModuleCacheCompiler.cpp:197-215`, `src/ledger/LedgerManagerImpl.cpp:995-1008,3432-3492` — cache rebuild, eviction, and newly-uploaded contract compilation happen in setup/writable/committing phases rather than concurrently with worker apply.

### Why It Failed

The claimed inefficiency exists, but the projected gain is below the optimize-soroswap Medium severity threshold. On the cited trace, a 3% apply-time win over 5.774 s requires about 173 ms total savings; across 10,061 cache-hit lookups, that means the lock-free design would need to remove roughly 17 microseconds from every lookup on the apply critical path. The code inside the lock is only `BTreeMap::get` plus `Arc` cloning, and cache mutation is not running concurrently during apply, so the expected cost is orders of magnitude smaller than the threshold unless there is measured mutex wait time not provided by the hypothesis. The observed 678 ms VM-instantiation total is also downstream of the lookup and consists of required wasmi store/instantiation/import-check work; removing the cache-map lock does not eliminate that dominant work.

The proposed immutable snapshot design is plausibly correct in principle, but it would need to preserve `compile`, `evict_contract_code`, `clear`, shallow-clone sharing, protocol-specific caches, and cache accounting across setup/writable/committing phases. That engineering risk is not justified by an uninstrumented read-side critical section whose call rate is only about 1.7k lookups/second over the trace. Under this objective's severity rule, a real but likely Low/sub-1% cleanup must be rejected rather than downgraded.

### Lesson Learned

Do not promote a structural shared-lock hypothesis to Medium severity without measuring lock wait or isolating the locked critical section. A mutex in a parallel apply path is worth investigating, but when the critical section is a tiny read-only map lookup and the workload performs only thousands of lookups per second, the severity projection must be bounded by per-call savings rather than by the much larger downstream VM-instantiation zone.
