# H001: Shard Soroban module-cache engines per apply worker

**Date**: 2026-05-23
**Subsystem**: transaction-ledger, soroban-env
**Severity**: High
**Impact**: Soroswap apply-time reduction by removing shared Wasmi engine/cache contention from parallel contract execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Parallel Soroban apply should execute the same cached Wasm modules with identical imports, metering, traps, diagnostics, storage effects, and deterministic output, while allowing independent clusters to run without contending on a single shared Wasmi engine/cache object. Any module-cache sharding must be bounded by the configured cluster parallelism and must preserve the same cache contents across protocol upgrades, evictions, and newly uploaded contracts.

## Mechanism

The current apply path gives each `ThreadParallelApplyLedgerState` a shallow clone of the application module cache (`src/transactions/ParallelApplyUtils.cpp:988-1001`). `LedgerManagerImpl::getModuleCache` also returns `mApplyState.getModuleCache()->shallow_clone()` during apply (`src/ledger/LedgerManagerImpl.cpp:954-961`). On the Rust side, the protocol-specific shallow clone explicitly points to the same underlying `ModuleCache` and the same associated `Engine` (`src/rust/src/soroban_proto_any.rs:761-776`), while `ModuleCache` documents that parsed modules share a `wasmi::Engine` and that each engine is locked during execution (`src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24`).

For soroswap, every cluster worker repeatedly invokes the same hot router/pair modules through this shared cache. Maintaining a small fixed set of per-worker/per-cluster module caches with separately compiled `wasmi::Engine`/`Linker` instances, synchronized only at cache rebuild/eviction/upload boundaries, should preserve deterministic Wasm semantics while reducing shared-engine or module-map contention during `Host::invoke_function`. The design must cap shards at `LEDGER_CLOSE_WORKER_THREADS` / `NUM_CLUSTERS`, not hardware concurrency.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with Tracy enabled. The trigger is a parallel Soroban stage with multiple clusters, each constructing hosts from `ThreadParallelApplyLedgerState::getModuleCache()` and repeatedly calling cached Wasm contracts. All workers use shallow clones that refer back to the same Rust `ModuleCache` and `wasmi::Engine`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:954-961` — apply-time module cache accessor returns a shallow clone of the single apply-state cache.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — each thread state stores a cloned module cache for worker execution.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1279-1282` — host invocation passes the thread state's module cache into Rust.
- `src/rust/src/soroban_proto_any.rs:761-776` — protocol-specific shallow clone shares the same underlying `ModuleCache` and `Engine`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` — `ModuleCache` structure and comment describing shared parsed modules, linker, and engine locking.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-802` — cache-hit path retrieves parsed modules from the shared cache before VM instantiation.

## Evidence

The current trace from `ai-summary/CURRENT_STATE.md` is `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`. Timestamp filtering confirms the relevant work is under `applyLedger`: `applySorobanStageClustersInParallel` accounts for 2,748,978,969 ns inside apply, and `Host::invoke_function` accounts for 8,244,655,069 ns of aggregate worker time inside the same apply windows. The source-level cache clone comments show worker clones share one engine/cache object, so contention or engine-internal locking can directly reduce the effective parallelism of the dominant Soroban worker phase.

This is distinct from prior rejected VM-instantiation and wasmi-dispatch hypotheses: it does not attempt to reuse `InstancePre`, cache VM instances, quicken bytecode, or replace the interpreter. It keeps the same parsed/compiled module semantics and targets cross-worker sharing/locking in the apply execution topology.

## Anti-Evidence

The trace does not directly expose Wasmi engine lock wait time, so the reviewer should add narrow lock/engine contention instrumentation before implementing the full sharded-cache design. Deep per-worker caches increase memory and rebuild/eviction cost; if Wasmi execution is already mostly lock-free, the extra cache footprint may regress locality. Cache updates from `addAnyContractsToModuleCache`, `evictFromModuleCache`, and protocol rebuilds must update all shards deterministically before any worker can observe them.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The close-ledger path creates a `ThreadParallelApplyLedgerState` per Soroban cluster, each state obtains `app.getModuleCache()`, and `LedgerManagerImpl::getModuleCache` returns a shallow clone of the single apply-state `SorobanModuleCache`. That cache clone is passed through `InvokeHostFunctionParallelApplyHelper` into `rust_bridge::invoke_host_function`, then into the p26 host, where `Host::instantiate_vm` looks up the cached parsed module and instantiates a fresh `Vm` using the shared cached `wasmi::Linker`. However, the pinned wasmi engine execution path does not serialize all workers on an exclusive engine lock: it holds a shared `RwLock` read guard over immutable engine resources while executing and only briefly locks the reusable stack pool before and after execution.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2574` — `applySorobanStageClustersInParallel` constructs one `ThreadParallelApplyLedgerState` per cluster, launches workers with `std::async`, and waits on all futures, so worker-local module-cache behavior is on the apply critical path.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — each thread state stores `mModuleCache(app.getModuleCache())`.
- `src/ledger/LedgerManagerImpl.cpp:954-961` — `getModuleCache` asserts no compilation is running during apply and returns `mApplyState.getModuleCache()->shallow_clone()`.
- `src/rust/src/soroban_module_cache.rs:54-60` and `src/rust/src/soroban_proto_any.rs:761-776` — shallow clones copy protocol-specific caches that point to the same underlying `ModuleCache` and associated `Engine`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585,1270-1282,1358-1377` — parallel invoke-host-function apply passes the thread state's module cache through the C++ helper into the Rust bridge.
- `src/rust/src/soroban_proto_any.rs:391-448` and `src/rust/src/soroban_proto_all.rs:95-129` — the Rust bridge dispatches to p26 and passes `Some(module_cache.p26_cache.module_cache.clone())` into the host.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — every invocation builds the host, installs the optional module cache, and calls `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-802` — the cache-hit path checks storage presence, calls `cache.get_module`, and instantiates from the cached parsed module and cached linker.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:45-83,185-203` — the shared module map is protected by a mutex, but `get_module` only locks long enough for a BTreeMap lookup and `Arc` clone.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-218` — cached-module instantiation creates a fresh store and instance from the cached module/linker for each invocation.
- `~/.cargo/git/checkouts/wasmi-5879a40047342411/bf3b756/crates/wasmi/src/engine/mod.rs:322-465` — wasmi `EngineInner::execute_func` holds `self.res.read()` during execution, not an exclusive write lock, and only locks `self.stacks` briefly for stack reuse/recycle.

### Why It Failed

The claimed bottleneck is an exclusive shared-engine execution lock, but the actual wasmi path uses a shared `RwLock` read guard for immutable engine resources during execution, allowing concurrent readers. The only exclusive locks on the traced path are short critical sections: the Soroban module-map mutex during cache lookup, the wasmi stack-pool mutex before and after execution, and engine write locks used during module translation/initialization outside the apply execution window. Sharding engines would duplicate compiled module state and complicate rebuild/eviction/upload synchronization while removing only short lookup/reuse critical sections; the provided `Host::invoke_function` aggregate worker time does not isolate lock wait and mostly covers real VM/host execution work, so the projected Medium/High soroswap apply-time reduction is unsupported and the stated mechanism is wrong.

### Lesson Learned

Comments saying an engine is "locked during execution" must be checked against the concrete lock mode and hold time. For this wasmi version, execution holds a shared read guard so module-cache sharding should not be promoted unless narrow instrumentation first shows measurable contention in the module-map mutex, stack-pool mutex, or `RwLock` acquisition itself.
