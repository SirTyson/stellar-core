# H001: Shard Soroban module-cache engines by apply cluster

**Date**: 2026-05-05
**Subsystem**: soroban-env, rust bridge
**Severity**: Medium
**Impact**: apply-time (parallel Soroban Wasm instantiation)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Parallel Soroban apply workers should be able to instantiate cached Wasm
modules concurrently without contending on a single shared `wasmi::Engine`.
For a soroswap ledger with `NUM_CLUSTERS=8`, each worker cluster should use a
deterministically selected cache shard, with no more than `NUM_CLUSTERS`
engines/linkers, and all shards should contain byte-identical parsed modules
for the same contract code hashes.

## Mechanism

`SorobanModuleCache::shallow_clone` currently preserves shared ownership of the
same protocol-specific `ModuleCache`, and `ProtocolSpecificModuleCache` says
the clone points to the same underlying module map and the same associated
`Engine`. The p26 `ModuleCache` also documents that each wasmi `Engine` is
locked during execution, while `Vm::instantiate_wasmi` calls
`wasmi_linker.instantiate(&mut store, &parsed_module.wasmi_module)` for every
contract frame. If the shared engine or linker has internal locking in this
path, the 8 apply workers serialize part of the hottest Wasm-instantiation
phase and amplify `applySorobanStageClustersInParallel` wait time.

The optimization would build a bounded shard set of independent
`ModuleCache`s for the current protocol, one per configured apply cluster
rather than per hardware thread. Each shard would own its own `wasmi::Engine`,
`wasmi::Linker`, and per-engine `ParsedModule`s for the same code hashes; the
C++ apply path would pass the shard corresponding to the deterministic cluster
index. Observable ledger output remains deterministic because each shard
contains the same Wasm bytes and cost inputs, and worker assignment is already
deterministic under `NUM_CLUSTERS`.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with
the module cache enabled. The trace shows repeated concurrent invocations of
the same cached pool/SAC-supporting Wasm modules during
`applySorobanStageClustersInParallel`; each contract frame reaches
`Vm::instantiate_wasmi - instantiate`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24` —
  `ModuleCache` owns one `wasmi::Engine`, one maximal linker, and the parsed
  module map; comments state the engine is locked during execution.
- `src/rust/src/soroban_proto_any.rs:761-776` — protocol-specific
  `shallow_clone` keeps the same underlying `ModuleCache` and same engine.
- `src/rust/src/soroban_module_cache.rs:54-60` — outer
  `SorobanModuleCache::shallow_clone` clones each protocol cache for use from
  C++-launched threads.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` —
  `Vm::instantiate_wasmi`, especially the `wasmi_linker.instantiate` call.
- `src/ledger/LedgerManagerImpl.cpp:2537` — `applySorobanStageClustersInParallel`
  is the parallel apply parent where worker wait time is visible.

## Evidence

The current soroswap Tracy trace reports `Vm::instantiate_wasmi - instantiate`
self-time of 1,315,387,452 ns across 20,389 calls. A filtered unwrap check
confirmed all 20,389 events are inside `applyLedger` windows, with
1,317,542,205 ns of event duration in-scope. The parent
`applySorobanStageClustersInParallel` zone has 3,455,290,270 ns self-time in
the same trace, consistent with worker wait/tail effects dominating the
parallel stage.

The source-level structure supports a contention theory: all shallow clones
share the same engine/linker, and the cache documentation explicitly calls out
engine locking during execution. Sharding would attack a dominant, repeated
apply-path phase without changing contract execution order within a cluster or
exceeding `NUM_CLUSTERS` parallelism.

## Anti-Evidence

Prior rejected hypotheses show that store-local wasmi state and `InstancePre`
cannot be reused safely; this hypothesis must not try to reset or reuse
`wasmi::Store`/`Instance`. If wasmi's engine lock is only taken for mutation or
is fine-grained enough that instantiate calls are not contending, sharding will
mostly add memory and compile-time overhead and may not clear the 3% Medium
floor. Cache warmup, eviction, memory accounting, and protocol-upgrade handling
would also need to update every shard consistently.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The parallel apply path gives each cluster a shallow-cloned `SorobanModuleCache`, and those clones do share the same protocol-specific `ModuleCache`, `wasmi::Engine`, maximal `Linker`, and parsed module map. On a cache hit, `Host::instantiate_vm` retrieves the parsed module and calls `Vm::from_parsed_module_and_wasmi_linker`, which creates a fresh per-invocation `Store` and calls `Linker::instantiate`. Tracing into the pinned `soroban-wasmi` source shows that this instantiate path resolves imports and allocates `Func`, `Instance`, memory/table/global state in the per-call `Store`; the shared engine lock involved in type/resource access is an `RwLock` read guard, not an exclusive lock that serializes the 8 apply workers. Sharding engines would duplicate parsed modules and linkers, but it does not remove the dominant mandatory per-store instantiation work and has no source-level basis for a Medium apply-time improvement.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` launches one async worker per stage cluster and later waits on the futures.
- `src/transactions/ParallelApplyUtils.cpp:988-996` — each `ThreadParallelApplyLedgerState` obtains `mModuleCache(app.getModuleCache())`, so each cluster receives a shallow clone of the apply-state module cache.
- `src/ledger/LedgerManagerImpl.cpp:954-962` — `getModuleCache` asserts no compilation is running and returns `mApplyState.getModuleCache()->shallow_clone()`.
- `src/rust/src/soroban_module_cache.rs:54-60` and `src/rust/src/soroban_proto_any.rs:761-776` — shallow clones preserve the same underlying protocol `ModuleCache`, map, and engine.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:15-24,45-83,189-203` — `ModuleCache` owns the engine/linker and protects only its parsed-module map with a mutex; cache lookup clones an `Arc<ParsedModule>` and releases the map lock before instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cache-hit VM construction checks storage, gets the cached parsed module, and passes `&cache.wasmi_linker` to `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` creates a new `wasmi::Store`, charges instantiation cost, checks imports, calls `wasmi_linker.instantiate`, and finishes the `InstancePre` with `ensure_no_start`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/linker.rs:646-658,670-702` — `Linker::instantiate` iterates module imports, looks up immutable linker definitions, converts host-function definitions into per-store `Func`s, and then calls `Module::instantiate`.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/module/instantiate/mod.rs:49-78,160-181` — module instantiation allocates a fresh instance and Wasm function entities in the target store; this work remains even with an independent engine shard.
- `/home/garand/.cargo/git/checkouts/wasmi-301e6db337b3b2df/0ed3f3d/crates/wasmi/src/engine/mod.rs:322-335,391-438,449-465` — the shared engine uses an internal `RwLock<EngineResources>`; parsing/module additions take write access, while type resolution and execution take read access that permits concurrent readers, plus a short stack-pool mutex for stack reuse.

### Why It Failed

The central contention claim is not supported by the traced implementation. The module-cache comment that the engine is "locked during execution" refers to protecting shared engine resources so new modules cannot be added while execution holds read access; it does not mean cached-module instantiation is serialized behind an exclusive engine lock. `Linker::instantiate` is mostly immutable linker lookup plus mandatory per-store allocation of host functions, Wasm functions, instance state, memories, tables, globals, and data/element initialization. A shard-per-cluster design would avoid sharing a few read-lock/cacheline accesses and the brief module-map mutex lookup, but those are not the 1.3s Tracy `instantiate` zone and cannot credibly clear the objective's 3% Medium floor. This is also consistent with the existing rejected minimal-linker/import-resolution investigations: trimming linker/import overhead leaves the same per-store allocations and instantiation work.

### Lesson Learned

Do not infer serialization from the presence of a shared engine or a "locked during execution" comment without checking lock mode and scope. For `soroban-wasmi`, the cacheable parsed module is engine-owned, but the hot instantiation path is dominated by per-store construction; engine sharding needs direct lock-wait evidence before it can be promoted as a Medium apply-time optimization.
