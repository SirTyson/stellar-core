# H002: Pre-resolve cluster ParsedModule Arcs at applyThread entry to remove ModuleCache lookups from per-invocation path

**Date**: 2026-04-30
**Subsystem**: soroban / parallel-apply
**Severity**: Medium
**Impact**: parallel-apply throughput (per-invocation Vm::instantiate overhead)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The set of contract Wasm hashes a cluster will invoke is fully known at
the time `applyThread` is launched: it is the union of
`ContractExecutable::Wasm(hash)` instances reachable from the contract
instances in each TxBundle's footprint within the cluster (and any
`InvokeHostFunctionOp` direct hashes). Resolving each unique hash to
its `Arc<ParsedModule>` is a deterministic, side-effect-free read.
Since soroswap re-uses a tiny set of contracts (router, pair, token
≈ 3-10 unique Wasm hashes) across thousands of invocations per ledger,
a cluster ought to perform that resolution **once per unique hash**,
not once per invocation.

## Mechanism

Today, `Host::instantiate_vm`
(`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-805`)
calls `cache.get_module(wasm_hash)` from inside the per-invocation hot
path. With ~220 invocations/ledger and 70 ledgers in the trace, that is
~15374 cache lookups, each acquiring `ModuleCacheMap`'s global mutex
(`module_cache.rs:46`) and walking a `BTreeMap`. Across 8 worker threads
the redundant per-invocation work translates to N×k duplicate `BTreeMap`
probes and N×k mutex acquisitions, where k is the number of unique
contract hashes per cluster (k ≪ N). Pre-resolving once per cluster
into a thread-local `HashMap<Hash, Arc<ParsedModule>>` and threading
that into the host (or wrapping the ModuleCache with a per-thread read
snapshot for the duration of the cluster) deviates from the current
"resolve every time" pattern and removes a serialization point that
should never have been on the per-invocation path for a deterministic,
read-only lookup.

## Trigger

Run the soroswap apply-load benchmark. During
`applySorobanStageClustersInParallel`
(`src/ledger/LedgerManagerImpl.cpp:2530-2575`), each of the 8 worker
threads enters `applyThread` and processes ~250 transactions, each
issuing 2-4 contract invocations against the same small set of contract
Wasms. Every invocation today hits the global mutex; with the
optimization, each worker performs k mutex acquisitions per cluster
(k ≈ 3-10) instead of ~750-1000.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2575` — `applyThread` entry
  point; site to compute the per-cluster contract hash set.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-660` — C++ entry
  to `invoke_host_function`; can pass a pre-warmed module map or an
  index into one.
- `src/rust/src/soroban_invoke.rs:7-38` — Rust bridge that constructs
  the Host; site to inject the pre-warmed cache snapshot.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-805` —
  `instantiate_vm` is where the lookup is performed; could be modified
  to consult the thread-local snapshot first.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:153-203` —
  `get_module` callsite to bypass.

## Evidence

- The cache map itself notes it is read-mostly and unmetered
  (`module_cache.rs:32-43`); pre-resolution preserves all
  protocol-visible semantics (still goes through the same
  `ParsedModule`, same `wasmi_linker`, same engine).
- `TxBundle` already owns rich per-tx pre-computed footprint and TTL
  cached keys (success #4 — `ParallelApplyStage.h::CachedTxFootprintKeys`),
  so the infrastructure for "compute once at cluster setup, consume in
  worker hot path" is established and extends naturally.
- A `HashMap<Hash, Arc<ParsedModule>>` lookup is ~30ns vs the current
  `Mutex<BTreeMap>::get` at ~150-300ns uncontended (and worse under
  contention). With ~15374 calls per run across 8 workers, the
  per-call savings compound into ~2-5 ms of wall time per ledger
  (~1-2% of the 278 ms soroswap median, but compounded with H001 the
  combined improvement plausibly reaches Medium).
- The set of contract hashes per cluster is bounded and small in
  practice (soroswap uses 3-10 unique Wasms across all txs); the
  pre-resolution cost is ≤k mutex acquisitions per cluster, fully
  amortized.

## Anti-Evidence

- This hypothesis overlaps with H001 (replacing the cache mutex with
  RwLock). If H001 is applied, the contention component disappears and
  this hypothesis only saves the per-call BTreeMap walk + `Arc::clone`
  cost, which may drop below the Medium threshold. Reviewer should
  treat H001 and H002 as mutually exclusive alternatives, not additive.
- Plumbing a per-thread/per-cluster module map through the
  C++→Rust bridge requires changes in `bridge.rs`, `soroban_invoke.rs`,
  the host's `instantiate_vm`, and `InvokeHostFunctionOpFrame.cpp`.
  The vendored `soroban-env-host` submodule edit will require
  observation-test regen (`UPDATE_OBSERVATIONS=1`).
- If the Tracy `Vm::instantiate_wasmi` total time is dominated by
  wasmi-internal work (engine state setup, memory allocation, function
  table copy) and not the cache lookup itself, the achievable savings
  cap out well below the projected number; per-call savings need
  microbenchmark validation before redesign.
- Determinism: pre-resolution must happen on the worker thread *after*
  the cluster's footprint has been resolved against the snapshot, so
  that the set of hashes considered matches what `instantiate_vm` would
  see today; otherwise we risk loading a stale module if a cluster
  contains an `UploadContractWasm` op (although in p26 such ops are
  serial, not in parallel clusters).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/001-modulecache-mutex-contention.md`
**Failed At**: reviewer

### Trace Summary

The close-ledger parallel Soroban path constructs one `ThreadParallelApplyLedgerState` per cluster, shallow-clones the shared `SorobanModuleCache`, and launches `applyThread` futures. Each transaction delegates through `TransactionFrame::parallelApply`, `OperationFrame::parallelApply`, and `InvokeHostFunctionOpFrame::doParallelApply` into the C++/Rust bridge, where a fresh p26 `Host` receives a clone of the protocol-specific `ModuleCache`. For `HostFunction::InvokeContract`, `Host::call_contract_fn` resolves the contract instance and calls `instantiate_vm`, which checks contract-code storage and then performs `cache.get_module(wasm_hash)` before entering the larger `Vm::instantiate_wasmi` path.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2575` — `applyThread` processes each cluster's `TxBundle`s and `applySorobanStageClustersInParallel` launches/waits for the worker futures.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` captures `mModuleCache(app.getModuleCache())`, so every cluster gets a shallow clone of the same underlying cache map.
- `src/ledger/LedgerManagerImpl.cpp:954-962` — `getModuleCache` returns `mApplyState.getModuleCache()->shallow_clone()` and asserts compilation is not running during apply.
- `src/transactions/TransactionFrame.cpp:2386-2430` and `src/transactions/OperationFrame.cpp:175-188` — successful Soroban transactions route their single operation into parallel apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1270-1280,1358-1378` — parallel invoke-host apply builds the helper from the thread state and uses the thread state's module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-584` — the helper calls `rust_bridge::invoke_host_function` and passes `*mModuleCache`.
- `src/rust/src/bridge.rs:193-208` and `src/rust/src/soroban_invoke.rs:7-38` — the CXX bridge and Rust wrapper pass the borrowed `SorobanModuleCache` to the protocol-specific host module.
- `src/rust/src/soroban_proto_all.rs:95-129` and `src/rust/src/soroban_proto_any.rs:700-776` — p26 invocation passes `Some(module_cache.p26_cache.module_cache.clone())`, and the shallow clone shares the same underlying thread-safe module map.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-480` — each invocation builds a fresh `Host`, installs the module cache, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1194,750-805` — `InvokeContract` reaches `call_contract_fn`; Wasm contracts call `instantiate_vm`, which checks storage and then calls `cache.get_module`.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:45-83,185-195` — `ModuleCacheMap` is an `Arc<Mutex<BTreeMap<Hash, Arc<ParsedModule>>>>`; `get_module` locks, probes, and clones the `Arc`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-206` — the Tracy `Vm::instantiate_wasmi` zone starts after the module lookup and includes store creation, instantiation-cost charging, import checks, linker instantiation, start-function rejection, and memory lookup.

### Why It Failed

This is substantially the same optimization target already investigated in `001-modulecache-mutex-contention.md`. That prior review traced the same per-invocation `Host::instantiate_vm -> ModuleCache::get_module -> Mutex<BTreeMap>::get -> Arc::clone` path and explicitly considered "pre-resolve all `Arc<ParsedModule>` for a cluster's contract hashes once at `applyThread` entry into a thread-local `HashMap`" as the simpler alternative.

The current source trace matches that prior finding: the inefficiency exists, but the removable work is only a short mutex-protected map lookup and `Arc` clone per Wasm VM instantiation, while the cited `Vm::instantiate_wasmi` zone covers much larger downstream work that pre-resolution would not bypass. Under the optimize-soroswap reviewer objective, Low/sub-threshold improvements are rejected; the prior review already concluded this cache-lookup family cannot plausibly reach the required Medium 3-10% apply-time improvement. H002 is therefore a duplicate, not a novel viable finding.

### Lesson Learned

Pre-resolving cluster-local module handles is the same optimization family as replacing or bypassing the `ModuleCache` lookup mutex. Unless a hypothesis isolates measured lock-wait or lookup cost large enough to clear the Medium threshold, broad `Vm::instantiate_wasmi` time should not be attributed to module-cache lookup overhead.
