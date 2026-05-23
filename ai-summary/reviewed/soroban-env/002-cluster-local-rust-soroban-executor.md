# H002: Cluster-Local Rust Soroban Executor

**Date**: 2026-05-23
**Subsystem**: soroban-env / rust bridge / transaction-ledger boundary
**Severity**: High
**Impact**: Dominant-phase redesign of the Soroban `closeLedger` apply path; expected 3-10%+ soroswap apply-time reduction if per-transaction C++↔Rust XDR setup and teardown are collapsed inside each deterministic cluster worker
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within one Soroban apply cluster, transactions must still execute in the cluster's deterministic transaction order, produce the same per-transaction results, events, rent fees, modified ledger entries, TTL updates, refunds, and rollback behavior, and must not use more workers than the configured cluster parallelism. The implementation should not rebuild a full Rust host from freshly serialized C++ buffers for every transaction when a cluster worker already owns the sequential state transition for that cluster.

## Mechanism

`InvokeHostFunctionOpFrame` currently serializes each transaction's footprint entries into `CxxBuf`s, calls the Rust bridge once per transaction, Rust decodes those buffers into a fresh host/storage/budget, then Rust re-serializes modified entries for C++ to parse and commit back into the same cluster-local ledger state. A next-protocol cluster-local Rust executor can move the sequential cluster loop across the FFI boundary: C++ passes the ordered cluster bundle and a deterministic storage adapter once, Rust creates a fresh per-transaction `Budget`/auth/events context while retaining an unmetered cluster-local decoded storage cache and returning per-transaction effects in order. This avoids the repeated C++ `addReads` serialization, Rust metered-XDR setup, Rust-to-C++ effect serialization/parsing, and bridge call overhead without adding nondeterminism or exceeding `NUM_CLUSTERS`.

## Trigger

Run the current soroswap apply-load benchmark with the accepted next-protocol baseline. Every successful Soroban transaction in a cluster currently goes through `InvokeHostFunctionOpFrame::addFootprint`, `invokeHostFunction`, and `recordStorageChanges` independently even though `LedgerManagerImpl::applyThread` then applies those effects sequentially to the same `ThreadParallelApplyLedgerState`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` already owns the deterministic per-cluster transaction loop; this is the boundary to replace with a Rust cluster executor call while preserving cluster order.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` serializes footprint ledger entries and TTL entries into per-transaction `CxxBuf`s.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-592` — `invokeHostFunction` performs one FFI call per transaction with separately serialized host function, resources, source account, auth entries, ledger entries, TTL entries, and PRNG seed.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-720` — `recordStorageChanges` parses Rust-emitted entries and matches them back to the read-write footprint before applying them to the same cluster state.
- `src/rust/src/soroban_proto_any.rs:310-500` — Rust bridge entry point decodes C++ buffers, creates per-transaction host execution, extracts rent/storage effects, and serializes outputs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292,408-580` — fresh per-transaction storage-map construction and ledger-change extraction to replace with a cluster-local executor/storage adapter.

## Evidence

The current soroswap trace verifies these zones are inside `applyLedger`, not TX-set construction. Apply-contained unwrap totals include `addReads` at 314,372,335 ns across 15,794 events, `read xdr with budget` at 204,336,327 ns across 149,459 events, `write xdr` at 180,059,763 ns across 227,325 events, `recordStorageChanges` at 112,473,485 ns across 7,851 events, and the Rust `invoke_host_function` / `invoke_host_function_or_maybe_panic` parent envelope at 21,578,080,129 ns across 15,702 nested events. Source inspection shows the same cluster worker immediately consumes each transaction's Rust output and mutates `ThreadParallelApplyLedgerState`, so the per-transaction bridge roundtrip is an architectural boundary rather than an externally observable ordering requirement.

## Anti-Evidence

This must be a protocol-gated redesign, not a p26-compatible decoded-value cache. Reusing decoded ledger entries while pretending the old per-transaction `ValDeser`, map-construction, and `ValSer` charges still occurred would violate exact budget accounting and repeat prior metering failures. A viable design needs an explicit next-protocol resource model for cluster execution, fresh per-transaction budget/error boundaries, deterministic per-transaction output ordering, and a conservative fallback to the existing per-transaction bridge for unsupported transactions, hot-archive restores, diagnostics modes, or any cluster shape the new executor cannot prove equivalent.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The apply path already partitions Soroban transactions into deterministic clusters, starts one worker per cluster, and executes each bundle sequentially in `LedgerManagerImpl::applyThread`. Each successful transaction then enters `TransactionFrame::parallelApply`, dispatches its single invoke operation to `InvokeHostFunctionOpFrame::doParallelApply`, serializes the current footprint state and auth/resources into bridge buffers, calls Rust once, reparses returned ledger entries, and mutates the same `ThreadParallelApplyLedgerState`. On the Rust side, the bridge creates a fresh per-transaction budget and host, decodes the footprint/storage/auth XDR into a `StorageMap`, clones that initial storage for diffing, executes the host function, materializes ledger changes, extracts rent/effect outputs, and serializes them back to C++.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` owns the ordered cluster loop and commits each successful transaction into the same thread-local ledger state before moving to the next bundle.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches exactly one async worker per cluster, so moving the per-cluster sequential loop across the Rust bridge would not exceed existing cluster parallelism.
- `src/transactions/TransactionFrame.cpp:2385-2455` — `parallelApply` applies the single Soroban operation, updates per-transaction metadata and result state, and only records deltas for invariant checks.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` loads each footprint entry/TTL from the thread-local state and serializes present entries into `CxxBuf`s for every transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-637` — `invokeHostFunction` allocates/auth-serializes per-transaction bridge arguments and calls `rust_bridge::invoke_host_function` once per transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — `recordStorageChanges` reparses each Rust-emitted ledger entry, scans the RW footprint to match it, applies upserts/deletes to the thread-local state, and enforces created-entry/TTL pairing.
- `src/rust/src/bridge.rs:30-55` and `src/rust/src/soroban_invoke.rs:7-61` — the CXX bridge shape is per-invocation and returns per-transaction `InvokeHostFunctionOutput` buffers, not a cluster batch.
- `src/rust/src/soroban_proto_any.rs:310-506` — the bridge builds a per-transaction `Budget`, calls the protocol-selected host invocation, extracts rent/storage effects, and returns serialized output buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — `invoke_host_function` decodes resources, footprint, storage, auth entries, host function, source account, and PRNG seed; constructs a fresh `Host`; executes; finishes; then computes storage/event outputs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — storage setup clones footprint keys, decodes each input ledger/TTL entry, builds `StorageMap`/`TtlEntryMap`, and inserts `None` for absent footprint entries on every invocation.
- `src/transactions/ParallelApplyUtils.cpp:988-1120` — `ThreadParallelApplyLedgerState` already caches and serves live cluster entries locally, confirming the repeated C++ serialization/Rust decode is a bridge-boundary artifact rather than required for ledger ordering.

### Findings

- **Inefficiency exists**: YES. The same cluster worker has a live decoded C++ ledger-state map, but each transaction converts its footprint entries to XDR buffers, Rust decodes them into a fresh host storage map, Rust serializes effects, and C++ parses those effects back into the same worker-local state.
- **Hot path**: YES. This occurs inside `closeLedger` for every successful Soroban invoke transaction in the soroswap stage; the traced zones are in the apply path and execute thousands of times per benchmark run.
- **Existing optimizations**: PARTIAL but insufficient. `ThreadParallelApplyLedgerState` preloads entries from global state, `InMemorySorobanState`, and snapshots, and the Rust `ModuleCache` avoids reparsing Wasm modules, but the C++/Rust storage-effect marshalling remains per transaction.
- **Correctness constraints**: The old per-transaction bridge cannot simply cache decoded values under p26 because XDR decode/encode, storage-map construction, map operations, and ledger-change extraction contribute protocol-visible `cpu_insns`/`mem_bytes`. A viable implementation must therefore be next-protocol gated with an explicit resource model, preserve fresh per-transaction budget/auth/events/error boundaries, return transaction results/effects in cluster order, and fall back for diagnostics, hot-archive restores, unsupported host functions, or any cluster shape that cannot be proven equivalent.
- **Impact estimate**: Medium. The directly traced avoidable work (`addReads`, budgeted XDR read/write, and `recordStorageChanges`) is hundreds of milliseconds across the apply trace, and the parent bridge envelope is a dominant repeated Soroban-invocation phase. The expected gain is plausibly in the objective's 3-10% band after prior native-path optimizations, but the trace does not justify a High verdict without benchmark proof that the cluster redesign removes more than 10% of apply time.

### PoC Guidance

- **Target code**: Add a next-protocol-only cluster execution path at `LedgerManagerImpl::applyThread` / `applySorobanStageClustersInParallel`, with a new CXX bridge entry alongside `rust_bridge::invoke_host_function`. On C++, factor `InvokeHostFunctionParallelApplyHelper` logic so supported invoke transactions can be described in an ordered cluster batch and unsupported transactions continue through the current per-transaction path. On Rust, add a cluster executor near `soroban_proto_any::invoke_host_function` / `e2e_invoke::invoke_host_function` that reuses a cluster-local decoded storage/effect adapter while creating fresh per-transaction `Budget`, `Host`, auth, event, PRNG, and result contexts.
- **Change description**: Pass the ordered cluster bundle once, execute transactions sequentially in Rust, and return a vector of per-transaction outputs that C++ applies in the same order. The cluster storage adapter should avoid repeatedly serializing/decoding unchanged shared entries, but it must define new protocol-visible charges rather than trying to reproduce p26 metering implicitly. Keep conservative fallbacks for diagnostics/tracing, hot-archive restoration, internal errors, non-invoke operations, classic creations that the batch path does not model, and any transaction whose source/auth/resources cannot be represented exactly.
- **Correctness check**: Existing parallel-apply, Soroban host invocation, auth, rollback, TTL/rent, transaction-meta, diagnostic-event, and invariant tests cover the surrounding behavior. The PoC should add focused equivalence coverage for mixed success/failure clusters, storage upsert/delete/TTL changes, rent/refundable fee outputs, event/result hashes, RO TTL bump flushing, rollback boundaries, and fallback interleaving with the legacy per-transaction bridge.
- **Benchmark focus**: Compare three non-Tracy `scripts/run_apply_load_matrix.py` runs against the accepted baseline, with soroswap median apply time as the primary metric. Instrument the PoC to report eliminated per-transaction `addReads`, `read xdr with budget`, `write xdr`, `recordStorageChanges`, storage-map build/clone, and bridge-call counts; require a reproducible 3-10% improvement for Medium, and only claim High if the cluster executor exceeds 10% or demonstrably restructures the dominant apply phase.
