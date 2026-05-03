# H001: Batch a Soroban Cluster Through One Rust Invoke Bridge Entry

**Date**: 2026-05-03
**Subsystem**: soroban / transactions / ledger
**Severity**: High
**Impact**: Dominant-phase apply-time redesign that amortizes per-transaction Rust bridge setup and host invocation scaffolding across each sequential soroswap cluster
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Transactions within a Soroban cluster must still execute in the exact stage/cluster/transaction order chosen by the generalized transaction set. Each transaction must keep independent budget limits, authorization entries, result codes, fee refunds, diagnostic events, contract events, and metadata. A failed transaction must leave the cluster ledger overlay in the same state as today's per-transaction `parallelApply` path, while successful transactions must feed their writes into the next transaction in the same cluster before final deterministic commit back to C++.

## Mechanism

`LedgerManagerImpl::applyThread` currently loops over a cluster and calls `TransactionFrame::parallelApply` once per transaction; each invoke-host transaction then builds C++ `CxxBuf` inputs, crosses `rust_bridge::invoke_host_function`, decodes ledger/config/auth/resource XDR, constructs a p26 `Host`, computes output ledger changes, returns encoded effects, and lets C++ record those effects before moving to the next transaction. In the current trace, the in-apply wrapper chain `InvokeHostFunctionOpFrame doParallelApply` / `doApply` / `invokeHostFunction` totals about 12.6 s / 12.6 s / 12.2 s across 6,776 calls, all under `applyLedger`, while the worker wall zone `applySorobanStageClustersInParallel` is the dominant measured stage at 3.52 s over 43 stage applications. A new cluster-level bridge entry could process the whole `Cluster` in one Rust call, keeping transaction isolation but amortizing invariant ledger info, cost params, rent config, module-cache access, CXX bridge dispatch, per-call Rust panic boundary, and reusable per-cluster scratch/overlay allocation across the sequential cluster.

## Trigger

Run the accepted baseline soroswap apply-load workload (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. The normal workload creates eight dependent swap clusters and `applyThread` executes each cluster sequentially on a worker; every swap currently pays the full C++/Rust invoke setup and teardown even though adjacent transactions in the same cluster share ledger sequence, network config, rent configuration, module cache, and a deterministic cluster-local ledger overlay.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` loops over cluster transactions and calls per-transaction `parallelApply`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` launches one worker per cluster and waits on the dominant parallel-apply wall zone.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` constructs per-transaction auth/resource/host-function/source/ledger-entry buffers and crosses the Rust bridge.
- `src/rust/src/bridge.rs:193-208` — the current CXX bridge exposes only single-transaction `invoke_host_function`.
- `src/rust/src/soroban_proto_any.rs:391-490` — single-transaction wrapper creates budget/config state and catches panics for every invoke.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — p26 invocation decodes one transaction's resources/storage/auth inputs, builds one host, executes it, and encodes one transaction's ledger changes/events.

## Evidence

The current diagnostic trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release` reports `applySorobanStageClustersInParallel,ledger/LedgerManagerImpl.cpp,2537,3520949405,...,43,...`, `InvokeHostFunctionOpFrame doParallelApply,transactions/InvokeHostFunctionOpFrame.cpp,1367,12664159786,...,6776,...`, `InvokeHostFunctionOpFrame doApply,transactions/InvokeHostFunctionOpFrame.cpp,985,12628235327,...,6776,...`, and `invokeHostFunction,transactions/InvokeHostFunctionOpFrame.cpp,559,12180825816,...,6776,...`. These events are descendants of `applyLedger` by timestamp overlap and by the source call chain from `applyTransactions` through the Soroban parallel phase. Unlike prior micro-fails that attack a small sub-slice, this proposal restructures the per-cluster boundary that encloses every successful soroswap host invocation in the dominant parallel-apply stage.

## Anti-Evidence

The broad wrapper totals include real contract execution that cannot be removed; the PoC must isolate the amortized setup/writeback portion and prove it survives benchmark noise. The redesign is invasive: Rust would need to return per-transaction results in C++ order, preserve independent budgets and failure rollback, derive the same `subSha256` PRNG seed per transaction, and expose enough per-transaction effects for existing meta/refund handling. It must also preserve the `NUM_CLUSTERS` concurrency cap: batching is one Rust call per existing cluster worker, not additional parallelism.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — exact cluster-level Rust invoke batching was not present in retained `fail/soroban` or `success/soroban` records; cross-subsystem fail/success directories are absent
**Failed At**: reviewer

### Trace Summary

The close-ledger path enters `applySorobanStageClustersInParallel`, launches one worker per cluster, and each worker runs `applyThread`, which applies cluster transactions sequentially by calling `TransactionFrame::parallelApply`. Each transaction reaches `InvokeHostFunctionOpFrame::doParallelApply`, builds per-transaction footprint CxxBuf inputs, calls the single-transaction Rust bridge, then records returned ledger changes, events, fee refunds, result hash, and metadata before committing successful tx changes into the thread-local overlay for the next transaction. On the Rust side, `soroban_invoke::invoke_host_function` dispatches to `soroban_proto_any::invoke_host_function_or_maybe_panic`, which builds a fresh per-tx budget and calls p26 `e2e_invoke::invoke_host_function`, where resources, footprint entries, auth, host function, source account, PRNG seed, host, storage snapshot, ledger changes, and events are all per-transaction.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` derives the per-tx PRNG seed, flushes RO TTL bumps, calls `parallelApply`, and commits only successful tx changes before the next cluster transaction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — one `ThreadParallelApplyLedgerState` is constructed per cluster and one `std::async` worker runs that cluster while the apply thread waits on the futures.
- `src/transactions/TransactionFrame.cpp:2385-2454` — `parallelApply` enforces single-op Soroban txs, calls the operation, sets per-op meta changes, and marks failed txs without committing returned effects.
- `src/transactions/OperationFrame.cpp:175-188` — operation-level parallel apply directly delegates to `doParallelApply`; validation has already run in pre-parallel apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:308-340` — each helper owns per-tx CxxBuf vectors, result references, meta/event managers, refundable-fee tracker, metrics, and module-cache reference.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` walks the tx footprint, loads live/restored entries from the C++ parallel ledger state, materializes `CxxBuf` ledger/TTL inputs, and meters/validates resources.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-638` — `invokeHostFunction` serializes auth, source, resources, host function, ledger entries, TTL entries, PRNG seed, and rent config into the single-transaction Rust bridge and maps failure output back to tx result codes.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-767` — `recordStorageChanges` decodes Rust-returned ledger effects and updates the per-tx C++ parallel ledger state.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-1018` — success handling decodes contract events and return values, consumes refundable resources, computes the success hash, populates meta/events, and records success metrics per transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1100-1282` — the parallel helper handles autorestore, hot-archive/live-bucket restores, per-tx cached ledger info, and `TxParallelApplyLedgerState` ownership.
- `src/transactions/ParallelApplyUtils.cpp:1240-1252` — successful tx effects are committed from the tx overlay into the thread overlay between transactions, which is the mechanism that feeds writes forward inside a cluster.
- `src/transactions/ParallelApplyUtils.cpp:1392-1408` — failed txs return no modified entry map, preserving per-transaction rollback semantics.
- `src/rust/src/bridge.rs:193-208` — the CXX bridge exposes a single invoke-host transaction entry point.
- `src/rust/src/soroban_invoke.rs:7-61` — Rust dispatch chooses the protocol host module and forwards the same single-tx inputs.
- `src/rust/src/soroban_proto_any.rs:391-557` — the protocol wrapper builds the per-tx budget, optional trace hook, panic/error boundary, output metrics, rent fee, diagnostic events, and serialized output.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — p26 invocation decodes resources/footprint/storage/auth/source/function, creates a fresh `Host` and enforcing `Storage`, invokes the function, finishes the host, and computes per-tx ledger changes/events.

### Why It Failed

The per-cluster sequential loop and repeated single-transaction bridge calls are real, but the hypothesis derives its High/Medium impact from broad wrapper zones whose dominant contents are still required per transaction. A correctness-preserving implementation cannot amortize independent budgets, auth managers, diagnostic/contract event buffers, host object tables, `Host::try_finish`, result codes, refundable-fee accounting, per-tx PRNG seeds, per-tx result hashes, per-tx metadata, or success/failure rollback. Preserving current p26 semantics also means the logical XDR decoding/encoding and metering around storage maps, return values, events, and ledger changes must remain or be precisely replayed.

The actually removable setup slices overlap prior retained investigations that were already below the optimize-soroswap Medium floor: bridge preparation and `addReads` serialization were bounded at about 2.5% even under optimistic assumptions, per-ledger budget templates were rejected as below threshold, module-cache pre-resolution was rejected as the same target as module-cache mutex/lookup work, and host allocation-capacity reuse was rejected because the safe removable allocator slice is much smaller than the broad conversion zones. A cluster-level Rust overlay could in theory avoid some C++/Rust round trips for ledger entries between adjacent transactions, but that is a different unmeasured redesign: Rust would need to duplicate the C++ `TxParallelApplyLedgerState`/`ThreadParallelApplyLedgerState` ownership, autorestore, rollback, write-forward, and per-tx effect/meta interfaces while still returning ordered per-transaction effects to C++. The current hypothesis does not isolate a measured removable slice large enough to clear the objective's 3% Medium threshold, and the safe pieces it names are already known sub-threshold.

### Lesson Learned

Do not project cluster-level batching wins from cumulative `InvokeHostFunctionOpFrame` wrapper time: those zones include real contract execution, host lifecycle, metered serialization, and per-transaction result/meta work. A viable structural batching hypothesis would need a dedicated measurement of C++/Rust ledger-entry round-trip overhead that excludes host execution and protocol-visible metering, plus a concrete design for preserving the existing C++ parallel apply overlay semantics without duplicating more work than it removes.
