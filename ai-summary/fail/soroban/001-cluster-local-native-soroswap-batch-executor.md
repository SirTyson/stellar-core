# H001: Cluster-Local Native Soroswap Batch Executor

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: High
**Impact**: Dominant-phase redesign of sequential same-pool Soroban cluster execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Transactions inside a Soroban apply cluster must still be applied in their existing deterministic order, with the same per-transaction budget enforcement, authorization checks, events, results, ledger changes, and rollback behavior. When a cluster is composed of allowlisted Soroswap swap invocations over the same pool/pair shape, the worker should be able to execute the sequence as a single native batch plan while emitting the same per-transaction externally visible artifacts.

## Mechanism

`LedgerManagerImpl::applyThread` already processes every `TxBundle` in a cluster sequentially on one worker thread, and soroswap intentionally bins same-pool conflicting swaps into those sequential clusters. Today each bundle re-enters the full per-transaction path: C++ footprint materialization, Rust bridge decode, fresh `Host`, Wasm/router execution, native pool subcalls, SAC transfers, ledger-change extraction, and thread-state commit. A cluster-local native batch executor could recognize a run of allowlisted Soroswap swap transactions, maintain an ordered pool/SAC balance journal for the cluster, execute each swap against that journal with per-tx checkpoints, and flush the same ordered per-tx effects back through `ThreadParallelApplyLedgerState`; this targets the whole `applySorobanStageClustersInParallel` worker wall time instead of another already-rejected single-read or metering micro-optimization.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load benchmark. The generated workload has eight configured clusters, and within a cluster the swaps are sequential because they conflict on pool/SAC state; each sequential bundle currently pays a full host invocation even though the worker already owns the deterministic transaction order.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` owns the deterministic per-cluster sequential loop and is the insertion point for recognizing a batchable run.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one worker per cluster and waits for their ordered results.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — current per-transaction parallel Soroban invoke path that the batch executor would bypass only for verified batchable swaps.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-837` — generic contract call dispatch currently detects native pool calls only after a fresh host/frame has already been created for the transaction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1170-1304` and `1330-1366` — existing native pool swap/SAC helper logic that can be reused as the per-tx semantic core inside a cluster journal.

## Evidence

The current Tracy trace shows `applySorobanStageClustersInParallel` fully contained in `applyLedger` with 44 calls / 3.008s total wall time, while the host invocation subtree across workers remains much larger than any individual micro-zone (`invoke_host_function` 10.811s total, `Host::invoke_function` 8.192s total, `Vm::invoke_function_raw` 7.146s total, `call` 4.871s total, and `SAC transfer` 2.602s total). Prior failures establish that isolated SAC, dispatch, metering, XDR, and VM-instantiation cleanups are each below the Medium floor after 8-way normalization; the remaining plausible multi-percent target is to restructure the repeated per-tx execution envelope for the same ordered cluster.

## Anti-Evidence

This is a large protocol-level design, not a tactical patch. The executor must provide binary-derived equivalence for router/pool semantics, exact event order and contract IDs, per-transaction auth trees, budget/fuel accounting, failure rollback, and fee/refund output; without that specification it collapses into the previously rejected native-bypass family. It also must not introduce extra parallelism beyond the existing cluster workers: batching preserves deterministic intra-cluster order rather than trying to rebalance or parallelize conflicting swaps.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entries for `001-cluster-rust-invoke-batching.md + 002-cluster-native-soroswap-swap-batching.md` and the native Soroswap bypass family
**Failed At**: reviewer

### Trace Summary

The proposed insertion point is real: `LedgerManagerImpl::applySorobanStageClustersInParallel` launches one worker per cluster, and `LedgerManagerImpl::applyThread` applies each `TxBundle` in deterministic cluster order before committing successful per-transaction effects. Each bundle then follows the existing per-transaction Soroban path through `TransactionFrame::parallelApply`, `OperationFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, `InvokeHostFunctionApplyHelper::apply`, and the Rust bridge `invoke_host_function`, which creates a fresh budget/host invocation result and returns per-tx modified entries, events, rent fees, CPU/memory usage, and diagnostics. The native Soroswap pool fast path exists inside a single host/frame invocation and is already protocol-gated, but a cluster-local journal would still have to duplicate or preserve per-tx host state, auth tracking, budget/fuel metering, rollback, event/result hashing, and C++ `ParallelTxSuccessVal` commit semantics.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md` — Records the substantially equivalent cluster-level batching duplicate: `001-cluster-rust-invoke-batching.md + 002-cluster-native-soroswap-swap-batching.md`, rejected because per-tx budgets, auth, events, PRNG seeds, metadata output, rollback semantics, and C++ parallel-apply commit interfaces cannot be amortized across transactions without duplicating or violating isolation.
- `ai-summary/fail/soroban/summary.md` — Records the broader native Soroswap bypass family as already rejected unless a complete binary-derived semantic, auth, event-order, error/trap, and metering specification exists.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` computes a per-tx PRNG sub-seed, flushes RO TTL bumps for the current bundle, calls `tx->parallelApply`, and commits each successful transaction independently into `ThreadParallelApplyLedgerState`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` only distributes clusters to worker threads and collects finished thread states; it does not expose a batch result interface that can replace per-bundle transaction effects.
- `src/transactions/TransactionFrame.cpp:2385-2454` — `parallelApply` requires a successful per-tx result payload, applies the single Soroban operation, records per-operation ledger changes/meta, and returns a `ParallelTxSuccessVal` for that transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:280-340, 982-1031, 1269-1310, 1358-1377` — `InvokeHostFunctionApplyHelper` owns per-tx resources, footprint buffers, diagnostics, refundable-fee tracker, host output processing, storage-change recording, event collection, and final success hashing; the parallel helper returns a per-tx `mTxState.takeResult(success)`.
- `src/rust/src/soroban_proto_any.rs:310-557` — The bridge invocation catches panics, constructs a per-tx `Budget`, calls e2e host invocation with per-tx ledger entries/auth/PRNG seed, and returns per-tx success/failure output with resource usage and ledger effects.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-837, 840-1074, 1076-1366` — Native Soroswap pool getter/swap handling is inside `Host::call_contract_fn` after retrieving the current contract instance; it is still a per-host/per-frame execution path and calls SAC transfer/balance helpers through normal host call machinery.

### Why It Failed

This is not novel: the fail summary already rejects cluster-local Soroban invocation batching and native Soroswap swap batching for the same mechanism and blockers. The proposed cluster journal is also a native Soroswap bypass variant without a new binary-derived semantic/metering specification, and tracing confirms the current interfaces are deliberately per-transaction: they produce isolated budgets, auth state, rollback behavior, events, result hashes, refundable fees, diagnostics, modified entries, and `ParallelTxSuccessVal` commits that cannot be safely amortized by merely running a cluster-local executor.

### Lesson Learned

Future Soroswap optimization hypotheses should not repackage cluster-level batching or native-bypass fusion unless they introduce a concrete new protocol-level specification and an implementation interface that preserves per-transaction artifacts rather than bypassing or duplicating the existing host and parallel-apply isolation model.
