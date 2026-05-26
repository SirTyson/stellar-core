# H001: Cluster-Batched Native Soroswap Swap Journal

**Date**: 2026-05-26
**Subsystem**: ledger / Soroban parallel apply
**Severity**: High
**Impact**: dominant-phase redesign of soroswap `applyLedger` by replacing per-transaction router/pool/SAC host execution inside each conflict cluster with a deterministic typed batch journal
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within a Soroban apply cluster, transactions must be applied in exactly the same order they are applied today. For the official soroswap swap workload, each successful transaction should still charge fees, enforce auth, emit per-transaction result/events, update pool reserves and SAC balances, report resources, and produce the same final ledger entries as the current per-transaction host path.

For a next-protocol-gated soroswap-native path, the cluster should be able to preserve that observable per-transaction order while keeping the hot pool reserves and pair SAC balances in a typed cluster-local journal. The apply path should materialize each transaction's result and ledger effects deterministically from the journal instead of reconstructing a fresh Rust `Host`, router Wasm VM, native pool frame, and SAC frames for every swap.

## Mechanism

`LedgerManagerImpl::applyThread` currently applies every `TxBundle` in a cluster independently: each transaction calls `TransactionFrame::parallelApply`, crosses the C++/Rust bridge, builds enforcing storage, runs router Wasm, calls the native pool helper, and invokes SAC transfers. Soroswap clusters are true write-conflict clusters, so prior attempts to parallelize inside a cluster are blocked; however, the same sequentiality makes a typed batch journal viable because the batch engine can execute swaps in transaction order while carrying forward the exact pool and pair-balance state that the next transaction would have loaded from storage.

A specialized batch path would fire only for homogeneous next-protocol official soroswap swap clusters. It would decode and validate every transaction shape up front, then execute the swaps in cluster order over typed state, producing per-transaction `ParallelTxSuccessVal`/effects in the same order and flushing the final dirty ledger entries through the existing thread/global merge path. This is materially different from generic cluster batching: it does not share arbitrary host contexts across unrelated contracts; it replaces a known router+pool+SAC state machine with an explicit deterministic state machine bounded to the same cluster.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the current baseline. The trigger is a parallel-apply stage whose cluster contains only official soroswap router swap transactions targeting one of the benchmark pairs, with next-protocol native soroswap optimizations enabled. The candidate path should fall back to the existing per-transaction host execution if any transaction shape, footprint, code hash, auth shape, protocol version, or contract layout check does not match the specialized batch preconditions.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` currently loops over every `TxBundle`, flushes TTL bumps, calls `parallelApply`, and commits each successful tx into the thread state one at a time.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one worker per cluster; the batch would remain inside each worker and would not exceed `NUM_CLUSTERS` parallelism.
- `src/transactions/TransactionFrame.cpp:2385-2420` and `src/transactions/OperationFrame.cpp:175-188` — per-transaction parallel apply dispatch that would need a specialized cluster-level alternative for recognized batches.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — current per-transaction C++ bridge call into Rust host execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-579` — per-transaction host setup, execution, finish, and ledger-change extraction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — native pool swap semantics that the batch journal must preserve transaction-by-transaction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1528` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC transfer/balance semantics that the journal must preserve while avoiding repeated generic frame/storage reconstruction.

## Evidence

The current-state trace is `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release` reports `applyLedger` at `ledger/LedgerManagerImpl.cpp:1484` with 4,412,547,914 ns total over 71 calls. Its Soroban worker descendants dominate the measured apply subtree: `parallelApply` at `transactions/TransactionFrame.cpp:2392` totals 11,586,376,901 ns over 8,039 calls, `Host::invoke_function` totals 8,262,600,385 ns, `Vm::invoke_function_raw` totals 7,250,910,294 ns, generated `call` import totals 4,950,309,676 ns, and `SAC transfer` totals 2,651,398,200 ns. Timeline intersection against `applyLedger` windows confirms these are in-scope descendants: `call` contributes 4,937,728,356 ns inside `applyLedger`, `SAC transfer` contributes 2,644,782,958 ns, and `invoke_host_function`/bridge spans contribute 21,779,331,303 ns.

Prior failures show that micro-optimizing frame setup, SAC balance reads, import dispatch, or intra-cluster antichains is too small or structurally blocked. This candidate instead targets the reason those costs remain dominant: the current apply loop repeats the whole router/pool/SAC host state machine for every transaction even when the cluster is a deterministic sequence over the same small typed state. Removing most of the repeated Host/VM/cross-contract/SAC reconstruction from the slowest-cluster critical path is plausibly Medium-to-High if the recognized batch covers the headline soroswap workload.

## Anti-Evidence

This is a large consensus-sensitive redesign, not a local refactor. The batch journal must preserve per-transaction failure boundaries, auth, diagnostics policy, contract events, resource metrics, refundable fees, TTL/rent effects, restore behavior, and final ledger-change ordering. It also overlaps conceptually with prior failed generic cluster-batching and native-router attempts; reviewer should treat it as novel only if the proposed implementation is an explicit typed state-machine batch with per-tx effect materialization, not a generic shared-host-context batch or a single-tx native-router retry.

---

## Review

**Verdict**: VIABLE
**Severity**: High
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — prior failures covered generic shared-host batching and per-transaction native-router trampolines, not a per-cluster typed journal that materializes per-transaction effects

### Trace Summary

The current apply path launches one worker per Soroban conflict cluster, but each worker still iterates transactions one at a time and creates a fresh per-transaction invoke-host-function execution. Every successful swap crosses `TransactionFrame::parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply` -> C++/Rust bridge -> p26 `invoke_host_function`, which rebuilds enforcing storage, constructs a `Host`, executes router Wasm, enters the native pool helper, performs SAC transfers/balance reads, extracts ledger changes, and then returns C++ buffers that are decoded into `ParallelTxSuccessVal`. The write-conflict cluster ordering already serializes same-pair swaps, and the thread/global merge path only needs a deterministic per-tx modified-entry map plus per-tx result/meta, so a narrowly gated typed state machine can replace repeated router/Host/VM/SAC frame reconstruction while preserving the same observable cluster order.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is the per-cluster hot loop; it flushes RO TTL bumps, calls `tx->parallelApply`, and commits each successful `ParallelTxSuccessVal` into thread state in cluster order.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` already limits execution to one worker per cluster, so a cluster-local batch path would not add parallelism or alter stage/cluster scheduling.
- `src/transactions/TransactionFrame.cpp:2385-2454` and `src/transactions/OperationFrame.cpp:175-188` — successful parallel apply dispatches the single Soroban operation, sets per-op ledger changes from `ParallelTxSuccessVal`, and records failure by leaving the tx uncommitted.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585, 640-928, 980-1017, 1358-1378` — each tx independently calls `rust_bridge::invoke_host_function`, decodes returned modified ledger entries/events/result, consumes refundable fees, sets the success hash/return value/events, and returns the tx dirty map through `takeResult`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-579` — the Rust bridge repeats resource/footprint decoding, storage-map construction, host construction, auth setup, `Host::invoke_function`, `Host::try_finish`, ledger-change extraction, and event/result encoding for every transaction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825, 1127-1375, 1465-1528` — native pool fast paths are already next-protocol gated and encode the exact pool getter/swap semantics; the batch journal can reuse these semantics as the reference for typed reserve, SAC-transfer, balance-read, event, and TTL behavior.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:357-427` — SAC transfer requires nonnegative amount checks, auth, instance/code TTL extension, source debit, destination credit, and transfer event emission; these are mandatory semantics the journal must model, but they are also typed and bounded for the recognized swap shape.
- `src/transactions/ParallelApplyUtils.cpp:1164-1252, 1392-1408` and `src/transactions/TransactionFrameBase.h:169-212` — the merge boundary is small and explicit: a successful tx contributes a `TxModifiedEntryMap` and restored entries; failed txs contribute nothing, providing a natural target output for per-tx journal materialization.
- `ai-summary/fail/ledger/summary.md:59, 71-75` — prior adjacent failures rejected shared-host cluster batching and missing native-router/pool trampolines; this hypothesis avoids the shared-host isolation bug and targets a now-present native pool path with a fuller typed router/pool/SAC state machine.

### Findings

The inefficiency exists and is in the hot path: the current cluster worker repeats the entire invoke-host-function stack for every swap even though same-pair transactions must already execute sequentially over the same pool reserves and SAC balances. Existing next-protocol native pool code proves this repository already accepts protocol-gated, benchmark-shape native Soroswap emulation when it is guarded by exact hash/function/layout checks and falls back to Wasm for all other cases.

The proposed fix is viable only as a strict typed journal, not as a shared Rust `Host` or a single-tx router trampoline. The PoC must recognize the full official router swap shape, source-account/SAC auth shape, contract hashes, footprints, pool instance layout, SAC executable layout, TTL/rent behavior, and event/result encoding before entering the batch path. It must maintain per-transaction rollback boundaries by applying each swap to a temporary journal slice, committing that slice only after all checks for that tx succeed, and emitting one normal `ParallelTxSuccessVal` plus op result/meta per transaction.

Impact is plausibly High for this objective because the candidate removes or amortizes the dominant worker phase rather than a small wrapper: router Wasm execution, repeated `Host` setup, cross-contract call dispatch, native pool frame setup, SAC frame dispatch, and ledger-change extraction all sit under `parallelApply` in the measured `applyLedger` windows. Even after normalizing aggregate worker time by the configured 8 clusters and retaining mandatory typed arithmetic, auth checks, ledger writes, TTL/rent accounting, and event construction, the removable portion is large enough to clear the 3% Medium floor and may exceed 10% if the specialized path covers the headline soroswap clusters.

Correctness constraints are severe but bounded. The path must be next-protocol gated; must reject any non-canonical router function, non-source-account/custom-account auth, unexpected diagnostic mode, restore case, footprint mismatch, mixed-pair cluster, unknown contract hash/layout, failed precondition, or unsupported event/result shape; and must fall back to the existing per-tx host path for the whole cluster if recognition is incomplete. It must not change cluster order, exceed `NUM_CLUSTERS` parallelism, or combine multiple txs into one observable success record.

### PoC Guidance

- **Target code**: Add a cluster-level fast path before the `for (auto const& txBundle : cluster)` loop in `src/ledger/LedgerManagerImpl.cpp:2483-2520`, with helper code near `InvokeHostFunctionOpFrame` / parallel-apply utilities to inspect tx shape, produce per-tx `ParallelTxSuccessVal`, set operation results/meta, and commit through existing `ThreadParallelApplyLedgerState::commitChangesFromSuccessfulTx`.
- **Change description**: Implement a next-protocol-gated `tryApplyNativeSoroswapSwapCluster` that first validates every tx in the cluster is the exact official router swap shape for one supported pair and supported SAC tokens, preloads typed pool/SAC/TTL state from the thread state, then executes swaps in cluster order over a copy-on-write journal. For each successful tx, materialize the same modified ledger entries, return value, contract events, refundable-fee/rent outputs, and result hash that the current native-pool-backed path would expose; on any recognition failure, run the existing per-tx path unchanged.
- **Correctness check**: Existing parallel Soroban apply tests and native Soroswap/p26 host tests should remain authoritative. Add focused tests for exact fallback conditions, per-tx failure rollback inside a recognized cluster, event/result-hash equivalence against the existing host path for a small swap sequence, auth-shape rejection, TTL/rent entry equivalence, and mixed-pair/mixed-contract rejection.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py` three non-Tracy times and require soroswap median apply time to improve by at least 3%, with no material SAC regression. A diagnostic Tracy pass should show reduced per-tx `parallelApply` / `Host::invoke_function` / `Vm::invoke_function_raw` / generated `call` / `SAC transfer` descendants inside `applyLedger`, while preserving the same number and order of successful transaction results.

---

## PoC Attempt

**Result**: POC_FAIL
**Date**: 2026-05-26
**PoC by**: gpt-5.5, high
**Failed At**: poc
**Iterations**: 0

### Failure Reason

The optimization could not be demonstrated safely as a bounded PoC. The required deliverable is not a local ledger-loop optimization; it needs a new consensus-sensitive cluster executor that can recognize canonical Soroswap router swaps, validate auth/footprint/code/layout invariants, execute the router/pool/SAC state machine over a copy-on-write typed journal, and materialize fully equivalent per-transaction result values, events, rent/refund accounting, restored entries, TTL changes, result hashes, and `ParallelTxSuccessVal` maps. The current production interfaces only expose per-transaction `TransactionFrame::parallelApply` and the Rust host bridge output, so there is no existing safe seam to synthesize equivalent per-tx effects outside the host without building and validating that whole executor.

There is also a baseline mismatch in this worktree: `CURRENT_STATE.md` and `origin/soroswap-perf` record p26 at `7aef8604bced962d79aaf06cab2f9e2c2c4e95d8` with the sparse no-meta bridge path, while this PoC worktree starts from p26 gitlink `bf6625f80504d9ccbd34ffe2fa5cc1761d5242fe` and lacks the accepted baseline source state. I fetched the p26 fork and confirmed the recorded `7aef8604` baseline commit exists, but implementing and validating the cluster-batch redesign on the older checked-out base would not produce a meaningful handoff for final review.

### Changes Attempted

No production source changes were left in the tree. I inspected the relevant apply loop (`src/ledger/LedgerManagerImpl.cpp`), per-transaction parallel apply dispatch (`src/transactions/TransactionFrame.cpp`), the invoke-host-function bridge call site (`src/transactions/InvokeHostFunctionOpFrame.cpp`), the parallel apply merge boundary (`src/transactions/ParallelApplyUtils.*` and `src/transactions/TransactionFrameBase.h`), and the Rust bridge declarations. I also initialized the p26 submodule and fetched the SirTyson p26 fork to compare the checked-out gitlink with the accepted baseline. Because no viable bounded implementation seam existed and no source change was attempted, no build-test cycle was run.
