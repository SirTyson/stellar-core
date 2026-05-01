# H002: Batch cluster-local Soroban invocation through one Rust worker executor

**Date**: 2026-05-01
**Subsystem**: transaction-ledger / ledger parallel apply / Soroban host bridge
**Severity**: High
**Impact**: Dominant-phase redesign of parallel Soroban `closeLedger` that can combine several sub-threshold per-transaction setup and bridge costs into a multi-percent soroswap apply-time reduction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban cluster should produce exactly the same per-transaction results, metadata, events, refundable-fee accounting, rent changes, TTL bumps, restored-entry effects, and final ledger state as the current C++ loop. Transactions in a cluster must still execute sequentially in transaction order, failed transactions must roll back only their own effects, successful changes must be visible to later transactions in the same cluster, and parallelism must remain capped by the configured cluster count (`NUM_CLUSTERS` / `ledgerMaxDependentTxClusters`).

## Mechanism

`LedgerManagerImpl::applyThread` currently iterates a cluster in C++ and invokes `TransactionFrame::parallelApply` once per transaction. Each `InvokeHostFunctionOpFrame::doParallelApply` constructs a helper, serializes auth/source/resources/host-function buffers, crosses the C++/Rust bridge, decodes resources and ledger entries in Rust, builds per-tx footprint/storage/TTL maps, constructs a `Host`, executes one host function, encodes output changes/events, returns to C++, and then commits effects into `ThreadParallelApplyLedgerState` before the next tx repeats the same boundary work. A Rust-side cluster executor can receive the ordered cluster inputs and the cluster's initial entry set once, maintain a per-cluster decoded ledger-entry cache, create a fresh per-tx `Budget`/`Host` view over that cache, commit each success to the cache before the next tx, and return the same ordered per-tx effect objects to C++.

This is a determinism-preserving redesign because it does not split true conflict groups or change transaction order; it only moves the existing sequential cluster loop across the bridge and reuses decoded cluster-local state between iterations. The current trace shows the parallel Soroban phase dominates `applyLedger` (`applySorobanStageClustersInParallel` total `3,467,944,842 ns` over 42 stage executions), while the per-tx Rust invocation boundary remains visible in `invoke_host_function` (`476,945,584 ns` self / `5,093` calls), `read xdr with budget` (`120,657,693 ns` self / `97,415` calls), `write xdr` (`132,205,893 ns` self / `152,631` calls), and remaining storage/map setup zones. Individually these families often fall below Medium, but a cluster executor attacks them together at the dominant phase boundary.

## Trigger

Run the current soroswap apply-load matrix with the accepted baseline from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). The benchmark constructs exactly eight dependent soroswap pair clusters, and each worker processes many sequential swaps against the same pair/SAC footprint family. In the Tracy run:

- `applySorobanStageClustersInParallel` is under `applyLedger` at `src/ledger/LedgerManagerImpl.cpp:2537` and accounts for `3,467,944,842 ns` total time across the trace.
- `InvokeHostFunctionOpFrame doParallelApply` at `src/transactions/InvokeHostFunctionOpFrame.cpp:1367` is reached `5,093` times.
- `invoke_host_function` at `soroban-env-host/src/e2e_invoke.rs:488` is reached once per Soroban tx and still has `476,945,584 ns` self-time after prior storage-map and XDR-size optimizations.
- Timestamp-filtered `read xdr with budget`, `write xdr`, `map lookup`, and storage get/put zones occur inside `applyLedger` worker windows.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — current per-cluster worker loop calls back into C++ transaction application once per tx and commits effects after each call.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — per-tx bridge setup serializes host-function/resources/source/auth/ledger buffers and calls `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-38` — C++ bridge dispatches exactly one host-function invocation at a time to the protocol-specific host module.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — Rust decodes resources and ledger entries, builds storage maps, constructs a `Host`, runs one invocation, finishes storage/events, and returns.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — `ThreadParallelApplyLedgerState` already collects the cluster footprint entries before the worker loop; this is the natural source for a one-shot cluster input.
- `src/transactions/ParallelApplyUtils.cpp:1203-1321` and `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — C++ effect recording paths that the batch bridge must either preserve as returned per-tx effects or move behind an equivalent ordered Rust output format.

## Evidence

- Soroswap clusters are true dependent clusters, so previous attempts to split them failed. This proposal keeps the dependency order intact and instead optimizes the serial work inside each worker.
- The current worker loop crosses the bridge and rebuilds Rust-side invocation state once per transaction even when adjacent txs in the same cluster repeatedly touch the same pair contract, SAC contracts, contract-code entries, and TTL entries.
- `ThreadParallelApplyLedgerState` already has the full cluster footprint entry set before applying the cluster, so a batch bridge can be fed the same deterministic initial state without extra live-snapshot reads.
- Prior failed hypotheses show that individual per-tx setup pieces (`CxxBuf` precompute, old-entry XDR, storage-map micro-optimizations, VM instantiation alone, commit coalescing) are often sub-threshold. A cluster executor is novel because it removes the repeated C++/Rust boundary and decoded-state reconstruction as a single dominant-phase redesign rather than as isolated micro-fixes.
- Determinism is straightforward relative to speculative parallelism: txs remain ordered within the cluster, each worker owns only its cluster state, and C++ merges the same per-cluster outputs after futures join.

## Anti-Evidence

- This is invasive. It requires a new batched bridge API, a Rust representation of per-tx inputs/results, and careful preservation of C++ metadata, diagnostic events, refundable-fee trackers, restored entries, and failure rollback behavior.
- A fresh `Budget`, auth stack, event buffer, PRNG sub-seed, source account, and `Host` frame state are still required per transaction; the batch executor must not accidentally share protocol-visible host state across tx boundaries.
- New-entry serialization and event/result serialization still need to be returned to C++ unless the effect format is redesigned further, so the win depends on reducing repeated input decoding, storage-map construction, bridge allocation, and state lookup rather than deleting all XDR.
- The per-cluster decoded cache must be bounded and ephemeral. Prior global in-memory byte caching regressed from cache pressure; this design should reuse only data already owned by the cluster worker and release it after the cluster.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no matching cluster-local/batched Rust executor record found in `fail/transaction-ledger` or `success/transaction-ledger`
**Failed At**: reviewer

### Trace Summary

The close-ledger path does execute Soroban clusters through a C++ per-transaction loop: each cluster worker calls `TransactionFrame::parallelApply`, which dispatches one `InvokeHostFunctionOpFrame::doParallelApply`, serializes per-tx inputs, crosses the C++/Rust bridge, builds a fresh Rust `Budget`/footprint/storage/`Host`, and commits only successful effects back into `ThreadParallelApplyLedgerState`. The hypothesized repeated setup is real, but the proposed decoded cluster cache is not behavior-preserving as stated because the Rust input decoding, map construction, storage cloning, and output encoding are charged to each transaction's protocol-visible budget. If a batch executor preserves equivalent per-tx charges and fresh host/storage isolation, the remaining safely removable work is mostly bridge/protocol-dispatch/glue overhead and falls below the objective's Medium threshold after normalizing aggregate worker self-time by the configured eight clusters.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` iterates a cluster sequentially, derives the per-tx PRNG sub-seed, flushes pending RO TTL bumps, invokes `tx->parallelApply`, and commits only successful per-tx changes before moving to the next transaction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` constructs one `ThreadParallelApplyLedgerState` per cluster, launches workers with `std::async`, and waits for all futures; the stage zone is a wall-clock wait on worker execution, not itself removable setup.
- `src/transactions/TransactionFrame.cpp:2385-2454` — `parallelApply` skips already-failed txs, dispatches the single Soroban operation, records invariant deltas only when enabled, and writes operation meta from the returned per-tx success value.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-525` — each tx scans its footprint, loads current entries/TTLs through the thread state or snapshots, serializes them into `CxxBuf`s, meters read resources, and handles hot-archive autorestore before entering Rust.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — each tx builds auth/source/resources/host-function/base-PRNG buffers and calls `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:391-557` — the bridge dispatches one invocation to the protocol host module, creates a fresh `Budget`, records metering totals, computes rent, and returns one `InvokeHostFunctionOutput`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — each invocation decodes resources, builds the enforcing footprint and storage maps, clones the initial storage map, constructs a fresh `Host`, installs auth/ledger/module state, invokes the host function, then computes encoded result/events/ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-82` — input XDR decoding and output XDR writing charge `ValDeser`/`ValSer` directly to the transaction budget.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292,933-1052` — ledger-change extraction and storage builders perform metered writes, clones, map operations, and TTL handling that contribute to each tx's `cpu_insns`/`mem_bytes`.
- `src/transactions/ParallelApplyUtils.cpp:1199-1252` — successful returned changes are converted into per-tx metadata deltas and then committed from tx state into thread state, preserving rollback isolation for failed txs.

### Why It Failed

The batching mechanism's main claimed win is to decode the cluster's initial ledger-entry set once and reuse a decoded cache across many transactions. That skips work currently performed under each transaction's fresh `Budget`: `metered_from_xdr_with_budget` charges `ValDeser`, `Rc::metered_new`/`MeteredOrdMap` construction charge memory and map costs, `init_storage_map.metered_clone` charges the per-tx initial snapshot, and `metered_write_xdr` charges output serialization. Those counters feed `InvokeHostFunctionOutput.cpu_insns`/`mem_bytes`, resource-limit failures, refundable-fee accounting, diagnostics, and replay behavior, so silently reusing decoded objects would change consensus-visible outcomes for borderline transactions.

A correctness-preserving batch executor would therefore have to replay equivalent per-tx metering and still create fresh per-tx `Budget`, auth stack, host frame state, events, PRNG state, rollback boundary, storage view, result/event encoding, and ordered C++ effect/meta output. Once those constraints are retained, the only clearly removable work is C++/Rust call dispatch and some helper/vector allocation. The trace numbers cited by the hypothesis are aggregate worker self-time; normalized by `T=8` and 42 stage executions, `invoke_host_function` self-time is roughly `476.9 ms / 8 / 42 ~= 1.4 ms` per ledger, while the cited `read xdr with budget` plus `write xdr` families add less than another millisecond per ledger before subtracting the portions that must remain or be charge-replayed. That is well below the optimize-soroswap Medium floor of 3% on the current ~300 ms soroswap baseline, and it is not a High-severity dominant-phase redesign because it does not remove the dominant per-tx `Host::invoke_function`/contract execution work.

### Lesson Learned

For Soroban apply optimizations, decoded-value reuse is not automatically a safe wall-clock optimization: XDR decoding, storage-map construction, map scans, clones, and serialization are part of protocol-visible transaction metering. Also, aggregate Tracy self-time from parallel workers must be divided by the active cluster count before projecting close-ledger critical-path savings; otherwise small per-worker setup costs can look like Medium/High opportunities when they are only Low or sub-noise.
