# H002: Cluster-Local Rust Storage Arena for Sequential Soroswap Invocations

**Date**: 2026-05-26
**Subsystem**: ledger / Soroban parallel apply bridge
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing repeated per-transaction C++/Rust storage-map rebuild and ledger-effect roundtrip work inside ordered conflict clusters
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within a Soroban conflict cluster, transactions must still execute in cluster order. Each transaction should see the ledger effects of prior successful transactions in the same cluster, should roll back only its own failed changes, and should produce the same per-transaction result, events, resource usage, modified entries, restored entries, and final thread/global ledger state as the current `applyThread` loop.

For a next-protocol or internal-apply-only bridge optimization, the worker should not need to rebuild an encoded footprint buffer, decode a fresh Rust `StorageMap`, clone an initial storage snapshot, extract encoded ledger changes, decode them in C++, and commit them back into `ThreadParallelApplyLedgerState` for every transaction when the whole cluster is already an ordered sequence on one worker. A cluster-local Rust storage arena should hold decoded clean entries and committed dirty entries across transactions, with a copy-on-write per-transaction overlay to preserve rollback.

## Mechanism

`LedgerManagerImpl::applyThread` currently calls `TransactionFrame::parallelApply` for each `TxBundle`. The C++ invoke path walks the transaction footprint in `addReads`, builds `CxxBuf` vectors for ledger and TTL entries, calls `rust_bridge::invoke_host_function`, Rust decodes those buffers into a fresh `StorageMap`, clones `init_storage_map`, executes the host, extracts encoded ledger changes, and C++ commits the returned changes into the thread state before the next transaction can run.

A cluster arena would be created once per `ThreadParallelApplyLedgerState` worker from the same entries that C++ already uses to satisfy the cluster footprints. Each transaction would create a fresh `Host` backed by an arena transaction view: reads resolve from the committed arena state, writes go to a tx-local overlay, successful ledger-change extraction commits the overlay to the arena, and failed invocations discard it. At the end of the cluster, C++ receives the same per-transaction `ParallelTxSuccessVal` objects and a final dirty map, but the hot loop avoids rebuilding/deep-copying the shared read-only and repeatedly-mutated Soroswap pool/SAC/TTL entries through the bridge on every swap.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`). The trigger is any Soroban apply stage with ordered clusters of official swap transactions that repeatedly touch the same router, pool, SAC instance/code, SAC balance, and TTL entries. The optimization should be entered only for clusters whose transactions are all handled by the enforcing-mode Rust bridge and whose footprints can be seeded into the arena; unsupported transactions should fall back to the existing per-tx bridge loop.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is the ordered per-cluster hot loop and the natural place to substitute a cluster bridge while preserving cluster order and `NUM_CLUSTERS` parallelism.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-430` and `540-584` — `addReads` builds per-transaction ledger/TTL buffers and `invokeHostFunction` calls the Rust bridge with those buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — Rust rebuilds enforcing storage from per-tx encoded entries, clones the initial storage map, and constructs a fresh `Host`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:556-580` — after execution, Rust finishes the host and extracts ledger changes back into bridge output.
- `src/transactions/ParallelApplyUtils.cpp:925-1001` — thread state construction already knows the cluster footprint and copies global clean entries into the worker state.
- `src/transactions/ParallelApplyUtils.cpp:1003-1121` — read-only TTL flushes and `getLiveEntryOpt` define the C++ semantics the arena must preserve for committed cluster state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — workers are already capped by stage clusters, so the arena adds no extra parallelism and preserves deterministic join/merge order.

## Evidence

The current-state soroswap trace is `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`. Timeline intersection confirms the candidate sits under `applyLedger`: `invoke_host_function` contributes 21,779,331,303 ns over 16,026 in-window events, `addReads` contributes 326,630,230 ns over 16,106 events, `read xdr with budget` contributes 205,940,194 ns over 152,620 events, `recordStorageChanges` contributes 114,784,946 ns over 8,013 events, and `commitChangesFromThreads` contributes 60,310,520 ns over 43 stage events. Aggregate `parallelApply` totals 11,586,376,901 ns over 8,039 calls, with `applySorobanStageClustersInParallel` as the dominant `applyLedger` child.

The source structure shows a repeated roundtrip at the cluster boundary rather than a consensus requirement: the worker is already sequential, and `ThreadParallelApplyLedgerState` is private to the worker until all futures join. Keeping decoded entries in a worker-local Rust arena and committing overlays in transaction order should be deterministic, should not exceed `NUM_CLUSTERS`, and could remove a broader end-to-end slice than prior C++-only encoded-byte or dirty-map proposals because it attacks both sides of the bridge and the per-tx storage snapshot rebuild.

## Anti-Evidence

Several nearby ideas were rejected as too small or unsafe: decoded-input caches, typed host storage ingress, clean-entry borrowing, and dirty-map commit shortcuts. This hypothesis is only distinct if it changes the bridge ownership model for an entire cluster, not if it merely caches one buffer or one decoded entry. The arena must preserve per-tx budget accounting, dense-vs-apply output rules, restored-entry handling, TTL live-until comparisons, auth/event rollback, and C++ `ParallelTxSuccessVal` semantics; if those force materializing the same full maps per transaction, the expected Medium win disappears.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — adjacent failures covered decoded input caches, typed ingress, shared-host batching, and typed native journals, but not exactly this cluster-local Rust storage-arena mechanism
**Failed At**: reviewer

### Trace Summary

The apply path is `applySorobanStageClustersInParallel` -> one `applyThread` per conflict cluster -> per-transaction `TransactionFrame::parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply`. Each transaction currently builds ledger/TTL `CxxBuf`s from `ThreadParallelApplyLedgerState`, calls the Rust bridge, decodes a fresh enforcing `StorageMap`, runs a fresh `Host`, extracts ledger changes, and commits the returned `ParallelTxSuccessVal` into the thread state before the next cluster transaction runs. The repeated storage ingress/egress work is real, but it is only a small subset of the broad `invoke_host_function`/`parallelApply` worker time; the dominant work remains actual host/router/VM/SAC execution and mandatory per-transaction result, event, budget, and rollback handling.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` applies txs in cluster order, flushes RO TTL bumps before each tx, and commits only successful tx changes into the worker state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` launches one worker per cluster and joins all workers before merging, preserving `NUM_CLUSTERS` parallelism and deterministic stage order.
- `src/transactions/TransactionFrame.cpp:2385-2454` and `src/transactions/OperationFrame.cpp:175-188` — per-tx parallel apply dispatch constructs per-op meta/result state and only commits a `ParallelTxSuccessVal` on success.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` performs per-tx TTL liveness/archive/restore checks, resource metering, validation, and owned C++ XDR buffer construction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — the bridge call passes per-tx encoded host function, resources, auth, source account, ledger entries, TTL entries, PRNG seed, rent config, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — C++ decodes returned modified ledger-entry buffers, validates them, writes them into tx state, and treats omitted RW entries as deletes.
- `src/transactions/ParallelApplyUtils.cpp:925-1121` — thread state is seeded from global state, then `getLiveEntryOpt` serves the latest committed cluster state from the worker map or immutable snapshots.
- `src/transactions/ParallelApplyUtils.cpp:1239-1252` and `src/transactions/ParallelApplyUtils.cpp:1285-1408` — each successful tx has a tx-local modified-entry map and restored-entry set that are committed to the thread state; failed tx state is discarded.
- `src/rust/src/soroban_proto_any.rs:391-505` — the Rust wrapper constructs the budget, calls p26 host invocation, extracts rent changes and ledger effects, and packages the exact C++ bridge output.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:490-523` — p26 decodes resources/footprint and ledger-entry buffers, builds a `StorageMap`, shallow-clones the map as the initial snapshot, builds positional metadata, and constructs a fresh `Host`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:549-580` — host execution, `try_finish`, ledger-change extraction, result XDR, and event encoding occur for each transaction.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1013-1151` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267, 323-456` — enforcing storage already has positional side indexes; storage-map clone is a vector/Rc clone, while writes still rebuild the immutable `MeteredOrdMap` vector at known positions.

### Why It Failed

The optimization claim over-attributes the broad `invoke_host_function` and `parallelApply` spans to removable storage ingress work. The measured candidate pieces cited by the hypothesis are small once converted from aggregate worker time to apply-wall impact: `addReads` is about 4.6 ms/ledger aggregate before 8-cluster normalization, `read xdr with budget` about 2.9 ms/ledger aggregate, `recordStorageChanges` about 1.6 ms/ledger aggregate, and the relevant storage-map construction/lookup pieces are similarly only low single-digit aggregate milliseconds per ledger. Dividing parallel worker totals by the configured cluster parallelism puts the realistic wall-clock ceiling well below the 3% Medium floor on the current ~270 ms soroswap apply baseline, and the actual removable subset is smaller because `addReads` also performs mandatory validation, TTL liveness/archive/restore handling, metering, and `mRwKeyExisted` setup.

The proposed arena would also not remove the dominant per-transaction work: fresh host isolation, auth and frame rollback, router/VM/SAC execution, resource accounting, event/result encoding, rent computation, and per-tx success/failure boundaries remain mandatory unless the design becomes a typed native cluster journal. That broader journal direction has been separately reviewed and failed at PoC due to implementation complexity. Under the optimize-soroswap objective, Low-tier or sub-noise storage-ingress savings are rejected even when the inefficiency is real, so this hypothesis is below objective severity threshold (Low not accepted).

### Lesson Learned

For cluster-level Soroban bridge optimizations, isolate the exact removable child work before projecting from broad worker spans. A worker-local cache/arena can reduce repeated storage-map ingress, but it does not make the per-transaction host execution, auth/event/budget semantics, or rollback boundary disappear; Medium-tier wins require removing or redesigning a dominant phase, not amortizing a low-single-digit-millisecond aggregate setup slice across already-parallel clusters.
