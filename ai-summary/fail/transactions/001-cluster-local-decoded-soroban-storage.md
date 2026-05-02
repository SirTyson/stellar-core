# H001: Reuse Decoded Soroban Storage Across Sequential Cluster Transactions

**Date**: 2026-05-02
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction by removing repeated C++/Rust XDR decode and host storage-map rebuild work inside deterministic parallel-apply clusters
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a soroswap cluster should preserve the exact transaction order within that cluster, the same ledger-entry reads and writes, the same Soroban budget accounting for the active protocol, and the same final `LedgerEntryChange` output. When consecutive transactions in a cluster touch the same contract code/data/TTL keys, the worker should not have to reserialize the updated `LedgerEntry` objects to `CxxBuf`, decode them back into Rust XDR, rebuild a fresh enforcing `StorageMap`, and clone that map again for the initial snapshot on every transaction. The already-sequential cluster execution should be able to carry a deterministic decoded storage cache from one transaction to the next and apply each transaction's successful ledger changes to it.

## Mechanism

`LedgerManagerImpl::applyThread` processes each `TxBundle` in a cluster sequentially, and `ThreadParallelApplyLedgerState` already owns the cluster-local view of modified entries. Despite that, every `InvokeHostFunctionOpFrame::doParallelApply` builds fresh `mLedgerEntryCxxBufs`/`mTtlEntryCxxBufs` in C++, calls the Rust bridge, and `e2e_invoke::invoke_function` reconstructs enforcing storage from those buffers and immediately clones the map for output diffing. Soroswap intentionally round-robins swaps over one pair per cluster, so a large fraction of the read-write footprint is stable across consecutive transactions in the same cluster. A cluster-local decoded-storage cache owned by the worker/thread state, invalidated only by deterministic in-cluster ledger changes and preserving/replicating protocol-visible metering, should remove repeated setup work without changing transaction order or observable ledger output.

## Trigger

Run the current apply-load matrix soroswap scenario (`soroswap, TX=2000, T=8`) from the baseline in `ai-summary/CURRENT_STATE.md`. The issue is triggered by each cluster applying many swaps against the same soroswap pair and SAC balances, causing consecutive worker transactions to rebuild host storage for largely overlapping footprints.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is the deterministic per-cluster sequential loop where a cluster-local decoded storage cache could live.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:385-535` — `addReads` reloads footprint entries from `ThreadParallelApplyLedgerState`, serializes each `LedgerEntry`/TTL entry to fresh `CxxBuf`s, and appends them to bridge input vectors per transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` passes the freshly rebuilt C++ buffers to the Rust bridge for every transaction.
- `src/rust/src/soroban_proto_any.rs:429-448` — the bridge invokes protocol-specific host execution using the per-transaction entry buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452` — `invoke_function` rebuilds the footprint/storage maps from XDR buffers and clones the initial storage map before every host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:493-508` — successful invocations diff final storage against the cloned initial snapshot and emit ledger changes that could update the cluster-local cache.

## Evidence

The current soroswap diagnostic trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Timestamp-filtering zone events inside the 71 `applyLedger` windows gives `applyLedger` wall time of 5,230,315,999 ns and `applySorobanStageClustersInParallel` wall time of 3,520,949,405 ns. The worker aggregate shows `invoke_host_function` at 12,055,276,481 ns, while its child `Host::invoke_function` is 9,824,196,894 ns; the roughly 2.23s aggregate gap is per-invocation setup/finish work around actual contract execution. Related setup/conversion zones inside apply windows include `addReads` at 271,050,094 ns, `read xdr with budget` at 178,988,395 ns, `ScVal to Val` at 995,921,819 ns, `new map` at 449,677,501 ns, and `map lookup`/`map lookup indexed` at 1,123,770,554 ns aggregate. Dividing the removable setup surface by the configured `T=8` cluster parallelism still leaves a Medium-tier wall-time target if a cache removes a material fraction of the fresh-storage rebuild path.

The current SAC diagnostic trace from the same run strengthens the case for the non-soroswap side: inside 28 `applyLedger` windows totaling 2,722,490,387 ns, the aggregate gap between `invoke_host_function` (7,933,595,896 ns) and `Host::invoke_function` (5,074,643,344 ns) is about 2.86s before dividing by the same 8 clusters. This indicates that repeated host setup/finish work is not a soroswap-only artifact.

## Anti-Evidence

This must not become a cross-transaction VM or host-state reuse shortcut: each transaction still needs isolated auth, events, budget, PRNG state, rollback, and result handling. The cache must be limited to deterministic decoded ledger-entry/storage representations, updated only after successful transaction effects have been committed to the thread state, and invalidated for any key modified or deleted by the prior transaction. Current-protocol metering is consensus-visible, so a viable implementation likely needs either next-protocol gating or explicit equivalent charges for XDR reads, map construction, and snapshot/diff work that are physically skipped.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related prior failures covered read-only CxxBuf sharing, read-side pre-serialization, and enforcing-storage Val conversion caches, but not this exact cluster-local decoded-storage combination
**Failed At**: reviewer

### Trace Summary

The repeated setup exists on the Soroban parallel-apply worker path: `LedgerManagerImpl::applyThread` applies transactions sequentially within each cluster, `InvokeHostFunctionOpFrame::doParallelApply` rebuilds C++ `CxxBuf` vectors from the thread ledger state for every transaction, and the Rust bridge rebuilds a fresh `Footprint`, `StorageMap`, TTL map, and initial-storage clone for each host invocation. Successful transactions then return `ledger_changes`, and `ThreadParallelApplyLedgerState::commitChangesFromSuccessfulTx` commits those changes into the cluster-local entry map before the next transaction. However, the proposed cache is not a correctness-preserving current-protocol optimization as framed, and the safely removable portion is smaller than the Medium threshold once aggregate worker times are divided by the configured eight clusters and non-target work is excluded.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is a deterministic per-cluster loop; after each successful `parallelApply`, it commits returned changes into `ThreadParallelApplyLedgerState`.
- `src/ledger/LedgerManagerImpl.cpp:2530-2554` — each cluster runs in its own `std::async` worker, so worker-zone Tracy totals are aggregate parallel work and must be converted to critical-path wall time.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:385-535` — `addReads` loads TTL and ledger entries from the parallel ledger state and serializes them to fresh `CxxBuf`s per transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` passes per-transaction host-function, resource, source-account, auth, ledger-entry, and TTL buffers to the Rust bridge.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — parallel Soroban application constructs an `InvokeHostFunctionParallelApplyHelper` and dispatches the operation through the worker path.
- `src/transactions/ParallelApplyUtils.cpp:988-1001,1084-1121` — `ThreadParallelApplyLedgerState` owns the cluster-local entry map and reads live Soroban entries from `InMemorySorobanState` when not present in the thread map.
- `src/transactions/ParallelApplyUtils.cpp:1164-1252` — successful tx changes are converted into thread-scope entries and committed into `mThreadEntryMap`, with RO TTL bumps buffered separately.
- `src/rust/src/bridge.rs:193-208` and `src/rust/src/soroban_invoke.rs:7-38` — the C++ bridge API accepts byte buffers, not a reusable decoded storage object or host-local handle.
- `src/rust/src/soroban_proto_any.rs:429-448` — protocol dispatch calls the selected protocol host implementation with iterators over the per-transaction buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452` — every invocation decodes resources, builds restored keys and the footprint, builds storage/TTL maps, clones the initial storage map, creates a fresh host, and sets per-tx auth/source/ledger/PRNG state.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:493-508` — successful invocations diff the finished storage against the cloned initial snapshot and emit ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` charges metered XDR reads, derives keys, builds TTL/storage ordered maps through metered inserts, verifies the footprint, and inserts absent footprint keys.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1082` — the initial storage snapshot is a `StorageMap` lookup source used by ledger-change extraction.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:40-46,56-60` — XDR deserialization/serialization charges `ValDeser`/`ValSer` budget inputs that are consensus-visible.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-390` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-225` — enforcing storage writes and map construction use immutable, metered map operations that support rollback/snapshot semantics and charge access/copy costs.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:435-460,543-657` and `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-490` — `ScVal to Val` conversion creates host-local objects and charges object/memory visits; these handles cannot be reused across fresh host instances.

### Why It Failed

The hypothesis combines several real costs, but the proposed cache overstates the safely removable surface. The broad `invoke_host_function` minus `Host::invoke_function` aggregate gap is only an upper bound on all non-contract-execution work around host invocation; it includes resource, auth, source-account, host-function decoding, host setup, diagnostics/events, result encoding, ledger-change extraction, and bridge overhead in addition to storage-map construction. Dividing the cited 2.23s aggregate by `T=8` gives about 279ms, roughly 5.3% of the cited `applyLedger` windows, before excluding all of that non-target work.

The larger cited generic sub-zones are also not fully removable by a cluster-local decoded-storage cache. `ScVal to Val` creates host-local object handles and charges `VisitObject`, heap allocation, memory copy, map/vector construction, and recursive conversion work against the active transaction's budget; those objects live in the fresh `Host` object table and cannot be reused across transactions. `read xdr with budget`, `StorageMap` inserts, footprint/map lookups, `metered_clone`, and XDR writes similarly contribute consensus-visible p26 budget counters. A current-protocol implementation that physically skips those operations must replay exactly equivalent charges and preserve per-transaction host isolation, rollback, initial snapshot, footprint access enforcement, and failure behavior; otherwise it changes resource-limit outcomes.

Once the non-cacheable `ScVal to Val` work and generic map lookups from contract execution/output diffing are excluded, the remaining target resembles the already-reviewed CxxBuf/XDR/map-construction surfaces: `addReads` at 271ms aggregate, `read xdr with budget` at 179ms aggregate, and at most a fraction of `new map` at 450ms aggregate. Even treating that entire 900ms-ish aggregate as removable would convert to about 112ms critical-path time over the traced windows, roughly 2.1% of `applyLedger`; the actual recoverable amount is lower because those zones include necessary validation, footprint setup, budget charging, and non-storage work. Under the optimize-soroswap objective, Low-tier or sub-3% projections are rejected.

### Lesson Learned

Cluster-local sequential execution is useful for carrying committed ledger entries, but it does not make Soroban host storage objects reusable across transactions. For current protocol, decoded-storage optimizations must first separate physical decoding/building from consensus-visible budget charges and host-local object identity; otherwise aggregate `invoke_host_function` setup gaps and generic `ScVal to Val`/`new map`/`map lookup` zones will overstate the removable apply-time impact. Future candidates should target a narrower protocol-gated storage-map build redesign or produce isolated timing that shows a post-metering, physically removable component above the Medium threshold.
