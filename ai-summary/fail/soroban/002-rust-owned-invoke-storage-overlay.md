# H002: Move Invoke-Host Footprint Materialization and Writeback Into a Rust-Owned Cluster Storage Overlay

**Date**: 2026-05-03
**Subsystem**: soroban / transactions / ledger
**Severity**: High
**Impact**: Dominant-phase apply-time redesign that removes per-transaction C++/Rust ledger-entry XDR round trips and repeated storage-map snapshots on the soroswap invoke path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each Soroban transaction, the host should see exactly the same footprint entries, TTLs, restored entries, and prior successful cluster writes that it sees today. Successful invoke-host operations should produce the same modified entries, TTL bumps, events, refundable-fee accounting, and metadata; failed operations should not mutate the cluster overlay. The observable transaction order and final `GlobalParallelApplyLedgerState::commitChangesFromThreads` output must remain identical to the current deterministic C++ writeback path.

## Mechanism

Today `InvokeHostFunctionParallelApplyHelper::doApply` first materializes a transaction footprint in C++ (`addFootprint`/`addReads`), serializes ledger entries and TTL entries into `CxxBuf`s, asks Rust to decode them into a `StorageMap`, clones that map as `init_storage_map`, executes the host, computes Rust-side ledger changes by diffing against the clone, returns encoded changes, and finally records them back into `TxParallelApplyLedgerState` in C++. This repeats for every transaction even when a cluster is already sequential and all later reads must observe earlier writes. A Rust-owned per-cluster storage overlay, initialized once from `ThreadParallelApplyLedgerState` and updated after each successful host invocation, could feed p26 `Storage` directly and return per-transaction deltas without rebuilding an XDR-backed `StorageMap` and old-entry snapshot from C++ buffers every time.

## Trigger

Run the current soroswap apply-load benchmark. Each swap transaction has a small but non-empty Soroban footprint, and a cluster worker executes hundreds of such transactions in sequence. The issue is triggered when every transaction independently performs C++ footprint materialization, Rust storage-map construction, Rust old-map cloning, Rust diffing, and C++ writeback even though the cluster already has a natural sequential overlay that could own those transitions once.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:540-553` — `addFootprint` walks read-only/read-write keys and builds per-transaction C++ ledger-entry/TTL buffers.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` passes those encoded entry buffers into Rust for one transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:643-760` — `recordStorageChanges` decodes Rust output and mutates the C++ parallel-apply transaction state.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-451` — Rust decodes resources, builds the footprint/storage map, and clones `init_storage_map`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:493-508` — Rust diffs final storage against the cloned initial map after each successful transaction.
- `src/transactions/ParallelApplyUtils.cpp:925-1000,1321-1457` — thread/tx parallel apply states already define the deterministic overlay boundaries that a Rust-owned cluster overlay would mirror.

## Evidence

The diagnostic trace shows the relevant path entirely under `applyLedger`: `addFootprint,transactions/InvokeHostFunctionOpFrame.cpp,540,272164347 ns,6824 calls`, `recordStorageChanges,transactions/InvokeHostFunctionOpFrame.cpp,643,98486607 ns,6776 calls`, and the surrounding single-transaction `invoke_host_function,soroban-env-host/src/e2e_invoke.rs,488,12055276481 ns,6776 calls`. Prior retained failures rejected narrower XDR-buffer and `addReads` micro-optimizations because each sub-slice was below Medium; this hypothesis targets the larger architectural round trip in which C++ and Rust reconstruct, clone, diff, serialize, and deserialize the same footprint state per transaction instead of maintaining one ordered cluster overlay. Because the cluster is already sequential, this can preserve determinism without adding workers or changing transaction ordering.

## Anti-Evidence

The low-level `addFootprint` and `recordStorageChanges` zones alone are below the Medium floor, so the PoC must demonstrate that the end-to-end storage-overlay redesign removes a much larger portion of `e2e_invoke` setup/diff/writeback than those visible C++ wrappers. The CXX bridge does not currently support Rust borrowing C++ `ThreadParallelApplyLedgerState`, and introducing such a bridge risks lifetime and aliasing bugs; a safer implementation may need a Rust-owned mirror of only Soroban entries. Exact p26 metering must be preserved: if storage-map clone/diff charges change, the optimization must be protocol-gated and update observation expectations rather than silently changing released behavior.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/001-cluster-rust-invoke-batching.md`
**Failed At**: reviewer

### Trace Summary

The claimed per-transaction storage round trip is real: each cluster worker calls `TransactionFrame::parallelApply`, which reaches `InvokeHostFunctionOpFrame::doParallelApply`, materializes per-transaction footprint entries into `CxxBuf`s, crosses the single-transaction Rust bridge, constructs a fresh p26 `StorageMap`, clones the initial map for diffing, and then decodes returned ledger effects back into the C++ transaction overlay. However, this is substantially the same cluster-level Rust bridge/overlay redesign already reviewed in `001-cluster-rust-invoke-batching.md`. That prior review traced the same apply-thread cluster loop, single-tx bridge boundary, p26 `e2e_invoke` storage setup/diff path, and C++ `TxParallelApplyLedgerState`/`ThreadParallelApplyLedgerState` write-forward semantics, and explicitly rejected the Rust-owned overlay variant as an unmeasured redesign whose safe removable slices overlap known sub-threshold failures.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` runs transactions sequentially inside a cluster, derives per-tx PRNG seeds, calls `parallelApply`, and commits only successful tx effects before the next transaction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — `applySorobanStageClustersInParallel` constructs one `ThreadParallelApplyLedgerState` per cluster and waits for the cluster workers in the apply path.
- `src/transactions/TransactionFrame.cpp:2385-2454` — `parallelApply` dispatches the single Soroban operation, sets per-op meta changes, and marks failed txs without committing effects.
- `src/transactions/OperationFrame.cpp:175-188` — operation parallel apply delegates directly to the concrete `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-553` — `addReads`/`addFootprint` walk the per-tx footprint, consult the C++ parallel ledger state, validate/meter entries, and build ledger-entry/TTL `CxxBuf` vectors.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` calls the current single-transaction Rust bridge with encoded host function, resources, source, auth, ledger entries, TTL entries, PRNG seed, rent config, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — `recordStorageChanges` decodes Rust-returned modified ledger entries and records the resulting upserts/deletes in `TxParallelApplyLedgerState`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1100-1285` — the parallel helper owns autorestore bookkeeping and feeds restored entries into the per-tx C++ overlay before invoking Rust.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — `ThreadParallelApplyLedgerState::getLiveEntryOpt` first checks the thread overlay, then `InMemorySorobanState` or the LCL snapshot.
- `src/transactions/ParallelApplyUtils.cpp:1165-1252` — successful tx effects are merged into the thread overlay and RO TTL bumps/restores are preserved for later txs in the same cluster.
- `src/transactions/ParallelApplyUtils.cpp:1285-1408` — `TxParallelApplyLedgerState` owns per-transaction modified entries and returns no modified map on failure, preserving rollback.
- `src/rust/src/bridge.rs:193-208` — the CXX bridge exposes only the single-transaction `invoke_host_function` entry.
- `src/rust/src/soroban_invoke.rs:7-61` — Rust dispatch forwards one transaction's buffers to the protocol-specific host module.
- `src/rust/src/soroban_proto_any.rs:391-557` — the protocol wrapper creates a fresh per-tx budget, panic/error boundary, diagnostics, rent-fee computation, and serialized output.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — p26 invocation decodes one transaction's resources/footprint/storage/auth/source/function, clones `init_storage_map`, invokes the host, and computes per-tx ledger changes/events on success.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes encoded entries and TTLs into a fresh `StorageMap`/TTL map for each invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:180-292,1068-1083` — `get_ledger_changes` compares final storage against the initial snapshot and serializes per-entry changes for the C++ writeback path.

### Why It Failed

This hypothesis is not novel. `001-cluster-rust-invoke-batching.md` already reviewed the same structural idea: move from per-transaction C++/Rust invoke calls toward a cluster-level Rust boundary with a deterministic cluster-local overlay while preserving independent budgets, auth, events, rollback, result/meta output, refundable fees, PRNG seeds, and C++ parallel-apply commit semantics. It also specifically addressed the Rust-owned overlay angle, noting that it would have to duplicate `TxParallelApplyLedgerState`/`ThreadParallelApplyLedgerState` ownership, autorestore, rollback, write-forward, and per-tx effect/meta interfaces while still returning ordered per-transaction effects to C++.

The new file adds more detail around `addFootprint`, `recordStorageChanges`, `build_storage_map_from_xdr_ledger_entries`, and `init_storage_map`, but it does not supply the dedicated measurement the prior review required for the removable C++/Rust ledger-entry round-trip slice. The visible C++ wrapper zones are below the objective floor by themselves, and prior retained failures already bounded related pieces: bridge preparation and `addReads` serialization were sub-Medium, old-entry output XDR materialization produced no benchmark improvement when metering was preserved, in-place `StorageMap` updates changed protocol-visible metering and regressed, and lazy rollback snapshots were also below the Medium threshold. Without a new isolated measurement and a concrete semantics-preserving overlay design, this is a duplicate of the retained failed investigation rather than a viable Medium-or-better optimization hypothesis.

### Lesson Learned

A Rust-owned cluster storage overlay should not be reproposed from broad `invoke_host_function` or C++ wrapper timings. To be novel, it must first isolate the actual removable storage decode/clone/diff/writeback cost, distinguish p26 metered work from implementation overhead, and specify how it preserves the existing C++ parallel-apply overlay, autorestore, rollback, meta, and fee interfaces without duplicating more work than it removes.
