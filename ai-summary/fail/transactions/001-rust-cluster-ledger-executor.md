# H001: Rust-Side Cluster Ledger Executor for Sequential Soroban Clusters

**Date**: 2026-05-20
**Subsystem**: transactions / Soroban parallel apply
**Severity**: High
**Impact**: Dominant-phase redesign; expected 3-10%+ soroswap apply-time reduction by removing repeated per-transaction C++/Rust ledger-state serialization and host storage-map reconstruction inside each sequential cluster
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban cluster should produce exactly the same per-transaction results, metadata, refundable-fee accounting, restored-entry records, final `ThreadParallelApplyLedgerState`, and deterministic transaction ordering as today's C++ loop. Transactions in a cluster must still execute sequentially and commit or fail independently, but entries already materialized for one transaction in the cluster should not have to be serialized to C++ and re-decoded into a fresh Rust enforcing storage map for the next transaction when the same worker immediately applies the next transaction against the same logical cluster state.

## Mechanism

`LedgerManagerImpl::applyThread` currently applies each `TxBundle` by entering C++, building `CxxBuf` inputs in `InvokeHostFunctionApplyHelper::addReads`, crossing the Rust bridge, constructing a fresh host `Storage`/snapshot in `e2e_invoke::invoke_host_function`, serializing all modified entries back to C++, decoding them in `recordStorageChanges`, and then committing them into `ThreadParallelApplyLedgerState`. In soroswap clusters, this repeats for every swap even though cluster order is already fixed and many footprint entries recur across sequential transactions. A cluster-level Rust executor that owns a typed Rust ledger-state mirror for the cluster, creates a fresh `Host`/`Budget` per transaction, applies each transaction in order, and returns per-tx result/meta plus the final modified-entry map would preserve determinism while removing the C++/Rust encode/decode/storage-map rebuild loop between transactions.

## Trigger

Run the current accepted soroswap apply-load scenario (`soroswap, TX=2000, T=8`). The parallel phase contains sequential clusters that repeatedly call the router/SAC path; each transaction rebuilds host storage from C++ buffers and sends modified entries back through XDR before the next transaction in the same cluster starts.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` is the current per-cluster sequential loop and the natural replacement point for a batched cluster executor.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-553` — `addReads` serializes each footprint entry and TTL entry into `CxxBuf`s for every transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-638` — `invokeHostFunction` crosses the Rust bridge once per transaction with per-tx storage buffers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452` — each invoke decodes resources, builds a fresh footprint and storage map, clones the initial storage map, and constructs a new `Host`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:489-513` — each successful invoke diffs storage and serializes ledger changes back to C++.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — `recordStorageChanges` decodes returned ledger-entry XDR and updates C++ parallel state after every transaction.
- `src/transactions/ParallelApplyUtils.cpp:1240-1252` — `commitChangesFromSuccessfulTx` promotes each transaction's result into the thread state.

## Evidence

The current soroswap trace from `ai-summary/CURRENT_STATE.md` has `applyLedger` at 5,230,315,999 ns across 71 windows. Timestamp-filtered descendants show the cluster worker region dominates apply time: `applySorobanStageClustersInParallel` overlaps `applyLedger` by 3,520,949,405 ns, and `InvokeHostFunctionOpFrame doParallelApply` accounts for 12,664,159,786 ns of parallel-worker aggregate time across 6,776 invokes. The specific roundtrip surfaces are visible inside those workers: `addReads` overlaps by 271,050,094 ns, `addFootprint` by 272,164,347 ns, `recordStorageChanges` by 98,486,607 ns, Rust `read xdr with budget` self-time is 164,491,109 ns, `write xdr` self-time is 150,911,171 ns, `new map` overlap is 449,677,501 ns, and `map lookup indexed` overlap is 543,656,426 ns.

Unlike a micro-optimization to one of these sites, the proposed executor removes the repeated boundary between them for cluster-local state. It also attacks a different mechanism from the previously rejected cluster-local decoded-storage idea: it must not carry metered `HostObject`s or a mutable `Host` across transaction boundaries, only an unmetered typed ledger-state mirror used to seed a fresh per-tx host and to receive the next per-tx ledger change.

## Anti-Evidence

This is a broad redesign and must preserve per-transaction rollback, metering, diagnostics, fee refunds, event ordering, and transaction metadata exactly. The Rust executor cannot reuse a `Host`, budget, storage map with metered objects, or Wasm VM across transactions, because prior investigations found those are transaction-local and rollback-sensitive. A viable PoC also needs a C++ result/meta bridge for every transaction and must cap parallelism at the existing cluster count / `LEDGER_CLOSE_WORKER_THREADS`; the win depends on eliminating enough storage-map/XDR boundary work to overcome the larger bridge surface.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to the prior `001-cluster-local-decoded-soroban-storage.md` failure, but not an exact duplicate because this version avoids carrying `Host`, `Budget`, or metered host objects across transactions.
**Failed At**: reviewer

### Trace Summary

The current path does perform a per-transaction C++ loop inside each cluster: `applyThread` calls `parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply` constructs a new helper, `addReads` serializes entries into `CxxBuf`s, the bridge invokes Rust, Rust builds a fresh `Budget`, `Footprint`, `StorageMap`, initial snapshot, and `Host`, then C++ decodes returned ledger-entry XDR and commits the transaction result into thread state. However, the proposed cluster executor over-attributes broad worker aggregate zones to removable boundary work. A typed Rust ledger-state mirror could remove some physical XDR encode/decode between C++ and Rust, but it cannot remove the fresh per-transaction host/budget/storage isolation, protocol-visible metering unless protocol-gated and exactly redefined, per-tx ledger-change extraction for rent/metadata/results, or the need to report per-tx effects back to C++.

### Code Paths Examined

- `ai-summary/fail/transactions/summary.md:40,78,82` — prior related cluster-local storage reuse was rejected, and the summary records the key review rule that T=8 worker aggregates must be divided by cluster parallelism before severity assessment.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` applies each `TxBundle` sequentially within a cluster, derives the per-tx PRNG sub-seed, flushes RO TTL bumps, calls `parallelApply`, and commits successful tx changes.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — one worker future is launched per cluster and joined before stage merge; per-worker Tracy totals are aggregate parallel work, not serial apply wall time.
- `src/transactions/TransactionFrame.cpp:2385-2430` and `src/transactions/OperationFrame.cpp:183-188` — `parallelApply` checks the pre-validated result, enforces single-op Soroban txs, and dispatches to `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-553` — `addReads` loads each footprint key from the thread/tx state, serializes live entries and TTL entries into `CxxBuf`s, and meters/validates read resources.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-638` — `invokeHostFunction` crosses the Rust bridge once per transaction with host function, resources, auth entries, ledger entries, TTL entries, ledger info, PRNG seed, rent config, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — `recordStorageChanges` decodes each returned `LedgerEntry`, validates/meter-writes it, matches it against the RW footprint, upserts/deletes in `TxParallelApplyLedgerState`, and preserves create/delete semantics.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — the parallel helper still executes `addFootprint`, host invocation, storage-change recording, event collection, refundable-resource consumption, and success finalization per transaction.
- `src/transactions/ParallelApplyUtils.cpp:1084-1120` — thread-state reads first consult the per-thread dirty map, then in-memory Soroban state or the live snapshot, so the C++ state is already a cluster-local logical view.
- `src/transactions/ParallelApplyUtils.cpp:1240-1252` and `src/transactions/ParallelApplyUtils.cpp:1285-1332` — successful tx changes are promoted from per-tx state to thread state, and `lastModifiedLedgerSeq` is applied in C++ state after Rust returns.
- `src/rust/src/bridge.rs:193-208` and `src/rust/src/soroban_invoke.rs:7-61` — the public CXX bridge is explicitly a single-invocation API that accepts per-tx vectors of encoded ledger entries and TTL entries.
- `src/rust/src/soroban_proto_any.rs:391-506` — each bridge call creates a fresh `Budget`, invokes the protocol-specific host, reads consumed CPU/memory, computes rent from ledger changes, extracts encoded ledger effects, and returns per-tx result/events/effects.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452` — each invoke decodes resources, restored keys, footprint, storage map, clones the initial storage map, constructs enforcing `Storage`, and creates a fresh `Host`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:489-513` — successful invokes still diff storage against the initial snapshot, write encoded keys/new values for rent and effects, encode events, and return per-tx ledger changes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:230-238` — storage-map construction is per-tx and footprint-enforcing; a typed mirror could seed it, but a fresh enforcing map and initial-state view are still required for rollback/diff correctness.

### Why It Failed

The inefficiency exists, but the claimed Medium/High impact does not survive the trace. The hypothesis cites aggregate worker timings from eight parallel lanes as if they were serial apply time. The directly removable C++/Rust boundary surfaces are bounded by approximately `addReads` 271.1 ms + `recordStorageChanges` 98.5 ms + Rust `read xdr with budget` 164.5 ms + Rust `write xdr` 150.9 ms = 684.9 ms of aggregate worker time; divided by T=8 this is about 85.6 ms over 5,230.3 ms of `applyLedger`, or roughly 1.6% before implementation overhead. `addFootprint` overlaps `addReads`, while broad `new map` and `map lookup indexed` zones include mandatory host storage/diff/contract-map work that a cluster bridge cannot simply delete.

Correctness constraints further shrink the addressable surface. The executor must still create a fresh per-tx `Budget` and `Host`, enforce the transaction footprint, preserve per-tx rollback, compute rent from per-tx ledger changes, emit per-tx result/meta/events/refundable-fee data, preserve `lastModifiedLedgerSeq` and INIT/LIVE/DELETE state, and provide per-tx deltas for invariant checks. Skipping `metered_from_xdr_with_budget`/`metered_write_xdr` charges in the current protocol would change resource-limit behavior; keeping equivalent charges preserves correctness but removes only physical serialization CPU, not the budget-accounting semantics. The remaining safe improvement is below the objective's 3% Medium threshold.

### Lesson Learned

A cluster-level Rust executor is a broad architectural idea, but for this objective it must be justified from isolated critical-path measurements of work that actually disappears. Worker-aggregate Soroban host/storage zones must be divided by cluster parallelism and narrowed to physical boundary overhead; fresh per-tx host isolation, metering, diff/rent extraction, and per-tx C++ effects are mandatory unless a separate protocol-gated redesign explicitly changes those semantics.
