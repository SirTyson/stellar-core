# H003: Zero-copy cluster footprint preload (borrow global state entries into thread map)

**Date**: 2026-05-25
**Subsystem**: ledger / parallel apply state setup
**Severity**: Medium
**Impact**: Apply-thread serial setup time reduction in `applySorobanStageClustersInParallel` by eliminating per-cluster `LedgerEntry` deep copies
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`applySorobanStageClustersInParallel` (`ledger/LedgerManagerImpl.cpp:2531`)
builds `ThreadParallelApplyLedgerState` instances sequentially on the apply
thread (lines 2545–2554) before each future is spawned. Each construction
calls `collectClusterFootprintEntriesFromGlobal`
(`transactions/ParallelApplyUtils.cpp:925`), which walks every tx's
read-write and read-only footprint (plus the derived TTL key for each
Soroban key) and, for every key already present in
`GlobalParallelApplyLedgerState::mGlobalEntryMap`, performs a
`scopeAdoptEntryOptFrom(entryIt->second.mLedgerEntry, global)` (line 963).
For the const-ref overload at `ledger/LedgerEntryScope.cpp:489–502`, that
adoption is a **full deep copy** of the wrapped
`std::optional<LedgerEntry>` into a new `ScopedLedgerEntryOpt`. With 8
clusters and ~30 txs/cluster averaging ~10 unique footprint keys + ~10 TTL
keys, this is on the order of several hundred `LedgerEntry` copies per
ledger; for `CONTRACT_CODE` (Wasm blobs up to tens of KB) and
`CONTRACT_DATA` (deeply nested `SCVal` maps for soroswap pair state), each
copy is several microseconds of allocation + memcpy work.

Correct behavior is that thread states must observe the same clean entry
snapshots as the global map for every footprint key. The thread states are
created strictly after `GlobalParallelApplyLedgerState`'s pre-parallel
classic write-back and RO preload finish (the
`DeactivateScopeGuard globalStateDeactivateGuard(globalState)` at
`LedgerManagerImpl.cpp:2543` deactivates the global scope for the duration
of cluster execution), and the global state outlives all thread states
(threads are joined and `threadStates.clear()` runs in `applySorobanStage`
before `globalParState.commitChangesToLedgerTxn(ltx)`). The clean snapshot
in `mGlobalEntryMap` is immutable from the cluster-launch point until
worker join: clusters only mutate their own `mThreadEntryMap`, and
`commitChangesFromThreads` runs after all workers complete.

Given that immutability, the expected behavior of an optimized
implementation is to have each thread's `mThreadEntryMap` *borrow* the
global entry (e.g., a non-owning pointer to
`mGlobalEntryMap[parallelKey].mLedgerEntry` or a shared-pointer indirection
on `mLedgerEntry`) for "clean" entries and only materialize an owned
`LedgerEntry` on the write path (`upsertEntry` /
`commitChangesFromSuccessfulTx`'s dirty branch). Reads via
`getLiveEntryOpt` would resolve through the borrowed pointer, returning the
same value the worker would have observed today.

## Mechanism

Today every clean footprint entry is copied into a thread-local map on
the apply thread before the worker is launched, **serialized across all 8
clusters** because the construction loop at
`LedgerManagerImpl.cpp:2545–2554` builds each `ThreadParallelApplyLedgerState`
before issuing the next `std::async`. Per-ledger this costs on the order
of 2–6 ms of apply-thread serial work — roughly half of the
`applySorobanStageClustersInParallel` self-time after subtracting the
parallel-join wait (Tracy shows ~38 ms/ledger wrapper self-time on the
current soroswap baseline of ~207 ms apply, of which the join-wait for
the slowest cluster of ~25 ms accounts for most of the remainder).
Eliminating the copy collapses the serial setup to a thin pointer-emplace
loop (microseconds per cluster), shifting the first worker start earlier
and shrinking the apply-thread critical path before the join window. This
is a *different mechanism* from the previously-rejected
`001-parallelize-cluster-state-setup` (which kept the copy and moved it
into the workers in parallel — and regressed due to memory-pressure /
cache contention from 8 concurrent footprint walks); this proposal
*removes the copy entirely* rather than parallelizing it, so the
contention pattern that defeated the prior PoC does not apply.

## Trigger

Any apply-load run that exercises the parallel Soroban phase with multiple
clusters. Soroswap (8 clusters × 250 txs, dense footprints with shared RO
contract code + per-pair RW state) is the worst case. Reproducible via
`scripts/run_apply_load_matrix.py` with the standard soroswap and max-sac
scenarios.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:925-986` — `collectClusterFootprintEntriesFromGlobal`; the `scopeAdoptEntryOptFrom` call at line 963 is the deep copy site.
- `src/transactions/ParallelApplyUtils.cpp:988-1001` — `ThreadParallelApplyLedgerState` ctor; receives `global` by const ref and currently materializes copies eagerly.
- `src/ledger/LedgerEntryScope.cpp:486-502` — `scopeAdoptEntryOptFromImpl(const&)`: returns `ScopedLedgerEntryOpt<S>{mScopeID, entry.mEntry}` (deep copy of `std::optional<LedgerEntry>`).
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` — `ThreadParallelApplyLedgerState::getLiveEntryOpt`; the read path that must transparently dereference borrowed entries.
- `src/transactions/ParallelApplyUtils.cpp:1123-1162` — `upsertEntry` / `eraseEntry`; the write path that must materialize an owned copy on first mutation (copy-on-write).
- `src/transactions/TransactionFrameBase.h:107-153` — `ParallelApplyEntry` template; the `mLedgerEntry` storage type would need a variant or pointer indirection to support both borrowed and owned modes.
- `src/ledger/LedgerManagerImpl.cpp:2531-2575` — `applySorobanStageClustersInParallel`; serial setup loop with `DeactivateScopeGuard` proving global state is immutable during cluster execution.

## Evidence

- Tracy `applySorobanStageClustersInParallel` self-time = 2.69 s / 71 ledgers = ~38 ms/ledger (26.16% of trace process time; ~30% of apply per `applyLedger` 4.43 s baseline). The parallel-join wait dominates this, but the serial setup loop is the apply-thread work that pushes the first worker start.
- `collectClusterFootprintEntriesFromGlobal` runs *for every cluster, sequentially* on the apply thread before the corresponding worker is launched. With 8 clusters and a `mGlobalEntryMap` populated by `GlobalParallelApplyLedgerState` before this point (per fail `022-consolidate-globalparapply-footprint-walks.md`'s observation that the global setup walks 4× over all footprints), the per-cluster fetch-from-global is a repeated walk of the same per-cluster footprint.
- For soroswap the shared RO set includes contract code for the router, each pair contract, and 2 SAC tokens — 4–5 large `CONTRACT_CODE` entries (multi-KB Wasm blobs) that get fully copied into each of the 8 thread maps (32–40 large-entry copies/ledger from RO alone).
- The `DeactivateScopeGuard globalStateDeactivateGuard(globalState)` at `LedgerManagerImpl.cpp:2543` is explicit proof that the global state is immutable for the entire cluster-execution window; this is the lifetime invariant a borrowed-pointer redesign needs.
- The recent success `002-cache-old-entry-xdr-sizes` (3.46% Medium win) is precedent that elimination of duplicate per-entry XDR serialization in the Soroban apply path is a Medium-tier lever; this hypothesis is the C++-side analog for entry *copies* rather than entry *serializations*.

## Anti-Evidence

- Meta-Pattern 6 (`Cluster State Parallelism: Memory/Cache Effects`) shows that any change in this region risks regressing the benchmark via cache pressure. The proposed change *reduces* memory footprint (no per-cluster duplicate `LedgerEntry` instances) and *reduces* allocator pressure (fewer deep copies), so the pattern's mechanism does not apply, but final-review must benchmark all three matrix runs to confirm.
- Fail `004-avoid-ledger-entry-copy-in-getliveentryopt.md` rejected an adjacent copy-avoidance idea on `getLiveEntryOpt`'s fallback path; that rejection was because the *fallback* path is cold (preload covers the hot path). This proposal targets the *preload itself* — exactly the path the prior rejection said was the actual perf-relevant site.
- The `ParallelApplyEntry` template + scope system threads a `ScopedLedgerEntryOpt` everywhere, so introducing a borrowed-or-owned variant requires touching read sites (`getLiveEntryOpt`, `commitChangeFromSuccessfulTx`, `commitChangesToLedgerTxn` consumption). The change is structurally significant; it is not a one-line fix.
- The cluster-internal RO TTL flush (`flushRoTTLBumpsInTxWriteFootprint` and `flushRemainingRoTTLBumps`) reads and writes `mThreadEntryMap`; the borrowed-pointer mode must correctly trigger materialization on those write sites as well.
- Quantification is upper-bounded by the apply-thread serial setup chunk of `applySorobanStageClustersInParallel`; if that chunk is closer to ~2 ms/ledger than ~5 ms/ledger, the win drops to Low. Reviewer should add a dedicated Tracy zone around `collectClusterFootprintEntriesFromGlobal` first and quantify before PoC.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — adjacent cluster-state setup and snapshot-copy failures did not investigate zero-copy borrowing of clean global entries
**Failed At**: reviewer

### Trace Summary

The execution path is `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> per-stage `applySorobanStageClustersInParallel`, where the apply thread constructs every `ThreadParallelApplyLedgerState` before launching its worker future. The claimed copy site is real: `collectClusterFootprintEntriesFromGlobal` walks each cluster footprint and uses the const `scopeAdoptEntryOptFrom` overload to copy `std::optional<LedgerEntry>` from the inactive global scope into the thread map. However, that copy only happens for keys already present in `mGlobalEntryMap` and only on the first occurrence per cluster; it does not cover every read-write footprint key, and it does not remove the repeated footprint walk, `ParallelApplyLedgerKey` hashing, TTL-key derivation, map lookups, tx-scope adoption copies, or host execution costs.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2784-2884` — `applyTransactions` loads Soroban config and routes parallel phases into `applyParallelPhase` during `closeLedger`.
- `src/ledger/LedgerManagerImpl.cpp:2967-3029` — `applyParallelPhase` builds stage/cluster `TxBundle`s and calls `applySorobanStages`.
- `src/transactions/ParallelApplyUtils.cpp:386-429` and `646-718` — `GlobalParallelApplyLedgerState` preloads modified classic entries and Soroban read-only entries/TTLs into `mGlobalEntryMap`; read-write Soroban entries are not generally preloaded before the first stage.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` deactivates the global scope, then constructs each thread state serially before `std::async` starts the worker.
- `src/transactions/ParallelApplyUtils.cpp:925-986` — `collectClusterFootprintEntriesFromGlobal` reserves the thread map, scans every tx footprint, derives TTL keys for Soroban entries, and copies only keys found in the global map into `mThreadEntryMap`.
- `src/ledger/LedgerEntryScope.h:278-304` and `src/ledger/LedgerEntryScope.cpp:189-207,486-502` — `ScopedLedgerEntryOpt` stores an owned `std::optional<LedgerEntry>` and the const adoption path deep-copies that optional.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121,1164-1252` — thread reads return owned scoped optionals, successful tx commits compare old/new entries, and RO TTL flushes may mutate the thread map, so a borrow design would require correct owned materialization on dirty paths.
- `src/transactions/TransactionFrameBase.h:107-153` — `ParallelApplyEntry` currently has a single owned `ScopedLedgerEntryOpt<S>` member; supporting borrowed clean entries would require a variant or indirection across clean, dirty, rescope, and final commit paths.

### Why It Failed

The inefficiency exists, but it is below this objective's Medium severity threshold. The hypothesis's own estimate is 2-6 ms/ledger of serial setup work, while the accepted optimize-soroswap Medium floor is at least 3% of apply time (about 6 ms on a ~207 ms baseline, and higher on the newer ~270 ms baseline). The trace also shows the copy count is materially lower than "every footprint key": `collectClusterFootprintEntriesFromGlobal` de-duplicates within the cluster and only copies entries already loaded into the global map, mainly read-only Soroban entries/TTLs and modified classic entries; most Soroban read-write state is loaded or updated elsewhere. A zero-copy clean-entry representation could reduce allocator pressure, but it cannot remove the footprint walk, hashing, TTL derivation, global/thread map probes, tx-level scoped-entry copies, worker execution, or join wait that dominate the enclosing `applySorobanStageClustersInParallel` wall time. Because Low-tier findings are rejected for this objective, this does not proceed to PoC.

### Lesson Learned

For cluster setup hypotheses, isolate the exact materialized payload from the wrapper zone. `applySorobanStageClustersInParallel` includes worker launch, slowest-cluster wait, synchronization, and per-footprint lookup work; eliminating clean-entry deep copies affects only first-touch global-map hits per cluster and must be measured with a dedicated span before claiming a Medium apply-time reduction.
