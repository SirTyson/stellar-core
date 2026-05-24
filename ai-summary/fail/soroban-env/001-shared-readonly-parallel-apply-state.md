# H001: Shared Read-Only Parallel Apply State

**Date**: 2026-05-24
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing repeated per-cluster copying of common read-only Soroban footprint entries
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each soroswap apply stage, read-only footprint entries that are identical across clusters, such as router code/instance, pair code, and SAC instance entries, should be made available to worker threads without cloning them into every `ThreadParallelApplyLedgerState`. Each transaction should still observe the exact same ledger entry contents, RO TTL bumps should still be buffered and flushed through the existing `mRoTTLBumps` path, and dirty read-write entries should still be isolated per cluster and merged in deterministic stage/cluster order.

## Mechanism

`ThreadParallelApplyLedgerState::collectClusterFootprintEntriesFromGlobal` currently reserves and populates `mThreadEntryMap` by scanning every transaction's read-write and read-only footprint, constructing `ParallelApplyLedgerKey` values, looking them up in the global map, adopting the entry into the thread scope, and inserting them into the thread-local map. The soroswap benchmark's generator gives every swap the same router instance/code, pair code, and SAC instance read-only keys, so this repeats the same immutable-entry adoption work across clusters and stages even though read-only entries cannot be modified by the thread. A shared immutable read-only view in `GlobalParallelApplyLedgerState`, with `ThreadParallelApplyLedgerState` copying only read-write entries plus mutable TTL bump state, would reduce setup/cache pressure without changing deterministic write ordering or exceeding `NUM_CLUSTERS`.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000,T=8`) from the next-protocol baseline. The generated swap transactions at `src/simulation/ApplyLoad.cpp:3447-3457` include common read-only router instance, two SAC instance entries, router code, and pair code keys in each transaction footprint, and `applySorobanStageClustersInParallel` builds a fresh thread state for every cluster of every stage.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:924-986` — scans every cluster footprint and copies both RW and RO global entries into `mThreadEntryMap`.
- `src/transactions/ParallelApplyUtils.h:183-220` — `GlobalParallelApplyLedgerState` already owns stage-spanning global state that could expose an immutable read-only entry view.
- `src/transactions/ParallelApplyUtils.h:128-181` — `ThreadParallelApplyLedgerState` lookup API would need to consult local mutable entries first, then the shared read-only view.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` is the measured apply-path zone that constructs per-cluster thread states.
- `src/simulation/ApplyLoad.cpp:3447-3457` — soroswap swap footprints repeat the same read-only router/SAC/code entries per transaction.

## Evidence

The current Tracy trace records `applySorobanStageClustersInParallel` at `ledger/LedgerManagerImpl.cpp:2537` with 2,691,904,192 ns self-time across 43 calls, all inside `applyLedger`. Its child work includes 15,702 in-apply `parallelApply` calls totaling 22,868,887,892 ns, so reducing per-cluster setup and cache footprint would affect the measured close-ledger envelope rather than TX-set construction. The source shows each `ThreadParallelApplyLedgerState` performs an O(cluster transactions × footprint keys) scan and insertion pass, while the soroswap workload structurally repeats common read-only keys on every swap.

## Anti-Evidence

Prior fail entry `005.md` rejected merely moving thread-state construction onto worker threads because setup is already pipelined with worker execution; this hypothesis must remove duplicated read-only copying rather than just reschedule it. The current comments also say thread states retain no references to global maps because the global structures are not thread-safe, so a viable PoC needs an explicitly immutable shared read-only container and must prove RO TTL bump buffering still accounts for TTL changes correctly.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The duplicated read-only setup work exists: global apply state preloads Soroban read-only entries and TTLs, and each cluster then scans every transaction footprint and copies matching global entries into its own `mThreadEntryMap`. The soroswap generator does place common router, SAC instance, router-code, and pair-code keys in every swap footprint. However, the global preload already deduplicates persistent-state fetches once per ledger close, and the remaining removable work is only per-cluster/thread-state setup: hash/map probes, scope adoption, and local insertion for a small fixed set of read-only keys. Since this setup is pipelined with worker execution and prior parallel-apply review established that `applySorobanStageClustersInParallel` self-time is mostly async wait rather than serial construction, removing only the read-only portion cannot credibly reach the objective's 3% Medium apply-time floor.

### Code Paths Examined

- `src/transactions/ParallelApplyUtils.cpp:386-428` — `GlobalParallelApplyLedgerState` constructs the stage-spanning state before parallel Soroban apply.
- `src/transactions/ParallelApplyUtils.cpp:646-719` — global state already preloads unique Soroban read-only footprint entries and their TTL entries from `InMemorySorobanState`/snapshot once, avoiding repeated live-state fetches.
- `src/transactions/ParallelApplyUtils.cpp:924-986` — each `ThreadParallelApplyLedgerState` still reserves from full RW+RO footprint sizes and scans RW and RO keys, but only inserts a global entry once per cluster because `mThreadEntryMap.find` filters duplicates.
- `src/transactions/ParallelApplyUtils.cpp:1042-1064` — deferred RO TTL bumps are flushed by materializing/upserting mutable local TTL entries, so a shared read-only base would still need local mutable state for bumped TTLs.
- `src/transactions/ParallelApplyUtils.cpp:1084-1121` — thread lookup first checks the local map and otherwise falls back to in-memory state/snapshot; a shared read-only view would need to fit this local-first contract.
- `src/transactions/ParallelApplyUtils.cpp:1164-1252` — successful transaction commits compare against the thread-visible old entry and buffer read-only TTL bumps rather than writing them immediately.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — per-cluster thread state construction occurs immediately before launching each async worker, so later setup is overlapped with earlier worker execution.
- `src/simulation/ApplyLoad.cpp:2672-2682` — soroswap setup creates one pair per configured cluster.
- `src/simulation/ApplyLoad.cpp:3381-3457` — generated swap transactions round-robin pairs and include the repeated read-only router/SAC/code footprint keys cited by the hypothesis.

### Why It Failed

The optimization target is real but too small for this objective. After the existing global read-only preload, the proposed change can only remove per-cluster copies and repeated read-only footprint probes for roughly the fixed read-only key/TTL set, while leaving RW setup, transaction execution, host storage reads, TTL bump materialization, and deterministic merge work intact. The trace's broad `applySorobanStageClustersInParallel` self-time is not a removable-cost estimate because it includes waiting for async workers, and the objective rejects Low/sub-Medium projections.

### Lesson Learned

For parallel-apply setup optimizations, separate unique persistent-state fetches, per-cluster local map setup, and async wait time. A shared read-only view may be a correctness-preserving refactor, but it needs isolated instrumentation showing at least a 3% top-line apply-time ceiling before promotion under the optimize-soroswap objective.
