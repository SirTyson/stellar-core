# H024: Asynchronously Destroy ThreadParallelApplyLedgerState Objects Between Soroban Stages

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / parallel apply orchestration
**Severity**: Low
**Impact**: Apply-thread serial destruction overhead between Soroban stages
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In `LedgerManagerImpl::applySorobanStage` (`src/ledger/LedgerManagerImpl.cpp:2623`),
after `applySorobanStageClustersInParallel` returns and `commitChangesFromThreads`
folds per-thread maps into the global state, each `ThreadParallelApplyLedgerState`
object owns a populated `mThreadEntryMap` (with hundreds-to-thousands of
`ThreadParallelApplyEntry` values, each holding a scoped `LedgerEntry`),
plus per-thread `RestoredEntries` and RO TTL bump buffers. The expected behavior
is that these per-thread containers are destroyed lazily and off the synchronous
apply critical path so that the next stage's setup (or the subsequent
`globalParState.commitChangesToLedgerTxn` work) can begin immediately after the
fold-back completes. In particular, between two stages of the same ledger
(rare for soroswap, common for any multi-stage workload), the destruction of
stage N's thread states would not block stage N+1's `GlobalParallelApplyLedgerState`
splitting.

## Mechanism

The current implementation calls `threadStates.clear()` inline on the apply
thread at `LedgerManagerImpl.cpp:2664` (with a `BUILD_TESTS`-gated timer
`sorobanDestroyThreadStatesMs`). This clear destroys every
`unique_ptr<ThreadParallelApplyLedgerState>`, which in turn destructs:
- `mThreadEntryMap` (`UnorderedMap<ParallelApplyLedgerKey, ThreadParallelApplyEntry>`)
  — for soroswap, ~250 txs/cluster × 8–10 entries each, so up to ~2,500
  entries per thread state, dominated by `ContractData`/`Balance` payloads.
  Hash-table tear-down plus `optional<LedgerEntry>` destruction is bounded by
  per-bucket linked-list traversal and per-entry XDR variant tear-down.
- `mThreadRestoredEntries` (two `UnorderedMap<LedgerKey, LedgerEntry>`) —
  usually empty for soroswap.
- `mRoTTLBumpsToFlush` and `mPreviouslyRestoredEntries` — small.

For a single-stage soroswap ledger, this destruction happens once after the
sole stage and immediately before `commitChangesToLedgerTxn`. There is no
per-stage overlap opportunity because the very next call on the apply thread
is also serial work. A novel fan-out would be to detach destruction to
`std::async(std::launch::async, ...)` and let it complete in the background,
not joining until ledger close ends.

## Trigger

Run the soroswap apply-load benchmark and observe the `applySorobanStage`
zone tail after `commitChangesFromThreads`. The destruction pass walks the
8 thread entry maps; each map releases ~2k–2.5k ContractData/TTL `LedgerEntry`
objects (variants with embedded `xdr::xvector<...>` releases).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2664` — `threadStates.clear()` inline
  destruction at the end of each stage.
- `src/transactions/ParallelApplyUtils.cpp` — `ThreadParallelApplyLedgerState`
  destructor implicitly destroys `mThreadEntryMap`, `mThreadRestoredEntries`,
  and `mRoTTLBumpsToFlush`.

## Evidence

- Per-stage thread map carries the cluster's footprint × tx count entries.
  For 8 clusters × ~250 txs × ~10 entries each, total entries across thread
  maps for a soroswap ledger is on the order of 20,000.
- Each entry destruction releases a `ScopedLedgerEntry` wrapper plus an
  `optional<LedgerEntry>` (XDR variant containing nested `xdr::xvector` /
  `xdr::xstring` allocations).
- `unordered_map` tear-down is sequential and unparallelizable per-map, so
  releasing the work via `std::async` is the only structural escape.
- Fail patterns on similar move/destroy hypotheses (e.g., 6bc4800c6 reverted
  "overlap per-thread commit with parallel execution +13.6% TPS") show the
  pipeline is sensitive to changes in this region.

## Anti-Evidence

- Soroswap exercises a single Soroban stage per ledger, so no second-stage
  setup exists to overlap with the first stage's destruction. The only
  available overlap window is between the last stage's destruction and the
  serial work that follows in `applySorobanStages` (the final
  `commitChangesToLedgerTxn`), but `commitChangesToLedgerTxn` reads from
  `mGlobalEntryMap` which already owns all the moved-from entries.
  Detaching the now-empty `unique_ptr` destructions buys nothing — the
  thread states have been moved out of by `commitChangesFromThreads` (entries
  use `std::move(entry)` at `ParallelApplyUtils.cpp:902`), so destruction
  walks an effectively empty map (each `ThreadParallelApplyEntry` is
  moved-from with `mLedgerEntry` reset to nullopt).
- After move-out, the only remaining work is releasing the hash table's
  bucket array and small per-slot metadata. For a 2,500-bucket
  `unordered_map`, this is sub-millisecond per thread state, and 8 thread
  states give ~2–4 ms aggregate at the absolute upper bound — orders of
  magnitude below the 3% Medium floor (~9 ms/ledger) once you account for
  the work that has actually been moved away.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a standalone optimization
target in fail/transaction-ledger, fail/transactions, or fail/ledger.

### Why It Failed

The optimization target is materially empty. After `commitChangesFromThreads`
runs at `ParallelApplyUtils.cpp:898`, it iterates `thread.getEntryMap()` and
calls `commitChangeFromThread(thread, key, std::move(entry), readWriteSet)`,
moving every `ThreadParallelApplyEntry` out of the thread's map. By the time
`threadStates.clear()` runs, the entry maps contain only moved-from values
whose `mLedgerEntry` scoped wrappers no longer own the underlying
`optional<LedgerEntry>`. Destruction is therefore reduced to releasing the
`unordered_map` bucket arrays plus the small `RestoredEntries` and RO TTL
bump containers. In aggregate this is sub-millisecond per cluster, and the
soroswap workload runs a single stage per ledger so there is no
inter-stage overlap window to exploit — only an after-the-last-stage detach,
which would race the `globalParState.commitChangesToLedgerTxn` call that
runs immediately after.

Even the most optimistic detach would shave 1–2 ms off the apply tail, well
below the 3% Medium floor. The proposal is therefore a Low-tier optimization
at best, and Low is not accepted at the hypothesis stage for this objective.

### Lesson Learned

When a destruction pass appears to walk a large container, verify whether
upstream code has already moved the contents out via `std::move`. The
`commitChangeFromThread` fold in parallel apply already drains thread entry
maps before the inline `threadStates.clear()` call, so the destruction is
near-empty work. Any future "destroy thread states off-thread" hypothesis
must first show measurable destruction time on the apply critical path
under non-Tracy timing.
