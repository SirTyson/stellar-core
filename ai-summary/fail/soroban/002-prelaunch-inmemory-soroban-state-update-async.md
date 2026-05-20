# H002: Pre-Launch `updateInMemorySorobanState` Async Before Sealing LedgerTxn

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 2-4% soroswap apply-time reduction by overlapping the
in-memory Soroban state update with the serial `addLiveBatch` and
post-tx-set apply work, instead of forcing it to start only after
`getAllEntries` seals the ltx
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Three independent state-update sinks consume the post-apply ledger
delta after `applySorobanStages` returns:
`mInMemorySorobanState` (the in-memory map fed into the next ledger's
parallel apply), `mLiveBucketList` (the on-disk LiveBucket list), and
`mHotArchiveBucketList`. The current code starts
`addHotArchiveBatch` and `updateInMemorySorobanState` as `std::async`
tasks and runs `addLiveBatch` synchronously, joining the two async
futures at the bottom of `finalizeLedgerTxnChanges`. The expected
behavior on a Soroban-only ledger is that the async work begins as
soon as the *Soroban-relevant* delta (CONTRACT_DATA / CONTRACT_CODE /
TTL entries — the only entries `InMemorySorobanState` cares about)
is known: that is, immediately after `globalParState.commitChangesToLedgerTxn(ltx)`
returns at `LedgerManagerImpl.cpp:2709`, before
`processPostTxSetApply` and the `applyStages.clear()` destructors run.
The async update should overlap those serial phases plus the synchronous
`addLiveBatch`, so the apply-thread join at the end of
`finalizeLedgerTxnChanges` rarely waits.

## Mechanism

Currently `updateInMemorySorobanState` is launched at
`LedgerManagerImpl.cpp:3345-3352` *inside* `finalizeLedgerTxnChanges`,
i.e. AFTER `getAllEntries(ltx)` has sealed the ltx
(`LedgerManagerImpl.cpp:3332`). Sealing requires that
`processPostTxSetApply` finished its fee-refund writes and that
`applyStages.clear()` finished its meta-XDR-attached destructors.
Between `applySorobanStages` returning (line 2705 inside
`applySorobanStages`'s caller) and the async launch at line 3345,
the apply thread runs sequentially through:

1. `globalParState.commitChangesToLedgerTxn(ltx)` (line 2709).
2. `processPostTxSetApply` (line 2925) — per-tx refunds and meta.
3. `applyStages.clear()` (line 2956) — destructors.
4. `resolveBackgroundEvictionScan` (line 3242).
5. Eviction processing, hot-archive prep.
6. `evictFromModuleCache`.
7. `maybeSnapshotSorobanStateSize`.
8. `SorobanNetworkConfig::loadFromLedger(ltx)` (line 3329).
9. `getAllEntries(ltx)` (line 3332) — only here is the ltx sealed.
10. `inMemoryStateUpdateFuture = std::async(...)` (line 3345).

All Soroban entries that `InMemorySorobanState::updateState` consumes
(CONTRACT_DATA, CONTRACT_CODE, TTL — see meta-pattern #12 in
`fail/soroban/summary.md`) are written into `ltx` by
`commitChangesToLedgerTxn` at step 1 and are not modified by
`processPostTxSetApply` (which only writes fee-source AccountEntry —
a CLASSIC, non-Soroban entry). Therefore the actual behavior deviates
from the expected behavior: the async update sits idle for the
duration of steps 2-9 (estimated ~5-10 ms/ledger of serial work)
even though all of its inputs are already final at step 1. Rearranging
the code to (a) extract the Soroban subset of entries via a streaming
walk of the ltx entry map without sealing — or, equivalently, by
having `commitChangesToLedgerTxn` materialize a Soroban-keyed
delta vector as it runs — and (b) launch
`inMemoryState.updateState` from that subset immediately after step 1,
moves the async into the gap that it should have been bridging all
along.

## Trigger

Reproduce the soroswap apply-load run as in `CURRENT_STATE.md`.
Profile the soroswap diagnostic Tracy trace and confirm:
(i) `inMemoryStateUpdateFuture.get()` (line 3365) sits behind a
non-trivial wait (i.e., the async finishes after `addLiveBatch`),
which means the join is the critical-path tail; (ii) the wall-time
gap between `commitChangesToLedgerTxn` completing and
`inMemoryStateUpdateFuture` being launched is ~5-10 ms covering
serial steps 2-9 above. If both hold, the rearrangement saves the
gap up to the wall-clock of the async's own work.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2682-2724` — `applySorobanStages`
  block where `commitChangesToLedgerTxn(ltx)` runs at line 2709.
  Soroban entries are fully written to `ltx` here.
- `src/ledger/LedgerManagerImpl.cpp:3334-3366` — current
  `updateInMemorySorobanState` async launch and join inside
  `finalizeLedgerTxnChanges`. The `initEntries`/`liveEntries`/
  `deadEntries` vectors are filled by `getAllEntries(ltx)` at line
  3332, blocking the async until then.
- `src/ledger/LedgerManagerImpl.cpp:3094-3149` — `processPostTxSetApply`
  is the dominant sequential phase between commit and seal; it only
  writes CLASSIC fee-source AccountEntry entries (see
  `TransactionFrame::processRefund:2793-2816`), all of which are
  ignored by `InMemorySorobanState::updateState`.
- `src/transactions/ParallelApplyUtils.cpp:107-...` — `getReadWriteKeysForStage`
  and the global state's commit path, which already segregate Soroban
  vs non-Soroban writes; the same segregation can be reused at the
  delta-extraction site to feed the early async.
- `src/bucket/InMemorySorobanState.{h,cpp}::updateState` — verify the
  inputs it consumes are exclusively CONTRACT_DATA, CONTRACT_CODE,
  TTL entries (Soroban subset).

## Evidence

- Meta-pattern #12 in `fail/soroban/summary.md` confirms that
  `InMemorySorobanState` is the fast path for CONTRACT_DATA /
  CONTRACT_CODE / TTL keys — exactly the subset written by
  `commitChangesToLedgerTxn`. CLASSIC fee-source writes from
  `processPostTxSetApply` are not part of this subset, so the
  in-memory state update has no input dependency on the
  post-tx-set fee-refund phase.
- The current code already proves the three-way independence: the
  in-line comment at `LedgerManagerImpl.cpp:3334-3339` says
  "All three can run in parallel" for `addLiveBatch`,
  `addHotArchiveBatch`, and `updateInMemorySorobanState`. The
  refinement here is that the *start time* of
  `updateInMemorySorobanState` is unnecessarily late: it can begin
  earlier in the apply pipeline because it only needs the Soroban
  subset of the delta, which is fixed at `commitChangesToLedgerTxn`.
- `addLiveBatch` (4.17 ms/ledger sync, ~1.5%) and `processPostTxSetApply`
  combined with the eviction/seal serial work add up to an estimated
  5-10 ms/ledger of wall-clock that is currently *not* overlapped with
  the async InMemorySorobanState update. Even partial overlap of
  ~50% of that gap saves ≥3 ms/ledger; full overlap (with a
  comparable-size async) would save up to ~5-8 ms/ledger ≈ 2-3% of
  the 272 ms baseline. The hypothesis is borderline Medium and
  worth measurement.
- This optimization differs from
  `fail/soroban/021-addlivebatch-as-third-async-future.md` (which
  tried to add a third async at the existing launch point) and from
  `fail/soroban/008-pipeline-finalize-seal-across-ledger-boundary.md`
  (which tried cross-ledger pipelining). Here the change is purely
  intra-ledger: relocate the async kickoff earlier within the same
  ledger close, with no cross-ledger state dependency to manage.

## Anti-Evidence

- `getAllEntries` currently both seals the ltx and produces the three
  output vectors atomically. Splitting it into "extract Soroban
  subset without sealing" + "later seal and extract remainder" is
  invasive — the `LedgerTxn` API does not expose an unsealed walk
  that returns owned vectors. A natural alternative is to populate
  a Soroban-only delta vector inside `commitChangesToLedgerTxn`
  itself (line 2709), where each entry is already being written to
  ltx, capturing only the CONTRACT_DATA / CONTRACT_CODE / TTL
  subset on the fly. This avoids touching the LedgerTxn API at the
  cost of an extra per-Soroban-entry copy in the commit path; for
  ~600 Soroban entries/ledger this is far below 1 ms/ledger.
- `updateInMemorySorobanState` may itself be quick (bounded by the
  Soroban delta size). If its wall-clock is well under the
  `addLiveBatch` wall-clock, the join already completes before
  `addLiveBatch` returns and there is no critical-path saving.
  This must be confirmed by direct Tracy measurement of
  `updateInMemorySorobanState (async)` vs `addLiveBatch` per-ledger
  durations before promoting beyond hypothesis stage.
- `evictFromModuleCache` (line 3311) and
  `addAnyContractsToModuleCache` (lines 3354-3355) read the same
  CONTRACT_CODE entries that `InMemorySorobanState::updateState`
  consumes. If `InMemorySorobanState` writes are racy with the
  module-cache reads, the early launch must hold a barrier at the
  module-cache boundary. For soroswap (no new contracts deployed
  per ledger), the module-cache calls are no-ops, so the practical
  risk is low — but the design must respect the dependency.
- `SorobanNetworkConfig::loadFromLedger(ltx)` at line 3329 reads
  config entries from ltx and is also a Soroban-config consumer.
  The early-launch design must serialize against config-entry
  writes; for soroswap this is a non-event because the network
  config doesn't change per ledger, but the implementation must
  still ensure correctness.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban` or `success/soroban`; cross-subsystem fail/success directories were absent
**Failed At**: reviewer

### Trace Summary

The current ordering is real: `applySorobanStages` commits parallel Soroban changes to the parent `LedgerTxn`, then the apply path runs post-tx-set fee processing and other serial finalization work before `finalizeLedgerTxnChanges` seals the `LedgerTxn` and launches `updateInMemorySorobanState` asynchronously. The data-dependency claim is also mostly right for normal Soroban data: `InMemorySorobanState::updateState` only applies `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` entries, while `processPostTxSetApply` only performs Soroban fee refunds through classic account writes and fee events. However, the performance model is wrong under the objective threshold: moving a task earlier can only save time if the current join waits for that task, and the retained Soroban fail summary already measured the existing async tasks in this finalization fan-out as tiny, with `updateInMemorySorobanState` around 2.5 ms total across the trace.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2672-2724` — `applySorobanStages` applies all parallel stages and calls `globalParState.commitChangesToLedgerTxn(ltx)` before leaving the global state scope.
- `src/transactions/ParallelApplyUtils.cpp:722-801` — `GlobalParallelApplyLedgerState::commitChangesToLedgerTxn` writes dirty global parallel-apply entries into a child `LedgerTxn` via `createWithoutLoading`, `updateWithoutLoading`, or erase, then commits to the parent `ltx`.
- `src/ledger/LedgerManagerImpl.cpp:2922-2963` — after transaction application, the apply thread runs `processPostTxSetApply`, updates metrics, logs, and destroys `applyStages` before ledger finalization.
- `src/ledger/LedgerManagerImpl.cpp:3094-3149` — parallel-phase `processPostTxSetApply` calls each transaction's post-tx-set hook and records fee-processing metadata before finalizing result/meta.
- `src/transactions/TransactionFrame.cpp:2782-2816` — `processPostTxSetApply` delegates to `processRefund`, which updates fee-source account state and emits an after-all-transactions fee event; this is not a Soroban contract-data/code/TTL write.
- `src/ledger/LedgerManagerImpl.cpp:3217-3367` — `finalizeLedgerTxnChanges` resolves eviction, evicts modules, snapshots in-memory-state size, loads final Soroban config, seals the `LedgerTxn` with `getAllEntries`, launches `updateInMemorySorobanState`, compiles new contract code into the module cache, runs `addLiveBatch`, then joins async futures.
- `src/ledger/LedgerTxn.cpp:1695-1737` — `LedgerTxn::Impl::getAllEntries` walks modified entries inside `maybeUpdateLastModifiedThenInvokeThenSeal`, confirming the current API couples vector extraction with sealing.
- `src/ledger/InMemorySorobanState.cpp:537-605` — `updateState` scans `initEntries`, `liveEntries`, and `deadEntries` but acts only on `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` keys, then checks invariants and reports metrics.
- `ai-summary/fail/soroban/summary.md:54` — prior retained measurement of the same `finalizeLedgerTxnChanges` async fan-out states that the two existing async tasks are small, about 38 ms and 2.5 ms total across 70 ledgers.

### Why It Failed

The hypothesis treats the 5-10 ms pre-launch serial gap as recoverable time, but the recoverable time is bounded by the work being moved: the in-memory update. Existing retained measurements show the in-memory update task is the small async task in the current fan-out, roughly 2.5 ms across the whole trace, or about 0.04 ms per ledger. Because the task is launched before synchronous `addLiveBatch` today and `addLiveBatch` is materially larger, the current `inMemoryStateUpdateFuture.get()` should already be hidden in normal soroswap ledgers; launching it earlier cannot convert the whole pre-launch gap into apply-time savings.

Even if an implementation avoided the correctness traps around final Soroban config, contract-code module-cache sequencing, and `LedgerTxn` sealing, the projected top-line impact is far below the optimize-soroswap Medium floor. This is therefore below the objective severity threshold rather than a viable Medium optimization.

### Lesson Learned

For async overlap hypotheses, size the task being moved and the actual join wait, not the elapsed time before the task is launched. A delayed launch only matters when the delayed task is on the critical-path tail; tiny tasks already hidden behind larger synchronous work remain sub-threshold even if their inputs become available earlier.
