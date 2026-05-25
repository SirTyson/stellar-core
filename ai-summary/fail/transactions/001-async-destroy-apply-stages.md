# H001: Async Destruction of applyStages To Remove TxBundle/TxEffects Teardown From Apply Critical Path

**Date**: 2026-05-25
**Subsystem**: transactions (apply-thread serial teardown of parallel-apply data structures)
**Severity**: Medium
**Impact**: soroswap apply-time reduction (headline)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::applyTransactions` builds a `std::vector<ApplyStage>
applyStages` (each `ApplyStage` is `vector<Cluster>`, each `Cluster` is
`vector<TxBundle>`, each `TxBundle` owns a `unique_ptr<TxEffects>` whose
`TxEffects` holds a `TransactionMetaBuilder`, a `LedgerTxnDelta`, and a
`ParallelPreApplyInfo`). After parallel Soroban apply, after
`processPostTxSetApply` has read everything it needs out of
`applyStages` into `ledgerCloseMeta` and `txResultSet`, and after
the cluster/stage metrics block has run, the function clears the vector
with `applyStages.clear()` at `ledger/LedgerManagerImpl.cpp:2956`. Per
the existing `BUILD_TESTS` instrumentation, this is explicitly timed as
`mLastPhaseTimings.destroyApplyStagesMs`, indicating the maintainers
already recognize this as a measurable serial phase on the apply thread.

A correct apply path should not need to *wait* for this destruction
synchronously before returning from `applyTransactions`. Nothing
downstream in `closeLedger` (`applyUpgrades`, `xdrSha256(txResultSet)`,
`sealLedgerTxnAndStoreInBucketsAndDB`, `finalizeLedgerTxnChanges`,
`ledgerApplied`) reads from `applyStages`. The expected behavior is to
release the apply thread as soon as the data structures are no longer
needed and to move the destruction onto a background worker, so that the
heap-free work overlaps with the rest of `closeLedger`'s serial epilogue
(in particular `finalizeLedgerTxnChanges` / `addLiveBatch`, which is the
dominant remaining serial cost at 7.5% of `applyLedger`).

## Mechanism

In the current code, the destructor chain for `applyStages.clear()`
walks O(stages * clusters * txs) elements and for each `TxBundle`:

1. Destroys the `unique_ptr<TxEffects>`, which destroys:
   - `TransactionMetaBuilder mMeta` — owns `TransactionMetaFrame
     mTransactionMeta` (the protocol-version-tagged XDR union for
     `TransactionMeta` v2/v3/v4, with a sized `xvector<OperationMeta>` /
     `xvector<OperationMetaV2>` whose entries hold `LedgerEntryChanges`
     and per-op `xvector<ContractEvent>`), an `xvector` of
     `OperationMetaBuilder`s (with their own internal pointers /
     references), a `TxEventManager` (with internal `xvector<ContractEvent>`
     for fee events), and a `DiagnosticEventManager`.
   - `LedgerTxnDelta mDelta` — contains an `unordered_map<LedgerKey,
     LedgerTxnDelta::EntryDelta>`, where each `EntryDelta` holds
     `std::shared_ptr<LedgerEntry const>` for current and previous
     versions of the entry. For soroswap with `INVARIANT_CHECKS` empty
     this map is mostly empty (per `checkAllTxBundleInvariants` at
     `LedgerManagerImpl.cpp:2588`).
   - `ParallelPreApplyInfo mParallelPreApplyInfo` — small.
2. Destroys the `TransactionFrameBasePtr` (shared_ptr to const
   `TransactionFrame`) — decrements the refcount; the tx itself is
   long-lived and survives until the `txSet` is released.

Even when `metaEnabled=false` (soroswap benchmark sets
`DISABLE_TX_META_FOR_TESTING=true`), the `TransactionMetaBuilder`
constructor still emplaces a per-op `OperationMeta` in
`mOperationMetas` regardless of `mEnabled` (see
`TransactionMeta.cpp:947-968`). More importantly, soroswap operations
emit real contract events through the Soroban host
(`out.contract_events`) which `InvokeHostFunctionOpFrame::collectEvents`
decodes into `xvector<ContractEvent>` and stores in `success.events`
(fail H029 confirms this materialization happens). Each
`ContractEvent` is a moderately deep XDR union (topics + data,
`SCVal` body). These all live inside the `TransactionMetaBuilder` /
`OperationMetaBuilder` until destruction.

The ACTUAL behavior is that this destructor chain runs serially on the
apply thread, blocking everything downstream until it completes. The
deviation from the expected (overlapping) behavior is that the
critical path through `closeLedger` includes the full destruction time
that could otherwise be free CPU on a background worker.

The proposed change: instead of `applyStages.clear()`, move
`applyStages` (and the `mutableTxResults` vector it transitively
references) onto an apply-thread-local async-destroy queue (e.g., a
`std::async(std::launch::async, ...)` whose lambda owns both vectors
by value, deterministically created exactly once per ledger close, and
whose future is joined either immediately before the next ledger's
apply begins, at process shutdown, or by a bounded-depth ring buffer
that drains in-order). The release-side work then happens on a worker
thread, overlapping with `applyUpgrades` (small), the txResultSet
hash, `sealLedgerTxnAndStoreInBucketsAndDB` (including the dominant
`finalizeLedgerTxnChanges` / `addLiveBatch` at 7.5% of `applyLedger`),
and `ledgerApplied`. Determinism is unaffected because nothing
downstream observes `applyStages`; only the order of memory frees
changes, and frees are commutative.

## Trigger

Run the soroswap apply-load benchmark on the current baseline; add a
`ZoneScopedN("destroyApplyStages")` around `applyStages.clear()` at
`LedgerManagerImpl.cpp:2956` and reproduce on a Tracy-enabled build to
confirm the cost; the gap between `applyTransactions` total
(3,817 ms) and the sum of its measured children (`applyParallelPhase`
3,058 ms + `prefetchTransactionData` 115 ms + `processPostTxSetApply`
28 ms = 3,201 ms) is 616 ms = 13.9% of `applyLedger` and includes the
destruction together with `getPhasesInApplyOrder` (70 ms),
`SorobanNetworkConfig::loadFromLedger` (small), `logTxApplyMetrics`
(small), and per-tx `Medida` metric increments inside
`processResultAndMeta` (~10 ms total). Subtracting the visible
non-destruction work from the gap gives a destruction upper-bound
near ~500 ms = ~11% of `applyLedger`; the actual destruction is the
unmeasured chunk inside that envelope.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2785-2964` — `applyTransactions` —
  replace `applyStages.clear()` (line 2956) with a move onto a
  background destroy queue. The function must also move
  `mutableTxResults` (currently owned by the caller at
  `LedgerManagerImpl.cpp:1678`) into the same queue entry because
  `TxBundle::mResPayload` is a reference into that vector and
  destruction order must keep results alive until all TxBundles are
  destroyed.
- `src/ledger/LedgerManagerImpl.cpp:1678-1688` — caller
  (`closeLedgerImpl`) that owns `mutableTxResults` — adjust ownership
  so the vector can be moved into the destroy queue at the end of
  `applyTransactions`.
- `src/transactions/ParallelApplyStage.h:73-114` — `TxBundle` — verify
  no other members reference apply-thread state with shorter lifetime.
- `src/transactions/TransactionMeta.{h,cpp}` — `TransactionMetaBuilder`
  destructor path — verify thread-safety (it must not call back into
  any apply-thread-only API during destruction; XDR destructors are
  pure value destruction, so this should hold).
- `src/ledger/LedgerManagerImpl.h` — add an apply-thread-local
  destroy-queue member (e.g., a single bounded `std::future<void>`
  joined at the start of the next `applyTransactions`, or a
  `std::deque<std::future<void>>` with a max depth of 2-3 to bound
  memory).

## Evidence

- The maintainers already singled out this exact line as worth
  timing (`mLastPhaseTimings.destroyApplyStagesMs` at
  `LedgerManagerImpl.cpp:2956-2962`), strongly indicating the cost is
  measurable in the BUILD_TESTS instrumentation.
- The unaccounted gap inside `applyTransactions` is 616 ms = 13.9% of
  `applyLedger`. Even attributing only a third of that to destruction
  yields ~4.6% — comfortably Medium-tier.
- Per-tx structures destroyed include `TransactionMeta` XDR (with
  per-op `OperationMeta` xvectors, each with `LedgerEntryChanges` and
  `xvector<ContractEvent>`); for ~110 Soroban txs/ledger across 71
  ledgers, that is ~7,800 deep XDR teardowns concentrated in a single
  serial loop on the apply thread.
- Soroswap operations emit real `ContractEvent`s (transfers, swaps)
  that are decoded and stored in `OperationMeta::events` regardless of
  `DISABLE_TX_META_FOR_TESTING` (since `collectEvents` populates
  `success.events` for the SHA256 result-hash path — confirmed by
  fail H029).
- The destination work to overlap with (`addLiveBatch` at 7.5% of
  `applyLedger`, plus the `finalizeLedgerTxnChanges` epilogue) is
  long enough to fully absorb a several-millisecond per-ledger
  destruction window. Unlike H025 (async addLiveBatch overlapping
  epilogue), here we are running the *cheap* work async and keeping
  the *blocking* bucket work on the apply thread, which means the
  critical-path savings equal the destruction time itself, not
  `min(destroy, epilogue)`. There is no `min()` cap because the apply
  thread continues straight into the next phase while the background
  thread frees memory.
- Pattern is already used in the same function: `addHotArchiveBatch`
  and `updateInMemorySorobanState` are launched as
  `std::async(std::launch::async, ...)` futures in
  `finalizeLedgerTxnChanges`, with futures joined at the natural
  consumer point. The async-destroy pattern uses the same primitive
  with a different join point.
- Determinism: the order of XDR/heap frees is not consensus-visible;
  ledger output (txResultSet hash, ledgerCloseMeta, bucket writes) is
  fully decoupled from when `applyStages`'s memory is released.

## Anti-Evidence

- The unaccounted 616 ms gap also contains `getPhasesInApplyOrder`
  (70 ms total = ~1.6% of `applyLedger`),
  `SorobanNetworkConfig::loadFromLedger` (not separately measured),
  `logTxApplyMetrics`, Medida histogram updates inside
  `processResultAndMeta` (32,945 events at ~298 ns mean = ~10 ms
  total), and TracyPlot calls. The destruction is the residual after
  these are subtracted — needs direct measurement via a Tracy zone
  around the `clear()` call before promotion.
- If most TxBundle internal data is empty under the
  `DISABLE_TX_META_FOR_TESTING + INVARIANT_CHECKS empty + non-meta-mode`
  configuration, the destruction is dominated by `unique_ptr` /
  `shared_ptr` decrement cost (cheap) and the gap is mostly something
  else.
- Async destruction with `std::async(std::launch::async, ...)`
  creates one extra thread per ledger (or one extra task in a thread
  pool); the overhead is sub-millisecond per ledger but non-zero.
- Memory pressure: the background thread holds the per-ledger
  TxBundle/TxEffects memory longer than today. If the destroy queue
  bounded depth is ≥1, that is one extra ledger's worth of TxEffects
  held in memory transiently. For soroswap (~110 Soroban txs/ledger),
  this is bounded and small but non-zero.
- `TxBundle::mResPayload` is a reference; moving requires also moving
  the result vector — a one-time refactor with minor API surface.
- If the bounded-depth queue is depth=1 and joined at the start of
  the next `applyTransactions`, the savings are the *minimum* of
  destruction time and the work between `applyStages.clear()` and the
  next ledger's join point (which is `applyUpgrades` + `txResultSet`
  hash + the *full* `sealLedgerTxnAndStoreInBucketsAndDB` including
  `addLiveBatch` and `finalizeLedgerTxnChanges` — i.e. ~7.5%+ of
  `applyLedger`). Since destruction is bounded above at ~11% and the
  overlap window is at least 7.5%, the *typical* recoverable amount
  is essentially the full destruction time.
- A simpler alternative would be a per-ledger arena allocator for
  TxBundle/TxEffects, making destruction O(1) (just reset the arena);
  this would be a larger refactor across the meta-builder, event
  manager, and XDR allocators. The async-destroy approach is the
  smaller surgical change that captures the same wallclock win
  without changing the allocator strategy.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The serial `applyStages.clear()` is real and is on the `closeLedger` apply path, but the proposed Medium-tier mechanism depends on `TxEffects` retaining deep event/meta XDR until teardown. In the soroswap benchmark config, `METADATA_OUTPUT_STREAM=""` and `DISABLE_TX_META_FOR_TESTING=true` leave `ledgerCloseMeta == nullptr`, so `enableTxMeta` is false and meta/event managers are disabled. Decoded contract events are used for the result hash in `InvokeHostFunctionOpFrame`, but with a disabled `OpEventManager` they are not moved into `TransactionMetaBuilder`; they are destroyed in the worker-local success preimage, before `applyStages.clear()`. When meta is enabled, `processResultAndMeta` finalizes and moves the populated XDR out of the builder before the clear, so the clear still does not own the large finalized meta payload.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1600-1631` — `ledgerCloseMeta` is only constructed for meta streams/debug, or in tests when `DISABLE_TX_META_FOR_TESTING` is false; the benchmark template disables both.
- `src/ledger/LedgerManagerImpl.cpp:2835-2847` — `enableTxMeta` follows `ledgerCloseMeta != nullptr` unless tests force it, and the benchmark's `DISABLE_TX_META_FOR_TESTING=true` prevents that force-enable.
- `src/ledger/LedgerManagerImpl.cpp:2871-2963` — `applyStages` is built, consumed by `processPostTxSetApply`, then cleared synchronously; direct `destroyApplyStagesMs` instrumentation already exists.
- `src/ledger/LedgerManagerImpl.cpp:3093-3141` — with `ledgerCloseMeta == nullptr`, post-tx-set apply writes refunds directly to the parent LTX and `processResultAndMeta` only appends the result pair, without finalizing meta.
- `src/ledger/LedgerManagerImpl.cpp:2727-2781` — `TransactionMetaBuilder::finalize` is only called when `ledgerCloseMeta` exists or BUILD_TESTS meta storage is enabled.
- `src/transactions/ParallelApplyStage.h:19-114` — `TxEffects` owns a meta builder, delta, and pre-apply info; `TxBundle::mResPayload` is a reference, but destruction does not dereference it.
- `src/transactions/TransactionMeta.cpp:924-974,1035-1108` — the constructor allocates per-op placeholder meta even when disabled, but all population/finalization paths are gated by `mEnabled`; enabled meta is moved out by `finalize`.
- `src/transactions/TransactionMeta.cpp:385-463` — ledger changes and return values are skipped when `mEnabled` is false.
- `src/transactions/EventManager.cpp:236-246,503-512,588-593` — `OpEventManager` is disabled when meta is disabled; `setEvents` returns without storing the moved event vector.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:769-816,834-875,879-928,982-1017` — events are decoded into local `success.events` for hashing and then passed to `setEvents`; with disabled meta they are not retained in `TxEffects`.
- `src/simulation/ApplyLoad.cpp:204-258` — current apply-load reporting already subtracts `destroyApplyStagesMs` and prints `| ~apply_stages`, so the previous residual-gap evidence is not a direct measure of this teardown.
- `docs/apply-load-benchmark-sac.cfg:18-24` — the benchmark disables Soroban metrics, transaction meta, metadata output, and metadata debug.

### Why It Failed

The claimed deep destructor chain does not exist in the measured soroswap configuration. `applyStages.clear()` destroys per-tx `TxBundle`/`TxEffects` shells, empty or moved-from metadata builders, empty invariant deltas when invariants are disabled, and shared/unique pointer bookkeeping; it does not destroy the decoded contract events or finalized transaction meta that the hypothesis counts as the dominant cost. The direct `~apply_stages` timing is already available in `ApplyLoad.cpp`, so using the older unaccounted `applyTransactions` residual as a destruction estimate over-attributes unrelated setup/tail work to teardown. Any remaining async-destroy win is a per-tx object teardown micro-cost and falls under the objective's below-Medium class rather than a credible 3-10% apply-time improvement.

### Lesson Learned

For disabled-meta apply-load runs, distinguish transient Soroban success preimages from data retained in `TxEffects`: event decoding still happens, but the decoded event vector is not stored in the meta builder when `OpEventManager` is disabled. Teardown hypotheses should use the explicit `destroyApplyStagesMs` / `~apply_stages` metric, not an `applyTransactions` residual, and should verify whether data has already been moved out or destroyed before the target clear.
