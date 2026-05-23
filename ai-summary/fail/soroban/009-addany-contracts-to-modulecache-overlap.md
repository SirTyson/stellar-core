# H009: Overlap `addAnyContractsToModuleCache` Walks With `addLiveBatch` Via Async Fan-out

**Date**: 2026-05-23
**Subsystem**: soroban, ledger
**Severity**: Low (sub-threshold)
**Impact**: Soroswap apply-time reduction by removing two serial `initEntries`/`liveEntries` scans from the `finalizeLedgerTxnChanges` critical path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::finalizeLedgerTxnChanges` currently launches two async
futures (`hotArchiveBatchFuture`, `inMemoryStateUpdateFuture`) and then runs
three sequential pieces of work on the apply thread before joining:

1. `addAnyContractsToModuleCache(lh.ledgerVersion, initEntries)`
2. `addAnyContractsToModuleCache(lh.ledgerVersion, liveEntries)`
3. `addLiveBatch(...)` (synchronous)

`addAnyContractsToModuleCache` only walks the entry vectors for `CONTRACT_CODE`
entries and inserts them into the in-memory `ModuleCache`. It does not require
the bucket-list mutation done by `addLiveBatch` and is independent of the
hot-archive update. If non-trivial, it could run concurrently with the existing
async tasks (e.g. by enclosing both walks in a third future or by joining the
two walks with the in-memory state update future) so that only `addLiveBatch`
remains on the apply thread.

## Mechanism

If the two `addAnyContractsToModuleCache` calls account for a meaningful
fraction of the post-`applyTransactions` serial tail, hoisting them into the
existing async fan-out would shorten the apply-thread critical path inside
`finalizeLedgerTxnChanges` and reduce per-ledger apply time. The intuition is
that adding-to-`ModuleCache` is structurally independent of the live-bucket
batch.

## Trigger

Run the soroswap apply-load benchmark and inspect Tracy zones under
`finalizeLedgerTxnChanges`. Each successful close calls both
`addAnyContractsToModuleCache` invocations and `addLiveBatch` synchronously.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3354-3356` — the three sequential serial
  steps after the async fan-out is launched
- `src/ledger/ApplyStateImpl.cpp:addAnyContractsToModuleCache` — the function
  being hoisted
- `src/bucket/BucketManagerImpl.cpp:addLiveBatch` — the synchronous step that
  would remain on the apply thread

## Evidence

Three serial calls share the apply-thread tail between launching the two
existing async futures and joining them. Two of them traverse the
`initEntries`/`liveEntries` vectors which `updateInMemorySorobanState` also
walks asynchronously, suggesting a natural place to fuse the walks.

## Anti-Evidence

`addAnyContractsToModuleCache` only inserts `CONTRACT_CODE` entries into a
shared `ModuleCache`. Soroswap workloads include a single router upload plus
pool factory deploys for the whole benchmark; per-close `CONTRACT_CODE`
entries are typically zero or very small. The per-ledger CPU cost of these
two walks is therefore expected to be a small fraction of a millisecond.

`addLiveBatch` is itself the dominant synchronous step in this tail (Tracy
`addLiveBatch` at 312ms / 71 ledgers ≈ 4.4 ms/ledger). Removing the two
`addAnyContractsToModuleCache` calls from before `addLiveBatch` does not
shorten `addLiveBatch` itself — it can only save the few microseconds the
walks themselves cost.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — distinct from fail/011-async-add-live-batch and
fail/021-third-async-future, which proposed moving `addLiveBatch` itself
off the critical path. This proposal hoists `addAnyContractsToModuleCache`,
not `addLiveBatch`.

### Why It Failed

The target zone is too small to clear any meaningful severity threshold:

- Soroswap closes ingest near-zero `CONTRACT_CODE` entries per ledger; the
  factory uploads happen once during setup and are not part of the measured
  benchmark window. The two `addAnyContractsToModuleCache` calls in
  steady-state degrade to a pair of cheap vector scans with no `ModuleCache`
  insertions.
- Even if the entire `addAnyContractsToModuleCache` aggregate were eliminated,
  the meta-pattern observation that this zone is ≪0.5% of apply time still
  stands. Per the retained `fail/soroban/summary.md` entry on
  `041-merge-addanycontracts-init-live-walks`, the combined walks are
  ~0.03% of apply.
- `addLiveBatch` (4.4 ms/ledger, ~2% of apply) is the actual bottleneck in
  this tail; that has been explored exhaustively (fail/011, fail/021) and
  is structurally blocked because it mutates `mLiveBucketList` which the
  next ledger's apply reads from.

### Lesson Learned

The `finalizeLedgerTxnChanges` serial tail is dominated by `addLiveBatch`.
Any sub-Medium proposal that targets the *other* serial steps in this tail
(`addAnyContractsToModuleCache`, `processFeesSeqNums` mop-up, etc.) cannot
clear the 3% Medium floor while `addLiveBatch` itself remains synchronous.
Future apply-tail proposals must either (a) attack `addLiveBatch` directly
with a determinism-preserving deferral, or (b) demonstrate a tail step
larger than ~0.5% of apply, which the retained fail history shows none of
them are.
