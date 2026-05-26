# H007: Fuse `prefetchTxSourceIds` and `prefetchTransactionData` into a single BL prefetch pass

**Date**: 2026-05-26
**Subsystem**: ledger / pre-apply classic prefetch
**Severity**: Medium
**Impact**: Eliminate one redundant txset scan and one redundant
`LedgerTxnRoot::Impl::prefetch` invocation per ledger
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::applyLedger` is supposed to make a single, complete
sweep of classic ledger keys that the upcoming transactions will read
during fee processing and apply. The intent of the prefetch hooks is to
warm the `LedgerTxnRoot::Impl::mEntryCache` against the live BucketList
snapshot so subsequent `loadHeader`/`getNewestVersion` calls during fee
processing and transaction application skip the bucket scan and return
directly from cache.

Concretely, the expected per-ledger pre-apply pattern is:

1. Collect the union of keys-for-fee-processing AND keys-for-tx-apply
   into a single `UnorderedSet<LedgerKey>`.
2. Call `LedgerTxnRoot::prefetch(keys)` exactly once on that union.
3. Proceed to `processFeesSeqNums` and `applyTransactions`, both of
   which observe a warm cache.

## Mechanism

The current implementation walks the txset twice and invokes the
prefetch path twice per ledger. `applyLedger` calls:

- `prefetchTxSourceIds(...)` at `src/ledger/LedgerManagerImpl.cpp:1659`,
  which iterates every phase × every tx and calls
  `tx->insertKeysForFeeProcessing(keys)` (ParallelApplyUtils.cpp lines
  2451–2459 logical equivalent in LedgerManagerImpl.cpp:2451–2459), then
  calls `ltx.prefetch(keys)`.
- `prefetchTransactionData(...)` at
  `src/ledger/LedgerManagerImpl.cpp:2823` (inside `applyTransactions`),
  which again iterates every phase × every tx and calls
  `tx->insertKeysForTxApply(keysToPreFetch)`, then calls
  `ltx.prefetch(keysToPreFetch)`.

Both routes ultimately reach `LedgerTxnRoot::Impl::prefetch` at
`src/ledger/LedgerTxn.cpp:3101`, which loops over the key set and, for
each key not already present in `mEntryCache`, dispatches the load to
`mSearchableBucketListSnapshot`. Calling it twice with overlapping key
sets means: (a) the second call re-iterates the txset to compute its
key union (CPU cost in `insertKeysForTxApply`), (b) the second
`mEntryCache.exists` check fires for every key that the first call
already loaded, (c) `putInEntryCache` evicts the not-yet-needed
fee-source-id keys if the cache is over capacity, costing the
fee-processing loop a re-load.

A fused pre-apply prefetch would walk the txset once, union the two key
sets, and call `LedgerTxnRoot::prefetch` exactly once.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000,
T=8`). Each ledger contains a mix of classic and Soroban transactions;
both `insertKeysForFeeProcessing` and `insertKeysForTxApply` are
non-empty for every classic transaction, producing overlapping key sets.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2443-2461` — `prefetchTxSourceIds`,
  the first txset scan + prefetch invocation.
- `src/ledger/LedgerManagerImpl.cpp:2463-2481` —
  `prefetchTransactionData`, the second txset scan + prefetch
  invocation.
- `src/ledger/LedgerManagerImpl.cpp:1659, 2823` — call sites that would
  be replaced with a single fused call.
- `src/ledger/LedgerTxn.cpp:3094-3160` — `LedgerTxnRoot::prefetch`, the
  shared implementation that would be invoked once.
- `src/transactions/TransactionFrame.cpp` (and other
  `insertKeysForFeeProcessing` / `insertKeysForTxApply` implementors) —
  the txset-walk source.

## Evidence

The latest soroswap trace
(`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`)
shows:

- `prefetchTransactionData` total 117,385,188 ns / 72 calls ≈ 1.63 ms/ledger
- `prefetchTxSourceIds` total 8,853,369 ns / 72 calls ≈ 0.12 ms/ledger
- `prefetch` (LedgerTxn.cpp:3103) total 145,919,777 ns / 144 calls ≈
  2.03 ms/ledger combined work, of which the per-ledger sum of the two
  prefetch sites is ≈ 1.75 ms/ledger of `LedgerTxnRoot::prefetch` time.

The "double scan" overhead is the difference between
`prefetchTransactionData` + `prefetchTxSourceIds` (1.75 ms) and the
fused single-pass work (estimated ~1.10 ms — one txset walk plus one
`LedgerTxnRoot::prefetch` call against the union key set, which is
typically only ~10–20% larger than either individual set since classic
source-account keys are also referenced as RW keys by their owning tx).

Estimated apply-time saving: ~0.55–0.65 ms/ledger.

## Anti-Evidence

`prefetchTxSourceIds` is intentionally called *before*
`processFeesSeqNums` because fee processing reads source accounts; if
the fused prefetch were deferred to `applyTransactions`, fees would
process against a cold cache. Any fusion must keep the single prefetch
call BEFORE `processFeesSeqNums`, which means moving
`prefetchTransactionData`'s logic earlier in `applyLedger`.

The `LedgerTxnRoot::Impl::prefetch` function already guards against
duplicate loads via `mEntryCache.exists(key, false)`
(LedgerTxn.cpp:3140), so the second prefetch call is not literally
re-loading every key — only iterating the union and probing the cache
for each one.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not duplicated by any prior ledger fail. The closest
prior fails are 003-skip-empty-soroban-prefetch-transaction-data (which
targeted skipping the Soroban-only no-op case) and 015-skip-prefetch-when-all-buckets-cacheresident (which targeted skipping prefetch entirely
when `allBucketsInMemory()` returns true). This proposal targets fusion of the two distinct
call sites, not skipping either one.

### Why It Failed

Quantified ceiling is far below the Medium 3% floor.

- Per-ledger removable work: ~0.55–0.65 ms (the second txset walk and
  the duplicate `mEntryCache.exists` probes plus any redundant
  putInEntryCache evictions). The actual `LedgerTxnRoot::prefetch` BL
  bulk-load work is NOT duplicated by the second call — the entry-cache
  guard at `LedgerTxn.cpp:3140` correctly short-circuits already-loaded
  keys, so the second call only pays the cache-probe cost (~tens of ns
  per key), not the full BL load.
- Apply baseline: 62.1 ms/ledger.
- Maximum saving: 0.65 / 62.1 ≈ **1.05% of applyLedger**, below the
  Medium (3%) and Low (1%) floors.

The structural insight that the second prefetch *path* is not actually
performing redundant disk loads (the EntryCache deduplicates) means the
"two-scan, one-load" pattern is closer to optimal than the gross
double-walk appearance suggests. The remaining cost (txset walk +
duplicate probes) is small in absolute terms because each
`insertKeysForFeeProcessing` / `insertKeysForTxApply` is a trivial
per-tx vector push, and each `mEntryCache.exists` probe is sub-µs.

### Lesson Learned

When a code path *looks* duplicated (two separate `prefetch*` functions
each scanning the same txset), check what the lower-level `prefetch`
implementation actually does before estimating savings. In this case,
`LedgerTxnRoot::Impl::prefetch` deduplicates against `mEntryCache` and
never issues two BL bulk-loads for the same key — so the visible "double
call" is not a "double load." The remaining txset-iteration cost is
sub-Medium and not worth a structural refactor. Future ledger
pre-apply-phase hypotheses must distinguish "two redundant API calls"
from "two redundant disk loads" before projecting savings against the
`prefetch` zone total.
