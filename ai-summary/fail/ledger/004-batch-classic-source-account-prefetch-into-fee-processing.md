# H004: Batch classic source-account fetch directly into `processFeesSeqNums`

**Date**: 2026-05-23
**Subsystem**: ledger
**Severity**: Low
**Impact**: redundant source-account load between `prefetchTxSourceIds` and
`processFeesSeqNums`

## Expected Behavior

Source-account loading for fee processing should happen once per ledger.
Currently `prefetchTxSourceIds` walks all txs and inserts source-account
keys into `LedgerTxnRoot::prefetch`, populating the entry cache. Then
`processFeesSeqNums` iterates the same txs and calls `loadSourceAccount`
which goes through `LedgerTxn::load` → `mEntry` miss → parent
`getNewestVersion` → `LedgerTxnRoot::Impl::getNewestVersion` (cache hit
from prefetch) → copy into ltx `mEntry`. The cache-hit path still
performs entry copy + map insert per tx; combining the two walks could
fetch directly into the apply-thread `LedgerTxn` `mEntry` map in a
single batched pass.

## Mechanism

`prefetchTxSourceIds` (LedgerManagerImpl.cpp:2448) and the
`processFeesSeqNums` (LedgerManagerImpl.cpp:2308) per-tx
`loadSourceAccount` both traverse all source accounts in a ledger.
The prefetch puts entries into `LedgerTxnRoot::Impl::mEntryCache`
without inserting into the apply-thread `LedgerTxn`; the subsequent
fee processing then must re-walk and copy into ltx. A fused
implementation could populate the ltx `mEntry` directly during the
prefetch walk, eliminating the cache-hit relookup-and-copy per tx.

## Trigger

Soroswap benchmark: 226 distinct source accounts per ledger × 71
ledgers = 16,036 source-account fetches. Each tx has a unique source
account so the cache hit path is exercised once per tx (no within-ledger
amortization).

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2448` — `prefetchTxSourceIds`
  collects source-account keys and calls `LedgerTxnRoot::prefetch`.
- `src/ledger/LedgerManagerImpl.cpp:2308` — `processFeesSeqNums` per
  tx calls `tx->processFeeSeqNum(ltx, ...)`.
- `src/transactions/TransactionFrame.cpp:1777` — `processFeeSeqNum`
  loads source account via `ltx.load(accountKey(...))`.

## Evidence

Tracy zones in soroswap trace:
- `prefetchTxSourceIds` self 8.57 ms total / 72 calls = 119 µs/ledger
- `prefetchTxSourceIds` total ~53 ms / 72 = 736 µs/ledger
- `processFeesSeqNums` self 18.0 ms / 72 = 250 µs/ledger
- `processFeesSeqNums` total ~162 ms / 71 = 2.28 ms/ledger

Combined ~3 ms/ledger ≈ 1.4% of soroswap applyLedger baseline. Fusing
to skip the second walk's per-tx cache-hit relookup-and-copy could
recover at most the source-account-load cache-hit overhead, which is
a small fraction of `processFeesSeqNums` (most of which is balance
arithmetic and seqnum updates, not key lookup).

## Anti-Evidence

- Prior fail `002-avoid-ledgertxnroot-cache-hit-relookup.md` already
  rejected `LedgerTxnRoot` cache-hit relookup elimination as sub-Medium
  (~4.3% of applyLedger upper bound, with the recoverable subset much
  smaller).
- Meta-pattern #4 documents that
  `prefetchTransactionData`/`prefetchTxSourceIds` paths are near-no-ops
  for Soroban-only ledgers; even with the classic source accounts they
  do for Soroban fee processing, the cost is small.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail-002 (which targeted the cache-hit
relookup at the `LedgerTxnRoot` layer generally); this targets fusion of
the prefetch+fee-load walks specifically.

### Why It Failed

The recoverable subset is a fraction of the
already-sub-Medium combined `prefetchTxSourceIds + processFeesSeqNums`
budget (~3 ms/ledger ≈ 1.4% of applyLedger). The dominant cost in
`processFeesSeqNums` is balance arithmetic, seqnum increment, and the
ltx-entry creation itself — not the upstream cache lookup. Eliminating
the second cache probe would save perhaps 100-300 ns per tx × 226 txs
= 22-68 µs/ledger ≈ 0.01-0.03% applyLedger. Far below Medium (3%) and
below Low (1%).

Additionally, fusing prefetch with fee processing eliminates the
ordering boundary that allows `prefetchTransactionData` and other work
to run in parallel with `prefetchTxSourceIds` async I/O, which itself
hides latency for slower bucket-backed loads.

### Lesson Learned

Source-account prefetch fusion is structurally sound but the per-tx
relookup cost is well below the Medium floor on a 220+ ms baseline.
Meta-pattern #4 stands: classic prefetch zones for Soroban-only ledgers
cannot yield Medium improvements through fusion or elimination. Combined
with fail-002's `LedgerTxnRoot` cache-hit relookup result, the entire
classic-key lookup chain in the Soroban apply path is exhausted as a
hypothesis source for this objective.
