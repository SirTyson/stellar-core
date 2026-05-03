# H015: Skip `prefetchTxSourceIds` / `prefetchTransactionData` When All Backing Buckets Use `InMemoryIndex`

**Date**: 2026-05-02
**Subsystem**: ledger / bucket
**Severity**: Low
**Impact**: apply-time (redundant prefetch work)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Prefetching ledger entries before tx apply should only do useful work when
the entries it loads are not already cheap to access via the BucketList
snapshot. When every level's bucket is small enough to use
`InMemoryIndex` (i.e., `LiveBucketIndex` keeps the whole bucket payload in
memory), a `getNewestVersion` lookup against the snapshot is already an
O(1) in-memory read; warming `mEntryCache` ahead of time provides no I/O
savings, only adds key-collection + dedup + insertion overhead on the apply
critical path. The expected behavior is for `prefetchTxSourceIds` and
`prefetchTransactionData` to short-circuit in that case.

## Mechanism

The current short-circuit in
`src/ledger/LedgerManagerImpl.cpp:2448` and `:2463` only trips when
`config.allBucketsInMemory()` returns `true`, which requires
`BUCKETLIST_DB_INDEX_PAGE_SIZE_EXPONENT == 0` (`Config.cpp:2629`). The
default benchmark config keeps the exponent at 14, so both prefetch
functions traverse every tx in the txset, build an `UnorderedSet<LedgerKey>`,
and call `LedgerTxn::prefetch`, which dedups against `mEntryCache` and then
issues a BL snapshot load — even though, in the soroswap benchmark, every
level fits under the 20 MB `BUCKETLIST_DB_INDEX_CUTOFF` and therefore uses
`InMemoryIndex`. Replacing the `allBucketsInMemory()` predicate with a
runtime check ("are all current buckets backed by `InMemoryIndex`?") would
let the same configuration that produces the benchmark also skip prefetch.

## Trigger

Soroswap apply-load benchmark with default
`BUCKETLIST_DB_INDEX_PAGE_SIZE_EXPONENT = 14` and
`BUCKETLIST_DB_INDEX_CUTOFF = 20 MB`: every closed ledger invokes
`prefetchTxSourceIds` once and `prefetchTransactionData` once on a 2000-tx
soroban-only set, both of which proceed past the early-return.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2444-2481` — `prefetchTxSourceIds` and
  `prefetchTransactionData`; both gate only on `config.allBucketsInMemory()`.
- `src/main/Config.cpp:2628-2632` — `Config::allBucketsInMemory()` predicate.
- `src/bucket/LiveBucketIndex.cpp:29-69` — InMemory vs Disk index selection
  (cutoff 20 MB).
- `src/ledger/LedgerTxn.cpp:3103` — `LedgerTxn::prefetch` (the costly
  dedup + BL load body).

## Evidence

Tracy (soroswap, T=8): `prefetchTransactionData` zone totals 117 M ns
(1.65 ms/ledger, 2.24% applyLedger), `prefetchTxSourceIds` totals 50 M ns
(0.7 ms/ledger, 0.95% applyLedger). The inner `prefetch` zone in
`LedgerTxn.cpp:3103` accounts for 145 M ns / 142 calls, confirming both
parents traverse the full early-return-skipped body. With the soroswap
loadgen using a bounded set of source accounts and bucket levels staying
well under 20 MB across the 71-ledger run, the prefetch is loading entries
that are already resident in the level-0 / low-level `InMemoryIndex`.

## Anti-Evidence

Fail/003 (per `summary.md`) already targeted skipping empty Soroban
transaction-data prefetch and was rejected as Low; the meta-pattern in
`summary.md` notes "Prefetch Path Triviality: prefetchTransactionData and
prefetchTxSourceIds are no-ops or near-no-ops for Soroban-only ledgers"
— though Tracy in the current trace shows the parent zones are NOT
no-ops (they fall past the early return because
`allBucketsInMemory()` returns false). The dedup pass inside `prefetch`
exists to avoid duplicate cache writes, and removing it could hide future
bugs where source accounts genuinely need to be loaded from disk under a
different config. Implementing a per-bucket "all-in-memory" runtime check
adds a small amount of state to track and a per-prefetch-call walk of the
BucketList levels.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Failed At**: hypothesis
**Novelty**: PASS — fail/003 attacked "skip when prefetch input is empty";
this attacks "skip when all buckets are in-memory regardless of configured
exponent". Different angle, same code surface.

### Why It Failed

Quantified ceiling is ~1.7% applyLedger (the `prefetch`-zone self-time of
88 M ns extractable cleanly; the rest is structural key-collection that
exists regardless). The two parent zones together total ~3.2% applyLedger,
but ~1.5% of that is the `UnorderedSet<LedgerKey>` build, which is
arguably useful work (it constructs the same key set the cache would need
on miss) and would have to be kept conditionally anyway to preserve the
existing semantics under non-benchmark configs. Net realistic savings
**~1.7%** sits below the Medium 3% bar and is a pure benchmark-shaped
optimization (i.e., it yields nothing in production deployments where
some buckets exceed the in-memory cutoff). The risk of subtly altering
production prefetch behaviour for a Low win on one benchmark is poor
trade.

### Lesson Learned

`allBucketsInMemory()` is a global, config-keyed boolean and conflates two
notions: (a) page-size-exponent tuning, and (b) whether the live bucket
levels actually use `InMemoryIndex`. Any future prefetch optimization
should distinguish these. Also: when revisiting the prefetch path, look
specifically at the *key-collection* loop (which iterates every tx and
calls `insertKeysFor*`) — that is the structural cost that survives all
"skip prefetch" optimizations and is the real ceiling on this code path.
