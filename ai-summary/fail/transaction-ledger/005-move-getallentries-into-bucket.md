# H005b: Eliminate the per-entry LedgerEntry copy in `LedgerTxn::getAllEntries` → `addLiveBatch` → `prepareFirstLevel`

**Date**: 2026-05-26
**Subsystem**: transaction-ledger (ledger / bucket)
**Severity**: Low (sub-threshold)
**Impact**: apply-time reduction (per-modified-entry copies on the
finalize → addLiveBatch path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After all transactions in a ledger have been applied, the modified
entries live in the root `LedgerTxn`'s `EntryMap` and are about to be
discarded once the ltx is destroyed. The expected cheapest path to
publish them to the bucket list is: a single move of each `LedgerEntry`
value from the EntryMap into the eventual `LiveBucket::mEntries`
storage, with at most one intermediate handle (a pointer/iterator), no
deep copies of `LedgerEntry` (CONTRACT_DATA entries can carry several
hundred bytes of SCVal payload), and no rehashing of keys that are
already hashed in the EntryMap.

## Mechanism

`LedgerTxn::Impl::getAllEntries`
(`src/ledger/LedgerTxn.cpp:1695-1737`) walks the EntryMap and calls
`resInit.emplace_back(entry->ledgerEntry())` /
`resLive.emplace_back(entry->ledgerEntry())` — copying every
`LedgerEntry` (by value) into temporary vectors. Those vectors are then
passed by `const&` to **three** sinks in `finalizeLedgerTxnChanges`
(`src/ledger/LedgerManagerImpl.cpp:3322-3367`):
`InMemorySorobanState::updateState`,
`addAnyContractsToModuleCache`, and `BucketManager::addLiveBatch`. The
final sink `addLiveBatch` → `addBatchInternal` → `prepareFirstLevel` →
`mergeInMemory` copies entries AGAIN into the new bucket's `mEntries`
vector. The same `LedgerEntry` value is therefore deep-copied at least
twice per modified entry per ledger.

## Trigger

Run the soroswap apply-load benchmark. Profile the `getAllEntries`
zone and the put-loop inside `mergeInMemory`. Soroswap modifies on the
order of 5,000–10,000 unique entries/ledger (pair balances, reserves,
TTL entries, swap-account entries).

## Target Code

- `src/ledger/LedgerTxn.cpp:1695-1737` — `getAllEntries` deep-copies
  every entry into output vectors.
- `src/ledger/LedgerManagerImpl.cpp:3322-3357` —
  `finalizeLedgerTxnChanges` distributes the vectors to three sinks by
  const-ref.
- `src/bucket/BucketManager.cpp:1026-1046` — `addLiveBatch` const-ref
  parameter signature.
- `src/bucket/LiveBucket.cpp` (`mergeInMemory` / put loop) — second
  deep-copy into the new bucket's `mEntries`.

## Evidence

- Multiple consumers share the same vectors, so a simple `std::move`
  out of `getAllEntries` is impossible — but the deepest copy
  (entry → bucket entries) could be eliminated by changing
  `addLiveBatch` to accept rvalue vectors and routing it FIRST (with
  the other two consumers using a shared-ptr view or the EntryMap
  directly).
- CONTRACT_DATA entries in soroswap include `SCVal` payloads
  (token-balance maps, reserves) on the order of ~200–500 bytes
  decoded; deep-copying 10k of these per ledger is non-trivial.

## Anti-Evidence

- Three independent consumers (`updateState`, `addAnyContractsToModuleCache`,
  `addLiveBatch`) all need access to the same entry set. Eliminating
  the second copy requires either (a) a refactor so one consumer wins
  the move and the others take pointer views, or (b) building a
  shared `vector<shared_ptr<LedgerEntry const>>` upstream.
- `InMemorySorobanState::updateState` already runs asynchronously
  (`std::async` at LedgerManagerImpl.cpp:3345), so the apply-thread
  critical path is only `addAnyContractsToModuleCache` (negligible for
  soroswap — no new CONTRACT_CODE) plus `addLiveBatch` itself.
- The Tracy measurement from fail-file 001 shows the entire
  `addLiveBatch` apply-path stack is ≈ 4.5 ms/ledger (2.1% of 211 ms);
  the put-loop / mEntries copy is a small fraction of that.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — no prior record targets the
`getAllEntries → addLiveBatch` copy chain specifically (greps for
`getAllEntries`, `addLiveBatch.*copy`, `mEntries.*move` over
`ai-summary/`). The closest prior records (H011, fail/001
defer-bucket-output-iterator) targeted bucket-side disk finalize or
whole-batch deferral, not the LedgerEntry copy itself.

### Why It Failed

Upper bound from the measured `addLiveBatch` apply-path envelope
(4.5 ms/ledger; fail-file 001-defer-bucket-output-iterator-getbucket
measured directly). Even if eliminating the second deep-copy halved
the put-loop cost, the savings ceiling is ~1–1.5 ms/ledger ≈
**0.5–0.7% of the 211 ms baseline** — below the 1% Low floor.

`getAllEntries` itself runs serially before the async
`updateInMemorySorobanState` and parallel `addHotArchiveBatch` are
launched, but its share of `finalizeLedgerTxnChanges` is bounded by
the EntryMap walk + emplace_back loop. With ~10k entries at ~200 ns
per emplace + LedgerEntry copy (CONTRACT_DATA `SCVal` copy dominated
by allocator), the upper bound is ~2 ms; halving it (or moving out
of the EntryMap) saves ~1 ms, again below threshold.

Combined with the put-loop saving, the most generous estimate is
~2 ms/ledger = ~1% — at the very edge of the Low floor and below the
Medium threshold this objective requires.

### Lesson Learned

Deep-copy elimination in the finalize→bucket path is bounded above by
the measured `addLiveBatch` envelope (≈ 4.5 ms/ledger). Any
optimization that targets just the copies (rather than the bucket
merge or write-amplification itself) is structurally sub-Medium on
the current 211 ms baseline. Future bucket-path hypotheses should
either restructure the merge algorithm (already
exhausted — meta-pattern 26) or move synchronous work off the apply
thread under the snapshotLedger constraint (also exhausted —
meta-pattern 26).
