# H002: Flat Cache-Local InMemory Bucket Index for Residual `scan` Cost

**Date**: 2026-05-03
**Subsystem**: soroban / bucket / ledger apply
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in BucketList point loads used by fee processing and parallel Soroban reads
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Small live buckets that are fully resident in memory should answer `BucketListSnapshot::load` probes with the same newest-entry/tombstone semantics and the same deterministic ledger output as today, but the lookup should be cache-local. A point lookup should not chase an `std::unordered_set` node, then chase a `shared_ptr<BucketEntry const>`, and then compare through scattered bucket-entry storage for every bucket level probed.

## Mechanism

The accepted `001-inmemory-bucket-scan-polymorphic-wrapper` success removed the old per-query heap allocation and virtual-dispatch wrapper, but the current `InMemoryBucketState` still stores entries in `std::unordered_set<InternalInMemoryBucketEntry>` (`src/bucket/InMemoryIndex.h:79-98`) and performs `mEntries.find(searchKey)` for every `scan` (`src/bucket/InMemoryIndex.cpp:249-262`). Each stored element is a node allocation containing a cached hash plus a `shared_ptr` to the bucket entry, so high-volume soroswap loads still pay hash-table bucket indirection, node pointer chasing, poor locality, and `LedgerKey` equality on collision.

A flat index representation can preserve the current external API while replacing the node hash table with cache-local vectors built once at bucket-index construction. For example, store per-entry records `{cached_hash, entry_ptr}` grouped by `LedgerEntryType` and sorted by `(cached_hash, ledger-key-order tie-breaker)`, then implement `scan` as a lower-bound over the relevant type vector followed by exact `keyEquals` checks for matching hashes. This is not the rejected hash-only optimization: the proposed win is removing the residual unordered-set node walk and improving locality for every in-memory bucket probe, while still computing the query hash once and doing exact key comparison before returning an entry.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) with the diagnostic trace from `ai-summary/CURRENT_STATE.md`. Fee-source/account loads and BucketList-backed reads enter `SearchableBucketListSnapshot::load`, which walks live bucket levels and calls `getBucketEntry`; for small buckets below the default in-memory-index cutoff, `LiveBucketIndex::scan` reaches `InMemoryBucketState::scan` for each probed level.

## Target Code

- `src/bucket/InMemoryIndex.h:19-98` — `InternalInMemoryBucketEntry` and `InMemoryBucketState`; replace the unordered node set with a flat per-type index while retaining exact entry pointers and `keyEquals` checks.
- `src/bucket/InMemoryIndex.cpp:241-262` — `InMemoryBucketState::insert` and `scan`; build/search the flat representation instead of `mEntries.find(searchKey)`.
- `src/bucket/InMemoryIndex.cpp:291-303` and `305-340` — in-memory index constructors already see bucket entries in bucket order and can populate/sort the flat vectors once.
- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry` consumes `IndexReturnT` from `scan`; the proposed representation must return identical cache-hit/not-found states.
- `src/bucket/BucketListSnapshot.cpp:313-345` — point-load bucket walk that makes residual `scan` cost visible during `applyLedger`.

## Evidence

The current soroswap diagnostic trace reports `scan` at `bucket/InMemoryIndex.cpp:253` with **1,951,942,732 ns self-time across 926,932 calls**, and `load` / `getBucketEntry` remain visible descendants of the apply path (`BucketListSnapshot.cpp:317` and `:174`). This is after the prior polymorphic-wrapper success; the old query allocation no longer exists in source, so the remaining self-time is attributable to the current hash-table representation, hashing/equality, and memory locality rather than the already-fixed wrapper.

Source inspection confirms that the residual hot lookup is a single `std::unordered_set::find` over node-allocated `InternalInMemoryBucketEntry` objects (`InMemoryIndex.h:81-87`, `InMemoryIndex.cpp:253-258`). `scan` ignores its `start` iterator for in-memory indexes, so the caller-visible iterator contract is already degenerate; a flat vector implementation can keep returning `begin()` and preserve the existing `LiveBucketIndex::scan` interface. This is distinct from rejected `004-cache-ledgerkey-hash-bucket-walk.md` and `001-bucketlist-load-precomputed-hash.md`, which only tried to reduce hash recomputation, and from `023-bucketlistsnapshot-perkey-cache.md`, which added a cache layer above an already-hot lookup rather than replacing the lookup representation.

## Anti-Evidence

The current `scan` self-time is spread across apply-thread work and parallel Soroban worker threads, so aggregate CPU time will not translate one-for-one into wall-clock apply-time savings. A sorted-vector lower-bound can also lose to hashing for large in-memory buckets unless grouping and cache locality dominate; the PoC should compare against representative bucket sizes and may need a hybrid threshold that keeps the unordered representation for very large in-memory indexes. If most residual cost is exact `LedgerKey` hashing/equality rather than hash-table locality, the prior hash-only failure suggests the impact may fall below Medium.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The residual lookup path exists as described: `SearchableBucketListSnapshot::load` walks buckets newest-to-oldest, `getBucketEntry` calls `LiveBucketIndex::lookup`, and in-memory-index buckets route to `InMemoryBucketState::scan`, whose hot body is still `mEntries.find(searchKey)`. The stored representation is a node-based `std::unordered_set` of `InternalInMemoryBucketEntry` values containing a cached hash and `shared_ptr<BucketEntry const>`, so every in-memory bucket probe pays hash-table bucket indirection and node pointer chasing after the prior wrapper-removal optimization. One correction to the hypothesis is that current Soroban `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` reads usually bypass BucketList through `InMemorySorobanState`; the relevant bucket-scan hot path is therefore mostly classic fee/source/account/trustline and non-Soroban fallback reads during `closeLedger`, plus any live-snapshot reads for non-in-memory types. That correction narrows the target but does not eliminate the hot path: the current diagnostic still reports roughly 927k `scan` calls and 1.95s aggregate self-time.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2303-2440` — `processFeesSeqNums` runs per transaction during ledger close and can trigger classic account/source loads through the root ledger transaction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2574` — Soroban stages run in parallel workers; their non-Soroban fallback reads can still reach the live snapshot, but Soroban storage keys are normally diverted before BucketList.
- `src/ledger/LedgerTxn.cpp:3669-3724` — `LedgerTxnRoot::Impl::getNewestVersion` checks `InMemorySorobanState::isInMemoryType` first, then loads non-offer, non-Soroban entries through `LedgerStateSnapshot::loadLiveEntry`.
- `src/ledger/LedgerStateSnapshot.cpp:438-449` — live entry and live-key loads delegate directly to `SearchableLiveBucketListSnapshot`.
- `src/transactions/ParallelApplyUtils.h:74-81` and `src/transactions/ParallelApplyUtils.cpp:1084-1120` — thread parallel apply reads Soroban entries from `InMemorySorobanState` and only falls back to `mLCLSnapshot.loadLiveEntry` for non-in-memory key types.
- `src/transactions/ParallelApplyUtils.cpp:646-718` — read-only Soroban footprint preload likewise uses `InMemorySorobanState` for Soroban keys, confirming BucketList scan is not the dominant contract-data read path.
- `src/ledger/InMemorySorobanState.cpp:146-151` and `206-238` — `CONTRACT_DATA`, `CONTRACT_CODE`, and `TTL` keys are classified as in-memory and served from the Soroban state cache.
- `src/bucket/BucketListSnapshot.cpp:170-201` — `getBucketEntry` consumes the index result and returns cache hits directly, so a new in-memory representation can preserve the existing `IndexReturnT` contract.
- `src/bucket/BucketListSnapshot.cpp:210-277` — bulk loads call `index.scan(indexIter, *currKeyIt)`; because in-memory `scan` already ignores `start`, a degenerate iterator remains compatible.
- `src/bucket/BucketListSnapshot.cpp:313-345` — point loads perform the bucket walk that fans out into repeated per-bucket index lookups.
- `src/bucket/LiveBucketIndex.cpp:28-60` and `src/main/Config.cpp:186-188` — buckets below the default 20 MB cutoff use `InMemoryIndex`.
- `src/bucket/LiveBucketIndex.cpp:223-257` — live point and bulk lookup route in-memory indexes to `InMemoryIndex::scan`.
- `src/bucket/InMemoryIndex.h:19-118` — current in-memory state is a `std::unordered_set` of node-allocated `InternalInMemoryBucketEntry` records and exposes iterator types only for interface compatibility.
- `src/bucket/InMemoryIndex.cpp:198-262` — stored-entry hashes are cached once, equality is exact and type-specific, and the hot lookup remains a single unordered-set `find`.
- `src/bucket/InMemoryIndex.cpp:264-343` — both constructors already observe all bucket entries once and can build grouped/sorted flat vectors during index construction.
- `ai-summary/fail/soroban/summary.md:20-24,52-56` and `ai-summary/success/soroban/001-inmemory-bucket-scan-polymorphic-wrapper.md:146-157` — related prior work covered wrapper allocation, query-hash reuse, bulk loading, and per-key cache layers, but not replacing the residual node-based in-memory index representation.

### Findings

The inefficiency exists and remains in a hot apply-path lookup. The current in-memory index no longer has the old per-query allocation or virtual dispatch, but it still uses a node hash table even though the index is immutable after construction and all entries are already resident. For a workload producing hundreds of thousands of in-memory bucket probes per trace, replacing nodes with type-grouped contiguous records is a plausible Medium optimization: even a 30-50% reduction of the 1.95s aggregate `scan` self-time would be in the range that can clear the 3% soroswap threshold if the saved work is concentrated in sequential fee/source-load portions of `closeLedger`; the PoC must confirm the wall-clock share because parallel-worker aggregate CPU does not map directly to apply time.

Existing optimizations do not cover this exact mechanism. The live bucket random-eviction cache is intentionally skipped for `mInMemoryIndex`, the ledger-entry cache only helps after a miss has already walked the bucket indexes, Soroban in-memory state removes contract-data/code/TTL reads from this path rather than optimizing this path, and prior rejected bucket hypotheses targeted query-hash reuse or an additional cache layer above `scan`. This proposal is therefore novel relative to the checked fail/success records.

The proposed fix is correctness-preserving if implemented carefully. It must preserve `getBucketLedgerKey` identity semantics for INIT/LIVE/DEAD entries, return tombstones as cache hits so newer deletes still shadow older live entries, perform exact `keyEquals` checks for every matching hash to handle collisions, and keep duplicate-key detection during index construction. Because sorted-vector lower-bound trades hash-table node chasing for `O(log n)` hash comparisons, the PoC should measure representative bucket sizes and use a hybrid cutoff if the flat representation loses on larger in-memory buckets.

### PoC Guidance

- **Target code**: `src/bucket/InMemoryIndex.h` and `src/bucket/InMemoryIndex.cpp`, especially `InternalInMemoryBucketEntry`, `InMemoryBucketState::insert`, `InMemoryBucketState::scan`, and the two `InMemoryIndex` constructors; `src/bucket/LiveBucketIndex.cpp` and `src/bucket/BucketListSnapshot.cpp` should not need semantic changes if the existing API is preserved.
- **Change description**: replace `InMemoryBucketState::mEntries` with a flat immutable representation grouped by `LedgerEntryType`, sorted by cached `std::hash<LedgerKey>` with an exact key-order tie-breaker or duplicate check, and searched by lower-bound over the relevant type vector followed by exact `keyEquals` on all equal hashes. Preserve `IndexReturnT(IndexPtrT)` on hits and `IndexReturnT()` on misses, and keep the in-memory iterator contract degenerate because callers already cannot rely on ordered progress.
- **Correctness check**: existing bucket index coverage in `src/bucket/test/BucketIndexTests.cpp` should exercise in-memory index construction, lookup, cutoff behavior, equality, type ranges, and cache-hit semantics. Add focused tests only if the representation introduces new collision or hybrid-threshold branches that existing tests do not cover.
- **Benchmark focus**: run the soroswap apply-load matrix multiple times against the `ai-summary/CURRENT_STATE.md` baseline, and inspect Tracy for `bucket/InMemoryIndex.cpp:253` or the updated `scan` zone. The PoC should report both top-line median apply time and normalized `scan` self-time/call; promotion requires a reproducible 3-10% apply-time improvement, not just lower aggregate CPU in parallel worker threads.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: gpt-5.5, high

### Changes Made

- `src/bucket/InMemoryIndex.h:20-104` — replaced the node-based `std::unordered_set` storage with a contiguous vector of `InternalInMemoryBucketEntry` records plus per-`LedgerEntryType` index ranges; retained the degenerate iterator API used by callers.
- `src/bucket/InMemoryIndex.cpp:24-53` and `195-209` — added type-to-range indexing and a sort comparator that orders entries by type, cached hash, then exact bucket-entry identity ordering.
- `src/bucket/InMemoryIndex.cpp:246-335` — cached each entry's type with its hash, changed insertion to append to the flat vector, finalized the immutable index by sorting and duplicate-checking, and implemented `scan` as a lower-bound over the matching type range followed by exact `keyEquals` checks for hash collisions.
- `src/bucket/InMemoryIndex.cpp:338-422` — finalized the flat index in both in-memory constructors after all bucket entries are observed, with reservation for vector-backed construction from an existing entry vector.

### Demonstration

The optimization removes the per-lookup `std::unordered_set` bucket and node walk from in-memory bucket probes while preserving the existing `IndexReturnT` cache-hit/not-found contract. Bucket entries remain owned by shared pointers and every candidate returned by the hash lower-bound is still verified with exact key identity, so tombstones, INIT/LIVE entries, and hash collisions retain the same lookup semantics.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built with `make -j $(nproc)`, and ran the focused bucket-index tests plus the full suite. Focused `[bucket][bucketindex]` passed 366489 assertions in 12 test cases; `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completed successfully with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.

---

## Final Review — Needs Revision

**Date**: 2026-05-03
**Final review by**: gpt-5.5, high

### What Needs Fixing

The PoC cannot be promoted to final benchmarking in its current handoff form because the source changes are not committed. The checked-out outer branch is `poc/002-flat-inmemory-bucket-index`, but `git status --short --branch` reports unstaged modifications to `src/bucket/InMemoryIndex.cpp` and `src/bucket/InMemoryIndex.h`; it also reports many unstaged `ai-summary` deletions in the worktree. The p26 submodule is clean at `fa1226b3068605c5376efe56c6cf809ca225a036`, but the outer worktree is not reproducible from branch commits alone.

The performance final-review handoff rules require the PoC's source changes to exist as committed branch state, with clean outer and submodule worktrees, before final review measures the optimization. Running the authoritative three `scripts/run_apply_load_matrix.py` measurements against dirty local edits would produce numbers that cannot be reproduced by checking out the PoC branch tip.

The PoC notes also do not include the required apply-load matrix benchmark results. That alone would not prevent final review from benchmarking a clean committed handoff, but combined with the dirty source state it leaves no reproducible performance claim to validate.

### Revision Instructions

Commit the `src/bucket/InMemoryIndex.cpp` and `src/bucket/InMemoryIndex.h` changes onto the PoC outer branch `poc/002-flat-inmemory-bucket-index`, or otherwise ensure the branch tip contains the complete optimization. Clean up the unrelated unstaged `ai-summary` deletions so `git status --short --branch` is clean in the outer worktree and `git -C src/rust/soroban/p26 status --short --branch` is clean in the submodule. Then rerun the required build and full test gate from a clean checkout.

After the clean committed handoff is available, run the objective benchmark workflow: compare against `ai-summary/CURRENT_STATE.md`, run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times without `--tracy`, report all soroswap and max-sac apply-time values, and only run the diagnostic `--tracy` capture if the three non-Tracy runs show an eligible soroswap improvement within the max-sac tradeoff envelope.

### Checks Passed So Far

Source inspection supports the claimed mechanism: the patch replaces the immutable in-memory bucket index's node-based `std::unordered_set` with a type-grouped, hash-sorted flat vector and retains exact `keyEquals` checks for collisions and tombstones. No test-file edits were present in the inspected source diff, and the submodule worktree was clean. Correctness and performance remain unverified by final review because the dirty outer handoff blocks the required independent build/test/benchmark gate.

---

## PoC Attempt (Revised Handoff)

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: claude-opus-4.7, high

### Revision Summary

This iteration addresses the prior final-review revision request by committing
the source changes onto the PoC outer branch `poc/002-flat-inmemory-bucket-index`
and re-running the full unit-test gate from a clean configured tree. The
underlying optimization is unchanged from the original PoC attempt: the
`InMemoryBucketState` node-based `std::unordered_set` is replaced with a flat,
type-grouped, hash-sorted vector and `scan` becomes a `std::lower_bound` over
the matching type range followed by exact `keyEquals` checks for hash
collisions.

The `src/rust/soroban/p26` submodule is untouched (clean at
`fa1226b3068605c5376efe56c6cf809ca225a036`), so no paired submodule branch is
required for this PoC.

### Changes Made (Re-stated)

- `src/bucket/InMemoryIndex.h` — replaced `std::unordered_set<InternalInMemoryBucketEntry, ...>` storage with `std::vector<InternalInMemoryBucketEntry>` plus a per-`LedgerEntryType` `std::array<EntryRange, 10>` of begin/end ranges. Added a cached `LedgerEntryType mType` to `InternalInMemoryBucketEntry`. Removed the now-unused transparent `Hash`/`Equal` functors. Added `finalize()` and `reserve()` to `InMemoryBucketState`.
- `src/bucket/InMemoryIndex.cpp` —
  - Added `ledgerEntryTypeIndex` and `inMemoryEntryLess` helpers (sort by type, then cached hash, then exact bucket-entry identity ordering via `BucketEntryIdCmp`).
  - `InternalInMemoryBucketEntry` ctor caches both `std::hash<LedgerKey>` and `LedgerKey::type()` once.
  - `InMemoryBucketState::insert` becomes an `emplace_back` into the flat vector.
  - `InMemoryBucketState::finalize` sorts the vector, asserts no duplicate keys, and populates `mEntryRanges` per type.
  - `InMemoryBucketState::scan` does a per-type-range `std::lower_bound` on the cached hash and walks equal-hash entries verifying `keyEquals`, preserving the `IndexReturnT` cache-hit/not-found contract and the degenerate `mEntries.begin()` iterator return.
  - Both `InMemoryIndex` constructors now `reserve` the vector and call `finalize()` once after observing all entries.

### Demonstration

The optimization removes the per-lookup `std::unordered_set` bucket and node
walk from in-memory bucket probes while preserving the existing `IndexReturnT`
cache-hit/not-found contract. Bucket entries remain owned by shared pointers,
type ranges keep search bounded to the relevant entries, and every candidate
returned by the hash lower-bound is still verified with exact key identity, so
tombstones, INIT/LIVE entries, and hash collisions retain identical lookup
semantics. Iteration ordering is now (type, cached-hash, identity) which is
deterministic across runs.

### Test Results

Built with the configured Tracy-enabled flags (`./configure --enable-ccache
--enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`)
and `make -j30`. The full gate `env NUM_PARTITIONS=30
STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make
check` completed with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`,
and `All 2 tests passed`. No test files were modified.

### Handoff State

- Outer branch tip contains the source change (`src/bucket/InMemoryIndex.{h,cpp}`).
- Submodule `src/rust/soroban/p26` is clean at `fa1226b3`.
- Branch pushed to `origin/poc/002-flat-inmemory-bucket-index` on the SirTyson
  stellar-core fork; no submodule branch required.

---

## Final Review — Needs Revision

**Date**: 2026-05-03
**Final review by**: gpt-5.5, high

### What Needs Fixing

The revised handoff is reproducible and the implementation is plausibly
correct, but the authoritative benchmark gate does not show a consistent
soroswap apply-time improvement. The full unit-test gate passed cleanly, and no
test files were modified, so this is not a correctness rejection. However,
promotion requires the headline soroswap metric to improve consistently across
all three non-Tracy `scripts/run_apply_load_matrix.py` runs.

Baseline soroswap medians from `ai-summary/CURRENT_STATE.md` are
272.249541 ms, 275.885919 ms, and 270.551362 ms (average 272.895607 ms).
The optimized non-Tracy runs measured:

| run | artifact | sac median_ms | soroswap median_ms | soroswap vs baseline avg |
|-----|----------|---------------|--------------------|--------------------------|
| 1 | `/mnt/nvme2/apply-load/8ad9a1220e60-20260503-025758` | 304.983557 | 269.774374 | +1.14% |
| 2 | `/mnt/nvme2/apply-load/8ad9a1220e60-20260503-030414` | 302.265628 | 271.233819 | +0.61% |
| 3 | `/mnt/nvme2/apply-load/8ad9a1220e60-20260503-031030` | 304.240763 | 280.439023 | -2.76% |

The optimized soroswap average is 273.815739 ms, a 0.34% regression relative to
the accepted baseline average. SAC improved slightly on average (303.829982 ms
vs 306.542755 ms, +0.88%), but SAC is secondary for this objective and cannot
rescue an inconsistent/regressing soroswap result. Because the three non-Tracy
runs did not show an eligible improvement, no diagnostic `--tracy` run was
captured.

### Revision Instructions

Rework the optimization so it produces a reproducible soroswap apply-time win
above noise. The current flat sorted-vector lookup may be trading away the
constant-time behavior of `std::unordered_set` for `O(log n)` lower-bound work
and extra sort/finalize cost that does not consistently help this workload.
Consider profiling bucket sizes and lookup distributions in the apply-load
trace, then trying a hybrid representation that keeps the existing
`unordered_set` for larger in-memory buckets or uses a flatter hash table /
bucketed vector design that avoids both node chasing and binary-search overhead.

After revising, rerun the same clean handoff gate: build with the configured
Tracy-enabled flags, run
`env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`,
then run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py`
three times without `--tracy`. Only run the diagnostic `--tracy` capture if all
three non-Tracy soroswap runs show an eligible improvement within the max-sac
tradeoff envelope.

### Checks Passed So Far

1. Source handoff is committed on `poc/002-flat-inmemory-bucket-index`; the p26
   submodule is clean at `fa1226b3068605c5376efe56c6cf809ca225a036`.
2. Source audit found the change limited to `src/bucket/InMemoryIndex.cpp` and
   `src/bucket/InMemoryIndex.h`, replacing the node-based in-memory index with a
   type-grouped hash-sorted vector while retaining exact key comparisons.
3. No test-file edits were present.
4. Build completed with
   `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production`
   and `make -j30`.
5. Full tests passed with
   `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`.


---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: gpt-5.5, high

### Changes Made

- `src/bucket/InMemoryIndex.h:60-90` — replaced the previous per-type range metadata with per-type flat open-addressed lookup tables. Each slot stores the cached `LedgerKey` hash and an index into the contiguous entry vector, keeping entries immutable and cache-local without sorting them.
- `src/bucket/InMemoryIndex.cpp:195-209` — replaced the sorted-vector comparator with a power-of-two lookup-table sizing helper that targets a 50% maximum load factor for short linear-probe chains.
- `src/bucket/InMemoryIndex.cpp:272-310` — changed `InMemoryBucketState::finalize` to count entries by `LedgerEntryType`, allocate one flat lookup table per non-empty type, populate those tables once, and retain exact duplicate-key detection using cached hashes plus bucket-entry identity equality.
- `src/bucket/InMemoryIndex.cpp:313-346` — changed `scan` from binary search over a hash-sorted type range to an O(1)-expected open-addressed probe over the matching type table, still requiring exact `keyEquals` before returning `IndexReturnT(IndexPtrT)`.

### Demonstration

This revision preserves the flat in-memory representation but avoids the prior sorted-vector attempt's `O(log n)` lower-bound lookup and construction-time sort. Each in-memory bucket probe now hashes the query once, selects the matching entry-type table, and linearly probes contiguous slots until it finds either an empty slot or a cached-hash candidate that passes exact key comparison, preserving tombstone and hash-collision semantics while reducing residual lookup work.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production`, then built with `make -j $(nproc)`. Focused bucket-index tests passed: `./src/stellar-core test --ll fatal -r simple --abort --disable-dots "[bucket][bucketindex]"` reported 366489 assertions in 12 test cases. Full regression suite passed: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completed with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.

---

## Final Review — Needs Revision

**Date**: 2026-05-03
**Final review by**: gpt-5.5, high

### What Needs Fixing

The current revised PoC handoff is not reproducible from committed branch state. The checked-out outer branch is `poc/002-flat-inmemory-bucket-index` at pushed commit `cb8ac0502dc6dffadbac1ec1a2cd072cc628c018`, but `git status --short --branch` still reports unstaged source edits to `src/bucket/InMemoryIndex.cpp` and `src/bucket/InMemoryIndex.h`. Those dirty edits are the open-addressed lookup-table revision described in this latest PoC attempt; the branch commit itself contains the earlier hash-sorted-vector implementation.

The performance final-review handoff rules require the complete optimization to be committed before independent build/test/benchmark validation. Benchmarking dirty local source would produce results that cannot be reproduced by checking out `origin/poc/002-flat-inmemory-bucket-index`, so the required three authoritative `scripts/run_apply_load_matrix.py` runs were not started.

### Revision Instructions

Commit the open-addressed `InMemoryBucketState` implementation in `src/bucket/InMemoryIndex.cpp` and `src/bucket/InMemoryIndex.h` onto `poc/002-flat-inmemory-bucket-index`, push the branch, and provide a clean outer worktree plus a clean `src/rust/soroban/p26` submodule. The revised handoff should have `git status --short --branch` clean in the outer repo except for pipeline-managed `ai-summary` artifacts, and `git -C src/rust/soroban/p26 status --short --branch` clean in the submodule.

After that clean committed handoff exists, rerun the required gate from the branch tip: configure/build with the objective flags, run `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`, then run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times without `--tracy`. Only run the diagnostic `--tracy` capture if all three non-Tracy soroswap runs show an eligible improvement within the max-sac tradeoff envelope.

### Checks Passed So Far

1. The p26 submodule is clean at `fa1226b3068605c5376efe56c6cf809ca225a036`.
2. Source inspection found no test-file edits in the working-tree diff.
3. The dirty revised source diff matches the latest PoC description at a high level: it replaces the prior sorted-vector lower-bound index with per-entry-type open-addressed lookup tables while retaining cached hashes and exact `keyEquals` checks.
4. The committed branch tip is reachable from `origin/poc/002-flat-inmemory-bucket-index`, but it does not contain the dirty open-addressed revision, so final-review correctness and benchmark gates remain blocked.

---

## PoC Attempt (Re-handoff: open-addressed lookup tables, committed)

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: claude-opus-4.7, high

### Revision Summary

This iteration addresses the prior final-review revision request that the
open-addressed `InMemoryBucketState` revision exist as committed branch state
(not dirty working-tree edits) before final benchmark validation. The
underlying optimization is unchanged from the previous PoC attempt — flat
contiguous entry vector plus per-`LedgerEntryType` open-addressed lookup
tables — but the source diff is now committed onto the PoC outer branch.

### Changes Made

- `src/bucket/InMemoryIndex.h:60-90` — per-type flat open-addressed
  `LookupSlot` tables (cached hash + entry index) over a contiguous
  `std::vector<InternalInMemoryBucketEntry>`. Adds `finalize()` and
  `reserve()` to `InMemoryBucketState`. Cached `LedgerEntryType mType`
  on `InternalInMemoryBucketEntry`.
- `src/bucket/InMemoryIndex.cpp:24-53,195-205` — `ledgerEntryTypeIndex`
  helper and `lookupTableSize` power-of-two sizing helper targeting a
  ~50% maximum load factor.
- `src/bucket/InMemoryIndex.cpp:242-264` — `InternalInMemoryBucketEntry`
  ctor caches both `std::hash<LedgerKey>` and `LedgerKey::type()` once;
  `keyEquals` and `operator==` retain exact identity equality.
- `src/bucket/InMemoryIndex.cpp:266-308` — `insert` is `emplace_back`;
  `finalize` counts entries by type, allocates one power-of-two table
  per non-empty type, and populates each table by linear probing while
  asserting no duplicate keys (via cached hash + exact entry equality).
- `src/bucket/InMemoryIndex.cpp:316-346` — `scan` hashes the query once,
  selects the matching type table, and linearly probes contiguous slots
  until either an empty slot or a cached-hash candidate that passes
  exact `keyEquals`. Preserves the `IndexReturnT(IndexPtrT)` cache-hit
  / `IndexReturnT()` not-found contract and the degenerate
  `mEntries.begin()` iterator return.
- Both `InMemoryIndex` constructors `reserve(inMemoryState.size())` (or
  build incrementally for the file-backed ctor) and call `finalize()`
  once after observing all entries.

### Demonstration

The optimization removes both the prior `std::unordered_set` node-walk
and the previous flat-vector revision's `O(log n)` lower-bound. Each
in-memory bucket probe now performs one query hash, one type-indexed
table dereference, and an open-addressed linear probe over contiguous
slots, with exact `keyEquals` only on cached-hash matches. Tombstones,
INIT/LIVE entries, hash collisions, and duplicate-key detection during
construction all retain identical semantics, and iteration order over
`mEntries` remains the bucket-file order observed at construction.

### Test Results

Configured with the objective Tracy flags
(`./configure --enable-ccache --enable-sdfprefs --enable-tracy
--enable-tracy-capture --disable-postgres
--enable-next-protocol-version-unsafe-for-production`) and built with
`make -j $(nproc)`. Focused
`./src/stellar-core test --ll fatal -r simple --abort --disable-dots
"[bucket][bucketindex]"` reported **All tests passed (366489 assertions
in 12 test cases)**. Full regression gate
`env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple
--abort --disable-dots' make check` completed with `PASS:
test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests
passed`. No test files were modified.

### Handoff State

- Outer branch `poc/002-flat-inmemory-bucket-index` tip is
  `f84878184` (`viable poc 002-flat-inmemory-bucket-index
  (open-addressed)`); pushed to
  `origin/poc/002-flat-inmemory-bucket-index` on the SirTyson
  stellar-core fork.
- `git status --short --branch` in the outer worktree is clean except
  for the pipeline-managed untracked `ai-summary` directory.
- `src/rust/soroban/p26` submodule is clean at the recorded
  `fa1226b3068605c5376efe56c6cf809ca225a036` (no submodule branch
  required for this PoC since no submodule edits were made).

---

## Final Review — Needs Revision

**Date**: 2026-05-03
**Final review by**: gpt-5.5, high

### What Needs Fixing

The clean committed open-addressed handoff is reproducible and passes the full
correctness gate, but the authoritative benchmark result is still below the
objective's minimum performance bar. Soroswap apply time improves on average by
only **0.614%** versus `ai-summary/CURRENT_STATE.md`, which is within benchmark
noise and below the required 1% threshold for a valid finding. The result is
therefore not eligible for confirmation even though all three soroswap runs are
below the accepted baseline average.

Baseline soroswap medians from `ai-summary/CURRENT_STATE.md` are 272.249541 ms,
275.885919 ms, and 270.551362 ms (average 272.895607 ms). The optimized
non-Tracy runs measured:

| run | artifact | sac median_ms | soroswap median_ms | soroswap vs baseline avg |
|-----|----------|---------------|--------------------|--------------------------|
| 1 | `/mnt/nvme2/apply-load/48636612e5b0-20260503-034356` | 301.923051 | 269.849370 | +1.12% |
| 2 | `/mnt/nvme2/apply-load/48636612e5b0-20260503-035009` | 299.883018 | 271.922498 | +0.36% |
| 3 | `/mnt/nvme2/apply-load/48636612e5b0-20260503-035627` | 300.450306 | 271.891498 | +0.37% |

Optimized soroswap average: 271.221122 ms, a **0.614% improvement** relative to
the accepted baseline average. SAC improves more clearly on average
(300.752125 ms vs 306.542755 ms, **1.889%**), but SAC is secondary for this
objective and cannot promote a sub-1% soroswap result. Because the three
non-Tracy runs did not show an eligible soroswap improvement, no diagnostic
`--tracy` run was captured.

### Revision Instructions

Rework the lookup representation or surrounding bucket-load path so the
soroswap headline metric clears the 1% threshold reproducibly across the three
required non-Tracy matrix runs. The current open-addressed table likely reduces
some CPU work, but the wall-clock impact is too small for this objective. Before
the next handoff, profile the lookup distribution by bucket size/type and focus
on changes that either reduce the synchronous bucket-walk call count or deliver
a larger per-lookup gain on the specific account/trustline fee/source-load path
exercised by soroswap.

After revising, provide the same clean committed handoff and rerun:
`./configure --enable-ccache --enable-sdfprefs --enable-tracy
--enable-tracy-capture --disable-postgres
--enable-next-protocol-version-unsafe-for-production`, `make -j $(nproc)`,
`env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort
--disable-dots' make check`, and three
`PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` invocations
without `--tracy`. Only capture the diagnostic Tracy run if those three
non-Tracy runs clear the objective threshold and max-sac tradeoff envelope.

### Checks Passed So Far

1. The source handoff is committed at outer branch tip `f84878184`
   (`poc/002-flat-inmemory-bucket-index`), with no dirty source edits.
2. The p26 submodule is clean at
   `fa1226b3068605c5376efe56c6cf809ca225a036`; no submodule changes are part of
   this PoC.
3. The diff is limited to `src/bucket/InMemoryIndex.cpp` and
   `src/bucket/InMemoryIndex.h`; no test files were modified.
4. Source audit found the open-addressed table preserves exact key comparison,
   tombstone cache-hit semantics, hash-collision checks, and duplicate-key
   rejection during index construction.
5. Build completed with the required Tracy/next-protocol configuration and
   `make -j $(nproc)`.
6. Full regression gate passed with
   `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort
   --disable-dots' make check`.

---

## PoC Attempt (Direct point-lookup hash reuse)

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: gpt-5.5, high

### Changes Made

- `src/bucket/InMemoryIndex.h:32,84-98,162-170` — extended `InternalInMemoryBucketEntry` and `InMemoryBucketState` so callers can provide an already-derived `LedgerKey` and an already-computed query hash, while retaining the existing `scan` API for bulk callers.
- `src/bucket/InMemoryIndex.cpp:220-267,314-350` — reused the `LedgerKey` already extracted by `processEntry` when constructing cached entries, added direct `lookup(searchKey, searchHash)`, and kept `scan` as a compatibility wrapper that computes the hash only for callers that still use the iterator API.
- `src/bucket/LiveBucketIndex.h:135-136` and `src/bucket/LiveBucketIndex.cpp:223-244` — added a `lookup(k, keyHash)` overload that routes in-memory buckets directly to the new flat-table lookup while preserving the existing `lookup(k)` entry point.
- `src/bucket/BucketListSnapshot.h:124-128` and `src/bucket/BucketListSnapshot.cpp:10,170-191,335-344` — changed point loads to compute the live `LedgerKey` hash once per `SearchableBucketListSnapshot::load` call and pass it through each bucket probe, avoiding repeated hashing across the bucket walk.

### Demonstration

This revision builds on the existing open-addressed in-memory bucket index by removing redundant work around the hot point-load path. A live bucket-list point lookup now computes the `LedgerKey` hash once at the snapshot-load level and reuses it for every in-memory bucket probed; index construction also reuses the key already extracted for counters/type ranges instead of extracting it again inside each cached entry. The lookup still probes only the matching `LedgerEntryType` table, still checks cached hashes before exact `keyEquals`, and still returns the same cache-hit/not-found states, preserving tombstone and collision semantics.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production` and built with `make -j $(nproc)`. Focused bucket-index coverage passed: `./src/stellar-core test --ll fatal -r simple --abort --disable-dots "[bucket][bucketindex]"` reported **All tests passed (366489 assertions in 12 test cases)**. The first full `make check` attempt failed before stellar-core tests in vendored `gperftools` (`tcm_min_asserts_unittest`, OOM tolerance assertion), then the required full regression gate was rerun with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` and completed successfully with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.

---

## Final Review — Needs Revision

**Date**: 2026-05-03
**Final review by**: gpt-5.5, high

### What Needs Fixing

The latest "Direct point-lookup hash reuse" PoC is not reproducible from committed branch state. The checked-out outer branch is `poc/002-flat-inmemory-bucket-index` at pushed tip `f84878184` (`viable poc 002-flat-inmemory-bucket-index (open-addressed)`), but `git status --short --branch` reports unstaged source edits in:

- `src/bucket/BucketListSnapshot.cpp`
- `src/bucket/BucketListSnapshot.h`
- `src/bucket/InMemoryIndex.cpp`
- `src/bucket/InMemoryIndex.h`
- `src/bucket/LiveBucketIndex.cpp`
- `src/bucket/LiveBucketIndex.h`

Those dirty edits are the direct point-lookup hash-reuse revision described in the latest PoC attempt. The performance final-review handoff rules require the complete optimization to be committed before independent build/test/benchmark validation. Benchmarking dirty local source would produce results that cannot be reproduced by checking out `origin/poc/002-flat-inmemory-bucket-index`, so the required correctness and benchmark gates were not started.

### Revision Instructions

Commit the direct point-lookup hash-reuse changes onto `poc/002-flat-inmemory-bucket-index`, push the branch, and provide a clean outer worktree plus a clean `src/rust/soroban/p26` submodule. The revised handoff should have `git status --short --branch` clean in the outer repo except for pipeline-managed `ai-summary` artifacts, and `git -C src/rust/soroban/p26 status --short --branch` clean in the submodule.

After that clean committed handoff exists, rerun the required gate from the branch tip: configure/build with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production`, run `make -j $(nproc)`, run `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`, then run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times without `--tracy`. Only capture the diagnostic `--tracy` run if all three non-Tracy soroswap runs clear the objective threshold and the max-sac tradeoff envelope.

### Checks Passed So Far

1. The p26 submodule is clean at `fa1226b3068605c5376efe56c6cf809ca225a036`.
2. Source inspection found no test-file edits in the dirty working-tree diff.
3. The dirty revised source diff matches the latest PoC description at a high level: it reuses a `LedgerKey` hash computed once in `SearchableBucketListSnapshot::load`, routes live bucket point lookups through a `LiveBucketIndex::lookup(k, keyHash)` overload, and keeps the existing `scan` API as a compatibility wrapper.
4. The committed branch tip is reachable from `origin/poc/002-flat-inmemory-bucket-index`, but it does not contain the dirty direct point-lookup hash-reuse revision, so final-review correctness and benchmark gates remain blocked.

---

## PoC Attempt (Re-handoff: direct point-lookup hash reuse, committed)

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: claude-opus-4.7, high

### Revision Summary

Addresses the prior final-review revision request that the direct
point-lookup hash-reuse changes exist as committed branch state (not
dirty working-tree edits) before final benchmark validation. The
underlying optimization is unchanged from the previous "Direct
point-lookup hash reuse" PoC attempt — `LedgerKey` hash computed once
in `SearchableBucketListSnapshot::load` and reused across every
in-memory bucket probe, plus `InternalInMemoryBucketEntry` reusing the
`LedgerKey` already extracted by `processEntry` rather than re-deriving
it. The source diff is now committed onto the PoC outer branch at
`485dac0b2`.

### Changes Made (committed at 485dac0b2)

- `src/bucket/BucketListSnapshot.cpp:170-201,335-345` and
  `src/bucket/BucketListSnapshot.h:124-128` — `getBucketEntry` takes a
  `keyHash` parameter and routes `LiveBucket` indices through the new
  `lookup(k, keyHash)` overload via `if constexpr`; `load` computes
  `std::hash<LedgerKey>{}(k)` once for live snapshots and threads the
  cached hash through each bucket probe (HotArchive snapshots ignore
  it, preserving their existing path).
- `src/bucket/LiveBucketIndex.h:135-136` and
  `src/bucket/LiveBucketIndex.cpp:223-244` — added a
  `lookup(k, keyHash)` overload that routes in-memory buckets directly
  to `InMemoryBucketState::lookup(k, keyHash)`, and kept the existing
  `lookup(k)` entry point as a wrapper that hashes once for callers
  without a precomputed hash.
- `src/bucket/InMemoryIndex.h:32,82-98,164-169` and
  `src/bucket/InMemoryIndex.cpp:233-310,313-353` — added
  `InMemoryBucketState::lookup(searchKey, searchHash)` returning
  `IndexReturnT` directly; refactored `scan` to delegate to `lookup`
  with a freshly computed hash for compatibility callers; changed
  `insert` and `InternalInMemoryBucketEntry`'s constructor to accept
  the `LedgerKey` already extracted in `processEntry`, avoiding the
  redundant `getBucketLedgerKey` call during index construction.

### Demonstration

Each live bucket-list point load now hashes the `LedgerKey` exactly
once at the snapshot-load level and reuses that hash for every
in-memory bucket probed. The lookup still selects the matching
`LedgerEntryType` table, still validates cached hashes before exact
`keyEquals`, and still returns the same cache-hit / not-found states,
preserving tombstone, INIT/LIVE, and hash-collision semantics. Index
construction also avoids redundantly re-extracting the `LedgerKey`
inside each cached entry by reusing the key produced by
`processEntry`.

### Test Results

Configured (already on disk) with
`./configure --enable-ccache --enable-sdfprefs --enable-tracy
--enable-tracy-capture --disable-postgres
--enable-next-protocol-version-unsafe-for-production` and built with
`make -j $(nproc)`. Focused
`./src/stellar-core test --ll fatal -r simple --abort --disable-dots
"[bucket][bucketindex]"` reported **All tests passed (366489
assertions in 12 test cases)**. Full regression gate
`env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple
--abort --disable-dots' make check` completed with `PASS:
test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests
passed`. No test files were modified.

### Handoff State

- Outer branch `poc/002-flat-inmemory-bucket-index` tip is `485dac0b2`
  (`viable poc 002-flat-inmemory-bucket-index (point-lookup hash
  reuse)`); pushed to `origin/poc/002-flat-inmemory-bucket-index` on
  the SirTyson stellar-core fork.
- `git status --short --branch` in the outer worktree is clean except
  for the pipeline-managed untracked `ai-summary` directory.
- `src/rust/soroban/p26` submodule is clean at the recorded
  `fa1226b3068605c5376efe56c6cf809ca225a036` (no submodule edits were
  made in this PoC).

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-03
**PoC by**: gpt-5.5, high

### Changes Made

- `src/bucket/InMemoryIndex.h:21-99` — replaced the node-based `std::unordered_set` in-memory bucket state with a contiguous entry vector plus per-`LedgerEntryType` open-addressed lookup tables, and added a direct `lookup(searchKey, searchHash)` API while preserving the existing `scan` compatibility API.
- `src/bucket/InMemoryIndex.cpp:24-52,195-350,375-391,429-434` — added stable entry-type table indexing, power-of-two lookup-table sizing, construction-time `reserve()`/`finalize()`, duplicate-key checks using cached hashes plus exact key equality, and direct lookup that probes only the matching type table.
- `src/bucket/LiveBucketIndex.h:135-136` and `src/bucket/LiveBucketIndex.cpp:223-245` — added a `lookup(k, keyHash)` overload so live in-memory bucket probes can reuse a caller-provided key hash while disk-index and cache behavior remain unchanged.
- `src/bucket/BucketListSnapshot.h:124-128` and `src/bucket/BucketListSnapshot.cpp:170-191,335-344` — changed point loads to compute a live `LedgerKey` hash once per `SearchableBucketListSnapshot::load` call and pass it through every live bucket probe; hot-archive snapshots continue to use their existing lookup path.

### Demonstration

The optimization removes the residual unordered-set node walk for small live buckets and avoids rehashing the same `LedgerKey` for every bucket in a point-load walk. Each in-memory live-bucket probe now selects a type-specific contiguous open-addressed table, compares cached hashes first, and performs exact `keyEquals` only for matching-hash candidates, preserving tombstone, INIT/LIVE, duplicate-key, and hash-collision semantics.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production`, built with `make -j $(nproc)`, and verified focused bucket-index coverage with `./src/stellar-core test --ll fatal -r simple --abort --disable-dots "[bucket][bucketindex]"`, which reported `All tests passed (366489 assertions in 12 test cases)`. The full regression gate `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completed successfully with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
