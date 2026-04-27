# H001: Replace InMemoryBucketEntry Virtual Wrapper With Direct Keyed Storage

**Date**: 2026-04-27
**Subsystem**: ledger
**Severity**: Medium
**Impact**: soroswap apply-time reduction by reducing BucketList lookup overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Small live buckets that use `InMemoryIndex` should support high-volume apply-path lookups without per-lookup heap allocation or virtual dispatch. Bulk and point BucketList loads should find cached entries by `LedgerKey` with minimal wrapper construction.

## Mechanism

`InMemoryBucketState::scan` constructs an `InternalInMemoryBucketEntry(searchKey)` for every lookup, and that wrapper owns a heap-allocated virtual `QueryKey`. Replacing the `unordered_set<InternalInMemoryBucketEntry>` representation with direct keyed storage or transparent heterogeneous lookup could remove the query allocation and virtual `copyKey()`/`hash()` calls. The current trace shows `bucket/InMemoryIndex.cpp:67` with 1,445,421 total calls and 3,139.849 ms total self-time, with 502,934 calls and 129.669 ms inside `applyLedger` windows.

## Trigger

Run the current soroswap apply-load benchmark and inspect BucketList lookups in the latest trace. The apply path performs hundreds of thousands of in-memory index scans through `BucketListSnapshot::load` / `getBucketEntry`.

## Target Code

- `src/bucket/InMemoryIndex.h:19-133` — virtual wrapper hierarchy and `unique_ptr<AbstractEntry>` representation.
- `src/bucket/InMemoryIndex.cpp:55-76` — per-lookup query wrapper construction and `unordered_set::find`.
- `src/bucket/BucketListSnapshot.cpp:166-201` and `src/bucket/BucketListSnapshot.cpp:313-346` — point lookup path that drives the hot scans.

## Evidence

The structural overhead is real and the zone is visible in the apply trace. `InternalInMemoryBucketEntry` allocates a `QueryKey` for lookup, while comments in the header say the design exists because C++20 heterogeneous lookup was not available when written.

## Anti-Evidence

Recent git history shows this exact optimization family was already attempted and repeatedly reverted/reapplied: `0a2a92b13 perf: replace InMemoryBucketEntry virtual set with unordered_map`, `97a431a75 Revert "perf: replace InMemoryBucketEntry virtual set with unordered_map"`, `225f583d0 Reapply ...`, `a0cfe2a53 Revert ...`, `eb661ec61 Reapply ...`, and `feae88100 Revert ...`. Without first understanding why those attempts failed or were reverted, this is not novel enough to promote as a fresh hypothesis.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelty**: FAIL — same optimization family appears repeatedly in recent commit history

### Why It Failed

The code path is hot, but the direct replacement of the virtual in-memory bucket-entry wrapper has already been tried and reverted multiple times on this branch. A new hypothesis would need a materially different design or an explanation of the previous revert cause; this investigation did not establish either.

### Lesson Learned

Before proposing obvious structural optimizations in hot BucketList code, check recent branch history as well as hypothesis directories; reverted perf commits often indicate hidden correctness, memory, or benchmark-repeatability constraints.
