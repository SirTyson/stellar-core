# H005: InMemoryIndex `scan` Hotspot Is Mostly Outside Soroswap `applyLedger`

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: Low
**Impact**: Below objective threshold for soroswap apply time; full-trace `scan` cost is not on the measured close-ledger critical path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

An optimization targeting `InMemoryBucketState::scan` should reduce soroswap apply time only if the scan calls occur inside the measured `applyLedger` windows. Full-trace scans from validation, TX-set construction, surge pricing, or other setup work should not be counted toward this objective, even if they dominate the process-wide Tracy self-time table.

## Mechanism

The full soroswap trace makes `scan` in `bucket/InMemoryIndex.cpp` look like a dominant hotspot (`1,951,942,732 ns` self-time across `926,932` calls), suggesting a flat cache-local index or a tighter bulk-load walk might improve apply time. Rechecking the event timestamps against `applyLedger` windows showed the deviation: almost all of the full-trace `scan` time falls outside the measured apply window, leaving only about `77,729 ns` overlapping soroswap `applyLedger`. The apparent hotspot is therefore a Tracy-trap setup/admission hotspot rather than a close-ledger apply bottleneck for the soroswap scenario.

## Trigger

Run `csvexport-release -e` on the current soroswap trace from `ai-summary/CURRENT_STATE.md` and observe `scan,bucket/InMemoryIndex.cpp,253` near the top of the full self-time table. Then export `applyLedger` and `scan` events with `csvexport-release -u -f ...` and intersect `scan` event intervals with the `applyLedger` intervals. The triggering condition for rejection is the current soroswap trace: `scan total 1,952,020,461 ns`, but only `77,729 ns` overlaps `applyLedger`.

## Target Code

- `src/bucket/InMemoryIndex.cpp:249-261` — `InMemoryBucketState::scan` performs a hash lookup in the in-memory bucket index.
- `src/bucket/BucketListSnapshot.cpp:203-277` — `loadKeysFromBucket` calls `index.scan` while bulk-loading keys.
- `src/bucket/BucketListSnapshot.cpp:313-330` — point loads go through `getBucketEntry` / index lookup when they are truly in the apply path.
- `src/transactions/TransactionFrame.cpp:1327` — `commonValidPreSeqNum` is a full-trace validation hotspot that can drive bucket lookups outside the measured window.
- `src/crypto/SecretKey.cpp:473` — another example of a full-trace hotspot that disappears after `applyLedger` overlap filtering.

## Evidence

The current full self-time table is misleading in exactly the way the objective warns about: `commonValidPreSeqNum` (`5.49 s`) and `verifySig` (`4.55 s`) dominate full-trace output but overlap only about `5.14 ms` and `2.29 ms` respectively with `applyLedger`. `scan` shows the same pattern for soroswap: its full-trace self-time is large, but the apply-window overlap is essentially zero. This makes any scan-layout optimization irrelevant to the soroswap headline metric unless a separate trace proves scan calls on the `applyLedger` critical path.

## Anti-Evidence

There are retained records showing in-memory bucket-index optimizations can matter in other shapes, including prior accepted/remediated work around `InMemoryBucketState` lookup allocation and a later flat-index idea that was treated as viable before being abandoned. Those do not rescue this soroswap-specific hypothesis: the current objective prioritizes soroswap apply time, and the current soroswap diagnostic trace does not place `scan` on that path. The SAC trace has more `scan` overlap than soroswap, but still not enough to justify promoting a soroswap-first Medium hypothesis without a separate max-SAC-focused objective.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — this rejects the current-trace `scan` hotspot as an apply-window false positive, rather than re-evaluating the already-recorded flat-index implementation idea

### Why It Failed

The hypothesis fails the objective's scope and severity filters. The apparent `InMemoryIndex::scan` hotspot is almost entirely outside soroswap `applyLedger`, so optimizing it would not materially reduce the measured soroswap apply time.

### Lesson Learned

For bucket-index candidates, do the `applyLedger` interval intersection before reading source too deeply. Full-trace bucket scans can be dominated by validation or TX-set preparation and are not automatically close-ledger bottlenecks.
