# H007: Pipeline addLiveBatch Hash-Prep Onto Apply Thread During Cluster Wait

**Date**: 2026-05-26
**Subsystem**: transaction-ledger
**Severity**: Medium (projected)
**Impact**: BucketList write critical path / apply-thread idle utilization
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The apply thread should not be blocked at `threadFuture.get()` in
`applySorobanStageClustersInParallel` (`src/ledger/LedgerManagerImpl.cpp:2556`)
doing nothing for ~38 ms/ledger while parallel cluster workers run. Any work
on the post-apply critical path that doesn't depend on cluster results — most
notably the `LedgerCloseMeta`-independent setup inside
`finalizeLedgerTxnChanges` — could be hoisted to run in this idle window.

For soroswap, Tracy shows the apply thread waiting on cluster futures consumes
~36 ms of one CPU per stage with no observable work. Meanwhile,
`finalizeLedgerTxnChanges` (4.7 ms/ledger) and `sealLedgerTxnAndStoreInBucketsAndDB`
(4.9 ms/ledger) together account for ~9.6 ms (15% of apply) running synchronously
*after* clusters complete. If even a portion of that synchronous post-apply
work were started during the cluster window, apply wall would drop by that
portion.

## Mechanism

`finalizeLedgerTxnChanges` already launches `addHotArchiveBatch` and
`updateInMemorySorobanState` as async futures (these touch state INDEPENDENT
of cluster output: hot archive and in-memory soroban state for prior-ledger
evictions). The mandatory synchronous work is `addLiveBatch` on the live
BucketList — which DOES depend on the entries produced by clusters.

But the *preparation* for `addLiveBatch` — specifically, the precomputation of
bucket-level snapshots, `LiveBucketList::getLevel()` walks, and the
construction of the empty `prepareFirstLevel` scratch structures that don't
depend on the new entries — could potentially be moved into the cluster wait
window.

Proposed approach: identify which fields of `BucketLevel::commit` / `addLiveBatch`
are independent of the new-entries vector, refactor those into a `prepareBatch`
phase, and call `prepareBatch` from the apply thread during the cluster wait
(after launching the `std::async` workers, before joining their futures). When
clusters complete and entries are merged, call the (now smaller) `addLiveBatch`
on the apply thread.

If `prepareBatch` is ~1.5 ms of `addLiveBatch`'s 4.3 ms/ledger inclusive (a
guess — likely the prepareFirstLevel scratch allocation and bucket list
snapshot acquisition), this saves ~1.5 ms/ledger ≈ 0.7%. To reach Medium
(3% = 6.2 ms), we'd need to find ~6 ms of pre-computable work, which the
absolute size of post-apply (~9.6 ms) makes mathematically tight.

## Trigger

Run soroswap apply-load benchmark. Observe apply thread idle during
`applySorobanStageClustersInParallel` (no Tracy zones between launch and join
loop); observe `addLiveBatch`/`prepareFirstLevel` synchronous after cluster join.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2530–2574` — `applySorobanStageClustersInParallel`
  launch/join loop; would need to host the pre-finalize work.
- `src/ledger/LedgerManagerImpl.cpp:3217–...` — `finalizeLedgerTxnChanges`;
  would need a `prepareBatch` split.
- `src/bucket/BucketManager.cpp:1031` — `addLiveBatch`; would need to split
  cluster-result-independent setup from the entry-dependent merge.
- `src/bucket/BucketLevel.cpp` (`commit`, `prepareFirstLevel`) — actual hot
  per-level work; need to identify scratch structures that can be pre-allocated.

## Evidence

- Apply thread is idle ~36 ms/stage during cluster execution per Tracy.
- `finalizeLedgerTxnChanges` post-cluster work totals 4.7 ms/ledger; subset of
  that is in `addLiveBatch` (4.3 ms/ledger via `prepareFirstLevel` 2.56 +
  `mergeInMemory` 2.0 + `writeOne` 2.88, with overlap).
- `prepareFirstLevel` allocates scratch structures whose sizes depend only on
  the current bucket-list state, not on the new entries.
- Hot archive and in-memory soroban state pipelining inside
  `finalizeLedgerTxnChanges` is already in place — the pattern is proven
  workable.

## Anti-Evidence

- **`addLiveBatch` snapshot/hash chain is mandatory synchronous (Meta-Pattern 26).**
  The bucket-list hash for `LedgerHeader` MUST be computed after the new entries
  are merged, and the consensus protocol requires this hash to be in the header.
  Any pre-merge work that races with `addLiveBatch`'s ordering invariants is
  unsafe.
- **Determinism.** `addLiveBatch`'s internal bucket-shifting logic is sensitive
  to ledger sequence number; pre-running anything that captures the bucket-list
  state before clusters complete must guarantee the captured state is exactly
  what `addLiveBatch` would have seen after cluster completion (the live bucket
  list does not change during the cluster window because clusters don't write
  to it, but verifying that invariant in code is non-trivial).
- **Sizing.** Even an idealized 100% overlap of `prepareFirstLevel` (~2.5 ms/ledger)
  saves at most ~1.2% of soroswap median (207 ms). To reach 3% Medium, would
  need to overlap nearly ALL of `addLiveBatch` (4.3 ms) — which is impossible
  because most of `addLiveBatch`'s cost is in `mergeInMemory` and `writeOne`,
  both of which directly consume the new entries.
- Bucket pre-merge / pipelining hypotheses have a long failure history
  (Meta-Patterns 14, 24, 25, 26 explicitly cap them as below threshold or
  unsafe due to hash-chain dependencies).
- fail #001 (bucket prepareFirstLevel), fail #030 (xdr_size pre-walk),
  fail #021 and many bucket-side fail entries collectively bound this region:
  any optimization that doesn't change the actual hash computation order is
  capped at the wall time of the non-hash-dependent fraction, which is small.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — pipelining specifically into the
`applySorobanStageClustersInParallel` apply-thread idle window (rather than
into a separate background thread) is a distinct angle from prior async-pipeline
hypotheses for bucket work, all of which proposed moving work to a NEW worker
thread rather than utilizing the existing apply-thread idle.

### Why It Failed

The cluster-wait idle window is real (~36 ms/stage of apply-thread idle), but
the work eligible to fill it is too small to reach Medium:

1. **Cluster-independent post-apply work is already async** — hot archive and
   in-memory soroban state futures are launched at the top of
   `finalizeLedgerTxnChanges`. Those are the natural pipelining targets and
   they are already done.

2. **`addLiveBatch` is cluster-result-dependent.** The new entries the bucket
   list must absorb come from the cluster outputs. Pre-merge work that
   doesn't touch entries (scratch buffer allocation, level snapshots) is a
   small fraction of `addLiveBatch`'s 4.3 ms/ledger — likely under 1 ms.
   That saves ~0.5% — sub-Low and below the objective's hypothesis threshold.

3. **Hash-chain ordering** prevents reordering the BucketList commit relative
   to the cluster merge — the live BucketList hash that ends up in
   `LedgerHeader` must reflect the new entries, and that hash chain is
   serialized through `addLiveBatch`. Meta-Pattern 26.

4. **Sizing math against the objective floor**: even fully eliminating
   `prepareFirstLevel` (2.5 ms/ledger) only buys 1.2% of soroswap median.
   To clear the Medium 3% floor we need to fold ≥ 6 ms into the cluster
   window, but the entire `finalizeLedgerTxnChanges` + `sealLedger…`
   block is only 9.6 ms/ledger and most of it is hash-chain-ordered work
   that cannot run early.

### Lesson Learned

The apply-thread cluster-wait idle window IS a real ~38 ms/stage of
unused CPU, but it is structurally hard to fill: (a) the next-stage's setup
needs cluster results (footprint reads, classic key merges); (b) the
post-apply phase's bucket-hash chain depends on cluster results; (c) the
cluster-independent post-apply work (hot archive, in-memory state) is
already pipelined. Future hypotheses for this window must either find
cluster-output-INDEPENDENT work elsewhere in the apply path (none identified
in this investigation) or accept that the window will remain idle. Apply-thread
cluster-wait pipelining of bucket-list operations is below the Medium floor
because `prepareFirstLevel` (the only meaningful entry-independent slice) is
sub-1.5 ms/ledger.
