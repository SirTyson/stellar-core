# H003: Deferred / Batched CheckpointBuilder durableWriteOne fsync on the Apply Path

**Date**: 2026-05-26
**Subsystem**: soroban
**Severity**: Low (sub-threshold)
**Impact**: Apply-thread serial fsync on history checkpoint stream writes
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LedgerManagerImpl::sealLedgerTxnAndStoreInBucketsAndDB` calls into
`CheckpointBuilder::appendTransactionSet` and `CheckpointBuilder::appendLedgerHeader`
on every closed ledger. Each of those calls invokes
`XDROutputFileStream::durableWriteOne`, which does `flush()` followed by
`fs::flushFileChanges()` (POSIX `fsync(fd)`). For three streams per ledger
(`mTxResults`, `mTxs`, `mLedgerHeaders`), this produces up to three synchronous
fsyncs per ledger on the apply thread. A correct redesign would defer the fsync
to the checkpoint boundary (every 64 ledgers by default) — fsync the partial
checkpoint files only when the checkpoint is closed and renamed durably, and
rely on best-effort writes between boundaries (matching how the published
checkpoint becomes authoritative only after `durableRename`).

## Mechanism

Currently each ledger pays 2.7 fsync calls × ~473 µs/call ≈ 1.29 ms of
apply-thread serial fsync. Removing per-ledger fsync while retaining the
checkpoint-boundary fsync would preserve crash-recovery semantics (the
checkpoint file is only considered authoritative after `durableRename` at
boundary), but recovers the wall-clock of the per-ledger fsync inside
`applyLedger`. The change touches `src/util/XDRStream.h:471 durableWriteOne`
(or its callers in `CheckpointBuilder`) to make per-write fsync optional.

## Trigger

Run the soroswap apply-load matrix. The `flushFileChanges` Tracy zone shows
194 calls over the 71-ledger soroswap window (~2.7 calls/ledger × 71 ≈ 192,
matching the trace), totalling 91.7 ms of apply-thread serial work.

## Target Code

- `src/util/Fs.cpp:224` — `flushFileChanges(int fd)` calls `fsync(fd)` in a loop.
- `src/util/XDRStream.h:471` — `XDROutputFileStream::durableWriteOne` calls
  `flush()` then `fs::flushFileChanges(getHandle())` after every write.
- `src/history/CheckpointBuilder.cpp:145-146,175` — three per-ledger callers:
  `mTxResults->durableWriteOne`, `mTxs->durableWriteOne`,
  `mLedgerHeaders->durableWriteOne`.
- `src/history/HistoryManagerImpl.cpp` (checkpoint publish path) — performs
  the durable rename at checkpoint boundary that would still anchor durability.

## Evidence

Tracy `flushFileChanges` self-time in the accepted baseline soroswap diagnostic
trace (`/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`):

- 91.7 ms total / 194 calls = 473 µs / call
- 194 calls / 71 ledgers = 2.73 calls / ledger
- Per-ledger cost: 2.73 × 473 µs ≈ 1.29 ms / ledger
- Fraction of 207 ms soroswap baseline: 1.29 / 207 ≈ **0.62%**

This is below the 1% Low floor and well below the 3% Medium floor required
by this objective.

## Anti-Evidence

- The 0.62% upper bound is the *total* fsync cost; a deferred design that
  still fsyncs at checkpoint boundary (every 64 ledgers) recovers only the
  63/64 of fsyncs that move off the apply path. So realistic recoverable
  savings on the apply thread are closer to 0.61% per non-boundary ledger
  but **0% on boundary ledgers** (which still pay the full 3× fsync).
- The benchmark window (~70 ledgers) likely contains 0–1 checkpoint
  boundaries (default checkpoint frequency 64), so almost all measured
  ledgers would benefit, but the *aggregate* benefit is still capped at
  the 0.62% absolute cost.
- Even if applied across all ledgers (not boundary-gated), the saving
  cannot exceed 0.62% of apply time.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; no prior fail entry in
soroban/transaction-ledger/transactions covers `flushFileChanges` /
CheckpointBuilder fsync on the apply path.

### Why It Failed

The entire `flushFileChanges` Tracy self-time in the apply window is 91.7 ms
over 71 ledgers = 1.29 ms/ledger = **0.62% of the 207 ms soroswap baseline**.
Even if every per-write fsync were eliminated, the saving would be below
both the 1% Low floor and the 3% Medium floor required by the
optimize-soroswap objective. This is the maximum possible upper bound;
realistic recoverable savings after preserving checkpoint-boundary fsync
(required for crash-recovery durability of published checkpoints) would be
strictly less.

### Lesson Learned

- The CheckpointBuilder per-ledger fsync cost on the apply thread is a real
  serial bottleneck but is bounded absolutely at ~1.3 ms/ledger = 0.62%
  of soroswap apply. No fsync-batching variant can clear the Medium floor
  on this baseline.
- For any "defer/batch fsync" hypothesis touching the apply path, compute
  `fsync_count_per_ledger × per_fsync_µs / baseline_ms` and check against
  the 3% Medium floor before drafting; for soroswap this is structurally
  sub-1%.
- Adds to Meta-Pattern #14 (sub-1% apply-thread serial paths exhausted):
  CheckpointBuilder fsync joins the list of serial apply-thread paths
  individually below Low and combined still well under 2% of apply time.
