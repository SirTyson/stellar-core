# H054: Pipeline Bucket-Output SHA256 With Disk Write During Apply

**Date**: 2026-05-21
**Subsystem**: crypto / bucket output / apply-path I/O
**Severity**: Low
**Impact**: Apply-path bucket-output bucket-hash overlap (sub-Medium)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`LiveBucket::fresh` and `BucketOutputIterator::put`/`getBucket` write a newly
finalized level-0 bucket file during apply, simultaneously feeding the same
byte stream into an `SHA256` `Hasher` to produce the deterministic bucket
content hash. The bucket hash must be byte-for-byte identical to today's,
the hash must be available before `BucketLevel::commit` returns, and apply
must not advance past the bucket commit until both the file is on disk and
the hash is finalized.

## Mechanism

Today, `XDROutputFileStream::writeOne` calls `writeBytes` (which issues the
ASIO write) and then `hasher->add(ByteSlice(mBuf.data(), toWrite))` for every
record in a single thread. The hash byte-volume per ledger is small enough
that it fits inside Meta-Pattern 1's SHA256 budget ceiling, but in principle
the SHA256 fold could be moved to a dedicated thread that consumes the
already-written `mBuf` slices via a small SPSC queue, allowing the apply
thread to continue feeding `writeBytes` without paying the hash latency
inline. The actual hash compute remains the same (identical bytes in identical
order), so the bucket hash is unchanged.

## Trigger

Run the current soroswap apply-load case from
`ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). Inspect
`writeOne`/`writeBytes`/`BucketOutputIterator::put` zones for the apply-path
bucket commit phase and measure the SHA256-only share inside those zones.

## Target Code

- `src/util/XDRStream.h:writeOne:481-515` — interleaves `writeBytes` and
  `hasher->add` per record.
- `src/bucket/BucketOutputIterator.cpp:put` and `getBucket` — drive the
  per-bucket write+hash loop during apply.
- `src/bucket/LiveBucket.cpp:fresh:390-528` — the apply-path entry that
  invokes the bucket output iterator.

## Evidence

The current Tracy trace shows `BucketOutputIterator::put` totals 166.846 ms
inside `applyLedger`, `writeOne` 126.162 ms, and `writeBytes` 28.414 ms
across the soroswap run. The hash component is a fraction of these zones —
the dominant share is XDR encoding (`xdr_argpack_archive`) and the ASIO
write itself.

## Anti-Evidence

- Meta-Pattern 1: the entire in-apply SHA256 budget for soroswap is
  ~4 ms per ledger (~0.67% of apply). Bucket-output hashing is a subset of
  that ceiling; even if pipelining hides 100% of the hash latency, the
  recoverable savings are sub-1%.
- SHA256-NI on the bench host runs at multi-GB/s; bucket bytes per ledger
  are small, so the inline hash cost is microseconds, not milliseconds.
- Pipelining a hasher across threads risks subtle ordering bugs if the
  bytes are not consumed in write order; the determinism risk is large
  relative to the projected gain.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — bucket-output SHA256 pipelining (cross-thread overlap)
was not previously considered; prior H029 targeted streaming SHA256 within a
single thread, not an apply/hash thread split.

### Why It Failed

The apply-path SHA256 budget is structurally capped below 1% by Meta-Pattern
1, and bucket-output hashing is a strict subset of that ceiling. Moving the
existing hash compute to a sibling thread can at best hide its latency, but
the latency is single-digit microseconds per record on SHA-NI hardware and
single-digit milliseconds per ledger in aggregate. The realistic recoverable
share is well below the 1% Low floor (and far from the 3% Medium minimum
this objective enforces), while the determinism + cross-thread ordering risk
is non-trivial.

### Lesson Learned

Cross-thread pipelining of apply-path crypto primitives cannot escape
Meta-Pattern 1's SHA256 budget ceiling: the upper bound on savings is the
entire in-apply SHA256 budget, which is already sub-1%. Reject up-front any
apply-path SHA256 latency-hiding scheme regardless of cleverness; the only
way to clear Medium is to remove crypto work whose total is itself
multi-percent, and no such surface exists in this subsystem.
