# H045: Collapse verifySig Double-Mutex Acquisition into Single Critical Section on Cache Hit

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low (sub-1%)
**Impact**: apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`PubKeyUtils::verifySig` (`src/crypto/SecretKey.cpp:469-520`) is the apply-path
signature verification entry point. On a cache hit — the common case for
re-verified soroswap transactions whose signatures have already been observed
during tx-set preparation — the function should perform a single shard-mutex
acquisition: lock, look up, increment hit counter, return. There is no need
to release and re-acquire the mutex in the hit case.

## Mechanism

The actual implementation always splits the cache interaction into two locked
critical sections, which is correct for the miss case (the slow
`crypto_sign_verify_detached` / dalek verification must run *outside* the
shard mutex to allow other threads to make progress) but is needlessly costly
on hits:

```cpp
{
    std::lock_guard<std::mutex> guard(shard.mMutex);
    if (auto* cached = shard.mCache.maybeGet(cacheKey))
    {
        gVerifyCacheHit.fetch_add(1, std::memory_order_relaxed);
        ZoneText("hit", 3);
        return {*cached, VerifySigCacheLookupResult::HIT};   // returns from inside lock_guard
    }
}
// (verify happens here, outside lock)
{
    std::lock_guard<std::mutex> guard(shard.mMutex);
    gVerifyCacheMiss.fetch_add(1, std::memory_order_relaxed);
    shard.mCache.put(cacheKey, ok);
}
```

The hit branch only acquires once already (the second `lock_guard` is reached
only when no `cached` was found). The deviation from expected behavior is
therefore not in the hit path itself, but in the miss path: the *miss* taker
acquires the shard mutex twice (once for the failed `maybeGet`, once for the
`put`). A redesign could combine the second lock with the first by keeping
the lock held across the verify (bad — serializes verifies on the shard) or
by splitting `maybeGet` to also reserve a write slot (a `getOrInsertPending`
shape). Either way, savings are bounded by the verifySig apply-path ceiling.

## Trigger

Every cache-miss verifySig call during apply takes the shard mutex twice.
The soroswap workload exercises ~1 verifySig call per transaction × 2000 tx
× 65 ledgers × 8 parallel workers ≈ 130k apply-path calls; cache hit ratio
is high but missed re-verifications still drive ~tens of thousands of double
acquisitions.

## Target Code

- `src/crypto/SecretKey.cpp:486-494` — first `lock_guard` (cache lookup)
- `src/crypto/SecretKey.cpp:514-518` — second `lock_guard` (cache insert
  on miss)
- `src/crypto/SecretKey.h:51-66` — `VerifySigCacheShard` declaration

## Evidence

The double acquisition is plainly visible in the source. Each `std::mutex::lock`
on Linux issues a `LOCK CMPXCHG` on the futex word in the uncontended fast
path; even uncontended mutex pairs are not free. Removing one acquisition
would halve the lock-acquire cost on the miss path.

## Anti-Evidence

This proposal sits squarely under Meta-Pattern 5: "The apply-path share of
`verifySig` work is bounded by `processSignatures` +
`checkAllTransactionSignatures` = ~46ms across the full 65-ledger soroswap
run (~0.7ms/ledger = <0.2% of apply median). Even bypassing the cache probe
entirely cannot reach the 1% Low floor."

Halving (not eliminating) one mutex acquisition on the miss subset of an
already <0.2% surface yields, in the most generous attribution, single-digit
microseconds per ledger. This is structurally below both the 1% Low floor
and the 3% Medium floor required by this objective.

H008/H009/H021/H034/H043/H044 collectively rejected six prior verifySig
sub-optimizations (cache-bypass, key-shortening, per-thread cache, batch
verify, shard-index hash, atomic counters) under the same ceiling. The
double-acquisition shape is novel relative to those records, but the
ceiling argument applies identically.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; prior verifySig hypotheses
targeted cache-bypass (H008), key-shortening (H009), per-thread cache (H021),
batch verify (H034), shard-index hash (H043), and atomic counters (H044), but
none addressed the miss-path double mutex acquisition.

### Why It Failed

Meta-Pattern 5 caps the entire apply-path verifySig surface at <0.2% of
apply time (~46ms across the 65-ledger soroswap run). Removing one of two
miss-path mutex acquisitions saves a fraction of a fraction of that
already-sub-1% surface. The change cannot reach the objective's 3% Medium
floor (which excludes Low at hypothesis stage) under any plausible model.

### Lesson Learned

The verifySig apply-path ceiling is a hard, structural bound on every micro-
optimization within the function — including mutex-pattern refactors,
counter-update patterns, and cache-key construction. Future verifySig
hypotheses must cite a callsite or workload that exceeds the
`processSignatures` + `checkAllTransactionSignatures` budget before sizing
any sub-optimization within the function body. When the per-ledger budget
is sub-millisecond, no internal restructure can clear Medium severity.
