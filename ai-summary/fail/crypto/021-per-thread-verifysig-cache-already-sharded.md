# H021: Per-thread `gVerifySigCache` to remove mutex contention during parallel apply

**Date**: 2026-05-03
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time signature verification reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When multiple parallel-apply clusters concurrently invoke
`PubKeyUtils::verifySig`, each call should complete its cache probe and
insert without serializing on a shared mutex. With `NUM_CLUSTERS` worker
threads (typically 8) all hitting the same global signature cache during
`processSignatures`/`checkAllTransactionSignatures` on the apply path,
mutex contention should not be a meaningful share of per-call latency.

## Mechanism

Hypothesis would propose either (a) replacing the global mutex-protected
cache with a thread-local cache per worker (eliminating contention but
losing cross-thread cache reuse), or (b) increasing the shard count to
reduce collisions further. The theory is that even with cache hits, every
call takes a `std::mutex` lock/unlock (line 487/494 in `SecretKey.cpp`),
and under the parallel-apply workload the locks could serialize hot paths.

## Trigger

Run the soroswap apply-load benchmark with `NUM_CLUSTERS=8` and aggregate
self-time of `verifySig` zones whose Tracy parent is `applyLedger` (i.e.,
`processSignatures` / `checkAllTransactionSignatures` invocations from
`commonPreApply` / `preParallelApply` / fee processing).

## Target Code

- `src/crypto/SecretKey.cpp:46-66` — sharded cache definition
  (`NUM_VERIFY_CACHE_SHARDS = 16`, `VerifySigCacheShard` array).
- `src/crypto/SecretKey.cpp:469-520` — `PubKeyUtils::verifySig` mutex
  acquire/release on probe and insert.
- `src/transactions/TransactionFrame.cpp:1588` — `processSignatures` apply
  callsite (~7.7 ms total in trace).
- `src/transactions/TransactionFrame.cpp:578` — `checkAllTransactionSignatures`
  apply callsite (~22.9 ms total in trace).
- `src/transactions/TransactionFrame.cpp:1873` — `removeAccountSigner`
  apply callsite (~13.7 ms total in trace).

## Evidence

Tracy self-time for `verifySig` at the process level is 4.55 s across 360 K
calls — dominant in the trace. The apply-path subset is bounded but real,
and parallel apply with N=8 threads could in principle generate mutex
contention for signature work happening inside the parallel cluster
critical sections.

## Anti-Evidence

The cache is **already sharded** into 16 independent shards
(`gVerifySigCacheShards[NUM_VERIFY_CACHE_SHARDS]`, each with its own
`std::mutex`), with shard index derived from
`std::hash<Hash>{}(cacheKey) % 16`. With 8 worker threads probing 16
random shards, expected contention is ~8/16 = 0.5 collisions per access on
average — already very low. The original "single global mutex" inefficiency
that this hypothesis would target does not exist in current code.

Independently, **Meta-Pattern 5** in `ai-summary/fail/crypto/summary.md`
caps the entire apply-path verifySig budget at ~46 ms across the 65-ledger
soroswap run (~0.7 ms/ledger, <0.2% of apply-time median). Even if mutex
contention were perfectly eliminated and the 8 worker threads were never
serialized at all, the recoverable budget is bounded above by 0.2% of
apply time — well below the 1% Low floor and three orders of magnitude
below the 3% Medium minimum required by this objective.

H011 (`shorthash::gKey` mutex lock-free) targeted a different mutex
(`gKeyMutex` for SipHash key, not `gVerifySigCacheMutex`), and H008
(bypass cache probe via sticky flag) addressed the cost of the cache
probe itself, not contention. Per-thread/sharded cache angle was not
explicitly recorded; this fail record closes that gap.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — distinct from H008 (sticky-flag bypass), H009
(shorter cache key), and H011 (`gKeyMutex` lock-free).

### Why It Failed

Two compounding reasons:

1. **The proposed restructuring already exists.** `gVerifySigCacheShards`
   is sharded 16 ways with per-shard mutexes (`SecretKey.cpp:46-66, 483-487`).
   With `NUM_CLUSTERS=8` workers spread across 16 shards by hash, the
   contention this hypothesis would address is already minimised.
   Per-thread caches would lose cross-thread cache reuse (a real win for
   apply paths that re-verify signatures already checked during preApply)
   without removing meaningful contention.

2. **The total budget is sub-floor.** Per Meta-Pattern 5, the entire
   apply-path verifySig surface is ~46 ms across the soroswap run
   (~0.2% of apply time). Even a perfect contention elimination cannot
   reach the 1% Low floor, let alone the 3% Medium minimum.

### Lesson Learned

Future verifySig-cache hypotheses must:

1. Read `gVerifySigCacheShards` definition first — the cache is sharded
   16 ways, so any "remove mutex contention" angle is already addressed.
2. Size proposed savings against Meta-Pattern 5's apply-path verifySig
   ceiling (~0.2% of apply), not against the process-wide `verifySig`
   self-time (which is dominated by tx-set construction).
3. Prefer hypotheses that target bridge-level batching of signature
   verification (e.g., ed25519 batch verification primitives) only if a
   specific apply-path callsite can supply N>>1 signatures in one batch
   — and even then, the bound is the same ~0.2% ceiling.

Add this to the cluster of "crypto subsystem optimizations bounded by
apply-path verifySig <0.2% ceiling" alongside H001, H005, H008, H009.
