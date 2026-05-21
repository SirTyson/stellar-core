# H044: Coalesce or Remove `gVerifyCacheHit/Miss` Atomic Increments on Apply Path

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low (sub-1%)
**Impact**: apply-time
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`PubKeyUtils::verifySig` (`src/crypto/SecretKey.cpp:469-520`) bumps two
process-wide `std::atomic<uint64_t>` counters on every call:

```cpp
gVerifyCacheHit.fetch_add(1, std::memory_order_relaxed);   // hit branch
...
gVerifyCacheMiss.fetch_add(1, std::memory_order_relaxed);  // miss branch
```

These counters are read by `flushVerifySigCacheCounts` for periodic metrics
reporting. The expected efficient implementation accumulates per-thread
counters (e.g., a `thread_local uint64_t` flushed on a periodic boundary)
or coalesces hits/misses into a single counter pair updated outside the
locked section.

## Mechanism

`std::atomic<uint64_t>::fetch_add` with `memory_order_relaxed` still issues
a `LOCK XADD` on x86, which is a contended cache-line operation when
multiple parallel-apply workers verify signatures concurrently. With 8
clusters each running `processSignatures` over their batch of transactions,
the two counter cache lines bounce between cores. The actual behavior
adds a serialization point per verifySig call that the per-shard mutex
sharding (`gVerifySigCacheShards`, H021) was specifically introduced to
avoid.

## Trigger

Every signature verification during `applyLedger` increments one of these
counters. The soroswap benchmark drives ~1 verifySig call per transaction
× 2000 tx × 65 ledgers = ~130k atomic-XADDs across the run, distributed
across the 8 parallel-apply workers.

## Target Code

- `src/crypto/SecretKey.cpp:490` — `gVerifyCacheHit.fetch_add` (hit branch)
- `src/crypto/SecretKey.cpp:516` — `gVerifyCacheMiss.fetch_add` (miss branch)
- `src/crypto/SecretKey.cpp:flushVerifySigCacheCounts` — exchange-based reader

## Evidence

- Two global atomics are touched on every verifySig call, on the same hot
  paths as the per-shard mutex acquisition.
- `memory_order_relaxed` does not eliminate the LOCK-prefix on x86 RMW.
- Per-thread counters are a textbook fix for cross-core counter contention
  and are used elsewhere in stellar-core for metric counters.

## Anti-Evidence

Same Meta-Pattern 5 ceiling that has rejected every prior verifySig
apply-path hypothesis: the entire apply-path verifySig zone is below 1%
of apply time, so any sub-zone cleanup is structurally sub-1%.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — the atomic counter increments have not previously been
proposed for thread-local coalescing in any of H008, H009, H021, or H034.
H021 sharded the cache mutex but left the counters as global atomics.

### Why It Failed

Bounded by **Meta-Pattern 5: Apply-Path verifySig and BLAKE2 Share Is
Below 1%**. The full apply-path verifySig surface is ~46ms across the
65-ledger soroswap run (~0.7ms/ledger ≈ <0.2% of apply median). A
`LOCK XADD` is on the order of tens of nanoseconds even under
contention; with ~130k apply-path calls across 8 workers (~16k per
worker), the absolute counter-contention cost is bounded at a few ms
total across the run — a single-digit-percent slice of the already-<0.2%
verifySig ceiling. This cannot clear the 1% Low floor, let alone the 3%
Medium floor required by this objective.

Additionally, the contention is partially hidden by the per-shard mutex
already acquired around the cache probe (the atomic XADD shares cache
traffic with that mutex), so the marginal removable cost is even smaller
than the bare atomic-only estimate.

### Lesson Learned

Global atomic counter contention is a real production concern in
high-throughput systems, but for the stellar-core soroswap apply path,
the verifySig zone is already capped by Meta-Pattern 5's <0.2% ceiling.
Any sub-zone cleanup — counter coalescing, shard-index simplification,
cache-key shortening, batched verify — sits inside that cap and cannot
be promoted. Future verifySig apply-path hypotheses must demonstrate a
caller of `verifySig` that falls *outside* the
`processSignatures`/`checkAllTransactionSignatures` envelope before
sizing savings.
