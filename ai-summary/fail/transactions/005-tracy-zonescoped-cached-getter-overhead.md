# H005: Tracy ZoneScoped overhead in cached getter functions on TransactionFrame

**Date**: 2026-04-30
**Subsystem**: transactions
**Severity**: Low
**Impact**: Apply-time reduction (instrumentation overhead removal)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TransactionFrame::getFullHash`, `getContentsHash`, and `getSize` are pure
cached getters: their first call computes a hash / size, all subsequent
calls return a cached `Hash` / `uint32_t` value. A trivial accessor that
returns a pre-computed scalar should not appear in Tracy as one of the
top-zone consumers in the apply path; if it does, the cost is from the
`ZoneScoped` macro itself rather than from any real work, and removing the
macro on the cached fast path should reclaim that cost without changing
behavior.

## Mechanism

`getFullHash` (`src/transactions/TransactionFrame.cpp:122-159`) and
`getContentsHash` are decorated with `ZoneScoped` even on the cached
return path. Tracy zone push/pop is non-trivial when the binary is built
with `--enable-tracy` (the apply-load benchmark binary is). With
`getFullHash` showing 145 ms across 2.86 M calls and `getContentsHash` /
`getSize` similar magnitudes, almost all of that time is the Tracy
instrumentation, not the cached load. Moving `ZoneScoped` inside the
"compute" branch (or replacing with `ZoneScopedC` only when the cache
miss occurs) would reclaim that cost.

## Trigger

Build the apply-load benchmark with `--enable-tracy` (current default)
and observe Tracy zones `getFullHash`, `getContentsHash`, `getSize` on
`TransactionFrame` during the soroswap workload — they show high call
count and small per-call self-time, consistent with macro overhead
dominating cached returns.

## Target Code

- `src/transactions/TransactionFrame.cpp:122-159` — `getFullHash` / `getContentsHash` cached getters with unconditional `ZoneScoped`.
- `src/transactions/TransactionFrame.cpp:2828` — `getSize` cached getter.

## Evidence

- Tracy export shows `getFullHash` self 145 ms / 2.86 M calls = ~50 ns
  per call — consistent with Tracy zone push/pop overhead, not hashing
  work.
- The cached path is `if (mFullHash) return mFullHash.value();` — a
  single branch + value copy.

## Anti-Evidence

- Total reclaim across all three getters is bounded by their measured
  self-time: ~145 + 113 + 94 = 352 ms aggregate across the entire trace
  (which spans far more than `applyLedger`). Filtering to events inside
  `applyLedger` reduces this further; many of these calls are during
  TX-set construction, which is out-of-scope per the Tracy Trap rule.
- Removing `ZoneScoped` only affects Tracy-enabled builds. Production
  builds may or may not enable Tracy, so the gain is measurement-tool
  specific rather than a real production speedup.
- Even an upper-bound estimate places the reclaim well below 1% of
  `applyLedger` total — clearly within benchmark noise.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-30
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated for `transactions/`.

### Why It Failed

The aggregate reclaim is bounded at <1% of `applyLedger` even before
filtering out TX-set-construction events (which the Tracy Trap rule
excludes from the apply path). Per the objective's severity floor,
hypotheses below Medium (3-10%) are not accepted. Additionally, the
"fix" only affects Tracy-instrumented builds; the non-Tracy production
binary is unaffected, so this would optimize the measurement harness
rather than the production apply path.

### Lesson Learned

Hot-zone Tracy reports for cached getters with very high call counts
and tiny per-call self-time often reflect `ZoneScoped` macro overhead
in Tracy-instrumented binaries. Before investigating, compute the
upper-bound reclaim (zone self-time / `applyLedger` total) and reject
if it lands below the objective's severity floor. Also remember that
many high-count zones live in TX-set construction, not `applyLedger`,
and must be filtered by ancestor before being treated as apply-path
hotspots.
