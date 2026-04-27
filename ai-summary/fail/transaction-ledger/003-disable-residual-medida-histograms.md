# H003: Disable remaining medida histogram `Update` calls in the apply path that survive `DISABLE_SOROBAN_METRICS_FOR_TESTING`

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (medida histograms reachable from `applyLedger`)
**Severity**: Low
**Impact**: Apply-time reduction from skipping histogram bookkeeping
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When the apply-load benchmark sets
`DISABLE_SOROBAN_METRICS_FOR_TESTING = true` (and the existing comment
in `docs/apply-load-benchmark-sac.cfg:13-24` explicitly notes
"Medida metrics (histograms in particular) in apply path cause severe
and non-deterministic performance degradation"), one would expect the
remaining hot-path histogram updates outside the Soroban metrics gate
to be similarly elidable, leaving the apply path with essentially zero
histogram-update cost during a benchmark run.

## Mechanism

Tracy reports `Update` (`libmedida/src/medida/histogram.cc:115`) at
**486 ms self-time across 38 890 calls** for the 65-ledger soroswap
benchmark — an average of ~600 histogram updates per ledger and
~7.5 ms/ledger total. This is despite
`DISABLE_SOROBAN_METRICS_FOR_TESTING = true`. The remaining histograms
fire from non-Soroban-gated code paths (e.g.,
`mTransactionApply.TimeScope()` only conditionally suppressed,
`LedgerCloseMetrics`, `BucketManager` size histograms, etc.).

A change that gates more of these histograms behind
`DISABLE_SOROBAN_METRICS_FOR_TESTING` (or introduces a broader
`DISABLE_APPLY_METRICS_FOR_TESTING`) would skip them.

## Trigger

Run soroswap benchmark; Tracy `Update` zone disappears or shrinks.

## Target Code

- `libmedida/src/medida/histogram.cc:115` — the hot kernel
- `src/ledger/LedgerManagerImpl.cpp:2483-2510` — example: per-tx
  `mTransactionApply.TimeScope()` is already gated by
  `DISABLE_SOROBAN_METRICS_FOR_TESTING`. Other histograms inside
  `applyLedger` / `closeLedger` are not.
- Search target: any `medida::Histogram::Update` reachable from
  `applyLedger` whose call site is not under a metrics-disable
  guard.

## Evidence

- Tracy `Update` total = 486 ms / 65 = 7.5 ms / ledger.
- The benchmark config comment explicitly acknowledges medida
  histograms as a known apply-path performance issue.

## Anti-Evidence

- **In production**, these histograms are required for monitoring;
  any "skip in benchmark" gate doesn't help production. A real
  optimization would have to (a) make histogram updates cheaper
  (lock-free / sampled) or (b) move them off the critical path
  (defer to a worker thread). Both are larger redesigns than a
  hypothesis here would warrant.
- The benchmark already disables the largest offender
  (`DISABLE_SOROBAN_METRICS_FOR_TESTING`); the residual 7.5 ms/ledger
  is what's left after the obvious wins.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a transaction-ledger
hypothesis (the existing `DISABLE_SOROBAN_METRICS_FOR_TESTING` flag
covers the largest histograms; this would be incremental).

### Why It Failed

Projected apply-time reduction is **~1.2 % (7.5 ms / 620 ms median
soroswap apply)** — below the Medium threshold (3–10 %). The
optimization that would matter (a redesign making histograms cheap
or asynchronous) is too speculative without a clear design, and the
"add more disable flags" approach helps only the benchmark, not
production. Per the optimize-soroswap-hypothesis severity rules,
sub-Medium hypotheses are not promoted.

### Lesson Learned

When Tracy shows a hot zone whose total is below the 3 % apply-time
floor, do not promote it as a Medium hypothesis on the basis that "it
adds up across a long benchmark". Convert the zone total to per-ledger
percentage before deciding viability. Histograms in particular are
already partly addressed by the existing config flags; remaining
calls are dispersed and individually small.
