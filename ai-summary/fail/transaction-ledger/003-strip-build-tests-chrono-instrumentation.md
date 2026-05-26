# H003: Strip BUILD_TESTS chrono instrumentation from apply hot path

**Date**: 2026-05-25
**Subsystem**: transaction-ledger (LedgerManagerImpl)
**Severity**: Low
**Impact**: micro-optimization (vDSO syscall overhead)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The `apply-load` benchmark measures `applyLedger` time. Because the benchmark
binary is compiled with `BUILD_TESTS` (the `apply-load` subcommand is gated by
`#ifdef BUILD_TESTS` in `src/main/CommandLine.cpp:2069`), the production-only
apply path SHOULD not be carrying extra timing instrumentation that the benchmark
itself does not require. If the chrono pairs measurably perturbed wall-clock
they would need to be hoisted or disabled when running the benchmark.

## Mechanism

`src/ledger/LedgerManagerImpl.cpp` contains 50 `steady_clock::now()` calls
inside `#ifdef BUILD_TESTS` blocks. The hottest cluster is `applySorobanStage`
(lines 2632–2668) which emits 8 `now()` calls per stage, plus `applySorobanStages`
adds more on either side. With a single stage per ledger this is ~20–30
`clock_gettime(CLOCK_MONOTONIC)` calls per ledger; each costs ~20–50 ns through
the Linux vDSO. Total cost: ~500–1500 ns per ledger — three to four orders of
magnitude below the 3% Medium threshold (~6.2 ms / ledger).

## Trigger

Build with `BUILD_TESTS`; run `apply-load` on the soroswap config; measure
`applyLedger` time.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2632-2668` — `applySorobanStage` 4 chrono
  pairs (parallel apply, check invariants, commit, destroy thread states).
- `src/ledger/LedgerManagerImpl.cpp:2681-2719` — `applySorobanStages` setup
  globals timing pair.
- `src/main/CommandLine.cpp:2069` — `apply-load` gated by `BUILD_TESTS`.

## Evidence

- 50 `steady_clock::now()` callsites in `LedgerManagerImpl.cpp` (grep -c).
- Benchmark binary IS a test build (apply-load command requires BUILD_TESTS).

## Anti-Evidence

- vDSO `clock_gettime` is heavily optimized; the per-call cost is in the low
  tens of nanoseconds, not microseconds.
- The instrumentation is feature-flagged for diagnostic value during this
  exact optimization campaign (`mLastPhaseTimings` is consumed by the matrix
  runner).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated (fail summary has no entry for
chrono / BUILD_TESTS instrumentation removal).

### Why It Failed

Math is decisive: ~30 vDSO clock_gettime calls/ledger × ~50 ns each = ~1.5 µs
per ledger of savings. Soroswap baseline median apply is ~207 ms; this is
0.0007% — five orders of magnitude below the Low-tier 1% noise floor, far below
the Medium 3% gate. Also: the `mLastPhaseTimings` data is actively consumed
by `scripts/run_apply_load_matrix.py` for sub-phase breakdowns, so removing
the instrumentation would regress observability with no measurable apply win.

### Lesson Learned

Counting callsites in a hot path is not enough; for `clock_gettime` via vDSO,
even 100 callsites per ledger amount to ~5 µs — well inside benchmark noise.
Future agents: do not investigate vDSO-cost removal in the apply path unless
the same call shows up *per ledger entry* (thousands of times), not per ledger
phase (tens of times).
