# H001: Remove Per-Budget-Charge Tracy Emission

**Date**: 2026-04-27
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: apparent soroswap apply-time reduction in Tracy-enabled builds only
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Budget charging should remain a cheap, deterministic accounting operation in the production apply path. Profiling instrumentation should help explain hot charge types without becoming the primary cost being optimized for the soroswap benchmark.

## Mechanism

The current Tracy build creates a `charge` zone for every CPU budget charge and emits the cost type name and amount. In the baseline trace this looks like a large optimization opportunity, but the expensive work is guarded by `#[cfg(all(not(target_family = "wasm"), feature = "tracy"))]` and does not exist in non-Tracy production builds. Removing or sampling this zone would make traced runs faster while not improving the production ledger apply path.

## Trigger

Run the current `soroswap, TX=4000, T=8` apply-load benchmark with `--enable-tracy`. The `charge` zone appears millions of times during Soroban host execution.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` evaluates the cost model and, only under the Tracy feature, creates a `charge` span and emits text/value metadata for CPU charges.

## Evidence

The current soroswap self-time export reports `charge` at `soroban-env-host/src/budget/dimension.rs:176` with 826,793,464 ns self-time across 8,704,023 calls. Event samples for the exact source location occur during `applyLedger` worker-thread execution, so the zone is genuinely in the measured apply subtree for Tracy captures.

## Anti-Evidence

The hot portion is profiling-only code under the `tracy` feature. Optimizing it would improve trace-capture overhead rather than the actual Soroban host execution path the objective is meant to optimize.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in this worktree

### Why It Failed

The apparent bottleneck is profiler instrumentation overhead, not production apply-path work. A patch that removes or samples the per-charge Tracy span could lower the Tracy-enabled benchmark number but would not reduce non-Tracy soroswap ledger apply time.

### Lesson Learned

Very high self-time in a Tracy-only zone must be separated from production hot-path cost before promoting a performance hypothesis. Trace overhead can explain measurements, but it should not be treated as a soroswap optimization unless the objective explicitly targets profiling-build runtime.
