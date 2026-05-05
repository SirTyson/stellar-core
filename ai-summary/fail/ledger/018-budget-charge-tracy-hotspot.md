# H018: Treat BudgetDimension charge self-time as a non-Tracy apply bottleneck

**Date**: 2026-05-05
**Subsystem**: ledger / Soroban host metering
**Severity**: Medium
**Impact**: unproven; trace evidence is contaminated by Tracy-only instrumentation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Budget charging during Soroban apply should update CPU and memory totals, enforce limits, and return the same consumed resource values used by Core for result validation and fees. Any optimization to budget metering must reduce authoritative non-Tracy apply time, not just reduce overhead introduced by profiling instrumentation.

## Mechanism

The tempting mechanism is that `charge` appears as a very large self-time zone in the current Tracy profile, so specializing constant-cost charges or bypassing detailed tracker updates might look like a Medium-tier apply optimization. The actual trace zone, however, is created inside `BudgetDimension::charge` only when the Rust `tracy` feature is enabled and includes per-charge `emit_text` and `emit_value` calls, which are absent from the three authoritative non-Tracy benchmark runs.

## Trigger

Run the current diagnostic Tracy soroswap trace and sort by self-time. `charge` appears near the top with 20,300,668 events.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` - `BudgetDimension::charge` contains the Tracy-only `charge` span and emits cost type text/value under `#[cfg(feature = "tracy")]`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-283` - `BudgetImpl::charge` performs the real CPU/memory charge, tracker updates, and limit checks.
- `src/rust/src/soroban_proto_any.rs:458-466` - Core-visible outputs read only total CPU/memory plus VM-instantiation tracker/time fields after invocation.

## Evidence

The current Tracy self-time export reports `charge` at `soroban-env-host/src/budget/dimension.rs:176` with 1,758,199,707 ns self-time across 20,300,668 calls. Timeline overlap analysis shows those charge events are inside `applyLedger`, so the path is in scope from a call-graph perspective.

## Anti-Evidence

The same source shows the `charge` Tracy span and text/value emission are compiled only under `#[cfg(all(not(target_family = "wasm"), feature = "tracy"))]`. The objective's verdict uses three non-Tracy `scripts/run_apply_load_matrix.py` runs, so the observed `charge` self-time cannot be used directly as evidence of non-Tracy apply overhead. The remaining real metering cost may still exist, but this investigation did not isolate it from the profiler-only span.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-05
**Failed At**: hypothesis
**Novelty**: PASS - not previously investigated as a self-rejected trace artifact

### Why It Failed

The hypothesis would be based on a profiling artifact rather than authoritative benchmark evidence. A future budget-metering hypothesis needs either non-Tracy micro-instrumentation, an A/B benchmark, or a source-level mechanism that removes real work outside the `feature = "tracy"` block.

### Lesson Learned

High self-time for a Rust Tracy span is not automatically a production bottleneck when the span body emits per-event text/value data. Always check whether the measured work exists in non-Tracy builds before promoting a metering hotspot.
