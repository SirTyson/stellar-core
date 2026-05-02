# H002: Fast-Path Zero-Memory Soroban Budget Charges

**Date**: 2026-05-02
**Subsystem**: soroban / rust
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in high-frequency host budget metering
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Charging a cost type whose memory model is statically zero should produce exactly the same observable budget state as the generic path: identical `meter_count`, per-cost tracker iterations/input/cpu/mem totals, CPU total, shadow totals, and CPU limit failure behavior. It should not spend time evaluating the memory dimension, updating a zero memory total, or checking a memory limit that cannot change for that charge.

## Mechanism

`BudgetImpl::charge` currently runs the same generic path for every cost type: update the tracker, evaluate and check the CPU dimension, evaluate and check the memory dimension, then update `tracker.mem`. For hot constant CPU-only costs such as `DispatchHostFunction` and `VisitObject`, `budget.rs` defines memory cost as exactly zero, yet every call still pays the memory-dimension lookup/evaluation/check and generic `Option`/`Result` plumbing. The current soroswap trace shows the `charge` zone under `applyLedger` at 1,758,316,809 ns across 18,706,355 events, and `visit host object` alone accounts for 2,728,946,416 ns inside `applyLedger` across 3,478,780 visits; a narrow zero-memory fast path can remove repeated generic metering overhead while preserving exact CPU metering.

## Trigger

Run the soroswap apply-load benchmark. The workload executes millions of host-object visits, storage-map lookups, host dispatches, and XDR/conversion steps inside parallel Soroban apply; each calls into `Budget::charge` or related bulk-charge helpers. The issue is most visible in Tracy with `csvexport-release -e`, where `charge` is one of the largest apply-window self-time zones.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` generic tracker/CPU/memory path; add a fast path for preclassified zero-memory models.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` performs cost-model lookup/evaluation and total update for both CPU and memory dimensions.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — `MeteredCostComponent::evaluate` generic constant/linear evaluation that can be bypassed for known constant models.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:361-368,715-721` — `DispatchHostFunction` and `VisitObject` have constant CPU cost and zero memory cost in the default model; network-config-loaded models should be preclassified after config load rather than assumed from defaults.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:468-475` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:237-242` — high-frequency callers of `VisitObject` and `DispatchHostFunction` charges.

## Evidence

Using the current diagnostic trace from `ai-summary/CURRENT_STATE.md`, an event-containment check against all 70 `applyLedger` windows found `charge` events totaling 1,758,316,809 ns inside the apply windows. Focused self-time export also shows `visit host object` at 2,735,707,479 ns / 3,491,848 calls process-wide, with 99.75% of that time inside `applyLedger`; every visit calls `charge_budget(ContractCostType::VisitObject, None)` before borrowing the object table.

The proposed implementation is not a metering reduction. It should classify each cost type's CPU and memory models once when a `Budget` is built from ledger config, then for types with `mem.const_term == 0`, `mem.lin_term == 0`, and input shape compatible with the tracker, update only the CPU dimension and set the memory charged amount to zero. The ledger result, fee/resource accounting, and budget tracker output should remain bit-for-bit equivalent.

## Anti-Evidence

There is a prior failed record for a broad "specialize budget charge hot path" attempt whose final-review handoff was not reproducible because the PoC edits were not committed. This hypothesis should be reviewed as a narrower, protocol-preserving zero-memory-dimension skip; if that prior attempt already implemented the same fast path, this should be treated as a duplicate. The impact also depends on the fraction of the `charge` zone spent in removable memory-dimension/generic-evaluation overhead rather than unavoidable tracker and CPU-limit updates, so a PoC must show `charge` self-time falling and repeated non-Tracy apply-load runs clearing the 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — adjacent condensed failure `002-specialize-budget-charge-hot-path` exists, but the retained fail/success records do not show this exact zero-memory-dimension skip was previously investigated
**Failed At**: reviewer

### Trace Summary

The proposed inefficiency is real: `BudgetImpl::charge` always charges both `cpu_insns` and `mem_bytes`, and `DispatchHostFunction` / `VisitObject` have default memory models with `const_term = 0` and `lin_term = 0`. However, the cited Tracy `charge` zone is not around the whole `BudgetImpl::charge` path; it is created only inside the CPU `BudgetDimension::charge` branch after CPU cost evaluation, and memory-dimension charging has no corresponding Tracy child span. A zero-memory fast path would therefore leave the cited 1.758s `charge` zone essentially unchanged and can only remove the uninstrumented memory lookup/evaluate/add/check slice, which is too small to clear the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates tracker state, charges CPU, checks CPU limit, charges memory, updates zero `tracker.mem`, and checks memory limit for every cost type.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` looks up the cost model, evaluates it, creates the Tracy `charge` span only when `IsCpu(true)`, then saturating-adds the amount to the selected total.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — `MeteredCostComponent::evaluate` returns `const_term * iterations` for `None` inputs and skips the linear calculation when `lin_term` is zero.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:361-368,715-721` — default `DispatchHostFunction` and `VisitObject` models are constant CPU and exactly zero memory.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:468-475` — every host-object visit charges `VisitObject` before borrowing and indexing the object table.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-242` — every VM-to-host call returns fuel to the host and charges `DispatchHostFunction` before marshalling arguments.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1261-1325` — public `Budget::charge` and `bulk_charge` route through `BudgetImpl::charge`, so any optimization must preserve public budget/tracker behavior for both single and batched charges.
- `ai-summary/fail/soroban/summary.md:45` — prior condensed failure records a broad budget-charge specialization handoff failure, but not enough retained detail to establish an exact duplicate.

### Why It Failed

The hypothesis over-attributes the observed Tracy `charge` time to removable memory-dimension work. The actual `charge` span is CPU-only instrumentation in `BudgetDimension::charge`; skipping `mem_bytes.charge` for zero-memory models would not remove that span, the tracker update, CPU model evaluation, CPU total update, CPU limit check, public `RefCell` borrow, or the surrounding host-object lookup/dispatch work.

The remaining removable work is a tiny per-call sequence: one memory cost-model array lookup, `MeteredCostComponent::evaluate` on a zero model, a saturating add of zero to the memory total, a zero `tracker.mem` add outside shadow mode, and a memory-limit check. On the hot `VisitObject` path this runs about 3.5M times in the cited trace; even an unrealistically high 100ns saving per visit would be about 350ms aggregate CPU, or roughly 44ms wall on 8 parallel workers, under 1% of the cited multi-second apply run. Including `DispatchHostFunction` adds only tens of thousands of calls, and broader zero-memory charge types would still need to save a large fraction of the CPU-only `charge` zone to reach the 3% Medium floor, which this change structurally cannot do.

There is also a small correctness trap for a bit-for-bit public fast path: current `BudgetImpl::charge` still checks the memory budget after a zero memory charge, so a fast path that skips `mem_bytes.check_budget_limit` would differ if a caller continues using a budget that is already over its memory limit. This can be preserved, but preserving it further reduces the removable work.

### Lesson Learned

For Soroban budget optimizations, inspect where Tracy spans are placed before projecting impact from their totals. In p26, the `charge` span measures only the CPU-dimension instrumentation block, so memory-dimension skips must be valued from the small uninstrumented code they actually remove rather than from aggregate `charge` self-time.
