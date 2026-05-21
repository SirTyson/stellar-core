# H002: Exact Pending Budget Charge Batching for Hot Host Metering

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: Medium
**Impact**: apply-time reduction by reducing millions of small `BudgetImpl::charge` calls in Soroban host execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During successful soroswap apply, host metering should update the same deterministic CPU and memory totals, enforce the same budget-exceeded boundary before any externally observable result, and report the same per-cost tracker totals for the new protocol's chosen metering semantics. The implementation should not run the full `BudgetImpl::charge` path for every tiny internal operation when several adjacent charges can be accumulated exactly and flushed before fuel transfer, shadow-mode work, public budget observation, serialization failure boundaries, and frame completion.

## Mechanism

`BudgetImpl::charge` currently performs tracker updates, CPU cost-model lookup/evaluation, limit checking, memory cost-model lookup/evaluation, and memory limit checking for every metered operation. After the accepted protocol-gated `VisitObject`/`ValSer` coalescing, the current trace still shows `charge` as a top apply-path hotspot: 1,758,199,707 ns self-time across 20,300,668 calls, all contained within `applyLedger`. A next-protocol exact pending-charge buffer that stores already-rounded `(cpu_amount, mem_amount, iterations, input_total)` deltas per `ContractCostType` and flushes at mandatory observer/error boundaries would preserve deterministic totals while replacing long runs of tiny internal charges with amortized checks, making a 3-10% soroswap apply-time win plausible if most of the residual `charge` calls are eligible.

## Trigger

Run the soroswap apply-load benchmark with the current next-protocol baseline. The trigger is any successful ledger with many Soroswap swaps: router/pool Wasm execution plus SAC transfers generates tens of millions of host metering calls through map/vector operations, object conversions, storage access, auth frame handling, and dispatch. The candidate should be validated by adding temporary per-cost eligibility counters, then rerunning `scripts/run_apply_load_matrix.py` to confirm the eligible subset of `charge` calls is large enough before implementing the accumulator.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` currently updates tracker fields and charges/checks CPU and memory dimensions on every call.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` evaluates the cost model and emits the hot `charge` Tracy span for CPU charges.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:286-303` — `get_wasmi_fuel_remaining` is a mandatory flush boundary before converting remaining CPU budget to VM fuel.
- `src/rust/soroban/p26/soroban-env-host/src/budget/util.rs:190-210` — shadow-mode entry/exit is a mandatory flush boundary because shadow totals and non-shadow totals must not mix.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:304` — VM call and host-function dispatch boundaries where pending charges must be flushed before fuel synchronization or returning to Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-82` and `:109` — metered XDR paths must flush before returning errors or externally observed budget totals.

## Evidence

The current trace from `ai-summary/CURRENT_STATE.md` shows the post-coalescing residual `charge` zone remains large: `charge,soroban-env-host/src/budget/dimension.rs:176,1,758,199,707 ns,20,300,668 calls` in self-time export, and unwrap containment found the same 1.758s/20.3M calls entirely inside the 71 `applyLedger` windows. Unlike already-rejected single micro-optimizations, this target is the shared physical metering path for the residual host execution zones also visible in apply (`map lookup` 580,114,128 ns, `map lookup indexed` 543,656,426 ns, `new map` 449,677,501 ns, `ScVal to Val` 995,921,819 ns, `storage get` 641,710,601 ns). Those zones all route through `BudgetImpl::charge`, so an exact accumulator attacks a cross-cutting cost center rather than a sub-1% callsite.

The prior rejected input-summing accumulator failed because aggregating `(iterations, input_sum)` can change linear-model rounding. This hypothesis avoids that specific failure by requiring each charge to compute the already-rounded CPU and memory amount before buffering, then adding those exact amounts to the dimensions and tracker on flush. This preserves totals while amortizing tracker writes, limit checks, and RefCell/borrow-heavy budget plumbing across batches.

## Anti-Evidence

A previous production-budget-tracker PoC regressed, so the physical accumulator can easily lose if it adds branches, cache misses, or flush complexity on every charge. The Medium case depends on direct eligibility measurement: if only a small fraction of the 20.3M residual calls can be buffered across safe boundaries, the idea should be rejected as below threshold. The design must also prove budget-exceeded timing remains acceptable for the next protocol: delaying a limit error is only safe at explicitly defined flush points before any observable host/VM boundary, storage/output mutation, diagnostic/shadow-mode observation, or returned result.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entries `001-exact-pending-budget-charge-accumulator.md + 002-exact-budget-charge-hot-subset.md` and follow-up to `001-next-protocol-budget-charge-accumulator.md`
**Failed At**: reviewer

### Trace Summary

The core hot path is real: `BudgetImpl::charge` updates the per-cost tracker, evaluates CPU and memory cost models through `BudgetDimension::charge`, records totals, and checks limits for every `Budget::charge`/`bulk_charge` caller. VM execution crosses mandatory budget-observation boundaries in `Vm::metered_func_call`, generated host-function dispatch, and `FuelRefillable::{return_fuel_to_host,add_fuel_to_vm}`, while public budget getters and shadow-mode transitions also read or switch the same counters. However, the exact pending-charge accumulator family has already been reviewed and failed promotion for this objective because it lacks direct post-coalescing measurement of the eligible subset and therefore cannot establish the required >=3% apply-time savings.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:58` — prior exact pending accumulator / exact hot-subset entry requires measured eligible constant-cost distribution and non-Tracy evidence before Medium promotion.
- `ai-summary/fail/soroban/summary.md:60` — prior next-protocol budget accumulator failed because input-sum batching changes linear rounding and mandatory flush boundaries were incomplete; it explicitly points future work toward exact already-rounded charge buffering.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` performs the claimed tracker updates, CPU charge, CPU limit check, memory charge, memory tracker update, and memory limit check.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — each dimension charge evaluates the cost model and updates total or shadow total; the Tracy `charge` span instruments CPU charges only.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1391-1429` — tracker and consumed/remaining-budget accessors are public observer boundaries, and `get_wasmi_fuel_remaining` converts current CPU remaining into fuel.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345` and `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-39` — VM calls transfer host budget to wasmi fuel and back, so pending CPU charges would have to be flushed before both fuel refill and fuel return accounting.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-242,291-294` — every generated host-function import returns VM fuel to host, charges dispatch, executes host work, then refills fuel before returning to Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/budget/util.rs:190-214` — observable shadow mode changes `is_in_shadow_mode` around a closure and checks shadow limits, so pending production and shadow totals cannot be mixed.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-82` — metered XDR serialization/deserialization converts metering errors into host errors at return boundaries, requiring exact budget state before error observation.

### Why It Failed

This hypothesis is not novel. It is the refined "already-rounded exact pending charge" version requested by the earlier failed `001-next-protocol-budget-charge-accumulator.md`, and it overlaps the later `001-exact-pending-budget-charge-accumulator.md + 002-exact-budget-charge-hot-subset.md` fail-summary entry. The current writeup still does not provide the direct eligibility counters, per-cost distribution, or repeated non-Tracy apply-load evidence needed to show that the safely bufferable post-coalescing subset reaches the optimize-soroswap Medium threshold; it projects from aggregate residual `charge` self-time, which prior reviews already identified as insufficient.

### Lesson Learned

Budget-charge accumulator proposals should not be promoted from aggregate `BudgetDimension::charge` Tracy time. A novel candidate must first quantify the exact flush-safe cost-type subset after existing coalescing and demonstrate a >=3% apply-time win with non-Tracy benchmark evidence.
