# H001: Flush-Bounded Exact Budget-Charge Accumulator

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing millions of hot host budget-charge calls without changing observed budget totals
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Protocol-next Soroban apply should charge the same CPU and memory totals, expose the same per-cost `BudgetTracker` values at every public observation point, and fail at the same budget limit boundaries as the current eager `BudgetImpl::charge` path. Successful soroswap transactions should still report identical `cpu_insns`, `mem_bytes`, fees, events, ledger entries, and result hashes, while avoiding repeated full `BudgetDimension::charge` bookkeeping for safe hot charge classes.

## Mechanism

The current hot path updates tracker fields, evaluates both CPU and memory dimensions, checks limits, and performs array/model lookups on every charge call. The current soroswap trace confirms `charge` at `soroban-env-host/src/budget/dimension.rs:176` is an in-`applyLedger` hotspot with **1,855,397,404 ns self-time over 20,819,272 calls**. A next-protocol-only exact accumulator can store already-rounded `(cpu_amount, mem_amount, iterations, input_total)` deltas for a restricted safe subset of charges and flush them before any observable boundary, preserving exact totals while collapsing most physical charge-call overhead.

## Trigger

Run the current soroswap apply-load benchmark with a protocol-next host that accumulates only allowlisted charges during successful host execution and flushes on:

1. every host-to-VM fuel transfer and VM-to-host fuel drain,
2. any budget-limit check that can return a user-visible `ExceededLimit`,
3. `Budget` observer calls used for `InvokeHostFunctionOutput`,
4. shadow-mode entry/exit,
5. metered-XDR failure paths, and
6. `Host::try_finish`.

The run should produce identical results and lower the `charge` self-time in a diagnostic Tracy trace. The hypothesis clears the Medium floor if the protocol-next accumulator captures at least two-thirds of the current `charge` self-time: roughly `(1.86s * 2/3) / 8 / 71 ~= 2.2 ms/ledger` in the Tracy window plus reduced cache pressure in the parallel workers, projected near the 3% threshold against the 250.7 ms non-Tracy soroswap median.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` currently updates tracker state and both dimensions eagerly on every call.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` performs model lookup/evaluation and emits the hot `charge` Tracy span.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — linear model evaluation; the accumulator must store already-rounded amounts, not raw input sums, for variable-input costs.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:286-303` — `get_wasmi_fuel_remaining` is a mandatory flush boundary before fuel transfer.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:291-295` — VM-boundary fuel refill after each host function must observe flushed CPU totals.
- `src/rust/src/soroban_proto_any.rs:458-466` — final `cpu_insns`, `mem_bytes`, and VM-instantiation subtraction must observe flushed tracker totals.

## Evidence

The current diagnostic trace places all selected `charge` events inside `applyLedger`: **20.8M calls / 1.855s self-time**. The code shows a high fixed physical overhead per charge beyond the arithmetic itself: tracker indexing and mutation, CPU model evaluation, CPU limit check, memory model evaluation, memory tracker mutation, and memory limit check. Many hot costs in `BudgetTracker::default` are constant-input classes (`DispatchHostFunction`, `VisitObject`, `InvokeVmFunction`, integer operations, many crypto curve helpers), so an exact accumulator can preserve per-call rounded totals by adding precomputed amounts rather than summing raw inputs. For variable-input classes, the design can still be exact by accumulating already-rounded `cpu_amount` and `mem_amount` returned by the current model for each call, flushing the same tracker fields before observation.

## Anti-Evidence

Prior budget-accumulator attempts failed when they aggregated `(iterations, input_sum)` and changed linear rounding, or when they skipped tracker detail and regressed benchmark results. This hypothesis is only viable if it is narrower: protocol-next only, already-rounded deltas only, explicit flush boundaries, and a first PoC that instruments the eligible subset before changing behavior. If the allowlisted subset is less than about two-thirds of current `charge` self-time, the saving falls below the objective's Medium floor and should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entries `001-next-protocol-budget-charge-accumulator.md` and `001-exact-pending-budget-charge-accumulator.md + 002-exact-budget-charge-hot-subset.md + 002-exact-pending-budget-charge-batching.md`
**Failed At**: reviewer

### Trace Summary

The current p26 source still routes every host budget charge through `BudgetImpl::charge`, updating `BudgetTracker`, both budget dimensions, and limit checks eagerly. The proposed flush boundaries are real: VM fuel return/refill crosses `FuelRefillable::return_fuel_to_host` and `FuelRefillable::add_fuel_to_vm`, final C++ bridge output reads budget totals through `get_cpu_insns_consumed`, `get_mem_bytes_consumed`, and `get_tracker`, and shadow mode changes accounting behavior in `Budget::with_shadow_mode`. However, this exact accumulator family has already been reviewed: the fail summary explicitly records that `(iterations, input_sum)` batching was rejected for rounding changes, then the exact-pending-charge refinement was rejected until the eligible post-coalescing subset is directly measured and shown to clear the 3% Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` performs eager tracker updates, CPU charge, CPU limit check, memory charge, memory tracker update, and memory limit check.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` evaluates the cost model, emits the Tracy `charge` span for CPU, and increments the dimension total.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — linear model evaluation rounds after multiplying `input * iterations`, confirming why earlier raw input aggregation changed totals.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — VM boundary fuel return/refill is a mandatory budget-observation boundary.
- `src/rust/src/soroban_proto_any.rs:458-466` — `InvokeHostFunctionOutput` reads final budget totals and per-cost tracker values.
- `ai-summary/fail/soroban/summary.md` — prior retained failures already cover next-protocol budget-charge accumulators, exact pending-charge batching, and the requirement to quantify the eligible subset after the accepted `VisitObject`/`ValSer` coalescing result.
- `ai-summary/success/soroban/001-protocol-gated-host-metering-coalescing.md` — accepted related optimization already removed/coalesced the largest previously identified fine-grained `VisitObject` and `ValSer` surfaces in the target objective context.

### Why It Failed

This is not novel. It is the refinement path already documented by the previous `001-next-protocol-budget-charge-accumulator.md` failure: track already-rounded `cpu_amount`/`mem_amount` deltas and flush at fuel, observer, shadow-mode, and metered-XDR boundaries. The later exact-pending-charge accumulator records were also rejected because, after the accepted protocol-gated `VisitObject`/`ValSer` coalescing result, the remaining eligible accumulator subset needs direct cost-type distribution or non-Tracy benchmark evidence to prove a Medium-severity apply-time reduction. This hypothesis still projects from aggregate `BudgetDimension::charge` self-time and an assumed two-thirds capture rate rather than providing the required measured eligible subset, so it is a duplicate of the retained prior investigation rather than a new viable finding.

### Lesson Learned

For Soroban budget-charge accumulator ideas, novelty requires a new measured distribution of residual charge self-time by cost type on the current post-coalescing baseline, plus evidence that the exact allowlisted subset alone can save at least 3% of soroswap apply time. Re-stating the exact pending-delta accumulator and flush-boundary design without that measurement is a duplicate of the prior failed review.
