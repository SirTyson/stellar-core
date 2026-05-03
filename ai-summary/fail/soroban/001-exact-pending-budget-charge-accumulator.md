# H001: Exact Pending Budget-Charge Accumulator for Constant Hot Costs

**Date**: 2026-05-03
**Subsystem**: soroban / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in high-frequency Soroban host budget charging
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Released p26 ledgers should keep exact per-call budget metering. In the next-protocol apply-load build, the Soroban host should still charge deterministic CPU and memory totals, preserve tracker totals, and fail before any observable side effect that would have been rejected by the old budget state. It should not physically run the full generic `BudgetImpl::charge` path for every tiny constant hot cost when the exact charged amount can be reserved and accumulated safely.

## Mechanism

`BudgetImpl::charge` currently updates tracker fields, evaluates CPU and memory cost models, checks CPU and memory limits, and records the `charge` Tracy span for every charge (`src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284`, `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188`). The previous broad accumulator idea was rejected because `(iterations, input_sum)` aggregation changes rounded linear-cost totals and because its flush-boundary map was incomplete. A narrower next-protocol accumulator should start with constant hot costs only, such as `DispatchHostFunction`, `InvokeVmFunction`, eligible fixed-size shallow-copy charges, and other preclassified zero-linear-term costs; it can add each already-rounded amount to pending CPU/memory counters, pre-reserve against the hard limit in deterministic chunks, and flush before fuel transfer, budget inspection, shadow/debug accounting, host/VM boundary exits, and transaction finalization.

This differs from the failed broad accumulator because it does not aggregate variable-input linear costs by input sum, and it makes mandatory flush/pre-reserve boundaries part of the mechanism. It also differs from the accepted `protocol-gated-host-metering-coalescing` success, which removed specific `VisitObject` and `ValSer` micro-metering surfaces; the current diagnostic trace still reports `charge` self-time after that success.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Successful swaps execute millions of host-function dispatches, VM invocations, map/vector accesses, shallow clones, storage operations, and conversion helpers beneath `applyLedger`; in a next-protocol build those constant-cost charges can be accumulated in deterministic chunks instead of paying the full generic charge machinery each time.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge`; add next-protocol pending exact-charge state, pre-reservation, and mandatory flush APIs.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge`; current per-charge cost-model evaluation and CPU `charge` Tracy span.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — per-call rounded linear evaluation; the accumulator must exclude or exactly preserve these semantics.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:291-296` — dispatch boundary that transfers host budget to VM fuel and must flush pending CPU first.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:325-345` — VM call boundary that adds/returns fuel and must not observe stale pending charges.
- `src/rust/src/soroban_proto_any.rs:458-459` — post-invocation budget reporting must flush pending charges before reading consumed CPU/memory.

## Evidence

The current soroswap diagnostic trace reports `charge` at `soroban-env-host/src/budget/dimension.rs:176` with **1,758,199,707 ns self-time across 20,300,668 calls**. The relevant caller chain is under `applyLedger`: `applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applySorobanStageClustersInParallel` -> `InvokeHostFunctionOpFrame doParallelApply` -> Rust `invoke_host_function` -> `Host::invoke_function`. Adjacent zones that still depend on hot charging include `call` (`vm/dispatch.rs:304`, 922,554,179 ns self), `map lookup indexed` (408,451,716 ns), `map lookup` (345,449,339 ns), and `new map` (331,023,872 ns).

The previous reviewer record for `001-next-protocol-budget-charge-accumulator.md` explicitly identified a viable refinement path: track exact per-call charged amounts or restrict eligibility to costs whose rounding semantics cannot change, and add an explicit mandatory-flush API for fuel transfer and public budget observers. This hypothesis is that refined design, constrained to constant hot costs first so it can preserve exact totals while attacking the remaining budget-charge machinery.

## Anti-Evidence

Budget failure timing is consensus-sensitive. If the flush map misses a public budget observer, a VM fuel transfer, shadow-mode transition, debug tracker read, or error path, the optimization can over-issue work before `ExceededLimit` becomes visible. The non-Tracy benchmark is authoritative, so the PoC must show real apply-time improvement rather than only removing Tracy span overhead. If the safe constant-cost subset is too small, or if pre-reservation/flush overhead approaches the removed charge work, the improvement will fall below the 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — this is the refinement suggested by `fail/soroban/001-next-protocol-budget-charge-accumulator.md`, not an exact duplicate; it is also distinct from `success/soroban/001-protocol-gated-host-metering-coalescing.md`
**Failed At**: reviewer

### Trace Summary

`BudgetImpl::charge` is on the Soroban apply path and does perform per-call tracker updates, CPU and memory model evaluation, CPU/memory limit checks, and the CPU-only Tracy `charge` span. The required flush points are real: VM-to-host dispatch returns fuel, charges `DispatchHostFunction`, and later adds remaining host budget back to VM fuel, while top-level VM calls add/return fuel around `func.call` and post-invocation C++ reporting reads consumed CPU/memory from the shared `Budget`. However, after the accepted `VisitObject` / `ValSer` coalescing, the submitted constant-cost subset is too small and too weakly quantified to clear the optimize-soroswap Medium threshold; the hypothesis still projects from the full residual `charge` zone and adjacent map/dispatch zones that include work outside the exact constant-charge accumulator.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates `meter_count`, per-cost tracker iterations/inputs, CPU total, CPU tracker amount, CPU limit, memory total, memory tracker amount, and memory limit on every charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` evaluates the cost model and emits the `charge` Tracy span only for `IsCpu(true)`, so the cited span is not the full generic charge path and is not proof that all residual calls are removable by this mechanism.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — `MeteredCostComponent::evaluate` preserves exact per-call rounding for `Some(input)` by evaluating each call independently; avoiding `(iterations, input_sum)` fixes the prior correctness bug, but variable-input charges still need either per-call evaluation or carefully precomputed call-site-specific exact amounts.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-296` — generated host-function dispatch returns VM fuel to host budget, charges `DispatchHostFunction`, executes the host call, then supplies remaining host CPU budget back to VM fuel; any pending CPU charge must be flushed before the final fuel transfer.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:275-345` — `Vm::metered_func_call` charges `InvokeVmFunction`, adds host CPU budget to the VM before `func.call`, and returns consumed fuel after the call; stale pending CPU would overstate fuel available to Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — `add_fuel_to_vm` reads `Budget::get_wasmi_fuel_remaining`, and `return_fuel_to_host` bulk-charges `WasmInsnExec`; these are mandatory flush/interaction points for any pending-charge design.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1391-1429` and `src/rust/src/soroban_proto_any.rs:458-459` — public tracker/time/CPU/memory observers and C++ post-invocation reporting read budget state directly, so pending charges must be materialized before these reads.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83,168-240` — hot map lookups charge `MemCpy` with inputs derived from entry size and map length, so they are not covered by a simple constant `None`-input accumulator despite being cited as adjacent `map lookup` evidence.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:49-94` — shallow-copy and heap-allocation helpers charge `MemCpy` / `MemAlloc` with explicit byte inputs; these can only be made exact without generic evaluation when the call site has a precomputed amount for the current network cost model and input.

### Why It Failed

The mechanism fixes the prior rounding objection for true constant costs, but the Medium performance claim is not supported by the code path it can safely cover. The clearly constant named costs are `DispatchHostFunction` and `InvokeVmFunction`; `DispatchHostFunction` occurs once per VM-to-host call and `InvokeVmFunction` once per VM export invocation, while prior dispatch-focused review already bounded dispatch micro-optimizations around roughly 19,982 dispatches below the 3% floor. `VisitObject`, the former million-call constant cost, has already been addressed by the accepted coalescing success, and `ValSer` was also coalesced there.

The remaining high-frequency cited work is mostly not a pure constant-cost accumulator target. `MeteredOrdMap` lookup charges use `MemCpy` with byte inputs depending on map entry size and binary-search magnitude; shallow clones and heap allocations also use `MemCpy` / `MemAlloc` with explicit byte inputs. To include those exactly, a PoC would either still run per-call model evaluation before accumulating the already-rounded amount, which leaves much of `BudgetDimension::charge`'s CPU work in place, or add broad call-site-specific precomputed exact-charge APIs not specified or quantified here. The hypothesis therefore continues to project from the full 20.3M-call residual `charge` span and adjacent map/new-map zones even though only an unmeasured subset is safely removable.

Under the optimize-soroswap objective, Low findings are rejected. The accepted `protocol-gated-host-metering-coalescing` change removed a larger, directly measured `VisitObject`/`ValSer` metering surface and still produced only a 2.10% soroswap median improvement; the residual true-constant subset left by this hypothesis is less compelling than that prior Low result unless a cost-type histogram or dedicated benchmark proves otherwise. As submitted, it is a plausible future direction but not a Medium-or-High viable finding.

### Lesson Learned

For Soroban budget-charge optimizations, distinguish "all residual `charge` events" from the subset whose exact charge can be skipped without per-call model evaluation or broad call-site rewrites. After `VisitObject` and `ValSer` coalescing, a Medium accumulator hypothesis needs a cost-type distribution or direct measurement showing that the exact eligible subset alone can save at least 3% of apply time.
