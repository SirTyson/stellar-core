# H001: Specialize the Soroban Budget Charge Hot Path

**Date**: 2026-04-29
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by lowering per-charge overhead while preserving exact budget accounting
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban budget charge during `InvokeHostFunctionOpFrame::doParallelApply` should still occur in the same order, use the same `ContractCostType`, iterations, and input values, update CPU and memory totals exactly as today, and raise `ExceededLimit` at the same point for near-limit transactions. The implementation should only reduce the physical overhead of computing and recording each charge; it must not batch, skip, reorder, or approximate charges.

## Mechanism

`BudgetDimension::charge` is called extremely frequently from storage maps, host-object traversal, XDR serialization, VM dispatch, and SAC helper paths. Each call performs a generic cost-model lookup and evaluation before adding the amount to the CPU or memory total; in Tracy builds it also opens a `charge` span and emits text/value for every CPU charge. A specialized hot path for common p26 charge shapes, such as cached direct access to `(const_term, lin_term)` and inlined evaluation for `input == None` or simple linear inputs, should preserve exact totals and per-call limit semantics while reducing millions of small dynamic-dispatch/evaluation costs in soroswap apply.

## Trigger

Run the current soroswap diagnostic trace from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`.
Export `applyLedger` and `charge` events with `csvexport-release -u`, then timestamp-filter `charge` events into the `applyLedger` windows. The filtered trace shows `charge` at `soroban-env-host/src/budget/dimension.rs:176` consuming 2,043,955,266 ns across 18,721,841 apply-window calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-187` — `BudgetDimension::charge` performs generic cost-model lookup/evaluation and total updates for every CPU/memory charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:365-372` — common high-frequency costs such as `VisitObject`, `ValSer`, `MemCpy`, and related small-object costs have simple constant or linear model terms that can be evaluated without a full generic path.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:450-468` — high-frequency host-object allocation/visit callers that feed the hot charge path during SAC and router calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — storage and map operations repeatedly charge comparison/copy work through the same hot path.

## Evidence

The target is a descendant of the measured apply path: the filtered `charge` events fall inside `applyLedger`, whose hot child path is `applyTransactions` -> `applySorobanStages` -> `applySorobanStageClustersInParallel` -> `TransactionFrame::parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply` -> Rust host execution. The absolute call count is high enough that even tens of nanoseconds of removable overhead per charge can become a Medium-tier aggregate worker saving. This is distinct from the rejected "batch host object budget visits" family: the proposed optimization keeps each charge as an individual event with identical totals and limit checks, and only specializes how the amount is computed and added.

## Anti-Evidence

Budget totals are consensus-visible via `cpu_insns` and `mem_bytes`, so any PoC must prove exact output equality for near-limit transactions and not merely reduce physical CPU. Some of the Tracy self-time is instrumentation-only from the per-charge `tracy_span!`, so the non-Tracy benchmark may recover less than the diagnostic trace suggests. If the cost-model lookup/evaluation is already optimized away in release non-Tracy builds, this may fall below the Medium threshold despite the large trace count.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no duplicate found in `ai-summary/fail/transactions` or `ai-summary/success/transactions`; cross-subsystem fail/success directories were absent
**Failed At**: reviewer

### Trace Summary

The target is on the parallel Soroban apply path: `applySorobanStageClustersInParallel` launches cluster workers, each transaction reaches `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, the Rust bridge, and p26 host budget charging. However, the cited Tracy `charge` zone at `dimension.rs:176` starts after `get_cost_model()` and `MeteredCostComponent::evaluate()` have already run, and ends before the total-count update, so it primarily measures per-charge Tracy span creation plus `emit_text`/`emit_value`, not the generic arithmetic the proposed specialization targets. In the authoritative non-Tracy benchmark configuration, `tracy_span!` compiles to `()`, and the remaining charge evaluation is already a monomorphic array lookup plus simple saturated arithmetic that still must be performed for both CPU and memory and followed by tracker and limit updates.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2488-2563` — Soroban cluster workers call `TransactionFrame::parallelApply` inside `applyThread`, then `future.get()` waits for completion on the apply path.
- `src/transactions/TransactionFrame.cpp:2385-2430` — parallel apply dispatches the single Soroban operation through `OperationFrame::parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584,603-629,1358-1377` — invoke parallel apply enters the Rust bridge and treats returned `cpu_insns`/`mem_bytes` as resource-limit outputs.
- `src/rust/src/soroban_proto_any.rs:412-458,478-506` — bridge constructs a `Budget`, calls p26 `invoke_host_function`, then reads consumed CPU and memory for the C++ result.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-481` — enforcing apply builds storage/auth/host state and runs `Host::invoke_function` with the shared `Budget`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284,1323-1325` — every `Budget::charge` mutably borrows the budget, updates the tracker, charges CPU, checks CPU limits, charges memory, and checks memory limits.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-187` — `BudgetDimension::charge` evaluates the amount before entering the Tracy-only `charge` span; the span encloses only Tracy emission, not cost-model lookup/evaluation or total updates.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:88-133` — `MeteredCostComponent::evaluate` is statically dispatched on a concrete component and performs simple constant/linear saturated arithmetic.
- `src/rust/soroban/p26/soroban-env-host/src/macros.rs:8-25` — in non-Tracy builds, `tracy_span!` expands to `()`, eliminating the measured per-charge instrumentation.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:446-475` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83,168-242` — high-frequency host-object and map callers do feed the charge path, but their budget calls must remain ordered and observable.

### Why It Failed

The hot path exists, but the measured evidence does not support the proposed Medium-tier optimization. The 2.04s aggregate `charge` total comes from a diagnostic Tracy run, and the specific zone location excludes the cost-model lookup/evaluation that the hypothesis wants to specialize; it measures instrumentation that is absent from the authoritative non-Tracy runs. The non-Tracy charge computation is already cheap and monomorphic, with no dynamic dispatch to remove, while most surrounding work in `BudgetImpl::charge` is mandatory resource tracking and per-dimension limit checking needed to preserve exact near-limit behavior. Even assuming a tiny arithmetic/bounds-check saving across millions of calls, the source trace does not justify a reproducible 3-10% soroswap apply-time reduction after dividing aggregate worker savings across the T=8 parallel critical path.

### Lesson Learned

Per-charge Tracy zones must be interpreted from their lexical scope before projecting apply-time savings. In this case, a line-176 `charge` event is a measurement-artifact hotspot, not proof that generic cost-model evaluation dominates non-Tracy apply time; future budget-charge hypotheses need either non-Tracy microbench evidence for the actual arithmetic path or a source-backed way to remove mandatory tracker/limit work while preserving exact metering.
