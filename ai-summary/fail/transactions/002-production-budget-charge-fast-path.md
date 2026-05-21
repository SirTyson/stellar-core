# H002: Production Budget Charge Fast Path with Minimal Reporting Trackers

**Date**: 2026-05-20
**Subsystem**: transactions / Soroban budget enforcement during invoke apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing per-budget-charge bookkeeping on the Soroban invoke hot path while preserving budget limits and transaction resource outputs
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban apply should enforce the same CPU and memory limits, return the same total `cpu_insns` and `mem_bytes`, preserve `cpu_insns_excluding_vm_instantiation` for transaction metrics, and raise resource-limit errors at the same deterministic points. In production apply, however, per-cost-type reporting fields that are only used for calibration, tests, diagnostics, or detailed budget introspection should not have to be updated on every charge if the transaction result and limit checks only require total CPU, total memory, and a small explicitly-needed subset such as VM-instantiation CPU/time.

## Mechanism

`BudgetImpl::charge` updates `BudgetTracker` on every non-shadow charge before and after charging CPU and memory: it increments the global meter count, accumulates per-cost-type iterations and inputs, records per-cost-type CPU and memory, and then calls both `BudgetDimension::charge` paths. The tracker is documented as "for calibration and reporting; not used for budget-limiting nor does it affect consensus", but the production invoke bridge only reads total CPU/memory and subtracts VM-instantiation-specific counters for reporting. A next-protocol or config-gated production mode that keeps exact total CPU/memory counters and the small counters still read by `invoke_host_function_or_maybe_panic`, while skipping the rest of `BudgetTracker` updates and using a streamlined charge path, should reduce the cost of the remaining 20M+ budget charges without changing deterministic resource enforcement.

## Trigger

Run the accepted soroswap apply-load scenario (`soroswap, TX=2000, T=8`) with the current next-protocol baseline. Map-heavy router/SAC execution repeatedly calls the Soroban budget charge path from storage, object conversion, VM dispatch, and XDR serialization during `InvokeHostFunctionOpFrame::doParallelApply`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:197-205` — `BudgetImpl` stores the enforcing dimensions plus the reporting-only `BudgetTracker`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` performs per-cost-type tracker updates for every charge before and after CPU/memory accounting.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` evaluates a cost model and updates total CPU or memory counters; this is the irreducible enforcement core.
- `src/rust/src/soroban_proto_any.rs:458-466` — the C++ bridge reads total CPU/memory and VM-instantiation counters after invocation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-590` — C++ receives those totals into `SorobanMetrics` for transaction application.

## Evidence

The current soroswap trace reports `charge` at `soroban-env-host/src/budget/dimension.rs:176` with 1,758,199,707 ns of apply-window overlap across 20,413,505 calls. This is inside `applyLedger` through `InvokeHostFunctionOpFrame doParallelApply` and not TX-set construction; normalized by the configured eight soroswap clusters, even the visible aggregate is roughly a 4.2% critical-path upper bound. Source inspection shows additional per-charge work outside the Tracy span in `BudgetImpl::charge`: tracker lookup, `meter_count`, iterations/input accumulation, and per-cost CPU/memory accumulation. Because accepted host-metering coalescing already showed that reducing high-count physical metering overhead can move soroswap apply time, a production fast path for the remaining charge bookkeeping has Medium-tier headroom if it removes a substantial fraction of the per-charge overhead.

## Anti-Evidence

The line-176 Tracy span includes Tracy-only instrumentation in diagnostic builds, so the PoC must validate with non-Tracy apply-load runs rather than treating the full span as removable production cost. The optimization must also preserve any budget fields that are externally observed by C++, tests, diagnostics, or simulation; in particular VM-instantiation CPU/time subtraction and exact near-limit failure behavior must remain unchanged. If most of the non-Tracy overhead is actually cost-model evaluation or required limit checking rather than reporting updates, the measurable gain may fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to `001-specialize-budget-charge-hot-path.md`, but not an exact duplicate because this version specifically targets reporting tracker updates rather than generic cost-model specialization.
**Failed At**: reviewer

### Trace Summary

The apply path is `LedgerManagerImpl::applyThread` -> `TransactionFrame::parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply` -> `InvokeHostFunctionApplyHelper::invokeHostFunction` -> Rust `invoke_host_function_or_maybe_panic` -> p26 `e2e_invoke::invoke_host_function`. Within that Rust invocation, storage, XDR, host-object, VM-dispatch, and wasmi-fuel paths call `Budget::charge`/`bulk_charge`, which updates `BudgetTracker`, evaluates CPU and memory cost models, updates total counters, and checks limits. After invocation, the bridge reads total CPU/memory and only the VM-instantiation tracker/time fields for C++ outputs; other tracker fields are mainly calibration/test/debug reporting. The reporting tracker overhead exists, but the only quantified Medium-tier evidence is a Tracy-only span inside `BudgetDimension::charge`, not a production measurement of tracker updates.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — parallel Soroban workers apply each transaction in a cluster and call `parallelApply` on the hot apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-638` — C++ invokes Rust for every Soroban transaction and uses returned CPU/memory totals for metrics and failure classification.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `doParallelApply` performs the host invocation, records storage changes, consumes refundable resources, and finalizes success per transaction.
- `src/rust/src/soroban_proto_any.rs:391-506` — the Rust bridge constructs a configured `Budget`, executes p26 invoke, reads total CPU/memory, and reads only `VmInstantiation` tracker/time for exclusion metrics.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-520` — p26 invocation builds enforcing storage and host state, executes the host function, then extracts results, ledger changes, and events while using the same budget.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:26-44` and `src/rust/soroban/p26/soroban-env-host/src/budget.rs:197-284` — `BudgetTracker` holds per-cost reporting fields, and `BudgetImpl::charge` updates meter count, iterations, inputs, per-cost CPU, and per-cost memory on every non-shadow charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — the mandatory CPU/memory dimension path evaluates the cost model, updates total or shadow total, and contains the cited line-176 Tracy-only `charge` span.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1391-1418` — public readers expose per-cost trackers/time plus total CPU and memory; production bridge uses totals and the VM-instantiation subset.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-82` — common hot subpaths charge budget for wasmi fuel and XDR serialization/deserialization.
- `src/rust/soroban/p26/soroban-env-host/src/cost_runner/runner.rs:68-84` and `src/rust/soroban/p26/soroban-env-host/src/test/budget_metering.rs:14-210` — calibration/test code directly relies on detailed tracker iterations and inputs, so any skip mode must be production-only or explicitly gated.
- `scripts/run_apply_load_matrix.py:34-41` and `scripts/run_apply_load_matrix.py:120-124` — the accepted soroswap scenario runs with metrics disabled by default, so C++ Medida publication is not the source of the apply-load target overhead.

### Why It Failed

The inefficiency is real, but the Medium severity claim does not survive the trace. The cited 1.758s / 20.4M-call `charge` evidence is the `#[cfg(feature = "tracy")]` span at `BudgetDimension::charge` line 176, after cost-model evaluation and outside the `BudgetImpl` tracker updates this hypothesis proposes to skip. In non-Tracy apply-load builds that span collapses to the mandatory total-counter update, while the mandatory cost-model evaluation, CPU total update, memory total update, and both limit checks must remain to preserve deterministic resource enforcement and error points.

The removable tracker work is only a handful of scalar saturating additions, an input-shape match, and per-cost array accesses around the two mandatory dimension charges. Even across roughly 20M aggregate worker calls, that must be divided by the eight configured Soroban clusters before comparing to the 5.23s apply window, and there is no non-Tracy microbenchmark or isolated production timing showing these tracker-only updates can recover the objective's 3% Medium floor. This also matches the prior `001-specialize-budget-charge-hot-path.md` lesson: line-176 budget-charge Tracy zones are measurement-artifact hotspots unless backed by production measurements of the exact arithmetic being removed.

### Lesson Learned

Budget-charge hypotheses need non-Tracy measurements of the exact removable production work. The detailed tracker is not consensus-critical for most production outputs, but removing it is a micro-optimization unless the tracker-only slice is isolated above the objective threshold; Tracy-only per-charge spans cannot be used as a Medium-tier apply-time projection.
