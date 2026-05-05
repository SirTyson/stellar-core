# H002: Production budget mode without full per-cost tracker updates

**Date**: 2026-05-05
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing reporting-only budget bookkeeping from every host budget charge
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During enforcing-mode `closeLedger` execution, budget metering should still update the consensus-relevant CPU and memory totals, enforce the same limits at the same charge points, and return the same `cpu_insns`, `mem_bytes`, and VM-instantiation-excluding metrics needed by stellar-core. It should not have to update a full per-`ContractCostType` reporting table on every charge when that table is not part of consensus and is not consumed by the production apply path.

## Mechanism

`BudgetImpl::charge` updates `BudgetTracker` before and after every charge: it increments `meter_count`, accumulates per-cost iterations and inputs, and then stores per-cost CPU and memory amounts. The struct comment explicitly says the tracker is "for calibration and reporting; not used for budget-limiting nor does it affect consensus", while production C++ invocation output reads only total CPU/memory plus `get_tracker(VmInstantiation).cpu` and `get_time(VmInstantiation)` for excluding-VM-instantiation metrics. A production/enforcing budget mode that tracks only the totals and the small VM-instantiation fields should preserve ledger behavior while removing several saturating arithmetic operations, an input-shape match, and per-cost array traffic from millions of hot `Budget::charge` calls.

## Trigger

Run the current soroswap apply-load benchmark. Successful Soroban host execution performs tens of millions of budget charges under `applyLedger`; each charge updates the full `BudgetTracker` even though the ledger apply output does not consume the per-cost reporting table except for VM-instantiation accounting.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:197-203` — `BudgetImpl` stores `BudgetTracker` and documents it as calibration/reporting-only and non-consensus.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates `meter_count`, per-cost `iterations`, `inputs`, `cpu`, and `mem` around every CPU/memory budget charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` performs the consensus-relevant total-count update and limit accounting that must remain intact.
- `src/rust/src/soroban_proto_any.rs:458-466` — the C++ bridge consumes total CPU/memory and only `VmInstantiation` tracker/time for the excluding-instantiation fields.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1391-1418` — public getters show the distinction between per-cost tracker reads and total consumed CPU/memory reads.

## Evidence

The current soroswap Tracy trace reports `charge` self-time of `1,758,199,707 ns` across `20,300,668` calls. That span is inside `BudgetDimension::charge`; the tracker updates in `BudgetImpl::charge` sit outside that span, so the trace understates the total physical overhead associated with each budget charge. Because accepted success `001-protocol-gated-host-metering-coalescing` already demonstrated that reducing tiny per-charge host metering surfaces can move soroswap apply time, removing non-consensus tracker bookkeeping from the remaining charge path is a plausible Medium-tier follow-up if implemented as a production mode that leaves budget totals and limit checks unchanged.

## Anti-Evidence

Tests, debug displays, calibration tools, preflight, and diagnostic modes may rely on the full per-cost tracker, so the optimization should be mode-gated rather than deleting the tracker globally. The bridge currently uses `get_tracker(VmInstantiation).cpu`; a production-fast mode must still maintain that field or compute the excluding-instantiation value from a separate lightweight accumulator. This is distinct from prior exact-charge accumulator hypotheses: it does not batch or delay budget charges, so it should not change overflow timing or budget-exceeded behavior.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-05
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in retained `fail/soroban` or `success/soroban` records; the closest success, `001-protocol-gated-host-metering-coalescing`, removed/coalesced selected metering call sites, while this targets per-charge reporting bookkeeping that remains on all budget charges.

### Trace Summary

The close-ledger Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge through `invoke_host_function`, constructs a protocol budget from ledger network config, and executes the p26 host with enforcing storage and that shared `Budget`. Every host budget charge on this path calls `BudgetImpl::charge`, which first mutates `BudgetTracker` and then separately charges the CPU and memory `BudgetDimension`s that enforce limits and feed production aggregate metrics. The production C++ bridge reads aggregate CPU/memory totals and only the `VmInstantiation` tracker/time fields, while the full per-cost tracker is otherwise used for reporting, display, and calibration tooling.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2488-2518` — `applyThread` applies each Soroban transaction in a cluster during the parallel close-ledger phase.
- `src/transactions/TransactionFrame.cpp:2385-2430` — `TransactionFrame::parallelApply` dispatches the single Soroban operation to `OperationFrame::parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-590` — `invokeHostFunction` calls `rust_bridge::invoke_host_function` and records only aggregate CPU/memory and VM-instantiation-excluding timing/CPU outputs into host-function metrics.
- `src/rust/src/soroban_invoke.rs:7-39` — Rust bridge selects the protocol-specific host module from the ledger protocol and forwards the invocation.
- `src/rust/src/soroban_proto_any.rs:391-466` — protocol wrapper builds `Budget::try_from_configs`, invokes the p26 host, then reads `get_cpu_insns_consumed`, `get_mem_bytes_consumed`, `get_tracker(VmInstantiation).cpu`, and `get_time(VmInstantiation)`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — p26 host invocation decodes resources into enforcing storage, builds `Host::with_storage_and_budget`, executes `host.invoke_function`, and serializes results/ledger changes/events using the same budget.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` — every Wasm-to-host boundary returns consumed VM fuel to the host budget, charges `DispatchHostFunction`, executes the host function, and refills VM fuel from remaining budget.
- `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:35-40` — consumed Wasm fuel is bulk-charged as `WasmInsnExec`, so VM execution also uses the same `BudgetImpl::charge` path.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:197-284` — `BudgetImpl::charge` updates `BudgetTracker` (`meter_count`, `iterations`, `inputs`, per-cost CPU, per-cost memory) around the consensus-relevant CPU/memory dimension accounting.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:143-188` — `BudgetDimension::charge` updates the aggregate total and `check_budget_limit` enforces CPU/memory limits independently of the per-cost tracker.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1060-1118` — budget formatting uses the tracker table and meter count for diagnostics/reporting, not ledger outcomes.
- `src/rust/soroban/p26/soroban-env-host/src/cost_runner/runner.rs:68-83` — calibration runners consume the per-cost tracker, confirming that non-production tooling needs the full table.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:50-73` — `VmInstantiationTimer` records VM-instantiation wall time via `track_time`, one of the two tracker-derived production bridge outputs that must be preserved.

### Findings

The inefficiency exists on the claimed hot path. `BudgetImpl::charge` obtains the per-cost `CostTracker`, increments `meter_count`, accumulates `iterations`, matches and accumulates `inputs`, then later accumulates per-cost CPU and memory amounts for every non-shadow budget charge. These updates are separate from the aggregate `BudgetDimension` totals and limit checks that determine success/failure and from the aggregate `cpu_insns`/`mem_bytes` values returned to C++.

The path is hot enough for the objective. Soroswap apply executes successful Soroban host functions under `applyLedger`, and both host calls and VM fuel accounting repeatedly funnel through `Budget::charge`/`bulk_charge`. The hypothesis's trace count of about 20.3M charge calls means even a small per-call reduction removes repeated saturated arithmetic and per-cost array traffic from a dominant measured metering surface; unlike the prior `VisitObject`/`ValSer` coalescing success, this affects all remaining charge types rather than selected call sites. Given the existing baseline where removing several million fine-grained metering operations moved soroswap apply time by about 2%, eliminating reporting-only work from roughly six times as many charge invocations is plausibly in the 3-10% Medium band, pending benchmark confirmation.

The proposed change is correctness-preserving only if it is mode-gated and keeps the non-reporting semantics intact. CPU/memory totals, CPU/memory limit checks, shadow-mode behavior, Wasm fuel transfer timing, `VmInstantiation` CPU/time fields, and production output fields must remain identical. One subtle constraint is that the current tracker `inputs` match also rejects internal calls that pass `Some` for constant-cost types or `None` for input-sensitive types; a production-fast implementation should preserve this validation with a cheap expected-input check or otherwise prove that dropping this internal-error behavior is acceptable.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/budget.rs` (`BudgetImpl`, `BudgetTracker`, `Budget::try_from_configs`, `BudgetImpl::charge`, `get_tracker`, `track_time`), plus `src/rust/src/soroban_proto_any.rs` if a new bridge-facing lightweight VM-instantiation accumulator or constructor is needed.
- **Change description**: Add a production/enforcing budget tracking mode that skips full per-cost reporting accumulation on normal charges but continues to update aggregate CPU/memory dimensions and enforce limits at the same points. Preserve full tracking for tests, benches, calibration/cost-runner use, diagnostics/debug paths, and any mode that displays or inspects the tracker. Preserve `VmInstantiation` CPU and time accounting for `cpu_insns_excluding_vm_instantiation` and `time_nsecs_excluding_vm_instantiation`.
- **Correctness check**: Existing Soroban invoke-host-function, budget-metering, VM-instantiation, and bridge-output tests should continue to pass with p26 exact behavior where required. Add or update focused tests only for the new gated mode: aggregate consumed CPU/memory remain unchanged, over-budget errors occur at the same charge, `VmInstantiation` exclusions match the fully tracked mode, and wrong input-shape charges still return the same internal error if that behavior is retained.
- **Benchmark focus**: Run the soroswap apply-load matrix against the current `ai-summary/CURRENT_STATE.md` baseline. The metric is median apply time across multiple non-Tracy runs; expected improvement is Medium only if the result clears 3% reproducibly, with a diagnostic Tracy run confirming reduced physical time around budget charge bookkeeping.
