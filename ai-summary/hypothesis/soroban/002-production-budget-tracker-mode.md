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
