# H002: Specialize the Soroban Budget Charge Hot Path

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in ubiquitous host metering
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban host operation must charge the exact same CPU and memory budget totals, tracker fields, shadow-mode totals, and limit errors as today, but the act of charging should be a low-overhead inlined arithmetic update. A valid `ContractCostType` enum should not pay repeated fallible array lookups, error-construction branches, and duplicated cost-model dispatch on every metering call in the production enforcing path.

## Mechanism

`Budget::charge` borrows the `BudgetImpl` and calls `BudgetImpl::charge`; `BudgetImpl::charge` then performs a fallible `get_mut` into the tracker array, updates tracker fields, separately calls `BudgetDimension::charge` for CPU and memory, and each dimension performs another fallible cost-model lookup plus model evaluation and limit accounting. The enum value already indexes fixed-size arrays initialized from `ContractCostType::variants()`, so the hot path can be split into an infallible/specialized charge routine using direct indexing, prevalidated model shape, and combined CPU/memory accounting while keeping the public fallible API for tests/config mutation. This removes repeated control-flow and bounds-check overhead from millions of charges without changing deterministic budget totals.

## Trigger

Run the current soroswap apply-load benchmark. SAC-heavy swaps and host invocation repeatedly call `Host::charge_budget`, `MeteredOrdMap` charge helpers, object visits, XDR conversion, and storage access. A PoC should introduce a production fast path for `BudgetImpl::charge(ty, 1, input)` that preserves all tracker and limit results exactly, then compare repeated soroswap medians and Tracy `charge` self-time.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1320-1325` — public `Budget::charge` takes a mutable `RefCell` borrow for every single-unit charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` performs tracker lookup/update, CPU charge, CPU limit check, memory charge, and memory limit check for every metered operation.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-187` — each dimension charge performs a cost-model lookup and model evaluation before adding to totals.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:634-635` — `Host::charge_budget` is the common host entry point used by object visits and many built-in helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:468-476`, `storage.rs:258-388`, and `host/metered_map.rs:173-194` — high-frequency callers that multiply the per-charge overhead in soroswap.

## Evidence

The current soroswap diagnostic trace shows `charge,soroban-env-host/src/budget/dimension.rs,176` entirely inside `applyLedger`: **2,043.955 ms self-time** across **18,721,841 calls**. The same apply-contained trace shows callers that are dominated by metering fan-out: `visit host object` has **2,372.465 ms** across **2,689,616 calls**, `map lookup` has **1,321.581 ms** across **754,812 calls**, `storage get` has **847.123 ms** across **176,910 calls**, and `write xdr` has **1,071.529 ms** across **132,907 calls**. The path is a descendant of `applyLedger` via parallel Soroban worker execution, and the zone's call count is high enough that even shaving tens of nanoseconds per charge can be measurable across a ledger.

The optimization is not a metering reduction. The PoC should assert identical `get_cpu_insns_consumed`, `get_mem_bytes_consumed`, `CostTracker` values for representative charges, and identical budget-exceeded behavior at boundaries. The intended saving is only wall-clock overhead from generic fallible dispatch and repeated indexing in a code path where the cost-type enum and array layout are already validated.

## Anti-Evidence

The Tracy `charge` span itself adds instrumentation overhead in diagnostic builds, so the PoC must prove a top-line non-Tracy apply-load improvement and not rely solely on the Tracy self-time drop. Some bounds checks may already compile away under optimization, and replacing safe indexing with unchecked indexing would be unacceptable unless the invariant is tightly encapsulated and tested. Because charges execute on parallel worker threads, aggregate worker self-time does not translate one-for-one into apply-thread wall-clock; the win must survive repeated benchmark runs to remain Medium.
