# H001: Next-Protocol Exact Budget Charge Fast Path

**Date**: 2026-05-03
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing per-charge overhead in the Soroban host budget hot path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol 27+ apply-load runs, Soroban host execution should produce the same ledger effects, success/failure outcomes, resource totals, refunds, and diagnostic behavior as the current optimized baseline. Each budget charge should still add the exact same rounded CPU and memory amounts, and budget-exceeded errors should remain deterministic. Released p26 behavior should remain unchanged unless the optimization is explicitly protocol-gated.

## Mechanism

The current `BudgetImpl::charge` path performs full tracker lookup/update, cost-model lookup/evaluation, CPU-limit check, memory cost-model lookup/evaluation, memory-limit check, and tracker CPU/memory updates for every charge. The current soroswap Tracy trace reports `charge` self-time of 1,758,199,707 ns across 20,300,668 calls, all inside `applyLedger`. A next-protocol fast path can precompute compact per-cost-type CPU/memory model arrays and update hot totals directly, while batching or lazily materializing reporting-only tracker fields, reducing repeated indexing, option matching, `ScaledU64` checks, and saturating tracker arithmetic without changing deterministic charged totals.

## Trigger

Run the current baseline from `ai-summary/CURRENT_STATE.md` with the soroswap apply-load workload (`soroswap, TX=2000, T=8`) and next-protocol build flags. The issue is triggered by normal successful Soroban host execution under `closeLedger`, especially SAC-heavy swap paths that perform millions of small host budget charges per benchmark run.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates reporting trackers and performs CPU and memory dimension charges on every call.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` fetches the cost model, evaluates it, enters the Tracy `charge` span for CPU charges, and updates totals.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-132` — `MeteredCostComponent::evaluate` recomputes constant/linear cost arithmetic for each charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1307-1324` — public `Budget::bulk_charge` and `Budget::charge` are the call surfaces that could route to a protocol-gated fast path.

## Evidence

The current diagnostic trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports `charge,soroban-env-host/src/budget/dimension.rs,176,1758199707,...,20300668,86,...`, making it the largest remaining in-scope Soroban host self-time zone after the accepted host-metering coalescing work. An unwrap overlap check against `applyLedger` windows found all 20,300,668 `charge` events inside apply. Unlike prior storage-map or addReads micro-optimizations, this target is a cross-cutting hot path with enough aggregate worker CPU to plausibly clear Medium if the fast path removes a meaningful fraction of the physical accounting overhead.

## Anti-Evidence

Budget accounting is protocol-visible through fees, resource totals, budget-exceeded behavior, and observation tests. The PoC must either preserve exact p26 charge order and totals or be gated to the next protocol like the accepted host-metering coalescing change. Prior budget-accumulator ideas failed when they projected from all `charge` time without isolating the eligible subset, so this hypothesis should start with a minimal exact fast path that preserves per-charge limit checks and only batches reporting-only tracker materialization; if the measurable saving is below 3%, it should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `002-specialize-budget-charge-hot-path.md`
**Failed At**: reviewer

### Trace Summary

The hot path is real: Soroban parallel apply reaches `InvokeHostFunctionOpFrame::doParallelApply`, crosses the C++/Rust bridge, constructs a fresh p26 `Budget`, invokes the host, and calls `BudgetImpl::charge` from many host and VM-boundary metering sites. `BudgetImpl::charge` still does the tracker update, CPU dimension charge, limit check, memory dimension charge, second limit check, and tracker CPU/memory accounting described in the hypothesis. However, the retained Soroban fail summary already records a substantially equivalent investigation, `002-specialize-budget-charge-hot-path.md`, titled "Specialize the Soroban Budget Charge Hot Path"; related retained rows also cover exact/linear budget-charge accumulator variants and zero-memory fast-path reasoning. This hypothesis is therefore not novel in the review pipeline.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:45` — prior retained investigation `002-specialize-budget-charge-hot-path.md` covers the same broad budget-charge-hot-path specialization target.
- `ai-summary/fail/soroban/summary.md:58-60,97` — related exact and linear budget-charge accumulator reviews already captured the need to isolate eligible charge subsets, preserve rounding, and map flush boundaries before promoting accumulator-like variants.
- `src/ledger/LedgerManagerImpl.cpp:2784-2884,2966-3029` — `applyTransactions` dispatches Soroban phases into `applyParallelPhase`, builds apply stages, and calls `applySorobanStages`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520,2530-2574` — worker threads call `TransactionFrame::parallelApply` for each Soroban transaction and wait for all cluster futures.
- `src/transactions/TransactionFrame.cpp:2385-2430` — `TransactionFrame::parallelApply` requires a single Soroban operation and delegates to `OperationFrame::parallelApply`.
- `src/transactions/OperationFrame.cpp:175-188` — `OperationFrame::parallelApply` delegates to the Soroban operation's `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1000,1358-1377` — invoke-host parallel apply runs `InvokeHostFunctionParallelApplyHelper::apply`, including `addFootprint`, `invokeHostFunction`, and `recordStorageChanges`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-638` — `invokeHostFunction` calls `rust_bridge::invoke_host_function` and records CPU/memory totals returned by Rust.
- `src/rust/src/soroban_invoke.rs:7-60` — bridge entry dispatches to the protocol-specific Soroban host module.
- `src/rust/src/soroban_proto_any.rs:391-459` — p26 wrapper creates the `Budget` from ledger cost params and invokes `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-491` — e2e host invocation decodes metered inputs, builds storage/host state, executes `Host::invoke_function`, and metered-encodes outputs.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:634-636` and `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1301-1324` — public host/budget charge surfaces route to `BudgetImpl::charge`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` performs the per-charge tracker updates, CPU and memory dimension charges, and both budget-limit checks.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` and `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-132` — each dimension fetches the cost model, evaluates constant/linear cost arithmetic, updates totals, and the CPU branch emits the `charge` Tracy span.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` and `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:22-40` — VM/host boundary fuel transfers and dispatch metering also route through `bulk_charge`/`charge`.

### Why It Failed

This is a duplicate investigation. The exact source-level inefficiency exists, but the pipeline has already investigated the same budget-charge-hot-path specialization target and retained it in `ai-summary/fail/soroban/summary.md` as `002-specialize-budget-charge-hot-path.md`. The current write-up also overlaps the retained accumulator lessons: any exact fast path that batches or lazily materializes tracker state must still preserve per-call rounded CPU/memory totals, budget-exceeded behavior, public budget observers, fuel-transfer boundaries, shadow-mode behavior, and metered-XDR semantics; these constraints were already recorded for budget-charge accumulator variants.

### Lesson Learned

Do not re-promote broad Soroban budget-charge-hot-path specializations solely from aggregate `charge` Tracy self-time. Future budget-metering hypotheses need a genuinely new mechanism or measurement, not a restatement of the already-retained hot-path specialization/accumulator family, and must cite the exact eligible charge subset after prior host-metering coalescing work.
