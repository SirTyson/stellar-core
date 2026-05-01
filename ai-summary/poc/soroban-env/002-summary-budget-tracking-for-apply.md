# H002: Track only apply-visible budget summaries on the production invoke path

**Date**: 2026-04-29
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing protocol-invisible per-cost tracker maintenance from the hot budget-charge loop
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Normal stellar-core Soroban apply should return the same `cpu_insns`, `mem_bytes`, `time_nsecs`, `cpu_insns_excluding_vm_instantiation`, and `time_nsecs_excluding_vm_instantiation` as today. It should not pay per-charge overhead to maintain full diagnostic per-cost `iterations`, `inputs`, `cpu`, `mem`, and `meter_count` tables for every cost type unless a caller is actually going to inspect those diagnostic trackers.

## Mechanism

`BudgetImpl::charge` updates `BudgetTracker` on every non-shadow charge before and after the CPU/memory dimension updates: it bumps the global meter count, per-cost iteration count, optional input sum, per-cost CPU sum, and per-cost memory sum. In the stellar-core Rust bridge's normal invoke output, the only per-cost tracker consumed is `get_tracker(ContractCostType::VmInstantiation)?.cpu`, used to compute `cpu_insns_excluding_vm_instantiation`; all other externally returned values come from aggregate budget totals or explicit wall-clock timing. A production "summary tracking" mode could maintain aggregate CPU/memory dimensions exactly and a dedicated VM-instantiation CPU accumulator, while compiling or enabling the full per-cost tracker only for tests, cost calibration, diagnostics, or callers that explicitly request it.

## Trigger

Run the current soroswap diagnostic trace from `ai-summary/CURRENT_STATE.md` and export self-time with `csvexport-release -e`. The hot `charge` zone at `soroban-env-host/src/budget/dimension.rs:176` has 2,043.955 ms self-time over 18,721,841 calls in a trace whose measured `applyLedger` envelope is 5,774.332 ms total. Each of those calls enters `BudgetImpl::charge`, so any tracker maintenance inside `budget.rs:241-280` is paid millions of times during Soroban apply.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:26-43` — `CostTracker` / `BudgetTracker` store full per-cost diagnostic accounting.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:241-280` — `BudgetImpl::charge` updates tracker fields on every non-shadow charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1391-1403` — `Budget::get_tracker` / `get_time` expose the diagnostic tracker values.
- `src/rust/src/bridge.rs:34-48` — `InvokeHostFunctionOutput` returns aggregate budget totals and the two "excluding VM instantiation" summaries, not the full per-cost tracker table.
- `src/rust/src/soroban_proto_any.rs:458-466` — the normal bridge output reads aggregate totals and only `get_tracker(VmInstantiation)?.cpu` from the per-cost tracker.

## Evidence

- Tracy scope check: sampled exact `charge` events occur inside `applyLedger` windows, and the target code is reached from Soroban host execution under `Host::invoke_function` in the measured close-ledger apply path.
- The tracker updates are protocol-invisible for transaction validity and fees: enforcement depends on `BudgetDimension.total_count` and limits, while bridge output returns aggregate `cpu_insns`/`mem_bytes`; the per-cost table is diagnostic/calibration state except for the VM-instantiation subtraction.
- The source shows several saturating updates and an optional-input branch per charge before dimension charging, then two more per-cost `cpu`/`mem` saturating updates after dimension charging. At 18.7 million charges in the diagnostic run, even tens of nanoseconds per charge becomes a multi-percent apply-time candidate.
- A summary mode can preserve the one production per-cost-derived result by adding a dedicated `vm_instantiation_cpu` accumulator updated only when `ty == ContractCostType::VmInstantiation`, avoiding the full table update for the other hot cost types.
- This is distinct from prior failed budget hypotheses: it does not cache budget construction, reduce metered charge counts, or alter cost-model arithmetic. It removes only diagnostic bookkeeping not needed by the production bridge output.

## Anti-Evidence

- Existing tests and cost-runner code inspect `get_tracker` for many cost types, so a viable implementation must keep full tracking enabled in those configurations or make tracking mode explicit. A blanket removal of tracker maintenance would break tests and developer diagnostics.
- `Budget` is a public Rust host type, not just an internal stellar-core bridge detail. The PoC must audit non-bridge users and avoid changing behavior for RPC/preflight/test paths that depend on per-cost trackers.
- The savings overlap with other `BudgetImpl::charge` fast paths such as zero-memory-dimension skipping. Benchmarking must evaluate this hypothesis independently and then together with other charge-loop changes to avoid double-counting the same self-time.
- The whole `charge` zone includes `BudgetDimension::charge` work and Tracy-only instrumentation. The tracker-maintenance subset must be isolated with focused instrumentation or before/after non-Tracy apply-load runs before claiming a confirmed Medium improvement.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The close-ledger Soroban apply path reaches `InvokeHostFunctionOpFrame::invokeHostFunction`, crosses the Rust bridge, constructs a p26 `Budget`, and then executes `e2e_invoke::invoke_host_function` / `Host::invoke_function`. Host operations and VM dispatch charge budget through `Host::charge_budget`, `Budget::charge`, and `BudgetImpl::charge`; the full `BudgetTracker` update block is executed on every non-shadow charge before and after the CPU/memory dimension totals are updated. Core's bridge output consumes aggregate CPU/memory totals plus `VmInstantiation` CPU/time summaries only, while the full per-cost tracker is otherwise used by tests, benches, cost runners, and formatting/debug paths.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-590` — Soroban operation application invokes `rust_bridge::invoke_host_function` and stores only aggregate instruction/memory/time metrics plus the two VM-instantiation-excluding fields.
- `src/rust/src/bridge.rs:34-48` — `InvokeHostFunctionOutput` has no per-cost tracker table; the externally visible fields are aggregate `cpu_insns`, `mem_bytes`, `time_nsecs`, and VM-instantiation-excluding summaries.
- `src/rust/src/soroban_proto_any.rs:391-420` — the Rust bridge constructs a normal `Budget` from network cost params for each host invocation.
- `src/rust/src/soroban_proto_any.rs:458-466,485-550` — bridge result construction reads aggregate totals and subtracts only `get_tracker(VmInstantiation)?.cpu`; time exclusion uses `get_time(VmInstantiation)`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-485` — enforcing-mode Soroban invocation uses the provided budget for XDR decoding, storage-map construction, host setup, and `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:634-636` — `Host::charge_budget` forwards directly to `Budget::charge`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:26-43,165-195` — `CostTracker` / `BudgetTracker` contain diagnostic per-cost iteration/input/cpu/mem tables, meter count, and time tracker.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` unconditionally locates the per-cost tracker and, for non-shadow charges, updates `meter_count`, `iterations`, `inputs`, `cpu`, and `mem` in addition to aggregate dimensions.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — aggregate CPU/memory totals and limit behavior are maintained by `BudgetDimension::charge`, independently of the diagnostic tracker table.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:50-73,154-187` — VM-instantiation time is recorded through `track_time(VmInstantiation)`, and VM-instantiation CPU is charged during instantiation; these are the only per-cost summaries used by Core's bridge output.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294`, `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:468-476`, `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:53-72`, and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:98-145` — representative hot charge sites for dispatch, object visits, copies, and comparisons all funnel into the same budget-charge loop.
- `src/rust/soroban/p26/soroban-env-host/src/cost_runner/runner.rs:68-83`, `src/rust/soroban/p26/soroban-env-host/benches/common/measure.rs:372-381`, and `src/rust/soroban/p26/soroban-env-host/src/test/budget_metering.rs:43-319` — full trackers are required for cost calibration, benches, and exact metering tests, so the optimization must be opt-in for Core's production apply path rather than a blanket removal.
- `ai-summary/fail/soroban-env/summary.md:9-18` and `ai-summary/fail/soroban-env/001-skip-zero-memory-budget-dimension.md:54-84` — prior budget failures do not duplicate this target; the closest failure targets zero-memory dimension evaluation and Tracy-zone interpretation, not per-cost tracker bookkeeping.
- `ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md:44-53,88-97` — the confirmed storage-map fast path is unrelated to budget tracking and provides no duplicate accepted finding.

### Findings

The optimization claim is source-valid. `BudgetImpl::charge` performs diagnostic tracker maintenance for every non-shadow budget charge, while consensus/resource enforcement depends on the aggregate `BudgetDimension` totals and limit checks. The per-cost tracker table is explicitly described as calibration/reporting state and is not used for budget limiting or consensus; Core's FFI output does not expose that table.

The proposed fix is also structurally correct if implemented as an explicit tracking mode used only by the Core invoke path. The default public `Budget::try_from_configs`, tests, benches, cost runners, and any path that formats or inspects `Budget` should retain full tracking. A new summary-tracking constructor or mode can preserve aggregate CPU/memory totals, limit checks, input-shape validation, shadow-mode behavior, `time_nsecs_excluding_vm_instantiation`, and the current exact `cpu_insns_excluding_vm_instantiation` semantics by maintaining a dedicated `VmInstantiation` CPU accumulator. It should not change charge counts, cost-model arithmetic, or any protocol-visible `cpu_insns` / `mem_bytes` totals.

The hot-path claim is plausible at Medium severity. The cited Tracy `charge` self-time should not be treated as the removable subset because it includes Tracy-only CPU-dimension instrumentation, but the event count still identifies roughly 18.7 million budget charges in the apply window. The tracker block adds several saturating arithmetic operations, an input-shape branch, and multiple per-cost table writes to every one of those calls. Removing that production bookkeeping for normal Core apply has a credible path to a 3-10% soroswap apply-time improvement, while preserving full trackers where they are observed.

Key correctness constraints for the PoC:

- Do not make `get_tracker` silently return incomplete data for default/test/bench/cost-runner budgets.
- Preserve current bridge semantics exactly: subtract only `ContractCostType::VmInstantiation` CPU, not `VmCachedInstantiation`, unless a separate intentional behavior change is justified.
- Preserve the current input-shape error behavior from `BudgetImpl::charge`; `BudgetDimension::charge` alone does not reject `Some` input for constant cost types or `None` for linear cost types.
- Preserve shadow-mode behavior. Current tracker updates are skipped in shadow mode, while CPU/memory shadow totals are still charged.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/budget.rs` and `src/rust/src/soroban_proto_any.rs`.
- **Change description**: Add an explicit budget tracking mode, keeping full tracking as the default. Use a summary mode only for `invoke_host_function_or_maybe_panic` in the Core bridge. In summary mode, skip full `BudgetTracker` per-cost updates in `BudgetImpl::charge`, but still update aggregate `BudgetDimension` totals and a dedicated `vm_instantiation_cpu` summary when `ty == ContractCostType::VmInstantiation`. Keep `time_tracker` or an equivalent `VmInstantiation` time accumulator because Core uses `time_nsecs_excluding_vm_instantiation`.
- **Correctness check**: Existing Rust host tests that inspect `get_tracker` should continue to use full tracking and remain unchanged. Exact budget/resource tests should verify unchanged aggregate `cpu_insns` and `mem_bytes`. Add focused coverage for the new summary mode if it exposes a constructor: charging linear and constant cost types should still reject mismatched `input`, and `VmInstantiation` CPU/time summaries should match full-tracking mode.
- **Benchmark focus**: Compare non-Tracy `scripts/run_apply_load_matrix.py` runs for soroswap and max-sac before/after. The primary metric is soroswap median apply time; the hypothesis needs a reproducible 3-10% median improvement to satisfy this objective. A diagnostic trace can be used only to confirm reduced budget-charge self-time after the non-Tracy signal is established.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-01
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:198-254,270-333,377-390,1393-1427,1559-1593` — added an explicit `BudgetTrackingMode`, kept `Full` tracking as the default, added summary-tracking construction for p26 production invocation budgets, preserved input-shape validation, and maintained a dedicated `vm_instantiation_cpu` accumulator for Core's `cpu_insns_excluding_vm_instantiation` summary.
- `src/rust/src/soroban_proto_all.rs:95-114,271-300,446-475,621-650,835-864,1044-1073` — added per-protocol budget-construction and VM-instantiation CPU summary adapters so only p26 uses summary tracking while p21-p25 retain existing full-tracking semantics.
- `src/rust/src/soroban_proto_any.rs:409-466` — changed the shared invoke path to construct budgets through the protocol adapter and compute `cpu_insns_excluding_vm_instantiation` through the protocol adapter instead of directly reading the full per-cost tracker.

### Demonstration

The p26 production Core invoke path now skips per-cost diagnostic tracker updates for every non-shadow budget charge, while still charging aggregate CPU/memory dimensions, checking limits, validating cost-type input shape, and preserving the exact VM-instantiation CPU subtraction used by the bridge output. Default/test/bench/cost-runner budgets still use full tracking, so diagnostic `get_tracker` consumers retain their prior behavior outside the optimized Core apply path.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built with `make -j $(nproc)`, and ran `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`. The full run completed successfully; the p26 Soroban host unit tests reported `750 passed; 0 failed; 2 ignored`, the additional p26 integration/doc tests passed, and the top-level suite ended with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
