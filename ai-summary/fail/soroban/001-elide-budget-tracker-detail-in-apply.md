# H001: Elide per-cost BudgetTracker detail on non-diagnostic apply invocations

**Date**: 2026-05-04
**Subsystem**: soroban
**Severity**: Medium
**Impact**: apply-time reduction in Soroban host budget charging for soroswap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Soroban apply must enforce the same CPU and memory budget limits and return the same aggregate `cpu_insns` and `mem_bytes` to C++ for every invocation. When diagnostics and Soroban metrics are disabled for the apply-load benchmark, it should not need to update the full per-cost `BudgetTracker` (`iterations`, `inputs`, `cpu`, `mem`, and `meter_count`) on every `Budget::charge`; only the aggregate budget dimensions and the narrow fields still read by the bridge, such as VM-instantiation exclusion counters, need to be maintained.

## Mechanism

`BudgetImpl::charge` currently updates per-cost reporting counters before and after the CPU and memory dimension charges on every non-shadow charge. This reporting work is not consensus state: aggregate budget totals come from `BudgetDimension::total_count`, and the C++ apply path only consumes aggregate `cpu_insns`/`mem_bytes` plus VM-instantiation exclusion metrics. A C++-controlled "aggregate-only budget tracking" mode for metrics-disabled apply could preserve exact `BudgetDimension::charge` arithmetic and limit checks while eliding most `BudgetTracker` per-cost updates, reducing the 20.3M-call `charge` hotspot without changing metered totals, failures, ledger entries, or event order.

## Trigger

Run the current next-protocol soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with the benchmark's usual metrics-disabled configuration. Each successful swap performs hundreds to thousands of host budget charges during SAC calls, storage access, VM dispatch, object conversion, map operations, and Wasm instantiation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates `BudgetTracker` fields around every CPU and memory dimension charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1391-1418` — `get_tracker`, `get_time`, `get_cpu_insns_consumed`, and `get_mem_bytes_consumed` show which reporting surfaces are read after invocation.
- `src/rust/src/soroban_proto_any.rs:458-466` — the C++ bridge returns aggregate CPU/memory and subtracts VM-instantiation tracker/time for metrics.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-590` — C++ receives the aggregate and exclusion metrics for each Soroban host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` performs the consensus-relevant total-count update that must remain exact.

## Evidence

The current accepted soroswap trace
(`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`) has 71 `applyLedger` windows totaling 5,230,315,999 ns. Timestamp overlap against those windows shows:

| Zone | Apply-window self-time | Calls | Source |
|---|---:|---:|---|
| `charge` | 1,758,199,707 ns | 20,300,668 | `soroban-env-host/src/budget/dimension.rs:176` |
| `SAC transfer` | 2,153,411,257 ns total | 13,527 | `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` |
| `call` | 9,353,235,883 ns total | 40,605 | `soroban-env-host/src/vm/dispatch.rs:304` |

The `charge` Tracy span is emitted inside the CPU dimension, but every `BudgetImpl::charge` also performs uninstrumented per-cost tracker updates in Rust before and after both dimensions. This hypothesis does not batch or defer charges: it removes reporting-detail writes that are not needed by the metrics-disabled apply path while keeping the exact per-call CPU/memory totals and immediate budget-limit checks.

## Anti-Evidence

Prior budget accumulator ideas failed because they either lacked a measured eligible subset or changed rounding/flush semantics. This proposal must not aggregate raw inputs, defer limit checks, or skip `BudgetDimension` updates; it only gates reporting-detail writes when C++ explicitly does not need per-cost reporting. If the tracker-update slice is a small fraction of the `charge` hotspot after Tracy overhead is removed, the benchmark delta may fall below Medium, so a PoC should first add a build-local counter or A/B flag that elides only `BudgetTracker` detail and compares non-Tracy apply-load runs.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in retained Soroban fail/success records
**Failed At**: reviewer

### Trace Summary

The hot path is real: `LedgerManagerImpl::applySorobanStages` dispatches Soroban clusters to worker threads, each successful invoke-host transaction reaches `InvokeHostFunctionOpFrame::invokeHostFunction`, crosses the Rust bridge, constructs a fresh enforcing `Host`, and executes contract code with a shared `Budget`. Every `Budget::charge` routes through `BudgetImpl::charge`, which updates per-cost `BudgetTracker` counters before and after the CPU/memory `BudgetDimension::charge` calls; after invocation, the bridge reads aggregate totals and only the `VmInstantiation` tracker/time for exclusion metrics. The apply-load matrix does set `DISABLE_SOROBAN_METRICS_FOR_TESTING=true`, so C++ medida emission is disabled, but the bridge output shape still computes the exclusion fields.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:34-40,417-424` — soroswap scenarios default `disable_metrics=true` and render `DISABLE_SOROBAN_METRICS_FOR_TESTING = true`.
- `src/ledger/LedgerManagerImpl.cpp:2583-2620,2630-2675,2729-2815` — parallel Soroban apply runs each cluster on worker threads and waits for completion inside the measured `closeLedger` apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:130-180,269-277,308-333,557-590,982-1030,1358-1378` — metrics-disabled apply skips C++ medida timers and histogram updates, but still invokes the Rust host and stores aggregate/exclusion fields in `HostFunctionMetrics`.
- `src/rust/src/soroban_proto_any.rs:391-466,488-555` — the bridge constructs a `Budget`, invokes the protocol-specific host, then reads `get_cpu_insns_consumed`, `get_mem_bytes_consumed`, `get_tracker(VmInstantiation).cpu`, and `get_time(VmInstantiation)` for the returned output.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:523-552` — each host invocation installs enforcing storage, source account, ledger info, auth, PRNG, diagnostics if enabled, and the module cache before calling `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:27-45,166-195,198-287,1498-1527` — `BudgetTracker` is reporting-only, but `BudgetImpl::charge` updates `meter_count`, `iterations`, `inputs`, per-cost `cpu`, and per-cost `mem`; aggregate totals come from the dimensions.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:143-188` — `BudgetDimension::charge` evaluates the cost model, updates `total_count`, and performs the consensus-relevant limit check that the proposal would keep.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:50-73` and `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:29-34` — VM-instantiation time and CPU tracker fields are the narrow per-cost data still consumed by the bridge after invocation.

### Why It Failed

The inefficiency exists, but the claimed Medium impact is not supported after isolating the removable work. The cited 1.76 s `charge` Tracy zone is inside `BudgetDimension::charge` and includes the CPU dimension model evaluation and Tracy span overhead; those operations are explicitly not removable, and the memory dimension charge plus immediate limit checks must also remain. The proposal can only skip a few reporting writes and saturating additions around each charge, while leaving the RefCell borrow, cost-model lookups/evaluations, aggregate counter updates, limit checks, VM-instantiation tracker/time accounting, and bridge output intact.

This residual reporting slice is smaller than the already-confirmed `001-protocol-gated-host-metering-coalescing` optimization, which removed whole physical `VisitObject` charges and leaf-granular `ValSer` charging and still measured only a 2.10% soroswap median improvement. Even granting high call volume, a per-charge tracker-detail skip would need to save roughly 60 ns per one of the 20.3M charge calls to clear 3% of the cited 5.23 s trace after 8-way worker normalization, and the removable code is mostly simple in-register arithmetic rather than the measured dimension-charge work. That puts the realistic projection in Low territory, below the optimize-soroswap objective threshold.

### Lesson Learned

For budget-metering hypotheses, do not treat the `charge` Tracy span as removable unless the proposed change actually removes `BudgetDimension::charge`; tracker/reporting updates are adjacent to that span, not the span itself. After the accepted coalesced-metering change, further per-charge reporting-detail skips need direct non-Tracy A/B evidence exceeding the 3% Medium floor before promotion.
