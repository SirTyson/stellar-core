# H002: Protocol-Gated Budget Charge Accumulator for Hot Host Metering

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / Soroban host metering
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by batching millions of small deterministic budget charge updates inside each host invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol Soroban ledgers, host metering should still produce deterministic final CPU and memory totals and deterministic budget-exceeded outcomes, but it should not need to take a `BudgetImpl` mutable borrow, update per-cost trackers, evaluate both CPU and memory dimensions, and check both limits for every tiny map/vector/conversion charge. Small monotonic charges that are known to occur inside one host invocation should be accumulated in a local charge buffer and flushed at deterministic safety points, producing the same ledger effects for successful transactions and a protocol-defined failure point for over-budget transactions.

## Mechanism

After the accepted protocol-gated host metering coalescing removed `VisitObject` and per-chunk `ValSer` micro-metering, the current trace still shows 20,247,202 in-window `charge` events in the seven long `applyLedger` windows, totaling 1,751.8 ms of Tracy self-time. The source path for each charge (`Budget::charge` -> `BudgetImpl::charge` -> two `BudgetDimension::charge` calls) updates tracker fields, evaluates cost models, and checks CPU/memory limits immediately, even for high-frequency internal charges from `MeteredOrdMap`, `MeteredVector`, `ScVal` conversions, and storage bookkeeping.

A next-protocol `BudgetImpl` accumulator can keep per-cost `(iterations, input_sum, cpu_sum, mem_sum)` deltas in plain fields for a selected safe set of host-internal cost types, then flush before returning from a host import to Wasm, before reporting resource totals, before any shadow-mode section, and before operations that can expose budget state. This avoids the per-charge tracker churn and repeated limit checks in the hottest successful soroswap path while preserving deterministic final resource totals under a new protocol metering contract.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md`:

`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`

Inside the seven long `applyLedger` windows, `charge` accounts for 1,751.8 ms across 20,247,202 calls. Normalized by 7 long ledgers and 8 clusters, that is about 31.3 ms/ledger of critical-worker charge-path envelope. Related charge-heavy zones in the same windows include `ScVal to Val` at 994.8 ms, `Val to ScVal` at 430.5 ms, `new map` at 448.7 ms, `map lookup indexed` at 542.8 ms, and `storage get` at 640.7 ms, all under `InvokeHostFunctionOpFrame doParallelApply`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates trackers, charges CPU/memory dimensions, and checks limits on every call.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1323-1325` — public `Budget::charge` borrows the budget mutably for every single charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — each dimension evaluates the cost model and updates total count per charge.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160,168-185` — hot map construction and lookup call into the budget path at very high frequency during soroswap.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:103-118` — vector construction contributes another high-frequency small-charge source.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-523` and `src/rust/src/soroban_proto_any.rs:391-506` — host invocations have a clean per-transaction budget object and a single point where final CPU/memory totals are read and returned to C++.

## Evidence

- Tracy scope check: timestamp-filtered `charge`, map/vector/conversion, and storage events above are contained inside the long `applyLedger` windows and under Soroban parallel apply, not in transaction-set construction.
- The existing accepted protocol-gated host-metering coalescing proves this branch already tolerates next-protocol metering changes while preserving p26 exact accounting; the new accumulator would use the same protocol gate rather than changing released p26 behavior.
- `BudgetImpl::charge` already receives bulk `iterations` and `input` parameters, and `MeteredOrdMap::from_exact_iter` comments explicitly accept temporary over-budget allocation before a batched charge for clone work. The codebase therefore already has precedent for batching metering when the protocol semantics allow it.
- The opportunity is broad enough to avoid the sub-threshold trap of individual charge-site hypotheses: it targets the common charge update/limit-check machinery shared by map lookup, map/vector construction, ScVal conversion, storage setup, and post-invocation extraction.

## Anti-Evidence

- Prior `001-specialize-budget-charge-fast-path.md` correctly rejected treating the Tracy `charge` span alone as production cost. A viable PoC must measure non-Tracy apply time and should add narrow counters for accumulator hit count and flush count; it must not claim the full Tracy span as removable.
- Deferring budget limit checks can change the exact instruction at which an over-budget transaction fails. This must be an explicit next-protocol metering rule, and the accumulator must flush before any boundary where a contract can observe or catch a budget failure differently.
- Shadow-mode budget sections, diagnostics, resource reporting, Wasm fuel synchronization, and test utilities that inspect per-cost trackers need immediate or pre-flush semantics. If those flush boundaries are too frequent, the improvement may collapse below Medium.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; prior budget-charge, `ValSer`, and `VisitObject` records cover narrower fast paths or failed PoCs, not a broad next-protocol accumulator for the common `BudgetImpl::charge` machinery

### Trace Summary

The close-ledger path reaches the target through parallel Soroban apply: `LedgerManagerImpl::applyParallelPhase` builds Soroban stages, cluster workers call `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply` crosses the C++/Rust bridge, and `soroban_proto_any::invoke_host_function_or_maybe_panic` creates a fresh `Budget` for each host invocation. Inside the host, map/vector construction, storage lookup, object conversion, XDR metering, and VM fuel settlement call `Budget::charge` or `Budget::bulk_charge`, which immediately mutates tracker state, evaluates CPU and memory models, and checks both limits. Final CPU/memory totals are read once after invocation, which gives a natural deterministic flush point, but shadow mode, tracker accessors, remaining fuel calculations, and any budget-observable boundary must force a flush.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2574` — cluster workers run `parallelApply` on each transaction and the apply thread waits on all worker futures, so per-invocation budget work is on the critical apply path after cluster normalization.
- `src/ledger/LedgerManagerImpl.cpp:2966-3020` and `2628-2636` — parallel phases are built and executed as Soroban apply stages within `closeLedger`.
- `src/transactions/TransactionFrame.cpp:2385-2430` — Soroban transactions have one operation and dispatch to `OperationFrame::parallelApply`.
- `src/transactions/OperationFrame.cpp:175-188` and `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — Soroban operation parallel apply reaches `InvokeHostFunctionOpFrame::doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-585` — each invocation serializes inputs and calls `rust_bridge::invoke_host_function`, then records returned CPU and memory totals.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:391-506` — protocol dispatch creates a per-invocation `Budget`, calls the p26 host, then reads `get_cpu_insns_consumed`, `get_mem_bytes_consumed`, and per-cost tracker data for output metrics.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:451-523` — the host is built with the per-invocation budget, runs `Host::invoke_function`, finishes storage/events, and performs post-invocation metered XDR/ledger-change extraction.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates `meter_count`, per-cost iterations/input totals, evaluates CPU and memory cost models, updates per-cost CPU/mem trackers, and checks CPU and memory limits for every charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1307-1325` — both `Budget::bulk_charge` and `Budget::charge` enter the same mutable-borrowed `BudgetImpl::charge` path.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:143-188` and `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — each dimension evaluates a linear model, updates total count, and performs a separate limit check; linearity makes accumulated `(iterations, input_sum)` flushing algebraically equivalent for eligible cost types.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83,144-160,168-185` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:38-60,103-118` — hot map/vector scans, binary searches, and clone-construction charges funnel through `Budget::charge` with small deterministic `MemCpy` inputs.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-68`, `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-476`, and `src/rust/soroban/p26/soroban-env-host/src/vm/fuel_refillable.rs:31-39` — XDR serialization, object visitation, and VM fuel settlement are important charge boundaries; some may be excluded initially or must flush before exposing an error/resource boundary.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1337-1430` — shadow mode and resource/tracker getters require pre-flush semantics; `with_shadow_mode` also swallows shadow errors, so accumulated non-shadow charges must not be carried into it.
- `ai-summary/fail/transaction-ledger/summary.md:39,47,52,151` — closest prior records rejected narrow Tracy-span specialization and individual `ValSer`/`VisitObject` attempts, while the meta-pattern explicitly leaves room for a combined protocol-gated metering change.

### Findings

The inefficiency exists in production code, though the full Tracy `charge` self-time is not production-removable. A successful PoC must not reuse the rejected argument that the `charge` Tracy span itself is the wall-clock target; the valid target is the repeated non-Tracy work visible in source: `RefCell` mutable access, tracker lookup/update, two linear cost-model evaluations, two total-count updates, and two limit checks per small charge. The trace's 20.2M in-window charge count is nevertheless important: after dividing by seven long windows and eight clusters, a Medium result only needs roughly tens of nanoseconds of net saving per critical-worker charge.

The proposed accumulator is correct in principle under a new protocol gate because the cost models are linear in `(iterations, input)` and the existing trackers store additive totals. Flushing accumulated deltas can reproduce final `cpu_insns`, `mem_bytes`, and per-cost tracker fields for successful transactions, while a next-protocol rule can define budget-exceeded detection at deterministic flush points rather than at the historical micro-charge instruction. This is broader and more plausible than the failed local budget fast path because it removes repeated model/tracker/limit work across many hot host-internal charge sources instead of trying to skip a Tracy span or rely on compiler inlining.

The main correctness constraint is that accumulation cannot be a blind global policy for every `ContractCostType`. Shared types such as `MemCpy` and `MemAlloc` are used both for abstract host bookkeeping charges and for real guest-memory copies or heap allocations where the current pre-charge is a DoS and error-order guard. The PoC should therefore use an explicit protocol-gated accumulated-charge API or scoped accumulator that only selected, audited call sites opt into; it should initially exclude or separately justify charge sites such as object visitation, XDR write chunks, real memory copies, real allocations, shadow-mode sections, and VM fuel synchronization if their boundaries make deferred errors observable or unsafe.

The projected impact meets the objective's Medium review bar but not High. The accepted severity is based on the enormous call count and the fact that removing two model evaluations plus tracker/limit work per eligible charge plausibly clears the 3% floor; it does not claim the full 31 ms/ledger Tracy envelope. If the implementation still borrows the `BudgetImpl` for every charge and only saves a few saturated additions, or if required flushes are so frequent that most hot charges remain immediate, the PoC should fail the benchmark gate.

### PoC Guidance

- **Target code**: Add the accumulator and flush plumbing in `src/rust/soroban/p26/soroban-env-host/src/budget.rs` and `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs`; opt in only audited hot call sites such as `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs` first. Add flush calls before `Budget` resource/tracker getters, before `with_shadow_mode`, before `get_wasmi_fuel_remaining` / `bulk_charge(WasmInsnExec)` boundaries if needed, and at the end of `invoke_host_function_or_maybe_panic` before output metrics are read.
- **Change description**: Under a next-protocol gate, accumulate eligible additive charges as `(iterations, input_sum)` per cost type, evaluate CPU and memory totals once per flush using the same linear model, update `meter_count` and per-cost trackers by the exact accumulated counts, then check CPU and memory limits. Do not globally defer all `MemCpy`/`MemAlloc`/`ValSer`/`VisitObject` charges by cost type alone; use explicit safe-site opt-in or a scoped host-internal API.
- **Correctness check**: Existing coverage to run in the PoC stage includes Rust budget metering tests in `src/rust/soroban/p26/soroban-env-host/src/test/budget_metering.rs`, host/object/vector/map/XDR tests that assert budget trackers, and transaction-level Soroban resource-limit tests in `src/transactions/test/InvokeHostFunctionTests.cpp`. Add next-protocol tests for equivalent successful final CPU/memory totals, deterministic over-budget failure at a flush boundary, shadow-mode isolation, and immediate flush before `get_tracker`/resource getter observations.
- **Benchmark focus**: Add temporary counters for accumulated-charge hits, immediate-charge fallbacks, and flush count by cost type, plus a non-Tracy before/after apply-load matrix for soroswap. The expected metric is a reproducible 3-10% reduction in top-line apply time; Tracy should be used only to confirm that `charge` call count and eligible map/vector/conversion charge sites are reduced or amortized, not as the production timing proof.
