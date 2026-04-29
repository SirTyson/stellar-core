# H001: Specialize the hot non-shadow `Budget::charge` path

**Date**: 2026-04-29
**Subsystem**: transaction-ledger / Soroban host budget metering
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing fixed overhead in every high-frequency host budget charge
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban host budget charge should produce the same CPU and memory totals, tracker fields, saturation behavior, and budget-exceeded result as today. The common production path for a single non-shadow charge should not repeatedly pay generic `Option`-returning array lookups, two nested `BudgetDimension::charge` calls, and separate limit-check helper calls when the cost-type enum is already a valid fixed-array index and the charge shape is overwhelmingly `iterations == 1`.

## Mechanism

`Budget::charge` borrows `BudgetImpl` and funnels every charge through the fully generic `BudgetImpl::charge`. That function looks up the tracker with `get_mut`, calls `BudgetDimension::charge` for CPU and memory, each dimension revalidates the cost-model index with `get_cost_model`, evaluates the model, updates totals, and then `BudgetImpl` separately checks the CPU and memory limits. A specialized fast path for non-shadow single charges can index the fixed arrays directly, inline the CPU-then-memory evaluation/update sequence, and keep the bulk/shadow/error-preserving path as a fallback, reducing fixed metering overhead across the whole apply hot path without changing deterministic metering.

## Trigger

Run the current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. Timestamp filtering confirms the generic `charge` zone is contained under `applyLedger`: across applyLedger windows it appears 18,721,841 times for 2,043.955 ms total event time, and in the longest 972.093 ms `applyLedger` window it appears 1,744,938 times for 374.541 ms total event time with 53.782 ms on the critical worker thread.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` performs the generic tracker lookup, CPU charge, CPU limit check, memory charge, memory limit check, and tracker updates for every charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1301-1325` — public `bulk_charge` and `charge` entry points; `charge` always enters the single-iteration path.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:96-188` — `BudgetDimension::charge` revalidates the cost-model index, evaluates the model, updates the dimension total, and owns the Tracy `charge` span.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — `MeteredCostComponent::evaluate` defines the arithmetic that the fast path must preserve exactly.

## Evidence

The zone is inside the measured close-ledger path, not TX-set construction: the longest apply window contains `applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applySorobanStages` -> `applySorobanStageClustersInParallel` -> `InvokeHostFunctionOpFrame doParallelApply` -> `invoke_host_function`, and the `charge` events occur on the same Soroban worker threads. The code is structurally optimized for generality rather than the dominant call shape: `ContractCostType` indexes fixed-size arrays whose length is `ContractCostType::variants().len()`, yet every charge uses checked `get`/`get_mut` calls and HostError construction paths that should be unreachable for valid enum inputs. Because `charge` is called millions of times per apply trace, removing even 15-25% of the fixed non-Tracy overhead from the critical worker is plausibly around 8-13 ms on the current soroswap median, clearing the 3% Medium threshold.

This differs from the reviewed `batch-metered-xdr-valser-charges` and `batch-host-object-visit-charges` hypotheses. Those reduce call counts for specific cost types at specific conversion/serialization sites; this targets the per-call implementation cost that remains for all cost types, including storage, map, vector, VM-dispatch, and SAC paths.

## Anti-Evidence

The Tracy `charge` span inflates the measured cost in Tracy builds, so the PoC must prove non-Tracy apply-time improvement rather than just removing profiler overhead. Budget-exceeded ordering is protocol-visible: the fast path must still update/check CPU before memory and must not charge memory if CPU already exceeds the limit. The expected impact can shrink if the reviewed charge-batching hypotheses land first, but the remaining call volume across non-`ValSer` and non-`VisitObject` cost types should still be measured before rejecting the generic fast path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in transaction-ledger fail/success records
**Failed At**: reviewer

### Trace Summary

The close-ledger hot path reaches budget metering through parallel Soroban apply: `LedgerManagerImpl::applySorobanStageClustersInParallel` launches worker threads, `applyThread` calls `TransactionFrameBase::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply` enters the Rust bridge, `soroban_proto_any::invoke_host_function_or_maybe_panic` creates a `Budget`, and `e2e_invoke::invoke_host_function` builds a `Host` using that shared budget. Host functions, storage/map/vector helpers, object visits, VM fuel return, memory helpers, crypto helpers, and metered XDR all call `Budget::charge` or `Budget::bulk_charge`.

The inefficiency is directionally real: the single-charge path still goes through a generic `BudgetImpl::charge`, checked tracker lookup, two `BudgetDimension::charge` calls, checked cost-model lookups, and separate limit helpers. However, the cited Tracy `charge` zone is not a measurement of that full path. In `BudgetDimension::charge`, cost-model lookup and `MeteredCostComponent::evaluate` happen before the Tracy span, and total-count update happens after the span, so the profiler event mostly measures Tracy span creation plus `emit_text`/`emit_value` for the CPU dimension only.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — each Soroban worker applies txs in `applyThread`, then commits successful tx changes to thread state.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` — `applySorobanStageClustersInParallel` constructs thread state, launches workers with `std::async`, and waits for them.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — the C++ helper calls `rust_bridge::invoke_host_function` with encoded host function, resources, ledger entries, TTL entries, PRNG seed, rent config, and module cache.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `doParallelApply` is the Soroban parallel-apply operation entry point and calls the helper apply path.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge entry creates `Budget::try_from_configs` from instruction/memory limits and on-chain cost params, then calls the protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-480` — invocation decodes resources, builds storage, constructs `Host::with_storage_and_budget`, decodes auth/host function/source account, then calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:634-636` — host-level `charge_budget` forwards to `Budget::charge`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — `BudgetImpl::charge` updates tracker state, charges CPU, checks CPU limit, charges memory, checks memory limit, and must preserve CPU-before-memory error ordering.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1301-1325` — public `bulk_charge` passes caller-provided iterations, while public `charge` always calls the implementation with `iterations == 1`.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — `BudgetDimension::charge` gets the cost model, evaluates it, opens the Tracy `charge` span only after evaluation, emits text/value only for CPU charges, then updates the dimension total after the span.
- `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:116-133` — `MeteredCostComponent::evaluate` performs saturating constant and linear-term arithmetic that any fast path must preserve exactly.
- `Cargo.toml:5-14` — release builds use `codegen-units = 1` and `lto = true`, so small same-crate helpers are likely to be inlined already in optimized builds.
- `ai-summary/CURRENT_STATE.md:18-30,60-73` — the authoritative soroswap baseline is roughly 297-313 ms, making the 3% Medium floor about 9 ms, while the cited detailed trace is diagnostic-only.

### Why It Failed

The hypothesis's impact estimate rests on the Tracy `charge` zone, but that zone does not cover the generic metering work targeted by the proposed fast path. It excludes cost-model lookup/evaluation, tracker updates, dimension total updates, and limit checks; it primarily captures instrumentation overhead for CPU charges in a diagnostic trace. A correctness-preserving fast path would still need to retain the `RefCell` borrow from public `Budget::charge`, tracker/input-shape validation, exact saturating model arithmetic for CPU and memory, CPU-limit checking before memory charging, memory-limit checking, and the same over-limit side effects. If it also preserves diagnostic trace semantics, it must keep the span; if it drops the span, any Tracy win is just removing instrumentation rather than improving non-Tracy apply time.

After removing the profiler-measurement artifact, the remaining plausible savings are only checked fixed-array lookups, small helper layers, boolean wrapper arguments, and multiplication-by-one/general-iterations handling. In optimized Rust builds with LTO these helpers are likely inlined, and the remaining direct-indexing/code-duplication win is not credibly a reproducible 3-10% soroswap apply-time reduction. This is below the objective severity threshold, so it is not viable for the optimize-soroswap pipeline.

### Lesson Learned

For Soroban budget-metering hypotheses, do not treat the Tracy `charge` event as the cost of `Budget::charge`. The current span is scoped around profiler emission inside the CPU dimension, not around the full metering operation; a Medium claim needs non-Tracy measurements or a trace zone that actually encloses the removable metering work.
