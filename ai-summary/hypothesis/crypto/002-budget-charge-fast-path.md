# H002: Exact Budget::charge Fast Path for Hot Soroban Apply Metering

**Date**: 2026-05-21
**Subsystem**: crypto / rust
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by preserving exact metering while reducing per-charge bookkeeping overhead
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-preserving optimizations, every Soroban budget charge should produce exactly the same CPU total, memory total, tracker values, and budget-exceeded result as today, but the implementation should avoid repeated generic dispatch work on the hottest apply path. Once `BudgetImpl` is built from ledger cost parameters, charging a known `ContractCostType` should use cached per-cost metadata and only execute the dimension work that can affect the result.

## Mechanism

`Budget::charge` currently enters `BudgetImpl::charge` via a `RefCell` borrow for every metered event, updates tracker counters, calls `BudgetDimension::charge` for CPU, checks the CPU limit, calls `BudgetDimension::charge` for memory, and checks the memory limit (`src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284`). Each `BudgetDimension::charge` then looks up the cost model by enum index and evaluates it (`src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188`). The current soroswap Tracy trace reports `charge` at `soroban-env-host/src/budget/dimension.rs:176` with 1,758,199,707 ns self-time across 20,300,668 calls, so an exact fast path that caches model pointers/zero-cost-dimension flags and avoids redundant memory-side work where the configured memory model is zero could reduce apply time without changing metering semantics.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the accepted baseline. Each `InvokeHostFunctionOp` exercises hundreds to thousands of budget charges through storage map operations, metered XDR, host-object conversion, VM dispatch, and SAC transfer helpers; these charges occur inside the `invoke_host_function` descendant of `applyLedger`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1323-1325` — public `Budget::charge` wrapper that borrows the mutable budget implementation per charge.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:235-284` — hot `BudgetImpl::charge` path that performs tracker updates, CPU charge/check, and memory charge/check for every call.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:163-188` — per-dimension model lookup/evaluation and Tracy instrumentation.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:20-25,77-81` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:258-654` — high-frequency apply callers that amplify the generic charge overhead.

## Evidence

- The zone is apply-path relevant: `Budget::charge` is called by Soroban host execution under `InvokeHostFunctionOpFrame doApply`, which is run inside `parallelApply` workers spawned by `applySorobanStageClustersInParallel`, a descendant of `applyLedger`.
- The current trace shows `charge` as the largest remaining in-scope Soroban host self-time: 1.758 s self-time and 20.3M calls. Reducing only 10-15% of its non-instrumentation overhead would recover roughly 176-264 ms across the diagnostic trace, meeting the Medium threshold against the 5.230 s `applyLedger` envelope.
- This hypothesis is not a metering model change. Unlike bulk/coalesced metering, it can preserve exact p26-visible instruction and memory totals by evaluating the same cost formulas and updating the same trackers, just through precomputed per-cost descriptors and specialized branches.
- The improvement is deterministic and does not add parallelism, change worker count, alter ledger output order, or touch cryptographic primitives.

## Anti-Evidence

- The `charge` Tracy span itself emits text and numeric values (`dimension.rs:174-179`), so Tracy self-time overstates production overhead. A PoC must be judged by repeated non-Tracy `run_apply_load_matrix.py` runs.
- If most production charge time is dominated by unavoidable `RefCell` borrow checking and limit checks that cannot be elided, the exact fast path may fall below Medium despite the large Tracy zone.
- Many charge callers are inside parallel Soroban worker threads, so aggregate worker self-time must be translated to wall-clock critical-path savings during review; the hypothesis depends on the `charge` overhead being broadly present on the long worker in each stage, not only on already-parallel aggregate work.
