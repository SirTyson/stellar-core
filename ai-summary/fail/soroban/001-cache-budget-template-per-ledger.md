# H001: Cache Per-Ledger Soroban Budget Templates Instead of Rebuilding Cost Models Per Invocation

**Date**: 2026-04-29
**Subsystem**: soroban / rust bridge
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing repeated per-invocation budget-configuration decoding and cost-model construction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every Soroban invocation in a ledger should start with a clean budget that has the same CPU limit, memory limit, cost-model parameters, tracker state, shadow-mode behavior, fuel costs, and depth limit as today. Since the Soroban network cost parameters are constant for the whole ledger, applying 3,335 soroswap transactions should not repeatedly deserialize identical `ContractCostParams` XDR and rebuild identical `BudgetDimension::cost_models` arrays for each transaction.

## Mechanism

The C++ side already caches `CxxLedgerInfo` once per thread and ledger in `getCachedLedgerInfo`, including serialized CPU and memory cost-parameter buffers. The Rust side still decodes those buffers and calls `Budget::try_from_configs` on every `invoke_host_function_or_maybe_panic`, rebuilding both `BudgetDimension`s from the same cost params for every invoke-host operation. A per-ledger/per-protocol budget template, owned by the Rust bridge module cache or another apply-thread-safe Soroban cache, could hold the parsed cost-model arrays and fuel-cost configuration, then instantiate each transaction's clean `BudgetImpl` by copying/resetting counters and applying the per-tx instruction limit and ledger memory limit.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with the p26 host path. The issue triggers on every successful and failed invoke-host operation because `invoke_host_function_or_maybe_panic` constructs a fresh `Budget` before executing the host function.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:43-94` — C++ builds and thread-locally caches `CxxLedgerInfo` per ledger, including `cpu_cost_params` and `mem_cost_params`.
- `src/rust/src/bridge.rs:70-82` — `CxxLedgerInfo` carries cost params as XDR buffers across the bridge.
- `src/rust/src/soroban_proto_any.rs:410-420` — every invocation decodes the identical cost-param buffers and calls `Budget::try_from_configs`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:208-224` — `BudgetImpl::try_from_configs` constructs CPU and memory `BudgetDimension`s.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:73-93` — `BudgetDimension::try_from_config` walks all contract cost parameters and fills the fixed cost-model array.
- `src/rust/src/soroban_module_cache.rs` and `src/rust/src/soroban_proto_any.rs` — likely ownership points for a protocol-specific, shared-but-immutable budget template keyed by `(protocol_version, ledger_seq or cost-param hash)`.

## Evidence

The current soroswap Tracy trace is `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`. `applyLedger` spans 5,774,332,215 ns over 69 windows. `InvokeHostFunctionOpFrame doParallelApply` has 3,335 calls fully contained in `applyLedger`, and the Rust `invoke_host_function` / `invoke_host_function_or_maybe_panic` path is reached once per call. The full-trace self-time table shows `invoke_host_function,soroban-env-host/src/e2e_invoke.rs,422,355077158,...,3335` and `invoke_host_function_or_maybe_panic,src/rust/src/./soroban_proto_any.rs,408` totaling 9,917,742,793 ns including descendants; budget construction is part of this per-invocation envelope before contract execution.

The structural redundancy is explicit: `ledger_info.cpu_cost_params` and `ledger_info.mem_cost_params` are ledger-level network configuration, while `instruction_limit` is the per-transaction value. Reusing parsed cost-model templates preserves determinism because cost-model parameters are read-only ledger state; each transaction would still receive a fresh tracker and zeroed totals.

## Anti-Evidence

This is not the same as the reviewed budget-charge hot-path hypothesis: that targets per-operation charging after a budget exists, while this targets per-invocation budget setup before the host runs. The current trace does not have a dedicated zone around `Budget::try_from_configs`, so a reviewer should first add temporary Tracy zones or micro-measure the setup slice to prove it is a Medium-sized portion of `invoke_host_function` self/envelope time. The implementation must also avoid sharing mutable budget counters between transactions; only immutable cost-model templates are safe to share across parallel worker threads.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; nearby bridge, storage, and budget-metering failures do not target per-invocation `Budget::try_from_configs`
**Failed At**: reviewer

### Trace Summary

The close-ledger Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply` on worker threads, serializes bridge inputs, then calls the Rust `invoke_host_function` entry point once per invoke-host transaction. The C++ helper does cache `CxxLedgerInfo` per thread and ledger, but the Rust protocol-agnostic invocation wrapper still decodes the cached CPU and memory `ContractCostParams` buffers and constructs a fresh `Budget` before entering `e2e_invoke::invoke_host_function`. That redundant setup is real and in the apply window, but the removable slice is only two small internal XDR decodes, two fixed-length cost-model array fills, and a constant `FuelCosts` initialization per invocation.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2483-2575` — Soroban clusters run on worker futures; each tx in a cluster calls `TransactionFrame::parallelApply` inside the measured apply stage.
- `src/transactions/TransactionFrame.cpp:2385-2430` — successful Soroban txs dispatch their single operation through `OperationFrame::parallelApply`.
- `src/transactions/OperationFrame.cpp:175-188` — `parallelApply` forwards to the concrete operation's `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1018,1358-1378` — invoke-host parallel apply constructs the helper, adds the footprint, invokes Rust, records storage changes, collects events, and finalizes success.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:43-94,556-584,1260-1267` — `getCachedLedgerInfo` caches serialized cost params per thread/ledger, and every host invocation passes that cached ledger info by reference across the bridge.
- `src/rust/src/bridge.rs:70-82,193-208` and `src/rust/src/soroban_invoke.rs:7-38` — `CxxLedgerInfo` holds cost-param buffers and is passed by reference to the selected protocol host module.
- `src/rust/src/soroban_proto_any.rs:391-420` — every invocation decodes `ledger_info.cpu_cost_params` and `ledger_info.mem_cost_params`, then calls `Budget::try_from_configs`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:208-224,1209-1275` — `Budget::try_from_configs` creates a new `Rc<RefCell<BudgetImpl>>`, fresh tracker, CPU/memory dimensions, calibrated fuel costs, and depth limit.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:73-93` and `src/rust/soroban/p26/soroban-env-host/src/budget/model.rs:94-105` — each dimension walks the decoded cost-param vector and copies const/linear coefficients into the fixed `MeteredCostComponent` array.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:396-452` — e2e invocation requires a clean budget and then shallow-clones it into the `Host`, so simply cloning an existing `Budget` would share mutable counters and is not a safe template mechanism.
- `src/rust/src/soroban_proto_any.rs:700-776` — `ProtocolSpecificModuleCache` is thread-shared only through its `ModuleCache` and atomics today; adding a mutable per-ledger budget-template cache would require new synchronization and host APIs rather than reusing an existing safe template surface.

### Why It Failed

The inefficiency exists, but it is below the optimize-soroswap objective severity threshold. A Medium finding must plausibly save at least 3% of the cited 5.77 s apply-window total, or roughly 173 ms across 3,335 invocations. This target would require more than 50 us of removable budget-setup work per invocation, yet the traced work is only two bounded internal XDR decodes of ledger-level `ContractCostParams`, two linear passes over the protocol cost-type array, a default tracker, and a five-field `FuelCosts` initialization.

The broad Tracy zones in the hypothesis do not isolate this cost: `time_nsecs` in the output is measured after budget construction, and `invoke_host_function_or_maybe_panic` includes the full e2e host execution descendants. The much larger apply-contained costs are storage, VM execution/instantiation, XDR ledger-entry handling, events, and budget charging during execution; this proposal removes only the small pre-host setup slice. A correct implementation also cannot reuse `Budget::clone`, because it is an `Rc<RefCell<BudgetImpl>>` shallow clone; it would need a new deep-template/reset API that preserves per-transaction counters and limits, further reducing the net win after synchronization/API overhead. The finding is therefore, at best, a Low/sub-threshold cleanup, and Low findings are rejected for this objective.

### Lesson Learned

Do not infer Medium impact from a wrapper zone that includes full Soroban host execution. For budget-template ideas, first add a dedicated measurement around `Budget::try_from_configs` or otherwise isolate decode-plus-dimension-build time; without evidence that this setup alone exceeds the 3% floor, per-ledger caching of small immutable cost-model parameters should be treated as below-threshold.
