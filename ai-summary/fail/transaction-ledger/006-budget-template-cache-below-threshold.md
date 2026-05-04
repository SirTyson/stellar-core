# H006: Cache decoded budget cost-model templates per ledger

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / Soroban host invocation
**Severity**: Low
**Impact**: Soroswap apply-time reduction from avoiding repeated cost-param XDR decode and budget model construction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each invoke-host operation needs a fresh budget tracker and fresh consumed-resource counters, but immutable network cost parameters should not need to be decoded from XDR and converted into cost models for every transaction if the ledger's Soroban config is unchanged.

## Mechanism

`invoke_host_function_or_maybe_panic` decodes `ledger_info.cpu_cost_params` and `ledger_info.mem_cost_params` from `CxxBuf` for every invocation, then `Budget::try_from_configs` rebuilds two `BudgetDimension` cost-model arrays. A cache could hold decoded `ContractCostParams` or a cloneable budget-dimension template per ledger/protocol and instantiate only the mutable tracker/limits per transaction.

## Trigger

Run the current soroswap benchmark and add narrow spans around `non_metered_xdr_from_cxx_buf::<ContractCostParams>` and `Budget::try_from_configs` in `src/rust/src/soroban_proto_any.rs`.

## Target Code

- `src/rust/src/soroban_proto_any.rs:412-420` — decodes CPU and memory cost params from `CxxLedgerInfo` for every invoke.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:210-224` — constructs `BudgetImpl` from cost params and calls `load_calibrated_fuel_costs`.
- `src/rust/soroban/p26/soroban-env-host/src/budget/dimension.rs:73-93` — loops through all cost params to populate a `BudgetDimension`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:43-94` — already caches the `CxxLedgerInfo` wrapper per ledger/thread, but not decoded Rust cost models.

## Evidence

This is structurally redundant: `CxxLedgerInfo` is cached per ledger in C++, while Rust still decodes the embedded cost-param buffers on each invoke. The current trace shows `invoke_host_function_or_maybe_panic` and `invoke_host_function` inside apply windows, so a narrow cache would target real apply work rather than TX-set construction.

## Anti-Evidence

The whole `invoke_host_function` self-time category is only **741,215,306 ns** aggregate over 6,776 calls in the current trace, and budget setup is only a subset of that category. After normalizing aggregate worker time across eight soroswap clusters and roughly 70 apply windows, even removing the entire wrapper self-time would be around 1-2 ms per ledger, below the objective's 3% Medium floor. A recent source history entry also indicates a prior thread-local budget-cache experiment was reverted, increasing implementation risk.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — this exact cost-param-template cache was not present in the active transaction-ledger summary

### Why It Failed

The redundant decode/setup exists, but the maximum recoverable wall-time is below the optimize-soroswap Medium threshold after cluster normalization. It should not be promoted as a standalone hypothesis unless bundled for free into a broader accepted host-invocation redesign.

### Lesson Learned

Per-invocation Rust bridge setup can look suspicious, but any worker-local aggregate must be divided by active cluster count before projecting apply-time impact. Cache ideas around `Budget` are especially risky because prior budget-cache changes have been reverted.
