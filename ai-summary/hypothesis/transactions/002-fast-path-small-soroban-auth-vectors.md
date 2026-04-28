# H002: Fast-Path Small Soroban Authorization Vectors Across the C++ Bridge

**Date**: 2026-04-28
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by avoiding per-transaction heap churn and XDR buffer construction for the common single source-account authorization shape
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban transaction with `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` authorization should produce exactly the same authorization tree, budget charges, results, events, and ledger changes as the generic auth-vector path. The bridge should still reject malformed or non-source-account auth entries through the existing Rust validation logic, but the common soroswap shape should avoid constructing a heap-backed `rust::Vec<CxxBuf>` and serializing each auth entry separately when the auth vector is empty or contains only the source-account entry shape.

## Mechanism

`InvokeHostFunctionApplyHelper::invokeHostFunction` always allocates a `rust::Vec<CxxBuf>`, reserves space for all auth entries, serializes each `SorobanAuthorizationEntry` with `toCxxBuf`, and passes that vector through the Rust bridge. The soroswap generator uses source-account Soroban credentials for its invoke-host-function transactions, so this generic auth-entry serialization path repeats thousands of times during apply even when the Rust host will treat the credentials as the simple source-account authorization case. Adding a deterministic small-auth bridge path, such as a fixed inline buffer or an explicit "all source-account credentials" bridge flag accompanied by the original auth count and validation, should reduce C++ allocation/XDR write work in the `InvokeHostFunctionOpFrame doParallelApply` subtree without changing transaction ordering or consensus-visible authorization outcomes.

## Trigger

Run the current soroswap benchmark shape (`soroswap`, 4000 tx, 8 clusters) with the accepted trace from `ai-summary/CURRENT_STATE.md`. The issue triggers once per Soroban transaction in `InvokeHostFunctionApplyHelper::invokeHostFunction` when the operation's auth vector contains the benchmark's source-account credential entries.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-565` — constructs and fills `rust::Vec<CxxBuf> authEntryCxxBufs` for every invoke-host-function apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584` — passes the serialized auth-entry vector to `rust_bridge::invoke_host_function`.
- `src/simulation/ApplyLoad.cpp:3395-3407` — soroswap generation uses a unique source account per transaction.
- `src/simulation/ApplyLoad.cpp:3477-3505` — soroswap invoke-host-function generation uses source-account Soroban credentials for the benchmark transactions.

## Evidence

The current Tracy trace places `InvokeHostFunctionOpFrame doParallelApply` under `applyLedger` with 4.656s of aggregate worker overlap, so per-transaction bridge setup is on the measured apply path rather than TX-set construction. A prior failed transaction-ledger record found that precomputing all C++ bridge buffers was below the Medium threshold when spread across host function, resources, source ID, and auth entries, but that analysis treated the generic precompute strategy as moving work out of apply; this hypothesis instead targets the soroswap-specific auth vector shape and removes the repeated vector allocation plus per-entry `toCxxBuf` serialization from the apply-side bridge path. Because this fast path is keyed on source-account credential structure and retains Rust-side validation for other auth shapes, it is more focused than broad bridge-buffer precomputation.

## Anti-Evidence

`ai-summary/fail/transaction-ledger/summary.md` reports `005-precompute-cxxbuf-on-tx-construction.md` as below threshold for broad C++ bridge-buffer precomputation, so this hypothesis depends on the source-account auth vector portion being a larger share of the remaining bridge overhead than that aggregate result implied, or on combining allocation removal with Rust-side decode simplification for this exact credential shape. The reviewer should measure auth-vector counts and bridge setup self-time directly before investing in implementation, and reject the idea if source-account auth entries are not present often enough in the current soroswap trace to clear the 3% objective floor.
