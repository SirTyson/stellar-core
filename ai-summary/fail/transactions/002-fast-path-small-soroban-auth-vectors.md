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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The p23+ Soroban parallel apply path enters `InvokeHostFunctionOpFrame::doParallelApply`, constructs an `InvokeHostFunctionParallelApplyHelper`, calls `InvokeHostFunctionApplyHelper::doApply`, then serializes the operation's auth vector before crossing the Rust bridge. The soroswap generator does create one source-account auth entry per swap transaction, so the C++ vector allocation and `toCxxBuf(authEntry)` serialization occur once per benchmark transaction. On the Rust side, however, `e2e_invoke::invoke_host_function` immediately decodes the full `SorobanAuthorizationEntry`, installs it into the host authorization manager, and converts the entry's root invocation plus sub-invocations into the authorization tracker used during contract-call matching. The source-account credential only skips signature authentication; it does not make the authorization entry, root invocation, sub-invocation tree, XDR decode, metered collection, or invocation matching removable.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — `InvokeHostFunctionApplyHelper::doApply` runs `addFootprint`, `invokeHostFunction`, storage-change recording, event collection, refundable-resource accounting, and success finalization on the apply path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` constructs a `rust::Vec<CxxBuf>`, reserves auth-entry capacity, serializes every `SorobanAuthorizationEntry` with `toCxxBuf`, and passes the vector to `rust_bridge::invoke_host_function`.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` materializes a new `std::vector<uint8_t>` from `xdr::xdr_to_opaque`, so the claimed C++ allocation/copy exists.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `doParallelApply` confirms this helper is used in the p23+ parallel Soroban apply path relevant to soroswap.
- `src/simulation/ApplyLoad.cpp:3395-3505` — the soroswap benchmark generates one unique source account per transaction and one `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` auth entry whose root invocation includes the router call and a SAC transfer sub-invocation.
- `src/rust/src/bridge.rs:193-208` and `src/rust/src/soroban_invoke.rs:7-38` — the CXX bridge API accepts `auth_entries: &Vec<CxxBuf>` and dispatches unchanged to the protocol-specific host.
- `src/rust/src/soroban_proto_any.rs:391-448` — p26 dispatch forwards `auth_entries.iter()` into `invoke_host_function_with_trace_hook_and_module_cache`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-462` — Rust builds storage, constructs the host, decodes auth entries with `build_auth_entries_from_xdr`, then sets the authorization entries before invoking the host function.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1055-1065` — every encoded auth entry is metered-decoded as a full `SorobanAuthorizationEntry` and collected into a metered `Vec`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:526-532` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:772-790` — `set_authorization_entries` creates an enforcing `AuthorizationManager` and one account tracker per decoded auth entry.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1801-1839` — source-account credentials resolve to the transaction source account and skip signature state, but still build an `InvocationTracker` from `auth_entry.root_invocation`.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:638-654` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1571-1583` — root invocations and sub-invocations are recursively converted into host authorization structures.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1700-1720` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:2076-2080` — invocation matching consumes the authorization tree during calls, while source-account authentication itself is only a no-op.

### Why It Failed

The inefficiency exists, but the proposed "small source-account auth vector" shortcut does not remove enough correct work to meet the optimize-soroswap Medium floor. In the benchmark case the auth vector is not semantically empty: it carries the router root invocation and SAC transfer sub-invocation that the Rust authorization manager must decode, meter, convert to host objects, and later match against the actual call stack. A bridge flag saying "all credentials are source-account" could at most avoid the small credential enum/signature portion and the outer one-element C++ vector allocation; it cannot elide transmission or decoding of the invocation tree without changing authorization semantics and consensus-visible metering. With the current baseline at 596.381 ms, the objective requires roughly an 18 ms wall-clock improvement, or about 144 ms of aggregate 8-way worker work; the removable portion here is just one small vector allocation and the source-account credential wrapper per 4000 transactions, while the full auth-entry XDR decode, `AuthorizedInvocation::from_xdr`, metered collection, host-object construction, and invocation matching remain mandatory.

### Lesson Learned

For Soroban source-account auth, "no signature authentication" is not the same as "no authorization payload." Optimization hypotheses targeting auth-entry bridge traffic must account for the full invocation tree and its metered Rust-side conversion; source-account credentials alone are too small a removable component for this objective.
