# H001: Apply-Mode Direct Ledger Effects and Rent Output

**Date**: 2026-05-25
**Subsystem**: transaction-ledger / Soroban host apply bridge
**Severity**: Medium
**Impact**: soroswap apply-time reduction by fusing the remaining sparse ledger-change bridge pipeline
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For successful Soroban apply transactions with ledger-close metadata disabled, the Rust host should return exactly the data stellar-core consumes: modified ledger-entry XDR buffers and the final rent fee. It should still perform the same metered key, old-entry, new-entry, TTL, and rent-size work in the same per-entry order, and C++ should record the same `ParallelTxSuccessVal`, storage effects, fees, result hash, and diagnostics.

The efficient apply-mode path should not allocate a `Vec<LedgerEntryChange>`, store intermediate rent-change structs, then immediately run `extract_rent_changes` and `extract_ledger_effects` to discard most of that intermediate shape before C++ sees the output.

## Mechanism

The accepted sparse no-meta path removed unused `encoded_key` retention and no-op read-only `LedgerEntryChange` records, but it still returns sparse `LedgerEntryChange` structs from `get_ledger_changes` to `soroban_proto_any.rs`, where the bridge makes a second pass to compute rent changes and modified ledger-entry buffers. The actual behavior therefore still builds an internal representation whose only apply-mode consumers are two extraction functions and C++ `recordStorageChanges`.

A dedicated `invoke_host_function_for_apply` result type can fuse `get_ledger_changes`, rent-change extraction, and modified-entry extraction into one apply-mode pass. It would push modified entry bytes directly into the bridge output, accumulate rent changes or rent fee immediately, and preserve all metered serialization by writing keys/entries into scratch buffers exactly as the dense path does. This targets the remaining output side of `invoke_host_function` rather than the already-accepted no-op filtering slice.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with transaction metadata disabled. Every successful swap returns through `invoke_host_function_for_apply`, produces a small set of modified entries and TTL/rent information, then `soroban_proto_any.rs` extracts rent and effects before C++ decodes the modified entries in `recordStorageChanges`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:568-745` — accepted apply wrapper and internal invoke flow; still calls `get_ledger_changes` and returns a sparse `LedgerEntryChange` vector.
- `src/rust/src/soroban_proto_any.rs:478-506` — successful bridge output immediately calls `extract_rent_changes`, `host_compute_rent_fee`, and `extract_ledger_effects` on the returned ledger changes.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-767` — C++ only consumes modified ledger-entry buffers and validates them against the RW footprint.

## Evidence

- The current diagnostic trace confirms the entire path is an `applyLedger` descendant: `parallelApply@transactions/TransactionFrame.cpp:2392` -> `InvokeHostFunctionOpFrame doParallelApply@transactions/InvokeHostFunctionOpFrame.cpp:1367` -> `invokeHostFunction@transactions/InvokeHostFunctionOpFrame.cpp:559` -> `invoke_host_function@soroban-env-host/src/e2e_invoke.rs:639`.
- The same trace reports `invoke_host_function@soroban-env-host/src/e2e_invoke.rs:639` at **11.916s total / 8705 calls** and **976.9ms self-time**, while downstream `recordStorageChanges@transactions/InvokeHostFunctionOpFrame.cpp:643` still accounts for **69.9ms self-time / 8705 calls**. The accepted sparse no-meta optimization proved this output pipeline can produce a measurable soroswap win without changing host execution.
- Source shows the apply bridge's consumer contract is narrower than `LedgerEntryChange`: `soroban_proto_any.rs` extracts rent and modified entries, and `InvokeHostFunctionOpFrame` receives only `out.modified_ledger_entries` plus `out.rent_fee`. This leaves an apply-only seam to bypass the intermediate vector shape while retaining dense/recording behavior for other callers.

## Anti-Evidence

- This is a follow-up to the accepted sparse no-meta work, so the remaining removable slice may be smaller than Medium. Review must measure the direct extraction pass separately; if it is only another Low-severity allocation cleanup, it should be rejected.
- Metering is load-bearing. The PoC must preserve every `metered_write_xdr`, `metered_from_xdr`, `ValSer`, `ValDeser`, TTL-hash, and rent-size charge that the existing sparse apply path performs, or explicitly protocol-gate any metering change.
- `recordStorageChanges` must still validate modified entries in C++ unless equivalent validation is moved across the bridge with the same diagnostics and failure ordering.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related ledger-change-output failures exist, but this exact metering-preserving output-shape fusion was not previously confirmed or rejected
**Failed At**: reviewer

### Trace Summary

The protocol 23+ Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, constructs `InvokeHostFunctionParallelApplyHelper`, and calls `rust_bridge::invoke_host_function` for every successful soroswap operation. The Rust bridge invokes the p26 host, which builds enforcing storage, executes `Host::invoke_function`, calls `get_ledger_changes`, then immediately converts those ledger changes into rent fee plus modified ledger-entry buffers in `soroban_proto_any.rs`. C++ consumes only `modified_ledger_entries` and `rent_fee`, but it must still decode and validate returned entries against the transaction footprint in `recordStorageChanges`.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-637` — C++ builds bridge buffers, calls `rust_bridge::invoke_host_function`, records CPU/memory/timing metrics, and handles host failures.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` — C++ decodes each returned modified `LedgerEntry`, validates resource limits and RW-footprint coverage, upserts returned entries, and erases omitted RW Soroban entries.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — the apply helper orders the hot path as `addFootprint`, `invokeHostFunction`, `recordStorageChanges`, event collection, refundable-resource consumption, and success finalization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — parallel Soroban apply calls the helper from `doParallelApply`, so the target path is inside `closeLedger`.
- `src/rust/src/soroban_invoke.rs:7-39` — the protocol dispatcher calls the selected host module's `invoke_host_function`.
- `src/rust/src/soroban_proto_any.rs:478-506` — on success, the bridge calls `extract_rent_changes`, `host_compute_rent_fee`, and `extract_ledger_effects`, then returns only result bytes, modified entries, events, metrics, and rent fee to C++.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` filters out read-only changes, forwards `encoded_new_value`, and synthesizes TTL `LedgerEntry` XDR for live-until extensions.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:49-67` — `InvokeHostFunctionResult` still exposes a full `Vec<LedgerEntryChange>` for the bridge, including no-op footprint entries in this worktree.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-357` — `get_ledger_changes` iterates the enforcing storage map, performs metered key/new-entry serialization, computes old/new rent sizes, records TTL changes, and builds the intermediate `LedgerEntryChange` vector.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:393-430` — `extract_rent_changes` performs a second pass over ledger changes and allocates `LedgerEntryRentChange` records only for non-no-op rent-relevant entries.
- `src/rust/soroban/p26/soroban-env-host/src/fees.rs:290-321` — rent fee calculation only needs a slice of rent changes and a small aggregate count of TTL extensions.

### Why It Failed

The local inefficiency exists, but the proposed metering-preserving fusion is below the optimize-soroswap Medium threshold. The expensive work inside `get_ledger_changes` is not just intermediate-shape construction: `metered_write_xdr` for keys and new entries, possible old-entry serialization, TTL hash derivation, entry-size computation, `wasm_module_memory_cost`, and restored-key checks are protocol-visible or otherwise semantically required. A correct direct-output path can avoid storing a `LedgerEntryChange` struct, avoid allocating a separate rent-change vector, fold the rent-fee pass, and push modified entry bytes directly, but it cannot remove the mandatory per-entry metered serialization or the C++ `recordStorageChanges` validation/decoding without changing consensus-visible resource accounting or error behavior.

Prior failure summaries bound the relevant adjacent opportunities: `002-track-dirty-ledger-changes.md` established that skipping `get_ledger_changes` metered serialization requires a protocol-gated metering change, `001-carry-initial-storage-metadata.md` established that replacing recursive serialization with size metadata is not equivalent because `ValSer` has per-chunk charges, and `002-protocol-gate-ledger-change-xdr-output.md` found even broad direct ledger-change XDR output below the objective threshold. This hypothesis deliberately preserves the metered work, so its remaining savings are a smaller non-metered allocation/pass-cleanup slice than those already rejected broader ledger-change-output ideas. Under the objective's severity rule, a real Low/sub-1% cleanup must be marked NOT_VIABLE rather than downgraded and accepted.

### Lesson Learned

For Soroban apply-output hypotheses, separate mandatory metered XDR/accounting work from non-metered bridge-shape cleanup before projecting impact. Directly returning C++'s consumed output shape is architecturally plausible, but after preserving `ValSer`/`ValDeser`, TTL/rent accounting, and `recordStorageChanges` validation, the residual vector/pass fusion is too small for the soroswap Medium bar.
