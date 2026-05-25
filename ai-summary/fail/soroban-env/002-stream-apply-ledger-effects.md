# H002: Stream Apply Ledger Effects During `get_ledger_changes`

**Date**: 2026-05-25
**Subsystem**: soroban-env / rust bridge
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating intermediate `LedgerEntryChange` materialization on the enforcing apply path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The production enforcing `invoke_host_function` path should produce exactly the data stellar-core apply needs: encoded modified ledger entries, encoded contract events, resource counters, and the final rent fee. It should not have to allocate a `Vec<LedgerEntryChange>` containing per-footprint intermediate records and then immediately re-scan that vector in the Rust bridge to derive `rent_changes` and `modified_ledger_entries`.

## Mechanism

`e2e_invoke::invoke_host_function` currently calls `get_ledger_changes` at `e2e_invoke.rs:569-579`, which allocates and fills one `LedgerEntryChange` per storage-map item (`e2e_invoke.rs:224-356`). The Rust bridge then scans the vector again: `extract_rent_changes` at `e2e_invoke.rs:393-430` builds a second rent-change vector, and `extract_ledger_effects` at `src/rust/src/soroban_proto_any.rs:261-302` consumes the original changes to build `Vec<RustBuf>` for C++. An apply-specific result builder can fuse these passes: while iterating the storage map, compute the rent-fee inputs, push modified `LedgerEntry`/TTL buffers directly into the bridge output, and drop no-op/read-only intermediate records before they ever allocate `LedgerEntryChange` fields.

## Trigger

Run the current `soroswap` apply-load benchmark (`TX=2000,T=8`) with the accepted sparse no-meta baseline. Every successful Soroban invocation still performs the `get_ledger_changes` pass and then bridge-side extraction; the workload has 8,705 Soroban invocations in the current trace, plus high write volume from native pair reserve updates, SAC transfers, balance TTL extensions, and event output.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:49-67` — `InvokeHostFunctionResult` currently exposes `ledger_changes: Vec<LedgerEntryChange>`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` materializes an intermediate change object for every storage-map entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:393-430` — `extract_rent_changes` re-scans the intermediate vector to compute rent-fee inputs.
- `src/rust/src/soroban_proto_any.rs:478-506` — bridge success path calls `extract_rent_changes`, computes rent fee, then calls `extract_ledger_effects`.
- `src/rust/src/soroban_proto_any.rs:261-302` — `extract_ledger_effects` consumes `LedgerEntryChange` only to produce the final modified-entry buffers.

## Evidence

The current soroswap trace shows the enclosing apply-contained host invocation output path remains large after sparse no-meta ledger changes: `invoke_host_function` (`e2e_invoke.rs:639`) has 976,933,609 ns self-time / 8,705 calls, `write xdr` (`host/metered_xdr.rs:72`) has 168,176,135 ns self-time / 252,173 calls, and C++ `recordStorageChanges` (`transactions/InvokeHostFunctionOpFrame.cpp:643`) still accounts for 69,896,221 ns self-time / 8,705 calls. Source inspection confirms that the production success path still allocates `LedgerEntryChange` records with `encoded_key`, optional `encoded_new_value`, and optional TTL metadata, then allocates separate rent/effect vectors from the same information before returning to C++.

The accepted sparse no-meta optimization already proved this area moves soroswap apply time by removing unconsumed ledger-change output. This hypothesis targets the remaining intermediate representation rather than the previously removed no-op read-only output: it keeps all mandatory XDR writes for final modified entries and TTL entries, but removes intermediate `LedgerEntryChange` allocations, encoded-key retention when a cached TTL hash is available, and the second and third vector scans in the bridge.

## Anti-Evidence

Much of `get_ledger_changes` is mandatory: changed ledger entries and TTL entries still need XDR buffers, rent fee still needs old/new sizes and live-until deltas, and protocol-visible `metered_write_xdr` charges must remain unchanged. The public recording/simulation API also relies on `LedgerEntryChange`, so the optimization should be an enforcing-apply-only result type rather than a blanket API deletion. If the remaining intermediate-allocation and re-scan portion is a small fraction of the 976 ms `invoke_host_function` wrapper self-time, this could fall below the 3% Medium threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - adjacent to prior `get_ledger_changes` failures, especially `032-skip-per-invocation-encoded-key-xdr-in-get-ledger-changes.md` and the summary entry for `004.md + 001-cache-entry-size-in-storage-map.md + 002-identity-skip-unchanged-readonly-entries.md`, but not a duplicate of the exact streaming-output shape.
**Failed At**: reviewer

### Trace Summary

The enforcing apply path calls C++ `InvokeHostFunctionOpFrame::invokeHostFunction`, crosses the CXX bridge into `soroban_proto_any::invoke_host_function_or_maybe_panic`, then runs `e2e_invoke::invoke_host_function`. On success, `e2e_invoke` builds `Vec<LedgerEntryChange>` from the final storage map; the bridge then scans it once for rent inputs and once for final modified ledger-entry buffers before C++ applies those buffers in `recordStorageChanges`. The intermediate vector is real, but the traced code shows that the expensive parts around it are mandatory serialization/metering and C++ write application, while the safely removable part is only unmetered struct materialization and small linear scans. That residual does not support a Medium 3% apply-time projection under the objective threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:49-67` - enforcing `InvokeHostFunctionResult` carries `ledger_changes: Vec<LedgerEntryChange>` plus encoded result/events.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:103-127` - `LedgerEntryChange` stores `encoded_key`, rent sizes, optional encoded new value, and optional TTL metadata.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` - `get_ledger_changes` allocates a vector, writes the key XDR, computes TTL/rent data, encodes every extant read-write entry value, and pushes one change per storage-map item.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:393-430` - `extract_rent_changes` is a simple filter-map over the intermediate changes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-593` - production invocation constructs storage, runs the host function, then calls `get_ledger_changes` and event encoding only on success.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-100` - `metered_write_xdr` performs the actual serialization and protocol-visible `ValSer` charges; a streaming implementation cannot drop or reduce those charges without changing observable budget values.
- `src/rust/src/soroban_proto_any.rs:261-302` - `extract_ledger_effects` consumes the intermediate vector, forwards encoded read-write entries, and creates TTL ledger-entry buffers for live-until increases.
- `src/rust/src/soroban_proto_any.rs:458-488` - the bridge reads budget counters after `e2e_invoke`, then calls `extract_rent_changes`, computes rent fee, and extracts final ledger effects.
- `src/rust/src/bridge.rs:34-54` - the CXX ABI returns only final result, events, modified ledger entries, and rent fee; it does not expose `LedgerEntryChange` directly.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` - C++ applies `modified_ledger_entries` and deletes read-write footprint entries not returned, so all extant read-write entries must still be returned even when unchanged.

### Why It Failed

The proposed streaming shape can remove an intermediate Rust vector and two small linear scans, but it cannot remove the dominant mandatory work on this path:

1. `metered_write_xdr` calls for keys and new ledger entries must preserve exact `ValSer` budget accounting. Prior failures and the subsystem summary meta-pattern explicitly show that reducing these charge counts changes observable `cpu_insns`/`mem_bytes`.
2. Every extant read-write entry still has to be returned to C++ because `recordStorageChanges` treats missing read-write keys as deletions. Dropping no-op read-write outputs would change ledger semantics unless the C++ protocol were redesigned around explicit deletes.
3. TTL-entry buffers and rent-change inputs still need to be produced. Fusing their production changes allocation shape, not the required data dependencies.
4. The cited 976 ms `invoke_host_function` wrapper and 168 ms `write xdr` totals are broad upper bounds. The safely removable subset is only unmetered `LedgerEntryChange` struct/vector materialization and iteration over already-produced data, which is a small fraction of those zones and lacks evidence for a reproducible 3-10% apply-time reduction.

Because this objective accepts only Medium or High findings, the remaining budget-preserving streaming cleanup is below the severity threshold even though the intermediate representation is real.

### Lesson Learned

For Soroban bridge-output optimizations, separate "can avoid an internal container" from "can avoid serialization, metering, or final C++ effects." In this path, the final ledger-entry buffers, TTL effects, rent inputs, and exact metered XDR charges dominate correctness; streaming can improve code shape but needs focused evidence that the unmetered container/scanning residual alone clears the Medium floor before promotion.
