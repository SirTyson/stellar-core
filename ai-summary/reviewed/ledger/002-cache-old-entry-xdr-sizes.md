# H002: Cache decoded input entry XDR sizes for ledger-change rent accounting

**Date**: 2026-04-29
**Subsystem**: ledger / Soroban host invocation output
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing redundant per-footprint XDR serialization in successful host invocations
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each successful Soroban invocation, the Rust host must return the same ledger changes, rent size fields, TTL changes, events, and result XDR as today. Computing `old_entry_size_bytes_for_rent` should not require reserializing every old ledger entry when the embedder already supplied the exact encoded `LedgerEntry` bytes used to build the initial storage map.

## Mechanism

`build_storage_map_from_xdr_ledger_entries` decodes every input `LedgerEntry` from an encoded buffer, inserts only `(Rc<LedgerEntry>, live_until)` into `StorageMap`, and discards the original encoded length. Later, `get_ledger_changes` asks the initial snapshot for the old entry and serializes that same old entry back to XDR only to compute `old_entry_size_bytes_for_rent`. Carrying the input encoded length alongside the initial storage entry, or providing a parallel snapshot map of initial rent sizes, would avoid this redundant old-entry serialization while leaving the emitted `encoded_new_value` and `encoded_key` bytes unchanged.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with successful invoke-host-function transactions that touch multiple footprint entries. Each transaction decodes its input ledger entries into a host storage map, executes, then serializes old entries again during ledger-change construction even when those entries were supplied as XDR bytes moments earlier.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` — `invoke_host_function` decodes resources, builds the storage map from encoded ledger entries, clones the initial map, and later uses it as the snapshot.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes `entry_buf` but stores only the decoded entry and TTL, not the original XDR size.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes `old_entry` at lines 227-231 solely to compute old rent size, then serializes read-write new entries separately for output at lines 264-272.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `StorageMapSnapshotSource` currently exposes only `(entry, live_until)`, so it cannot answer "initial encoded size" without reserialization.

## Evidence

In the current soroswap Tracy trace, the `write xdr` zone is fully in-scope: `132,898` of `132,907` events overlap `applyLedger`, accounting for `1,071,500,405 ns` of overlapped time. `invoke_host_function` and `Host::invoke_function` are also descendants of `applyLedger`; the trace shows `invoke_host_function` total time `9,871,843,503 ns` across 3,335 calls and `write xdr` self-time `764,102,894 ns`. The code path demonstrates at least one avoidable serialization per old entry in the footprint: unlike `encoded_new_value`, the old entry bytes are not returned to C++ and are only used for `entry_size_for_rent`.

## Anti-Evidence

Not all `write xdr` time is removable: keys, result `ScVal`, events, and new read-write values still need encoded output, and contract-code rent size uses `entry_size_for_rent` semantics rather than raw XDR length. A safe PoC must preserve metering semantics or consciously account for any budget-charge differences, because `metered_write_xdr` currently charges `ValSer` while it serializes.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/ledger`, `success/ledger`, or cross-subsystem verdict directories

### Trace Summary

The successful C++ apply path materializes each footprint entry as XDR with `toCxxBuf`, passes those buffers to Rust, Rust decodes them into a `StorageMap`, clones that map as the initial snapshot, and then `get_ledger_changes` reserializes every existing old entry only to compute `old_entry_size_bytes_for_rent`. This redundant serialization runs after `host.invoke_function` succeeds and before rent extraction and modified-entry extraction, so it is inside `invoke_host_function` and the measured `applyLedger` window. The size cache is semantically available at ingress, and for non-code entries the cached XDR length is exactly the rent size input; for contract code it is still the correct XDR-size component passed to `entry_size_for_rent`.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` walks read-only and read-write footprint keys, serializes each existing ledger entry with `toCxxBuf`, records `entrySize`, and pushes the encoded `LedgerEntry`/TTL buffers into `mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:575-584` — `invokeHostFunction` passes `mLedgerEntryCxxBufs` and `mTtlEntryCxxBufs` through the Rust bridge on every successful Soroban operation attempt.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:430-487` — the bridge dispatches to the protocol-specific host, then computes rent changes and modified ledger effects from the returned `LedgerEntryChange` records.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` — enforcing-mode `invoke_host_function` decodes resources, builds the storage map from the encoded input entries, and clones the initial map for later snapshot comparisons.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` has `entry_buf.as_ref().len()` available immediately before decoding each `LedgerEntry`, but returns only `StorageMap` and `TtlEntryMap`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes each `old_entry` into a temporary `Vec` solely to pass `buf.len()` into `entry_size_for_rent`; the buffer is not emitted or reused.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:324-386` — `extract_rent_changes` consumes only the old/new rent-size fields and TTL deltas, while `entry_size_for_rent` explicitly expects a caller-provided XDR size and only adds Wasm memory cost for contract-code entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:86-90` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `SnapshotSource` currently returns only `(entry, live_until)`, so `StorageMapSnapshotSource` cannot provide the cached ingress size without an API or side-map extension.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` and `src/rust/soroban/p26/soroban-env-host/src/budget.rs:71-79,369-372,725-728` — the redundant serialization also charges `ValSer`; a PoC must deliberately handle the resulting budget-counter/resource-limit semantics.

### Findings

The inefficiency exists and is in a hot path. For every successful invoke-host-function transaction, C++ has already produced canonical XDR buffers for the footprint entries before Rust host execution. Rust decodes those buffers, discards their lengths, and later serializes the same old entries again even when the old entry is read-only, unchanged, classic/non-TTL, or about to be zeroed as an auto-restored old size. In the soroswap swap generator, a typical swap footprint contains five read-only entries and five read-write entries, so the waste is repeated many times per transaction; contract-code read-only entries can make the avoidable old-entry serialization materially larger than a scalar-key micro-optimization.

The proposed size cache is correct for rent-size computation if it carries the encoded `LedgerEntry` length, not merely a post-`entry_size_for_rent` value. `entry_size_for_rent` returns the raw XDR size for accounts, trustlines, contract data, and other non-code entries; for contract code it adds Wasm memory cost to that same raw XDR size. Therefore a cached ingress XDR length can replace `buf.len()` without changing `old_entry_size_bytes_for_rent`, while leaving key encoding, new read-write value encoding, result encoding, event encoding, and output ledger effects unchanged.

The main correctness constraint is metering. The current old-entry `metered_write_xdr` calls contribute `ValSer` CPU/memory charges and can affect `out.cpu_insns`, `out.mem_bytes`, and resource-limit failure behavior. If the intended optimization removes serialization entirely, the PoC must either be protocol-semantics-aware about the lower metered cost or add an explicit replacement charge policy that is accepted as preserving the intended metering semantics. A single charge by cached total length would preserve total `ValSer` input but not necessarily the historical per-`WriteXdr` iteration count because `ValSer` has nonzero constant CPU and memory terms, so this must be measured and reviewed rather than hidden.

The projected impact is plausibly Medium. The trace cited by the hypothesis puts in-scope `write xdr` work around one second total / 764 ms self-time across 3,335 invocations, and this target removes an entire old-entry write per existing footprint entry rather than only preallocating buffers. Since keys, events, results, and new values remain mandatory, the PoC still must prove a reproducible 3%+ apply-time reduction, but the removable share is large enough to pass review.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs`, especially `build_storage_map_from_xdr_ledger_entries`, `StorageMapSnapshotSource`, and `get_ledger_changes`; mirror the change across supported protocol host copies if the repository's protocol-generation workflow requires manual or generated synchronization.
- **Change description**: carry each decoded input ledger entry's original XDR length alongside the initial storage snapshot, expose it to `get_ledger_changes`, and compute old rent size from the cached length plus `entry_size_for_rent` instead of serializing `old_entry` to a temporary buffer. Preserve the existing serialization of `encoded_key`, read-write `encoded_new_value`, result values, events, and constructed TTL entries.
- **Correctness check**: verify identical ledger changes, modified ledger entries, TTL changes, rent fees, events, and result XDR for successful invoke-host-function tests. Explicitly document and test the intended budget behavior: either counters/resource-limit outcomes remain equivalent by an accepted replacement charge mechanism, or the metering delta is deliberate and protocol-safe for the targeted protocol version.
- **Benchmark focus**: run the soroswap apply-load matrix repeatedly and compare top-line `applyLedger` time plus Tracy `write xdr` self/total time inside `invoke_host_function`. The expected improvement should come from fewer old-entry `write xdr` events and lower per-success invocation time; the finding should only proceed if the median apply-time reduction is at least 3%.
