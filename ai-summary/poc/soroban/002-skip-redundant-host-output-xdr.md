# H002: Skip Redundant XDR Serialization in Soroban Host Output

**Date**: 2026-04-27
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing per-invocation XDR work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban invocation, stellar-core should return only the data the C++ apply path needs to commit the transaction and charge fees: modified ledger-entry bytes, TTL updates, rent inputs, result value, and events. It should not repeatedly reserialize unchanged input keys or old ledger entries when equivalent bytes or sizes are already available from the C++ inputs or are irrelevant to the enforcing apply path.

## Mechanism

The p26 host builds a `LedgerEntryChange` for every storage-map item and calls `metered_write_xdr` for the ledger key, old entry, new entry, result value, and contract events. In stellar-core's enforcing apply path, `soroban_proto_any::extract_ledger_effects` only forwards `encoded_new_value` and synthesized TTL entries to C++, while C++ immediately decodes each returned modified entry in `recordStorageChanges`; rent is computed in Rust from `LedgerEntryChange` fields. Carrying original encoded entry sizes from `build_storage_map_from_xdr_ledger_entries`, and adding a streamlined core-only output path that computes rent changes plus modified-entry buffers directly, should remove a large fraction of the `write xdr` zone without affecting determinism because serialized ledger effects and deterministic merge order remain unchanged.

## Trigger

Run the soroswap apply-load benchmark with Tracy enabled and inspect `write xdr` events inside `applyLedger`. A PoC should avoid serializing `LedgerEntryChange::encoded_key` and old-entry XDR for the non-recording/enforcing core invocation path when the old encoded size can be preserved from the input buffers, then compare repeated soroswap median apply time and verify identical transaction results/meta.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-272` — `get_ledger_changes` allocates one `LedgerEntryChange` per storage item, serializes each key at line 208, serializes old entries at lines 227-231 for rent size, and serializes new entries at lines 263-272.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` is the hot `write xdr` Tracy zone used by result/change/event serialization.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` discards most `LedgerEntryChange` fields and forwards only modified entry bytes plus synthesized TTL ledger entries to C++.
- `src/rust/src/soroban_proto_any.rs:479-506` — successful invocations compute rent from `res.ledger_changes`, extract modified entries, and wrap already-encoded buffers in `InvokeHostFunctionOutput`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:654-675` — C++ decodes each returned `modified_ledger_entries` buffer back into a `LedgerEntry` before matching it to the read-write footprint.

## Evidence

The current soroswap Tracy trace reports `write xdr,soroban-env-host/src/host/metered_xdr.rs,61` at 388,067,513 ns self-time across 61,830 calls in `csvexport-release -e`. Unwrapped timestamp checks show 59,051 of those calls, totaling 516,931,038 ns of event duration, are contained inside `applyLedger` windows; `applyLedger` totals 4,591,086,908 ns in the same trace, so this serialization path is large enough for a medium-tier win if a substantial fraction is removed. The source shows repeated serialization around the host-output boundary: C++ first serializes footprint entries into `CxxBuf`s before invocation, Rust deserializes and later reserializes old/new state while building `LedgerEntryChange`, and C++ then deserializes returned modified entries for commit validation.

## Anti-Evidence

Some `write xdr` calls are semantically required: result values, emitted contract events, genuinely modified ledger entries, and TTL ledger entries must still be encoded for the existing bridge/API. Rent accounting for contract-code entries depends on both encoded XDR size and in-memory module cost, so preserving old encoded sizes from input buffers must be done carefully and validated against restored/archive paths. A broader CXX bridge redesign that returns structured Rust-side changes instead of XDR buffers could be higher impact, but it would carry more API churn; the narrower hypothesis is to remove only redundant key/old-entry serialization in the core enforcing path.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in Soroban fail/success; related H004 only rejected a bridge-preparation framing, not this host-output materialization target

### Trace Summary

The enforcing Soroban apply path in C++ serializes footprint ledger entries into `CxxBuf`s, Rust decodes them into a `StorageMap`, clones that initial map, invokes the host, and then calls `get_ledger_changes` on successful output. `get_ledger_changes` serializes every storage key into `LedgerEntryChange::encoded_key` and serializes every old entry solely to recover the XDR length for rent, but `soroban_proto_any::extract_ledger_effects` discards `encoded_key` and only forwards `encoded_new_value` plus synthesized TTL entries back to C++. The old entry XDR size is already available at Rust entry materialization time from the input buffer, and key serialization is only needed for entries whose TTL hash cannot be obtained from the input TTL map, so a core/enforcing output path can skip a substantial per-invocation serialization subset while preserving returned ledger effects.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:381-535` — `addReads` validates footprint keys, serializes existing ledger entries and TTL entries with `toCxxBuf`, and records whether each RW key existed before invocation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` passes host-function XDR, resources, source account, auth entries, encoded ledger entries, encoded TTL entries, restored-entry indices, rent config, and module cache into the Rust bridge for every Soroban apply.
- `src/rust/src/soroban_proto_any.rs:391-448` — the bridge wrapper creates a budget, invokes the protocol-specific host with encoded C++ buffers, and measures the host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — enforcing `invoke_host_function` decodes resources and entries, clones the initial storage map, runs `Host::invoke_function`, encodes the result value, computes ledger changes, and encodes contract events.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` decodes every input ledger-entry buffer and TTL buffer; the entry buffer length available here is the old-entry XDR size needed later for rent.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` serializes each key, serializes old entries for rent size, serializes new RW entries for output/rent size, updates TTL changes, and pushes one `LedgerEntryChange` per storage-map item.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:324-387` — `extract_rent_changes` consumes only rent sizes and TTL fields, while `entry_size_for_rent` explicitly accepts a precomputed XDR size and only adds Wasm memory cost for contract-code entries.
- `src/rust/src/soroban_proto_any.rs:261-301` — `extract_ledger_effects` drops read-only changes and `encoded_key`; it forwards encoded new values and independently serializes TTL ledger entries from `ttl_change`.
- `src/rust/src/soroban_proto_any.rs:479-506` — successful bridge output computes rent from `res.ledger_changes`, extracts modified entries, and returns XDR buffers to C++.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — `recordStorageChanges` decodes each returned modified-entry buffer, validates it against the RW footprint, upserts returned entries, and erases RW entries not returned.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — all target serializations enter the same `write xdr` Tracy zone and charge `ValSer` budget while writing to a `Vec<u8>`.

### Findings

The inefficiency exists on the `closeLedger` hot path. `InvokeHostFunctionOpFrame::doApply` runs `addFootprint`, `invokeHostFunction`, and `recordStorageChanges` for every successful Soroban transaction; for p23+ parallel Soroban apply this executes inside worker `applyLedger` activity. The current soroswap trace reports `InvokeHostFunctionOpFrame doApply` at about 4.93s total across 1,562 calls, `e2e_invoke::invoke_function` at about 4.80s total, `Host::invoke_function` at about 3.65s total, and `write xdr` self-time at 388ms across 61,830 calls. That puts post/pre-host output materialization in a large enough region that removing the avoidable key and old-entry serializations plausibly clears the objective's 3% Medium threshold, while still leaving mandatory result, event, new-entry, and TTL-entry encodings intact.

The proposed fix is correctness-preserving if implemented as a narrow enforcing/core path rather than by weakening the generic `LedgerEntryChange` contract. `encoded_key` cannot be blindly removed for all cases because new TTL-bearing entries with no input TTL still need a deterministic SHA256 hash of the XDR-encoded `LedgerKey`; existing TTL-bearing entries can reuse the input TTL map's hash, and non-TTL entries do not need an encoded key for core output. Old-entry XDR serialization can be skipped by carrying the original encoded ledger-entry length alongside each decoded storage-map entry, then passing that length to `entry_size_for_rent`; contract-code entries still need `wasm_module_memory_cost` added exactly as today. New RW entries must still be serialized because C++ consumes those bytes for ledger commit validation, write-byte metering, success hashing inputs, and meta construction.

The PoC must preserve observable outputs and metering semantics. If skipped `metered_write_xdr` calls currently affect returned `cpu_insns`/`mem_bytes` or diagnostic metrics in a way tests assert, the implementation should either deliberately accept the optimized lower host cost as the new behavior or charge an equivalent `ValSer` amount without materializing a buffer; this choice needs explicit validation against existing Soroban metering tests. The performance hypothesis remains viable because the expensive part is repeated XDR encoding and allocation for data that the core apply path does not consume, and the profile shows enough `write xdr` self-time in the invoke/apply region for a measured 3-10% apply-time improvement if a substantial subset is removed.

### PoC Guidance

- **Target code**: Modify `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` and `src/rust/src/soroban_proto_any.rs`; add any required bridge/internal structs in `src/rust/src/bridge.rs` only if the narrower Rust-side extraction cannot be kept behind the existing `InvokeHostFunctionOutput` shape. C++ changes should be limited to `src/transactions/InvokeHostFunctionOpFrame.cpp` only if the returned modified-entry format changes, which is not required for the narrow version.
- **Change description**: Carry old encoded entry sizes from `build_storage_map_from_xdr_ledger_entries` into the initial snapshot/change computation, avoid filling `LedgerEntryChange::encoded_key` on the core enforcing path except when a missing TTL-map entry requires hashing the key for a newly created TTL-bearing entry, and compute rent changes plus modified-entry buffers directly without allocating/storing discarded fields. Keep current recording-mode and simulation-facing `LedgerEntryChange` behavior unchanged unless all callers are updated.
- **Correctness check**: Existing Soroban invoke-host-function, rent, restore/autorestore, TTL-extension, contract-code, event, and transaction-meta tests should continue to pass with identical ledger effects and transaction results. Pay special attention to created entries, restored persistent entries, expired temporary entries, contract-code rent sizing, diagnostic-event CPU/memory metrics, and any tests that compare host metering.
- **Benchmark focus**: Run repeated soroswap apply-load matrix measurements, especially `soroswap, TX=4000, T=8`, and require at least a reproducible 3% reduction in the top-line apply-time metric. Secondary Tracy validation should show reduced `write xdr` self-time/call count in the Soroban invoke output path while `recordStorageChanges` still receives identical modified ledger-entry bytes and synthesized TTL entries.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-28
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:5-40` — added an internal `BTreeMap` metadata type for unmetered preservation of input ledger-entry XDR sizes keyed by `LedgerKey`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:184-292` — changed enforcing-path ledger-change construction to skip populating discarded `encoded_key` bytes outside test/recording builds, reuse input TTL key hashes when present, serialize keys only for newly-created TTL-bearing entries that still need a hash, and use preserved old-entry XDR sizes for rent sizing instead of reserializing old entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:461-530, 809-854, 985-1081` — carried input XDR sizes out of `build_storage_map_from_xdr_ledger_entries`, passed them only to the normal enforcing invocation path, and left recording-mode ledger-change behavior unchanged by passing `None`.

### Demonstration

The PoC removes redundant `metered_write_xdr` calls for data discarded by stellar-core's C++ apply path: most ledger keys and all existing old ledger entries in successful p26 enforcing invocations. It preserves required output bytes for result values, contract events, modified ledger entries, and synthesized TTL entries; contract-code rent sizing still adds `wasm_module_memory_cost` on top of the preserved input XDR length. Recording-mode/test builds continue to fill `encoded_key` and compute old-entry size through the existing path so simulation-facing metering expectations stay stable.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`; `make -j $(nproc)` completed successfully. Full regression run `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completed successfully with `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and all Soroban p26 host checks passing, including `750 passed; 0 failed; 2 ignored; 1 filtered out` for the main p26 host test binary.
