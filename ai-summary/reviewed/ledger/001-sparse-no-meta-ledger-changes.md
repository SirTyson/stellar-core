# H001: Sparse no-meta Soroban ledger-change extraction

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban host apply path
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding dense per-footprint ledger-change construction when transaction meta is disabled
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the apply-load soroswap benchmark, which disables transaction metadata, the host should compute the same rent fee and return the same modified ledger entries to Core without allocating and filling a `LedgerEntryChange` for every read-only, read-write, changed, and unchanged footprint entry. Unchanged read-only entries should not require an encoded key buffer, old-entry size field, access-type lookup, and `LedgerEntryChange` push unless they actually contribute a TTL/rent change.

## Mechanism

`get_ledger_changes` currently builds a dense `Vec<LedgerEntryChange>` for every item in `Storage::map`, serializing every key into `entry_change.encoded_key` before knowing whether the entry will be filtered out later. In the no-meta apply-load path, `soroban_proto_any::invoke_host_function_or_maybe_panic` immediately consumes that dense vector only through `extract_rent_changes` and `extract_ledger_effects`, both of which discard most unchanged read-only entries. A no-meta sparse extractor can stream only rent-relevant changes and modified ledger-entry buffers, preserving deterministic output while removing allocation, key-XDR, and per-entry postprocessing from successful soroswap invocations.

## Trigger

Run the current soroswap apply-load workload with `DISABLE_TX_META_FOR_TESTING = true` and successful `InvokeHostFunction` swaps. Every invocation enters `e2e_invoke::invoke_function`, calls `get_ledger_changes`, then runs `extract_rent_changes` and `extract_ledger_effects`; read-only contract instances/code and unchanged footprint entries are represented in the dense vector even though no ledger-close meta will consume them.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:get_ledger_changes:224-356` — builds one `LedgerEntryChange` per storage-map entry and serializes every key.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:extract_rent_changes:392-430` — filters dense changes down to rent-relevant TTL/size deltas.
- `src/rust/src/soroban_proto_any.rs:extract_ledger_effects:261-302` — filters dense changes again to modified ledger-entry XDR buffers.
- `src/rust/src/soroban_proto_any.rs:invoke_host_function_or_maybe_panic:478-506` — always constructs the dense vector before rent/effects extraction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — C++ consumes only `modified_ledger_entries`, not the dense no-op entries, when metadata is disabled.

## Evidence

This path is a verified `applyLedger` descendant: `InvokeHostFunctionOpFrame doParallelApply` -> `InvokeHostFunctionApplyHelper::invokeHostFunction` -> Rust `invoke_host_function_or_maybe_panic` -> `e2e_invoke::invoke_function`. The accepted `002-cache-old-entry-xdr-sizes` success shows this exact post-invocation ledger-change construction area was large enough to produce a 3.46% soroswap median improvement by removing one redundant old-entry serialization. The current source still serializes each key and allocates a dense change object before later filters discard unchanged/read-only entries; soroswap invokes this path for every swap and carries shared read-only SAC/router/pool entries in the footprint.

## Anti-Evidence

The sparse path must preserve budget charging and rent semantics exactly; if the current dense `encoded_key` serialization is relied on for metered `ValSer` charges, the optimization must either retain equivalent charging or be protocol-gated with intentional budget-number updates. Some read-only entries may still produce TTL rent changes, so the sparse extractor cannot simply skip read-only keys wholesale; it must emit TTL changes when `new_live_until_ledger > old_live_until_ledger`.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The successful apply path is `LedgerManagerImpl::applyTransactions` -> `applyParallelPhase` -> `applyThread` -> `InvokeHostFunctionApplyHelper::doApply` -> Rust `invoke_host_function_or_maybe_panic`. C++ disables transaction metadata in the apply-load benchmark, but the Rust bridge still calls `e2e_invoke::invoke_function`, which returns a dense `Vec<LedgerEntryChange>` for every enforcing storage-map key. That dense vector is immediately reduced to `rent_changes` and `modified_ledger_entries`; `encoded_key` is not consumed by either extractor after `get_ledger_changes` has already derived any needed TTL key hash. The inefficiency is therefore real, hot, and adjacent but not duplicate to the accepted old-entry-size caching optimization.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2835-2847` — `enableTxMeta` is false for no-ledger-close-meta apply-load runs when `DISABLE_TX_META_FOR_TESTING` is set, so C++ metadata builders are mostly disabled.
- `src/ledger/LedgerManagerImpl.cpp:2967-3032` and `src/ledger/LedgerManagerImpl.cpp:3093-3149` — parallel Soroban stages create `TxBundle` effects with the metadata flag, apply workers, then process result/meta; this is inside `closeLedger`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-638` — C++ calls `rust_bridge::invoke_host_function` and receives only result bytes, events, modified ledger-entry buffers, resource counters, and rent fee.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — storage recording iterates `out.modified_ledger_entries`; it never sees or needs the dense Rust-side `LedgerEntryChange` vector.
- `src/rust/src/bridge.rs:30-55` — the CXX bridge output type exposes `modified_ledger_entries` and `rent_fee`, not dense ledger changes.
- `src/rust/src/soroban_proto_any.rs:478-506` — successful host results call `extract_rent_changes(&res.ledger_changes)` and `extract_ledger_effects(res.ledger_changes)` immediately before returning bridge output.
- `src/rust/src/soroban_proto_any.rs:261-302` — `extract_ledger_effects` uses only `read_only`, `encoded_new_value`, and `ttl_change`; it never uses `encoded_key`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` reserves `storage.map.len()`, serializes every key into `entry_change.encoded_key`, fills old/new rent fields, looks up access type, and pushes a `LedgerEntryChange` even for unchanged read-only entries later discarded.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1039-1151` — input decoding already records initial XDR size and optional TTL metadata, including the TTL key hash needed to avoid key hashing for existing Soroban entries.

### Findings

The dense-construction inefficiency exists. In enforcing-mode apply, `build_storage_map_from_xdr_ledger_entries` prepopulates `Storage::map` with all footprint keys, including absent entries, and `get_ledger_changes` then emits a `LedgerEntryChange` for each map item. The first per-entry action is `metered_write_xdr(budget, key.as_ref(), &mut entry_change.encoded_key)`, even when the key belongs to an unchanged read-only entry that will not produce a modified ledger entry or rent delta. For existing Soroban entries, the current metadata path can already provide the TTL hash from the decoded `TtlEntry`, so many of those key encodings are only temporary scaffolding for the dense representation.

The optimization is in the soroswap apply hot path. Every successful invoke-host-function transaction calls this Rust path before C++ applies storage changes and consumes refundable rent. The accepted `002-cache-old-entry-xdr-sizes` result proved this exact post-invocation ledger-change loop can move soroswap median apply time by Medium-tier amounts: removing old-entry serialization alone measured a 3.46% improvement. A sparse bridge-output extractor would remove additional metered key serialization, dense-vector allocation, and two filtering passes on the same per-transaction path, so the Medium projection is credible enough for PoC.

The proposed fix is correct only if it preserves current bridge semantics exactly. Read-write entries with an encoded value must still be returned even if their value is unchanged, because `recordStorageChanges` treats absent read-write keys as deletions. Read-only entries must still produce TTL `LedgerEntry` buffers and rent changes when `new_live_until_ledger > old_live_until_ledger`. Created entries, restored entries, and entries lacking cached TTL metadata still need correct TTL key-hash derivation, which may require key XDR only for those rent/effect-producing cases. Output ordering should match the current `extract_ledger_effects` order: for each storage-map entry, emit the non-read-only new value first, then any TTL entry.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` and `src/rust/src/soroban_proto_any.rs`.
- **Change description**: Add an enforcing/apply-output path that walks `Storage::map` once and directly builds `Vec<LedgerEntryRentChange>` plus `Vec<RustBuf>`/`Vec<Vec<u8>>` modified ledger effects, without materializing `Vec<LedgerEntryChange>` for the bridge path. Keep the existing dense `ledger_changes` path for recording/simulation/tests that require it, or refactor shared per-entry logic so dense and sparse outputs remain equivalent.
- **Correctness check**: Preserve rent fee, `modified_ledger_entries`, resource counters, result/event bytes, deletion semantics, restored-key handling, and deterministic effect ordering. Any reduced metered `ValSer` work changes instruction/memory accounting, so either intentionally protocol-gate/update exact budget-number tests like `002-cache-old-entry-xdr-sizes`, or charge equivalent budget explicitly.
- **Benchmark focus**: Re-run the soroswap apply-load matrix with at least three non-Tracy runs and require a reproducible 3%+ median apply-time reduction. A diagnostic Tracy run should show reduced post-invocation `write xdr`/ledger-change construction work, especially from key serialization and dense change filtering, without increasing C++ `recordStorageChanges` or rent computation time.
