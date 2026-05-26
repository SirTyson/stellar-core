# H002: Protocol-Gated Dirty Effect Builder for Apply-Mode Ledger Changes

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Soroban Rust-C++ apply bridge
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding full storage-map ledger-change scans and intermediate `LedgerEntryChange` construction in apply mode
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

In next-protocol apply mode, the host should return the C++ apply path's required outputs by walking only positions that were actually written, deleted, restored, or had rent-relevant TTL/size changes. It should preserve deterministic output ordering by sorting dirty positions by the existing storage-map order, keep p26 metering unchanged, and gate any reduced no-op read-only serialization/metering behind the next protocol.

## Mechanism

`invoke_host_function` currently builds `init_storage_map`, constructs enforcing `Storage`, runs the host, and then calls `get_ledger_changes`, which iterates every entry in `storage.map` and creates a `LedgerEntryChange` object even for unchanged read-only entries before the bridge extracts rent changes and modified ledger effects. The accepted sparse no-meta direction already showed apply-mode output shape can differ from simulation/recording output, but the remaining source still has the structural full-map pass and intermediate change shape. A dirty-position log maintained by enforcing `Storage::put`, `Storage::del`, and TTL extension paths could feed an apply-only builder that emits modified-entry buffers and rent inputs directly, avoiding full-map iteration, read-only key serialization, initial-map lookup, and the two `extract_*` passes for entries that cannot affect C++ apply state.

## Trigger

Run the current soroswap apply-load benchmark. Each successful swap enters `applyLedger -> applyParallelPhase -> InvokeHostFunctionOpFrame::doParallelApply -> invoke_host_function`, mutates a small subset of its declared footprint, and then finishes through `get_ledger_changes` and `extract_ledger_effects`. The optimization triggers on successful enforcing-mode invocations with unchanged read-only footprint entries and a smaller dirty RW set than total storage-map size.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — apply invocation builds `storage_map`, clones `init_storage_map`, constructs enforcing `Storage`, and computes initial metadata.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` iterates the full storage map, serializes keys, looks up the initial value, computes rent metadata, and pushes intermediate `LedgerEntryChange` records.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:388-429` — `extract_rent_changes` re-walks `LedgerEntryChange` records.
- `src/rust/src/soroban_proto_any.rs:478-506` — bridge success path computes rent and modified ledger entries from the intermediate vector before returning to C++.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-490` — enforcing `put`/`del` paths are the natural place to mark dirty storage-map positions.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — C++ consumer of modified ledger entries; output ordering and validation semantics must remain deterministic.

## Evidence

The current soroswap Tracy trace was filtered to zones contained by `applyLedger`. The bridge/finish envelope is still material: `invoke_host_function_or_maybe_panic` contributes ~154.07ms aggregate/ledger, Rust `invoke_host_function` contributes ~152.68ms aggregate/ledger, `write xdr` contributes ~2.44ms aggregate/ledger, `read xdr with budget` contributes ~2.90ms aggregate/ledger, and `map lookup indexed` contributes ~8.79ms aggregate/ledger. Source inspection confirms `get_ledger_changes` still walks `storage.map` and pushes intermediate records before C++ sees the final modified-entry list.

This hypothesis is specifically the protocol-gated version of the dirty-output idea: p26 would retain exact metered read-only serialization, while next protocol can deliberately stop charging no-op read-only change extraction that has no effect on C++ apply state, rent, events, or success hash. The dirty builder targets a larger combined envelope than a local `extract_ledger_effects` cleanup because it removes the full storage-map scan, intermediate allocation, and redundant post-pass iteration together.

## Anti-Evidence

This is not viable as an ungated p26 cleanup: `metered_write_xdr` and storage-map access charges are protocol-visible, and skipping them can change budget-exceeded outcomes. It must also retain rent correctness for TTL-only changes and restored entries, and the dirty-position log must be deterministic and cheaper than scanning the small soroswap footprint. Prior direct-effect and dirty-entry ideas were rejected when they counted mandatory metered XDR as removable; this version needs narrow counters proving the combined full-map scan plus intermediate-shape overhead clears the current Medium floor after preserving or explicitly protocol-gating all metering changes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entries `002-track-dirty-ledger-changes.md` and `001-apply-direct-ledger-effects.md`
**Failed At**: reviewer

### Trace Summary

Successful Soroban apply reaches `InvokeHostFunctionOpFrame::doParallelApply`, builds the bridge inputs, calls Rust `invoke_host_function`, finishes host storage through `Host::try_finish`, then calls `get_ledger_changes` before the bridge runs `extract_rent_changes` and `extract_ledger_effects`. `get_ledger_changes` does still walk `storage.map`, meter key serialization, compute TTL/rent metadata, look up the initial entry, and push `LedgerEntryChange` records; C++ then only consumes the encoded modified entries in `recordStorageChanges`. This is the same dirty-ledger-change tracking idea already recorded in the fail summary, combined with the already-failed direct ledger-effect output fusion.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:76` — prior failed `002-track-dirty-ledger-changes.md` covers tracking dirty and rent-relevant enforcing-storage slots to skip unchanged read-only entries during `get_ledger_changes`; the summary notes that read-only XDR/accounting is protocol-visible and C++ already does not see read-only entries after `extract_ledger_effects`.
- `ai-summary/fail/transaction-ledger/summary.md:200` — prior failed `001-apply-direct-ledger-effects.md` covers fusing `get_ledger_changes` Rust-to-C++ apply bridge output directly without intermediate `LedgerEntryChange` construction; the remaining removable shape cleanup is below the Medium threshold after mandatory accounting is preserved.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-523` — host invocation decodes resources, builds the enforcing footprint/storage map, clones `init_storage_map`, constructs `Storage`, and aligns initial metadata by storage position.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:556-585` — on successful host execution, `Host::try_finish` returns storage/events and the apply path calls `get_ledger_changes`, then returns a `Vec<LedgerEntryChange>` plus encoded events.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` iterates every storage-map position, meters key serialization, computes TTL hash/rent fields, performs initial-entry lookup, writes new-entry XDR for read-write entries, handles restored entries, and appends an intermediate `LedgerEntryChange`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:393-429` — `extract_rent_changes` re-walks the intermediate records to build the rent-fee input while filtering no-op TTL/size changes.
- `src/rust/src/soroban_proto_any.rs:261-301,478-506` — the bridge first computes rent from `res.ledger_changes`, then consumes the same vector in `extract_ledger_effects` to emit encoded modified ledger entries and synthesized TTL entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-490,600-687,708-757` — writes/deletes and TTL extensions are the places a dirty-position log would need to hook, including TTL-only mutations from `extend_ttl`/`extend_ttl_v2`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766,982-1017,1358-1377` — parallel and sequential Soroban apply both invoke Rust, record returned storage changes, collect events, consume refundable resources, and finalize success; `recordStorageChanges` validates, meters, upserts, deletes uncovered RW Soroban entries, and enforces TTL pairing.

### Why It Failed

The hypothesis is not novel. The dirty-slot part is substantially equivalent to the prior `002-track-dirty-ledger-changes.md` failure, and the direct rent/effect output part is substantially equivalent to the prior `001-apply-direct-ledger-effects.md` failure. Adding a next-protocol gate addresses the old p26 budget-compatibility caveat, but it does not create a new Medium-severity apply optimization: a correct implementation still needs deterministic dirty ordering, TTL-only/restored-entry correctness, rent-size computation, new-entry serialization for writes, event/result serialization, and C++ resource/footprint validation. The C++ side already receives only modified/TTL entries after `extract_ledger_effects`, so unchanged read-only entries only affect the Rust finish/accounting path that was already investigated.

### Lesson Learned

Protocol gating can make budget-accounting changes permissible, but it does not make a previously investigated dirty ledger-change scan automatically viable. Future variants need fresh narrow measurements showing that the non-mandatory dirty/full-map scan and intermediate-shape work alone clears the objective's 3% Medium floor after excluding mandatory XDR, rent, TTL, event, restored-entry, and C++ validation work.
