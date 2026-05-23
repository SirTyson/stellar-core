# H002: Fused Ledger-Effect Extraction Skips No-Op Footprint Work

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding per-footprint key serialization, map lookups, and temporary `LedgerEntryChange` records that are discarded before crossing the C++ bridge
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

On the enforcing apply path, the Rust host should return exactly the same modified ledger entries, TTL ledger entries, rent changes, and contract events to stellar-core, but it should not fully materialize no-op `LedgerEntryChange` records for footprint entries whose data and TTL do not change and whose only role is to be filtered out by `extract_rent_changes` / `extract_ledger_effects`.

## Mechanism

`get_ledger_changes` currently iterates every entry in `storage.map`, serializes every key into `entry_change.encoded_key`, looks up the initial entry by position, computes rent metadata, and pushes a `LedgerEntryChange` even for no-op footprint entries. The bridge layer immediately filters this vector into rent changes and `modified_ledger_entries`; a fused enforcing-mode extractor can compute those two outputs directly, using cached initial TTL metadata for key hashes and emitting encoded `LedgerEntry` bytes only for entries that actually need to be upserted, while preserving the existing full `LedgerEntryChange` path for recording-mode tests/simulation.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current next-protocol soroswap workload. Each successful Soroban transaction calls `invoke_host_function`, then `get_ledger_changes`, then Rust-side `extract_rent_changes` and `extract_ledger_effects` before C++ `recordStorageChanges` re-parses only `modified_ledger_entries`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` builds a full `LedgerEntryChange` for every footprint/storage entry and serializes each `LedgerKey`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:490-580` — enforcing `invoke_host_function` calls `get_ledger_changes` even though the bridge only needs extracted effects.
- `src/rust/src/soroban_proto_any.rs:261-290,481-488` — bridge extraction discards read-only/no-op `LedgerEntryChange` records and forwards only encoded modified entries plus TTL entries.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-720` — C++ consumes `modified_ledger_entries`, reparses each emitted `LedgerEntry`, and never sees the intermediate no-op Rust records.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:72` — `write xdr` zone targeted by skipping key/new-entry serialization that does not contribute to outputs.

## Evidence

The current accepted soroswap trace shows `invoke_host_function` at `e2e_invoke.rs:488` with 828.3 ms self-time across 7,891 calls, and `write xdr` at `host/metered_xdr.rs:72` with 160.3 ms self-time / 150.5 ms apply-contained total. Source inspection shows `LedgerEntryChange.encoded_key` is populated for every storage-map entry, but in the normal enforcing bridge flow the full vector is immediately reduced to rent changes and `modified_ledger_entries`; read-only and no-op read-write records do not cross the FFI boundary except through their filtered TTL/rent effects.

## Anti-Evidence

The current comments say `InvokeHostFunctionResult.ledger_changes` intentionally contains every footprint item, and recording-mode/simulation rely on that shape. The optimization must therefore be an enforcing-only fused extraction path, must prove that the soroswap footprint has enough no-op or TTL-only entries to clear the Medium floor, and must not change rent-fee computation or the ordering of emitted modified entries and TTL entries.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL - duplicate of `ai-summary/fail/soroban-env/summary.md` entry `004.md + 001-cache-entry-size-in-storage-map.md + 002-identity-skip-unchanged-readonly-entries.md`
**Failed At**: reviewer

### Trace Summary

The enforcing invocation path in `e2e_invoke::invoke_host_function` consumes the host, calls `get_ledger_changes`, and returns a full `Vec<LedgerEntryChange>` only after a successful result is encoded. The bridge then immediately derives rent changes with `extract_rent_changes`, derives C++-visible storage writes with `extract_ledger_effects`, and discards read-only/no-op intermediate records before `InvokeHostFunctionOpFrame::recordStorageChanges` reparses only `modified_ledger_entries`. This is the same already-investigated optimization family as the failed no-op/read-only `get_ledger_changes` work: avoiding no-op ledger-change materialization and serialization changes p26's protocol-visible budget accounting unless all skipped `ValSer`/`MemCpy` charges and lookup/comparison charges are reproduced exactly.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:206-290` - `get_ledger_changes` serializes each `LedgerKey`, looks up TTL and initial storage state, serializes old/new entries for rent sizing, marks read-only entries, and pushes a `LedgerEntryChange` for every storage-map entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:324-365` - `extract_rent_changes` filters out entries whose TTL and rent size did not increase, confirming that many fully materialized changes can be discarded after the fact.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:489-513` - successful enforcing invocation unconditionally calls `get_ledger_changes` before encoding contract events and returning `InvokeHostFunctionResult`.
- `src/rust/src/soroban_proto_any.rs:261-301` - `extract_ledger_effects` forwards only non-read-only encoded new values and synthesized TTL entries whose live-until ledger increases.
- `src/rust/src/soroban_proto_any.rs:478-488` - bridge success handling computes rent fee from `extract_rent_changes(&res.ledger_changes)` and then consumes the same vector in `extract_ledger_effects`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-720` - C++ only iterates `out.modified_ledger_entries`, reparses each emitted `LedgerEntry`, validates it against the read-write footprint, and applies it; it never observes the discarded Rust-side no-op `LedgerEntryChange` records.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` - `metered_write_xdr` wraps XDR serialization in the `write xdr` Tracy span and charges budget through `MeteredWrite`.

### Why It Failed

This exact optimization class has already been investigated and failed in `ai-summary/fail/soroban-env/summary.md`: batching/fusing `get_ledger_changes` work and skipping unchanged/read-only ledger-change serialization runs into p26's exact metering requirements. In the current code, the supposedly discardable work is not only physical work; `metered_write_xdr`, entry-size serialization, map lookups, comparisons, and metered clones feed `cpu_insns`/`mem_bytes` accounting that is returned through the bridge and covered by exact-budget tests. A fused extractor that omits no-op `LedgerEntryChange` records would need to reproduce the same protocol-visible charge sequence without performing the work, which is the same blocker recorded for the duplicate investigation.

### Lesson Learned

For p26 Soroban ledger-effect extraction, "not visible to C++ output" is not the same as "free to skip": intermediate serialization and lookup steps also define exact host budget consumption. Future variants should only be promoted if they are explicitly next-protocol-gated with a metering-model change, or if they can prove a large physical saving while replaying the exact existing charge order.
