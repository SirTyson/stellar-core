# H002: Protocol-Gated Skip of Read-Only Ledger-Change Extraction

**Date**: 2026-05-25
**Subsystem**: ledger / soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding remaining no-op read-only ledger-change serialization and lookups
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a successful Soroban invocation, ledger-change extraction should emit and charge work needed for ledger-visible effects: read-write entry updates, TTL/rent changes, restored entries, and events/results. For read-only footprint entries that were not modified and do not need a rent/TTL effect, a next-protocol-gated path should produce the same final ledger state and downstream metadata semantics without serializing keys, computing TTL hashes, or probing the initial storage snapshot solely to build a no-op `LedgerEntryChange` that will later be ignored.

## Mechanism

`get_ledger_changes` currently iterates every entry in `storage.map`, including read-only no-op entries. It serializes each key into `entry_change.encoded_key`, constructs TTL-change scaffolding, looks up the initial entry by known position, then looks up the footprint access type by known position before discovering `AccessType::ReadOnly` and emitting a read-only change. The current accepted sparse-output path removes some downstream consumption of these no-op changes, but this function still performs the metered serialization and indexed map lookups; a protocol-gated sparse extractor that first identifies read-write/TTL-relevant positions and skips read-only no-ops should remove apply-path CPU without changing deterministic ledger output.

## Trigger

Run the current soroswap apply-load benchmark with successful swap invocations whose footprints include many read-only pool, contract-code, and SAC entries. The issue triggers during `invoke_host_function` after host execution succeeds, when `get_ledger_changes` scans the storage map to produce ledger changes for every footprint entry even if most entries are read-only and unchanged.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:221-357` — `get_ledger_changes` builds a `LedgerEntryChange` for every storage-map position.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:248-280` — serializes every key and loads the initial entry before checking whether the footprint entry is read-only.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:318-355` — only after the per-entry serialization and old-entry work does the code classify read-only entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:565-579` — successful invocation always calls `get_ledger_changes` with `init_storage_map` and positional metadata.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-99` — `metered_write_xdr` charges and writes key/value XDR used by ledger-change extraction.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-348` — positional snapshot/footprint lookups used by extraction still hit the indexed metered-map path.

## Evidence

The latest current-state soroswap Tracy trace is `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`. `csvexport-release -e` reports apply-relevant hotspots in the exact primitives used by `get_ledger_changes`: `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:72` has 168,176,135 ns self over 252,173 calls, and `map lookup indexed` at `soroban-env-host/src/host/metered_map.rs:330` has 532,467,330 ns self over 931,436 calls. Unwrapped event intersection confirms `write xdr` has 188,155,837 ns / 251,597 events inside `applyLedger`, while `map lookup indexed` has 681,483,367 ns / 929,010 events inside `applyLedger`.

The source structure shows the read-only decision is made after key serialization, optional TTL hash preparation, initial-entry lookup, and footprint lookup. Soroswap workloads have large repeated read-only footprints, so skipping no-op read-only extraction before those steps should remove measurable apply work on the headline benchmark.

## Anti-Evidence

This is not safe as a p26-equivalent change because the existing code intentionally preserves metered key serialization and legacy ledger-change shape for budget and compatibility. A viable implementation must be protocol-gated, must preserve extraction for read-write entries, TTL bumps, restored keys, rent-affecting entries, and diagnostic/recording-mode paths, and must adjust only budget-derived expectations rather than weakening semantic tests.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — adjacent prior work kept metered key serialization or targeted different storage-metering paths
**Failed At**: reviewer

### Trace Summary

The execution path is `InvokeHostFunctionOpFrame::invokeHostFunction` -> `rust_bridge::invoke_host_function` -> p26 `e2e_invoke::invoke_host_function` -> `get_ledger_changes` after successful host execution. The inefficiency is real: the extraction loop serializes every key, prepares TTL scaffolding, reads the initial entry, and performs a footprint lookup before setting `read_only` and pushing a change that downstream rent/effect extraction will ignore when there is no TTL extension. A correct future-protocol implementation could skip read-only no-op positions only after proving the footprint access type and unchanged live-until state, while preserving read-write changes, TTL bumps, restored entries, and recording/dense-output semantics. However, the measured remaining primitive work is too small to satisfy the optimize-soroswap Medium floor.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ Soroban apply calls the Rust bridge for each successful invoke-host-function operation and records returned resource metrics.
- `src/rust/src/soroban_proto_all.rs:95-130` and `src/rust/src/soroban_proto_any.rs:391-488` — protocol dispatch reaches the p26 host, then downstream code consumes only rent changes and modified ledger effects from the returned `ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` scans every `storage.map` position and performs key XDR serialization, initial-storage lookup, old-size/rent preparation, footprint lookup, and dense change push for read-only no-op entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:503-579` — successful invocation builds enforcing storage with positional metadata, clones the initial storage map, finishes host execution, and unconditionally calls `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:393-430` and `src/rust/src/soroban_proto_any.rs:261-301` — downstream rent/effect extraction filters no-op read-only changes unless a TTL live-until increase is present.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` and `533-757` — enforcing storage has stable side indexes, but TTL extension can update a read-only entry's live-until value, so a skip must compare old and new TTL state before dropping an entry.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-99` — `metered_write_xdr` performs the key/value XDR serialization the hypothesis wants to skip for no-op read-only positions.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-348` — `get_at_known_position` still charges and spans `map lookup indexed`; extraction uses it for initial-storage and footprint access by position.

### Why It Failed

The optimization is structurally plausible but below this objective's severity threshold. The hypothesis's own apply-intersected broad target spans sum to about 869 ms across the diagnostic soroswap run (`write xdr` 188 ms plus `map lookup indexed` 681 ms), while that run's log contains 209 `txs=2000` benchmark ledgers and reports a 209.9 ms soroswap median. Even the impossible ceiling of eliminating all `write xdr` and all indexed-map lookup time would be only about 4.2 ms per ledger, roughly 2% of median apply time before accounting for Soroban worker parallelism and before subtracting the large portions of those spans unrelated to read-only no-op ledger-change extraction. The actually removable subset is therefore Low/sub-Medium, and Low findings are rejected for this objective.

### Lesson Learned

For follow-ons to sparse no-meta ledger changes, bound the remaining primitive spans against the benchmark ledger count before projecting severity. Broad `write xdr` and `map lookup indexed` totals include non-extraction and non-read-only work; after filtering to no-op read-only extraction and parallel apply wall time, they cannot support a 3-10% optimize-soroswap claim without a dedicated larger trace span or benchmark-backed projection.
