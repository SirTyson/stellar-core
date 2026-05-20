# H001: Position-indexed Soroban storage setup to skip redundant footprint-key reconstruction

**Date**: 2026-05-20
**Subsystem**: transaction-ledger / Soroban invoke setup
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing duplicate footprint membership searches, key reconstruction, and immutable-map inserts before each host invocation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For each invoke-host-function transaction, the Rust host should build the enforcing `Footprint` and initial `StorageMap` from exactly the ledger entries loaded from the declared footprint, preserving the same membership validation, missing-entry handling, TTL validation, restored-entry handling, rent-size metadata, deterministic key ordering, and protocol-visible resource accounting. On a next-protocol path, the C++ bridge should be able to pass position/index metadata for each loaded footprint entry so Rust can reuse the already-decoded footprint keys instead of reconstructing a `LedgerKey` from every decoded `LedgerEntry` and searching the footprint map again.

## Mechanism

`InvokeHostFunctionApplyHelper::addReads` already iterates the read-only and read-write footprint keys, validates each key, loads any present ledger entry and TTL entry, and serializes those entries for Rust. `e2e_invoke::build_storage_map_from_xdr_ledger_entries` then decodes each entry, reconstructs the key with `ledger_entry_to_ledger_key`, searches `footprint.0.contains_key`, inserts the entry into `storage_map`, and later walks all footprint keys again to insert missing entries. A position-indexed bridge format could carry the footprint slot for each serialized entry and build the storage map in footprint order using `Rc` clones of the footprint keys, with protocol-gated budget updates for the removed metered clones/lookups.

## Trigger

Run the current soroswap Tracy benchmark from `ai-summary/CURRENT_STATE.md`:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.
Every Soroban transaction enters `InvokeHostFunctionOpFrame::doParallelApply`, loads the declared footprint in C++, then reconstructs and validates the same footprint relationship in Rust before VM execution.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:385-534` — `addReads` iterates footprint keys, loads/validates entries, computes entry sizes, and fills `mLedgerEntryCxxBufs` / `mTtlEntryCxxBufs` without passing the matched footprint slot to Rust.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-583` — `invokeHostFunction` passes only entry and TTL byte buffers across the bridge.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs@fa1226b3:1013-1037` — `build_storage_footprint_from_xdr` constructs the footprint map from decoded resource keys.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs@fa1226b3:1039-1151` — `build_storage_map_from_xdr_ledger_entries` reconstructs entry keys, checks footprint membership, records metadata, inserts present entries, then walks footprint keys again for missing entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs@fa1226b3:983-1011` — `ledger_entry_to_ledger_key` clones key fields out of decoded entries even though the declared footprint key already exists.

## Evidence

- Timestamp-filtering the current trace to `applyLedger` windows shows `addReads,transactions/InvokeHostFunctionOpFrame.cpp:388` at **271,050,094 ns** total over **13,648** in-window calls, confirming this setup path is in scope.
- The Rust setup work that follows is also inside `applyLedger`: `read xdr with budget` totals **178,988,395 ns**, `map lookup` totals **580,114,128 ns**, `map lookup indexed` totals **543,656,426 ns**, and `new map` totals **449,677,501 ns** in the same windows. These are aggregate worker times, but together they are large enough that removing a broad setup slice can plausibly clear the ~8 ms/ledger Medium floor after T=8 normalization.
- The source has a structural duplicate: C++ proves that each present entry came from a specific footprint key, but Rust derives a new key from the entry and performs another footprint lookup before inserting it. A compact positional metadata vector would let Rust validate slot bounds/order, reuse footprint keys, and fill missing slots in one deterministic pass.
- This is not the previously rejected `xdr_size` skip, `recordStorageChanges` TTL precompute, or per-cluster CxxBuf cache: it targets the Rust enforcing-storage setup pipeline's duplicate key/membership work, not just entry-size calculation, output decoding, or cached serialized bytes.

## Anti-Evidence

- Prior failures show that narrow `xdr_size`, CxxBuf, and storage-map lookup slices are below threshold in isolation; this hypothesis only remains viable if the PoC removes a combined setup path and measures the exact share with narrower spans.
- The p26 metering model charges several key clones, map operations, and XDR decodes. Any skipped metered work must be protocol-gated or reproduced explicitly, and budget-number tests may need mechanical updates to lower values.
- The bridge currently sends only present entries, not explicit missing-entry slots. The new format must preserve deterministic ordering for read-only/read-write keys, handle restored and missing entries, reject malformed slot metadata, and avoid adding enough bridge copying to erase the setup savings.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — substantially duplicates `ai-summary/success/transaction-ledger/001-bulk-build-host-storage-maps.md`
**Failed At**: reviewer

### Trace Summary

The close-ledger path reaches this setup for every Soroban invoke: C++ `addReads` walks the declared footprint, loads present ledger and TTL entries, serializes them into parallel buffers, and `invokeHostFunction` sends only those buffers and the original resource footprint over the Rust bridge. Rust then decodes the resource footprint, builds an enforcing `Footprint`, decodes each present ledger entry, reconstructs the corresponding `LedgerKey`, checks membership against the footprint map, inserts present entries, and finally scans the footprint to insert missing `None` entries. The redundant key reconstruction and membership check are real, but they are part of the same enforcing storage-map construction path already investigated and confirmed in the prior bulk-build success record.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:addReads:385-534` — iterates read-only/read-write footprint keys in order, validates/restores/meters them, and appends only present ledger-entry and TTL buffers; it does not pass footprint positions to Rust.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:invokeHostFunction:557-583` — calls `rust_bridge::invoke_host_function` with resources, restored indices, ledger-entry buffers, and TTL buffers, but no slot/index metadata.
- `src/rust/src/soroban_invoke.rs:invoke_host_function:7-39` — forwards those C++ buffers unchanged to the protocol-specific host module.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:invoke_host_function:408-447` — decodes `SorobanResources`, builds the enforcing footprint, then builds the initial storage/TTL maps before host execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:ledger_entry_to_ledger_key:903-931` — reconstructs a `LedgerKey` by metered-cloning fields from each decoded `LedgerEntry`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:build_storage_footprint_from_xdr:933-957` — constructs the footprint map from the declared read-write and read-only keys.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:build_storage_map_from_xdr_ledger_entries:959-1052` — decodes present entries, reconstructs keys, validates footprint membership via `contains_key`, inserts present entries/TTLs, then iterates footprint keys to insert missing entries.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:insert/contains_key/keys:196-305` — shows the repeated map lookup and immutable-map reconstruction costs that the prior success record targeted.
- `ai-summary/success/transaction-ledger/001-bulk-build-host-storage-maps.md:531-553` — prior confirmed finding optimized the same enforcing storage setup path and measured only a Low soroswap improvement, about 1.63% average.

### Why It Failed

This hypothesis is not novel enough to promote. The previously confirmed `001-bulk-build-host-storage-maps` investigation covered the same Rust enforcing footprint/storage-map construction path, including `build_storage_map_from_xdr_ledger_entries`, membership checks, missing-key insertion, and repeated `MeteredOrdMap` work. That broader optimization was ultimately confirmed at Low severity, with about a 1.63% average soroswap apply-time improvement. The current position-indexed bridge proposal would remove a narrower remaining subset of the same setup work (`ledger_entry_to_ledger_key` clones and footprint membership lookup) while adding bridge metadata validation and ordering constraints, so it does not plausibly meet the optimize-soroswap review floor of Medium (3-10% apply-time reduction). Under the objective-specific rule, Low-tier or duplicate storage-setup optimizations are rejected at review.

### Lesson Learned

When a new Soroban invoke setup hypothesis targets `build_storage_map_from_xdr_ledger_entries`, compare it against the confirmed bulk-build storage-map record first. A follow-up idea must show a clearly new dominant cost beyond the already benchmarked storage-map construction work, not just a smaller variant of the same setup pipeline.
