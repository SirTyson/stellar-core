# H001: Fuse enforcing footprint and storage maps for Soroban host storage

**Date**: 2026-05-04
**Subsystem**: soroban
**Severity**: Medium
**Impact**: apply-time reduction in Soroban host storage access for the soroswap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

In enforcing mode, every Soroban host storage access should prove that the key is in the transaction footprint and then read or update the corresponding value deterministically. Because the footprint key set and the storage-map key set are both derived from the same transaction resources before execution, this should be achievable with a single ordered lookup per access over one per-invocation structure containing `(AccessType, Option<EntryWithLiveUntil>)`, while still rejecting out-of-footprint reads/writes and preserving the exact final ledger changes.

## Mechanism

The current enforcing path keeps two independent sorted `MeteredOrdMap`s: `FootprintMap` for access type and `StorageMap` for entry values. A successful storage read goes through `Footprint::enforce_access` and then `StorageMap::get`; writes do the footprint lookup and then rebuild the storage map through `MeteredOrdMap::insert`. A next-protocol-only fused enforcing storage map could bulk-build one sorted vector from the footprint, merge in the encoded ledger entries, and make `get`/`put`/TTL extension perform one binary search rather than repeatedly probing two maps with the same `LedgerKey`, reducing the hot `storage get` / `storage put` / `map lookup` work without changing transaction ordering or ledger output.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on a next-protocol build. Each successful swap repeatedly reads, writes, and TTL-extends SAC balance and contract entries through enforcing `Storage`, exercising duplicate footprint-map and storage-map lookups inside the parallel apply workers.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-957` — `build_storage_footprint_from_xdr` builds the footprint map separately from values.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1044` — `build_storage_map_from_xdr_ledger_entries` builds a separate storage map, re-checking each entry against the footprint.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — `Footprint::enforce_access` performs the first ordered lookup on every enforcing read/write.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-266` — `Storage::try_get_full_helper` performs `enforce_access` and then a second `StorageMap::get`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-514` — writes and TTL extensions perform the footprint lookup and then rebuild the storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-224` — each map lookup/insert charges and binary-searches the vector independently.

## Evidence

The current accepted soroswap trace
(`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`) has 71 `applyLedger` windows totaling 5,230,315,999 ns. A timeline-overlap check against those windows shows the relevant storage/map zones are descendants of apply execution rather than TX-set construction:

| Zone | Apply-window total | Calls | Source |
|---|---:|---:|---|
| `storage get` | 641,710,601 ns | 305,065 | `soroban-env-host/src/storage.rs:329` |
| `map lookup` | 580,114,128 ns | 502,648 | `soroban-env-host/src/host/metered_map.rs:173` |
| `map lookup indexed` | 543,656,426 ns | 779,242 | `soroban-env-host/src/host/metered_map.rs:330` |
| `new map` | 449,677,501 ns | 170,072 | `soroban-env-host/src/host/metered_map.rs:148` |
| `storage put` | 119,301,798 ns | 33,882 | `soroban-env-host/src/storage.rs:488` |
| `extend key` | 252,582,503 ns | 94,908 | `soroban-env-host/src/storage.rs:654` |

The fused structure attacks a repeated structural cost: many enforcing accesses touch the same `LedgerKey` first in the footprint map and immediately again in the storage map. If it removes roughly half of the duplicated ordered-map lookup/rebuild work in this family, the projected wall-time reduction after 8-way worker normalization is in the Medium range relative to the 5.23 s apply-window trace.

## Anti-Evidence

This must be protocol-gated or exact-metering-preserving: dropping an entire `MeteredOrdMap` lookup changes p26 budget observations. The fused map also has to represent footprint keys that do not yet have values, because RW footprint entries may be created during execution. Prior storage-map indexing attempts show this surface is easy to regress if the replacement adds enough construction or branch overhead, so a PoC needs direct non-Tracy apply-load evidence and should compare the storage/map zone family rather than one zone in isolation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in retained Soroban fail/success records
**Failed At**: reviewer

### Trace Summary

The duplicate enforcing lookup exists: `invoke_host_function` builds a `Footprint` and a separate `StorageMap`, installs both into `Storage`, and hot contract-data host functions route through `Storage` during Soroban apply. Reads call `Footprint::enforce_access` and then `StorageMap::get`; writes call `has`, `get_with_live_until_ledger`, and `put`, causing multiple footprint and storage-map probes; TTL extension reads through the same `get_with_live_until_ledger` path before updating the storage map. However, the reclaimable part is bounded by map child zones that run inside the 8-way parallel Soroban workers, and the proposed fusion cannot remove the required storage-value lookup or the storage-map rebuild needed to produce final ledger changes.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-452` — deserializes resources, builds the footprint, builds a separate storage map, clones the initial storage snapshot, and constructs enforcing `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries` populate independent `MeteredOrdMap`s and use footprint membership checks while constructing storage values.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154,252-266,333-357,431-514,532-573,693-720` — enforcing reads, writes, and TTL extensions perform a footprint lookup plus the storage-map lookup/insert needed for entry values.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-564` — `put_contract_data_into_ledger` shows writes are especially probe-heavy (`has`, `get_with_live_until_ledger`, then `put`), but still require value retrieval and a final storage update even with a fused access-type map.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160,168-240,294-300` — `MeteredOrdMap` lookups and inserts charge, binary-search, and rebuild vectors independently.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-534,575-584` — parallel apply materializes ledger and TTL entry buffers from the Soroban footprint before crossing the Rust bridge, making this path part of `closeLedger`.

### Why It Failed

The inefficiency is real but below the objective severity threshold. The hypothesis adds overlapping Tracy parent zones (`storage get`, `storage put`, `extend key`) to child zones (`map lookup`, `new map`), but only the child lookup/rebuild work represents the concrete removable map cost. Even the overly generous upper bound of eliminating the entire `map lookup` plus `new map` family is about `(580 ms + 450 ms) / 8 = 129 ms` of worker-normalized wall time over a 5.23 s trace, or roughly 2.5% of apply time; the actual saving is lower because many map lookups are required storage-value probes, `StorageMap::insert` still has to rebuild the value map, and construction/output code still needs storage iteration and initial snapshots. That places the realistic impact in Low territory, which this objective rejects.

### Lesson Learned

For Soroban parallel-worker micro-optimizations, do not add enclosing storage zones to child map zones when estimating wall-time savings. Normalize aggregate worker child-zone time by `NUM_CLUSTERS`, then subtract non-removable storage-value probes and required final-change work; duplicated footprint checks are a valid target, but this one is not large enough for the optimize-soroswap Medium floor.
