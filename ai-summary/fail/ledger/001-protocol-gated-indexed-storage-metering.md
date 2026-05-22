# H001: Protocol-gated bulk metering for indexed storage-map access

**Date**: 2026-05-21
**Subsystem**: ledger / Soroban host apply
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction if indexed storage/footprint access can coalesce legacy per-lookup budget charges
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol Soroban apply, enforcing-mode storage and footprint access should still charge deterministic, replayable budget for the same logical reads and writes, but it should not pay the full CPU cost of a legacy binary-search-style charge on every indexed lookup when the key position has already been proven by the side index. Protocol <=26 should retain the exact existing budget profile.

## Mechanism

The optimized p26 stack added side indices for enforcing storage maps, but the indexed paths still deliberately emulate legacy per-access metering: `get_at_known_position` charges `charge_binsearch` and `charge_access`, and `insert_at_known_position` charges access, binsearch, deep-clone, and scan work even though the caller already knows the stable key position. On the current next-protocol benchmark path this compatibility charging is no longer required to preserve p26 replay, so a protocol-gated bulk or coalesced indexed-access charge could replace hundreds of thousands of per-access `Budget::charge` calls with deterministic aggregate charges per host invocation or per storage phase.

## Trigger

Run the soroswap apply-load benchmark on the current baseline (`soroswap, TX=2000, T=8`) with successful Soroban invokes that repeatedly read, write, and finalize enforcing storage maps. The issue triggers on every storage `get`, `has`, `put`, TTL extension, and post-invocation `get_ledger_changes` iteration that takes the indexed storage/footprint path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — `Storage::with_enforcing_footprint_and_map` builds stable side indices proving key positions for the whole enforcing-mode invocation.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:283-320` — `Storage::enforce_access_indexed` uses the side index but still calls metered map indexed lookup per access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-352` — `Storage::try_get_full_helper` uses `get_at_known_position` for indexed storage reads.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-457` — `Storage::put_opt_helper` uses `insert_at_known_position` for indexed storage replacements.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:317-348` — `MeteredOrdMap::get_at_known_position` still charges legacy binsearch/access costs.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:350-385` — `MeteredOrdMap::insert_at_known_position` still charges legacy replacement costs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:248-322` — `get_ledger_changes` performs indexed map lookups once per storage-map entry during output construction.

## Evidence

Current Tracy trace:
`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`.

- `applyLedger` total: 5,230,315,999 ns across 71 ledgers.
- `applySorobanStageClustersInParallel` self/wait envelope: 3,455,290,270 ns and is a descendant of `applyLedger` through `LedgerManagerImpl::applySorobanStage`.
- `parallelApply` aggregate worker time: 12,671,220,592 ns, implying about 3.67x effective worker overlap against the stage wall time.
- `map lookup indexed` (`soroban-env-host/src/host/metered_map.rs:330`): 408,451,716 ns self across 779,242 calls.
- `map lookup` (`soroban-env-host/src/host/metered_map.rs:173`): 345,449,339 ns self across 502,648 calls.
- `storage get` (`soroban-env-host/src/storage.rs:329`): 215,980,007 ns self across 305,065 calls, also in the `invoke_host_function` path.

The two map-lookup zones alone total about 754 ms aggregate worker self-time; normalized by the observed worker overlap, that is about 205 ms of apply critical-path opportunity, or roughly 3.9% of the 5.23 s `applyLedger` envelope. The proposed change is deterministic because the counts and map lengths are already known from the same fixed key sets used by the indexed fast paths; only the timing and next-protocol budget constants would change.

## Anti-Evidence

The earlier generic "budget charge hotspot" angle was rejected because Tracy span overhead can exaggerate production cost, so this must be validated by non-Tracy A/B runs. Also, not all `map lookup` time is removable: the side-index `HashMap` probe, value access, and some memory traffic remain real work. The viable implementation must be protocol-gated so p26 replay and recording-mode budget expectations remain unchanged.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to prior positioned-storage work, but not previously investigated as protocol-gated indexed-access metering
**Failed At**: reviewer

### Trace Summary

The apply path reaches the p26 Rust host through `LedgerManagerImpl::applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applyThread` -> `TransactionFrame::parallelApply` -> `OperationFrame::parallelApply` -> `InvokeHostFunctionOpFrame::doParallelApply` -> `rust_bridge::invoke_host_function`. In the actual Rust source, `invoke_host_function` builds a plain `StorageMap`, clones it for the initial snapshot, and constructs `Storage::with_enforcing_footprint_and_map` without any side index. Runtime storage reads and output construction use `MeteredOrdMap::get`, `contains_key`, `insert`, and `iter`; there are no `get_at_known_position`, `insert_at_known_position`, or `enforce_access_indexed` symbols in this checkout. Therefore the claimed indexed path and its removable compatibility charges do not exist in the reviewed code.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1457-1688` — `applyLedger` enters close-ledger transaction processing and calls `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2673-2709` — `applySorobanStages` constructs global parallel state and applies every Soroban stage.
- `src/ledger/LedgerManagerImpl.cpp:2484-2506` — `applyThread` invokes `txBundle.getTx()->parallelApply` once per Soroban transaction in a cluster.
- `src/transactions/TransactionFrame.cpp:2385-2430` and `src/transactions/OperationFrame.cpp:175-188` — parallel transaction apply dispatches to the operation's `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — Soroban invoke operations construct `InvokeHostFunctionParallelApplyHelper` and run `helper.apply()`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — the helper calls `rust_bridge::invoke_host_function`, passing encoded footprint, ledger entries, TTL entries, and module cache into Rust.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` — `invoke_host_function` builds a plain storage map from XDR entries, clones it, and constructs enforcing `Storage`; no side-index metadata is built or threaded.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — `Footprint::enforce_access` uses `self.0.get(...)`, a normal metered map lookup, to validate read/write access.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:693-719` — storage reads call `prepare_read_only_access` then `self.map.get(...)`; the key position is not known.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` — storage writes enforce the footprint and call `self.map.insert(...)`, again through the normal binary-search path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` iterates `storage.map.iter(...)`, calls the initial snapshot, then performs normal `footprint_map.get(...)` and `restored_keys.contains_key(...)` lookups.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` populates `StorageMap` with repeated `contains_key` and `insert`; no positional index is retained.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1083` — `StorageMapSnapshotSource::get` uses `self.map.get(...)`, not a known-position lookup.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — the only relevant lookup implementation charges `charge_binsearch`, performs a binary search, then charges access for found values.

### Why It Failed

The proposed optimization depends on stable key positions already being proven by a side index, but the reviewed code has no side index and no known-position access APIs. The observed `map lookup` charge is the normal deterministic binary-search lookup cost for `MeteredOrdMap`; removing or bulk-coalescing it without first introducing a new positional storage/footprint representation would under-meter the actual lookup path and change protocol behavior. Because the target mechanism is absent, the 3-5% projection from eliminating "`map lookup indexed`" work is not supported by this source tree.

### Lesson Learned

Do not draft follow-on metering hypotheses from Tracy zone names or prior optimization notes without confirming that the corresponding indexed APIs exist in the target checkout. In this tree, storage and footprint access still use the legacy `MeteredOrdMap` API directly, so any viable future proposal must first establish a correct positional/indexed representation and then separately measure whether its remaining budget-charge overhead clears the 3% Medium objective floor.
