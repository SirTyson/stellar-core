# H002: Batch e2e Ledger Materialization Instead of Rebuilding Maps and XDR

**Date**: 2026-04-27
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: soroswap apply-time reduction by avoiding redundant per-entry storage-map construction and ledger-change serialization
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During `invoke_host_function`, ledger entries supplied by stellar-core should be decoded once into host storage while retaining deterministic metadata that will be needed at output time: encoded keys, original encoded entry sizes, TTL metadata, and footprint access type. Building the enforcing storage map and producing `LedgerEntryChange` output should be linear in the footprint size and should not repeatedly rebuild sorted maps or reserialize unchanged old ledger entries.

## Mechanism

The current e2e path constructs `FootprintMap`, `StorageMap`, and `TtlEntryMap` by calling `MeteredOrdMap::insert` inside loops, and `insert` rebuilds a new sorted `Vec` via `from_exact_iter` every time. Later, `get_ledger_changes` walks the storage map and calls `metered_write_xdr` for each key and old entry even though the input entries arrived as encoded XDR and `entry_size_for_rent` explicitly accepts a precomputed XDR size to avoid recomputation. A prepared ledger-entry materialization pass could collect entries into vectors, sort/validate once, build maps with a single `from_map`/batch constructor, and carry encoded-key/old-size metadata into `get_ledger_changes`; this preserves deterministic ordering by using the same canonical key ordering while removing repeated allocation, lookup, and serialization work.

## Trigger

Run the current `soroswap, TX=4000, T=8` benchmark. The trigger is a high-volume Soroban apply ledger where each invoke-host-function operation receives a footprint and ledger-entry vector, constructs enforcing host storage, executes the contract, and emits ledger changes for every footprint entry, including unmodified entries.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:175-281` — `get_ledger_changes` serializes every key and old entry, then serializes new read-write entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:365-375` — `entry_size_for_rent` is designed to consume an already-known XDR size, but the caller recomputes old entry sizes by serializing old entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:921-1040` — `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries` build maps one insertion at a time from already-batched input vectors.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-160` — `from_exact_iter` allocates and clones a full map vector.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-222` — `insert` performs a lookup and reconstructs the whole map for each inserted entry.

## Evidence

The current soroswap Tracy trace reports `applyLedger` total time of 4,591,086,908 ns. Relevant self-time descendants include `map lookup` at `soroban-env-host/src/host/metered_map.rs:173` with 403,316,483 ns over 350,923 calls, `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:61` with 388,067,513 ns over 61,830 calls, and `new map` at `soroban-env-host/src/host/metered_map.rs:148` with 125,110,718 ns over 59,296 calls. These zones appear in worker-thread samples during `applyLedger`, and the structural source pattern explains why soroswap amplifies them: every transaction constructs fresh host maps from batched ledger inputs and then materializes ledger-change XDR outputs entry by entry.

The code comments in `InvokeHostFunctionResult` state that ledger changes include every item in the input footprint, including no-ops, so unchanged old entries are on the hot output path. The source also notes that recomputing XDR size in `entry_size_for_rent` "might be costly", yet `get_ledger_changes` reserializes old entries solely to obtain `buf.len()` before calling it.

## Anti-Evidence

`MeteredOrdMap` charges budget for map construction, lookup, and cloning; a batch constructor must preserve the same metered semantics or deliberately charge an equivalent amount so protocol-visible budget consumption does not change. Ledger-change ordering is also observable to stellar-core, so any batch representation must emit changes in the same canonical order as the current sorted storage map. Finally, new entries still require serialization for output, so the hypothesis depends on old-entry/key metadata and batched map construction being a large enough fraction of the observed `write xdr` and map self-time to clear the Medium threshold.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no prior fail/success record found for this hypothesis

### Trace Summary

The apply path is `InvokeHostFunctionOpFrame::doApply`/`doParallelApply` into `invokeHostFunction`, which passes footprint ledger entries and TTL entries across the Rust bridge into the protocol-selected p26 `e2e_invoke::invoke_host_function`. The p26 e2e path decodes resources, builds footprint/storage/TTL maps by repeated `MeteredOrdMap::insert`, clones the initial storage map, executes the host function, then calls `get_ledger_changes` over the sorted storage map. In the soroswap benchmark each generated swap has a 10-key footprint (5 read-only and 5 read-write), so this map-building and ledger-change materialization is per-transaction apply-path work rather than setup-only work. The exact optimization must preserve canonical `LedgerKey` ordering and protocol-visible budget accounting, but the redundant allocations/lookups and old-entry/key serialization are real.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swaps are generated per ledger, one invoke-host-function operation per transaction, with a fixed 5 read-only + 5 read-write footprint.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` loads each footprint entry, serializes live ledger entries and TTL entries into `mLedgerEntryCxxBufs`/`mTtlEntryCxxBufs`, and already observes each old encoded entry size.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` passes host-function XDR, resources, ledger entries, TTL entries, source account, auth, ledger info, and module cache into `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_invoke.rs:7-39` and `src/rust/src/soroban_proto_all.rs:56-129` — the bridge dispatches by protocol and the p26 adapter calls `soroban_env_host_p26::e2e_invoke::invoke_host_function`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-521` — the e2e invocation decodes resources, builds storage maps, clones the initial storage map, invokes the host function, and computes ledger changes on success.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — `build_storage_footprint_from_xdr` and `build_storage_map_from_xdr_ledger_entries` repeatedly call `insert` for footprint entries, ledger entries, TTL entries, and missing footprint entries.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-292` — `get_ledger_changes` iterates every storage entry, serializes every key, serializes every old entry only to compute `old_entry_size_bytes_for_rent`, performs TTL/footprint snapshot lookups, and serializes every non-deleted read-write new entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:368-385` — `entry_size_for_rent` intentionally accepts precomputed XDR size because recomputing XDR size may be costly.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — `from_map` validates sorted unique keys, while `from_exact_iter` collects a new vector and charges/clones before delegating to `from_map`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-222` — `insert` charges access, binary-searches, and reconstructs a whole new map vector for each inserted key.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:56-68` — `metered_write_xdr` charges `ValSer` and writes into a `Vec<u8>`, making skipped old-entry/key serialization require equivalent budget charging if protocol-visible metering must remain unchanged.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-28` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1082` — `FootprintMap`, `StorageMap`, and snapshot lookup are `MeteredOrdMap`-backed, so the later snapshot/footprint lookups are the same metered binary-search path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-767` and `src/rust/src/soroban_proto_any.rs:261-301` — Rust converts `LedgerEntryChange` into modified ledger entries, and C++ expects every surviving read-write entry to be returned so missing entries can be erased.

### Findings

The inefficiency exists. `MeteredOrdMap::insert` is persistent-style: every insertion does a lookup and builds a replacement vector via `from_exact_iter`. The p26 e2e construction code repeatedly invokes this for already-batched resource and ledger-entry inputs, and then `get_ledger_changes` repeats map lookups for the initial snapshot, TTL map, restored set, and footprint access type.

The old-entry serialization waste also exists. C++ already serializes the live ledger entry into `CxxBuf` before crossing the bridge, but Rust discards the encoded size and later reserializes `old_entry` into a temporary `Vec` just to pass `buf.len()` to `entry_size_for_rent`. Key serialization is also done for every storage entry before TTL handling, even though existing durable entries already have a TTL entry with `key_hash` and classic entries do not need TTL hashes. New read-write values still need serialization for C++ output, so that part should not be counted as removable.

The path is hot for the objective. The soroswap swap generator creates one Soroban invoke transaction per swap with 10 footprint keys, and the benchmark runs thousands of these through `closeLedger`. This places the repeated p26 map construction, storage snapshot clone, map lookups, and ledger-change materialization directly under apply, not in transaction construction or setup.

The proposed fix is correctness-sensitive but feasible. A batch materialization path can collect decoded entries and metadata into vectors, sort by the same `Budget::compare(LedgerKey)` canonical ordering used by `MeteredOrdMap`, validate uniqueness with `from_map`, and emit ledger changes in that same order. It must preserve metered semantics: avoiding physical XDR writes or map reconstruction should still charge equivalent `ValSer`/`MemCpy` costs where those costs affect transaction budget, or the optimization would change protocol-visible resource use.

Projected impact clears the review threshold. The cited trace attributes roughly 0.9s of 4.6s apply time to `map lookup`, `write xdr`, and `new map`; this hypothesis will not remove all of that, but the soroswap footprint size and per-transaction repetition make it plausible to remove enough e2e-only work to land in the 3-10% Medium band. The PoC should reject the change if repeated `run_apply_load_matrix.py` runs do not show at least a 3% apply-time reduction.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` (`build_storage_footprint_from_xdr`, `build_storage_map_from_xdr_ledger_entries`, `get_ledger_changes`, `StorageMapSnapshotSource`) and, if needed for a clean API, `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs` for a batch constructor that preserves metering.
- **Change description**: Replace insertion-in-loop map construction with a prepared materialization pass that decodes all footprint/ledger/TTL inputs, records access type, old encoded entry size, TTL key hash/live-until metadata, and optionally encoded key bytes, sorts once by canonical `LedgerKey` order, and builds `FootprintMap`, `StorageMap`, and `TtlEntryMap` through `from_map` or an equivalent batch path. Feed retained metadata into `get_ledger_changes` so existing old entries are not reserialized for rent size and existing durable keys do not serialize solely to recover a TTL hash. Continue serializing non-deleted read-write new entries because C++ needs them to upsert/pass through survivors.
- **Correctness check**: Preserve output ordering, duplicate-key rejection, unsupported-key rejection, restored-key semantics, TTL live-until behavior, and all budget charges that can affect success/failure. Existing e2e host tests and invoke-host-function transaction tests should still cover ledger changes, rent changes, TTL changes, and C++ application of modified entries; add focused p26 e2e tests only if the new metadata path introduces branchy behavior not already covered.
- **Benchmark focus**: Run the soroswap apply-load benchmark repeatedly, especially `TX=4000, T=8`, and compare top-line apply time. Secondary Tracy spans should show fewer `new map`, `map lookup`, and avoidable `write xdr` samples in `e2e_invoke`; accept only if repeated runs show a reproducible 3-10% apply-time reduction.
