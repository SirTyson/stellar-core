# H001: Elide Cached ContractCode Bodies From Per-Tx Rust Bridge Input

**Date**: 2026-05-20
**Subsystem**: soroban
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by avoiding repeated XDR encode/decode of read-only Wasm code entries that are already present in the shared module cache
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During production `closeLedger` apply, a Soroban transaction should not copy full `CONTRACT_CODE` Wasm bodies across the C++/Rust bridge when the only runtime operation needed for that code is "is this contract code present?" plus fetching the already-parsed `ParsedModule` from `SorobanModuleCache`. If the module cache contains the code hash for the active protocol, the bridge should pass a compact code-presence witness (hash, TTL, and read access metadata) and the host should instantiate from the cached parsed module. Full `ContractCode` XDR bytes should still be passed for cache misses, newly uploaded code, simulation/recording paths that require exact storage contents, or any path that may need `retrieve_wasm_from_storage`.

## Mechanism

`InvokeHostFunctionOpFrame::addReads` currently serializes every live footprint entry into `CxxBuf`, including read-only `CONTRACT_CODE` entries, via `toCxxBuf(*entryOpt)` (`src/transactions/InvokeHostFunctionOpFrame.cpp:474-497`). For soroswap swaps the footprint explicitly includes `routerCodeKey` and `pairCodeKey` on every transaction (`src/simulation/ApplyLoad.cpp:3449-3456`), and those Wasm files are about 34 KiB and 27 KiB respectively (`src/rust/apply-load-wasm/soroswap_router.wasm`, `soroswap_pool.wasm`). On the Rust side, the normal cached path in `Host::instantiate_vm` only calls `storage.has(&wasm_key)` before `cache.get_module(wasm_hash)` and never reads the code body when the module cache hits (`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801`). The actual behavior therefore repeatedly encodes, transfers, decodes, stores, clones, and later walks tens of KiB of Wasm code per tx even though the apply path already has the parsed module it will execute.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) with the diagnostic Tracy trace. Each swap transaction carries at least the router and pair `CONTRACT_CODE` read-only keys; both code hashes should be present in `LedgerManagerImpl::mModuleCache` after setup. A PoC can instrument `InvokeHostFunctionOpFrame::addReads` to count bytes serialized for `CONTRACT_CODE` entries and compare that to the number of `SorobanModuleCache::contains_module(protocol, hash)` hits.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` serializes every read-only `CONTRACT_CODE` ledger entry into a `CxxBuf` and pushes it into `mLedgerEntryCxxBufs`.
- `src/rust/src/bridge.rs:323-329` and `src/rust/src/soroban_module_cache.rs:82-99` — the C++ bridge already exposes `SorobanModuleCache::contains_module(protocol, key)`, which can guard omission.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` currently requires full `LedgerEntry` XDR for every storage-map entry and inserts it into `StorageMap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cached VM instantiation checks code-key presence, then uses the cached parsed module and shared linker rather than reading the Wasm bytes.
- `src/simulation/ApplyLoad.cpp:3449-3456` — soroswap swap footprint includes router and pair code keys on every swap transaction.

## Evidence

- The current soroswap trace confirms all relevant work is inside `applyLedger`: `addReads` has `196,665,860 ns` self-time across `13,648` calls, `read xdr with budget` has `178,990,000 ns` inside apply, and `write xdr` has `168,020,000 ns` inside apply. Those zones are descendants of `applyLedger` in the diagnostic trace, not tx-set construction.
- The source-level byte volume is large even before metering overhead: the swap footprint includes router and pair code on every tx, and their Wasm bodies total about 61 KiB. Across 6,776 invoke-host-function calls in the diagnostic trace this is hundreds of MiB of repeated code-entry XDR traffic that does not feed execution when the module cache hits.
- This is distinct from prior broad "XDR bridge cost is distributed" failures: the proposal is not to cache arbitrary encoded ledger entries or auth buffers. It targets a specific immutable entry type whose executable payload has an existing correctness guard (`contains_module`) and an existing runtime consumer (`cache.get_module`) that already bypasses the bytes.
- Determinism is preserved by omitting code bodies only when the active protocol's module cache contains the exact hash. Nodes with the same ledger state compile the same module cache before apply; if the cache does not contain the hash, the old full-XDR path remains mandatory.

## Anti-Evidence

- `Storage` currently represents all live entries as `LedgerEntry`; adding a compact "cached code present" representation is an API change. The implementation must prevent any non-instantiation path from observing a fake empty code body.
- Cache-hit checks add a bridge call and a module-cache lookup per candidate code key. This is only worthwhile for large `CONTRACT_CODE` entries; the PoC should gate on entry type and cache hit and leave small or missing-code paths unchanged.
- If module-cache completeness is not guaranteed during same-ledger uploads, those transactions must keep the full code body. The optimization is aimed at steady-state soroswap apply, where router and pair code were uploaded during setup and are already compiled.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — this is a narrower ContractCode-body variant, but it falls under the prior XDR bridge/addReads severity cap in `fail/soroban/summary.md`
**Failed At**: reviewer

### Trace Summary

The claimed waste exists: the parallel apply helper materializes every live footprint entry, so soroswap's router and pair `CONTRACT_CODE` read-only entries are XDR-encoded in C++, passed through `mLedgerEntryCxxBufs`, decoded in Rust, and inserted into enforcing `StorageMap`. On the cached VM path, `Host::instantiate_vm` uses that storage entry only to answer `storage.has(wasm_key)`, then gets the already-parsed module from `ModuleCache` and never reads the Wasm bytes. However, the removable code-body bridge work is a subset of the already-investigated addReads / C++-Rust XDR bridge cost, which the retained failure summary caps below the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3447-3456` — every soroswap swap declares router and pair contract-code keys in the read-only footprint.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-535` — `addReads` checks TTL/liveness, loads each live footprint entry, serializes it with `toCxxBuf(*entryOpt)`, serializes the TTL entry, and pushes both buffers for Rust.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` serializes via `xdr::xdr_to_opaque`, so a `CONTRACT_CODE` entry includes the full Wasm body.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — the accumulated ledger-entry and TTL buffers are passed to `rust_bridge::invoke_host_function` together with the shared module cache.
- `src/rust/src/bridge.rs:321-329` and `src/rust/src/soroban_module_cache.rs:82-99` — `SorobanModuleCache::contains_module(protocol, key)` exists and could check active-protocol cache hits.
- `src/rust/src/soroban_proto_any.rs:391-448` — the bridge wrapper forwards all encoded ledger entries and TTL entries into the protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-451` — enforcing host setup builds the footprint, decodes every ledger-entry XDR buffer, and constructs `Storage::with_enforcing_footprint_and_map`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` — `build_storage_map_from_xdr_ledger_entries` requires full `LedgerEntry` XDR, derives the key from the decoded entry, requires a TTL for contract code/data entries, and represents omitted footprint entries as `None`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:421-429` — `Storage::has` is implemented as `try_get_full(...).is_some()`, so simply omitting the entry would make the cached VM path see the code as absent.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — `instantiate_vm` checks `storage.has(wasm_key)`, then returns `Vm::from_parsed_module_and_wasmi_linker` on a module-cache hit without reading the code body.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:806-900` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:133-160` — cache-miss and recording-mode paths call `retrieve_wasm_from_storage`, which requires the full `ContractCode` body and must remain on the old path.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-570` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-307` — contract-code TTL extension and live-until queries need a present entry plus TTL, so a compact witness would require a real storage representation change, not just an absent entry.

### Why It Failed

The optimization is below the objective severity threshold. The exact inefficiency is a sub-slice of the XDR bridge/addReads surface already summarized in `fail/soroban/summary.md` as "XDR Bridge Cost Is Distributed and Sub-Threshold", with a retained lesson that any `addReads` body optimization must be projected against the prior ~2.5% cap on total bridge cost. This proposal can remove only the cached `CONTRACT_CODE` input bodies; it cannot remove full footprint handling, TTL handling, host-function/resource/source/auth serialization, non-code ledger-entry decode, output ledger-change/event/result XDR, or the mandatory storage and VM work. After normalizing aggregate worker-thread costs by the parallel Soroban cluster count and apply windows, the cited `addReads`/input-XDR zones do not leave enough ContractCode-only removable work to plausibly reach the required 3% Medium floor.

The proposed mechanism is also more invasive than a bridge-side omission: Rust `StorageMap` currently distinguishes only present full `LedgerEntry` values from `None`, and `Storage::has` would treat an omitted cached code entry as missing. A correctness-preserving implementation would need a new explicit "cached contract code present" storage representation and must keep `retrieve_wasm_from_storage` and same-ledger/cache-miss paths on full XDR. That API work may be possible, but it does not change the severity conclusion for the soroswap objective.

### Lesson Learned

Large repeated byte volume is not enough to clear the apply-time threshold. For parallel Soroban bridge work, first bound the exact removable self-time, divide aggregate worker CPU by cluster parallelism, and compare the ContractCode-only subset against the 3% Medium floor before proposing a new storage/bridge representation.
