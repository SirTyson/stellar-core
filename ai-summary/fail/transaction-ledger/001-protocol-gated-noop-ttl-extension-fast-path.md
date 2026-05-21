# H001: Protocol-Gated No-Op TTL Extension Fast Path

**Date**: 2026-05-21
**Subsystem**: transaction-ledger / Soroban host storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by skipping storage-map reads and entry clones for persistent TTL extensions that provably do not change state
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a persistent Soroban ledger entry already has `live_until_ledger_seq` farther away than the requested TTL extension threshold, `Storage::extend_ttl` should enforce that the key exists in the transaction footprint and then return without touching the storage map value. The ledger output should be unchanged: no TTL ledger entry should be emitted, no rent change should be charged, and the final storage map should remain byte-for-byte equivalent to the pre-call map.

## Mechanism

The current enforcing-storage path always enters `Storage::prepare_extend_ttl`, which calls `get_with_live_until_ledger`, performs footprint/storage lookup, clones the `EntryWithLiveUntil`, computes durability and max-live-until, and only then discovers that `current_ttl > threshold` and therefore no extension is applied. For the current soroswap workload most `extend_current_contract_instance_and_code_ttl` and SAC balance TTL calls are persistent-entry maintenance calls on hot contracts/balances that are normally far above the threshold, so the actual behavior spends apply time proving a no-op repeatedly.

Under the next-protocol host-metering gate, enforcing `Storage` can add a persistent-only fast path before `prepare_extend_ttl`: use the existing enforcing storage index/known storage position to read only the stored `live_until_ledger_seq`; if the key is present, persistent, non-deleted, and `live_until_ledger_seq.saturating_sub(ledger_seq) > threshold`, return `Ok(())` immediately. This keeps deterministic ledger effects and stays within one cluster worker; it only changes protocol-visible metering for ledgers that have explicitly opted into the next-protocol coalesced-metering model.

## Trigger

Run the current soroswap apply-load diagnostic trace from `ai-summary/CURRENT_STATE.md`:

`/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`

The seven long `applyLedger` windows contain 47,320 `extend_current_contract_instance_and_code_ttl` events totaling 959.6 ms and 304,187 `storage get` events totaling 640.7 ms. Normalized by 7 measured long ledgers and 8 soroswap clusters, the current-contract TTL maintenance envelope is about 17.1 ms/ledger on the critical worker path; skipping even half of the no-op persistent extensions clears the current ~8.2 ms Medium floor for a 272.9 ms soroswap median.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:431-573` — `prepare_extend_ttl` and `extend_ttl` currently fetch the full entry and compute max/durability before checking whether the extension threshold is met.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:250-267` — accepted current-state `Storage::with_enforcing_footprint_and_map` already builds a key-to-position index that can support a known-position no-op check.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-224` — every SAC transfer extends the current contract instance/code TTL before balance mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:170-177,276-277` — accepted typed SAC balance helpers still call `Storage::extend_ttl` after balance reads/writes.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-523` — each host invocation receives the encoded TTL entries and constructs enforcing storage before execution.

## Evidence

- Tracy scope check: `extend_current_contract_instance_and_code_ttl` and `storage get` events counted above are descendants of `applyLedger` through `applyParallelPhase` -> `applySorobanStageClustersInParallel` -> `InvokeHostFunctionOpFrame doParallelApply`; they are not TX-set construction or background bucket work.
- Source inspection shows `extend_ttl` only mutates the map in `apply_ttl_extension` when `current_ttl <= threshold`; otherwise all earlier `prepare_extend_ttl` work is discarded.
- The current accepted stack already introduced enforcing-storage side indices for storage lookups, so a fast presence/live-until check can be local to enforcing mode and does not require new cross-thread state or more than `NUM_CLUSTERS` workers.
- This is broader than prior SAC-balance-only TTL fusion: it targets all persistent no-op TTL extensions, including current contract instance/code TTL maintenance and balance TTL maintenance, and is gated on the no-op condition rather than carrying one balance read into one balance write.

## Anti-Evidence

- If apply-load initializes TTLs close to the extension threshold, the fast path will rarely fire and the hypothesis collapses to the previously rejected narrow TTL-fusion variants. A PoC should add a temporary counter for `(persistent, present, current_ttl > threshold)` hits before relying on the full Tracy envelope.
- Public `extend_ttl` semantics for temporary keys must stay on the existing path because `prepare_extend_ttl` can raise `InvalidAction` for `extend_to > max_ttl` even when no extension would be applied. The proposed fast path should be persistent-only.
- Budget accounting is protocol-visible. The optimization should be enabled only under the next-protocol host-metering gate, with tests documenting the lower instruction/memory counts for successful no-op persistent extensions.
---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related SAC TTL-fusion and storage-map lookup variants were previously investigated, but this exact persistent no-op TTL fast-path hypothesis was not present as an individual target-subsystem verdict
**Failed At**: reviewer

### Trace Summary

The Soroban parallel apply path reaches Rust host execution through `LedgerManagerImpl::applyParallelPhase` -> `applySorobanStageClustersInParallel` -> `applyThread` -> `InvokeHostFunctionOpFrame::doParallelApply` -> `rust_bridge::invoke_host_function` -> `e2e_invoke::invoke_host_function_with_trace_hook_and_module_cache`. Enforcing storage is built from the transaction footprint and encoded ledger/TTL entries, then SAC methods repeatedly call `extend_current_contract_instance_and_code_ttl` and balance helpers call `extend_contract_data_ttl`. `Storage::extend_ttl` does perform the no-op check only after `prepare_extend_ttl` loads the entry and live-until value, but the claimed fast path depends on an existing key-to-position side index that is not present in the p26 source. Without such an index, a correct no-op check still must enforce the footprint and look up the storage-map value to read `live_until_ledger_seq`, so it only avoids an `Rc` clone and a few scalar checks, not the dominant lookup path.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2966-3020` — builds parallel Soroban apply clusters inside `applyParallelPhase`.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` and `2530-2565` — worker threads call `TransactionFrameBase::parallelApply` for each cluster and join via futures.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — `InvokeHostFunctionOpFrame::doParallelApply` delegates to the parallel apply helper.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:556-585` — helper serializes invocation inputs and calls `rust_bridge::invoke_host_function`.
- `src/rust/src/soroban_proto_any.rs:430-488` — Rust bridge invokes the host, computes rent changes, and extracts ledger effects.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:431-452` and `959-1049` — enforcing storage is constructed from encoded ledger and TTL entries; `StorageMap` stores `(Rc<LedgerEntry>, Option<u32>)` values and no side index.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:233-239` — `Storage::with_enforcing_footprint_and_map` only stores `mode`, `footprint`, and `map`; it does not build the claimed key-to-position index.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-329` and `431-573` — `prepare_extend_ttl` calls `get_with_live_until_ledger`; no-op detection happens later in `extend_ttl` after the map lookup, shallow `Rc` clone, durability/max-TTL checks, and overflow-sensitive `new_live_until` computation.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:700-717` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154` — enforcing-mode access requires a footprint `MeteredOrdMap` lookup before storage access.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — `MeteredOrdMap::get` performs a metered binary search and returns a borrowed value; the clone in `try_get_full_helper` is only cloning `Option<(Rc<LedgerEntry>, Option<u32>)>`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2334` and `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-264` — current-contract instance/code TTL maintenance must still retrieve the instance to discover the Wasm code hash before extending code TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-224` and `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-57,74-96` — SAC transfer and balance paths do call the TTL helpers frequently, but their surrounding reads/writes and required instance/code discovery remain.
- `ai-summary/fail/transaction-ledger/summary.md:42` and `69` — closest prior records show the broader storage-map lookup fast path and narrower SAC balance TTL fusion are sub-Medium after objective normalization; this hypothesis would affect only a subset of those lookup costs.

### Why It Failed

The specific mechanism is not present: enforcing `Storage` has no existing key-to-position side index to reuse. A correct persistent no-op check in the current implementation must still do the two expensive operations the hypothesis hoped to skip — footprint enforcement and a storage-map lookup — in order to prove that the key is in-footprint, present, persistent, non-deleted, live, and above threshold. The remaining removable work is an `Rc` clone plus small scalar checks, and even the broader previously-recorded storage-map lookup opportunity is below the optimize-soroswap Medium threshold; this narrower TTL no-op subset cannot plausibly reach the required 3% apply-time reduction. It also cannot simply return before all current checks: `extend_ttl` currently preserves `threshold <= extend_to`, live-entry validation, persistent clamping/overflow behavior, and temporary-entry max-TTL errors.

### Lesson Learned

No-op TTL extensions are a real pattern, but a viable Medium finding needs a measured mechanism that removes more than the already-sub-Medium storage-map lookup cost. Future TTL hypotheses should first instrument the exact no-op hit rate and isolated self-time after existing lookup optimizations, then target a broader protocol-gated metering redesign or a fused caller path that avoids redundant required reads without changing budget/error semantics.
