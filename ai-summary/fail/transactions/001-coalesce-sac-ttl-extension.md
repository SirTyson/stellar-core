# H001: Coalesce Repeated SAC Instance and Code TTL Extension

**Date**: 2026-04-28
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: reduce soroswap apply time by skipping duplicate same-key TTL-extension storage work inside repeated Stellar Asset Contract calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During Soroswap apply, every Stellar Asset Contract (SAC) call should still enforce the same footprint permissions, reject expired or missing instance/code entries, clamp persistent live-until values the same way, and produce the same final ledger changes. Repeated calls that request the same `(key, threshold, extend_to)` TTL extension for the same SAC contract during one host invocation should not redo storage lookups and map updates once an earlier successful extension has already proven the key valid and extended it to at least the requested target.

## Mechanism

Every SAC public entry point begins by calling `Host::extend_current_contract_instance_and_code_ttl`, and soroswap swaps call SAC `balance` and `transfer` repeatedly for the same small set of asset contracts. In the current headline soroswap trace, the longest `applyLedger` interval contains 163.662 ms of `extend_current_contract_instance_and_code_ttl` overlap at `soroban-env-common/src/vmcaller_env.rs:270`, 108.457 ms of its host dispatch at `soroban-env-host/src/vm/dispatch.rs:304`, and 111.768 ms of `extend key` overlap at `soroban-env-host/src/storage.rs:540`; aggregate self-time also shows `extend_current_contract_instance_and_code_ttl` at 89.549 ms, `storage get` at 88.783 ms, and `map lookup` at 411.627 ms. A per-host-invocation coalescing cache for successful TTL extensions can make subsequent identical SAC instance/code extension requests deterministic no-ops against the storage map, reducing repeated footprint enforcement, storage lookup, TTL computation, and immutable-map insert work without adding parallelism or changing transaction order.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap`, 4000 tx, 8 clusters) using `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`. The issue triggers in the steady 1.711 s `applyLedger` window when each swap repeatedly invokes SAC balance/transfer paths that extend the same contract instance and code TTLs.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:186-224` — SAC `balance` and `transfer` call `extend_current_contract_instance_and_code_ttl` before balance reads/writes.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2333` — `extend_current_contract_instance_and_code_ttl` extends both the current contract instance key and its Wasm code key.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:247-260` — `extend_contract_code_ttl_from_contract_id` reloads the contract instance to discover the executable and then extends code TTL.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:433-498` — `prepare_extend_ttl` performs supported-type checks, storage reads, live-until validation, max-TTL checks, and current-TTL computation.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:500-572` — `apply_ttl_extension` and `extend_ttl` update the immutable storage map when the current TTL is under threshold.

## Evidence

The target zones are descendants of `applyLedger`: the longest current soroswap apply interval contains 1,518 `InvokeHostFunctionOpFrame doParallelApply` calls, 3,042 `SAC transfer` calls, 3,039 `SAC balance` calls, and 6,083 `extend_current_contract_instance_and_code_ttl` events. Structurally, SAC uses fixed `INSTANCE_TTL_THRESHOLD` and `INSTANCE_EXTEND_AMOUNT` constants, so repeated extensions for the same current SAC contract in one transaction converge to the same `new_live_until = min(ledger_seq + extend_to, max_live_until)` and final storage state is the maximum live-until already enforced by `apply_ttl_extension`. Coalescing is local to a single host invocation and therefore preserves cluster determinism and stays within the existing `NUM_CLUSTERS` worker bound.

## Anti-Evidence

Budget accounting is consensus-visible: skipping storage/map operations changes resource consumption unless the optimization is protocol-gated as an intentional metering change or explicitly charges compatibility costs for skipped work. The already reviewed `002-fuse-enforcing-storage-footprint-lookups.md` may remove some of the same underlying `map lookup` time; this hypothesis remains distinct because it targets repeated SAC TTL-extension calls before they reach the generic storage lookup path. A PoC must also handle the case where the first extension is a no-op because the current TTL is already above threshold; subsequent skips are only safe after the code has established that the same key is live, in-footprint, and already satisfies the requested extension condition.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

The Soroban apply path constructs a fresh p26 host per invoke-host-function transaction, installs the transaction footprint-backed storage map, and invokes the router contract. The soroswap generator creates swaps with two SAC instance keys in the read-only footprint, one token-in transfer authorization, and pair/user balance keys in the read-write footprint; the router/pair execution shape plausibly accounts for the traced four SAC `extend_current_contract_instance_and_code_ttl` calls per swap, with each of the two SAC contracts extended twice. Each SAC `balance` or `transfer` enters the built-in SAC frame, calls `extend_current_contract_instance_and_code_ttl`, extends the instance key through `Storage::extend_ttl`, then reloads the same instance again only to discover `ContractExecutable::StellarAsset` and skip code TTL extension. The duplicate work exists, but a per-host cache can only skip the second same-SAC extension per token, not the first extension or cross-transaction repetitions.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swap generation creates one router invocation per transaction, includes exactly two SAC instance keys in the read-only footprint, and authorizes the token-in SAC transfer.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-507` — each invoke-host-function apply builds a fresh `Storage` and `Host`, calls `host.invoke_function`, then computes ledger changes from the final storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — `HostFunction::InvokeContract` enters `call_n_internal` for the router invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — each nested contract call retrieves the callee instance and dispatches `ContractExecutable::StellarAsset` calls through the built-in SAC frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:186-224` — SAC `balance` and `transfer` both call `extend_current_contract_instance_and_code_ttl` before their balance logic.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/storage_types.rs:4-6` — SAC instance extensions use fixed threshold and extend-to constants, so repeated calls use identical parameters.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2320-2334` — the host function gets the current contract ID, builds the instance key, extends instance TTL, then calls the code-TTL helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:75-87,113-130,247-264` — the instance key is metered-constructed, the instance is reloaded from storage, and SAC executables skip code-key extension after the reload.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-329,433-572,693-719` — TTL extension enforces read access through the footprint, reads the storage map, validates live-until and durability, computes the clamped target, and updates the immutable map only when current TTL is at or below threshold.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — footprint and storage lookups are budgeted binary searches with budgeted value access, which is the real repeated map work.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:190-229,404-562` — frame push/pop records rollback points and restores the storage map on failed frames, so any TTL coalescing cache would also need rollback-aware invalidation or storage-coupled state.

### Why It Failed

The inefficiency is real, but the projected recoverable work is below the optimize-soroswap objective's Medium severity threshold. The trace reports 6,083 SAC TTL-extension calls for 1,518 invoke-host-function calls in the longest apply interval, or almost exactly four SAC TTL calls per swap. The swap footprint and authorization shape indicate two SAC contracts per swap, so a successful same-key cache can skip only the second call for each SAC key: roughly half of the 163.662 ms cited TTL-extension overlap, not all of it.

With `NUM_CLUSTERS=8`, even an optimistic removal of about half the cited TTL-extension overlap is roughly 80 ms aggregate worker time, or about 10 ms wall-clock equivalent. Against the accepted current soroswap median baseline of 596.381 ms, that is about 1.7% before adding cache lookup overhead and before preserving or protocol-gating consensus-visible budget charges. This is a Low-tier projection, so the objective-specific rule requires rejection even though the local optimization idea is technically plausible.

The correctness constraints also reduce the practical removable portion. The cache cannot skip the host-function call itself or the first extension for each SAC key; it must remain rollback-aware because `with_frame` restores storage on failed frames, and it must either replay compatible metering or be a protocol-gated metering change. Those constraints make it less likely, not more likely, that the top-line apply-time delta reaches the 3% Medium floor.

### Lesson Learned

SAC TTL extension is a real repeated-work hotspot, but per-host coalescing must be evaluated on duplicate same-key calls within a single transaction, not on all SAC TTL-extension events across the ledger. For soroswap's current two-token swap shape, same-key coalescing removes at most about half of this already parallelized worker-time slice, which is below the objective threshold after normalization.
