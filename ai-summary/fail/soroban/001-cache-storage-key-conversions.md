# H001: Cache Enforcing-Mode Storage Key Conversions Within a Host Invocation

**Date**: 2026-04-29
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in persistent storage host functions
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a deterministic contract storage key value that is used repeatedly within one Soroban host invocation, the host should derive the corresponding `Rc<LedgerKey>` once and reuse it for subsequent enforcing-mode storage operations in the same host. The optimization must preserve the same observable storage result, diagnostics, and budget accounting as the current `storage_key_from_val` path: converting a key to a `LedgerKey`, rejecting muxed-address storage keys, and charging equivalent conversion/clone/visit work must remain protocol-identical.

## Mechanism

The current p26 host reconstructs a full `LedgerKey` on every persistent/temporary `has_contract_data`, `get_contract_data`, `put_contract_data`, `del_contract_data`, and TTL-extension call by routing through `Host::storage_key_from_val` (`host/conversion.rs:156-166`). That path converts the key `Val` back into an owned `ScVal` via `from_host_val_for_storage` (`host/conversion.rs:422-432`) and then allocates a fresh `Rc<LedgerKey>`, even when the same key object is reused in a SAC balance/allowance/update sequence. A per-`Host` memo keyed by `(current_contract_id, durability, Val payload)` or a narrow typed fast path for storage-key object handles would avoid repeated structural conversion and allocation while still replaying the exact budget charges required by the existing conversion path.

## Trigger

Run the current soroswap apply-load benchmark. Each swap executes SAC-heavy storage traffic: balance checks and balance updates repeatedly call `has_contract_data`, `get_contract_data`, and `put_contract_data` over small `ScVal` keys containing symbols and addresses. In the current soroswap Tracy trace, apply-contained storage host functions account for `get_contract_data` **1000.265 ms**, `has_contract_data` **503.453 ms**, `put_contract_data` **310.447 ms**, `storage get` **847.123 ms**, and storage-key `Val to ScVal` conversion at `host/conversion.rs:423` **217.352 ms**.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:156-166` — `storage_key_from_val` always converts a key `Val` into an owned `ScVal` and then into a new `Rc<LedgerKey>`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:422-432` — storage-key `Val` to `ScVal` conversion toggles the storage-key conversion flag and recursively visits host objects on every call.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2242` — persistent/temporary `put_contract_data`, `has_contract_data`, and `get_contract_data` all call `storage_key_from_val` before touching storage.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-266` — storage reads then perform metered map lookup over the reconstructed key.

## Evidence

The headline soroswap trace from `ai-summary/CURRENT_STATE.md` verifies these zones are descendants of the `applyLedger` window through `InvokeHostFunctionOpFrame::doParallelApply` and Rust `invoke_host_function`. `storage_key_from_val` is not separately zoned, but the trace shows a dedicated `Val to ScVal` zone at `host/conversion.rs:423` consuming **217.352 ms** inside apply, and the call sites that require this conversion are hot: `get_contract_data` appears **86,580** times, `has_contract_data` **60,073** times, and `put_contract_data` **13,431** times. The workload reuses the same logical keys within a transaction: SAC `transfer` spends one balance, receives another, emits events, and nearby `balance`/`authorized` calls use the same address-shaped storage keys.

The potential win is broader than the 217 ms conversion span alone. Reusing a canonical `Rc<LedgerKey>` per invocation also avoids repeated `LedgerKey` allocation, repeated `ScVal` deep clone for address/vector keys, and some downstream comparison work in the enforcing `StorageMap`/`FootprintMap` binary searches. The optimization is deterministic because the cache is local to one `Host`, populated from immutable key values, and cannot alter storage contents or observable ordering.

## Anti-Evidence

This path is metering-sensitive. A cache that simply skips `from_host_val_for_storage` would reduce CPU/memory budget consumption for transactions with repeated keys and would be protocol-visible, so a PoC must either replay the exact charges for cached conversions or implement a typed fast path with identical charging and error behavior. The already-failed "single lookup try-get" investigation shows that storage-access optimizations can be rejected when they remove metered work. The actual repeated-key rate in soroswap must also be measured; if most `Val` handles are newly allocated per call, the cache will collapse to a low-impact allocation cleanup.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as a storage-key-conversion cache; related storage-map and has/get duplicate-read investigations do not target `from_host_val_for_storage` caching
**Failed At**: reviewer

### Trace Summary

The conversion path exists as described: persistent and temporary contract-data host functions reconstruct an `Rc<LedgerKey>` by converting the incoming key `Val` to `ScVal`, combining it with the current contract ID, and then probing enforcing storage. However, the SAC hot path does not generally reuse the same key object across balance update phases: helpers repeatedly call `key.try_into_val(e)?`, which creates fresh host object handles for the same logical `DataKey`. A memo keyed by `Val` payload therefore mainly hits the intentional `try_get_contract_data` `has_contract_data` -> `get_contract_data` pair, while broader structural caching would need conversion-like traversal plus exact metering replay before it could identify equivalent newly-created keys.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-452` — enforcing invocations build the footprint and storage map, then create a `Host` with `Storage::with_enforcing_footprint_and_map`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-166` — `storage_key_from_val` calls `from_host_val_for_storage` and allocates a new metered `Rc<LedgerKey>` through `storage_key_from_scval`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:422-432` — storage-key conversion toggles `storage_key_conversion_active`, runs `ScVal::try_from_val` under the depth limit, and checks representability.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-538` — object conversion recursively visits host objects, metered-clones vectors/maps/addresses, and rejects muxed addresses only while the storage-key flag is active.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2242,2268-2317,2390-2417` — persistent/temporary `has`, `get`, `del`, and TTL extension all convert the supplied `Val` before storage access.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:509-560` — `put_contract_data_into_ledger` converts the key once for lookup/update and, for new entries, separately converts the key again for the stored `ContractDataEntry`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — `try_get_contract_data` passes the same `Val` first to `has_contract_data` and then to `get_contract_data` on successful reads, the clearest same-handle cache-hit case.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-96,120-145,172-199,233-254` — SAC balance helpers rebuild `DataKey::Balance(...).try_into_val(e)?` at separate read, write, authorization, and TTL-extension call sites.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/allowance.rs:15-107` — allowance read/write paths similarly rebuild the logical allowance key for the try-get, put, and TTL-extension phases.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-357,421-429,431-574` — storage reads, writes, has, and TTL extension use the reconstructed key for footprint enforcement and storage-map operations.

### Why It Failed

The optimization is below the objective severity threshold. The real same-`Val` cache-hit surface is mostly the successful `try_get_contract_data` double conversion, which is a subset of the already-rejected has-then-get storage duplicate work and cannot plausibly clear the 3% Medium floor by itself. The larger "same logical key" opportunity is not available to a `(contract, durability, Val payload)` cache because SAC helpers create fresh object handles with `key.try_into_val(e)?`; catching those would require a structural key cache that first traverses the host object graph enough to identify the key, while also replaying the exact conversion, clone, visit, muxed-address rejection, and depth-limit metering. Once those correctness constraints are included, the hypothesis no longer has a credible Medium projection for soroswap apply time.

### Lesson Learned

For host storage keys, distinguish exact `Val`-handle reuse from logical key reuse. SAC code often reuses a Rust `DataKey` variable but converts it to a new host object at each call site, so handle-keyed host caches collapse to the has/get pair; structural caches must prove they avoid more work than they spend on traversal and exact metering replay before being considered Medium.
