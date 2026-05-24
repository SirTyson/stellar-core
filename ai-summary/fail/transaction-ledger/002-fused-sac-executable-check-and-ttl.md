# H002: Fuse direct SAC executable check with instance TTL extension in native pair balance reads

**Date**: 2026-05-24
**Subsystem**: transaction-ledger / Soroban host native Soroswap path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing one token-instance storage lookup from each direct native pair SAC balance read
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The native Soroswap pair direct SAC balance path should preserve SAC `balance(pair)` semantics for Stellar Asset Contract tokens: it must fail or fall back for non-SAC executables, extend the token contract instance TTL when appropriate, read the pair contract-balance entry, extend that balance TTL, and return the same `i128` balance. It should not need to fetch the token contract instance twice when the first fetch already proves the executable is `StellarAsset`.

## Mechanism

`soroswap_pool_read_sac_contract_balance` first calls `contract_instance_executable_is_stellar_asset(&instance_key)`, which performs `Storage::get` on the token instance and inspects `ScContractInstance.executable`. If that returns true, the same function immediately calls `extend_contract_instance_ttl_from_contract_id(instance_key, ...)`, which clones the key and calls `Storage::extend_ttl`; `extend_ttl` calls `prepare_extend_ttl`, which performs another `get_with_live_until_ledger` on the same token instance entry before computing whether the TTL should change. A native-pair-only helper can fetch the token instance entry once with its live-until value, verify `ContractExecutable::StellarAsset`, and apply the same TTL threshold/clamp/update logic to that entry, preserving the final storage map contents while eliminating the duplicate footprint/storage-map lookup and instance-entry clone.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md`. Each successful native pair `swap` calls `soroswap_pool_invoke_sac_balance` for both token contracts after the output transfer; when the token is a Stellar Asset Contract and the owner is the pair contract, the direct balance path executes `soroswap_pool_read_sac_contract_balance` and performs the executable check followed by the instance TTL extension on the same token instance key.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1175-1176` — native pair swap reads both token balances after output transfer.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1365` — `soroswap_pool_invoke_sac_balance` dispatches to the direct SAC balance path before falling back to a child SAC `balance` call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1368-1392` — `soroswap_pool_read_sac_contract_balance` performs executable check and then a separate instance TTL extension on the same `instance_key`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:122-160` — `contract_instance_executable_is_stellar_asset` reads the token instance to inspect only the executable discriminant.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:307-320` — `extend_contract_instance_ttl_from_contract_id` delegates to `Storage::extend_ttl`, causing the second same-key read.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:531-598,646-687` — `prepare_extend_ttl` and `extend_ttl` contain the TTL validation, threshold, clamp, and update logic the fused helper must preserve.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:180-199` — direct contract-owner balance read and balance TTL extension that should remain unchanged after the token-instance lookup is fused.

## Evidence

The target runs under `applyLedger`: in the current soroswap trace, `storage get` contributes **672.075 ms total** across **321,796** start-in-`applyLedger` events, `extend_current_contract_instance_and_code_ttl` contributes **340.374 ms total** across **15,684** start-in-`applyLedger` events, `SAC transfer` contributes **2,477.085 ms total**, and `call` contributes **5,134.323 ms total**. The source shows a concrete same-key sequence in the direct SAC balance helper: check token instance executable, then extend the same token instance TTL, then read the pair balance. Fusing only the first two steps targets a redundant storage access introduced by the accepted direct SAC balance path without bypassing SAC transfer, auth frames, balance TTL extension, event emission, or ledger-change extraction.

The change is deterministic: the helper still sees the same token instance entry from enforcing storage, applies the same live-until validation and clamping rules, and writes the same TTL entry if the threshold is met. It does not add parallelism or change observable transaction ordering.

## Anti-Evidence

This hypothesis only removes duplicate token-instance work around direct native pair balance reads; it does not remove the mandatory contract-balance read, balance TTL extension, output SAC transfer, or event/result serialization. The PoC must isolate calls from `soroswap_pool_read_sac_contract_balance` rather than citing the full `storage get` or `extend key` categories, and must protocol-gate any metering-profile change caused by replacing two metered helper calls with one fused helper.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no exact prior fail/success record for fusing the direct SAC executable peek with that same token instance's TTL extension
**Failed At**: reviewer

### Trace Summary

The native Soroswap pool swap path is real and hot: the hash-gated native pair executor performs output SAC transfers, then reads both pair token balances through `soroswap_pool_invoke_sac_balance`. For contract-owner SAC balances, `soroswap_pool_read_sac_contract_balance` builds the token instance key, reads that instance once to confirm `ContractExecutable::StellarAsset`, then calls `extend_contract_instance_ttl_from_contract_id`, which reaches `Storage::extend_ttl` and reads the same key again with its live-until ledger. The redundant same-key read exists, but current enforcing storage already uses side-indexed lookups, and the removable subset is one in-memory storage-map access per direct pair balance read, not the TTL validation/update or balance read/extension work.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-837` — `call_contract_fn` dispatches Wasm pool calls into hash-gated native Soroswap hooks and SAC token calls into `Frame::StellarAssetContract`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1074` — native pool `swap` gate validates protocol, hash, symbol, argument shape, and pair instance layout before entering a native contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1158-1176` — native pair `swap` performs any positive output SAC transfer and then calls `soroswap_pool_invoke_sac_balance` for both token balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1392` — direct SAC balance dispatch checks whether the owner is a contract, constructs `instance_key`, peeks at the token executable, extends the same instance key's TTL, and then reads the pair balance.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:136-160` — `contract_instance_executable_is_stellar_asset` calls `Storage::get` and inspects only the `ScContractInstance.executable` discriminant.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:307-320` — `extend_contract_instance_ttl_from_contract_id` clones the key and delegates to `Storage::extend_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-416` — storage reads funnel through `try_get_full_helper`; in enforcing mode the current tree uses precomputed footprint/storage indices before cloning the stored `(entry, live_until)` pair.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:531-687` — TTL extension still must check key support, retrieve live-until state, validate liveness/durability, clamp persistent TTLs, apply the threshold, and update the storage map only when needed.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:180-199` — after token-instance handling, the direct contract-owner balance path still performs the contract-balance storage read and balance TTL extension.

### Why It Failed

The claimed duplicate lookup is technically present, but it is much too small for the optimize-soroswap objective. Each direct pair balance read can at most remove the first token-instance storage-map lookup by replacing the executable peek with a get-with-live-until variant; the actual instance TTL semantics, possible storage-map update, contract-balance read, balance TTL extension, output SAC transfer, auth, diagnostics, and event work all remain mandatory.

The hypothesis's own trace numbers bound the opportunity below the Medium floor. `storage get` averages about 2.1 microseconds of aggregate worker time per event (`672.075 ms / 321,796`), and even if every `15,684` relevant balance-side instance extension event represented a removable duplicate read, that is only about 33 ms of aggregate worker time, or roughly 4 ms after `NUM_CLUSTERS=8` normalization. Against the cited 4.48 s apply window this is far below 1%, and the current side-indexed enforcing-storage fast path makes the per-lookup work even less compelling. Related prior TTL-fusion failures in `ai-summary/fail/transaction-ledger/summary.md` also found the entire `extend key`/SAC TTL family below threshold before filtering to this narrower token-instance subset.

### Lesson Learned

Same-key TTL fusion can be structurally correct while still being below the objective threshold. For this benchmark, direct SAC balance reads already avoid the expensive child `balance` call; remaining token-instance executable/TTL plumbing must be sized from narrow per-site counts and cluster-normalized in-memory lookup cost, not from broad `storage get` or TTL aggregate zones.
