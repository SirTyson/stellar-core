# H002: Protocol-gate actual-cost indexed enforcing-storage replacements

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / Soroban host storage
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing legacy replacement-map metering from indexed storage writes and TTL extensions
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When enforcing storage already has a side-index position for a read-write key, next-protocol storage writes and TTL extensions should replace the known slot deterministically and charge the actual indexed replacement cost. They should preserve ledger effects, key ordering, and footprint enforcement, but should not continue to charge the p26 `insert`/`from_map` compatibility profile for work that the indexed path no longer performs.

## Mechanism

`Storage::put_opt_helper` and `Storage::apply_ttl_extension` use `enforce_storage_idx` to call `MeteredOrdMap::insert_at_known_position` for existing keys. That helper still charges the old top-level access, old binary-search lookup, deep-clone, and full scan costs to match `insert` plus `from_exact_iter`/`from_map`, even though the key position is known and sort-order verification is skipped by construction. Under a new protocol version, the host can define a cheaper deterministic indexed-replacement charge for these enforcing-storage updates, reducing repeated SAC balance writes and TTL extensions in soroswap without changing the final `StorageMap` content or observable write order.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). Each swap performs SAC balance mutations and TTL extensions under `SAC transfer`; contract balance writes enter `Storage::put`, and balance/instance TTL maintenance enters `Storage::extend_ttl`, both of which can take the indexed replacement path when the key is already in the enforcing storage map.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-456` at accepted p26 commit `fa1226b3` — `put_opt_helper` enforces read-write access and calls `insert_at_known_position` when the storage side index has the key.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:600-628` at accepted p26 commit `fa1226b3` — `apply_ttl_extension` uses the same indexed replacement path for TTL updates.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:350-385` at accepted p26 commit `fa1226b3` — `insert_at_known_position` preserves the legacy replacement budget profile while replacing a known position.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:212-277` at accepted p26 commit `fa1226b3` — SAC contract-balance writes construct updated `ContractData` entries, call `Storage::put`, then extend the same balance TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` at accepted p26 commit `fa1226b3` — `transfer` invokes `spend_balance`, `receive_balance`, and event generation for every soroswap token-leg transfer.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — these SAC writes execute under `InvokeHostFunctionOpFrame::doParallelApply`, an `applyLedger` descendant.

## Evidence

- Tracy timestamp filtering against the seven long `applyLedger` windows in the current soroswap trace shows the write-side and TTL path is still large enough to matter: `SAC transfer` totals **2,152,137,511 ns** worker time (**307.448 ms aggregate per long window**), `extend_current_contract_instance_and_code_ttl` totals **959,636,217 ns** (**137.091 ms aggregate per long window**), `new map` totals **448,726,196 ns** (**64.104 ms aggregate per long window**), and `storage put` totals **119,071,887 ns** (**17.010 ms aggregate per long window**).
- `insert_at_known_position` explicitly documents that it is matching `insert`'s top-level access charge, matching the `find` binary-search charge, charging the deep clone, and matching `from_map`'s scan charge. Those charges are compatibility work once the side index has established the replacement position.
- The mechanism is narrower than the rejected journaled-storage-map redesign: it does not change storage representation, rollback semantics, or deterministic map ordering. It only changes the protocol-gated cost model and budget calls for the existing indexed replacement helper.
- The mechanism is also distinct from prior SAC balance-context attempts. It does not add transfer-local context allocation or extra indirection; it reduces the cost of the storage update primitive already used by the accepted typed SAC balance path and by generic enforcing storage updates.

## Anti-Evidence

- The current p26 metering contract must remain exact. A PoC has to keep the legacy charges for protocol 26 and only use actual-cost indexed replacement for a future protocol.
- `new map` includes generic `MeteredOrdMap` construction outside storage replacements, and `SAC transfer` is inclusive of auth, events, and storage work. A reviewer should add narrow counters around `insert_at_known_position` before attributing the full zone totals to this hypothesis.
- If the dominant cost of `insert_at_known_position` is actual vector reconstruction rather than the legacy budget charges, this protocol-gated metering refinement may fall below Medium unless combined with a separately safe representation change.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related storage-map write and indexed-read variants exist in `fail/transaction-ledger`, but this exact protocol-gated write-metering claim was not previously investigated
**Failed At**: reviewer

### Trace Summary

The close-ledger path reaches this code through protocol 23+ parallel Soroban apply: `InvokeHostFunctionOpFrame::doParallelApply` invokes the Rust host, SAC `transfer` mutates contract balances, and `write_contract_balance` writes the updated `ContractData` through `Storage::put` before extending the balance TTL. In enforcing mode, `Storage::put_opt_helper` and `Storage::apply_ttl_extension` can both use the side index and call `MeteredOrdMap::insert_at_known_position`. That helper does preserve p26 compatibility charges, but it also still performs the actual vector reconstruction for the replacement; a metering-only protocol change can only remove the compatibility budget bookkeeping, not the dominant allocation/copy work.

### Code Paths Examined

- `ai-summary/fail/transaction-ledger/summary.md:24` — prior in-place storage-map update review found the full write-side `new map` removal upper bound below the objective threshold after cluster normalization.
- `ai-summary/fail/transaction-ledger/001-protocol-gated-indexed-storage-read-metering.md:52-76` — the analogous indexed-read metering change was rejected because the whole indexed lookup span was only a tight upper bound and the removable compatibility charge was smaller than the Medium floor.
- `ai-summary/CURRENT_STATE.md:46-63` — the accepted current baseline averages 272.895607 ms, so the objective's 3% Medium floor is about 8.19 ms per ledger.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — soroswap Soroban transactions execute via `doParallelApply`, making worker-local SAC storage writes descendants of `applyLedger`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:490-523` — each invocation constructs enforcing `Storage` from the footprint and initial storage map before creating the host.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:245-267` — enforcing storage builds `enforce_storage_idx`, and comments state the storage key set remains fixed while writes only replace existing entries.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:418-457` — `put_opt_helper` enforces read-write access, then replaces an indexed existing key with `insert_at_known_position`; otherwise it falls back to `insert`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:531-598` — TTL extension first reads the existing entry through `get_with_live_until_ledger`, so not all TTL-zone time belongs to the replacement write.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:600-628` — `apply_ttl_extension` uses the same indexed replacement helper only when the computed TTL actually extends the entry.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83` — `charge_access`, `charge_scan`, and `charge_binsearch` are budget charges implemented as `MemCpy` budget calls.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-224` — the legacy `insert` path charges top-level access, runs `find`, and rebuilds a vector through `from_exact_iter`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:350-385` — `insert_at_known_position` skips the binary search and sort-order verification but still clones all preserved elements into a new vector, charges the deep clone, and charges a compatibility scan.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` extends current contract instance/code TTL, spends one balance, receives another balance, and emits the transfer event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:212-277` — existing contract-balance writes clone and edit the `ContractData` entry, call `Storage::put`, then call `extend_contract_balance_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/budget.rs:238-287` and `src/rust/soroban/p26/soroban-env-host/src/budget.rs:1400-1407` — each removed budget charge saves tracker updates, cost-model arithmetic, and limit checks, but not the storage-map vector allocation/copy itself.

### Why It Failed

The inefficiency exists, but the projected impact is below the optimize-soroswap Medium threshold. The hypothesis's own current-trace evidence gives `storage put` at only 17.010 ms aggregate worker time per long apply window, which is about 2.13 ms after T=8 cluster normalization; this entire span is already far below the 8.19 ms Medium floor. The broader `new map` total is 64.104 ms aggregate per long window, or about 8.01 ms after T=8 normalization, but that is still slightly below the floor before subtracting non-target map construction, actual `Vec` allocation and element cloning in `insert_at_known_position`, mandatory entry construction, and TTL/read work. A protocol-gated actual-cost metering change can safely remove only compatibility budget charges such as the old binary-search and validation-scan charges; it cannot claim the actual replacement-map reconstruction cost without becoming a separate representation or in-place-update redesign, a class already reviewed as sub-threshold.

### Lesson Learned

For storage-write metering hypotheses, separate consensus-visible budget bookkeeping from actual data-structure work. If the full traced storage write or map-construction span barely reaches the Medium floor before cluster normalization and target isolation, the protocol-gated charge subset is not a viable soroswap apply-time optimization on its own.
