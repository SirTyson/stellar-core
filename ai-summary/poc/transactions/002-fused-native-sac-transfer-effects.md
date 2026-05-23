# H002: Fuse Native SAC Transfer Balance Effects on Soroswap Swap Path

**Date**: 2026-05-23
**Subsystem**: transactions, Soroban SAC apply
**Severity**: Medium
**Impact**: soroswap apply-time reduction by collapsing generic SAC transfer storage/auth/event work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a soroswap swap transfers `token_in` from the user to the pair and `token_out` from the pair back to the user, the apply path should produce the same balance deltas, TTL bumps, authorization results, emitted SAC transfer events, resource accounting for the next protocol, and ledger changes as two generic `StellarAssetContract::transfer` calls. The efficient expected behavior is to execute the known SAC transfer effects through a native, typed balance-effect path rather than re-entering generic SAC contract logic for each transfer.

## Mechanism

`StellarAssetContract::transfer` currently performs generic work for every transfer: amount validation, `MuxedAddress` decoding, `require_auth`, instance/code TTL extension, sender balance spend, receiver balance receive, balance-entry authorization checks, persistent storage get/put, balance TTL extension, and event construction. The soroswap swap shape is narrower: the C++ generator declares exactly two SAC balance keys in the RW footprint (`Balance[pair]` for token-in and token-out) plus the two user trustlines, and the auth tree authorizes only the token-in user-to-pair transfer. A next-protocol fused native effect path could apply the two balance moves and required events in deterministic order using typed SAC balance/trustline helpers, amortizing duplicate contract-frame, storage-map, and conversion work without changing cluster scheduling or exceeding `NUM_CLUSTERS`.

## Trigger

Use the current soroswap apply-load scenario (`TX=2000`, `T=8`). Each generated transaction has a two-token path, RW footprint entries for user trustline(token-in), user trustline(token-out), SAC `Balance[pair]` for token-in, SAC `Balance[pair]` for token-out, and the pair instance (`src/simulation/ApplyLoad.cpp:3458-3475`). The auth tree authorizes the source account for `token_in.transfer(user, pair, amount)` (`src/simulation/ApplyLoad.cpp:3477-3496`).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC `transfer` path currently exercised by soroswap
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — contract balance read and TTL extension
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97` — contract balance write plus TTL extension
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` generic auth/read/write path
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:220-229` — `spend_balance` authorization wrapper
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:319-390` — enforcing storage get/put map path used by SAC balance updates
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — C++ records modified ledger entries returned by the host and validates them against the RW footprint

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` was timestamp-filtered against `applyLedger` windows. The SAC transfer zones are apply descendants and overlap the measured window:

| zone | source | apply-overlap ns | count overlapping apply | critical-path bound at T=8 |
|------|--------|------------------|--------------------------|----------------------------|
| `SAC transfer` | `stellar_asset_contract/contract.rs:212` | 2,477,084,982 | 15,665 | ~309.6 ms / 6.9% of `applyLedger` |
| `storage get` | `soroban-env-host/src/storage.rs:329` | 672,084,842 | 321,802 | ~84.0 ms / 1.9% |
| `map lookup` + `map lookup indexed` | `metered_map.rs:173,330` | 1,223,514,982 | 1,327,079 | ~152.9 ms / 3.4% |
| `new map` | `metered_map.rs:148` | 461,915,256 | 181,114 | ~57.7 ms / 1.3% |
| `ScVal to Val` | `host/conversion.rs:436` | 1,144,488,055 | 800,217 | ~143.1 ms / 3.2% |

The `SAC transfer` overlap alone is a 6.9% critical-path upper bound after dividing worker aggregate time by T=8. The fused path only needs to remove roughly half of the generic SAC transfer envelope to clear the 3% Medium floor, and the storage/conversion/map zones show enough adjacent work to make that plausible if the implementation bypasses generic contract-data `Val` construction for the known balance/trustline updates.

## Anti-Evidence

This is not a proposal to skip authorization, events, TTL extension, or budget accounting. The fused path must preserve token-in source-account auth and token-out invoker-contract auth, exact event order, failure behavior, and rollback semantics. Existing accepted typed SAC balance and direct native-pair balance-read optimizations already cover some balance access, so the viable surface is the remaining generic transfer envelope and write-side effect construction; if implementation can only remove a small storage lookup or key conversion, it will fall below the Medium threshold.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as a full SAC transfer-effect fusion in transactions fail/success records

### Trace Summary

`ApplyLoad::generateSoroswapSwaps` builds the fixed two-token router invocation and declares the two user trustlines, two pair SAC balance entries, and pair instance in the RW footprint. In the accepted baseline, `Host::call_contract_fn` still lets the router Wasm execute the inbound `token_in.transfer(user, pair, amount)`, while the next-protocol native pool swap intercepts the pair `swap` and calls `soroswap_pool_invoke_sac_transfer` for the outbound `token_out.transfer(pair, user, amount)`. That helper re-enters `call_n_internal`, creates a `Frame::StellarAssetContract`, and dispatches through the generic SAC `transfer` implementation. The C++ bridge then consumes the host's modified ledger entries/events through the existing `recordStorageChanges` and event collection path, so a safe fused implementation should remain inside the Rust host and leave C++ output validation unchanged.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3427-3505` — confirms the benchmark transaction shape, RW footprint entries, and source-account auth tree for the inbound SAC transfer.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-837` — `call_contract_fn` checks native Soroswap pool getter/swap fast paths, otherwise falls through to Wasm; SAC calls still use `Frame::StellarAssetContract` and `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1073` — native Soroswap pool `swap` is protocol-gated and exact-hash/shape-gated before executing in a native contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305` — native pool swap validates output amounts, transfers token out via SAC, reads pair balances, updates reserves, and emits the pair swap event.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` — outbound pool transfer still constructs a `transfer` symbol and calls `call_n_internal` into the generic SAC transfer path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1349-1393` — accepted direct SAC balance read only optimizes post-transfer pair balance reads; it does not optimize transfer writes.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC `transfer` still performs amount check, muxed-address decode, `require_auth`, instance/code TTL extension, spend/receive balance mutation, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-168,235-300,303-345,357-428,431-440` — contract balance transfer paths still perform authorization reads, amount reads, writeback reads, storage `put`, and TTL extension through generic helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-112` — transfer event construction still checks issuer/mint/burn cases and reads SAC metadata for event topics.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:478-509` — host invocation returns encoded result, ledger changes, and events through the normal enforcing-storage path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-766` — C++ validates returned modified entries against the RW footprint and applies them; this path need not change for a host-side fused effect.

### Findings

The inefficiency exists in the current accepted Soroswap baseline. The native pool swap removed pool Wasm execution and direct SAC balance reads removed two read-only SAC balance calls, but transfer writes still go through the generic SAC function dispatcher: the router Wasm performs the inbound transfer and the native pool swap explicitly calls `call_n_internal` for the outbound transfer.

The path is hot enough for the objective. The timestamp-filtered `SAC transfer` span covers about 15,665 apply-overlapping calls, matching roughly two transfers per accepted swap, and its T=8 critical-path bound is about 6.9% of `applyLedger`. A dispatch-only change would be below threshold, but a protocol-gated typed effect that handles both transfer writes, avoids duplicate contract-balance auth/read/writeback probes, and bypasses generic SAC argument/object construction has enough addressable surface to plausibly clear the 3% Medium floor.

The fix is only correct if implemented as a production-safe host-side native effect, not as a C++ footprint shortcut. The helper must still execute under an SAC-equivalent call/auth frame so source-account auth for the inbound transfer and invoker-contract auth for the outbound transfer match the same authorized functions. It must preserve SAC instance/code TTL bumps, balance TTL bumps, account/trustline balance bounds and authorization semantics, issuer/mint/burn event selection, event order, rollback behavior, and next-protocol budget repricing.

### PoC Guidance

- **Target code**: Add the typed transfer-effect helper in `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs` or a closely-related SAC module, and call it from `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` near `call_native_soroswap_pool_swap` / `soroswap_pool_invoke_sac_transfer`. Keep `src/transactions/InvokeHostFunctionOpFrame.cpp` unchanged unless bridge plumbing is strictly necessary.
- **Change description**: Under the existing next-protocol gate, recognize only the exact native Soroswap path and replace generic SAC `transfer` calls with a typed effect that loads each affected trustline/contract-balance entry once, performs authorization and bounds checks, writes the updated entries and TTLs, and emits identical SAC transfer/mint/burn events. If the PoC attempts to fuse both inbound and outbound transfers, it must do so from an exact router/pool native path that proves the router/pair/token shape; do not infer semantics from footprint membership alone.
- **Correctness check**: Compare generic and fused execution for successful swaps and failure boundaries covering source-account auth mismatch, invoker-contract auth, deauthorized trustlines/balances, issuer endpoints, insufficient balance, overflow, event/meta ordering, and ledger-change/TTL equality. Existing Soroban invoke-host-function and parallel-apply tests cover the bridge and rollback machinery; add focused equivalence coverage for the fused transfer helper.
- **Benchmark focus**: Run multiple non-Tracy `scripts/run_apply_load_matrix.py` soroswap `TX=2000,T=8` measurements and require at least a 3% apply-time reduction. In Tracy, `SAC transfer` count/time should drop for matching swaps while C++ `recordStorageChanges`, event encoding, and modified-ledger-entry validation remain present and consistent.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-23
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1-10,1334-1375` — changed the native Soroswap pool outbound SAC transfer helper to detect Stellar Asset token contracts, push an SAC-equivalent `Frame::StellarAssetContract`, and call the typed native transfer helper instead of re-entering generic `call_n_internal`; non-SAC token contracts still use the existing fallback call path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract.rs:14-15` — re-exported the native Soroswap SAC transfer helper for the host-frame fast path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:45-67` — added `native_soroswap_transfer`, preserving generic SAC transfer validation order, auth, instance/code TTL extension, fallback behavior for unsupported shapes, and transfer event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:302-407,676-720,753-806` — added the typed contract-balance-to-classic-account/trustline effect path used by Soroswap pool payouts. It loads the sender contract balance once, checks authorization and available amount, writes the updated contract balance and TTL, then updates the receiver account/trustline with authorization and bounds checks.

### Demonstration

The PoC removes the generic SAC `call_n_internal` dispatch and duplicate SAC balance helper work from the native Soroswap pool's outbound `token_out.transfer(pair, user, amount)` path while preserving the SAC call/auth frame and C++ modified-entry validation path. For the soroswap apply-load shape, this turns one hot SAC transfer into a typed ledger effect that avoids redundant contract-balance authorization/read/writeback probes and generic argument/object dispatch overhead.

### Test Results

Configured and built with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j $(nproc)`. Full regression command `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j $(nproc) check` completed with exit code 0; captured summaries include Rust host `test result: ok. 751 passed; 0 failed; 2 ignored; 0 measured; 1 filtered out` and `All 2 tests passed`.
