# H001: Fast-Path SAC Transfer Events for Non-Issuer Address Shapes

**Date**: 2026-04-28
**Subsystem**: soroban / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in SAC-heavy host execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC `transfer` should emit the same `transfer`, `mint`, or `burn` event as today, but it should not read the SAC asset info and construct an issuer `Address` twice when the endpoint address shapes prove that neither endpoint can be the issuer. For example, if both endpoints are contract addresses, the issuer checks are impossible because SAC issuers are classic account IDs, so the event path should deterministically emit a `transfer` event without the two `read_asset_info` calls and two host-object comparisons.

## Mechanism

`event::transfer_maybe_with_issuer` currently calls `is_issuer(e, &from)` and then `is_issuer(e, &to)` for every transfer where `from != to`; each `is_issuer` reads `AssetInfo`, builds an issuer account `Address`, and compares host objects. Soroswap is SAC-transfer heavy, and the current trace shows `SAC transfer` as a hot apply descendant; specializing the event classification by decoding `from` and `to` once, then checking only account endpoints against a single decoded issuer, removes repeated storage/map/object work while preserving the exact event type.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) with the p26 host. Swaps call SAC `transfer` for token movements; transfers whose endpoints are not the issuing account still pay the generic issuer-detection path. A PoC should add a fast classification helper that decodes `from`/`to` to `ScAddress` once, handles native assets and contract-address endpoints without issuer reads, and otherwise reads `AssetInfo` at most once before comparing account IDs.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` invokes balance updates and then event classification.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-26` — `is_issuer` reads asset info and compares an issuer `Address` against one endpoint.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64` — `transfer_maybe_with_issuer` performs two independent issuer checks before choosing transfer/mint/burn.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:349-375` — `Address::compare` and `Address::to_sc_address` route through host-object access.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` — `read_asset_info` / `read_asset` load SAC asset metadata from instance storage.

## Evidence

The current soroswap trace reports `SAC transfer,soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs,212` at **1,186,494,193 ns total** over **3,082 calls** with **104,429,728 ns self-time**. The same trace shows broad host-object and map overhead inside `applyLedger` windows: `visit host object` has **1,104,960,760 ns** of contained event duration, `map lookup` has **619,797,065 ns**, and exact `charge` has **795,017,536 ns**. Source inspection ties part of this overhead to the SAC event path: the transfer path already updates balances, then `transfer_maybe_with_issuer` repeats metadata loads and object comparisons solely to distinguish issuer mint/burn events from ordinary transfers.

This is distinct from existing soroban records. Prior records cover TTL extension frequency, storage-map write rebuilding, redundant host-output XDR, InMemoryIndex lookup wrappers, and parallel-apply key hashing; none target SAC event issuer classification or eliminating impossible issuer checks based on endpoint address types.

## Anti-Evidence

The whole `SAC transfer` zone is not recoverable; balance reads/writes, auth, TTL extension, and event construction remain mandatory. Soroswap endpoint shapes must be confirmed in the generated workload because if many transfers involve account endpoints, the fast path may only remove one metadata read rather than both. The implementation must also preserve observable event classification for issuer sends/receives, native assets, muxed destinations, and `from == to` transfers.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The local code trace confirms the narrow inefficiency: non-self SAC transfers call `is_issuer` for `from` and then `to`, and each `is_issuer` reads `AssetInfo` from instance storage before constructing and comparing an issuer account `Address`. However, the soroswap benchmark shape is account-to-contract / contract-to-account, not contract-to-contract. Because one endpoint is a classic account, event classification still needs the SAC issuer information to distinguish ordinary transfers from issuer mint/burn events; the proposed shape fast path can skip at most the second issuer metadata read and contract-endpoint issuer comparison on the measured swap path. That saved work is a small subset of the `SAC transfer` zone and does not plausibly clear the objective's 3% Medium floor.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` performs auth, TTL extension, balance spend/receive, then calls `event::transfer_maybe_with_issuer`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:229-249` — `transfer_from` follows the same event helper after allowance and balance updates.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-26` — `is_issuer` does read `AssetInfo`, creates an issuer account `Address`, and compares it with the candidate endpoint.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64` — `transfer_maybe_with_issuer` first compares `from` and `to`, then can perform two independent issuer checks before emitting transfer/mint/burn.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-24` — `read_asset_info` looks up `InstanceDataKey::AssetInfo` through instance storage and decodes it to `AssetInfo`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2231-2263` — `get_contract_data(..., StorageType::Instance)` reads from the in-memory instance storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:1223-1231` and `src/rust/soroban/p26/soroban-env-common/src/compare.rs:127-145` — address comparison over object `Val`s delegates to host object visits and `HostObject` comparison.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:349-375` — `Address::compare` delegates to host `Val` comparison; `to_sc_address` would itself visit and clone the stored `ScAddress`.
- `src/simulation/ApplyLoad.cpp:3382-3505` — benchmark swap generation uses a unique source account as `from`, the pair contract as the token-in transfer destination, and footprints for the pair contract and user trustlines, so the hot-path SAC transfers are not both-contract endpoint transfers.
- `src/simulation/ApplyLoad.cpp:3327-3345` and `src/simulation/ApplyLoad.cpp:3484-3492` — generated auth trees explicitly model `transfer(root/account, pair)` in setup and `transfer(user account, pair)` in swaps, confirming account endpoints are common.

### Why It Failed

The inefficiency exists, but the benchmark does not exercise the high-value shape claimed by the hypothesis. For soroswap swaps, at least one endpoint is an account, so classification must still read the asset issuer once to preserve mint/burn-vs-transfer behavior. The remaining avoidable work is roughly one instance-storage metadata read plus one issuer-address construction/object comparison per SAC transfer; with only a few thousand `SAC transfer` calls per ledger, this is far below the aggregate worker-time reduction needed to move the current ~596 ms soroswap median by 3%. Additionally, removing these host operations directly would change component budget charging unless a PoC carefully replicated equivalent metering, further reducing any wall-clock gain.

### Lesson Learned

For SAC event optimizations, validate the benchmark endpoint shapes before projecting from total `SAC transfer` time. A hot parent zone can still contain mostly mandatory balance/auth/event work, and an optimization that only removes one instance-storage lookup per transfer is below the optimize-soroswap review threshold.
