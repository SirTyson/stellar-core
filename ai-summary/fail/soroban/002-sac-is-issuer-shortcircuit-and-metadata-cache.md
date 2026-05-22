# H002: Short-Circuit `is_issuer` for Contract Addresses and Cache `read_name` in SAC Event Emission

**Date**: 2026-05-22
**Subsystem**: soroban (built-in SAC, event emission)
**Severity**: Medium
**Impact**: apply-time reduction (soroswap, contract-to-contract SAC transfer hot path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For SAC `transfer(from, to, amount)` between two **contract** addresses (the
soroswap pool↔user case), the host should:

1. Trivially answer `is_issuer(from)` and `is_issuer(to)` as `false`
   without any storage read, because the issuer is always an `AccountId` and
   a `ScAddress::Contract` can never compare equal to a `ScAddress::Account`.
2. Compute the asset's `name` Symbol used as an event topic once per host
   invocation (or once per VM lifetime) rather than re-reading and re-decoding
   the `StellarAssetContractMetadata` ScVal from instance storage on every
   transfer, since instance storage for `METADATA` is never written during
   the soroswap apply path.

Currently neither holds: `event::transfer_maybe_with_issuer` issues two
`is_issuer` calls on every transfer, each of which reads `AssetInfo` from
instance storage and constructs an `Address` from the issuer's bytes; and
`event::transfer` calls `read_name` which always re-reads and re-decodes the
whole `StellarAssetContractMetadata` struct (decimal + name + symbol fields)
just to extract `.name`.

## Mechanism

`src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47`
(`transfer_maybe_with_issuer`) calls `is_issuer(e, &from)` and, if false,
`is_issuer(e, &to)`. `is_issuer` (line 13) does:

```rust
match read_asset_info(e)? {        // instance storage read + ScVal decode
    AssetInfo::Native => Ok(false),
    AssetInfo::AlphaNum4(asset) => issuer_check(asset.issuer, addr),
    AssetInfo::AlphaNum12(asset) => issuer_check(asset.issuer, addr),
}
```

`issuer_check` then runs `account_id_from_bytesobj` and `Address::from_account`
just to compare against `addr`. But when `addr` is a `ScAddress::Contract`
(verifiable cheaply via `addr.to_sc_address()?` matching), the result is
**guaranteed** to be `Ordering::Equal == false` because the issuer is an
account. We are paying for a full `read_asset_info` + `Address::from_account`
+ `Host::compare` round-trip whose outcome is statically known.

Then `event::transfer` (line 94) builds the topics vec with
`read_name(e)?` (metadata.rs:192):

```rust
let metadata: StellarAssetContractMetadata = e
    .get_contract_data(key.try_into_val(e)?, StorageType::Instance)?
    .try_into_val(e)?;        // decodes decimal+name+symbol map
Ok(metadata.name)
```

The full `StellarAssetContractMetadata` map is decoded just to extract `.name`.
The Tracy trace shows ~13,527 transfers / 71 ledgers ≈ 191 SAC transfers per
ledger, each paying this combined overhead.

The fix has two parts, both local and determinism-safe:

1. In `is_issuer`, pre-check `addr.to_sc_address()?` and short-circuit
   `Ok(false)` when the variant is `ScAddress::Contract(_)`, before
   `read_asset_info` runs.
2. Add an optional cached `(name_string_handle, asset_info_was_loaded)` slot
   on the SAC's per-VM instance state, populated lazily on first `read_name`
   and invalidated on `write_asset_info` / `set_metadata` (which never run on
   the soroswap transfer path). Alternatively: introduce
   `read_name_only(e)` that reads only the `name` map entry from the metadata
   ScVal map instead of fully decoding `StellarAssetContractMetadata`.

## Trigger

Run the soroswap apply-load benchmark. Soroswap pools and users are
contract addresses, so every `event::transfer_maybe_with_issuer` call falls
into the "neither is issuer" branch after two wasted `read_asset_info`
loads. Every emitted transfer event also calls `read_name` once.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13`
  — `is_issuer`: add `ScAddress::Contract(_) => Ok(false)` short-circuit
  before `read_asset_info`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47`
  — `transfer_maybe_with_issuer`: callsite that does the two `is_issuer` calls.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:94`
  — `transfer`: callsite of `read_name`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192`
  — `read_name`: full `StellarAssetContractMetadata` decode just for `.name`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20`
  — `read_asset_info`: the underlying storage + ScVal decode whose work the
  short-circuit avoids entirely.

## Evidence

- The host has `addr.to_sc_address()` available cheaply (it is already called
  in every `read_balance` / `spend_balance` branch), so the short-circuit
  branch is one extra match arm.
- Each SAC transfer mean wall is 159 µs in the Tracy trace
  (`SAC transfer,...stellar_asset_contract/contract.rs:212`). The
  `get_contract_data,vmcaller_env.rs:270` zone is 594 ms aggregate across
  67,692 calls; conservatively ~3 of those 10 calls per soroswap SAC
  invocation come from the two `is_issuer.read_asset_info` reads and one
  `read_name.get_contract_data`. Avoiding them saves ≈ 3 × 8.8 µs × 191 =
  5 ms per ledger ≈ 1.8% of the 272.9 ms soroswap apply window.
- The metadata-decode portion (`try_into_val::<StellarAssetContractMetadata>`)
  also avoids decoding decimal + symbol fields per call; combined the two
  optimizations are projected at 3–4% apply-time reduction.
- Determinism: `is_issuer` returns the same `bool` either way (the
  short-circuit returns the correct answer for `ScAddress::Contract`).
  Charge bookkeeping must be preserved — same caveat as H001 — but the call
  has no other observable effect (no events emitted, no storage written).
- Metadata caching/slicing is safe because `set_metadata` is only called
  during SAC initialization, not during `transfer`. A per-invocation cache
  (lazy on first `read_name`, dropped at host finalization) cannot affect
  ledger output.

## Anti-Evidence

- Budget charge identity: removing `read_asset_info` and trimming the
  `read_name` decode reduces the metered work, which (without protocol
  gating or explicit replacement charges) will reduce host fees. Same
  meta-pattern #11 concern as H001 — must be either protocol-gated or
  paired with explicit equivalent `charge_budget` calls.
- A pathological asset whose issuer is itself a Contract address does not
  exist by SAC's construction (issuer is `AccountId`), so the
  short-circuit is sound for the on-chain SAC.
- Fail #001 (`extend-ttl-noop-short-circuit`) was rejected; that short-circuit
  was about `extend_contract_data_ttl` no-op cases, not about `is_issuer`.
  No fail file targets `is_issuer` or `read_name` directly.
- This hypothesis is disjoint from H001 (which targets balance.rs reads);
  the two PoCs can be combined or sequenced and their gains should be
  additive (different host-fn calls, different ledger entries).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated
**Failed At**: reviewer

### Trace Summary

`StellarAssetContract::transfer` does call `event::transfer_maybe_with_issuer` after balance mutation, and contract-to-contract transfers reach two `is_issuer` calls plus one `read_name` call before emitting the transfer event. The claimed redundant work is real, but the traced storage path for `StorageType::Instance` is an already-initialized per-frame `InstanceStorageMap` lookup, not a repeated ledger-entry read or repeated `ScVal` materialization from ledger storage. The target therefore removes small in-memory map lookups, host-object visits, and tiny map/struct decodes; this does not plausibly clear the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` checks amount/auth, extends instance/code TTL, mutates balances, then emits transfer/mint/burn event through `transfer_maybe_with_issuer`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-26` — `is_issuer` always calls `read_asset_info`; for non-native assets it constructs an account `Address` from issuer bytes and compares it with the supplied address.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64` — unequal `from`/`to` addresses call `is_issuer(from)` and then `is_issuer(to)` before falling back to the ordinary transfer event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:94-113` — ordinary transfer event builds topics with `read_name(e)?`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-24` — `read_asset_info` retrieves `InstanceDataKey::AssetInfo` from instance storage and converts the resulting `Val` into `AssetInfo`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-198` — `read_name` retrieves `METADATA` from instance storage and decodes the full `StellarAssetContractMetadata` struct to return `.name`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2264` — `StorageType::Instance` `has_contract_data`/`get_contract_data` only probe the current frame's `InstanceStorageMap`; durable/temporary storage is the branch that constructs a ledger key and borrows `Storage`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1196-1211` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:33-65` — instance storage is lazily converted once from the frame's `ScContractInstance` into a `MeteredOrdMap<Val, Val, Host>` and reused for later reads in that frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:363-375` and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:254-256` — the proposed contract-address precheck is correct but still visits and metered-clones the address object.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:123-128` and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:45-95,170-189` — the avoided issuer path includes bytes-object visit, account address construction, and address comparison.

### Why It Failed

The hypothesis overstates the removable cost. On the SAC event path, `read_asset_info` and `read_name` use `StorageType::Instance`, which after first access is a small in-frame `MeteredOrdMap` containing SAC instance data (`Admin`, `AssetInfo`, and `METADATA`), not the persistent storage path used by balance reads. Even accepting the hypothesis's own optimistic 5 ms/ledger aggregate Tracy estimate for three `get_contract_data` calls, that component is only 1.8% before correcting for parallel-cluster Tracy aggregation; the extra metadata struct decode is only a three-field host-map decode and is not enough to raise the real apply-wall projection into the 3-10% Medium band. Because this objective rejects Low-tier findings, the real but small inefficiency is below the accepted severity threshold.

### Lesson Learned

For SAC optimizations, distinguish persistent balance/allowance storage from instance storage. Instance data is converted once per frame and then read from a tiny host-side map, so aggregate `get_contract_data` traces cannot be treated as repeated ledger-storage reads or projected directly to serial apply-wall savings without accounting for storage type and cluster parallelism.
