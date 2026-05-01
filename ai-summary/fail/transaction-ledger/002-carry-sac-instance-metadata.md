# H002: Carry SAC instance metadata through transfer/auth/event logic

**Date**: 2026-05-01
**Subsystem**: transaction-ledger / Soroban SAC apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by avoiding repeated instance-storage reads and contracttype conversions for SAC asset metadata during each transfer
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Within one SAC `transfer` or `transfer_from` invocation, the asset identity and token metadata should be read from instance storage at most once per logical value and reused by internal authorization, balance, issuer-classification, and event-emission helpers. The resulting behavior should be identical: the same issuer detection, trustline asset selection, event topic name, errors, metering totals or protocol-gated metering change, and ledger writes should occur deterministically.

## Mechanism

SAC helpers repeatedly re-enter instance storage for immutable per-contract data during a single transfer. `read_asset` calls `read_asset_info`, which does `get_contract_data(InstanceDataKey::AssetInfo)` and converts the result into `AssetInfo` / `Asset`; account authorization, classic balance mutation, issuer checks, and several admin/metadata helpers call it independently. After the balance mutation, `event::transfer_maybe_with_issuer` calls `is_issuer` on `from` and maybe `to`, and each `is_issuer` calls `read_asset_info` again; the actual `transfer` / `mint` / `burn` event then calls `read_name`, which separately loads `METADATA_KEY` and converts `StellarAssetContractMetadata` just to put the token name into event topics. A transfer-local context containing decoded `AssetInfo`, derived `Asset`, issuer account/address, and metadata name can be threaded through `spend_balance`, `receive_balance`, and event emission, replacing repeated instance-map lookups and host-object/contracttype conversions with one deterministic read per value.

## Trigger

Run the current soroswap apply-load baseline from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). The benchmark repeatedly invokes SAC token transfers from router/pair Wasm calls under `parallelApply`; each successful transfer needs asset information for trustline authorization/mutation and event issuer classification, and needs metadata name for the emitted SAC transfer/mint/burn event.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` - `read_asset_info` and `read_asset` perform instance-storage get plus conversion.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:375-430` - `transfer_classic_balance` / `get_classic_balance` call `read_asset` for account-side balance mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:786-807` - `is_account_authorized` calls `read_asset` again for authorization.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-26` - `is_issuer` calls `read_asset_info` for each issuer check during event classification.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-112` - `transfer_maybe_with_issuer` can call `is_issuer` twice and then `transfer`, which calls `read_name`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-198` - `read_name` loads metadata from instance storage and converts it for event topics.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2242` - instance `get_contract_data` routes through `MeteredOrdMap` lookup and host-value conversion.

## Evidence

Tracy scope check: SAC transfer execution is under the applyLedger parallel Soroban apply tree (`InvokeHostFunctionOpFrame doParallelApply` -> Rust `invoke_host_function` -> `Host::invoke_function`), not transaction-set construction. Current trace self-times show remaining hot conversion/storage families in that tree: `SAC transfer` at `contract.rs:212` consumes 329,402,855 ns over 10,172 calls; `get_contract_data` at `vmcaller_env.rs:270` / `dispatch.rs:304` consumes about 140 ms combined self-time over roughly 101k calls; `has_contract_data` consumes 119,930,675 ns; `ScVal to Val` consumes 293,123,796 ns; and `visit host object` consumes 1,432,652,085 ns over 3,491,848 calls. The code structurally explains a repeated immutable-data pattern inside each transfer: asset info is needed by authorization/mutation and event issuer classification, while token name is needed by event topics, but each helper currently loads and converts its own copy.

## Anti-Evidence

A prior SAC event direct-XDR hypothesis was rejected because broad event/container timing overstated the removable subset, and a simple metadata-cache-only change may be below threshold. This hypothesis must therefore measure the combined transfer-local metadata reuse across balance authorization/mutation and event classification, not just `read_name`. It must also preserve budget and error ordering: if repeated instance-storage gets and contracttype conversions are currently charged, the implementation must either charge equivalent deterministic costs while skipping the real work or intentionally gate lower metering behind the active protocol version.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related SAC balance/event sub-investigations exist, but this exact transfer-local AssetInfo carry-through was not previously reviewed as a combined transaction-ledger finding
**Failed At**: reviewer

### Trace Summary

The repeated SAC asset-info reads are real on the hot soroswap transfer path. A swap reaches SAC `transfer` through the router/pair calls; for account-side endpoints, authorization and classic balance mutation each call `read_asset`, and event issuer classification then calls `read_asset_info` once for `from` and usually once for `to`. However, the removable work is limited to small instance-storage `MeteredOrdMap<Val, Val>` lookups and contracttype conversions, while the `read_name` part is not a repeated per-transfer read in the normal transfer event path. Prior stronger SAC duplicate-read attempts that removed heavier persistent balance/trustline work failed or were rejected below the Medium threshold, so this narrower metadata-carrying optimization does not credibly reach the objective's required 3-10% soroswap apply-time reduction.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` — generated soroswap swaps invoke the router with a source-account-authorized `token_in.transfer(user, pair, amount)` sub-invocation and declare user trustlines plus pair `Balance[pair]` entries, so SAC transfers are in the measured apply path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` runs amount/auth checks, TTL extension, `spend_balance`, `receive_balance`, then `event::transfer_maybe_with_issuer`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:229-249` — `transfer_from` follows the same balance and event path after spender auth and allowance spending.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:281-324` — `receive_balance` checks authorization first; account receivers then call `transfer_classic_balance`, while contract receivers use contract balance storage and generally do not read SAC asset info unless the balance is missing.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:396-405` — `spend_balance` checks authorization before delegating to the no-authorization mutation path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:543-570` — `transfer_classic_balance` calls `read_asset` again to choose native/account versus trustline mutation and issuer short-circuit behavior.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:953-975` — `is_account_authorized` calls `read_asset` for account authorization before probing trustline flags.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-26` — each event issuer check calls `read_asset_info` and constructs the issuer address for comparison.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64` — `transfer_maybe_with_issuer` can do two issuer checks before selecting `transfer`, `mint`, or `burn`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:94-112` — the normal transfer event calls `read_name` once to include the token name in event topics; there is no second same-transfer metadata-name read to eliminate.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` — `read_asset_info` performs the instance `get_contract_data` and contracttype decode, and `read_asset` adds conversion to XDR `Asset`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/metadata.rs:192-198` — `read_name` performs one instance metadata lookup and decodes `StellarAssetContractMetadata`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2230-2265` — instance `get_contract_data` is an in-memory instance map lookup returning an already-host `Val`, not a persistent storage get or ledger/bucket read.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — instance map lookup charges and runs a binary search/comparison through `MeteredOrdMap::find`.
- `ai-summary/fail/transaction-ledger/001-fuse-sac-account-trustline-transfer.md:48-72` — a broader account-side trustline/asset duplicate-read target was rejected as below threshold on the current baseline.
- `ai-summary/fail/transaction-ledger/002-fuse-sac-authorization-balance-reads.md:191-217` — a heavier contract-balance duplicate-read fusion passed correctness but regressed soroswap in final benchmarking.
- `ai-summary/fail/transaction-ledger/002-build-sac-events-as-xdr.md:54-76` — the SAC event path was previously found real but below the objective threshold once mandatory conversions and final event serialization were accounted for.
- `ai-summary/CURRENT_STATE.md:39-68` — the current accepted soroswap baseline average is 278.740030 ms, so a Medium finding must save roughly 8.4 ms or more consistently across non-Tracy runs.

### Why It Failed

The hypothesis identifies real repeated instance metadata reads, but not a Medium-severity optimization for this objective. In the current mixed account/contract soroswap shape, the duplicated `AssetInfo` loads on the account side and issuer-classification path are narrower than the previously rejected account-trustline fusion, and much narrower than the contract-balance duplicate-read PoC that already failed the soroswap performance gate. The cited broad `get_contract_data`, `ScVal to Val`, and `visit host object` totals include Wasm contract storage calls, event construction/externalization, storage-map work, and many non-asset conversions; only a small subset belongs to SAC `AssetInfo`/`METADATA` instance reads. Also, `read_name` is required once to build the event topic and is not duplicated inside normal `transfer` emission, so carrying it in a transfer-local context mostly moves the same lookup rather than removing work.

Preserving current budget/error behavior further reduces the practical removable subset: skipping charged `MeteredOrdMap` lookups, object visits, address construction, and contracttype conversions would either change visible resource use or require deterministic replacement charges/protocol gating. After applying the objective rule that Low-tier optimizations are rejected, this transfer-local metadata-carrying proposal is below the accepted Medium threshold.

### Lesson Learned

For SAC transfer optimizations, repeated `read_asset_info` calls are not enough to justify a Medium finding unless narrow counters show that the removable instance-map and contracttype conversion subset alone clears the current ~8.4 ms wall-time threshold. Do not attribute broad host conversion, object-visit, or event timing to SAC metadata reuse, and treat `read_name` as a required single event-topic read unless a design also removes or protocol-gates the event metadata requirement itself.
