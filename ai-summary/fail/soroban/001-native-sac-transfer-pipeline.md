# H001: Native Typed SAC Transfer Pipeline

**Date**: 2026-05-02
**Subsystem**: soroban / rust
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in repeated Stellar Asset Contract transfers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC `transfer` should produce the same ledger writes, authorization checks, contract events, budget/resource accounting, and errors as the current built-in implementation, but it should not have to round-trip through the generic host object and `Env` layers for data that is already native Rust data inside the built-in. For a soroswap swap that transfers SAC balances between account and contract addresses, the host should decode each address once, load each affected balance/trustline once, apply authorization and balance arithmetic on the typed value, and record the same event without constructing transient `HostVec`/`HostMap` objects solely to be converted back to XDR at `try_finish`.

## Mechanism

The current `StellarAssetContract::transfer` path is implemented as if it were ordinary contract code: it repeatedly converts `AddressObject` handles to `ScAddress`, calls authorization helpers that load the same balance/trustline data later loaded again by mutation helpers, builds event topics/data as host objects, and then externalizes those objects back to XDR. A typed native pipeline for the SAC transfer case can preserve consensus-visible outputs while replaying required metering, but avoid duplicate object-table visits, repeated typed storage decoding, and transient event object construction. This is significant for soroswap because the current trace places `SAC transfer` inside `applyLedger` for 10,140 of 10,172 calls, totaling 2,245,135,102 ns; it is a first-order child of the Soroban worker execution rather than TX-set construction.

## Trigger

Run the current soroswap apply-load benchmark (`TX=2000, T=8`) and inspect the Tracy trace from `ai-summary/CURRENT_STATE.md`. Swaps that invoke token transfers through the built-in Stellar Asset Contract call `StellarAssetContract::transfer`, which then enters the repeated address decode, authorization, balance update, TTL extension, and event construction path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — top-level SAC transfer sequence: amount check, muxed-address extraction, auth, instance TTL extension, spend/receive balance, event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` first calls `is_authorized`, then for contract balances loads the same `DataKey::Balance` entry again before writing.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:155-230` — `spend_balance` performs the same authorization-then-mutation split; contract balances and classic trustlines pay separate read/decode paths.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:375-430,583-617` — classic account/trustline helpers reread asset and trustline/account state in mutation helpers after authorization helpers have already classified or loaded related state.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — SAC transfer event construction builds host vectors/maps and rereads asset/name metadata before event recording.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-39,207-248` — contract events are stored as host-object references and later converted back to XDR.

## Evidence

The current diagnostic trace confirms this path is in scope: an unwrap containment check against all 70 `applyLedger` windows found `SAC transfer` totaling 2,245,135,102 ns inside the apply windows, with 10,140 contained calls. The same trace shows large adjacent implementation costs that the native SAC path exercises heavily: `visit host object` totals 2,728,946,416 ns inside `applyLedger`, `storage get` self-time is 151,677,551 ns / 229,684 calls, and `new map` / `add host object` / `write xdr` together account for hundreds of milliseconds of aggregate worker CPU.

The source shows a concrete duplicate-work shape rather than a speculative micro-optimization. `transfer` passes the same `Address` values through `require_auth`, `spend_balance`, `receive_balance`, and event emission; `spend_balance` and `receive_balance` each call `is_authorized` before their mutation helpers reload the balance/trustline data they need to update. Event emission then constructs object-table vectors and maps that are only used as an intermediate representation before `InternalContractEvent::to_xdr` converts them back to `ScVal` vectors.

## Anti-Evidence

This must not repeat the rejected metadata/address-cache hypotheses: simply caching issuer/name reads was already judged sub-threshold. The viable version must attack the broader typed transfer pipeline and demonstrate that duplicate balance/trustline loads plus event object construction are the removable slice, not just SAC metadata classification. The largest correctness risk is Soroban metering: if the existing helper calls charge budget in a protocol-visible way, the optimized path must replay equivalent charges or intentionally justify a protocol-cost reduction; otherwise observation fixtures and fee behavior can change.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in `fail/soroban` or `success/soroban`; adjacent SAC address/metadata cache failures cover a narrower caching idea, not this full typed-transfer pipeline
**Failed At**: reviewer

### Trace Summary

The traced SAC call path does contain repeated host-object visits, address-to-XDR conversions, balance authorization reads, balance mutation reads, and event host-object construction. However, the only plausibly large part of the proposal is the balance-storage duplicate work, and p26 already treats the existing storage/object/conversion operations as metered components; a correctness-preserving rewrite must either keep or replay much of that cost. After excluding required authorization, TTL extension, ledger writes, budget-compatible storage metering, and the already-rejected metadata/address-cache slice, the remaining removable work is not large enough to reach the optimize-soroswap Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — invokes Stellar Asset Contracts by pushing `Frame::StellarAssetContract` and calling the built-in through `BuiltinContract`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` checks amount, derives the non-muxed destination, calls `require_auth`, extends instance/code TTL, spends, receives, and emits the transfer/mint/burn-style event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/base_types.rs:373-379,475-497` — every `Address::to_sc_address` visits the host object table and clones the `ScAddress`; muxed destination extraction visits the muxed object and may allocate a new address object.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3605-3631` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-850` — `require_auth` clones current SAC frame arguments and builds the authorized-function record, so the auth step is required and not removable transfer bookkeeping.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145,220-245` — `receive_balance` and `spend_balance` call `is_authorized`; contract balances then perform another `DataKey::Balance` read before writing the updated balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:375-403,583-617,786-842` — classic-account paths load asset/trustline/account state for authorization and mutation, but still must preserve issuer/trustline semantics and balance-limit checks.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:2211-2244` — `try_get_contract_data` is a metered has-then-get path; replacing it with one physical lookup changes the charged host operation shape unless equivalent charges are replayed.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — event emission compares addresses, checks issuer status, reads metadata name, builds a `HostVec` topics object, and only builds a `HostMap` for muxed destinations.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:22-39,207-248` — contract events are stored as `VecObject`/`Val` handles and externalized by visiting the host objects later.
- `ai-summary/fail/soroban/summary.md:13` — prior SAC address/metadata caching was already rejected as below threshold; this review treats the broader pipeline as novel but cannot count that narrow slice as Medium-sized evidence.
- `ai-summary/CURRENT_STATE.md:3-20,79-81` — the current performance arc is already stacked on typed SAC balance-storage and XDR-size optimizations, so any new hypothesis must beat a baseline where part of the claimed balance-storage opportunity has already been harvested.

### Why It Failed

The inefficiency exists, but the hypothesis attributes too much of the broad `SAC transfer`, `visit host object`, storage, and XDR/event Tracy time to work that a typed transfer pipeline can safely remove. Most of the transfer sequence is semantically required: authorization must observe the current SAC invocation arguments, instance/code TTL and balance TTL updates must run, balance writes and classic trustline/account invariants must remain, and events must externalize to the same XDR. The common non-muxed soroswap transfer event also does not exercise the expensive map case; it mainly allocates one topics vector and reads metadata, which is the same narrow address/metadata class already judged sub-threshold.

The cited `SAC transfer` aggregate of 2.245 s is worker CPU across 70 ledgers and 8 parallel clusters. Even under the favorable Tracy-window interpretation, clearing the 3% Medium floor would require removing a large fraction of the entire SAC transfer zone; a correct implementation cannot remove authorization, storage metering, balance arithmetic, ledger writes, TTL extension, or event externalization. If it replays p26-compatible metering for the skipped storage/object/conversion components, the saved physical work is further reduced to cached address classifications, duplicate decode plumbing, and small transient event objects. That remaining slice is below the objective threshold, and Low-tier optimizations are not accepted for optimize-soroswap review.

### Lesson Learned

Do not promote a broad "native typed pipeline" from aggregate nested SAC or host-object Tracy totals without subtracting the required semantic and metering work. For SAC transfers, the real opportunities are narrow and must be valued after preserving p26 budget/resource accounting; address/metadata/event-object cleanup alone is below threshold, and balance-storage fast paths must be judged against the current accepted baseline rather than the older generic helper shape.
