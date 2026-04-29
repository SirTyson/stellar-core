# H009: Fast-Path SAC Transfer Issuer Checks for Contract Endpoints

**Date**: 2026-04-29
**Subsystem**: transactions, soroban-env
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

SAC transfer events should keep classifying transfers as transfer, mint, or burn exactly as today. If either endpoint is the asset issuer account, the event must still be mint/burn; if neither endpoint is the issuer, it must be a transfer with the same topics, data, and metering behavior.

## Mechanism

`transfer_maybe_with_issuer` calls `is_issuer` on both `from` and `to` whenever the addresses differ. `is_issuer` reads SAC asset info, reconstructs the issuer account address, and compares it with the endpoint address. Since AlphaNum issuers are accounts and the native asset has no issuer, any endpoint that is already a contract address cannot be the issuer; an endpoint-type fast path could avoid one issuer read/compare for account-to-contract transfers and two for contract-to-contract transfers.

## Trigger

Run the current soroswap diagnostic trace and inspect SAC built-in zones under `applyLedger`. The trace shows `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` consuming 2.406468508 s across 6,656 calls, and `SAC balance` at line 187 consuming 545.826198 ms across 6,636 calls.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC transfer calls `transfer_maybe_with_issuer` after balance updates.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:13-26` — `is_issuer` reads asset info and compares the endpoint with the issuer account address.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64` — transfer/mint/burn classification calls `is_issuer` for both endpoints.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` — asset info read and conversion used by issuer detection.

## Evidence

The endpoint-type observation is semantically valid for SAC assets: a contract address cannot equal an AlphaNum issuer account address, and native assets have no issuer. Soroswap transfers frequently cross contract/account boundaries, so this branch would be on the apply path.

## Anti-Evidence

The trace does not isolate enough issuer-check self-time to support a Medium-tier claim. The whole `SAC transfer` zone includes authorization, TTL extension, two balance updates, event construction, storage access, conversions, and budget charging; issuer checks are only a subcomponent. Preserving exact metering for skipped `read_asset_info`, address construction, and comparison would also require compatibility charges or a protocol-gated cost-model change, reducing the safely recoverable physical work.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — this endpoint-type SAC event classification angle was not present in the transactions fail summary

### Why It Failed

The fast path is logically plausible but not justified at the required severity. It would optimize only a fraction of `SAC transfer`, has no direct zone evidence isolating a Medium-tier amount of work, and is entangled with consensus-visible budget charges.

### Lesson Learned

SAC transfer is a large aggregate zone, but sub-hypotheses inside it need direct subpath timing or a structural change that removes a large fraction of the call. Endpoint-type micro-fast-paths should be recorded as Low-tier unless future instrumentation proves otherwise.
