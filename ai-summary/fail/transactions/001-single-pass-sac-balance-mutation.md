# H001: Single-Pass SAC Contract-Balance Mutation and TTL Writeback

**Date**: 2026-05-04
**Subsystem**: transactions, soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing duplicate SAC balance storage, conversion, and TTL writeback work
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a soroswap ledger where SAC `transfer` is called repeatedly for contract addresses, each transfer should authenticate the source, verify both balances are authorized, update the source and destination amounts exactly once, preserve `authorized` and `clawback` fields, extend balance TTLs when required, and emit the same transfer/mint/burn event. The resulting contract-data entries, TTL entries, events, budget behavior for the current protocol, and error ordering should remain unchanged; a next-protocol implementation may deliberately reduce budget charges only behind the protocol gate.

## Mechanism

`StellarAssetContract::transfer` calls `spend_balance` and `receive_balance` independently. For contract addresses, each path first calls `is_authorized`, which loads and decodes the `BalanceValue`, then loads and decodes the same balance again to mutate the amount, and `write_contract_balance` converts the same `DataKey::Balance` into a host value twice for `put_contract_data` and `extend_contract_data_ttl`. A specialized single-pass contract-balance helper could load each side's `BalanceValue` once, carry the decoded authorization/clawback state into the mutation, and update value plus TTL with one prebuilt key representation, reducing the dominant SAC transfer worker slice without changing observable ledger output.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) with contract-address SAC transfers. The current Tracy trace shows 13,527 `SAC transfer` events inside `applyLedger`; each contract-to-contract transfer exercises the duplicated `is_authorized` + read/mutate/write path for source and destination balances.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` sequences `require_auth`, instance TTL extension, `spend_balance`, `receive_balance`, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` checks authorization, loads the contract balance, mutates amount, and writes it back.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-229` — `spend_balance` checks authorization, then `spend_balance_no_authorization_check` loads the same contract balance again before mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-245` — `is_authorized` performs the first contract-balance load and `BalanceValue` decode.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97` — `write_contract_balance` rebuilds the balance key Val for both `put_contract_data` and `extend_contract_data_ttl`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-389` — storage `get` and `put` map probes, cloning, and writeback that the duplicated SAC helper calls funnel through.

## Evidence

The current accepted soroswap Tracy trace reports `applyLedger` total time of 5,230,315,999 ns across 71 ledgers, so the Medium threshold is about 156,909,480 ns of critical-path time. Timestamp-filtered apply descendants show `SAC transfer` total time of 2,153,411,257 ns across 13,527 calls; with T=8 worker aggregation, this is a 269,176,407 ns critical-path upper bound, roughly 5.1% of `applyLedger`. Supporting zones remain large in the same trace: `ScVal to Val` totals 995,921,819 ns in apply windows, and `storage get` / `map lookup indexed` / `map lookup` are repeatedly present on the SAC balance path.

The source structure shows concrete redundant work: `is_authorized` decodes `BalanceValue` to read only `authorized`, while `spend_balance_no_authorization_check` and `receive_balance` immediately decode the same balance again to change `amount`. Unlike a generic storage-map rewrite, this can be scoped to SAC contract balance entries and preserve exact ledger effects by reusing the already decoded `BalanceValue` only within one built-in transfer call.

## Anti-Evidence

Current-protocol metering is consensus-visible, so an implementation that simply skips the duplicate decode or key conversion in p26 may change resource usage. This should either be protocol-gated to the next protocol or explicitly reproduce the old budget charges while avoiding only physical allocation/map work. Prior SAC micro-optimizations have failed when they targeted only issuer checks or metadata caching; this candidate must demonstrate that the broader balance-load/mutate/write path recovers enough of the `SAC transfer` total, not just a small endpoint or metadata subcase.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md`; also overlaps the `001-sac-balance-auth-read-fusion.md` entry summarized in `ai-summary/fail/transactions/summary.md`
**Failed At**: reviewer

### Trace Summary

The traced SAC `transfer` path still matches the claimed local mechanism: `transfer` calls `spend_balance` and `receive_balance`, contract-address balance helpers call `is_authorized`, `try_get_contract_data`, `put_contract_data`, and `extend_contract_data_ttl`, and the generic host storage API repeatedly converts `DataKey::Balance` / `BalanceValue` through host `Val` and storage `ScVal` forms. However this is not novel: the prior confirmed transaction-ledger finding already reviewed and PoC'd typed SAC balance helpers that build the balance key/value directly, use a single typed storage lookup, update contract data directly, and reuse the built ledger key for TTL extension. The transactions fail summary also records a specific SAC contract-balance authorization/read fusion attempt, so the additional "load authorization and mutation in one pass" framing has already been investigated.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` extends instance/code TTL, then invokes `spend_balance` and `receive_balance` before emitting the transfer event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97,100-145,156-229,233-245` — contract balance writeback converts the same key for put and TTL extension, while `is_authorized` and the mutation helpers separately read/decode existing balances.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/storage_utils.rs:4-14` — `try_get_contract_data` is `has_contract_data` plus `get_contract_data`, so a present balance goes through two generic key conversions and storage probes per logical read.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2249,2293-2318` — generic `put_contract_data`, `get_contract_data`, and `extend_contract_data_ttl` reconstruct storage keys from host `Val`s and read/write storage.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:159-166,407-460` — `storage_key_from_val` and host value conversion perform the `Val`/`ScVal` round trips targeted by the hypothesis.
- `src/simulation/ApplyLoad.cpp:3382-3505` — each hot soroswap swap uses two SAC token legs with `Balance[pair]` entries in the read-write footprint, so the path is indeed apply-hot.
- `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md:80-95,100-115,123-139` — already confirmed the same SAC balance key/value conversion and storage lookup/writeback optimization, including a PoC and final review.
- `ai-summary/fail/transactions/summary.md:25` — records a prior `001-sac-balance-auth-read-fusion.md` investigation covering the authorization/read fusion part of this hypothesis.

### Why It Failed

This hypothesis is substantially equivalent to a previously confirmed typed SAC balance storage fast path and overlaps a previously recorded SAC balance auth/read fusion investigation. The inefficiency is real, but the pipeline has already investigated the same SAC `DataKey::Balance` / `BalanceValue` single-pass typed storage direction, including the writeback and TTL reuse portions, so this review must fail it as a duplicate rather than promote it for another PoC.

### Lesson Learned

Future SAC balance optimization hypotheses should check both the transactions failure summary and the cross-bucket transaction-ledger success records before re-framing the same typed storage fast path. A novel follow-up would need to target a different remaining cost after the typed SAC balance helper, not the already-reviewed generic conversion, duplicate read/decode, or TTL key-reuse mechanism.
