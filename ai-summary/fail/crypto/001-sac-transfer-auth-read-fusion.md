# H001: Fuse SAC Authorization Reads with Balance Mutation

**Date**: 2026-05-25
**Subsystem**: crypto / rust / Soroban SAC apply path
**Severity**: Medium
**Impact**: reduce soroswap SAC transfer storage reads by avoiding duplicate typed balance lookups inside each transfer leg
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

A SAC transfer should read each contract balance entry once per logical balance leg, check the same authorization flag that the current implementation checks, update the same amount field, write the same ledger entry, extend the same TTLs, and emit the same event in the same order. For contract-address balances, the `authorized`, `clawback`, and `amount` fields should be decoded once and reused through the authorization and mutation logic instead of loading and decoding the same `BalanceValue` again moments later.

## Mechanism

`StellarAssetContract::transfer` calls `spend_balance` and `receive_balance`. For contract addresses, both helpers call `is_authorized`, which builds the balance key and calls `read_contract_balance`; then `spend_balance_no_authorization_check` or `receive_balance` builds the same key again and calls `read_contract_balance` again before mutating the amount. The actual behavior therefore performs two storage-map lookups and two `BalanceValue` decodes for the same `(token, owner)` balance leg; a fused helper can read once, validate authorization from that decoded value, mutate it, and write it back while preserving errors and TTL behavior.

## Trigger

Run the current accepted soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) and inspect the diagnostic trace from `ai-summary/CURRENT_STATE.md`: `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`. Timestamp filtering against `applyLedger` shows apply-overlapping `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` around 2.91 s total over 17,333 events, `storage get` around 789 ms, `storage put` around 160 ms, `map lookup` around 707 ms, and `map lookup indexed` around 681 ms. The trigger is any soroswap swap whose SAC transfer uses contract-address balances, causing the authorization read and mutation read to target the same balance key.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-345` — `receive_balance` calls `is_authorized`, then reads the same contract balance again before adding the amount.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:357-427` — `spend_balance` calls `is_authorized`, then `spend_balance_no_authorization_check` reads the same contract balance again before subtracting the amount.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:431-440` — `is_authorized` builds the same contract-balance ledger key and decodes the same `BalanceValue`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178,234-299` — typed SAC balance read/write helpers that can be factored into a single read-check-mutate-write path.

## Evidence

The duplicate-read pattern is visible directly in the source and is apply-contained because soroswap's native pair path still invokes SAC transfers for output token movement. This is not a primitive SHA/verifySig micro-optimization and is not generic host result caching: it targets the SAC-specific typed balance helpers that already know the `BalanceValue` schema. If contract-address transfers dominate the current `SAC transfer` zone, eliminating one read/decode per balance leg can remove a meaningful share of the apply-overlapping `storage get`, `map lookup`, and balance-map decode work while keeping writes, authorization semantics, and event emission unchanged.

## Anti-Evidence

The trace zones are aggregate worker time and must be normalized by `NUM_CLUSTERS = 8`, so a PoC needs narrow counters proving that duplicate contract-balance reads are frequent enough in the current workload. The fused path must preserve subtle SAC behavior: missing balances use issuer auth flags, deauthorized existing balances fail, `spend_balance_no_authorization_check` remains available for clawback-style callers, and account-address trustline paths must remain untouched. If most soroswap transfer legs are account balances or if the second read is already optimized by storage-map locality, the measurable gain may fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The local duplicate-read mechanism is real for contract-address SAC transfers: `transfer` calls `spend_balance` and `receive_balance`, each checks `is_authorized`, and the contract-address branch then rereads the same balance before mutation. However, this is a remaining micro-optimization after the accepted typed SAC balance storage fast path; the second read is an indexed host storage-map lookup plus `BalanceValue` decode, not the older generic `Val`/`ScVal` conversion chain. The current diagnostic run contains 200 soroswap ledgers at 8 clusters, so the cited aggregate worker-time rows must be divided by both 200 ledgers and 8 parallel clusters before comparing to the current ~207.59 ms non-Tracy apply baseline.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` extends SAC instance/code TTL, then calls `spend_balance` and `receive_balance` before emitting the transfer event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-56` — contract balance keys are built directly as persistent `LedgerKey::ContractData` entries for the current SAC contract and `Vec["Balance", address]`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-168` — `read_contract_balance` performs one `Storage::try_get` and decodes `LedgerEntryData::ContractData.val` into `BalanceValue`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:234-299` — `write_contract_balance` still performs `Storage::try_get_full` to preserve/update the existing ledger entry and live-until value, then writes and extends the balance TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-345` — `receive_balance` calls `is_authorized`, then rebuilds the same key and rereads the contract balance before adding to the amount.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:357-427` — `spend_balance` calls `is_authorized`, then `spend_balance_no_authorization_check` rebuilds the same key and rereads the contract balance before subtracting from the amount.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:431-440` — `is_authorized` reads the same contract balance and returns its `authorized` flag, or falls back to issuer auth-required state for missing balances.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:324-389` — all SAC typed reads funnel through `try_get_full_helper`; the current stack already has an indexed fast path for storage-map lookups.
- `ai-summary/CURRENT_STATE.md:54-77` and `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.log:2363-2378` — authoritative soroswap non-Tracy median average is ~207.59 ms, and the diagnostic Tracy run reports 200 ledgers with 2000 tx per ledger.

### Why It Failed

This does not meet the optimize-soroswap Medium severity floor. The objective requires at least a 3% apply-time reduction, about 6.23 ms per ledger on the current 207.59 ms baseline. The whole cited `SAC transfer` envelope is only about `2.91s / 200 / 8 = 1.82 ms` wall time per ledger, roughly 0.9% of apply time, and eliminating the entire SAC transfer is impossible because authorization checks, amount arithmetic, writes, TTL extension, and event emission must remain. The narrower cited `storage get` surface is smaller still: `789ms / 200 / 8 = 0.49 ms` per ledger, about 0.24%, before subtracting non-SAC gets and the mandatory write-side `try_get_full` needed to preserve live-until state. A fused auth/mutation helper would be technically clean, but its realistic savings are below the objective severity threshold (Low/Informational, not Medium).

### Lesson Learned

After the typed SAC balance storage fast path, remaining SAC balance micro-optimizations must be sized against the complete `SAC transfer` envelope after 8-way worker normalization. If the entire enclosing transfer zone is below 3% of current apply time, a subcomponent such as duplicate auth/mutation reads cannot be promoted for this objective without new benchmark evidence showing a much larger wall-clock surface.
