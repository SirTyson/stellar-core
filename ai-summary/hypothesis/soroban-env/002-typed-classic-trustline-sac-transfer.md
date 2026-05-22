# H002: Typed classic trustline update fast path for SAC transfers

**Date**: 2026-05-22
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by reducing classic trustline cloning/reconstruction inside native SAC transfer
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a Stellar Asset Contract transfer updates a classic trustline balance, the host should preserve the same trustline validity checks, balance bounds, ledger entry output, and SAC events, but avoid reconstructing more XDR structure than necessary for the common apply-load case where only `TrustLineEntry.balance` changes. Any change should be protocol-gated or explicitly replay existing budget charges so p26 metering remains stable.

## Mechanism

Soroswap swaps use SAC transfers between a classic source-account trustline and a pool contract balance on every transaction. The contract-data balance side has already had typed-storage work accepted, but the classic trustline side still takes the generic path: build a trustline key, read a full `LedgerEntry`, clone the full `TrustLineEntry`, update `tl.balance`, wrap it back into `LedgerEntryData::Trustline`, clone the outer ledger-entry extension in `Host::modify_ledger_entry_data`, and then `storage.put` the rebuilt entry. A typed trustline-balance update helper for SAC transfers could clone/rebuild only the fields required for a balance-only mutation and avoid generic ledger-entry reconstruction overhead on a path hit roughly once per SAC transfer.

## Trigger

Run the current accepted soroswap benchmark. Each generated transaction performs `router.swap_exact_tokens_for_tokens`; the router/pair flow invokes SAC `transfer` for the input and output token movement. For credit assets, the user's side of each transfer updates a classic trustline through `transfer_trustline_balance`.

## Target Code

- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swap generator creates one unique source account per transaction and read-write footprints for user trustlines of the input and output assets.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `SAC transfer` hot path calls `spend_balance` and `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:376-403` — credit assets dispatch to trustline balance mutation unless the recipient is issuer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:584-617` — `transfer_trustline_balance` clones the full trustline, mutates `balance`, reconstructs `LedgerEntryData`, and stores it.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:468-483` — `modify_ledger_entry_data` rebuilds the outer `LedgerEntry` and clones `original_entry.ext` even when only a trustline balance changed.

## Evidence

The current trace shows `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` with 2.326747229s total / 616.339357ms self across 13,976 calls, all inside `applyLedger`. Supporting apply-contained zones include `storage get` at 679.878419ms total, `storage put` at 128.589568ms total, `ScVal to Val` at 1.074400446s total, and `Val to ScVal` at 463.737849ms total. Not all of that belongs to trustlines, but the workload shape guarantees classic trustline reads/writes for the user side of every swap.

The source-level observation is narrower than prior storage-fusion attempts: it does not try to coalesce reads and writes or skip authorization. It targets the representation work after the trustline entry is already found and validated, where the common mutation is a single `i64` balance field update.

## Anti-Evidence

Protocol-visible metering is the main risk. A p26-preserving implementation must replay current clone/allocation charges, which may shrink the physical saving below Medium; a cleaner PoC should be next-protocol gated with updated budget expectations. The optimization also only applies to classic trustline sides of SAC transfers, not contract-balance sides or native-XLM account balance transfers.
