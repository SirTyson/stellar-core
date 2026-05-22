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

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as a typed classic-trustline balance-update helper; related SAC/storage failures cover event emission, issuer checks, balance read/write fusion, in-place map mutation, and storage-map lookup specialization, but not this exact mechanism.
**Failed At**: reviewer

### Trace Summary

The soroswap generator declares two user trustlines read-write per swap and authorizes the input SAC transfer, so credit-asset swaps do exercise classic trustline balance updates in apply. `SAC transfer` calls `spend_balance` and `receive_balance`; account-address sides dispatch through `transfer_classic_balance` into `transfer_trustline_balance`, which reads a trustline entry, clones the shallow fixed-size `TrustLineEntry`, checks bounds, allocates a new `LedgerEntry`, clones the outer extension, and writes through `Storage::put`. The claimed clone/rebuild work is real, but it is only a small fixed-size representation step between mandatory storage lookup, validation, storage-map replacement, auth, TTL, contract-balance mutation, and event work.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` — soroswap swaps use a unique source account, include user input/output trustlines in the read-write footprint, and authorize the input token SAC transfer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` performs amount/auth/TTL work, then calls `spend_balance`, `receive_balance`, and emits the SAC transfer event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-229,376-403,584-617` — account-address spend/receive paths convert amounts to `i64`, choose credit-asset trustline mutation when not the issuer, clone the trustline, update only `balance`, rebuild a `LedgerEntryData::Trustline`, and call `storage.put`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:756-780` — balance bounds depend on `TrustLineEntry.ext` liabilities/limit, so the trustline must still be read and checked before mutation.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:374-383,468-483` — trustline keys are allocated as `Rc<LedgerKey>`, and `modify_ledger_entry_data` necessarily allocates a new `Rc<LedgerEntry>` with cloned `LedgerEntryExt`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-390,693-719` — `Storage::try_get` and `Storage::put` enforce footprint access and use the metered storage map; the write still replaces the value through `MeteredOrdMap::insert`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_clone.rs:187-255,330-342` and `src/rust/soroban/p26/soroban-env-host/src/host/declared_size.rs:163-175` — `TrustLineEntry` and `LedgerEntryExt` are shallow metered clones with declared sizes 128 and 33 bytes, while `LedgerEntry` allocation is declared 256 bytes.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-224` — `Storage::put` still rebuilds the sorted storage map entry vector around the new `Rc<LedgerEntry>`, so this hypothesis does not remove the dominant storage-write machinery.

### Why It Failed

The optimization does not meet the objective's Medium severity floor. A p26-compatible implementation cannot simply skip the `TrustLineEntry`/`LedgerEntryExt` clone and `LedgerEntry` allocation charges, because those `MemCpy`/`MemAlloc` charges contribute to observable Soroban budget totals; replaying them leaves only tiny physical enum/field-copy/helper overhead. A next-protocol implementation that changes metering still has to materialize a full updated `LedgerEntry` for the storage map and eventual XDR output, so it cannot avoid most of the claimed reconstruction either. At roughly one classic trustline update per SAC transfer, the removable work is a 128-byte shallow clone, a 33-byte shallow extension clone, and small glue code inside a 616ms aggregate SAC-transfer self-time; after cluster/ledger normalization this is far below the 3% apply-time reduction required by the optimize-soroswap objective.

### Lesson Learned

For SAC classic-trustline updates, distinguish "only the balance field changes" from "only the balance field must be materialized." The storage layer still requires a complete immutable `LedgerEntry`, and p26 metering makes the shallow clone/allocation charges protocol-visible. Future trustline hypotheses need focused timing that isolates a much larger removable component than fixed-size XDR struct copying, or they should target a broader next-protocol storage representation redesign rather than a narrow balance-update helper.
