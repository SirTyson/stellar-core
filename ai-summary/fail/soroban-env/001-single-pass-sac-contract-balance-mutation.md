# H001: Single-Pass SAC Contract-Balance Mutation

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by collapsing redundant contract-balance key construction, storage lookups, balance decoding, and TTL rereads inside hot SAC transfer paths
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Stellar Asset Contract `transfer` involving a contract-owned balance, the host should preserve the exact SAC behavior: sender authorization is checked, deauthorized balances fail, missing contract balances behave as zero or insufficient as today, balance values keep their `authorized`/`clawback` flags, live-until ledgers are extended with the same threshold/extend amount, and the same SAC transfer event is emitted under the token contract. The implementation should not reread and reparse the same `Balance(owner)` ledger entry several times while processing one side of the transfer.

## Mechanism

`spend_balance` and `receive_balance` currently compose `is_authorized`, `read_contract_balance`, `write_contract_balance`, and `extend_contract_balance_ttl`; for contract owners this rebuilds the same `Balance(owner)` key and repeats storage lookup / `BalanceValue` decoding before finally writing the updated value and then calling `extend_ttl`, which itself rereads the same key via `get_with_live_until_ledger`. A next-protocol helper can mutate contract balances in one storage pass: load `EntryWithLiveUntil`, parse `BalanceValue` once, perform the authorization and amount update checks, write the modified `LedgerEntry`, and apply the TTL extension using the already-known live-until metadata. This preserves external SAC semantics while removing repeated physical work from the `SAC transfer` hot path.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the accepted next-protocol soroswap workload (`soroswap, TX=2000, T=8`). Each accepted swap executes SAC `transfer` calls for token movement; contract-owned pair balances take the duplicated contract-data balance paths in `spend_balance` or `receive_balance`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `SAC transfer` calls `spend_balance`, `receive_balance`, and event emission for every token movement.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-56` — contract balance key construction repeated by authorization, read, and write helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-178` — `read_contract_balance` and `extend_contract_balance_ttl` perform separate storage accesses for the same key.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:235-299` — `write_contract_balance` rereads the entry with live-until metadata, writes it, then calls the separate TTL extension path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-345,357-427,431-440` — `receive_balance`, `spend_balance_no_authorization_check`, and `is_authorized` compose the repeated balance reads.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:531-688` — `extend_ttl` rereads the entry and performs another footprint/storage lookup before applying a TTL update.

## Evidence

The current soroswap Tracy trace shows this path is inside the measured apply window: `SAC transfer` at `builtin_contracts/stellar_asset_contract/contract.rs:212` has 638,599,625 ns self-time and 15,665 in-`applyLedger` events totaling 2,477,084,982 ns; `storage get` at `storage.rs:329` has 321,802 in-`applyLedger` events totaling 672,084,842 ns; `map lookup indexed` and `map lookup` have 585,969,208 ns and 637,545,774 ns respectively inside `applyLedger`. Source inspection shows a contract-owned transfer side can read the same balance once for authorization, again for mutation, again in `write_contract_balance`, and again in `extend_ttl`, so a single-pass mutation helper targets repeated work in a dominant remaining soroswap phase rather than a micro-check.

## Anti-Evidence

A p26-preserving "single lookup" variant has previously failed because exact budget charges are protocol-visible; this hypothesis must therefore be next-protocol-gated or explicitly replay the old charges. The reviewer must also isolate contract-owner transfer sides in the current soroswap workload, because account-side classic balance transfers use different code, and must verify malformed balance values, missing balances, auth-required assets, clawback flags, TTL extension/no-extension cases, and event ordering remain equivalent.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban-env/summary.md` entry `001-protocol-gated-sac-balance-readwrite-fusion.md`
**Failed At**: reviewer

### Trace Summary

The traced SAC `transfer` path still enters `spend_balance` and `receive_balance`, and contract owners do rebuild `DataKey::Balance(addr)` and use `try_get_contract_data` for authorization and mutation. `write_contract_balance` then calls `put_contract_data` and `extend_contract_data_ttl`; `Storage::extend_ttl` reaches `prepare_extend_ttl`, which rereads the same key through `get_with_live_until_ledger` before applying a TTL update. This confirms the mechanical inefficiency, but the exact read/write fusion idea has already been investigated and rejected after benchmarking.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` checks amount/auth, extends the SAC instance/code TTL, calls `spend_balance` and `receive_balance`, then emits the transfer event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-63` — `read_balance` constructs `Balance(addr)`, reads persistent contract data, extends the balance TTL on hit, and decodes `BalanceValue`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:74-97` — `write_contract_balance` writes the updated `BalanceValue` and separately extends TTL for the same key.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145,156-230,233-245` — `receive_balance`, `spend_balance_no_authorization_check`, and `is_authorized` compose repeated contract-balance reads and decoding around the same owner key.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-330,431-573` — storage reads clone `EntryWithLiveUntil`; TTL extension prepares by rereading the entry and then reinserts only when the new live-until ledger is higher.
- `ai-summary/fail/soroban-env/summary.md:54` — prior final review records `001-protocol-gated-sac-balance-readwrite-fusion.md`, a protocol-gated SAC balance read/write fusion to coalesce redundant storage lookups into one access, as failed because all authoritative soroswap runs regressed.

### Why It Failed

VERDICT: NOT_VIABLE — duplicate of `001-protocol-gated-sac-balance-readwrite-fusion.md`. The current hypothesis is substantially equivalent: next-protocol SAC balance read/write fusion that coalesces redundant contract-balance storage lookups and TTL rereads in the SAC transfer path. The previous PoC passed tests but regressed soroswap in all three authoritative non-Tracy benchmark runs, with storage-access coalescing overhead and changed cache access patterns negating the saved lookup work; therefore this is not novel and should not be re-promoted under the optimize-soroswap Medium floor.

### Lesson Learned

SAC contract-balance fusion looks attractive from source-level repeated reads, but the soroswap benchmark has already shown that coalescing these storage accesses can cost more than it saves. Future variants need a materially different mechanism or benchmark evidence that avoids the previously measured fusion overhead.
