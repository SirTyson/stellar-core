# H002: Fuse SAC balance authorization and update reads in soroswap transfers

**Date**: 2026-05-04
**Subsystem**: ledger / Soroban SAC storage
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by eliminating redundant SAC balance storage reads, key conversions, and map lookups in hot transfer calls
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

A SAC transfer should read each affected balance entry once per logical side of the transfer, validate authorization from that value, compute the new amount, and write the resulting value. It should preserve the same error ordering, TTL extension behavior, emitted events, and final ledger entries, but should not re-derive the same `DataKey::Balance`, convert it to a host value, and fetch/decode the same contract-data balance multiple times within one transfer side.

## Mechanism

The current SAC contract balance path separates authorization checks from balance updates. `receive_balance` first calls `is_authorized`, which reads the balance through `try_get_contract_data`; then `receive_balance` derives the same key and calls `try_get_contract_data` again before writing. `spend_balance` has the same pattern: `is_authorized` reads the balance, then `spend_balance_no_authorization_check` reads the same balance again before subtracting and writing. Soroswap invokes SAC transfers heavily, so this repeats storage footprint enforcement, `MeteredOrdMap` lookups, `ScVal` conversion, and `BalanceValue` decoding on the apply worker critical path.

The proposed optimization is to introduce SAC-internal helpers that fetch a contract balance once, return the decoded `BalanceValue` and authorization state, and perform the spend/receive mutation from that already-decoded value. For account/trustline addresses, the same pattern can be applied by reading the trustline/account once where authorization and balance mutation currently use the same ledger entry. This is deterministic because it changes only redundant reads of the same host storage snapshot inside one host invocation, not output ordering or ledger-entry semantics.

## Trigger

Run the current soroswap apply-load workload (`soroswap, TX=2000, T=8`). Transfers involving contract-address balances trigger the duplicate path when `StellarAssetContract::transfer` calls `spend_balance` and `receive_balance`; each of those functions checks authorization and then reads the same balance again to mutate it.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — hot `SAC transfer` path extends TTL and calls `spend_balance` then `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` — `receive_balance` calls `is_authorized`, then derives `DataKey::Balance` and calls `try_get_contract_data` again.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:156-230` — `spend_balance` calls `is_authorized`, then `spend_balance_no_authorization_check` derives the same key and reads the same balance again.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:233-240` — `is_authorized` performs the first contract-data balance read for contract addresses.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:73-96` — `write_contract_balance` writes the updated balance and extends TTL; fused helpers must preserve this write and TTL behavior.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:253-267` and `src/rust/soroban/p26/soroban-env-host/src/storage.rs:693-718` — every redundant `try_get_contract_data` flows into storage read preparation, footprint enforcement, and storage-map lookup.

## Evidence

The current soroswap Tracy trace reports `SAC transfer` total time of 2,153,411,257 ns over 13,527 calls, with 100% of sampled events overlapping `applyLedger`. The same trace shows in-scope storage and host-call children on this path: `storage get` totals 641,710,601 ns across 305,065 calls, `get_contract_data` totals 594,010,156 ns at `vmcaller_env.rs:270` plus 142,529,580 ns at `vm/dispatch.rs:304`, and `has_contract_data` totals 483,234,063 ns at `vm/dispatch.rs:304`. The code structure explains why soroswap pays those costs repeatedly: authorization and balance mutation fetch the same balance separately.

This targets a different path from prior C++ `addReads` or typed host-storage ingress hypotheses. It is SAC-specific and should primarily benefit the soroswap headline workload, where SAC transfer volume is high.

## Anti-Evidence

The current branch already includes a typed SAC balance-storage fast path, so a PoC must verify that the remaining duplicate reads are not already optimized away below the Rust source layer. The Medium estimate also depends on soroswap using contract-address balances or trustline/account entries where authorization and mutation read the same ledger entry; if the benchmark mix mostly exercises paths where authorization reads different state from balance mutation, the improvement may fall below the objective threshold.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-04
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

`StellarAssetContract::transfer` enters the measured `SAC transfer` span, checks source auth, extends the SAC instance/code TTL, then calls `spend_balance` and `receive_balance`. For contract addresses, both balance sides call `is_authorized`, which derives the `Balance` ledger key and reads/decode the contract-data balance, then the mutation branch derives the same key and reads/decodes the same entry again before writing. The soroswap benchmark constructs every swap with two user trustline keys and two `Balance[pair]` contract-data keys in the read-write footprint, so this pattern is exercised in the parallel Soroban apply path for each swap.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — `transfer` is the hot SAC entry point and always dispatches through `spend_balance` then `receive_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-168` — `read_contract_balance` performs the contract balance storage read and decodes `BalanceValue`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:213-277` — `write_contract_balance` re-derives the same balance key, performs `try_get_full`, writes the updated entry, and preserves balance TTL extension.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:281-427` — `receive_balance` and `spend_balance` both call `is_authorized` before rereading the same contract balance in their contract-address mutation branches.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:751-783` and `:953-1008` — the account/trustline side has the same shape for credit assets: authorization reads trustline flags and the later transfer rereads the trustline to mutate balance.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:323-352`, `:355-389`, and `:531-666` — each SAC read flows through `try_get_full_helper` / `try_get`; existing indexed lookups reduce lookup cost but do not coalesce repeated reads, key derivation, cloning, or decoding.
- `src/simulation/ApplyLoad.cpp:3381-3505` — `generateSoroswapSwaps` builds `soroswap, TX=2000, T=8` transactions with two trustline RW keys and two SAC `Balance[pair]` RW keys per swap.
- `scripts/run_apply_load_matrix.py:120-124` and `:417-424` — the active matrix scenario is `soroswap` with 2000 txs and 8 dependent clusters, matching the trigger.

### Findings

The inefficiency exists. On contract-address balance sides, `is_authorized` reads `Balance[contract]` to check `authorized`, then `receive_balance` or `spend_balance_no_authorization_check` reads the same key again to compute the new amount; successful writes then currently read the same entry again in `write_contract_balance` to recover the full entry/live-until pair before calling `put` and `extend_ttl`. On credit-asset account sides, `is_account_authorized` reads the trustline flags and `transfer_trustline_balance` rereads the same trustline before balance mutation.

This is on the soroswap apply hot path. The benchmark footprint explicitly contains user trustlines for token-in/token-out and `Balance[pair]` for token-in/token-out; the generated invoke-host-function transaction calls the router, which performs SAC transfers against those entries. The existing enforcing-storage indexed fast path in `storage.rs` makes each lookup cheaper, but it still enters `storage get`, enforces access, clones the map value, and for contract balances decodes `BalanceValue`; it does not remove the repeated SAC-level reads.

The proposed fix is correctness-preserving if implemented SAC-internally. It should keep the current error ordering, especially authorization before receive-side i64 conversion/overflow, missing-contract-balance semantics (`!is_asset_auth_required` for receive, balance error for positive spend), issuer special cases for trustlines, and the final `extend_contract_balance_ttl` behavior. To avoid only moving the duplicate read, the contract-balance helper should carry enough data from the first read (`Rc<LedgerKey>`, decoded `BalanceValue`, and ideally full entry/live-until when present) for the write helper to update from the already-read entry.

The expected impact is Medium, not High. The supplied trace shows `storage get` at 641.7 ms aggregate over 305,065 calls and `SAC transfer` at 13,527 calls. With two SAC transfers per soroswap swap and both trustline and contract-balance sides participating, a fused implementation can remove tens of thousands of repeated storage reads plus associated key/scval/decode work from that trace. After normalizing by the 8-cluster parallelism, this is plausibly in the 3-10% apply-time range but should be benchmark-gated carefully because the current indexed storage fast path already reduced the per-read map-search component.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs`, primarily `read_contract_balance`, `write_contract_balance`, `receive_balance`, `spend_balance`, `spend_balance_no_authorization_check`, `is_authorized`, `is_account_authorized`, `get_trustline_flags`, and `transfer_trustline_balance`.
- **Change description**: Add fused SAC helpers for the transfer path. For contract holders, derive the balance key once, read/decode once for authorization, reuse the decoded value for amount mutation, and update the ledger entry without an avoidable second `read_contract_balance`; if practical, pass full-entry/live-until information into the write path to eliminate the current `try_get_full` reread as well. For credit-asset account holders, read the trustline once when checking authorization and reuse the same decoded trustline for balance mutation when the holder is not the issuer.
- **Correctness check**: Existing SAC transfer, trustline authorization, issuer, missing-balance, overflow, and TTL-extension tests should still cover behavior. Pay special attention to preserving the current order of `BalanceDeauthorizedError`, overflow errors, missing trustline errors, and `write_contract_balance` TTL extension.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py` for the active `soroswap, TX=2000, T=8` scenario and compare repeated non-Tracy medians. Expected improvement should show as fewer `storage get` calls/time under `SAC transfer` and a 3-10% reduction in soroswap apply time; if the final median reduction is below 3%, this should be rejected by the objective threshold despite the real micro-optimization.
