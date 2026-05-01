# H001: Fuse SAC account-side authorization and trustline mutation reads

**Date**: 2026-05-01
**Subsystem**: transaction-ledger / Soroban SAC apply path
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating duplicate account/trustline storage lookups, asset decodes, and trustline clones in hot SAC transfers
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the account-address side of a Stellar Asset Contract transfer, the host should read the SAC asset and the affected classic trustline/account entry once, use that entry to validate authorization and balance constraints, and then write the same final balance entry in the same source-before-destination order. Successful transfers should produce identical ledger effects, events, TTL extensions, and error precedence for issuer, missing trustline, deauthorized trustline, insufficient balance, reserve, and overflow cases.

## Mechanism

The current account-side path checks authorization and mutates balance through separate generic helpers. `spend_balance` calls `is_authorized`, which reaches `is_account_authorized`, `read_asset`, `get_trustline_flags`, and `read_trustline_entry`; it then calls `spend_balance_no_authorization_check`, which reaches `transfer_classic_balance`, calls `read_asset` again, rebuilds the same trustline key, and reads/clones the same trustline again to mutate `balance`. `receive_balance` has the same authorization-then-mutation split for account destinations. Soroswap declares user trustline keys for both swap directions, so a mixed account/contract transfer can pay one duplicate classic trustline lookup on the user side even after contract-balance optimizations; an internal account-side helper can carry the decoded `Asset`, issuer decision, `TrustLineAsset`, and loaded `TrustLineEntry` from authorization into mutation without changing deterministic ordering.

## Trigger

Run the current soroswap apply-load baseline from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) and inspect the diagnostic trace `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`. `ApplyLoad::generateSoroswapSwaps` creates `token_in.transfer(user, pair, amount)` auth and includes both user trustline keys plus both pair contract-balance keys in the read-write footprint, so successful swaps exercise SAC account-side trustline debit/credit under `InvokeHostFunctionOpFrame doParallelApply`.

## Target Code

- `src/simulation/ApplyLoad.cpp:3447-3475` - soroswap footprint includes user trustline(A/B) and pair `Balance[...]` keys, proving the mixed account/contract shape.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - `transfer` runs `spend_balance`, `receive_balance`, then event emission for every SAC transfer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:220-230` - `spend_balance` performs account authorization before calling the mutation helper.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:375-404` - `transfer_classic_balance` calls `read_asset` again and dispatches to trustline mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:583-628` - `transfer_trustline_balance` rebuilds and reloads the trustline for mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:786-842` - `is_account_authorized` / `get_trustline_flags` read the same asset and trustline flags for authorization.

## Evidence

Tracy scope check: the target is reached from `applyLedger` -> `applyTransactions` -> `applyParallelPhase` -> `applySorobanStageClustersInParallel` -> `TransactionFrame::parallelApply` -> `InvokeHostFunctionOpFrame doParallelApply`; this is the measured apply path, not TX-set construction. In the current diagnostic trace, hot descendant zones include `SAC transfer` at `contract.rs:212` with 329,402,855 ns self-time over 10,172 calls, `storage get` at `storage.rs:329` with 151,677,551 ns self-time over 229,684 calls, `ScVal to Val` at `conversion.rs:436` with 293,123,796 ns self-time over 521,065 calls, and `map lookup` / `map lookup indexed` at `metered_map.rs:173,330` with 517 ms combined self-time. The source shows an avoidable account-side duplication distinct from the rejected contract-balance duplicate-read PoC: it targets classic trustline authorization/mutation for the user side, not persistent `Balance[pair]` contract data.

## Anti-Evidence

The previous account/account formulation failed because soroswap is mixed account/contract, not account/account. This refined version must isolate only the user trustline side and should not re-propose contract-balance duplicate-read removal, which already failed final-review benchmarking. Budget accounting and failure precedence are visible: a PoC must either preserve equivalent component charges or explicitly protocol-gate cheaper SAC account-side metering, and it must prove that source authorization, source spend, destination authorization, and destination receive errors still occur in the same order.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-01
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated in this exact mixed account/contract trustline-side form
**Failed At**: reviewer

### Trace Summary

The duplicate account-side work exists: a successful SAC account trustline debit or credit calls `is_account_authorized`, which reads SAC asset info and the trustline flags, then calls `transfer_classic_balance`, which rereads the SAC asset and reloads the same trustline to mutate its balance. Soroswap is indeed mixed account/contract: each generated swap footprint contains the user's two classic trustlines plus the pair contract's two SAC `Balance[pair]` entries, and the authorized sub-invocation is `token_in.transfer(user, pair, amount)`. However, the removable user-trustline duplicate is smaller than the already-tested contract-balance authorization/mutation fusion: it avoids one classic `Storage::try_get`/map probe and one asset-info reread per account-side endpoint, not the heavier `try_get_contract_data` has+get, `Val`/`ScVal`, and `BalanceValue` decode path. The prior stronger contract-side duplicate-read PoC failed the soroswap performance gate, so this smaller account-side-only refinement does not credibly reach the objective's required Medium 3-10% apply-time reduction.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` - soroswap transactions are generated with one source-account authorized `swap_exact_tokens_for_tokens` invocation, read-write user trustline keys for both tokens, and read-write pair `Balance[pair]` contract-data keys for both tokens.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - SAC `transfer` checks the amount and auth, extends instance/code TTL, then runs `spend_balance` before `receive_balance` and only then emits the transfer/mint/burn event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145` - account-address receives first call `is_authorized`, then convert the amount to `i64` and call `transfer_classic_balance` for the actual trustline/account mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:220-230` - account-address spends similarly check `is_authorized` before dispatching to `spend_balance_no_authorization_check`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:375-404` - `transfer_classic_balance` rereads SAC asset info, handles issuer short-circuiting, and dispatches credit assets to `transfer_trustline_balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:583-628` - `transfer_trustline_balance` rebuilds the trustline ledger key, reloads the trustline entry, clones it for mutation, checks balance bounds, and writes the updated trustline.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:786-842` - `is_account_authorized` rereads SAC asset info and, for non-issuer credit assets, `get_trustline_flags` rebuilds and reloads the same trustline only to inspect flags.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/asset_info.rs:20-28` - every `read_asset` fetches instance `AssetInfo` through the generic contract-data API and converts it to an XDR `Asset`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-303` - each trustline/account reload is an enforcing storage read that checks key support, enforces footprint access, and probes the in-memory storage map.
- `ai-summary/fail/transaction-ledger/002-fuse-sac-authorization-balance-reads.md:191-217` - the analogous but heavier contract-balance duplicate-read fusion was implemented and tested, but final review rejected it because three non-Tracy soroswap runs regressed from a 288.723 ms baseline average to 293.849 ms.
- `ai-summary/CURRENT_STATE.md:39-68` - the current accepted baseline is even lower at a 278.740 ms soroswap median average, so a new hypothesis must save at least about 8.4 ms wall time to clear the 3% Medium floor.

### Why It Failed

The optimization target is real but below the objective severity threshold. The candidate savings are limited to the account/trustline side of mixed SAC transfers and are strictly smaller than a prior contract-balance duplicate-read optimization with the same per-swap endpoint frequency but higher per-endpoint cost; that stronger optimization did not improve soroswap apply time. The cited broad Tracy zones (`storage get`, `map lookup`, `ScVal to Val`, and `SAC transfer`) include much more than the account-side trustline rereads, and the traced removable subset does not support a Medium projection after the current accepted baseline and `T=8` parallelism are considered.

### Lesson Learned

For soroswap SAC micro-optimizations, a source-level duplicate is not enough: the duplicate must account for a large isolated share of top-line apply time after existing accepted optimizations. Classic trustline-side fusions should be treated skeptically unless they come with narrow counters showing at least an 8-10 ms wall-time opportunity on the current baseline, especially when a heavier contract-balance duplicate-read fusion has already failed benchmark validation.
