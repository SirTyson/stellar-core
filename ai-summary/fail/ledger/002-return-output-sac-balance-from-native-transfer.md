# H002: Return Output SAC Balance From Native Pair Transfers

**Date**: 2026-05-25
**Subsystem**: ledger / Soroban host apply path
**Severity**: Medium
**Impact**: 3-5% soroswap apply-time reduction by avoiding one post-transfer SAC balance read per native pair swap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The native Soroswap pool swap path should observe the same SAC transfer effects, authorization, TTL bumps, events, reserve updates, and K-invariant checks as the current protocol-gated native emulation. After a successful output-side SAC transfer from the pair contract, the pool swap should use the actual pair balance produced by that transfer rather than perform an additional SAC balance lookup that recomputes the same storage key and re-extends the same SAC instance/balance TTLs.

## Mechanism

`call_native_soroswap_pool_swap` invokes one or two SAC transfers for output amounts, then immediately calls `soroswap_pool_invoke_sac_balance` for both token balances. In the common soroswap swap shape exactly one output transfer occurs, and the post-transfer pair balance for that output token is already known to the transfer implementation because SAC must debit the pair balance before returning success. A native SAC transfer helper used only by the protocol-gated pair path could preserve the public SAC `transfer` result as `Void` while returning the updated `from` balance internally; the pair swap would then only read the input-side balance from storage, cutting one direct SAC balance read and its instance/balance TTL work per swap.

## Trigger

Run the current soroswap apply-load benchmark with the accepted native Soroswap pair swap enabled. Each successful router swap calls the protocol-gated native pool `swap` path, performs an output-side SAC transfer from the pair to the recipient, and then reads both token balances at `call_native_soroswap_pool_swap` lines 1251-1252 even though the output-side balance was just written by the transfer.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1253` — native pool swap extends pool TTLs, calls output SAC transfers, then reads both balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1482` — `soroswap_pool_invoke_sac_transfer` currently calls generic SAC `transfer` through `call_n_internal` and discards the updated source balance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1484-1528` — direct SAC balance read path verifies StellarAsset executable, extends SAC instance TTL, constructs the balance key, reads the balance entry, and extends balance TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-199` — low-level balance read and TTL extension used by the direct read path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` — Tracy `SAC transfer` zone for the existing transfer implementation whose debit result should be exposed internally.

## Evidence

This path is present in the current checkout: `match_native_soroswap_pool_swap` recognizes the pool `swap` ABI and `call_native_soroswap_pool_swap` uses `soroswap_pool_invoke_sac_transfer` plus the direct SAC balance-read helper. The latest soroswap trace shows the surrounding SAC/native path is hot inside `applyLedger`: `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` has 771,914,182 ns self over 17,381 calls; unwrapped intersection shows 17,333 in-`applyLedger` transfer events totaling 2,910,469,000 ns. The direct-balance support primitives are also apply-path hot: `storage get` has 266,675,391 ns self over 357,046 calls, `get_contract_data` has 113,289,753 ns self over 86,957 calls in the common VM caller path, and `extend_current_contract_instance_and_code_ttl` has 254,250,355 ns self over 17,404 calls in `vmcaller_env.rs`.

Prior `skip-output-side-sac-balance-read` was rejected because the native pair path did not exist in that reviewed checkout. That blocker has changed: the accepted current state includes native pair swap and direct SAC balance reads, so the concrete target now exists at `frame.rs:1234-1252`.

## Anti-Evidence

It is not safe to replace the output balance with `reserve_out - amount_out` in the general pool contract path because a caller could have transferred additional output-side tokens to the pair before calling `swap`; the correct value is the actual balance after SAC transfer. The viable implementation must therefore get the updated balance from the transfer write itself (or an equivalent storage-delta result), not derive it from reserves. This overlaps semantically with prior SAC-transfer-boundary failures, so the reviewer must confirm the internal helper preserves SAC auth, event, TTL, rollback, and public return semantics before promoting.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/ledger/summary.md` entry `002-journal-sac-balance-deltas-for-native-swap.md` and its referenced `fail/soroban-env/002-return-post-transfer-pair-balance.md`
**Failed At**: reviewer

### Trace Summary

The native pool swap path now exists: `call_contract_fn` matches the Soroswap pool `swap`, pushes a `Frame::NativeContract`, executes one or two output-side SAC transfers, then reads both pair balances before computing input amounts and updating reserves. The output-side pair balance is indeed computed during SAC debit: `SAC transfer` calls `spend_balance`, which reads the pair's contract balance, subtracts the amount, writes the new balance, and returns public `Void`. However, this is substantially the same optimization already recorded in the ledger failure summary as SAC balance delta journaling / returning the post-transfer pair balance, and that prior review found the saving below the optimize-soroswap Medium floor.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-812` — `call_contract_fn` loads the callee instance, recognizes native Soroswap pool `swap`, constructs `Frame::NativeContract`, and dispatches to the native helper.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1253` — native pool swap validates output amounts/reserves, performs output SAC transfers, then unconditionally reads both token balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1482` — the native swap calls SAC `transfer` through `call_n_internal` and discards the public `Void` result.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1484-1528` — direct SAC balance helper verifies the token is StellarAsset, extends the SAC instance TTL, reads the pair contract balance, and extends balance TTL.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` enforces nonnegative amount, auth, instance/code TTL extension, debit, credit, and transfer event emission before returning `Ok(())`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:357-427` — `spend_balance` / `spend_balance_no_authorization_check` read the source contract balance, compute the post-debit amount, and write it back; an internal helper could expose this value, but doing so is the previously reviewed balance-delta mechanism.
- `ai-summary/fail/ledger/summary.md:83` — prior ledger failure `002-journal-sac-balance-deltas-for-native-swap.md` covers avoiding post-swap balance storage reads via SAC balance deltas and rejects it as below threshold, noting the same cross-subsystem duplicate.

### Why It Failed

This is not novel. The exact optimization family — capture the SAC transfer's post-debit pair balance / journal balance deltas to avoid native swap post-transfer balance reads — is already summarized as rejected in `ai-summary/fail/ledger/summary.md:83` with projected impact below 1%, below this objective's Medium threshold. The current mechanism is narrower than the previously summarized journaling form because it only removes the output-side balance read; the swap still needs the input-side balance read to observe tokens sent to the pair before `swap`, and the SAC transfer still must perform auth, SAC frame semantics, instance/balance TTL work, source read/write, destination read/write, and event emission.

### Lesson Learned

Native SAC transfer helpers may expose a post-debit balance internally without changing public `transfer` semantics, but one removed direct balance read per swap is too small for optimize-soroswap and has already been investigated. Future native SAC/pool hypotheses need to remove or amortize a larger semantic phase than a single balance lookup, and must be checked against the ledger failure summary's condensed duplicate entries before promotion.
