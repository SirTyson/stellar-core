# H002: Native Soroswap SAC Transfer-Balance Fusion

**Date**: 2026-05-24
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction in native pool swap worker path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During a protocol-gated native Soroswap pool `swap`, the pool's outbound SAC transfer should debit the pair balance, credit the recipient, emit the same SAC transfer event, perform the same authorization checks, and leave the pair reserves and swap event identical to the current path. The pair's post-transfer output-token balance should be available to the native swap logic without re-entering the generic SAC contract or doing a second balance lookup for that same token.

## Mechanism

`call_native_soroswap_pool_swap` invokes a generic SAC `transfer` through `call_n_internal` for the output token and then calls `soroswap_pool_invoke_sac_balance` for both pool token balances. For the output side, the native pool path already knows the sender is the current pair contract, the amount debited, and the reserve before transfer, so a typed helper can apply the SAC balance effect directly and return the post-debit pair balance while preserving the SAC event/auth semantics. This removes roughly one generic `SAC transfer` dispatch and one follow-up balance read per swap, while keeping the input-side balance read that is needed to detect the router's prior inbound transfer.

## Trigger

Run the current `soroswap, TX=2000, T=8` apply-load scenario with a swap where exactly one of `amount_0_out` or `amount_1_out` is positive and both token contracts are Stellar Asset contracts. The fast helper should trigger only for protocol-gated native Soroswap pool frames and only when the token address resolves to a SAC contract; otherwise `soroswap_pool_invoke_sac_transfer` and `soroswap_pool_invoke_sac_balance` should keep the existing fallback behavior.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1253` at gitlink `bf6625f8` — native pool swap calls outbound SAC transfer(s), then reads both token balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1483` at gitlink `bf6625f8` — `soroswap_pool_invoke_sac_transfer` still routes through generic `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1484-1503` at gitlink `bf6625f8` — `soroswap_pool_invoke_sac_balance` reads balances after the transfer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC transfer sequence to preserve.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-346,357-397` — balance receive/spend logic that the typed helper would reuse or factor without changing semantics.

## Evidence

The current soroswap Tracy trace has `SAC transfer` inside benchmark-sized `applyLedger` windows for all 16,722 relevant events, with 2601.188 ms aggregate worker overlap. Dividing by T=8 gives about 325 ms of critical-path upper bound, or roughly 6.9% of the 4677.285 ms benchmark-sized apply-window total. The native pool path performs the outbound transfer at the exact source lines above before immediately reading both pool balances, so removing about half of the generic transfer path plus one balance read is plausibly in the 3-10% Medium range.

## Anti-Evidence

The helper cannot skip SAC semantics: `from.require_auth`, authorization/deauthorization checks, TTL extension, balance overflow handling, clawback flags, muxed-address event data, and event ordering all need exact preservation. Input-side balance detection cannot be removed by this hypothesis because the pool observes the router's prior inbound transfer only through the post-transfer balance. The optimization must be next-protocol gated because it changes physical host dispatch and metering.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transactions/summary.md:86` (`002-fused-native-sac-transfer-effects.md`)
**Failed At**: reviewer

### Trace Summary

The current native Soroswap pool swap path loads reserves and token addresses, conditionally calls `soroswap_pool_invoke_sac_transfer` for the outbound token, and then reads both token balances before calculating input amounts and updating reserves. The transfer helper still builds a `transfer` symbol and enters `call_n_internal`, which reaches the generic SAC `transfer` sequence: amount check, `from.require_auth`, instance/code TTL extension, spend, receive, and transfer event emission. The balance helper first attempts the specialized SAC contract-balance read for contract owners and falls back to generic `balance` dispatch otherwise. This matches the mechanism in the prior `002-fused-native-sac-transfer-effects.md` record exactly: replacing generic SAC dispatch in the native pool outbound path with a typed balance-effect helper.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` — `call_native_soroswap_pool_swap` performs native pool validation, outbound SAC transfer for positive `amount_0_out`/`amount_1_out`, then reads both balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1265` — the read balances feed input detection, K-invariant checks, and reserve updates, so any fused helper must preserve post-transfer balance semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1366` — `soroswap_pool_invoke_sac_transfer` routes through `call_n_internal`; `soroswap_pool_invoke_sac_balance` uses a typed SAC contract-balance read where possible and otherwise falls back to generic `balance`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC transfer performs nonnegative check, auth, TTL extension, spend, receive, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-346,357-427` — receive/spend paths enforce authorization, overflow/underflow, classic-vs-contract balance handling, and balance writeback.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64,94-110` — transfer/mint/burn event selection depends on issuer checks and muxed transfer data.
- `ai-summary/fail/transactions/summary.md:86` — prior final-review entry records the same fused native SAC transfer-effect optimization and its rejection reason.

### Why It Failed

This hypothesis is a duplicate. The exact optimization target has already been investigated as `002-fused-native-sac-transfer-effects.md`: replacing generic SAC `call_n_internal` dispatch in the native Soroswap pool outbound path with typed SAC balance-effect logic for Stellar Asset contracts. The prior record reached final-review, meaning the inefficiency and approach were already advanced through the pipeline; this new hypothesis does not add a materially different mechanism or scope.

### Lesson Learned

Native Soroswap pool SAC transfer/balance fusion should not be reintroduced as a fresh transactions hypothesis unless it explicitly references the previous `002-fused-native-sac-transfer-effects.md` final-review failure and addresses the recorded handoff/test-gate blockers rather than reproposing the same code-path optimization.
