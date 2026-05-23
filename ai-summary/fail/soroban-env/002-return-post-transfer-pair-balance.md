# H002: Return Post-Transfer Pair Balance From Native SAC Transfer

**Date**: 2026-05-23
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by fusing the native pair's output SAC transfer with the immediately following actual-balance observation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After a native Soroswap pair `swap` transfers the output token from the pair contract to the recipient, the pair logic must observe the actual post-transfer pair balance for that token, including donations or any prior divergence between reserves and token balances. The host should preserve SAC `transfer` semantics - pair `require_auth`, SAC instance TTL extension, balance authorization/clawback checks, balance storage updates, balance TTL extension, and SAC transfer event emission under the token contract id - while returning the pair's new balance directly from the transfer helper when the transfer was executed by the native pair path.

## Mechanism

The accepted direct-balance optimization still runs `soroswap_pool_invoke_sac_transfer` and then calls `soroswap_pool_invoke_sac_balance` for both tokens. For the output token, the SAC transfer necessarily reads, validates, mutates, and writes the pair's `Balance(pair)` entry; immediately re-reading that same contract-data entry to compute `amount_*_in` is redundant if the transfer helper returns the exact post-write pair balance. Unlike the rejected reserve-arithmetic shortcut, this mechanism captures the actual storage value after the SAC transfer, so donated balances and other balance/reserve divergence remain observable.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current soroswap benchmark. Each successful native pair swap transfers exactly one output token through `soroswap_pool_invoke_sac_transfer(...)`, then reads both pair token balances through `soroswap_pool_invoke_sac_balance(...)`; the output-side read can be replaced by the balance returned from the transfer that just updated the same pair balance entry.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1159-1176` - native pair swap calls SAC transfer for the nonzero output amount, then reads both balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1379` - `soroswap_pool_invoke_sac_transfer` currently delegates through `call_n_internal`, while `soroswap_pool_read_sac_contract_balance` directly reads the pair balance afterward.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - SAC `transfer` behavior that must be preserved by a direct helper.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:151-201,235-427` - typed direct contract-balance read/write helpers and `spend_balance`/`receive_balance` logic that can be extended to return the updated pair-side `BalanceValue`.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:250-263` and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:15-41` - event recording currently derives `contract_id` from the current frame, so the direct SAC helper must emit the transfer event with the explicit token contract id.

## Evidence

The current soroswap trace shows `SAC transfer` at `builtin_contracts/stellar_asset_contract/contract.rs:212` with 638,599,625 ns self-time across 15,747 calls; unwrap containment confirms 15,665 of those events and 2,477,084,982 ns total execution time occur inside `applyLedger`. The same accepted native pair code immediately performs direct pair-balance reads after the transfer, and `storage get` remains apply-contained with 224,247,260 ns self-time / 672,084,842 ns total time across 321,802 in-apply events. Prior output-balance reserve arithmetic was rejected because reserves are not actual balances; this hypothesis instead reuses the actual balance entry that SAC transfer has just read and written.

## Anti-Evidence

This is narrower than a generic SAC-transfer specialization but still touches a correctness-sensitive built-in contract. A viable PoC must preserve the SAC frame's observable authorization and event behavior even though the helper runs from the native pair frame, including explicit token-contract event attribution and fallback to `call_n_internal` for non-SAC tokens, non-contract pair owners, malformed balance entries, or any unsupported transfer shape. The reviewer should also verify that the saved output-side read and subframe scaffolding clear the Medium threshold; if only the direct read is removed and the SAC transfer frame remains, the impact may fall below 3%.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - prior work rejected reserve arithmetic and broader SAC-transfer specialization, but this exact post-spend-balance-return variant was not previously reviewed
**Failed At**: reviewer

### Trace Summary

The native Soroswap pair `swap` path transfers exactly one nonzero output token through `soroswap_pool_invoke_sac_transfer`, then reads both token balances through the accepted direct SAC balance helper. The SAC transfer body does mutate the pair's contract-balance entry for the output token, so a private helper could in principle return the post-spend amount without using reserves and without losing donations or other balance/reserve divergence. However, preserving SAC semantics still requires the SAC contract frame, auth-stack advancement, `from.require_auth`, instance/code TTL extension, balance authorization checks, balance write/TTL extension, and event emission under the token contract id; the only clearly removable work unique to this hypothesis is the immediately following output-side direct balance read. That residual saving is below the objective's Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-838` - `call_contract_fn` dispatches SAC calls by pushing `Frame::StellarAssetContract`; bypassing this frame would change current-contract identity used by auth, storage, and events.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1176` - native pair `swap` extends pair TTL, validates output amounts, calls one or both output SAC transfers, then reads both actual token balances before computing input amounts and reserves.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1393` - `soroswap_pool_invoke_sac_transfer` delegates to `call_n_internal`, while `soroswap_pool_invoke_sac_balance` first tries the accepted direct SAC contract-balance read and falls back to the public `balance` call.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1531-1729` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` - `call_n_internal` and `with_frame` provide reserved-function checks, reentry checks, diagnostics, rollback, and auth-frame/tracker advancement for each SAC transfer frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` - SAC `transfer` checks nonnegative amount, extracts the muxed destination, requires auth from the sender, extends current SAC instance/code TTL, spends the sender balance, receives the destination balance, and emits the transfer/mint/burn event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-200,303-345,357-427` - direct contract-balance reads and transfer balance updates parse/write the same `Balance(pair)` value, and `spend_balance_no_authorization_check` has the post-subtraction amount that the proposed helper wants to return.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:250-263` and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:223-233` - contract events derive their `contract_id` from the current frame, so any direct event emission outside a SAC frame would be misattributed to the pair unless a new explicit-contract event path were added.

### Why It Failed

The behavior-preserving optimization is too small for this objective. If the PoC keeps the SAC frame, as correctness requires, it keeps the expensive part of `SAC transfer`: `require_auth`, auth-frame/tracker state, instance/code TTL extension, pair-balance authorization and spend, recipient receive, storage writes, event construction, rollback, and diagnostics. The output-side balance read after the transfer is already the accepted direct helper, not the previously rejected full `balance` subframe, so eliminating one of two direct reads removes only a narrow storage/TTL/key-construction slice. The broader idea of replacing the SAC transfer machinery itself overlaps the previously rejected specialized-SAC-transfer family and still cannot skip the mandatory SAC semantics. Under the optimize-soroswap rules, this projects as Low at best and is NOT_VIABLE because Low findings are below the Medium acceptance floor.

### Lesson Learned

Capturing the post-spend pair balance from SAC transfer is the correct semantic alternative to reserve arithmetic, but after the accepted direct-balance baseline it is only an incremental read-elision. Future variants need to remove or redesign a larger mandatory phase than one direct contract-balance read, while still preserving SAC frame/auth/storage/event behavior, before they can clear the 3% soroswap apply-time threshold.
