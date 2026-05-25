# H001: Fused Native SAC Transfer-and-Balance Settlement for Native Pair Swap

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing the remaining nested SAC `transfer` frame path from the native pair swap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For next-protocol native Soroswap pair `swap` calls, output-token movement should preserve SAC `transfer` semantics exactly: reject negative or unauthorized transfers, extend the SAC instance/code TTL and touched balance TTLs, mutate the token contract's persistent `Balance(from)` and `Balance(to)` entries, emit the token contract's `transfer`/mint/burn event as appropriate, and leave the pair contract able to observe the actual post-transfer token balances before the K-invariant check. The observable ledger entries, events, auth consumption, and rollback behavior should match the current nested `call_n_internal(..., "transfer", ...)` path for the exact SAC-token/pair-owner benchmark shape.

## Mechanism

The current native pair swap still calls `soroswap_pool_invoke_sac_transfer` for each positive output amount, which pushes a full SAC frame via `call_n_internal`, runs generic SAC dispatch, clones/authenticates the current frame arguments, performs generic balance read/write helpers, and only afterwards lets the native pair read post-transfer balances through the accepted direct-balance helper. A next-protocol exact-shape helper could fuse the output transfer and post-transfer balance observation: for confirmed SAC token contracts and contract-owner pair addresses, perform the typed balance mutations directly under the explicit token contract id, emit the SAC event under that token contract id, return the actual mutated pair balance to the pair swap, and fall back to the existing nested frame for all non-exact shapes. This targets a much larger remaining phase than prior single-read elisions because the whole in-apply `SAC transfer` subtree is still present after the accepted native getter, native swap, and direct-balance optimizations.

## Trigger

Run the current next-protocol soroswap apply-load benchmark (`TX=2000,T=8`). In each matching native pair `swap` with `amount_0_out > 0` or `amount_1_out > 0`, the native path calls `soroswap_pool_invoke_sac_transfer`, then separately calls `soroswap_pool_invoke_sac_balance` for both tokens before computing `amount_*_in`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1252` — native pair `swap` still delegates output token movement to nested SAC transfer frames and then separately reads both post-transfer balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1500` — `soroswap_pool_invoke_sac_transfer` always uses `call_n_internal`, while balance reads have a direct SAC fast path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC `transfer` wrapper performs auth, TTL extension, balance spend/receive, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-199,234-346,357-428` — typed balance read/write primitives that could be refactored behind an explicit token-contract-id transfer helper.

## Evidence

The current Tracy trace from `ai-summary/CURRENT_STATE.md` shows `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` with 17,381 calls, 771,914,182 ns self-time, and 2,915,268,822 ns total time. Unwrap containment against the 71 `applyLedger` windows confirms 17,333 `SAC transfer` events and 2,910,469,315 ns of their total time occur inside `applyLedger`. The same trace also shows hot child/adjacent zones that this fusion is expected to shrink, including `push auth frame` (52,185 in-apply events, 395,868,465 ns total), `snapshot auth` (52,185 in-apply events, 235,081,358 ns total), `storage get` (356,070 in-apply events, 789,297,585 ns total), and VM/host `call` wrappers (26,079 in-apply events, 5,428,387,766 ns total).

This is distinct from the already-accepted direct SAC balance read: the current helper only bypasses read-only `balance` subframes after the transfer has completed. It is also distinct from reserve arithmetic elision because it would return the actual post-transfer balance produced by the typed SAC mutation path, preserving donated-token and external-balance divergence semantics.

## Anti-Evidence

Prior SAC-transfer specialization attempts were rejected when they only removed generic wrapper scaffolding while retaining mandatory SAC frame/auth/storage/event behavior. A viable PoC must therefore fuse a complete exact-shape transfer-and-balance operation, not just inline `contract.rs:transfer`; it must preserve direct-invoker auth semantics, token contract ids on events and storage, TTL side effects, rollback, and all non-exact fallback behavior. The full `SAC transfer` zone is an upper bound, and the PoC must prove the removed nested-frame/call machinery survives benchmark noise in three non-Tracy runs.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as this exact native output-transfer settlement fusion

### Trace Summary

The p26 native Soroswap `swap` fast path is entered from `call_contract_fn` only after the next-protocol gate, exact pool Wasm hash, `swap` symbol, argument shape, and instance-layout checks pass. Inside that native pair frame, positive output amounts still call `soroswap_pool_invoke_sac_transfer`, which constructs `transfer` and calls `call_n_internal` on the SAC token contract, pushing a full `Frame::StellarAssetContract` before running the generic SAC `transfer` implementation. After this nested frame returns, the native path separately reads both token balances through the accepted direct SAC-balance helper and then updates reserves and emits the pair event. This means the remaining output settlement path still pays subcall/frame/auth-stack machinery that is avoidable for the exact SAC-token, pair-as-owner shape if storage, event contract id, TTL, and direct-invoker semantics are explicitly reproduced.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-835` — `call_contract_fn` creates `Frame::NativeContract` for matching native Soroswap pair calls, but still uses normal `Frame::StellarAssetContract` dispatch for SAC subcalls.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1252` — native pair `swap` extends pair TTLs, validates reserves, then invokes `soroswap_pool_invoke_sac_transfer` for positive output amounts before reading balances.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1500` — transfer always goes through `call_n_internal`, while `soroswap_pool_invoke_sac_balance` already has an explicit-token SAC fast path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1864` — `call_n_internal` performs reentry checks, diagnostics, dispatch, and frame creation for the called contract.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-520` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1336-1370` — pushing each contract frame snapshots storage/events/auth and pushes an auth call-stack frame.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` checks nonnegative amount, requires auth, extends SAC instance TTL, spends/receives balances, and emits the transfer/mint/burn event.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:180-199,234-346,357-428` — current direct balance read already proves explicit token-contract-id balance access is possible; write helpers still depend on current-contract storage keys and need explicit-token variants for transfer fusion.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-64,94-114` and `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` — SAC event emission currently records under the current frame's contract id, so a direct helper must record the event under the explicit token id rather than the pair id.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-849,875-935,1146-1155` — the current SAC frame makes pair-as-`from` auth succeed via the direct-invoker rule; a fused helper must emulate that no-tracker-consumption success only for `from == current pair contract`, and otherwise fall back.

### Findings

The inefficiency exists and is on the objective's hot path: every matching native pair output transfer still pays `call_n_internal`, SAC frame push/pop, auth-frame push/snapshot, generic SAC dispatch, current-frame-dependent storage-key construction, and generic event recording before the already-direct post-transfer balance reads. This is distinct from prior failed SAC micro-optimizations: it targets the remaining nested output-transfer frame itself, not a single redundant storage probe, event-topic lookup, or post-transfer read.

The proposed fix is correctness-feasible but must be exact-shape and explicit-contract-id based. Calling existing `spend_balance`, `receive_balance`, or `event::transfer_maybe_with_issuer` directly from the pair frame would be wrong because `storage_key_from_scval`, `read_asset_info`, `read_name`, and `record_contract_event` all use the current contract id, which would be the pair, not the token. A viable PoC should instead add narrowly scoped helpers that take the SAC token `ContractId` explicitly, confirm the token instance is `ContractExecutable::StellarAsset`, operate on token-owned balance keys, extend the token instance TTL and touched balance TTLs, emit the token event with the token contract id, and fall back to the existing subcall for every non-matching shape.

The projected impact clears the review threshold as a PoC candidate. The full `SAC transfer` zone is only an upper bound, but unlike prior rejected low-tier ideas this removes a whole apply-contained subcall/frame/auth-dispatch layer on the accepted native pair path after direct balance reads have already proven a 5% class win for eliminating SAC balance subframes. Three non-Tracy runs are still required at PoC stage because storage mutation and event work remain mandatory and broad Tracy zones can overstate savings.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` (`call_native_soroswap_pool_swap`, `soroswap_pool_invoke_sac_transfer`, `soroswap_pool_invoke_sac_balance`), `builtin_contracts/stellar_asset_contract/balance.rs` (explicit-token contract-balance mutation helpers), and `builtin_contracts/stellar_asset_contract/event.rs` or `events/mod.rs` (explicit token-contract-id SAC event emission).
- **Change description**: Add a next-protocol-only `try_soroswap_pool_direct_sac_transfer_and_balance` path for confirmed SAC token contracts where `from` is the current pair contract. It should mutate the explicit token's `Balance(pair)` and recipient balance, preserve nonnegative/authorization/TTL/event semantics, return the mutated pair balance for the output token, and fall back to `call_n_internal(..., "transfer", ...)` for non-SAC tokens, non-pair `from`, unsupported recipient/asset shapes, or any uncertain semantic case.
- **Correctness check**: Existing native pair swap and SAC tests should continue to cover fallback and generic SAC behavior; add focused equivalence coverage in PoC for direct-vs-subcall output transfer with contract recipient, account recipient if supported, missing balance, insufficient balance, deauthorized balance, issuer mint/burn edge cases or explicit fallback, event contract id/topics/data, TTL extension, and rollback when the later K-invariant fails.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py` three times without Tracy against `CURRENT_STATE.md`. The target metric is soroswap `TX=2000,T=8` median apply time; Medium requires a reproducible 3-10% reduction, while max-sac regression should remain within the objective's accepted tradeoff envelope.
