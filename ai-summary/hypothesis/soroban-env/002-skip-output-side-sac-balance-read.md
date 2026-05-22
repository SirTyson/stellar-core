# H002: Skip output-side SAC balance read in native single-output pair swaps

**Date**: 2026-05-22
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by eliminating one of the two post-transfer SAC `balance` calls in each native pair swap
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a next-protocol native Soroswap pair `swap` where exactly one output amount is positive and the output token is a Stellar Asset Contract, the pair's post-transfer balance for the output token should be `old_reserve - amount_out` immediately after a successful SAC `transfer(pair, to, amount_out)`. The host should still read the input-side SAC balance to detect the actual input amount, enforce the same liquidity/input/K-invariant checks, update reserves to the same final values, emit the same pair event, and fall back to the current implementation for released p26 ledgers, non-SAC tokens, both-output swaps, zero-output swaps, or any shape not proven exact.

## Mechanism

The accepted native pair `swap` performs the output SAC transfer and then calls `soroswap_pool_invoke_sac_balance` for both token balances. For the output side in the benchmark's single-output SAC swaps, the successful SAC transfer has just subtracted exactly `amount_out` from the pair's contract balance; re-entering the SAC `balance` function for that same output token only confirms a value the native pair already knows. A gated single-output helper can compute the output-side post-balance from reserves and amount-out, read only the input-side SAC balance, and then run the existing input amount and K-invariant logic with the same final reserve values.

## Trigger

Run the current accepted soroswap benchmark (`soroswap, TX=2000, T=8`). Each generated route produces a pair `swap` with one positive output amount and one zero output amount; the accepted native pair path performs one SAC output transfer and then two SAC balance reads.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1155-1173` at accepted p26 commit `03d78248` — output transfer followed by unconditional `balance_0` and `balance_1` SAC reads.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1175-1223` at accepted p26 commit `03d78248` — input amount inference can use one computed output-side balance plus one actual input-side balance.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1239-1263` at accepted p26 commit `03d78248` — K-invariant and reserve update consume the two post-transfer balance values.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — a successful SAC transfer is exact for the pair's output token balance mutation.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:335-405` — SAC contract-balance spend/receive logic either applies the exact amount or returns an error before the native pair continues.

## Evidence

The current diagnostic trace shows `SAC balance` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:187` with 416.970093ms total across 14,894 calls, and unwrap containment confirms 14,830 calls / 415.920127ms are inside `applyLedger`. The call count is approximately two per successful pair swap, matching `call_native_soroswap_pool_swap`'s unconditional reads of token0 and token1 after the output transfer.

The source-level invariant is stronger than a generic balance cache: the native pair itself just executed the output transfer and stops immediately on any SAC error. In the exact one-output SAC shape, there is no intervening code that can mutate the pair's output-token balance before the pair computes `amount_0_in` / `amount_1_in`.

## Anti-Evidence

This must not be applied to arbitrary pair swaps. The original pair contract reads actual balances to support externally donated input tokens and unusual swap shapes; the fast path should still read the input side and should fall back when both outputs are positive or when token/owner shapes are not the accepted SAC benchmark shape. It also only removes roughly half of the `SAC balance` aggregate, and the remaining input-side read plus storage/TTL work remains; a PoC must show that removing one read per swap clears the 3% Medium floor after benchmark noise.
