# H002: Storage-Map-Resolved Native Router Swap

**Date**: 2026-05-26
**Subsystem**: soroban-env
**Severity**: High
**Impact**: Soroswap apply-time reduction by removing the remaining router Wasm frame without pair-hash reconstruction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the vendored apply-load Soroswap router, a successful next-protocol `swap_exact_tokens_for_tokens(amount_in, amount_out_min, [token_in, token_out], to, deadline)` with the benchmark's two-token path should produce the same TTL extensions, input SAC transfer, pair swap, reserve update, events, auth checks, and rollback behavior as the Wasm router path. Non-matching code hashes, functions, argument shapes, path lengths, deadlines, pair layouts, or ambiguous pair candidates should fall back to normal Wasm execution.

## Mechanism

The current host only recognizes native Soroswap behavior after the router Wasm has already been instantiated and has called into the pair. That leaves 8,079 apply-contained `Vm::instantiate_wasmi` events in the current trace, including 467,581,245 ns self-time in `Vm::instantiate_wasmi - instantiate`, plus 1,166,051,341 ns self-time in generated VM host-call dispatch. A native router fast path can avoid the previous failed pair-ID hashing design by resolving the pair from the already-loaded enforcing storage map: scan the small footprint for exactly one contract instance whose executable is the vendored pool hash and whose instance-storage token addresses match the two-token path, then call the existing native pair swap path in deterministic order.

## Trigger

Run apply-load soroswap with the current setup. `ApplyLoad::generateSoroswapSwaps` invokes the router contract at `swap_exact_tokens_for_tokens` with args `(i128(100), i128(0), [token_in, token_out], source_account_address, u64::MAX)` and includes router code/instance, pair code, pair instance, SAC instances, trustlines, and pair SAC balances in the footprint.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:794-825` — `call_contract_fn` currently checks native pool paths only after matching a pool contract; router calls still instantiate Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — existing native pair `swap` matcher can be reused once the router fast path resolves the pair contract id and output direction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1502` — existing native pair swap implementation already preserves pair TTL, SAC transfer/balance behavior, reserve updates, invariant checks, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — fresh wasmi store/instance construction that the router fast path would bypass.
- `src/simulation/ApplyLoad.cpp:3412-3496` — benchmark trigger shape and footprint/auth layout for router swaps.

## Evidence

The vendored router hash is `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07`, and `wasm-tools print` confirms it exports `swap_exact_tokens_for_tokens`. In the current trace, unwrap containment shows 8,079 of 8,113 `Vm::instantiate_wasmi` events inside `applyLedger`; the current successes have already made pool getters, pair swap, and direct SAC balance reads native, so the router frame is the remaining Wasm layer around a mostly native downstream path. Resolving the pair from loaded storage-map contents avoids the known-expensive pair-salt XDR/SHA256 reconstruction that caused prior router-native attempts to regress.

## Anti-Evidence

Prior router fast paths failed or became unviable because pair resolution either performed too much new metered hashing/XDR work or lacked a clean correctness gate. This variant must prove that the storage-map scan is deterministic, cheap, unique, and semantically equivalent for the exact benchmark path; it must also faithfully reproduce router deadline, amount-out-min, path validation, factory-initialization behavior, and error fallback ordering before it can clear review.
