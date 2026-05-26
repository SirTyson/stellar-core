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

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The top-level `InvokeContract` path decodes the router call, enters `call_n_internal`, and reaches `call_contract_fn`, where only the pool hash is currently recognized before falling through to `instantiate_vm` for the router Wasm. The enforcing `Storage` is built from the declared footprint and ledger-entry payloads before host execution, and its sorted `StorageMap` contains the pair contract instance entry used by the benchmark. Existing native pair `swap` handling is already hash-, symbol-, arity-, argument-, and storage-layout gated, so a router fast path can use a deterministic storage-map scan only to resolve the pair id/direction, then invoke the existing native pair path through normal frame/auth/rollback machinery.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-825` — `call_contract_fn` loads the contract instance, recognizes native pool getters/swap only for `SOROSWAP_POOL_WASM_HASH`, and otherwise instantiates Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — native pair `swap` matcher already gates on next protocol, exact pool hash, `swap`, arity 3, i128/address argument shape, and pair storage layout.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1502` — native pair `swap` preserves pair TTL extension, output SAC transfer, balance reads, reserve updates, invariant checking, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:436-594` and `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` — `Frame::NativeContract` participates in the same rollback and authorization stack as VM and SAC frames.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:180-195,323-352` — enforcing storage holds the preloaded footprint-backed `StorageMap`; key order is deterministic and values are already resident.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-523,1039-1151` — host invocation constructs the footprint/storage map from XDR inputs, adds absent footprint keys as `None`, then builds `Storage::with_enforcing_footprint_and_map`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — router fallback pays fresh wasmi store/instance setup.
- `src/simulation/ApplyLoad.cpp:3412-3496` — benchmark calls the fixed router function with a two-token path and includes the router, pair, SAC, trustline, and balance entries needed by the proposed scan.

### Findings

The inefficiency exists and is in the soroswap apply hot path: the router Wasm hash is not recognized today, so every benchmark swap still pays a router VM instantiation and Wasm host-call dispatch before reaching the already-native pair path. Existing optimizations cover pool getters, pair `swap`, and pair SAC balance reads, but not the outer router frame.

The proposed storage-map resolution is materially different from the prior failed router attempts. It does not reconstruct a pair salt or hash a contract-id preimage, and it does not rely solely on footprint key presence; it can inspect the already-loaded `ScContractInstance` value and require exactly one `ContractData(LedgerKeyContractInstance)` candidate whose executable is `SOROSWAP_POOL_WASM_HASH` and whose instance-storage token addresses match the router path. The `MeteredOrdMap` backing storage is sorted deterministically, and ambiguity can safely fall back to Wasm.

The fix must preserve correctness by keeping the normal router invocation frame, validating exact router hash/function/arity/argument shape/path length/deadline/order, performing the input SAC `transfer` via `call_n_internal`, computing the exact two-token amount-out value, enforcing `amount_out_min`, and invoking the existing pair `swap` via `call_n_internal` so pair auth, TTL, reserve update, event, and rollback behavior remain centralized. Any malformed, missing, non-unique, non-SAC/pair, or non-benchmark-shaped case should return `Ok(None)` from the matcher and fall through to Wasm.

Severity is Medium rather than High at review: the eliminated work is one router VM frame per swap plus its ABI dispatch overhead, while mandatory router frame/auth, input SAC transfer, and pair native swap work remain. The cited trace and call count support a plausible 3-10% apply-time win if the storage scan stays small and hash-free, but the claim needs benchmark confirmation before being considered High.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`, with a small helper to scan `Host` storage for the unique matching pair instance; add a router hash constant for `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07`.
- **Change description**: In `call_contract_fn`, before `instantiate_vm`, recognize next-protocol router calls with exact hash `swap_exact_tokens_for_tokens` and args `(i128, i128, VecObject length 2 of AddressObject, AddressObject, u64)`. Push a `Frame::NativeContract` for the router, validate deadline/path/amounts, scan the resident enforcing `StorageMap` for exactly one matching pool instance, call input-token SAC `transfer(from/to benchmark account, pair, amount_in)` through `call_n_internal`, compute the output amount using the router's `get_amount_out` formula, check `amount_out_min`, then call pair `swap` through `call_n_internal` with output direction derived from token order.
- **Correctness check**: Existing frame/auth/storage/SAC behavior is covered by the Soroban host and SAC test suites, but this path needs focused native-vs-Wasm equivalence coverage for exact success, expired deadline, short/long path, wrong arg tags, ambiguous/no pair candidate, wrong pool hash, insufficient output, and rollback after downstream SAC/pair failure.
- **Benchmark focus**: Run `scripts/run_apply_load_matrix.py` without Tracy at least three times and compare soroswap median apply time against the current accepted baseline. The review threshold is a reproducible 3-10% improvement; also confirm max-sac does not regress materially.
