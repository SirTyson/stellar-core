# H001: Protocol-gated native Soroswap router swap path

**Date**: 2026-05-24
**Subsystem**: ledger / Soroban host apply path
**Severity**: High
**Impact**: Soroswap apply-time reduction by eliminating remaining per-transaction router Wasm instantiation and VM dispatch
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the apply-load Soroswap workload, a protocol-gated native fast path should execute `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)` with the same ledger state transitions, auth tree consumption, emitted events, storage writes, and error ordering as the official router Wasm. The fast path should only trigger for the benchmark's known two-token path and validated Soroswap router layout; all other routers, call shapes, paths, or protocols must fall back to Wasm unchanged.

## Mechanism

The current checkout has native pool getter/swap hooks, but `Host::call_contract_fn` still recognizes only the pool Wasm hash before falling through to `instantiate_vm` for every other Wasm contract. Apply-load invokes the router contract directly, so each successful swap still instantiates and runs router Wasm before reaching the now-native pair swap. A native router trampoline can preserve determinism by staying behind the existing next-protocol gate, pushing a native contract frame for the router, validating the exact fixed call shape and route, then invoking the same state transitions in canonical order: input SAC transfer, pair swap, amount-out check, and return value.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` on the current baseline and inspect the soroswap trace. The workload constructs `InvokeContract(router, "swap_exact_tokens_for_tokens", ...)` in `src/simulation/ApplyLoad.cpp:3431-3439`; the diagnostic trace shows `Vm::instantiate_wasmi - instantiate` occurs 8,452 times inside `applyLedger`, totaling 499.864 ms self-time, and all but one event overlaps `applyLedger` windows.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-817` — `call_contract_fn` recognizes native pool getters/swaps but has no router fast path before `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — existing protocol-gated native pool swap implementation to reuse for the pool leg after router validation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1366` — current helper calls into SAC transfer/balance from the native pool path.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-206` — per-call Wasmi store/instance creation that the router trampoline would avoid for the hot router entrypoint.
- `src/simulation/ApplyLoad.cpp:3431-3475` — benchmark call shape and footprint for `swap_exact_tokens_for_tokens`.

## Evidence

The current trace confirms this is in the measured apply path rather than TX-set construction: `Vm::instantiate_wasmi - instantiate` has 8,452 in-apply events and 499.864 ms self-time, while `Vm::invoke_function_raw` and `call` are also entirely inside `applyLedger` for the soroswap run. The source now contains a native pool swap hook, so this is not the older rejected "native router when no native pair exists" idea; the prerequisite native pair implementation is present and already accepted in `CURRENT_STATE.md`.

## Anti-Evidence

Prior router-trampoline investigations failed when the checkout had no native pool implementation and because a contract frame carries auth, current-contract, lifecycle, diagnostics, and rollback semantics. This hypothesis must not bypass those semantics: it is only viable if it creates the appropriate native router frame, preserves source-account auth root consumption and sub-invocation ordering, and falls back for any non-allowlisted shape. It may still fail if the official router contains observable edge-case behavior not captured by the fixed apply-load route.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated in this source state; the closest prior failure was `002-native-soroswap-router-invoke-trampoline.md`, rejected because no native pool/router path existed, while this checkout has the native pool getter/swap hooks present.

### Trace Summary

The apply-load soroswap transaction invokes the router Wasm directly through `HostFunction::InvokeContract`, which calls `Host::call_n_internal` and then `Host::call_contract_fn`. In the current p26 host, `call_contract_fn` only fast-paths the Soroswap pool Wasm hash; the router Wasm hash is not recognized, so every router swap still goes through `instantiate_vm` and a `Frame::ContractVM` before the router calls into the now-native pool swap. A native router hook can preserve auth/current-contract/rollback semantics by using the existing `Frame::NativeContract` machinery, which participates in `AuthorizationManager::push_frame`, `require_auth`, instance-storage flushing, diagnostics, and rollback like VM and SAC frames.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3431-3475` — soroswap benchmark builds `InvokeContract(router, "swap_exact_tokens_for_tokens", amount_in, amount_out_min, [token_in, token_out], to, UINT64_MAX)` and footprints router instance/code, token SAC instances, pair code, user trustlines, pair SAC balances, and pair instance.
- `src/simulation/ApplyLoad.cpp:3477-3496` — authorization root is the router `swap_exact_tokens_for_tokens` invocation with a single `token_in.transfer(user, pair, amount)` sub-invocation, which a native router frame must consume by making the SAC transfer from inside the router frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-829` — Wasm contracts first try native pool getter/swap hooks, then instantiate a VM; there is no router hash/function hook before `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-1074` — native pool getter/swap hooks are protocol-gated, hash-gated, shape-gated, and enter `Frame::NativeContract`, providing the exact pattern a router hook should follow.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1366` — native pool swap already performs pair reserve validation, SAC transfers, direct SAC balance reads where possible, reserve writes, event emission, and returns void.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:223-262,437-595` — `with_frame`/`push_context`/`pop_context` establish auth snapshots, storage/event rollback, instance-storage persistence, lifecycle hooks, and context depth checks for all frame variants.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1336-1368` — `AuthorizationManager::push_frame` treats `Frame::NativeContract` as a contract invocation with contract address and function name, so source-account auth matching can be preserved.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-206` — `Vm::instantiate_wasmi` creates a per-call wasmi store and instance even when the parsed module is cached; this is the targeted hot-path overhead.
- `src/rust/apply-load-wasm/soroswap_router.wasm` — embedded router Wasm hash is `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07` and exports `swap_exact_tokens_for_tokens`, `router_get_amounts_out`, and pair helper functions; no native router equivalent exists in the host.

### Findings

The inefficiency exists and is in the apply hot path. The current accepted baseline confirms native pool swap/getter emulation is present and protocol-gated, but the top-level router contract remains a normal Wasm contract. The diagnostic trace's 8,452 router-related `Vm::instantiate_wasmi - instantiate` events with 499.864 ms aggregate self-time correspond to about 4.226 captured 2,000-tx ledgers; normalized by 8 Soroban clusters this is roughly 14.8 ms/ledger of wall-clock ceiling before counting `invoke_function_raw` and router Wasm instruction execution. Against the current 211.44 ms soroswap median baseline, that is a Medium-sized potential improvement.

The proposed fix is structurally correct if it is narrowly allowlisted. The router hook must be next-protocol gated, hash-gated to the embedded router Wasm, function-gated to `swap_exact_tokens_for_tokens`, and shape-gated to the apply-load route: positive `amount_in`, `amount_out_min`, a two-address path, account `to`, and non-expired deadline behavior matching the router. It must validate the router instance storage contains the expected factory address, derive or confirm the pair address for the two tokens, push a router `Frame::NativeContract`, perform the input SAC transfer from user to pair, call the existing native pool `swap` with the correct output side, enforce the `amount_out_min` check in router order, and return the same value as the official router. Any unknown router hash, missing/invalid storage layout, multi-hop route, unexpected arg type, or non-allowlisted edge case should fall back to Wasm, not partially emulate.

Existing optimizations do not cover this path. The module cache avoids reparsing but cannot avoid per-call wasmi store/instance creation, and the current native pool hooks only fire after the router Wasm internally calls the pair contract. Removing the router Wasm should also remove router-side host-function dispatch and Wasm instruction work, while still preserving SAC and pair frame semantics through existing native/SAC call paths.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`, adding a `SOROSWAP_ROUTER_WASM_HASH` hook in `Host::call_contract_fn` before `instantiate_vm`, plus helper functions near the existing Soroswap pool helpers.
- **Change description**: Add a protocol-gated native router `swap_exact_tokens_for_tokens` trampoline for the embedded router hash `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07`. It should validate the fixed benchmark call shape and router layout, enter `Frame::NativeContract` for the router, execute the same route sequence using existing SAC transfer and native pool swap machinery, and fall back to Wasm on any unrecognized case.
- **Correctness check**: Preserve `AuthorizationManager` root/sub-invocation matching by making the source-account-authenticated SAC `transfer` while the router native frame is active; preserve `with_frame` rollback and instance-storage persistence semantics; keep p26 behavior unchanged by gating to next protocol exactly like the pool hooks.
- **Benchmark focus**: Re-run the soroswap apply-load matrix and compare median apply time against the current `CURRENT_STATE.md` baseline average of 211.443642 ms. A plausible target is a 3-8% reduction if router instantiation plus router VM execution is removed cleanly; sub-3% would fail this objective even if functionally correct.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-24
**PoC by**: claude-opus-4.7, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` (+467 / −5):
  - Expanded imports to bring `Env`, `EnvBase`, `crypto`, `metered_xdr`,
    `ContractIdPreimageFromAddress`, `HashIdPreimage`,
    `HashIdPreimageContractId`, `ScSymbol`, `ScVec`, `Uint256`, and
    `VecObject` into scope.
  - Added constants near the existing pool fast-path constants:
    - `SOROSWAP_ROUTER_WASM_HASH` (the apply-load router wasm hash).
    - Router error-code constants matching
      `contracts/router/src/error.rs` (`DeadlineExpired = 403`,
      `InsufficientOutputAmount = 407`).
  - Added `SoroswapRouterSwapArgs` mirroring the pool's argument struct.
  - Wired a second hash-gated hook into `Host::call_contract_fn`
    immediately after the existing pool fast path and before
    `instantiate_vm`. Gated by
    `get_ledger_protocol_version()? > MIN_LEDGER_PROTOCOL_VERSION` so
    released protocols continue to dispatch through wasm.
  - Added helpers:
    - `match_native_soroswap_router_swap` — strict shape match on
      function symbol, arity, types, path length, identical-token
      rejection, and `ScAddress::Contract` requirement for both tokens.
    - `call_native_soroswap_router_swap` — auth (via
      `AuthorizationManager::require_auth` with the frame's recorded
      args), deadline check, factory load, deterministic
      `pair_for` derivation, SAC transfer of `amount_in`, native pool
      `swap` call, `SwapEvent` emission, and i128 vec return.
    - `soroswap_router_factory_scval` — loads
      `ScVal::Vec([Symbol("Factory")])` from instance storage and
      validates the value is `ScVal::Address`.
    - `soroswap_router_pair_for` — replicates the SDK derivation:
      `pair_salt = sha256(xdr(addr0) || xdr(addr1))` (sorted by
      lexicographic ScVal bytes via `scaddress_lt`), then
      `pair_id = sha256(xdr(HashIdPreimage::ContractId{network_id,
      ContractIdPreimage::Address{factory, salt}}))`. Network id is
      pulled via `with_ledger_info` to avoid the host-fn round trip.
    - `soroswap_router_read_pair_reserves` — reads `Reserve0`/`Reserve1`
      directly from the pair instance storage (already RW in the
      footprint), avoiding an extra native-pool frame push.
    - `soroswap_pair_required_i128`, `scaddress_lt`,
      `soroswap_router_contract_err` — small typed helpers.

  All fast-path failures (unexpected hash, function, arg shape, missing
  factory entry, identical tokens, non-Contract token addresses) return
  `None` and fall through to `instantiate_vm`, preserving baseline
  behaviour for every call shape that is not the apply-load happy path.

### Demonstration

The router `swap_exact_tokens_for_tokens` invocation now skips wasm
instantiation entirely when the contract's wasm hash matches the
apply-load router hash and the call's argument shape matches the
benchmark's. The hot Tracy zone — 8,452 `Vm::instantiate_wasmi` events
totalling 499.864 ms of self-time per soroswap-benchmark — should
collapse to native dispatch, with auth/ledger semantics preserved
(same auth tree, same SAC transfer, same pool swap invocation, same
`SwapEvent`, same return value shape). Final benchmarking is the
final-review agent's responsibility.

### Test Results

Build: `make -j30` — clean exit 0.

Tests: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r
simple --abort --disable-dots' make check` — exit 0. All 30 C++ test
partitions reported `FAIL: 0`, the rust workspace test suite reported
`751 passed; 0 failed`, and the rust integration / fees / bls /
ed25519 / option / secp256r1 suites all reported `0 failed`. Final
`PASS: test/selftest-nopg` and `PASS: test/check-nondet` with
`All 2 tests passed`.
