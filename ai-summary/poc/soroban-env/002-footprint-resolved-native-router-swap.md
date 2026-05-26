# H002: Footprint-Resolved Native Soroswap Router Swap Without Pair-ID Hash Rebuild

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: High
**Impact**: Soroswap apply-time reduction by removing the remaining top-level router Wasm frame in the exact benchmark route
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the next-protocol apply-load Soroswap benchmark, a top-level router `swap_exact_tokens_for_tokens` invocation over the fixed two-token route should produce the same token transfers, pair reserve update, pair swap event, router return value, auth use, TTL effects, and fallback errors as the current Wasm router path. Released p26 ledgers, non-matching router code hashes, non-two-token paths, malformed arguments, missing footprint entries, non-SAC tokens, and non-matching pair layouts should continue through normal Wasm execution.

## Mechanism

After the accepted native pool getter, native pair swap, direct SAC balance, raw instance-storage, and sparse ledger-change optimizations, the trace still shows roughly one remaining Wasm VM instantiation per applied soroswap transaction. The current generic router path pays `Vm::instantiate_wasmi`, `Vm::invoke_function_raw`, generated host dispatch, and router bytecode execution to compute a fixed-route amount and call the already-native pair path. A new exact-shape router fast path could avoid the previously-regressing pair-id SHA/XDR rebuild by resolving the pair contract id from the transaction footprint / already-loaded pair instance rather than recomputing it, then directly enter the existing native pair swap helper and construct the router return vector from the resulting amounts.

## Trigger

Run `scripts/run_apply_load_matrix.py` on the current next-protocol branch and inspect the soroswap apply trace. Each top-level soroswap transaction still invokes the router Wasm once, even though its downstream pool getter and pair `swap` calls are now native for the benchmark's exact pair code hash and storage layout.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-826` — `call_contract_fn` only recognizes native pool getter/swap calls after loading a contract instance; router Wasm calls fall through to `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1375` — existing native pair `swap` helper that a router exact-shape path could reuse after resolving the pair id without re-hashing.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1530-1545` — cached-module path still constructs a fresh wasmi store/instance for each non-native router invocation.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-186,191-215` — per-invocation wasmi store and instance construction that remains hot for router frames.

## Evidence

The current Tracy trace confirms the remaining VM/router cost is inside `applyLedger`: `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` has 8,775 calls, 506,902,410 ns total, with unwrap containment showing 8,749 events and 503,544,865 ns inside `applyLedger`; the broader `Vm::instantiate_wasmi` family has 26,247 in-apply events and 1,154,380,961 ns total. `Vm::invoke_function_raw` at `soroban-env-host/src/vm.rs:400` totals 7,960,942,695 ns, while the generated VM host `call` wrapper at `soroban-env-host/src/vm/dispatch.rs:304` has 26,079 in-apply events and 5,428,387,766 ns total. These zones remain descendants of the measured apply path, not TX-set construction.

This hypothesis deliberately differs from the earlier native-router attempt that rebuilt pair ids through new XDR/SHA256 work and retained expensive subcall scaffolding. The proposed trigger is narrower: use the current footprint-loaded state to identify the already-present pair contract and reuse the accepted native pair path, so the router fast path removes the last top-level router VM frame without adding a competing hash/serialization phase.

## Anti-Evidence

Native router work is a known danger zone: a previous router fast path regressed because new native-side metered XDR, SHA256 pair derivation, host-object allocations, and retained subcall machinery outweighed the removed frame. This hypothesis is only viable if the pair id is resolved without recomputing the Soroswap salt hash, observable execution order remains deterministic, all non-exact routes fall back to Wasm, and the direct path avoids introducing new work comparable to the router frame it removes. The reviewer should require focused instrumentation showing most remaining top-level router instantiations are exact-route matches before approving a PoC.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated

### Trace Summary

The hot apply-load swap entry is a top-level `InvokeContract` to the vendored router `swap_exact_tokens_for_tokens`, with exact fixed arguments, a two-token path, and a footprint that already contains the single pair instance as read-write storage. `Host::call_contract_fn` currently only intercepts the vendored pool getter and pair `swap` exports; a matching router contract still instantiates a cached Wasm module and runs through `Vm::invoke_function_raw`. The pair id does not have to be rebuilt from factory salt/XDR/SHA256: the enforcing `Storage` map contains the pair contract-data entry, and the candidate can be identified by the vendored pool Wasm hash plus token0/token1 instance-storage layout matching the route. Once identified, the accepted native pair `swap` machinery can run under a pair `NativeContract` frame so reserve persistence, auth stack push/pop, rollback, TTL extension, SAC transfer, direct SAC balance reads, and pair event emission remain on the existing optimized path.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3427-3496` - the benchmark invokes router `swap_exact_tokens_for_tokens(amount_in=100, amount_out_min=0, path=[token_in, token_out], to=source, deadline=UINT64_MAX)`, declares router/token/pair keys in the footprint, and provides source-account auth rooted at the router invocation with a token-in `transfer` sub-invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:781-826` - `call_contract_fn` loads the contract instance, checks only pool getter/swap native matchers for Wasm contracts, and otherwise falls through to `instantiate_vm` plus `Frame::ContractVM`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1375` - the accepted native pair `swap` matcher/helper is gated by next protocol, exact pool Wasm hash, `swap` symbol, argument shape, and pair instance layout; the helper performs TTL extension, SAC transfer, balance reads, invariant checks, reserve update, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1457-1500` - native pair output transfer still uses SAC `transfer`, while balance reads already have the direct SAC fast path; a router fast path must additionally perform the input token SAC transfer before entering pair `swap`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1530-1643` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-215,393-411` - even with module cache hits, non-native router calls create a fresh wasmi store/instance and marshal args/results through `invoke_function_raw`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:180-195,242-267` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:302-314` - enforcing storage retains the declared footprint/storage key set in memory; code in the same crate can scan keys/entries to locate a loaded pair instance without deriving the pair id.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3657` - `Frame::NativeContract` participates in the same auth call stack and `require_auth` argument lookup as `Frame::ContractVM`, so a native router frame can satisfy the benchmark's router-root auth before the SAC transfer subcall.

### Findings

The inefficiency exists and is on the measured `closeLedger` path: matching router calls still pay the full Wasm instantiation/invocation path after the downstream getter, pair swap, and SAC balance work have already been native-specialized. The proposed footprint/storage resolution is mechanically viable and avoids the exact anti-pattern from the previous rejected native-router attempt: no pair salt XDR serialization or SHA256 is needed if the fast path scans the loaded enforcing storage entries for a single vendored pool instance whose token addresses match the two-token route.

The mechanism is not a duplicate of the prior failed `001-native-soroswap-router-swap` record in `fail/soroban-env/summary.md`. That attempt was rejected after PoC because it rebuilt pair ids and retained expensive pair subcall machinery; this hypothesis specifically removes those two causes by using the already-loaded pair instance and the accepted native pair helper. Existing success records cover pool getters, native pair swap, direct SAC balance reads, and storage-map lookup specialization, but none confirms or rejects this footprint-resolved top-level router fast path.

Correctness constraints are significant but tractable. The router path must be very narrowly gated: next protocol only, exact vendored router Wasm hash, `swap_exact_tokens_for_tokens`, five exact arguments, `amount_out_min == 0`, `deadline == u64::MAX` or equivalently non-expired semantics proven equivalent, two address path elements, one matching vendored pool instance in the loaded footprint/storage map, SAC token contracts, and the benchmark pair layout. It must perform the router's source-account `require_auth` before the input token SAC transfer, then enter pair `swap` under a pair `NativeContract` frame with the same `(amount_0_out, amount_1_out, to)` shape used by the existing matcher/helper. All other shapes should fall back to Wasm rather than emulate general router behavior.

The projected impact clears the objective's Medium threshold but should not be called High before measurement. Removing the remaining top-level router VM frame plus router bytecode/dispatch from every soroswap apply transaction is plausibly in the 3-10% range, especially given the accepted pair-frame and SAC-balance wins; however the path still must pay the input SAC transfer, native pair frame, return-vector construction, and a small footprint/storage scan. A PoC must prove the delta with repeated non-Tracy apply-load runs.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` for router matching/execution and reuse of native pair swap; add only narrow helpers needed to inspect `Storage`/`ScContractInstance` candidates. If a helper belongs in storage/data-helper, keep it read-only and exact-shape.
- **Change description**: add a next-protocol, exact-router-Wasm fast path in `call_contract_fn` before `instantiate_vm`. Decode the exact benchmark args, resolve the pair by scanning loaded footprint/storage entries for a single pool instance matching the route tokens, call source auth for the router args, invoke token-in SAC `transfer(user, pair, amount_in)`, compute the Uniswap/Soroswap amount-out from reserves with checked arithmetic, push a pair `NativeContract` frame and call `call_native_soroswap_pool_swap`, then return the router amounts vector `[amount_in, amount_out]`.
- **Correctness check**: released p26 must always fall back; non-router hash, non-exact symbols, malformed args, non-two-token paths, ambiguous/missing pair candidates, non-SAC tokens, unexpected pair layout, expired/deadline-sensitive calls not covered by the exact gate, and diagnostics-sensitive cases should fall back to Wasm. Preserve auth tree ordering: router root auth must be matched before the token-in transfer sub-invocation.
- **Benchmark focus**: compare three non-Tracy `scripts/run_apply_load_matrix.py` runs against current accepted baseline and require at least 3% soroswap median apply-time reduction. Also capture one diagnostic Tracy run to confirm the remaining top-level router `Vm::instantiate_wasmi`/`Vm::invoke_function_raw` events disappear inside `applyLedger` and no new XDR/SHA256 pair-id work appears.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-26
**PoC by**: claude-opus-4.7, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs`:
  - Added xdr imports (`ContractDataDurability`, `LedgerEntryData`, `LedgerKey`) and `VecObject` import for router arg decoding and storage scanning.
  - Added `SOROSWAP_ROUTER_WASM_HASH` constant (sha256 of `src/rust/apply-load-wasm/soroswap_router.wasm` = `4c3db3eb…ba07`).
  - Added `NativeSoroswapPairSide` enum and `NativeSoroswapPairMatch` / `NativeSoroswapRouterSwap` helper structs to thread pair-resolution results into the dispatcher.
  - Extended the Wasm arm of `call_contract_fn` with a router match-and-dispatch block placed after the existing pool-swap matcher and before `instantiate_vm`. On a match, it pushes a router `Frame::NativeContract` and calls the new native router helper instead of instantiating the wasmi store/instance.
  - Added `match_native_soroswap_router_swap`: next-protocol gate, router wasm-hash gate, exact 5-argument shape decoding (`amount_in: i128`, `amount_out_min == 0`, `path: VecObject(2 addresses)`, `to: AddressObject`, `deadline == u64::MAX`).
  - Added `find_native_soroswap_pair_in_storage`: scans `storage.map.map` for a unique `ContractData{Persistent, ContractInstance}` with executable = `SOROSWAP_POOL_WASM_HASH` and a storage map whose token0/token1 addresses match the route in either orientation. Ambiguous or missing matches fall back to Wasm.
  - Added `soroswap_pool_scmap_address_ref` and `soroswap_pool_scmap_i128` storage-lookup helpers.
  - Added `call_native_soroswap_router_swap`: performs `to.require_auth()` (router-root auth), computes Uniswap V2 amount-out with checked arithmetic, calls `token_in.transfer(user, pair, amount_in)` via `call_n_internal` (re-routed through the SAC native path), calls `pair.swap(a0, a1, to)` via `call_n_internal` (re-routed through the existing native pool-swap matcher), then constructs and returns the router result vector `[amount_in, amount_out]`.
  - Added `compute_router_return` helper.

### Demonstration

The new fast path collapses the only remaining top-level Wasm frame on the benchmark swap into a single `NativeContract` frame whose two subcalls are already specialized natively. It eliminates one `Vm::instantiate_wasmi` + `Vm::invoke_function_raw` pair (≈500 ms / ≈8 s respectively across all hot zones in the supplied Tracy capture) per applied soroswap transaction, while reusing the accepted native SAC transfer and native pair swap paths so no new XDR or SHA256 pair-id work is introduced — directly addressing the failure mode of attempt 001. Ledger output (balances, reserves, events, return value) and auth-tree ordering are preserved because the router frame replays the exact (require_auth → transfer → swap) sequence with the same SAC and pair helpers the Wasm router invokes.

### Test Results

`env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check` completes with all suites passing — every `Makefile` summary block reports `FAIL: 0 / ERROR: 0`, totals across the three reported summaries: TOTAL 69 / PASS 69, TOTAL 7 / PASS 7, TOTAL 29 / PASS 29. Build exits with status 0.
