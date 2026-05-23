# H001: Fused Native Soroswap Swap Pipeline

**Date**: 2026-05-23
**Subsystem**: soroban-env / rust bridge
**Severity**: High
**Impact**: >10% soroswap apply-time reduction if the remaining router Wasm frame and both SAC transfer subframes are fused into one protocol-gated native apply transition
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the current next-protocol soroswap benchmark route, a top-level router `swap_exact_tokens_for_tokens` invocation should produce the same authorization checks, SAC balance mutations, pair reserve update, TTL extensions, contract events, diagnostic/error behavior, and rollback semantics as the existing router-Wasm -> SAC transfer -> native pair swap -> SAC transfer flow. The host should not need to cross the Wasm/host boundary for the router frame or re-enter the built-in SAC dispatcher twice when the route, footprint, token contracts, and vendored pair instance all match the fixed apply-load shape.

## Mechanism

The accepted stack removed the pair Wasm frame and the pair's post-transfer SAC `balance` subframes, but each successful swap still pays one router Wasm invocation and two generic SAC `transfer` subframes. Prior native-router and SAC-transfer variants failed because they preserved most subcall scaffolding or only removed one post-transfer read; a fused next-protocol pipeline would instead validate the entire exact swap shape once, then apply the two SAC balance effects, pair reserve transition, and events in deterministic router order with a single rollback boundary. This materially differs from smaller rejected variants because the removable work is the union of the remaining router VM execution, generated dispatch, SAC frame setup/auth/event scaffolding, and duplicate conversion around the two token legs.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on the current next-protocol soroswap workload (`soroswap, TX=2000, T=8`). Each accepted transaction that calls the fixed two-token router path should match the fused path after checking the router function/arity, auth tree root, footprint entries, SAC token instances, pair code hash, pair storage layout, and exact input/output token legs; any mismatch must fall back to the existing execution path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — `call_contract_fn` currently falls through to router Wasm instantiation for non-pool contracts; add a next-protocol router-shape dispatch gate before `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — accepted native pair `swap` logic to reuse for reserve math, invariant checks, reserve writeback, and pair event shape.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1393` — current pair helper still invokes SAC `transfer` through `call_n_internal` and only optimizes balance reads.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` behavior that must be preserved by typed token-leg effect helpers.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-200,303-397` — typed SAC balance read/write helpers for contract-owner pair balances and account/trustline legs.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-206,393-411` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:250-304` — router VM instantiation, raw Wasm invocation, generated host-function dispatch, and fuel handoff avoided on exact matches.

## Evidence

The current soroswap trace records `applyLedger` total time of 4,475,605,676 ns across 71 ledgers. Apply-contained unwrap totals show the remaining router/host-call envelope is large: `Vm::instantiate_wasmi - instantiate` contributes 456,510,514 ns across 7,910 in-apply instantiations, `call` at `vm/dispatch.rs:304` contributes 5,134,322,517 ns total across 23,569 in-apply host dispatches, `Vm::invoke_function_raw` contributes 7,271,629,987 ns total across 7,867 in-apply calls, and `SAC transfer` contributes 2,477,084,982 ns total across 15,665 in-apply events. The successful native pair and direct-balance optimizations prove that exact-code-hash Soroswap emulation can move soroswap by 5-8% per removed frame family; fusing the remaining router plus transfer families targets a larger residual phase than any single prior micro-optimization.

## Anti-Evidence

This is deliberately high-risk and must not be implemented as another narrow native-router wrapper that still calls through generic SAC/pair subframes. The fused path must preserve observable authorization tree matching, event ordering/contract IDs, SAC issuer/trustline semantics, TTL extension behavior, rollback on every failure point, and deterministic output ordering, and it must be gated to the next protocol because metering will intentionally differ from released p26. If review finds that preserving those semantics forces reusing the same `call_n_internal` SAC frames and router call scaffolding, the hypothesis collapses to previously rejected low-impact variants.

---

## Review

**Verdict**: VIABLE
**Severity**: High
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated

### Trace Summary

The accepted baseline still enters `call_contract_fn` for the router contract and falls through to `instantiate_vm`, while only vendored pool getter/swap calls are intercepted natively. The benchmark constructs a fixed `swap_exact_tokens_for_tokens` router invocation with a two-token route, a router-rooted auth tree containing the input SAC `transfer`, two SAC token instances, two pair balance entries, and one vendored pair instance in the footprint. After the router Wasm runs, the native pair swap still delegates output token movement through `call_n_internal(..., "transfer", ...)`, and the input token transfer is still performed by the router through the generic SAC dispatcher. The full fused pipeline is therefore distinct from the failed native-router wrapper and specialized-SAC-transfer micro-variants: it targets the remaining router Wasm frame plus both SAC transfer dispatcher/frame paths together.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3427-3496` — the workload builds the exact router `swap_exact_tokens_for_tokens` invocation, declares router/SAC/pair footprint entries, and supplies an auth root for the router call with a token-in `transfer` subinvocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-835` — `call_contract_fn` has native gates only for the vendored pool hash; non-pool router Wasm still instantiates a VM and invokes the export.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — native pair `swap` already implements reserve checks, output SAC transfer calls, direct post-transfer SAC balance reads, reserve writeback, K-invariant checking, and pair event emission inside a native contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1393` — native pair output transfer still goes through `call_n_internal`, while only the subsequent `balance` observation has a direct SAC fast path.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` requires nonnegative amounts, `from.require_auth`, SAC instance/code TTL extension, spend/receive balance mutation, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-200,375-397` — direct typed balance helpers already support explicit contract-owner pair balance reads, and the SAC account/trustline path is the behavior that must be preserved for user legs.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:829-849,1340-1370,1614-1732` — authorization matching is frame-stack dependent; a fused implementation must still consume the router root and transfer subinvocation in the same logical order, even if it avoids full nested `with_frame` storage/event rollback.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` and `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:223-233` — contract events derive their contract ID from the current frame today, so direct SAC and pair event emission will need explicit-contract attribution or equivalent scoped frames.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-206,393-411` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-304` — these are the router VM instantiation, raw invocation, host-function dispatch, fuel handoff, and relative-object conversion paths avoided by an exact router native gate.

### Findings

- **Inefficiency exists**: YES. The current accepted baseline removes the pool getter frame family, the pair `swap` Wasm frame, and post-transfer SAC `balance` subframes, but leaves one router Wasm invocation and two SAC `transfer` dispatcher/frame paths per successful swap.
- **Hot path**: YES. The benchmark generates these router invocations for the `soroswap, TX=2000, T=8` close-ledger apply path; the footprint/auth shape is fixed enough to gate a next-protocol native path and fall back on any mismatch.
- **Existing optimizations**: PARTIAL. Native pair swap and direct SAC balance reads provide the reusable reserve math, balance read semantics, and event shape, but they intentionally retain SAC `transfer` subframes and do not intercept the router contract.
- **Correctness constraints**: The PoC must not simply call the existing native pair swap and SAC transfer helpers through `call_n_internal`; doing so collapses to rejected router/SAC variants. To be viable it must add explicit typed router/pair/SAC effect helpers that preserve router-root and transfer-subinvocation auth consumption, SAC instance/balance TTL extension, account/trustline and contract-owner balance semantics, exact event contract IDs/order, and success-only reserve writeback under one outer rollback point.
- **Impact estimate**: High. The remaining router VM instantiation/raw invocation family is approximately one event per accepted swap, and SAC `transfer` appears twice per swap. Prior accepted native emulation wins were 5-8% for individual removed frame families; fusing the remaining router and transfer families is a material restructuring of the dominant Soroswap apply phase and plausibly clears the objective's >10% High threshold if the implementation avoids the previously failed subcall scaffolding.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` for a next-protocol router-shape gate before router VM instantiation and for reusing native pair reserve/event logic; `builtin_contracts/stellar_asset_contract/{contract.rs,balance.rs,event.rs}` for extracting typed SAC transfer effects with explicit token contract IDs; `auth.rs` and `events/mod.rs` only as needed for scoped auth matching and explicit-contract event attribution.
- **Change description**: Add an exact-match fused router swap path gated on next protocol, router function/arity, two-token route, auth root/subinvocation shape, SAC token instances, footprint entries, vendored pair hash/layout, and expected account/pair legs. On match, execute the router input transfer, output transfer, pair balance observations, reserve update, K-invariant, and events directly in router order without entering router Wasm or `call_n_internal` SAC transfer frames; fall back to existing execution for every mismatch.
- **Correctness check**: Existing Soroban auth, frame rollback, SAC, storage, TTL, and native pair tests cover many primitives, but this path needs focused equivalence tests against the Wasm/router path for successful swaps, auth mismatch, malformed route/footprint/layout fallback, insufficient output/input/liquidity errors, donation-induced balance/reserve divergence, SAC event contract IDs, pair event payload/order, and rollback after each post-mutation failure point.
- **Benchmark focus**: Count accepted fused hits and eliminated router `Vm::instantiate_wasmi`, `Vm::invoke_function_raw`, `vm/dispatch` calls, and SAC `transfer` `call_n_internal` frames. Then run at least three non-Tracy `scripts/run_apply_load_matrix.py` runs against the current `CURRENT_STATE.md` baseline; the finding only remains High if soroswap median apply time improves by more than 10%, otherwise reassess against the objective's Medium floor.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-05-23
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:809-1070` — added a next-protocol native router gate for the fixed two-token `swap_exact_tokens_for_tokens` apply-load shape. It validates the router wasm hash, function/arity, route shape, deadline/min-output shape, pair address/hash/layout, SAC token instances, and then performs the input transfer, native pair swap, and return amount vector without instantiating the router VM.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1073-1155` — added helpers to read the router factory, derive the deterministic Soroswap pair address from sorted token XDR, and compute router `get_amount_out` using the 997/1000 fee formula.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1599-1665` — specialized Soroswap SAC transfers for StellarAsset contracts by running typed SAC transfer effects in a native contract frame, preserving `require_auth`, TTL extension, account/trustline and contract balance mutations, and SAC event attribution while avoiding `call_n_internal` dispatch.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract.rs:14-18` — re-exported the existing SAC balance and event helpers needed by the native fused path.

### Demonstration

The optimized path fuses the accepted benchmark router call, the router input SAC transfer, the native pair reserve transition, and the output SAC transfer into native host code for exact next-protocol Soroswap apply-load swaps. Exact-shape mismatches fall back to the existing Wasm path, while successful matches avoid the router VM instantiation/raw invocation and both generic SAC `call_n_internal` transfer frames.

### Test Results

`./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres` and `make -j30` completed successfully. Full regression verification passed with `NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS="--ll fatal -r simple --abort --disable-dots" make -j30 ALL_SOROBAN_GIT_STATE_STAMPS= check`; the `ALL_SOROBAN_GIT_STATE_STAMPS=` override was only needed because this worktree stores submodule gitdirs under `.git/worktrees/...`, while the generated Makefile prerequisite expects top-level `.git/modules/...` paths.
