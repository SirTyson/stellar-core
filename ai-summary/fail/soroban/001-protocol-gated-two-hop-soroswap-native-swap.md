# H001: Protocol-Gated Native Fast Path for Two-Hop Soroswap Swaps

**Date**: 2026-05-21
**Subsystem**: soroban
**Severity**: High
**Impact**: apply-time reduction by bypassing repeated router/pool Wasm instantiation and interpretation for the benchmark's fixed two-token swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the current soroswap workload, every apply-phase transaction invokes `swap_exact_tokens_for_tokens(amount_in=100, amount_out_min=0, path=[token_in, token_out], to=source, deadline=u64::MAX)` on the same allowlisted Soroswap router Wasm, with a two-address path and a footprint containing only the router instance/code, the two SAC instances, the pool Wasm code, two user trustlines, two pool SAC balances, and the pool instance. A next-protocol native implementation for this exact code-hash/function/argument shape should produce the same ledger writes, auth checks, events, return value, and failure conditions as the Wasm router+pool path, while preserving deterministic output order and using an explicitly versioned metering schedule.

## Mechanism

The current path treats the router and pool as generic Wasm contracts, so each successful swap pays fresh `call_contract_fn` storage lookup, VM instantiation, import linking, `wasmi` interpretation, host-call dispatch, object conversion, and frame setup for a workload shape that is fixed by construction. A protocol-gated native fast path keyed by the known router/pool code hashes and the exact `swap_exact_tokens_for_tokens` ABI could execute the equivalent pool reserve update and SAC transfer sequence directly through host storage/SAC helpers, bypassing the generic VM layers that dominate aggregate worker time. This is significant because the current Soroswap trace shows the targeted generic VM path entirely inside `applyLedger`: `Vm::invoke_function_raw` totals 12,842,366,133 ns / 20,313 calls, `call` totals 9,353,235,883 ns / 40,605 calls, `Vm::instantiate` totals 1,655,685,114 ns / 20,389 calls, and `SAC transfer` totals 2,153,411,257 ns / 13,527 calls; even after 8-way cluster normalization, bypassing only the router/pool Wasm interpretation and instantiation slice has High-tier headroom.

## Trigger

Run `scripts/run_apply_load_matrix.py` in the current next-protocol configuration and inspect the soroswap case (`TX=2000, T=8`). The generator creates only the fixed two-hop swap shape in `ApplyLoad::generateSoroswapSwaps`: function name `swap_exact_tokens_for_tokens`, path length 2, `amount_in=100`, `amount_out_min=0`, `deadline=UINT64_MAX`, and source-account authorization for the nested input-token SAC transfer.

## Target Code

- `src/simulation/ApplyLoad.cpp:3381-3505` — confirms the exact benchmark call shape, footprint, auth tree, and alternating pair direction that the fast path must match.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — current generic `call_contract_fn` dispatch point where a next-protocol code-hash/function fast path could branch before `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1194` — top-level host-function invocation converts invoke args to `Val` and returns `ScVal`; fast path must preserve this external shape.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `Vm::instantiate_wasmi` cost that is avoidable for allowlisted native execution.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-411` — `Vm::invoke_function_raw` cost that is avoidable for allowlisted native execution.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — existing native SAC transfer semantics that the swap fast path should reuse rather than reimplementing token balance behavior.

## Evidence

The current accepted diagnostic trace is `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`. Unwrap containment against the 71 `applyLedger` windows confirmed the relevant zones are inside the measured apply window: `Vm::invoke_function_raw` 12.842s aggregate / 20,313 calls, `call` 9.353s / 40,605 calls, `Vm::instantiate_wasmi - instantiate` 1.318s / 20,389 calls, and `SAC transfer` 2.153s / 13,527 calls. The apply-load source shows the top-level swap ABI, path length, authorization tree, and footprint are intentionally synthetic and stable, making a code-hash/function-gated next-protocol fast path testable without attempting to native-compile arbitrary contracts.

The three vendored workload Wasms are local artifacts (`src/rust/apply-load-wasm/soroswap_router.wasm`, `soroswap_pool.wasm`, `soroswap_factory.wasm`), and the pool export list includes the exact swap-related surface (`swap`, `get_reserves`, `token_0`, `token_1`, `k_last`) needed to define the native equivalence boundary.

## Anti-Evidence

Prior native-precompile investigations failed because broad router/pair and pool-only proposals were underspecified. This hypothesis is narrower but still requires reviewer confirmation of the exact router and pool storage schema, event ordering, error/trap mapping, return value, auth-tree matching, and next-protocol metering schedule before PoC. The vendored Soroswap Wasms are opaque binaries in this repository; equivalence testing may need to consume the upstream Soroswap source or derive a precise spec from contract metadata and golden ledger-close meta. The optimization must be protocol-gated: changing p26 Wasm execution or metering would be consensus-breaking.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-protocol-gated-soroswap-native-router-pair.md`; also overlaps the narrower `001-pool-only-soroswap-native-precompile.md`
**Failed At**: reviewer

### Trace Summary

The apply-load generator does create the claimed fixed two-token swap shape and authorization tree, and the apply path crosses from `InvokeHostFunctionOpFrame` through the Rust bridge into `e2e_invoke`, `Host::invoke_function`, `call_contract_fn`, `Vm::instantiate_wasmi`, and `Vm::invoke_function_raw`. The proposed branch point before `instantiate_vm` is real for Wasm contracts, while SAC transfers already use the native `StellarAssetContract` path. However, the same code-hash native Soroswap router/pair bypass was previously investigated and failed novelty/refinement: the existing fail summary already records that the hot path is real but requires exact code hashes, ABI conversions, storage schema, event order, error/trap mapping, auth-tree semantics, and a protocol metering schedule before PoC.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:109` — prior `001-protocol-gated-soroswap-native-router-pair.md` records the same known-hash native router/pair fast path and marks it `NEEDS_REFINEMENT` for missing semantics and metering specification.
- `ai-summary/fail/soroban/summary.md:117,155` — prior pool-only precompile record confirms the narrower pool/code-hash angle is also already known but under-specified.
- `src/simulation/ApplyLoad.cpp:3381-3505` — confirms the benchmark emits `swap_exact_tokens_for_tokens` with path length 2, fixed amount/deadline, fixed footprint shape, and source-account auth for the nested input-token SAC transfer.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1378` — parallel apply invokes the Rust bridge with host-function XDR, resources, ledger entries, auth entries, ledger info, PRNG seed, rent config, and module cache.
- `src/rust/src/soroban_proto_any.rs:391-448` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-430` — Rust bridge builds the budget, decodes resources, constructs the enforcing footprint/storage input, and dispatches to the host invocation path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1194,750-785` — host invocation converts external `ScVal` args to `Val`, loads the contract instance, and dispatches either through generic Wasm instantiation/invocation or the native SAC built-in.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187,393-411` — generic Wasm contract execution pays instantiation and raw function invocation costs that the proposed native path targets.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` requires auth, extends instance/code TTL, updates balances, and emits transfer events; any native swap path must preserve these observable semantics.

### Why It Failed

This is not novel. It is a narrower wording of the already-reviewed protocol-gated native Soroswap router/pair fast path, and it retains the same blocker: the hypothesis does not supply the concrete native semantic and metering specification needed to prove equivalence to the opaque vendored router/pool Wasms. Narrowing the trigger to the current two-hop benchmark ABI confirms the workload shape but does not resolve the previously identified missing storage schema, event/error ordering, auth matching, return-value, and metering requirements.

### Lesson Learned

Future Soroswap-native proposals should cite the prior router/pair and pool-only records and must arrive with a complete next-protocol native-contract specification, not just a narrower benchmark trigger or branch point.
