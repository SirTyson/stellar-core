# H001: Binary-Specified Native Soroswap Pool `swap` Precompile

**Date**: 2026-05-22
**Subsystem**: soroban
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing one pool Wasm instantiation/interpreter path per swap transaction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-next apply-load ledgers, a call to the vendored Soroswap pool Wasm hash
`18051456816b66f12e773a56f77c5794fac1b1fb7ab6e22d4fad5a412770f73e` and export
`swap(amount_0_out: i128, amount_1_out: i128, to: address)` should be executable by a
native host implementation instead of by a fresh wasmi instance. The native path should
produce byte-identical ledger writes, return values, contract events, auth-stack behavior,
and contract error codes to the existing Wasm path, and should fall back to Wasm whenever
the code hash, function name, storage schema, or argument shape does not match exactly.

## Mechanism

The current `Host::call_contract_fn` treats every non-SAC `ContractExecutable::Wasm` call
uniformly: it instantiates a new `Vm`, pushes `Frame::ContractVM`, and runs
`Vm::invoke_function_raw`. Soroswap benchmark swaps pay that path for both the router and
the pool; the pool `swap` body is a fixed binary artifact with exported contract spec and
stable error codes. A protocol-gated native pool `swap` can perform the same reserve math,
SAC transfer subcalls, reserve updates, and event emission without the pool Wasm
instantiation/interpreter layer, preserving determinism because dispatch is gated on an
exact code hash and exact ABI/schema checks.

## Trigger

Run the current soroswap apply-load benchmark. Each measured transaction invokes router
`swap_exact_tokens_for_tokens`, which sub-invokes the pair/pool `swap`; the pool code hash
is computed from `src/rust/apply-load-wasm/soroswap_pool.wasm` during setup and placed in
the read-only footprint. A PoC should compare one native-enabled run against forced-Wasm
fallback and assert identical transaction results, meta, ledger entries, events, and budget
observations for the same generated swap ledger.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — dispatch point that currently routes every `ContractExecutable::Wasm` through `instantiate_vm` and `Frame::ContractVM`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-218` — per-call wasmi store/instance creation and `Vm::instantiate_wasmi - instantiate`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` argument marshalling and interpreter entry.
- `src/simulation/ApplyLoad.cpp:2855-2913` — fixed vendored Soroswap Wasm upload and hash derivation.
- `src/simulation/ApplyLoad.cpp:3382-3505` — measured swap transaction shape, two-token path, footprints, and auth tree.

## Evidence

The current diagnostic soroswap trace confirms this is inside `applyLedger`: `Vm::instantiate_wasmi - instantiate` at `soroban-env-host/src/vm.rs:171` has **827,245,199 ns self-time** over **14,040** calls, and `Vm::invoke_function_raw` at `soroban-env-host/src/vm.rs:400` has **12,652,494,561 ns total-time** over **13,983** calls. Unwrap containment places these VM events inside the `applyLedger` windows, and a max-per-worker-window estimate attributes roughly **23.7 ms/ledger** of critical-path time to `Vm::invoke_function_raw` descendants. `wasm-tools print` on the vendored pool binary exposes the exact export set and contract spec, including `swap`, `SwapEvent`, and error discriminants: `SwapInsufficientOutputAmount=108`, `SwapNegativesOutNotSupported=109`, `SwapInsufficientLiquidity=110`, `SwapInvalidTo=111`, `SwapInsufficientInputAmount=112`, `SwapNegativesInNotSupported=113`, and `SwapKConstantNotMet=114`.

## Anti-Evidence

Prior native-Soroswap ideas failed when they were broad or under-specified. This remains risky unless the PoC derives storage keys, event XDR, arithmetic/rounding, and metering from the vendored binary rather than from upstream source assumptions. The native path must be next-protocol-gated; changing p26 metering or released Wasm semantics would be invalid. The projected Medium impact also depends on isolating pool-specific VM time from router VM and mandatory SAC transfer work; if pool `swap` is a smaller slice than expected, this may fall below threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry `001-pool-only-soroswap-native-precompile.md + 001-native-soroswap-pool-swap.md` and `ai-summary/fail/soroban/001-native-soroswap-pool-swap-and-liquidity.md`
**Failed At**: reviewer

### Trace Summary

The benchmark setup uploads the vendored Soroswap pool Wasm and records its code hash in `mSoroswapState.pairCodeKey`; each measured swap transaction then invokes router `swap_exact_tokens_for_tokens` with the router instance/code, pair code, SAC instances, user trustlines, pool balances, and pair instance in the footprint. In the p26 host, top-level `InvokeContract` calls enter `invoke_function_and_return_val`, dispatch through `call_n_internal`, and then `call_contract_fn`; every production `ContractExecutable::Wasm` still instantiates a fresh `Vm`, pushes `Frame::ContractVM`, and calls `Vm::invoke_function_raw`, while only `ContractExecutable::StellarAsset` uses a built-in native path. This confirms the targeted path is real, but the same pool-only native Soroswap precompile has already been reviewed and recorded as needing refinement for missing binary-proven storage/event/error/metering equivalence and code-hash-normalized impact bounds.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:117` — prior retained failure for `001-pool-only-soroswap-native-precompile.md + 001-native-soroswap-pool-swap.md` records the same pool-only allowlisted native precompile idea and the same unresolved requirements.
- `ai-summary/fail/soroban/summary.md:167` — lesson learned states that a pool-only native precompile is a distinct but under-specified proposal requiring exact export set, storage schema, event order, error/trap mapping, next-protocol metering, and cluster-normalized impact bounds before PoC.
- `ai-summary/fail/soroban/001-native-soroswap-pool-swap-and-liquidity.md:236-266` — prior reviewer already traced the same `call_contract_fn`/VM path and rejected the native pool swap/liquidity proposal as duplicate of the pool-only native precompile failures.
- `src/simulation/ApplyLoad.cpp:2855-2913` — setup obtains `get_apply_load_soroswap_pool_wasm()`, hashes it, stores `mSoroswapState.pairCodeKey`, and uploads the pool code.
- `src/simulation/ApplyLoad.cpp:3382-3505` — measured swaps invoke router `swap_exact_tokens_for_tokens`; the pair code and pair instance are included in the footprint, and auth covers the router root invocation plus token-in SAC transfer sub-invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `HostFunction::InvokeContract` converts XDR args and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1115` — `call_n_internal` performs reserved-function/reentry checks and then dispatches to `call_contract_fn` in production.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` routes all `ContractExecutable::Wasm` contracts through `instantiate_vm` and `Frame::ContractVM`; SAC is the only production built-in dispatch.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-218` — `Vm::from_parsed_module_and_wasmi_linker` creates a fresh wasmi store and instance for each call.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::invoke_function_raw` converts host `Val` arguments to relative wasmi values and enters the exported Wasm function.

### Why It Failed

This is substantially equivalent to the previously investigated pool-only native Soroswap precompile / native pool swap hypothesis. The new file narrows the export to `swap` and names the vendored binary hash and some error discriminants, but it still leaves the same blocking work to PoC: binary-derived storage keys, exact event XDR, arithmetic/rounding behavior, auth/frame semantics, and a next-protocol metering schedule that preserves or intentionally redefines consensus-visible budget behavior. It also reuses aggregate VM timing rather than providing new code-hash-specific, cluster-normalized measurements isolating pool `swap` enough to prove a Medium apply-time reduction. Because this duplicate was already recorded in fail-summary guidance, it should not be promoted again.

### Lesson Learned

Do not re-submit pool-only native Soroswap precompile variants unless they complete the prior refinement requirements with binary-proven storage/event/error/metering equivalence and isolated pool-swap impact measurements. Naming the exact vendored pool hash and `swap` export is not enough to make the hypothesis novel when the unresolved correctness and severity blockers are unchanged.
