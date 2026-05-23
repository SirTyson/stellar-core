# H001: Native Soroswap router trampoline before pair dispatch

**Date**: 2026-05-23
**Subsystem**: ledger / Soroban apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by bypassing the remaining router Wasm layer on the benchmark swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the exact Soroswap router swap shape used by `soroswap-tx-2000-t-8`, applying a transaction should produce the same authorization checks, nested pair calls, SAC transfers, events, ledger-entry changes, refundable fee accounting, and deterministic transaction result ordering as the current Wasm router path. The optimization should only run behind the existing next-protocol gate and only after validating the router contract hash, function symbol, argument shape, and supported path shape; every unsupported call must fall back to Wasm unchanged.

## Mechanism

The accepted current state adds native handling for Soroswap pool getters and pair `swap`, but the outer router contract still executes through the generic Wasm VM path before it reaches the native pair hook. In the current soroswap Tracy trace, unwrap-mode overlap with `applyLedger` shows `Vm::invoke_function_raw` contributing 7,271,629,987 ns across 7,867 in-apply events and `Host::invoke_function` contributing 8,244,655,069 ns across 7,851 in-apply events; normalized by `NUM_CLUSTERS=8`, that is still a multi-ms-per-ledger serial-equivalent envelope. A protocol-gated router trampoline in `Host::call_contract_fn` can recognize the exact router swap entrypoint and directly execute the already-native pair swap calls in deterministic path order, avoiding one Wasm instantiation/invoke layer and its host-object/map conversion overhead while preserving the pair/SAC state transitions.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy` on the current accepted baseline and inspect the soroswap trace under `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply -> invoke_host_function`. Each benchmark swap invokes the official Soroswap router Wasm, which then calls into the Soroswap pair; the current native hook only catches the pair call after the router Wasm has already run.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-827` at p26 `fbbea0d9` — `Host::call_contract_fn` checks native Soroswap pool getter/swap hooks only after decoding the callee instance and before falling back to `instantiate_vm`; this is the insertion point for a router-hash trampoline.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1304` at p26 `fbbea0d9` — existing native pair `swap` implementation that the router trampoline can delegate to in the same deterministic order the Wasm router would call pairs.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — C++ apply bridge calls `rust_bridge::invoke_host_function` for every Soroban invocation; the router trampoline remains inside this measured apply path and does not affect TX-set construction.
- `src/ledger/LedgerManagerImpl.cpp:2530-2575` and `src/ledger/LedgerManagerImpl.cpp:2672-2705` — parallel apply runs clusters under `NUM_CLUSTERS`; the trampoline preserves per-cluster sequential transaction order and does not introduce extra parallelism.

## Evidence

`CURRENT_STATE.md` records that native pool getter, native pool swap, and direct SAC balance paths are already accepted for the current baseline, so the prior "native Soroswap path absent" blocker no longer applies to the pair layer. The remaining Tracy VM zones are verified to overlap `applyLedger` windows, not TX-set construction: `Vm::invoke_function_raw` overlaps 7.27 s of worker time and `Host::invoke_function` overlaps 8.24 s of worker time in the current soroswap trace. Since the benchmark route is fixed-shape and uses a path that ultimately reaches the native pair hook, bypassing the router Wasm layer has a plausible Medium ceiling even after normalizing worker totals by the configured 8 clusters.

## Anti-Evidence

The router frame is semantically meaningful: it owns the source-account auth root, current-contract identity, argument decoding, diagnostics, and rollback boundary. The trampoline must therefore push an equivalent router frame (or otherwise preserve auth-stack and event/diagnostic behavior) and must reject unsupported routes rather than approximating them. Some `Vm::invoke_function_raw` time also belongs to non-router Wasm or fallback calls, so a reviewer should isolate the router contract hash/function event count before promoting this beyond hypothesis.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/ledger/summary.md` entry `002-native-soroswap-router-invoke-trampoline.md`
**Failed At**: reviewer

### Trace Summary

The benchmark does issue the claimed top-level router call, and the accepted p26 commit `fbbea0d9` does add native pool getter/swap and direct SAC balance helpers behind the Wasm executable branch. However, this hypothesis is still the same optimization class already retained in the ledger fail summary: replacing the remaining Soroswap router Wasm invocation with a native trampoline. The traced path confirms the router frame is not removable scaffolding; it defines the auth root/current-contract context and rollback boundary before the input SAC transfer and native pair/SAC state transitions execute.

### Code Paths Examined

- `ai-summary/fail/ledger/summary.md:74` — retains `002-native-soroswap-router-invoke-trampoline.md`, a substantially equivalent Soroswap router Wasm bypass rejection.
- `src/simulation/ApplyLoad.cpp:3431-3496` — constructs `swap_exact_tokens_for_tokens(amount_in, amount_out_min, [token_in, token_out], to, deadline)` on the router contract and roots the auth tree at that router call with a token-in SAC `transfer` subinvocation.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-585` — every Soroban invoke-host-function operation crosses the C++/Rust bridge inside apply.
- `src/ledger/LedgerManagerImpl.cpp:2483-2510` and `src/ledger/LedgerManagerImpl.cpp:2530-2575` — Soroban transactions run through per-cluster worker apply; the trampoline would remain intra-cluster sequential work and would not change cluster parallelism.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:223-262` — `with_frame`/context push snapshots auth, storage, and events so errors roll back through the correct contract frame.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:783-838` — `call_contract_fn` checks native pool hooks only for the pool Wasm hash, then otherwise instantiates and invokes Wasm; a router trampoline would be another native contract-frame replacement here.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:1013-1393` — native pool `swap` still performs pair-frame work, output SAC transfer, direct/indirect SAC balance reads, reserve updates, K-invariant checks, TTL effects, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs@fbbea0d9:1531-1755` — `call_n_internal` performs reserved-name checks, reentry policy, diagnostics, auth-frame progression, and then dispatches to `call_contract_fn`; behavior-preserving native router execution must preserve these semantics.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs@fbbea0d9:154-206,393-411` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs@fbbea0d9:240-304` — the targeted Wasm instantiation/raw invocation/dispatch work is real, but only the router-specific subset is removable.

### Why It Failed

This is a duplicate of the retained ledger failure for a native Soroswap router invoke trampoline. The updated premise that pair-layer native hooks now exist does not make the router bypass novel: the proposal still must reproduce the router-level auth root, current-contract identity, input SAC transfer, pair selection, pair swap call, event ordering, diagnostics, metering differences, and rollback semantics. The broad `Host::invoke_function` and `Vm::invoke_function_raw` totals include required subcall and non-router work, and the removable router-only subset is not isolated strongly enough to overcome the prior rejection or justify another PoC under the Medium-only objective.

### Lesson Learned

Router-level Soroswap shortcuts need more than a hash gate and fixed two-token route. A viable future proposal must either reference a materially different retained design or quantify an isolated router-only cost that remains after preserving auth/frame/rollback semantics and the mandatory SAC/pair state transitions.
