# H001: Fused Native Router Swap Settlement

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Soroban native apply path
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing the remaining router Wasm frame, generic cross-contract dispatch, and post-pair balance re-read work for the exact apply-load swap shape
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the next-protocol-gated Soroswap apply-load path, a router `swap_exact_tokens_for_tokens` call over the known two-token native pool should produce the same ledger writes, auth records, SAC transfer events, pair swap event, return value, failure ordering, and deterministic success hash as the current router-Wasm-plus-native-pair execution. The apply path should not have to instantiate and run the router Wasm, perform generic router-to-token/router-to-pair call dispatch, and then have the native pair code re-read pair balances to rediscover the exact input amount the router already knew.

## Mechanism

`Host::call_contract_fn` still falls back to `Vm::invoke_function_raw` for the Soroswap router frame, while only the pair `swap` and pool getters are native-gated (`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-825,1178-1375` at p26 `7aef8604`). Inside the native pair swap, `call_native_soroswap_pool_swap` performs the output SAC transfer, then calls `soroswap_pool_invoke_sac_balance` for both token balances and derives `amount_0_in` / `amount_1_in` from post-transfer balances (`frame.rs:1234-1327`), even though a fused exact-router path can carry the router's input amount and token direction directly into pair settlement. A protocol-gated fused settlement path would match the exact router code hash/function/arity/path used by apply-load, perform the two SAC transfers and pair reserve update in canonical order, and compute the pair invariant from known input/output amounts without the router VM frame and pair balance re-read round trip.

## Trigger

Run the current soroswap apply-load scenario from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`) on the next-protocol branch. Each successful matched router swap enters `applyLedger -> applyParallelPhase -> InvokeHostFunctionOpFrame::doParallelApply -> e2e_invoke::invoke_host_function_for_apply`, then executes the router Wasm and native pair swap. The trigger is a known router exact-swap call whose path is the native Soroswap pair and whose pair call matches `match_native_soroswap_pool_swap`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-825` — `call_contract_fn` dispatch boundary where a router hash/function matcher could take a native path before `instantiate_vm`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — native pair swap body that still performs output SAC transfer, pair balance reads, invariant computation, reserve update, and event construction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1501` — generic `call_n_internal` SAC transfer/balance helpers that fused settlement can avoid for balance re-read and narrow for the known token legs.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-410` — remaining router Wasm invocation and argument marshaling that the fused path bypasses.

## Evidence

The current diagnostic soroswap trace is inside `applyLedger`: `Vm::invoke_function_raw` accounts for 7.231s contained worker time over 8,034 in-window calls, `call` accounts for 4.938s over 24,078 calls, `SAC transfer` accounts for 2.645s over 16,005 calls, `storage get` accounts for 719ms over 328,819 calls, and `get_contract_data` accounts for 738ms over 80,093 calls. Prior accepted native pair-swap work proves this benchmark tolerates exact hash/function/shape gated native emulation under a next-protocol metering gate. The new angle is not merely a router trampoline: it uses the router's exact input amount and path knowledge to avoid the pair-local post-transfer balance re-read and generic balance call fallback that the current native pair body must keep when entered from arbitrary callers.

## Anti-Evidence

This must be protocol-gated and exact-shape gated. It is only viable if it preserves router-visible failure order, all SAC auth/event semantics, pair event bytes, reserve writes, and success-hash inputs; any shortcut that skips SAC `require_auth` or event externalization is invalid. Related router-trampoline investigations were rejected when they only removed the router Wasm frame and left the pair/SAC work unchanged; this hypothesis needs narrow counters showing the combined removed subset (router VM + generic call scaffolding + pair balance re-read) clears the current Medium floor of roughly 6ms per soroswap ledger.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `002-native-router-trampoline-refined.md + 002-fused-native-router-exact-swap-executor.md + 001-native-router-swap-trampoline.md + 001-native-router-exact-swap-trampoline.md`
**Failed At**: reviewer

### Trace Summary

The current apply path does enter Soroban parallel apply through `LedgerManagerImpl::applyParallelPhase` and `InvokeHostFunctionOpFrame::doParallelApply`, then the host dispatch in `Host::call_contract_fn` only recognizes native Soroswap pool getters and pair `swap`; unmatched router Wasm still reaches `instantiate_vm` and `Vm::invoke_function_raw`. The native pair `swap` body still performs output SAC transfers and reads both pair token balances before computing `amount_0_in` / `amount_1_in`. However, the exact router trampoline / fused exact-swap executor mechanism has already been investigated and rejected: the prior review found the removable router frame was below the objective's Medium threshold after critical-path normalization, while SAC transfer, reserve mutation, pair native-swap, and event work remain mandatory.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2871-2963` — parallel Soroban phases are executed inside the `applyLedger` transaction-application path.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1378` — each parallel InvokeHostFunction operation delegates to the Soroban apply helper from the apply hot path.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-825` — `call_contract_fn` dispatches native pool getter/swap hooks only, otherwise instantiates and invokes Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — native pair `swap` matcher is limited to the pool Wasm hash/function/argument shape and does not include a router exact-swap matcher.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — native pair `swap` performs output SAC transfers, balance reads, invariant checks, reserve update, and swap event emission.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1501` — SAC transfer and fallback balance helper calls use `call_n_internal`, with a direct SAC contract-balance read fast path already present for eligible balance reads.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-410` — `Vm::invoke_function_raw` performs Wasm argument marshaling and metered function invocation for non-native contract frames.

### Why It Failed

This is substantially equivalent to the already-condensed failed native router trampoline / fused exact-swap executor investigation. That prior review specifically covered bypassing the router `swap_exact_tokens_for_tokens` Wasm frame on a baseline with native pool getter/swap hooks and found the removable work below the optimize-soroswap Medium severity threshold; it also found that preserving correct SAC auth, rollback/storage/TTL/event semantics keeps the expensive pair/SAC work in place.

### Lesson Learned

For follow-on Soroswap router ideas, novelty requires more than combining router VM bypass with pair-local balance knowledge: the proposal must identify a new, non-mandatory critical-path cost not already rejected in the native router/fused executor and SAC fast-lane reviews, and it must be sized after cluster normalization against the objective's 3% Medium floor.
