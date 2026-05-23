# H002: Native Soroswap router `swap_exact_tokens_for_tokens` trampoline (refined for current baseline)

**Date**: 2026-05-23
**Subsystem**: transaction-ledger / soroban-env (Soroswap router emulation)
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by bypassing the remaining Soroswap router Wasm instantiation and Wasm body execution for the benchmark's fixed two-token `swap_exact_tokens_for_tokens` shape, dispatching directly to the existing accepted native pair `swap` emulation
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For the official apply-load Soroswap router contract on the next protocol, an invocation of `swap_exact_tokens_for_tokens(amount_in, amount_out_min, [token_in, token_out], to, deadline)` should produce the same authorization checks, input SAC transfer (caller -> pair), pair-address derivation, output amount computation against pair reserves, pair `swap` effects, event/error behavior, storage effects, and return value whether executed through the router Wasm or a protocol-gated native router trampoline. The native path should only run when the router Wasm hash, function symbol, arity, argument shape, router instance-storage layout, and exact two-element token path match the audited benchmark shape; every other router call (different hash, symbol, arity, multi-hop path, expired deadline shape, non-contract `to`, non-SAC tokens, released protocol, mismatched factory state) must fall back to normal Wasm router execution unchanged.

## Mechanism

The accepted baseline (CURRENT_STATE p26 SHA `fbbea0d9`) already adds native emulation for Soroswap pool getters, pool `swap`, and direct SAC balance reads. However, `Host::call_contract_fn` (frame.rs:783-839) still only dispatches `try_call_native_soroswap_pool_getter` (line 797) and `try_call_native_soroswap_pool_swap` (line 807) for `ContractExecutable::Wasm`. Router calls fall through to `instantiate_vm` (line 820) and execute the full router Wasm body, which then calls `Token::transfer(caller, pair, amount_in)` and `Pair::swap(...)` through the regular `call_n_internal` path - the latter of which finally enters the accepted native pair swap. The remaining router Wasm execution per swap consists of: (i) one `Vm::instantiate_wasmi` + `Store::new` for the router contract, (ii) full Wasm body execution including arg-vector destructuring, deadline comparison, path validation, pair-address derivation via factory storage reads, output-amount computation, (iii) one `Host::call` into SAC `transfer` for the input transfer, (iv) one `Host::call` into the pair contract that then enters the native swap.

A protocol-gated native router trampoline in `call_contract_fn` (analogous to the accepted `try_call_native_soroswap_pool_swap`) that validates exact router Wasm hash, `swap_exact_tokens_for_tokens` symbol, arity 5, argument-type shape `(i128, i128, Vec<Address>, Address, u64)`, two-element path length, deadline check, and the router instance-storage factory-address layout, can: (a) skip router Wasm instantiation entirely, (b) push a single native router frame, (c) derive the pair address deterministically from the factory layout (same logic the Wasm router uses, audited against the vendored router source), (d) issue the input SAC `transfer(caller, pair, amount_in)` directly through the same typed SAC helpers introduced by `001-direct-sac-balance-for-native-pair` (or the H001 transfer fast path proposed in this batch), (e) invoke the existing `try_call_native_soroswap_pool_swap` machinery for the pair leg, (f) return the computed amount-out vector. All non-matching invocations return `None` and run the router Wasm unchanged.

The Tracy trace at `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy` shows the following aggregate worker self-time inside `applyLedger` windows: `Vm::instantiate_wasmi - instantiate` 459.7 ms / 7,956 calls, `Vm::invoke_function_raw` 476.5 ms / 7,907 calls, `call,soroban-env-host/src/vm/dispatch.rs:304` 1,216.4 ms self / 5,153.0 ms inclusive / 23,696 calls, `Host::invoke_function` 8,276.6 ms inclusive / 7,891 calls, plus the router's `Token::transfer` call contributing to `SAC transfer` 638 ms self / 2,486 ms inclusive. After 8-cluster parallelism and 71 dense apply windows, eliminating the per-swap router Wasm frame (one instantiation + Wasm body + one extra Host::call into pair) plausibly recovers 8-15 ms/ledger critical-path - about 3.7-6.9% of the current 218 ms soroswap median - clearing the 3% Medium floor.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from the baseline in `ai-summary/CURRENT_STATE.md`. Each generated tx invokes the router function `swap_exact_tokens_for_tokens` with `amount_in=100`, `amount_out_min=0`, a two-element `[token_in, token_out]` path, the source account as `to`, and `deadline=UINT64_MAX` (see `src/simulation/ApplyLoad.cpp:3431-3475`). The router call enters `Host::call_contract_fn`, where the new trampoline would match every accepted swap and skip the existing Wasm instantiation + Wasm body + `Host::call`-to-pair sequence.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-839` - `call_contract_fn` dispatch site that currently recognizes only pool getter and pool swap natives; add `try_call_native_soroswap_router_swap_exact_tokens_for_tokens` between line 797 and 807, before `instantiate_vm` at line 820.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` - accepted `try_call_native_soroswap_pool_swap` to be invoked by the new router trampoline for the pair leg, ensuring the trampoline produces identical effects to the current Wasm path that ultimately enters this function.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1330-1347` - `soroswap_pool_invoke_sac_transfer` (or the typed transfer fast path from H001 in this batch) to be reused for the router's input transfer.
- `src/simulation/ApplyLoad.cpp:3431-3475` - generated benchmark invocation shape and footprint for `swap_exact_tokens_for_tokens` confirming the steady-state two-token path and authorization chain.
- `src/rust/src/soroban_test_wasm.rs` - vendored apply-load router Wasm whose code hash gates the trampoline.

## Evidence

The accepted SUCCESSES `ai-summary/success/soroban-env/001-native-soroswap-pair-swap.md` (8.17% improvement) and `ai-summary/success/soroban-env/001-complete-native-soroswap-pool-getters.md` (8.13% improvement) establish that the protocol-gated, hash-gated, shape-gated native emulation pattern for vendored Soroswap binaries is accepted and produces Medium-tier soroswap gains. The router is the immediately upstream Wasm contract in the same call chain - it calls the pair contract that has already been replaced with native code. The accepted `001-direct-sac-balance-for-native-pair.md` further demonstrates that the project is comfortable replacing additional sub-frames inside this call chain when a clean shape-gated native path exists.

Per-call savings shape is favorable: eliminating router Wasm instantiation (avg 57.8 us/call from 459.7 ms / 7,956 calls), the router Wasm body execution (a fraction of the 476.5 ms aggregate `Vm::invoke_function_raw` self-time and a meaningful portion of the 5,153.0 ms aggregate `call` inclusive time), and one redundant `Host::call`-into-pair frame transition together represent a structurally similar removable subset to what the pool-swap and pool-getter natives removed (and those each cleared Medium with margin).

## Anti-Evidence and Differentiation From Prior Rejection

A prior hypothesis `ai-summary/fail/transaction-ledger/001-native-router-two-token-swap.md` proposed essentially this trampoline and was reviewed NOT_VIABLE on 2026-05-23. The rejection rationale was: (1) "duplicate of `002-codehash-native-soroswap-precompiles.md`" - but that older PoC failure was rejected because *no audited native Soroswap source existed at the time*; the now-accepted native pair `swap` (`try_call_native_soroswap_pool_swap` at `frame.rs:1013`) and getters (`try_call_native_soroswap_pool_getter` at `frame.rs:840`) directly contradict that premise; (2) "no `try_call_native_soroswap_pool_swap` hook to extend" - the reviewer's source inspection happened against upstream p26 v26.0.0 (`b351f88a`), not the active baseline p26 SHA `fbbea0d9` recorded in `CURRENT_STATE.md`, where the hook is present at frame.rs:807 (verified by `git show fbbea0d9... :soroban-env-host/src/host/frame.rs`). This refined hypothesis is therefore not structurally a duplicate: it explicitly delegates to the now-existing native pair `swap` hook rather than reimplementing it, and the prior rejection's premise of "absent prerequisite" no longer applies on the current baseline.

The legitimate remaining risk surface is correctness of the router-specific logic that has not previously been ported to native: factory-state-derived pair address computation, deadline check, amount-out propagation, and authorization-tree consumption shape. The trampoline must (a) be narrowly hash-gated to the exact vendored router Wasm, (b) shape-check arity, argument types, path length 2, and instance-storage layout before taking the native path, (c) reproduce the router's exact authorization tree consumption order (the caller's source-account auth tree must be consumed identically so the inner SAC `transfer` and pair `swap` calls see the same authorization context), (d) emit identical contract events (none, since the router emits no events itself in the benchmark shape) and identical return value (the computed amounts vector). All non-matching calls must fall back to Wasm execution. A PoC should add direct unit-test coverage comparing the native and Wasm router paths produce bit-identical authorization-tree consumption, ledger entries, fees, and event sequences for the benchmark shape.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - re-reviewed because the prior `001-native-router-two-token-swap.md` failure was based on the upstream `b351f88a` p26 source where the native pool hooks were absent; the accepted `fbbea0d9` baseline does contain those hooks.
**Failed At**: reviewer

### Trace Summary

The current soroswap close-ledger path applies each benchmark transaction through `LedgerManagerImpl::applyThread`, `TransactionFrame::parallelApply`, `InvokeHostFunctionOpFrame::doParallelApply`, the Rust bridge, and `Host::invoke_function`. In the accepted `fbbea0d9` p26 source, `Host::call_contract_fn` does have native pool getter and native pool `swap` hooks, but no router hook, so the top-level router `swap_exact_tokens_for_tokens` invocation still instantiates and executes router Wasm before making an input SAC `transfer` and a pair `swap` call. The pair call then hits `try_call_native_soroswap_pool_swap`, so the remaining removable work is only the router Wasm frame plus Wasm-to-host dispatch overhead, not the SAC transfer, pair frame, pair native swap, pair event, or pair reserve/storage effects.

### Code Paths Examined

- `ai-summary/CURRENT_STATE.md:11-33,124-131` - records the accepted p26 submodule SHA `fbbea0d9` and next-protocol gating for the native Soroswap pool optimizations.
- `ai-summary/fail/transaction-ledger/001-native-router-two-token-swap.md:41-76` - prior router-trampoline review failed on absent native hooks in the wrong p26 source state; that premise is stale for `fbbea0d9`.
- `ai-summary/fail/transaction-ledger/summary.md:74,221` - records older native-precompile and absent-hook failures; the "until a native implementation lands" condition is now partially satisfied for pool getter/swap only.
- `src/ledger/LedgerManagerImpl.cpp:2483-2574` - Soroban cluster workers run `txBundle.getTx()->parallelApply` and the apply path waits on all worker futures, so per-router work is on the apply critical path.
- `src/transactions/TransactionFrame.cpp:2385-2430` and `src/transactions/OperationFrame.cpp:175-188` - successful Soroban transactions dispatch their single operation through `OperationFrame::parallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1377` - `InvokeHostFunctionParallelApplyHelper` calls `rust_bridge::invoke_host_function` with the host function, footprint entries, auth entries, ledger info, and module cache.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-552` - the Rust side builds enforcing storage/auth/module state and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-829` - `ContractExecutable::Wasm` dispatch checks pool getter and pool swap native hooks, then falls through to `instantiate_vm` and `vm.invoke_function_raw`; no router hook exists.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-872,1013-1074` - existing native pool hooks are real, hash-gated, next-protocol-gated, and shape-gated.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1076-1305,1330-1366` - native pool swap still performs output SAC transfers, balance reads, K-invariant checks, reserve updates, and swap event emission under a pair frame; a router trampoline must still invoke this pair frame to preserve effects and event source.
- `src/simulation/ApplyLoad.cpp:3093-3118,3409-3496` - the benchmark deterministically derives pair addresses, invokes router `swap_exact_tokens_for_tokens(amount_in=100, amount_out_min=0, [token_in, token_out], source_account, UINT64_MAX)`, includes router and pair code/instance footprint entries, and authorizes the input SAC transfer.
- `src/rust/src/soroban_test_wasm.rs:135-138` and `src/rust/apply-load-wasm/soroswap_router.wasm` - the router Wasm is vendored; its SHA-256 in this baseline is `4c3db3ebd2d6a2ab23de1f622eaabb39501539b4611b68622ec4e47f76c4ba07`.

### Why It Failed

The inefficiency exists, but the claimed Medium impact does not survive critical-path normalization. Using the hypothesis's own Tracy totals over 71 apply windows and 8 clusters, router Wasm instantiation is about `459.7 / 71 / 8 = 0.81 ms` per critical ledger and `Vm::invoke_function_raw` self-time is about `476.5 / 71 / 8 = 0.84 ms`. Even the entire `call,soroban-env-host/src/vm/dispatch.rs:304` self-time is only `1216.4 / 71 / 8 = 2.14 ms` per critical ledger, and a router trampoline would not remove all of it because the input SAC transfer and pair native swap still require contract calls/frames for identical auth, storage, and event behavior. This gives an optimistic upper bound around 3.8 ms, and a realistic bound below that, versus a Medium threshold of roughly 6.5 ms on the current 218 ms soroswap median.

The projection also counts inclusive child work that cannot be eliminated by this trampoline. `SAC transfer` time, pair balance reads, output transfers, reserve updates, swap event emission, and most pair-frame work remain necessary for identical ledger effects. In addition, the hypothesis's shape gate says non-contract `to` should fall back, but the benchmark passes the source account as `to`; any PoC would need to accept account addresses to hit the benchmark at all. That is fixable, but it reinforces that the accepted mechanism is narrower than the stated savings model.

Because this objective only accepts Medium/High hypotheses, the router trampoline is below the objective severity threshold even though it is technically implementable against the current native pool hooks.

### Lesson Learned

For follow-on native Soroswap hooks after pool swap/getter emulation, count only self-time that disappears from the apply critical path. Broad inclusive `Host::invoke_function`, `call`, or SAC totals mostly belong to child SAC/pair work that a correctness-preserving router trampoline still has to execute, so they cannot justify a Medium projection without narrower spans or counters proving at least a 3% top-line apply-time saving.
