# H001: Native two-token Soroswap router swap trampoline

**Date**: 2026-05-23
**Subsystem**: soroban, soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by bypassing the remaining router Wasm frame for the fixed two-token swap path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the apply-load Soroswap router contract, `swap_exact_tokens_for_tokens(amount_in, amount_out_min, [token_in, token_out], to, deadline)` should produce the same auth checks, input SAC transfer, pair lookup, pair swap call, events, error behavior, ledger writes, and return vector whether it runs through Wasm or through a next-protocol native trampoline. The native path should run only when the router Wasm hash, function symbol, argument shape, two-token path, router instance layout, and factory/pair footprint match the audited benchmark shape; all other calls should fall back to Wasm unchanged.

## Mechanism

The current accepted p26 stack already bypasses the vendored Soroswap pool getters and pool `swap` in `Host::call_contract_fn`, but it still instantiates and executes the router Wasm once per swap transaction before reaching those native pool hooks. The current Tracy trace has 7,867 `Vm::invoke_function_raw` events starting inside `applyLedger` windows for 7.272s aggregate worker time, plus 23,569 generated host-function `call` events for 5.134s and 7,851 `Host::invoke_function` events for 8.245s. A hash-gated router trampoline can remove the top-level router VM frame and dispatch directly to the existing native pool-swap machinery, cutting a dominant remaining Soroswap-specific apply slice while preserving determinism by executing the same state transitions in the same order.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) on the accepted baseline from `ai-summary/CURRENT_STATE.md`. Each generated transaction invokes the router contract with a two-token path, `amount_in = 100`, `amount_out_min = 0`, recipient equal to the source account, and `deadline = UINT64_MAX`, so every accepted swap pays a router Wasm invocation before the already-native pool `swap` path.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-838` — `call_contract_fn` currently checks native Soroswap pool getter/swap hooks for Wasm contracts but has no router hook.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1013-1305` — existing native pool `swap` implementation the router trampoline can reuse after validating/deriving the pair and output amounts.
- `src/simulation/ApplyLoad.cpp:3431-3475` — generated steady-state benchmark swap shape and footprint for `swap_exact_tokens_for_tokens`.
- `src/rust/src/soroban_test_wasm.rs:135-138` — vendored apply-load router Wasm source used to derive the exact code-hash gate.

## Evidence

`ai-summary/CURRENT_STATE.md` points to `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`. Timestamp-filtering zone starts against the 71 `applyLedger` windows shows the remaining top-level invoke/VM surface is still large and in scope: `Host::invoke_function` totals 8.245s, `Vm::invoke_function_raw` totals 7.272s, and generated dispatch `call` totals 5.134s. Source at p26 commit `fbbea0d9` already contains next-protocol, code-hash-gated native Soroswap pool hooks, so this hypothesis extends an existing accepted pattern rather than inventing a new ungated precompile model.

## Anti-Evidence

Prior native-router ideas failed when the checked source did not yet contain native pool hooks; this hypothesis depends on the accepted `fbbea0d9` p26 state, not the detached upstream v26 submodule currently visible in this worktree. The PoC must keep the router scope narrow and reject any call that requires unaudited general Soroswap/factory behavior; if pair derivation or amount-out computation requires reimplementing more than the fixed two-token apply-load path, this should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entry for `001-router-only-native-soroswap-trampoline.md + 002-native-two-token-router-swap-plan.md + 001-exact-router-native-swap-plan.md + 002-two-token-router-native-trampoline.md`
**Failed At**: reviewer

### Trace Summary

The current apply-load generator does create the claimed fixed router invocation shape: each steady-state swap calls `swap_exact_tokens_for_tokens` with a two-address path, `amount_in = 100`, `amount_out_min = 0`, source-account recipient, and `deadline = UINT64_MAX`. The transaction apply path enters `InvokeHostFunctionOpFrame::doParallelApply`, crosses the Rust bridge, builds a fresh Soroban `Host`, and calls `Host::invoke_function`; for `HostFunction::InvokeContract`, `call_n_internal` falls through to `call_contract_fn`. In this checkout, `call_contract_fn` has no Soroswap router or pool native hook at all: every `ContractExecutable::Wasm` retrieves the instance, instantiates a VM, pushes a `ContractVM` frame, and calls `vm.invoke_function_raw`.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:131` — prior retained rejection covers router-only native trampoline variants, including exact hash-specified and two-token trigger shapes.
- `ai-summary/fail/soroban/summary.md:178` — retained lesson says all native Soroswap bypass variants share unresolved blockers: absent native frame/helper implementation in current source, unspecified binary-derived storage schema, event order, error/trap mapping, auth-tree semantics, and next-protocol metering schedule.
- `src/simulation/ApplyLoad.cpp:3431-3475` — confirms the benchmark emits the fixed two-token router call and footprint shape cited by the hypothesis.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply helper serializes auth/resources/ledger entries and invokes the Rust Soroban host for each transaction.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge builds the budget and delegates to protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — constructs enforcing storage, host, auth, ledger info, module cache, and calls `host.invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — top-level `InvokeContract` converts function/args and enters `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:936-1114` — after reserved-name and reentry checks, non-test contracts fall through to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — Wasm contracts unconditionally instantiate a VM and call `vm.invoke_function_raw`; only SAC uses a native built-in frame.
- `src/rust/src/soroban_test_wasm.rs:135-138` — the vendored router Wasm is present only as an apply-load artifact source, not as a native execution implementation.

### Why It Failed

This is a duplicate of prior router-only native Soroswap trampoline investigations, including the two-token and exact-router variants already retained in the Soroban fail summary. The current hypothesis narrows the trigger shape and cites an accepted pool-native prerequisite, but it does not resolve the prior blockers: the current source still lacks the native frame/helper implementation assumed by the mechanism, and a safe next-protocol native router path would still need a complete semantic and metering specification for auth frame context, event contract IDs and ordering, pair lookup semantics, router/pair error mapping, storage schema, and binary equivalence.

### Lesson Learned

Do not resubmit native Soroswap router bypass variants by only adding hash gates or a narrower two-token benchmark shape. A viable proposal first needs isolated per-code-hash router cost attribution and a complete native-contract protocol specification that addresses the retained semantic, auth, event, storage, and metering blockers.
