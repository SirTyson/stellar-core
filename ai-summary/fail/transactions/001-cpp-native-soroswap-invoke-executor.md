# H001: C++ Native Soroswap Invoke Executor

**Date**: 2026-05-24
**Subsystem**: transactions
**Severity**: High
**Impact**: soroswap apply-time dominant-phase redesign
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For protocol-gated soroswap benchmark transactions whose top-level `HostFunction::InvokeContract` is the exact Soroswap router swap shape, apply should produce the same ledger entries, TTL bumps, result, events, auth behavior, and resource accounting as the current Rust host path. Non-matching transactions, older protocols, malformed args, or unexpected footprints should fall back to the existing `rust_bridge::invoke_host_function` path unchanged.

## Mechanism

`InvokeHostFunctionOpFrame` always serializes the host function/resources/auth into `CxxBuf`s and calls the full Rust host/VM path, even when the current stack has already moved the hot Soroswap pair and pool logic into protocol-gated native code. A C++ apply-path executor keyed off the top-level router swap could run before the bridge in `InvokeHostFunctionParallelApplyHelper::invokeHostFunction`, interpret the allowlisted Soroswap transaction directly against `TxParallelApplyLedgerState`, and emit the same modified entries/events without instantiating the router Wasm or entering the generic host dispatch tree. This materially restructures the dominant `applySorobanStageClustersInParallel` phase while preserving determinism because transactions remain processed in the existing cluster order and no extra workers beyond the existing cluster count are introduced.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` on the current baseline with `soroswap, TX=2000, T=8`, protocol 27 enabled, and a transaction set whose top-level invoke calls the Soroswap router swap path. The fast path should trigger only when the envelope host function, auth entries, and declared footprint match the known native Soroswap pair/SAC/pool layout; otherwise the current bridge path should be used.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — constructs bridge buffers and calls `rust_bridge::invoke_host_function`; candidate insertion point for an optional native executor result.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — parallel Soroban apply entry point that owns `ThreadParallelApplyLedgerState` and transaction effects.
- `src/ledger/LedgerManagerImpl.cpp:2531-2574` — existing cluster-parallel execution; the executor must preserve this scheduling and deterministic cluster order.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-835` at gitlink `bf6625f8` — current Rust `call_contract_fn` still handles the top-level router Wasm path unless an inner pair/pool native match fires.

## Evidence

The current Tracy trace from `ai-summary/CURRENT_STATE.md` shows benchmark-sized `applyLedger` windows totaling 4677.285 ms. Timestamp overlap confirms these zones are inside those windows: `applySorobanStageClustersInParallel` overlaps 2977.602 ms, `Vm::invoke_function_raw` overlaps 7128.213 ms across worker threads, generated VM `call` overlaps 4859.286 ms, and `SAC transfer` overlaps 2601.188 ms. The worker aggregate must be divided by T=8, but the bridge/VM/router stack still accounts for a multi-percent critical-path slice, and a C++ executor would remove an entire layer rather than a micro-cost.

## Anti-Evidence

This is a larger protocol-gated redesign, not a localized refactor. It must exactly reproduce Soroban auth, events, TTL extension, budget/resource-limit reporting, rollback behavior, and result hashing; any mismatch would be consensus-visible. The implementation should initially be allowlist-only and fallback-heavy, and it should not attempt to parallelize within a cluster or exceed the configured cluster worker count.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transactions/summary.md:85` (`001-native-router-swap-fast-path.md`)
**Failed At**: reviewer

### Trace Summary

The C++ parallel apply path constructs the Soroban apply helper, serializes host function/resources/auth/ledger buffers, and calls `rust_bridge::invoke_host_function`; the Rust host then dispatches top-level contract calls through `Host::call_contract_fn`. The current Rust host already has protocol-gated native Soroswap pool getter/swap paths for inner pool calls, while the top-level router Wasm path remains the optimization target. That target is substantially equivalent to the prior `001-native-router-swap-fast-path.md` investigation recorded in the transactions failure summary, which proposed native dispatch for exact Soroswap router `swap_exact_tokens_for_tokens` to bypass router Wasm instantiation.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` builds auth/base PRNG buffers and calls `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017` — apply helper sequence adds footprint, invokes host, records storage changes, collects events, consumes refundable resources, and finalizes the success hash.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — parallel Soroban entry constructs `InvokeHostFunctionParallelApplyHelper` and commits returned parallel effects.
- `src/ledger/LedgerManagerImpl.cpp:2531-2574` — clusters execute via one async task per cluster and join deterministically before committing thread states.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:783-838` — `call_contract_fn` dispatches Wasm contracts, only falling into native Soroswap pool getter/swap helpers before generic VM instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:840-1265` — native Soroswap pool helpers are protocol-gated and cover pool getters/swap, not a full top-level router executor.

### Why It Failed

This is not novel: the transactions fail summary already records a substantially equivalent native top-level Soroswap router fast-path investigation. Moving the dispatch boundary from Rust `Host::call_contract_fn` to C++ `InvokeHostFunctionParallelApplyHelper::invokeHostFunction` changes implementation placement, but the same core optimization target and correctness burden were already investigated.

### Lesson Learned

Router-level Soroswap native execution has already been explored; future hypotheses should either reference that prior finding explicitly and propose a materially different unresolved mechanism, or target a different apply-path cost center.
