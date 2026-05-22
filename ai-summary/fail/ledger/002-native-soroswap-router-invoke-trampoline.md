# H002: Native Soroswap router invoke trampoline for the apply-load swap path

**Date**: 2026-05-22
**Subsystem**: ledger / Soroban apply
**Severity**: High
**Impact**: >10% soroswap apply-time reduction by removing the remaining top-level router Wasm invocation and generic host-call cascade for the benchmark swap transaction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the exact Soroswap router swap shape used by the benchmark, the apply path should produce the same storage writes, return value, events, authorization checks, TTL extensions, refundable-fee accounting, and result hash as the existing router Wasm execution. It should preserve transaction order inside every Soroban cluster and must fall back to normal Wasm execution for any non-matching contract hash, symbol, arity, protocol, diagnostics-sensitive mode, or argument shape.

## Mechanism

The current apply path still pays the full top-level `Host::invoke_function` and VM dispatch cost for every swap transaction before reaching optimized native pool logic and SAC subcalls. `e2e_invoke::invoke_host_function` rebuilds enforcing storage and creates a host, `Host::invoke_function` decodes the `HostFunction`, converts router call arguments, instantiates/invokes the router VM, and the router then re-enters generic `call` for pool/token subcalls. A protocol-gated native trampoline at the top-level `InvokeContract` boundary can recognize the benchmark router contract/hash/function/argument layout and execute the same deterministic sequence directly through typed host helpers, avoiding the router Wasm frame and a large fraction of the `call`/conversion cascade without exceeding `NUM_CLUSTERS` or changing ledger ordering.

## Trigger

Run the current soroswap apply-load benchmark with `TX=2000` and `T=8`. Each successful transaction invokes the Soroswap router swap entrypoint with the same router Wasm, fixed symbol/arity, and benchmark-shaped arguments; the transaction then performs pool and SAC calls under the same host invocation.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — `invoke_host_function` decodes transaction inputs, builds host storage, and calls `host.invoke_function(host_function)` for every Soroswap transaction.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — `invoke_function_and_return_val` handles `HostFunction::InvokeContract`, converts `ScVal` arguments to host `Val`s, and enters `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — `call_contract_fn` instantiates and invokes Wasm contracts or dispatches builtin SAC calls; this is the boundary a router-specific native trampoline would bypass for the top-level router Wasm.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2568-2592` — the VM `call` host function copies nested contract-call arguments and re-enters `call_n_internal` for router-to-pool/token subcalls.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ invokes the Rust bridge for every transaction; the trampoline would remain inside this deterministic per-transaction apply call and would return the same `InvokeHostFunctionOutput`.

## Evidence

The current diagnostic trace identifies the router invocation family as a dominant descendant of `applyLedger`, not setup work. Timeline overlap against `applyLedger` windows found `invoke_host_function` at 10.478s aggregate worker time, `e2e_invoke::invoke_function` at 10.521s, `Host::invoke_function` at 8.223s, and nested `call` at 5.379s across the same apply windows. Normalized by eight configured clusters, `Host::invoke_function` alone accounts for about 22.5% of the `applyLedger` window and `call` for about 14.7%, so removing the top-level router Wasm frame plus some generic nested call dispatch is a High-severity opportunity.

This hypothesis is structurally distinct from small serialization or map micro-optimizations: it changes the execution route for one recognized benchmark contract entrypoint while keeping all ledger state transitions in the existing single transaction, single worker, cluster-ordered path. A viable design would use exact contract-code hash and symbol matching, protocol-next gating, and typed helper calls for the already-optimized pool/SAC operations, with the generic Wasm path retained for every non-exact case.

## Anti-Evidence

This is a larger semantic optimization and must prove byte-for-byte compatible ledger outputs for the supported swap shape, including result hash, events, auth, TTL, and budget behavior under a new protocol gate. Some of the `Host::invoke_function` total is mandatory storage setup and post-invocation ledger-change construction that a router trampoline would not remove, and the trace is aggregate worker time that must be divided by `NUM_CLUSTERS`; the hypothesis only remains High if the top-level router Wasm and nested generic dispatch account for a substantial share after that normalization.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no ledger fail/success record covers this exact top-level Soroswap router trampoline; the adjacent SAC `transfer` call-boundary rejection is narrower
**Failed At**: reviewer

### Trace Summary

The benchmark does build one `InvokeContract` to the embedded Soroswap router per swap transaction, with function `swap_exact_tokens_for_tokens`, fixed five-argument shape, and a source-account auth tree rooted at the router invocation. C++ passes each transaction through `InvokeHostFunctionOpFrame::invokeHostFunction` into Rust `invoke_host_function`, which constructs enforcing storage, decodes the host function/auth/source account, and calls `Host::invoke_function`. The host then pushes a `HostFunction` frame, converts the router `ScVal` args to `Val`, enters `call_n_internal`, retrieves the router instance, instantiates the router Wasm, and executes it in a `Frame::ContractVM`; nested router/pair/token calls go back through the generic VM `call` import. The broad measured `Host::invoke_function` and `call` zones therefore are real apply-path work, but they are not equal to removable top-level router dispatch.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:3382-3505` — `generateSoroswapSwaps` creates benchmark swaps as router `InvokeContract("swap_exact_tokens_for_tokens")` calls with path `[token_in, token_out]`, router/pair/SAC footprint entries, and source-account auth rooted at the router plus a SAC `transfer` sub-invocation.
- `src/simulation/ApplyLoad.cpp:2855-2913,3006-3077` — setup uploads the official Soroswap factory/pair/router Wasms and deploys the router as a normal Wasm contract; there is no native router or pool executable registered in Core.
- `src/rust/src/soroban_test_wasm.rs:122-138` — the benchmark Soroswap contracts are bundled as raw Wasm bytes (`soroswap_factory.wasm`, `soroswap_pool.wasm`, `soroswap_router.wasm`), not as Rust/native host implementations.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — every Soroban transaction invokes the Rust bridge with encoded host function, resources, auth entries, ledger entries, TTL entries, PRNG seed, rent config, and module cache.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-481` — `invoke_host_function` decodes resources/footprint/storage/auth/source/host function, configures a fresh host, and measures the full `host.invoke_function(host_function)` body.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1124-1148` — `HostFunction::InvokeContract` is executed inside a `Frame::HostFunction`, converts function name and args, then calls `call_n_internal` with external-call parameters.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1121` — `call_n_internal` enforces reserved-function and reentry rules, emits call diagnostics, and dispatches to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-784` — Wasm contracts instantiate a VM and execute inside `Frame::ContractVM`; only `ContractExecutable::StellarAsset` has a builtin native dispatch.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:401-562` — `with_frame` pushes auth/context state, snapshots storage/events/auth for rollback, runs lifecycle hooks, persists instance storage, and rolls back on error.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:3605-3631` — authorization frames and `require_auth` derive the authorized invocation from the current contract frame and its stored args, so a router bypass must recreate equivalent frame/auth semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2568-2600` — nested Wasm contract calls copy the VM argument vector and re-enter `call_n_internal`; these calls include mandatory pair/SAC frame, auth, storage, and rollback semantics unless the callee logic is also reimplemented natively.

### Why It Failed

The central mechanism assumes there are "already-optimized pool" helpers below the router, but the current checkout has no native Soroswap router or pool implementation. The apply-load setup uploads official Soroswap Wasms and the host dispatch table only has native handling for `ContractExecutable::StellarAsset`; the pool remains a Wasm contract. A correctness-preserving router trampoline therefore could not simply jump into typed pool/SAC helpers: it would either still call the pair Wasm through `call_n_internal` or would need to duplicate the Soroswap router and pool contract semantics in Core, including exact reserve math, storage keys, events, auth tree shape, instance storage, lifecycle hooks, rollback behavior, diagnostics-sensitive behavior, and protocol-gated budget changes.

The projected High/Medium impact also over-counts the removable work. `Host::invoke_function` encloses the whole transaction execution, including mandatory contract execution, nested pair/SAC calls, frame rollback, authorization, event/storage effects, result conversion, and budgeted work; `Host::call` similarly includes semantic nested contract boundaries, not just dispatch overhead. If the implementation preserves auth/current-contract semantics, it must still push an equivalent router frame for the source-account auth root and must still execute the pair/SAC state transitions. The residual top-level router-only saving is one Wasm frame plus some router-to-pair argument/dispatch work, with no source evidence that this subset can clear the optimize-soroswap 3% Medium floor after eight-cluster normalization. A broader native reimplementation of Soroswap might be a different protocol-design project, but it is not the specific trampoline described here.

### Lesson Learned

For Soroban benchmark-specific rewrites, separate a broad host span from the exact semantic subset that can be removed. A Wasm contract frame is not just dispatch overhead: it defines the current contract id, auth stack node, instance-storage scope, lifecycle hooks, diagnostics, and rollback boundary. Without an existing native implementation of the target contract logic, a top-level trampoline cannot claim the full `Host::invoke_function` or nested `call` totals as savings.
