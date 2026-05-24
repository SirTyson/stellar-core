# H002: Direct InvokeContract Bridge for Top-Level Soroswap Router Invokes

**Date**: 2026-05-24
**Subsystem**: transactions / Soroban invoke bridge
**Severity**: Medium
**Impact**: soroswap apply-time reduction in per-transaction invoke setup before router Wasm execution
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a successful top-level `HostFunction::InvokeContract` transaction that invokes the allowlisted Soroswap router shape, apply should still install the same budget, ledger info, source account, authorization entries, storage footprint, diagnostic settings, base PRNG seed, and module cache, and should execute the router through the existing `call_n_internal`/VM path with identical auth, event, rollback, result, rent, and ledger effects. Non-`InvokeContract` host functions, non-router contracts/functions, malformed args, and older protocols should continue through the existing `rust_bridge::invoke_host_function` path.

## Mechanism

The C++ transaction path owns a decoded `HostFunction` in `InvokeHostFunctionOpFrame`, but `InvokeHostFunctionApplyHelper::invokeHostFunction` serializes it to XDR, the Rust bridge decodes it back to `HostFunction`, and `Host::invoke_function` then pattern-matches `HostFunction::InvokeContract` to call `call_n_internal`. A protocol-gated direct bridge entrypoint for the top-level `InvokeContract` case could pass the already-known contract ID, function symbol, and argument XDR slices separately, construct the host/budget/storage exactly as today, and enter `call_n_internal` directly after replaying or redefining the top-level metering under protocol 27. Unlike the prior native-router fast path, this does not replace router Wasm or nested host-call semantics; it removes only the top-level bridge/decode/dispatch layer that is paid once for every soroswap transaction.

## Trigger

Run the current protocol-27 `soroswap, TX=2000, T=8` apply-load workload. Every successful transaction reaches `InvokeHostFunctionOpFrame::doParallelApply`, sends the top-level Soroswap router `InvokeContract` host function through the C++/Rust bridge, and then executes the same router Wasm; the direct bridge should be selected only after checking the host function discriminant, router contract/function allowlist, and argument shape.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — serializes `hostFunction`, `resources`, source account, auth entries, footprint entries, TTL entries, and PRNG seed into the generic bridge call.
- `src/rust/src/soroban_proto_any.rs:391-452` — constructs the budget and calls the protocol host invocation wrapper for every invoke.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:488-531` — decodes resources, footprint/storage, auth entries, `HostFunction`, and source account before invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1728-1805` — top-level `HostFunction::InvokeContract` dispatch path eventually calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` and `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:250-304` — router Wasm and generated host-import wrappers remain the fallback/execution path and must preserve fuel/error semantics.

## Evidence

The current-trace transaction records place this path inside `applyLedger`: `invoke_host_function` at `soroban-env-host/src/e2e_invoke.rs:488` has 828,296,243 ns self-time and 10,781,064,987 ns total time, while its measured child `Host::invoke_function` totals 8,276,651,656 ns, leaving roughly 2.50 s aggregate worker time for setup/finish/output around host execution. Earlier accepted Soroswap traces also showed top-level conversion/object zones inside the same `applyLedger -> applyTransactions -> applyParallelPhase -> applySorobanStages -> applySorobanStageClustersInParallel -> InvokeHostFunctionOpFrame doParallelApply` envelope, including `ScVal to Val` and `Val to ScVal` families in the hundreds of milliseconds before current native fast paths were stacked. The direct bridge targets a structurally unavoidable per-transaction layer still visible in source after the accepted native pair/pool/SAC optimizations: generic XDR host-function decode plus the `HostFunction::InvokeContract` dispatch wrapper before the router Wasm is entered.

## Anti-Evidence

Prior C++/Rust XDR-roundtrip investigations found that removing only C++ serialization is below Medium because Rust still needs native XDR values and protocol-visible `ValDeser` charges. This hypothesis is only viable if the direct entrypoint removes a larger top-level layer — generic host-function decode, enum dispatch, and duplicated invoke-contract argument handling — or if it is explicitly next-protocol gated with corresponding budget changes. The PoC must isolate this top-level bridge subset with new spans; if the removable share is just the `toCxxBuf(hostFunction)` call or a few `metered_from_xdr` reads, it will fall below the objective threshold and should be rejected.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated as this exact top-level `InvokeContract` bridge/decode shortcut; related prior failures cover native router execution, router VM import dispatch, and broader C++/Rust boundary overhead
**Failed At**: reviewer

### Trace Summary

The soroswap apply path reaches `TransactionFrame::parallelApply`, dispatches the single Soroban operation through `OperationFrame::parallelApply`, and enters `InvokeHostFunctionOpFrame::doParallelApply`. The helper serializes the already-decoded C++ `HostFunction`, resources, source account, auth entries, ledger entries, TTL entries, and PRNG seed into the generic Rust bridge. Rust selects the protocol host module, constructs the budget and host storage, decodes resources/auth/source/host-function XDR, then `Host::invoke_function` matches `HostFunction::InvokeContract`, converts the function and `ScVal` args to host values, pushes the `HostFunction` frame, and calls `call_n_internal` for the router Wasm.

### Code Paths Examined

- `src/transactions/TransactionFrame.cpp:2385-2430` — parallel Soroban apply rejects failed txs, asserts a single operation, and delegates to the operation frame.
- `src/transactions/OperationFrame.cpp:175-188` — `parallelApply` dispatches directly to the Soroban operation's `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ serializes auth entries, host function, resources, source account, ledger info inputs, and PRNG seed into `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017,1358-1377` — the parallel apply helper adds the footprint, invokes Rust host execution, records storage changes, collects events, consumes refundable resources, and finalizes success.
- `src/rust/src/bridge.rs:193-208` and `src/rust/src/soroban_invoke.rs:7-38` — the only production CXX entrypoint is the generic `invoke_host_function`, which selects a protocol module and forwards the encoded host-function buffer.
- `src/rust/src/soroban_proto_any.rs:391-452` — Rust constructs the budget and calls the versioned host invocation wrapper; this setup remains required for any direct `InvokeContract` bridge.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-552` — host invocation decodes resources, builds storage and auth entries, decodes `HostFunction` and source account, sets host context, and invokes `Host::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1868-1936` — `HostFunction::InvokeContract` pushes the host-function frame, validates contract address type, converts the function symbol and `ScVal` args, then calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1666-1857` — `call_n_internal` enforces reserved-function/reentry rules, emits diagnostics, dispatches native/test/Wasm contracts, and preserves frame/rollback semantics.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:216-221` and `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:51-57` — argument materialization and XDR decoding are metered, protocol-visible work rather than purely physical bridge overhead.

### Why It Failed

The real inefficiency is much smaller than the projected Medium-tier surface. The 2.50 s aggregate `invoke_host_function` minus `Host::invoke_function` envelope is an upper bound that includes required budget creation, storage-footprint construction, auth-entry construction, source-account decode, ledger-change extraction, event/result encoding, rent computation, and output preparation; a direct top-level `InvokeContract` bridge would not remove those costs. Within the claimed target, a correctness-preserving direct entrypoint must still push the `Frame::HostFunction`, validate the contract address, materialize the function and argument `Val`s, call `call_n_internal`, and preserve the same auth, diagnostics, reentry, error, frame rollback, Wasm entry, and output semantics. If protocol 27 redefines metering it can avoid the outer `HostFunction` XDR buffer/decode and one enum match, but the router call arguments still need equivalent conversion before entering `call_n_internal`, and the removed work is only a narrow per-transaction wrapper. That subset is bounded by previously failed C++/Rust boundary and router-dispatch investigations and does not plausibly reach the objective's 3% Medium floor after T=8 worker-time normalization.

### Lesson Learned

Do not attribute the broad `invoke_host_function` setup/finish envelope to the top-level `HostFunction` enum bridge. For Soroban invokes, most of the apparent pre-router cost is mandatory host setup, storage/auth/output work, or protocol-visible conversion; a viable bridge hypothesis needs isolated timing for the exact host-function XDR decode/dispatch subset and must show that subset alone clears the Medium threshold.
