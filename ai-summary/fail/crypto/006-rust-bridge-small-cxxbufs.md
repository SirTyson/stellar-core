# H006: Borrow Small Rust Bridge Input Buffers Instead of Rebuilding Them Per Invocation

**Date**: 2026-04-28
**Subsystem**: crypto / rust bridge
**Severity**: Low
**Impact**: reduce per-invocation XDR buffer construction around Soroban host apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The C++/Rust invoke-host-function bridge should pass the same XDR bytes to Rust that it passes today, and Rust should deserialize the same `SorobanResources`, host function, source account, auth entries, and PRNG seed. For small immutable inputs such as `SorobanResources`, source account, and the 32-byte PRNG seed, apply should avoid unnecessary ownership transfers or heap allocation when a borrowed view is sufficient.

## Mechanism

`rust_bridge::invoke_host_function` borrows most large inputs (`hf_buf`, source account, auth entries, ledger entries, TTL entries, base PRNG seed), but the bridge signature takes `resources: CxxBuf` by value. The C++ caller also constructs several fresh `CxxBuf` values inside `InvokeHostFunctionParallelApplyHelper::invokeHostFunction`, including `toCxxBuf(mResources)`, `toCxxBuf(mOpFrame.getSourceID())`, `toCxxBuf(hostFunction)`, auth-entry buffers, and a heap-allocated vector for the 32-byte base PRNG seed. Changing the resources argument to `&CxxBuf` and avoiding the dedicated PRNG vector allocation looked like a possible per-transaction bridge cleanup.

## Trigger

Run the current soroswap apply-load benchmark and inspect per-invocation bridge overhead around `InvokeHostFunctionOpFrame::invokeHostFunction` and `soroban_proto_any::invoke_host_function_or_maybe_panic`. The path triggers once for every successful soroswap invoke-host-function operation in parallel apply.

## Target Code

- `src/rust/src/bridge.rs:193-208` — `invoke_host_function` borrows most buffers but accepts `resources: CxxBuf` by value.
- `src/rust/src/common.rs:12-15` — `CxxBuf` already exposes borrowed bytes via `AsRef<[u8]>`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — each invocation builds `authEntryCxxBufs`, a heap-backed `basePrngSeedBuf`, `toCxxBuf(hostFunction)`, `toCxxBuf(mResources)`, and `toCxxBuf(sourceID)` before crossing the bridge.
- `src/rust/src/soroban_proto_any.rs:391-459` — Rust immediately deserializes the received resources and other buffers for host invocation.

## Evidence

The bridge shape is inconsistent: `resources` is the only byte buffer in the hot invoke-host-function signature passed by value while neighboring buffers are references. The soroswap trace confirms this path is inside apply (`InvokeHostFunctionOpFrame doParallelApply,transactions/InvokeHostFunctionOpFrame.cpp:1465` totals 5.101 s over 1,699 events, and `invoke_host_function_or_maybe_panic,src/rust/src/./soroban_proto_any.rs:408` appears once per invocation). Source inspection also shows a fresh heap allocation just to pass the fixed-size PRNG seed.

## Anti-Evidence

The directly profiled wrapper overhead is tiny compared with host execution and output serialization: self-time export shows `invokeHostFunction,transactions/InvokeHostFunctionOpFrame.cpp:579` at 9.435 ms and `invoke_host_function_or_maybe_panic,src/rust/src/./soroban_proto_any.rs:408` at 12.991 ms across the whole soroswap run. The unprofiled `toCxxBuf` work for resources/source/seed is small relative to `write xdr` (403.775 ms self) and host-object/storage costs, and the highest-impact bridge/XDR output optimizations are already covered by reviewed records in other subsystem queues.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — this small-buffer bridge ownership cleanup was not listed in crypto fail/hypothesis/reviewed/poc records

### Why It Failed

The bridge cleanup is mechanically plausible but below the objective severity threshold. It can at best remove a few small allocations and one by-value `CxxBuf` transfer per invocation, while the measured wrapper zones are only about 22 ms of self-time across the whole run and the dominant soroswap costs lie in host execution, metered XDR serialization, and storage/object access.

### Lesson Learned

For Rust bridge hypotheses, separate API-shape cleanliness from apply-time impact. Borrowing small buffers may be worthwhile during broader refactors, but it is not a standalone Medium-tier soroswap optimization unless the trace shows the wrapper or conversion work on the critical path at much larger scale.
