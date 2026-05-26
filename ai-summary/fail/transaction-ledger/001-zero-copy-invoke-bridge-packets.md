# H001: Zero-copy invoke bridge packets for Soroban apply inputs

**Date**: 2026-05-26
**Subsystem**: transaction-ledger / Soroban invoke bridge
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by removing C++ `CxxBuf` allocation/copy and Rust bridge indirection across host-function inputs
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During parallel Soroban apply, C++ should pass the already-owned XDR bytes for the host function, resources, source account, authorization entries, footprint ledger entries, TTL entries, and PRNG seed to Rust as borrowed slices whose lifetime is bounded by the synchronous `rust_bridge::invoke_host_function` call. The Rust host should decode those slices exactly as today, preserve all metered `ValSer`/`ValDeser` charges, and return the same ledger changes, event bytes, fees, and result codes without allocating a fresh `std::vector<uint8_t>` wrapper for every input buffer.

## Mechanism

`InvokeHostFunctionApplyHelper::invokeHostFunction` and `addReads` materialize many `CxxBuf` objects whose `CxxBuf::data` is a `UniquePtr<CxxVector<u8>>`; each `toCxxBuf` call allocates a vector and copies XDR bytes before Rust immediately consumes the bytes through `AsRef<[u8]>`. Previous CxxBuf hypotheses tried to precompute or cache individual buffers and hit sub-threshold ceilings because the bridge still required owning vectors. A bridge-level packet type that stores borrowed pointer/length slices for the duration of the call would remove the allocation/copy/UniquePtr traffic across all invoke inputs at once while keeping the same metered Rust decoding and deterministic host execution.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=2000, T=8`) from `ai-summary/CURRENT_STATE.md`. Every successful invoke-host-function transaction executes `InvokeHostFunctionApplyHelper::addFootprint`, fills `mLedgerEntryCxxBufs` / `mTtlEntryCxxBufs`, builds auth/resource/source/seed `CxxBuf`s, and then calls the Rust bridge synchronously.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:338-497` — `addReads` reserves and fills per-invocation owned `CxxBuf` vectors for ledger and TTL entries.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` constructs auth, host-function, resources, source-account, and seed buffers immediately before crossing to Rust.
- `src/rust/src/bridge.rs:5-15,193-205` — `CxxBuf` is modeled as an owned `UniquePtr<CxxVector<u8>>` and the invoke bridge accepts vectors of that owned wrapper.
- `src/rust/src/common.rs:12-15` — Rust consumes `CxxBuf` only as a byte slice, so the hot invoke path does not need ownership after the synchronous bridge call begins.
- `src/rust/src/soroban_invoke.rs:7-39` — the wrapper forwards buffers by reference into the selected protocol host module.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-593` — the host decodes borrowed bytes through `AsRef<[u8]>`, which can be preserved with a borrowed-slice packet.

## Evidence

- Current diagnostic trace path: `/mnt/nvme2/apply-load/9e61f0301cf2-20260525-143357/logs/9e61f0301cf2-20260525-143357-02-soroswap-tx-2000-t-8.tracy`.
- `applyLedger` has 71 windows totaling **4,412.548 ms** in the trace; timestamp-filtered apply-window C++ invoke helper zones include `addFootprint` at **327.718 ms** over 8,053 calls, `recordStorageChanges` at **114.785 ms** over 8,013 calls, and C++ `invokeHostFunction` self-time at `transactions/InvokeHostFunctionOpFrame.cpp:559` in the self-time export.
- The same trace has `readOne,./util/XDRStream.h:132` at **140.790 ms** inside `applyLedger`, showing that byte-oriented XDR ingress remains visible after the accepted host-side storage-map optimizations.
- Source inspection shows Rust's `CxxBuf` use is read-only on the normal invoke path: `impl AsRef<[u8]> for CxxBuf` just returns `self.data.as_slice()`, and p26 `invoke_host_function` immediately decodes those slices. This makes a borrowed packet a deterministic representation change rather than a host-execution semantic change.
- This differs from prior `005-precompute-cxxbuf-on-tx-construction` and per-cluster CxxBuf-cache failures: those kept the owned-vector ABI and merely moved or duplicated serialization. The proposed redesign removes the owned-vector boundary itself for all invoke inputs.

## Anti-Evidence

- The earlier CxxBuf precompute and per-cluster serialized-entry cache failures establish that single-site input-buffer caching is below Medium and can regress cache locality. A PoC must add narrow spans around `toCxxBuf` allocation/copy and CXX bridge conversion to prove the whole-bridge redesign exceeds the 3% objective floor.
- CXX may not directly support every desired borrowed-slice shape across vectors of slices; the implementation may need a stable C++ packet object with pointer/length arrays whose lifetime is owned by `InvokeHostFunctionApplyHelper`.
- Rust metered decoding, storage setup, VM execution, event serialization, and ledger-change extraction remain mandatory. The win is limited to non-metered bridge allocation/copy and wrapper traversal, not to protocol-visible XDR work.
- The borrowed slices must never outlive the synchronous bridge call or be retained in `ModuleCache`, diagnostics, trace hooks, or testutils replay paths.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related CxxBuf precompute/cache failures exist, but this exact whole-bridge borrowed-packet variant was not previously recorded in fail/success
**Failed At**: reviewer

### Trace Summary

The close-ledger path runs Soroban clusters through `LedgerManagerImpl::applySorobanStageClustersInParallel`, each worker calls `OperationFrame::parallelApply`, and invoke-host-function operations reach `InvokeHostFunctionOpFrame::doParallelApply`. The helper synchronously builds ledger/TTL/auth/resource/source/seed `CxxBuf`s, calls `rust_bridge::invoke_host_function`, and Rust forwards the buffers as `AsRef<[u8]>` into p26 `e2e_invoke::invoke_host_function`, where they are decoded and not retained. The read-only lifetime premise is true, but the stronger "already-owned XDR bytes" premise is false for nearly all inputs: C++ owns XDR objects, not stable contiguous encoded byte slices, so a borrowed packet would still need encoded scratch storage produced by XDR serialization before Rust can decode it.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:2484-2574` — worker hot path calls `parallelApply` for each transaction and the apply thread waits on the cluster futures, so invoke setup is inside the objective's apply window.
- `src/transactions/OperationFrame.cpp:175-188` — `parallelApply` dispatches to the operation-specific `doParallelApply`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:280-340` — the helper stores `rust::Vec<CxxBuf>` for ledger entries and TTL entries and reserves them from the footprint size.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-497` — `addReads` serializes each present ledger entry and TTL entry with `toCxxBuf`, or allocates an empty vector for non-Soroban TTL placeholders.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — `invokeHostFunction` serializes auth entries, host function, resources, source account, and the 32-byte PRNG seed before calling the Rust bridge.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` constructs a `std::vector<uint8_t>` from `xdr::xdr_to_opaque(t)` and wraps it in `std::unique_ptr`; this produces the encoded XDR bytes, it is not merely wrapping bytes that already exist elsewhere.
- `src/rust/src/bridge.rs:13-15,193-205` — the CXX bridge models `CxxBuf` as `UniquePtr<CxxVector<u8>>` and passes vectors of those wrappers to Rust.
- `src/rust/src/common.rs:12-15` — Rust's normal `CxxBuf` access is read-only `AsRef<[u8]>`.
- `src/rust/src/soroban_invoke.rs:7-39` — the bridge dispatches by protocol and forwards the buffers by reference/iterator into the host module.
- `src/rust/src/soroban_proto_any.rs:310-448` — Rust catches panics, constructs the budget from ledger info, and passes `CxxBuf` iterators onward without retaining them.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:472-593` — p26 decodes resources, ledger entries, TTL entries, auth entries, host function, source account, and PRNG seed from `AsRef<[u8]>` slices, then invokes the host and encodes outputs.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1039-1164` — ledger/TTL/auth setup immediately calls `metered_from_xdr_with_budget` or `Host::metered_from_xdr` on those slices; no caller-visible ownership of `CxxBuf` is required after the synchronous call.

### Why It Failed

The proposed bridge representation removes the wrong layer. Rust can borrow the input bytes, but for `HostFunction`, `SorobanResources`, auth entries, source account, ledger entries, and TTL entries the C++ side does not have pre-existing encoded XDR byte buffers to borrow. `toCxxBuf` is the step that creates those bytes from structured XDR objects; replacing `UniquePtr<CxxVector<u8>>` with pointer/length slices would still require some owned encoded scratch buffer with a lifetime covering the bridge call. It therefore cannot be a true zero-copy path unless the design also preserves encoded bytes from transaction parse/load time or changes the Rust host API to accept typed objects directly, neither of which is this hypothesis.

The impact also falls below the optimize-soroswap severity floor. The mandatory Rust XDR decoding, host storage setup, VM/native execution, output encoding, and C++ `recordStorageChanges` remain unchanged, and the C++ serialization pass remains necessary to create byte slices. The remaining removable work is mostly per-buffer heap ownership and wrapper traffic; `std::make_unique<std::vector<uint8_t>>(xdr::xdr_to_opaque(t))` move-constructs the vector from the serialization result rather than copying the byte payload a second time. Prior fail-summary entries already bound related CxxBuf precompute/cache variants below Medium, including transaction input precompute, shared read-only entry caches, dirty-entry caches, TTL-entry hoists, and ledger-constant hoisting. This bridge-only variant does not add a mechanism capable of clearing the required 3% apply-time reduction.

### Lesson Learned

A borrowed Rust bridge is only a meaningful optimization when the caller already owns stable encoded bytes. The Soroban apply bridge mostly starts from structured C++ XDR objects and must create canonical encoded XDR for metered Rust decoding, so a viable Medium-tier design would need a broader typed-input host API or a proven encoded-byte retention strategy with measured critical-path savings, not just a `CxxBuf` ABI replacement.
