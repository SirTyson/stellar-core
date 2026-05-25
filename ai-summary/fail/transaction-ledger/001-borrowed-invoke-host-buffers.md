# H001: Borrowed Invoke-Host Buffers for Immutable Per-Tx Inputs

**Date**: 2026-05-25
**Subsystem**: transaction-ledger / Soroban host bridge
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing per-invocation C++ XDR serialization, heap allocation, and `cxx::UniquePtr<CxxVector<u8>>` churn on immutable host inputs
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For a Soroban transaction whose host function, resources, source account, auth
entries, and base PRNG seed are immutable during apply, the parallel apply path
should pass stable borrowed byte slices into Rust instead of rebuilding owned
`CxxBuf` objects for those fields on every `parallelApply` call. The Rust host
must still perform the same metered XDR decoding and charge the same budget, but
the non-metered C++ side should not repeatedly allocate vectors and serialize
the same immutable XDR values inside the measured apply window.

## Mechanism

`InvokeHostFunctionApplyHelper::invokeHostFunction` constructs
`authEntryCxxBufs`, allocates a new vector for `basePrngSeedBuf`, and calls
`toCxxBuf` for `hostFunction`, `resources`, and `sourceID` on every invocation
(`src/transactions/InvokeHostFunctionOpFrame.cpp:557-584`). `CxxBuf` is an
owned `UniquePtr<CxxVector<u8>>` bridge object (`src/rust/src/bridge.rs:13-15`),
so this path pays allocation/copy cost even for transaction fields that were
fixed at `TransactionFrame` construction time. A borrowed-slice bridge plus
cached immutable encoded buffers on the operation/transaction frame would keep
Rust's metered decode semantics unchanged while removing the C++ allocation and
serialization layer from the hot worker path.

## Trigger

Run the accepted soroswap apply-load scenario (`soroswap, TX=2000, T=8`) on the
current baseline. Every parallel Soroban tx reaches
`InvokeHostFunctionApplyHelper::invokeHostFunction`, so the trigger is one
buffer rebuild for each of the 8,705 contained `invoke_host_function` calls in
the diagnostic trace.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — per-invocation
  construction of auth buffers, base seed vector, and `toCxxBuf` arguments for
  `rust_bridge::invoke_host_function`.
- `src/rust/src/bridge.rs:13-15,193-208` — owned `CxxBuf` definition and bridge
  signature that force C++-owned vectors for immutable inputs.
- `src/rust/src/soroban_invoke.rs:7-38` and
  `src/rust/src/soroban_proto_any.rs:391-440` — Rust bridge entry that can be
  taught to accept borrowed byte slices while preserving the same metered
  `metered_from_xdr` path.

## Evidence

The current soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` has 8,705
`invoke_host_function` calls fully contained in `applyLedger`, totaling
23.906s of worker time across the trace. The C++ call site constructs several
owned bridge buffers per call before entering Rust; the source shows no cache
for `hostFunction`, `resources`, `sourceID`, auth entries, or the 32-byte base
seed. Earlier C++-side precompute attempts were sized against an older, much
slower baseline; against the current ~207.6ms median soroswap apply baseline,
removing several allocations and XDR serializations per tx has a plausible
Medium ceiling if it saves roughly 6-20ms per ledger.

## Anti-Evidence

Rust must still decode the same XDR under the transaction budget, so this
hypothesis cannot claim savings from `metered_from_xdr`, host storage-map
construction, or guest execution. It also needs a careful CXX API design:
borrowed slices must outlive the Rust call, must not alias mutable C++ buffers,
and should fall back to the existing owned path for fields that are not cached.
If direct narrow profiling shows `toCxxBuf` allocation/copy is below roughly
3us per immutable field per tx, this falls below the objective's Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/transaction-ledger/summary.md` entry `005-precompute-cxxbuf-on-tx-construction`
**Failed At**: reviewer

### Trace Summary

The parallel Soroban apply path reaches `InvokeHostFunctionOpFrame::doParallelApply`, constructs an `InvokeHostFunctionParallelApplyHelper`, gathers ledger-entry and TTL buffers, then calls `InvokeHostFunctionApplyHelper::invokeHostFunction`. That function still rebuilds owned `CxxBuf` wrappers for the immutable host function, resources, source account, auth entries, and 32-byte PRNG seed before crossing into Rust. This is real per-invocation work, but it is the same immutable-input CxxBuf precompute target already recorded as failed in the transaction-ledger fail summary.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:280-340` — `InvokeHostFunctionApplyHelper` stores references to the operation, transaction resources, PRNG seed, config, module cache, and reserves per-invocation ledger/TTL buffer vectors.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — rebuilds auth-entry `CxxBuf`s, allocates/copies `basePrngSeedBuf`, serializes `hostFunction`, `resources`, and source ID with `toCxxBuf`, then calls `rust_bridge::invoke_host_function`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1358-1377` — protocol-23+ Soroban transactions enter this helper via `doParallelApply`, so the target is in the close-ledger parallel apply worker path.
- `src/transactions/TransactionUtils.h:370-376` — `toCxxBuf` allocates a fresh `std::vector<uint8_t>` from `xdr::xdr_to_opaque`.
- `src/rust/src/bridge.rs:13-15,193-208` — `CxxBuf` is an owned `UniquePtr<CxxVector<u8>>`, and the exported invoke bridge accepts those buffers.
- `src/rust/src/common.rs:12-15` and `src/rust/src/soroban_proto_any.rs:136-143,391-448` — Rust reads `CxxBuf` as byte slices and continues into the same host invocation/decode path, so the proposed bridge change only targets the C++ ownership/allocation layer.

### Why It Failed

This hypothesis is substantially equivalent to the prior failed `005-precompute-cxxbuf-on-tx-construction` investigation, which already covered precomputing `toCxxBuf` for `hostFunction`, `resources`, `sourceID`, and auth entries and sized the maximum recoverable C++-side work at about 16 ms per soroswap ledger, roughly 2.5% and below this objective's 3% Medium floor. The borrowed-slice framing does not add a new hot component: it removes the same C++ XDR serialization/vector-allocation layer, while Rust metered decoding, storage setup, guest execution, output serialization, and ledger-entry buffers remain. The extra 32-byte PRNG-seed vector is smaller than the previously sized fields and cannot lift the duplicate mechanism over the severity threshold.

### Lesson Learned

For invoke-host bridge hypotheses, distinguish zero-copy API shape from the actual removable work. A borrowed bridge can make the precompute cleaner, but if the only avoided work is the already-sized immutable-input `toCxxBuf` construction, the optimization remains a duplicate/sub-threshold C++ apply-path micro-optimization under the optimize-soroswap Medium-only review gate.
