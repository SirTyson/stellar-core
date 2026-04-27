# H004: C++/Rust XDR Bridge Serialization Hotspot

**Date**: 2026-04-27
**Subsystem**: soroban
**Severity**: Low
**Impact**: possible Soroban host invocation serialization overhead, below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The C++/Rust Soroban invocation boundary should avoid redundant serialization work when preparing footprint entries and consuming host output. If ledger entries are already available as C++ XDR objects, the apply path should not spend enough time re-encoding and decoding those same objects to materially affect soroswap `closeLedger` time.

## Mechanism

The initial concern was that `InvokeHostFunctionOpFrame::addReads` serializes footprint entries into `CxxBuf`, Rust deserializes them in `soroban_proto_any`, Rust serializes modified entries back to `RustBuf`, and C++ deserializes them in `recordStorageChanges`. If this bridge round-trip dominated the apply path, replacing it with a more direct representation or a batched bridge format could reduce apply time. The trace, however, did not isolate this bridge path as a Medium-or-better bottleneck: the visible C++ bridge zones are much smaller than the host execution and bucket lookup zones.

## Trigger

Run the current soroswap benchmark (`scripts/run_apply_load_matrix.py --tracy`, soroswap TX=4000, T=8) and inspect the Soroban invocation bridge zones. The trace shows `write xdr` in the Rust host at **516,931,038 ns total / 388,067,513 ns self**, but the C++ bridge preparation zones are only `addReads` at **67,218,508 ns total / 44,565,504 ns self** and `recordStorageChanges` at **23,976,764 ns total / 13,220,787 ns self**.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:381-535` — `addReads` serializes footprint ledger entries and TTL entries with `toCxxBuf`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-638` — `invokeHostFunction` serializes host-function inputs and calls the Rust bridge.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — `recordStorageChanges` deserializes returned modified ledger entries.
- `src/rust/src/soroban_proto_any.rs:136-165` — helper functions deserialize and serialize XDR buffers.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust-side invocation passes encoded buffers into the versioned Soroban host.

## Evidence

The C++ code clearly performs a bridge round-trip: `addReads` calls `toCxxBuf(*entryOpt)` and `toCxxBuf(*ttlEntry)`, `invokeHostFunction` passes vectors of `CxxBuf` into `rust_bridge::invoke_host_function`, and `recordStorageChanges` calls `xdr::xdr_from_opaque` on each returned modified entry. This is on an applyLedger descendant through `InvokeHostFunctionOpFrame::doParallelApply`.

## Anti-Evidence

The dominant `write xdr` zone in the trace is reported from `soroban-env-host/src/host/metered_xdr.rs`, which is mostly host-side metered XDR work inside contract execution, not uniquely the C++ bridge preparation loop. The directly attributable C++ bridge zones (`addReads` and `recordStorageChanges`) total under 100 ms across the full trace, below the objective's Medium threshold unless a much broader host XDR redesign is proposed and proven.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in local soroban hypothesis/fail/review queues

### Why It Failed

The trace does not support a specific bridge-only optimization with a plausible 3-10% soroswap apply-time reduction. Most visible XDR self-time belongs to Soroban host metered XDR internals, while the concrete C++ bridge preparation and result-consumption zones are below the objective severity threshold.

### Lesson Learned

Do not treat aggregate `write xdr` host zones as proof that the C++/Rust bridge is the bottleneck. Separate bridge preparation (`addReads`, `recordStorageChanges`) from host-internal XDR before proposing serialization optimizations.
