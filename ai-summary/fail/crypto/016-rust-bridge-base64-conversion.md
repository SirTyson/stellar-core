# H016: Eliminate base64 conversions on the apply-path Rust bridge

**Date**: 2026-04-29
**Subsystem**: crypto, rust-bridge
**Severity**: Low
**Impact**: Apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The `to_base64` / `from_base64` Rust-bridge functions
(`src/rust/src/b64.rs`) are utility primitives for XDR-text interop and
should NOT appear on the soroswap apply path. The Soroban host invocation
bridge (`invoke_host_function`) passes raw XDR bytes through `CxxBuf` /
`RustBuf` directly and never base64-encodes them.

## Mechanism

If `to_base64` or `from_base64` were unexpectedly invoked from the apply
path (e.g., for diagnostic event encoding, trace export, or some metering
log), it would add per-call work scaling with the size of the encoded
buffer. base64 is pure CPU work but adds ~3-5x cycles vs. raw byte copy.

## Trigger

Investigate whether any `closeLedger` descendant calls `to_base64` /
`from_base64` directly or transitively.

## Target Code

- `src/rust/src/b64.rs:1-30` — base64 encode/decode utilities
- `src/rust/src/bridge.rs` — bridge declarations
- `src/transactions/InvokeHostFunctionOpFrame.cpp` — bridge call site

## Evidence

base64 is cited as a Rust-bridge utility in the rust subsystem summary,
making it a candidate for hidden apply-path overhead.

## Anti-Evidence

Direct grep of `src/transactions/`, `src/ledger/`, `src/bucket/`, and
`src/herder/` for `to_base64` / `from_base64` / `b64` / `base64` returns
**no matches** in apply-path code. The Rust-bridge base64 functions are
only used by `core/CommandHandler` for CLI/HTTP endpoint XDR text
conversion (out-of-band, not during `closeLedger`). The Soroban
invocation bridge passes raw bytes via `CxxBuf` / `RustBuf` and never
hits the base64 path — verified by reading
`src/rust/src/soroban_invoke.rs` and the `invoke_host_function`
signature in `src/rust/src/bridge.rs`, neither of which touches the
b64 module.

Tracy traces of the soroswap apply benchmark show no `to_base64` or
`from_base64` zones inside `applyLedger`. The hypothesis is fully
defeated by code inspection: base64 is not on the apply critical path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — Rust-bridge base64 was not previously investigated
for apply-path impact; prior fails focused on Soroban host SHA256,
verifySig, ShortHash, and FFI buffer overhead, not text-encoding bridge
functions.

### Why It Failed

base64 conversion is not invoked from any `closeLedger` descendant. It is
exclusively used by HTTP/CLI command handlers for XDR-text interop, which
runs outside the benchmark's measured window. There is no apply-time work
to eliminate. This is a "no hotspot found" rejection — the proposed
optimization target does not exist on the critical path.

### Lesson Learned

Before proposing a Rust-bridge optimization, verify the target function
is reachable from `closeLedger` in production. The Rust subsystem
contains many utility functions (base64, i128 arithmetic, quorum checker,
log shim) that are NOT on the apply path. Only `invoke_host_function`,
`compute_transaction_resource_fee`, `compute_rent_fee`,
`compute_rent_write_fee_per_1kb`, and `contract_code_memory_size_for_rent`
are reachable during soroswap apply (per the rust subsystem summary
"Soroban Host Invocation" + "Fee Computation" sections). All other
bridge functions are out-of-scope for apply-time optimization.
