# H010: Zero-Copy `modified_ledger_entries` FFI Return to Eliminate Per-Entry Round-Trip Allocations

**Date**: 2026-04-29
**Subsystem**: rust (cxx bridge) / transactions
**Severity**: Medium (proposed) → rejected
**Impact**: reduce per-invoke FFI allocator and copy overhead on the soroswap apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The Soroban host invocation should return modified-ledger-entry payloads to C++
without forcing a per-entry allocation chain. Today, each entry follows this
round-trip:

1. Rust host serializes `LedgerEntry` to a `Vec<u8>` via `metered_write_xdr`
   (or, for synthesised TTL entries in `extract_ledger_effects`, via a fresh
   `non_metered_xdr_to_rust_buf`, src/rust/src/soroban_proto_any.rs:294-296).
2. The `Vec<u8>` is wrapped in a `RustBuf` and pushed onto a
   `Vec<RustBuf> modified_ledger_entries`.
3. cxx exposes this as a `rust::Vec<RustBuf>` to C++.
4. C++ iterates `out.modified_ledger_entries` (InvokeHostFunctionOpFrame.cpp:654)
   and calls `xdr::xdr_from_opaque(buf.data, le)` per entry, which materialises
   a fresh `LedgerEntry` value in C++.

Expected behaviour: a single contiguous serialised buffer + small offset/length
table per invoke would let C++ either (a) avoid per-entry `RustBuf` heap
ownership or (b) skip re-deserialisation by passing a structured
already-deserialised representation across the bridge.

## Mechanism

Each soroswap invoke produces a handful of modified entries (a few CONTRACT_DATA
writes plus 1–2 TTL entries). For 2 000 swaps × ~3 ledgers in the apply window,
that is ~6 k–12 k entries per benchmark run, each incurring a Rust `Vec<u8>`
allocation, a cxx `rust::Vec` slot, and a C++ XDR deserialisation. The TTL path
is especially wasteful: `extract_ledger_effects` constructs a fresh
`LedgerEntry { TtlEntry { key_hash, live_until_ledger_seq } }` purely to encode
it as XDR so C++ can decode it back. A typed cross-FFI struct (or a single
concatenated buffer with offsets) would remove the encode-then-decode cycle
and amortise the per-entry allocator and `rust::Vec` overhead.

## Trigger

Run `apply-load --mode soroswap` with Tracy enabled and inspect `recordStorageChanges`
self-time, plus aggregated per-invoke RustBuf consumption. A zero-copy or batched
return path should reduce both `recordStorageChanges` and the surrounding
FFI cleanup zones.

## Target Code

- `src/rust/src/soroban_proto_any.rs:261-302` — `extract_ledger_effects`
- `src/rust/src/soroban_proto_any.rs:487-506` — output assembly
- `src/rust/src/bridge.rs` — `InvokeHostFunctionOutput { modified_ledger_entries: Vec<RustBuf>, ... }` declaration
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-720` — `recordStorageChanges`
- `src/rust/src/common.rs` — `RustBuf` / `CxxBuf` definitions

## Evidence

- Trace `1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`:
  `write xdr` (soroban-env-host/src/host/metered_xdr.rs:61) is 764 ms self
  with 132 907 calls; this includes the entry-write encoding that ends up in
  `modified_ledger_entries`.
- `recordStorageChanges` at InvokeHostFunctionOpFrame.cpp:643 is
  invoked 3 335 times (one per Soroban invoke) and contains the per-entry
  XDR-decode loop.

## Anti-Evidence

- Prior failure `006-rust-bridge-small-cxxbufs.md` established that the cxx
  bridge wrapper zones (CxxBuf / RustBuf alloc/free overhead) total only
  ~22 ms across the entire trace. The per-entry FFI allocator overhead is
  therefore far below the Medium floor.
- `recordStorageChanges` itself is only 28 ms self-time across the whole
  trace (~0.28%). Even eliminating the entire C++ XDR-decode step (impossible
  without a major API redesign) would not reach the 3% Medium floor.
- Replacing `Vec<RustBuf>` with a typed cxx struct that mirrors `LedgerEntry`
  would require duplicating the entire XDR LedgerEntry surface across the
  bridge — a cross-cutting redesign whose maintenance cost vastly outweighs
  the achievable saving.
- The `write xdr` work itself happens **inside the soroban host** (metered XDR
  encoding for entry-change tracking and rent accounting). It is required by
  the host's metering and entry-change semantics, and removing it would mean
  modifying the soroban-env subsystem's data model — which is out of scope for
  the crypto/rust subsystem and structurally locked by the host's metered XDR
  contract.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — zero-copy / batched FFI return for modified ledger entries
was not previously investigated. Distinct from fail/006 which targeted
**input** CxxBuf rebuilds.

### Why It Failed

The C++-side per-entry XDR-decode zone (`recordStorageChanges`) is 28 ms self
across the trace and the cxx wrapper overhead is bounded at ~22 ms per
fail/006. Sum total is ~50 ms; Medium floor on a 313 ms median soroswap apply
is ~9.4 ms × 3 of headroom, but only if savings are concentrated inside
applyLedger. Realistic savings from a zero-copy redesign are a fraction of
those 50 ms because (a) some XDR work cannot be eliminated (the host *must*
serialise to compute entry sizes for write-byte metering), and (b) the
synthesised TTL entries still require a key-hash + live-until tuple to
reach C++. The redesign cost (cross-bridge typed wrappers for the full
LedgerEntry surface) is grossly disproportionate to the achievable apply-time
reduction.

### Lesson Learned

FFI redesigns for soroban output payloads are structurally bounded by the
soroban-env subsystem's metered XDR contract: the host must serialise entries
for its own internal accounting before they can be returned, so eliminating
the C++-side decode does not eliminate the encoding work that already happens
on the Rust side. To get a Medium-tier win in this neighbourhood, the
hypothesis must target the host-side encoding itself (a soroban-env-scope
change), not the C++-side decode.
