# H032: Eliminate Per-Invocation Re-Encoding of Footprint Key XDR in `get_ledger_changes`

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: Low (projected ~0.2–0.5% apply-time)
**Impact**: Redundant XDR serialization on the host→C++ return path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`e2e_invoke::get_ledger_changes`
(`src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356`) walks
every entry in `storage.map` and, for each one, calls

```rust
metered_write_xdr(budget, key.as_ref(), &mut entry_change.encoded_key)?;
```

The resulting bytes are returned to the C++ caller (`InvokeHostFunctionOpFrame`)
purely so that C++ can look the LedgerKey back up in its already-cached map
of footprint entries. C++ already has the LedgerKey (it serialized it to
build the input footprint in `addReads`,
`src/transactions/InvokeHostFunctionOpFrame.cpp:386`).

The protocol-level operation result XDR does NOT include `encoded_key` — it's
an internal Rust↔C++ marshaling field. SHOULD: pass back a stable
position-into-footprint index (the same `pos` that's already computed at
line 248) and let C++ map index→LedgerKey it already owns. That eliminates
~N × M XDR encodes per ledger.

## Mechanism

For every footprint entry on every invocation, both sides serialize the same
LedgerKey to XDR:

1. C++ `addReads` writes the LedgerKey to XDR to set up the Rust call.
2. Rust `get_ledger_changes` writes the SAME LedgerKey to XDR for the return
   trip.

The Rust-side encode is metered via `metered_write_xdr` (touches
`ValSer.const_term` and `MemCpy`). That metering DOES count against the
protocol-visible budget, so dropping it entirely changes instruction counts
and is therefore protocol-visible — and **that is what kills this
hypothesis**.

## Trigger

Every Soroban invocation. For soroswap, ~123 invocations × ~10 footprint
keys = ~1230 redundant key encodes per ledger close.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:248-356`
  (`get_ledger_changes` main loop) — `metered_write_xdr(budget, key.as_ref(),
  …)` at line 250 and the parallel use at line 381 in
  `add_footprint_only_ledger_changes`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386` (`addReads`) — C++
  side that would consume the position-based index.

## Evidence

- Tracy: `write xdr` zone (`soroban-env-host/src/host/metered_xdr.rs:72`)
  shows 168 ms total self-time across the whole soroswap window with
  ~252K calls. A meaningful fraction (~1230/ledger × 71 = 87K) flows through
  the `get_ledger_changes` key-encode path.
- Per-key encode is small but not free; cumulative is ~50 ms CPU / 8 workers
  ≈ 6 ms wall over the entire 71-ledger window — about 0.08 ms per ledger
  close, or **~0.04%** of the 207 ms soroswap baseline.

## Anti-Evidence

- **Protocol-visible metering**: `metered_write_xdr` charges budget
  dimensions with non-zero `const_term`. Removing the charge changes the
  number of instructions and memory bytes recorded in the host budget,
  which is observable in the operation result. This is squarely covered
  by Meta-Pattern #2 from `fail/soroban-env/summary.md`: "ValSer/MemCpy
  have non-zero const_term → protocol-visible charge counts; can't skip
  charges without protocol change."
- Even ignoring metering, the wall-clock saving is two orders of magnitude
  below the Medium threshold and below the 1% benchmark-noise floor.
- The encoded_key bytes are part of the established host↔C++ ABI; reworking
  it requires touching both the Rust bridge and `InvokeHostFunctionOpFrame`
  and changing/recording corresponding protocol metering — a high-risk
  surface for a sub-1% gain.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not in fail/hypothesis/reviewed/poc. Adjacent to fail
`003-cache-encoded-xdr-bytes-in-memory-soroban-state` (which targeted entry,
not key, caching across invocations) and to the general Meta-Pattern #2.

### Why It Failed

Twofold:

1. **Below severity threshold**: Even with zero metering concerns, projected
   savings are ~0.04% — far under the 1% noise floor and the 3% Medium gate.
2. **Protocol-visible metering**: The `metered_write_xdr` charge feeds
   directly into the budget dimensions that produce observable instruction
   and memory counts in the operation result. Dropping or reducing this
   charge requires a protocol bump (Meta-Pattern #2). The combination of
   tiny gain and protocol cost makes this strictly worse than no-op.

### Lesson Learned

C++↔Rust XDR round-trips look wasteful in a profile but are usually pinned
by protocol-observable metering. Before chasing them, check whether
`metered_write_xdr` or `metered_from_xdr` is on the hot path — if so,
the charge counts are part of the protocol contract and the only viable
optimization is one that preserves the charges (e.g., charging the same
bulk amount without re-running the serializer). For sub-1% gains the
engineering cost is rarely justified.
