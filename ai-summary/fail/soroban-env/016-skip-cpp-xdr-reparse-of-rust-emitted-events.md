# H016: Skip C++ XDR re-parse of Rust-emitted ContractEvent buffers

**Date**: 2026-05-04
**Subsystem**: soroban-env (rust bridge boundary)
**Severity**: Low
**Impact**: apply-time (post-invoke event collection)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Once the soroban host has externalized a `ContractEvent` to XDR bytes
(`metered_write_xdr` on the Rust side), the C++ embedder should be able
to forward those bytes into the ledger meta / pre-image accounting
without re-parsing them into typed XDR on the C++ side. Each event was
just produced by a deterministic Rust XDR writer; an immediate inverse
parse on the C++ side is purely round-trip work.

## Mechanism

Today, `InvokeHostFunctionOpFrame::collectEvents`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:770-800`) runs:

```cpp
ContractEvent evt;
xdr::xdr_from_opaque(buf.data, evt);
success.events.emplace_back(evt);
```

per Rust-emitted event buffer. The downstream consumers of
`success.events` either re-emit those events into the meta XDR or hash
them; both could be done directly against the original opaque buffer.
Removing the parse would also eliminate the per-event `ContractEvent`
allocation/copy on the C++ heap. Soroswap's trace shows ~20,283
`contract_event` host-call dispatches (and the events buffer ends up
being read back at meta emission), so the work is non-zero.

## Trigger

Any Soroban invocation that emits contract events — soroswap pool
swaps, SAC transfers, mints, burns, etc.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:770-800` — `collectEvents`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:834-870` — `setEvents`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:60-115` —
  `metered_write_xdr` already produces the wire bytes.

## Evidence

- Tracy soroswap trace: `write xdr` 150,911,171 ns self / 202,955 calls
  (includes events plus other write-xdr work).
- `contract_event` dispatch wrapper: 55,969,657 ns self / 20,283 calls.
- C++ side parses each emitted event back to typed XDR using
  `xdr::xdr_from_opaque`, which is uncached and allocates a new
  `ContractEvent` per buffer.

## Anti-Evidence

- The parsed `ContractEvent` is not just used opaquely: it feeds into
  size/limit accounting (`txMaxContractEventsSizeBytes`), pre-image
  hashing, and SAC reconciliation in `setEvents`. Most of these can
  consume the raw wire size, but the SAC reconciliation path
  (`mProtocol23SACReconciliationEvents`) merges events into a typed
  vector that is later XDR-encoded again — keeping that path requires
  either typed events on the C++ side or a refactor of the
  reconciliation merge.
- The existing roundtrip is small in absolute terms: assuming a
  pessimistic ~1 µs of `xdr_from_opaque` work per event ×
  20,283 events ≈ 20 ms aggregate, divided by 8-way parallelism
  ≈ 2.5 ms wall = ~0.013 % of the 19.3-second soroswap apply
  envelope. Even an optimistic 5 µs per event is ~0.06 %.
- The same roundtrip pattern in the opposite direction (C++→Rust)
  was investigated as fail entry 007-eliminate-c++-rust-roundtrip
  and rejected for being below the 3 % Medium floor; the output
  direction has even less aggregate volume.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — fail #007 covered the input-direction roundtrip
(C++→Rust XDR for hostFunction/sourceAccount/authEntries); the
output-direction event roundtrip (Rust→C++ XDR for ContractEvent)
had not been explicitly written up.

### Why It Failed

Below the objective's 3 % Medium severity floor and below the 1 %
benchmark-noise floor. The `xdr_from_opaque` parse for a small
`ContractEvent` struct is sub-microsecond per call; aggregated over
the soroswap workload it is in the low-tens-of-milliseconds range,
which becomes single-digit milliseconds wall-clock after the
parallel-apply 8-way parallelism factor. Even removing the parse
entirely cannot move the soroswap apply median by 1 %.

### Lesson Learned

C++↔Rust roundtrip optimizations on the InvokeHostFunction boundary
have a hard ceiling driven by event/auth/footprint volumes per ledger.
For soroswap (~286 events per ledger across 71 ledgers, post-parallelism),
a single-µs-per-event parse is ~3 ms wall. To clear the 3 % Medium
floor on this objective via roundtrip elimination, the per-call
removable work would need to be ~30 µs+, which is far above what an
opaque-bytes pass-through can save. Future roundtrip hypotheses on
this boundary should pre-quantify the per-call removable work in
microseconds and multiply by the per-ledger call count after
parallelism before promotion.
