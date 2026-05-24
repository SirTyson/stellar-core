# H006: Eliminate Round-Trip `xdr_from_opaque` Decode Of Host-Returned Contract Events In `collectEvents`

**Date**: 2026-05-24
**Subsystem**: soroban
**Severity**: Low
**Impact**: Per-tx C++/Rust XDR bridge overhead on the apply path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The soroban host emits contract events that the apply path must (a) size-meter
against the per-tx event-size limit and (b) include in the
`InvokeHostFunctionSuccessPreImage` hashed into the ledger. Both operations
only require the encoded XDR length and the encoded bytes themselves, not a
fully-decoded `ContractEvent` structure. A correctly-engineered path should
read the byte length, accumulate it for the size check, and emplace the
encoded bytes into the preimage without an intermediate
`xdr::xdr_from_opaque` decode step.

## Mechanism

`InvokeHostFunctionOpFrame::collectEvents`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:770-800`) currently iterates
`out.contract_events` (`Vec<RustBuf>` of XDR-encoded events), and for each
buffer:

1. Reads `buf.data.size()` for the size meter (correct, no decode needed).
2. Calls `xdr::xdr_from_opaque(buf.data, evt)` to decode the buffer into a
   `ContractEvent`.
3. `emplace_back(evt)` into `success.events`.

`InvokeHostFunctionSuccessPreImage::events` is later serialized for hashing,
so the decoded `ContractEvent` is immediately re-encoded back to XDR. The
deviation from expected behavior is the unnecessary decode/re-encode round
trip per event.

## Trigger

Run the protocol-27 soroswap apply-load benchmark. Each successful soroswap
swap emits ~3-6 `ContractEvent` records (transfer events from each SAC token
hop plus router-level events); these all flow through `collectEvents`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:770-800` — `collectEvents`
  performs the per-event `xdr_from_opaque` decode and `emplace_back`.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:643` — `recordStorageChanges`
  follows the same input-decode-then-rehash pattern that fail H013 already
  established as sub-Low.

## Evidence

The diagnostic Tracy trace
(`8dd3f525748f-20260524-114704-02-soroswap-tx-2000-t-8.tracy`) reports
`collectEvents` self-time of 32.43 ms across 8,379 invocations (0.31% of
trace self-time, mean ~3.87 µs/tx). Source reading confirms a redundant
XDR decode is present and that `success.events` is consumed only by
re-serialization for the preimage hash.

## Anti-Evidence

After normalizing by `NUM_CLUSTERS=8` parallel workers and 5 measurement
ledgers (per CURRENT_STATE: 5 of 72 closeLedger events are soroswap
measurement), the projected critical-path saving is far below the Medium
severity floor:

- Raw self-time 32.43 ms ÷ 8 ÷ 5 ≈ 0.81 ms/ledger ≈ **0.38% of the 211 ms
  soroswap median**.

This places the optimization below even the 1% Low floor accepted by this
objective. The cost ceiling is structurally identical to fail H013
(`013-recordstoragechanges-xdr-from-opaque-redecode.md`), which was
rejected for the same XDR-bridge decode pattern on the ledger-entries
side: meta-pattern 8 / Crypto-MetaPattern documents the FFI per-entry
decode cap at sub-Low. There is also a meta-design constraint: replacing
`ContractEvent evt` with the raw `RustBuf` byte view in
`InvokeHostFunctionSuccessPreImage::events` would change the XDR type of
the preimage field, which is a protocol-visible change to the success
preimage that the ledger hashes (it would either require XDR schema
changes or a non-trivial parallel pathway that preserves the existing
preimage type). Without that, the decode cannot be elided.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — `collectEvents` is a distinct call site from
`recordStorageChanges` (fail H013); the events redecode at
`InvokeHostFunctionOpFrame.cpp:770-800` does not appear in any prior
fail record.

### Why It Failed

The removable per-tx XDR-decode work in `collectEvents` is bounded above
by 0.38% of the soroswap median after parallel-worker and
measurement-ledger normalization, below the 1% Low floor and far below
the 3% Medium floor required by this objective. The redecode also
cannot be elided without changing the type of
`InvokeHostFunctionSuccessPreImage::events`, which is XDR-protocol-visible.

### Lesson Learned

The C++/Rust XDR bridge decode pattern is bounded at the same sub-Low
ceiling at every call site on the apply path: ledger-entries
(`recordStorageChanges`, H013), contract events (this hypothesis,
`collectEvents`), and similarly for return values. The
`Vec<RustBuf>` → typed-XDR-decode pattern in C++ should be flagged as
exhausted; no apply-path call site of this pattern clears the Medium
floor in isolation, and the preimage/ledger-hash dependency prevents
batched or eliminated decodes without protocol-visible changes.
