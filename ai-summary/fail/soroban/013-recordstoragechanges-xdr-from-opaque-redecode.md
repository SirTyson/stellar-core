# H013: Eliminate Round-Trip `xdr_from_opaque` Decode of Host-Returned Ledger Entries in `recordStorageChanges`

**Date**: 2026-05-23
**Subsystem**: soroban (C++/Rust XDR bridge — apply side)
**Severity**: Low (sub-threshold)
**Impact**: Avoid per-modified-entry XDR re-decode in the parallel-apply
worker writeback path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After `invokeHostFunction` returns, the Rust host hands back
`InvokeHostFunctionOutput.modified_ledger_entries` as a `rust::Vec` of
opaque byte buffers — each one a re-serialized XDR `LedgerEntry` that
the host had a moment earlier in structured Rust form (the
`Storage::map` `Rc<LedgerEntry>` values). The C++ side then immediately
re-decodes each buffer back into a structured `LedgerEntry` via
`xdr::xdr_from_opaque(buf.data, le)` (`InvokeHostFunctionOpFrame.cpp:657`)
so that `LedgerEntryKey(le)` and `upsertLedgerEntry(lk, le)` can run.
An efficient design would either (a) have the host return the
structured `LedgerEntry` plus the already-known `LedgerKey` directly
across the bridge — bypassing the encode/decode round trip — or (b)
re-use the cached `Rc<LedgerEntry>` that the host already owns in
`Storage::map` for unchanged-RW entries, only paying the encode/decode
cost for entries the host materially mutated.

## Mechanism

The host owns `Rc<LedgerEntry>` values in `Storage::map`. At
`recordStorageChanges` time the host serializes every footprint
`(key, Option<entry>)` slot whose entry is `Some` into XDR bytes,
pushes them into `modified_ledger_entries`, and ships the rust::Vec to
C++. The C++ writeback then deserializes the same bytes back into a
`LedgerEntry`, computes `LedgerEntryKey(le)` (essentially the inverse
of what the host already knew), and threads the structured entry into
`upsertLedgerEntry`. For soroswap with ~6 RW entries returned per
soroban tx (2 ContractData balance entries, 2 TTL entries, 1 pool
ContractData, 1 pool TTL), this is roughly `7,891 tx × 6 ≈ 47k`
redundant decode+keying cycles per benchmark run. Each
`xdr_from_opaque` on a small ContractData is in the low microseconds.

The ACTUAL deviation: a structured value that already exists in the
host is dropped, re-encoded into bytes, shipped across the bridge,
and re-decoded — twice paying for an O(entry_size) walk that produces
no new information.

## Trigger

Run the soroswap apply-load benchmark; the
`recordStorageChanges`/`xdr_from_opaque` zone is exercised in every
parallel worker's per-tx writeback.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641-741` —
  `recordStorageChanges` per-entry `xdr_from_opaque` + `LedgerEntryKey`
  + `upsertLedgerEntry` loop.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` — host-side
  `Storage::map` walk that materializes
  `modified_ledger_entries: rust::Vec<RustBuf>`.
- `src/rust/src/contract.rs` / `lib.rs` (`InvokeHostFunctionOutput`
  definition) — the `modified_ledger_entries` field shape that locks
  C++ into the opaque-bytes contract.

## Evidence

- The host operates on structured `Rc<LedgerEntry>` values and
  serializes them only to satisfy the C++ bridge.
- Each `xdr_from_opaque(buf, le)` walks the entry's full XDR shape,
  even for soroswap's small ContractData balance entries (~80–160 B
  per entry).
- The corresponding `LedgerEntryKey(le)` then re-derives a `LedgerKey`
  that the host already had as a `Rc<LedgerKey>` in its storage map.

## Anti-Evidence

- The bridge boundary is `Send + 'static` — the host's `Rc<LedgerEntry>`
  cannot be passed across the C++ ABI; only owned/copied data can
  cross. So "share the structured entry" requires either a deep clone
  (which costs the same as XDR encode+decode for small entries) or a
  full architectural redesign of the host output contract to use a
  C-friendly tagged representation.
- The cached-XDR-bytes side of the bridge (caching encoded inputs to
  the host) is already in Meta-Pattern #4 (XDR Bridge Cost Is
  Distributed and Sub-Threshold). The output side is symmetric in
  size and frequency: at ~6 modified entries × ~7,900 tx × ~1.5 µs
  decode = ~70 ms aggregate worker CPU per run.
- After 8-way cluster parallelism: ~8.8 ms wall-clock across the
  entire 71-ledger benchmark. Per ledger: ~125 µs. Against the 218 ms
  soroswap baseline: ~0.057%.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail file targets the OUTPUT side of the
host bridge specifically. Meta-Pattern #4 and fails 004 / 006 / 001 /
004-residual all target the INPUT side (`toCxxBuf` for ledger entries
being shipped TO the host, `addReads` preparation). The output decode
in `recordStorageChanges` has not been written up.

### Why It Failed

Arithmetic puts the recoverable wall time deep below the 1% Low floor:

- ~47k decode cycles × ~1.5 µs/cycle ≈ 70 ms aggregate worker CPU.
- After 8-way cluster parallelism normalization: ~8.8 ms total
  wall-clock across the 71-ledger benchmark run.
- Per ledger: ~125 µs.
- Against the 218 ms soroswap baseline: ~0.057%.

This is two orders of magnitude below the 1% Low floor and ~50× below
the 3% Medium threshold required by the optimize-soroswap objective.

Even a perfect-elimination variant (assume the bridge is redesigned
to pass structured entries with zero marshalling cost — architecturally
implausible without a C-friendly tagged representation) caps the
recoverable surface at the same 0.057%. A realistic variant that
shares the structured Rust representation requires a deep clone of
each `LedgerEntry` on the C++ side anyway, which costs roughly the
same as XDR encode+decode for soroswap's small ContractData/TTL entry
shapes. Symmetric to the input side covered by Meta-Pattern #4.

### Lesson Learned

The output side of the host XDR bridge has the same per-entry cost
ceiling as the input side: a small fraction of 1% of apply time for
soroswap's modified-entry shape (~6 small entries per tx). Extend
Meta-Pattern #4 to cover both directions — neither input nor output
encode/decode can clear the Medium floor for soroswap. Future XDR
bridge hypotheses should be projected against the bidirectional
~2.5% / sub-1% combined ceiling before deep investigation.
