# H003: Reuse Host-Encoded LedgerEntry Bytes in addLiveBatch via Post-Stamp 4-Byte Patch

**Date**: 2026-05-22
**Subsystem**: ledger, bucket, transactions
**Severity**: Medium
**Impact**: Apply-time CPU (XDR encode/decode work)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For each Soroban output entry, the Rust host already produces a fully
XDR-encoded `LedgerEntry` (with `lastModifiedLedgerSeq=0`) in
`InvokeHostFunctionOutput::modified_ledger_entries`. The C++ apply path then
re-encodes the same `LedgerEntry` shortly afterwards when the entry is
written to the BucketList (via the bucket put path that consumes the
sealed LedgerTxn output). A more efficient design would carry the
host-supplied encoded bytes through `commitChangesFromSuccessfulTx` →
`mGlobalEntryMap` → `getAllEntries(initEntries, liveEntries, deadEntries)`
→ `addLiveBatch`, perform a **4-byte in-place patch** of the
`lastModifiedLedgerSeq` prefix at stamp time, and reuse the resulting bytes
when wrapping the entry as `BucketEntry::LIVEENTRY` or `INITENTRY` for the
output bucket — eliminating the `xdr_to_opaque(le)` re-encode per output
entry.

## Mechanism

In `InvokeHostFunctionOpFrame::recordStorageChanges`
(`src/transactions/InvokeHostFunctionOpFrame.cpp:641`), each entry in
`out.modified_ledger_entries` is decoded via `xdr_from_opaque` into a fresh
`LedgerEntry`. The decoded entry is then handed off through
`commitChangesFromSuccessfulTx` and eventually fed into `addLiveBatch`,
where the bucket assembly pipeline must re-encode it to XDR for the bucket
file. The host-supplied bytes are discarded after the C++ decode. If those
bytes were threaded through alongside the `LedgerEntry`, the apply path
could skip the bucket-side `xdr_to_opaque` per output entry, replacing it
with a `memcpy` + 4-byte sequence-number patch.

## Trigger

Soroswap workload: each tx writes ~3–5 RW Soroban entries; `addLiveBatch`
encodes each into the bucket. Across 7467 txs / 71 ledgers ≈ 420
entries/ledger that take this path.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:641` — `recordStorageChanges`
  (host bytes available, decoded then discarded)
- `src/transactions/ParallelApplyUtils.cpp:1241` — `commitChangesFromSuccessfulTx`
  (entry handoff to global map)
- `src/bucket/BucketManager.cpp:1026` — `addLiveBatch` (re-encode site)
- `src/bucket/LiveBucket.cpp` — `convertToBucketEntry` (BucketEntry wrap +
  encode site)

## Evidence

- Tracy: `addLiveBatch` self-time ~155ms across 71 ledgers (~2.2ms/ledger)
  of which a portion is BucketEntry XDR encoding.
- Tracy: Soroban `xdr_from_opaque` calls aggregated in `recordStorageChanges`
  zone (per-tx self-time small but cumulative).
- Fail 006 explicitly identified the post-stamp 4-byte patch as the
  "required design" — i.e., this lineage was recognized as the only
  technically viable route to actually reuse the bytes.

## Anti-Evidence

- **Per-entry savings are small.** Decoding + re-encoding a Soroban
  `LedgerEntry` is ~1–3µs combined; 420 entries/ledger ≈ 0.4–1.3ms/ledger
  saved, i.e. **0.2–0.6%** of soroswap apply baseline (230ms). This is
  **below the Medium threshold (3%)** and at/below benchmark noise.
- The bucket put path wraps `LedgerEntry` as `BucketEntry` (a XDR union with
  discriminant + the entry). Reusing host bytes requires either (a) a custom
  serializer that splices the bucket-entry discriminant prefix in front of
  the patched entry bytes, or (b) a refactor of the bucket writer to accept
  pre-encoded entry bodies. Both are invasive changes spanning bucket,
  ledger, and transactions subsystems for sub-1% return.
- Pin-pointed risk: bucket file format is part of the network's persisted
  state. Any byte-level encoding shortcut introduces a high probability of
  divergence from the canonical XDR encoder; consensus-critical.
- The lesson in fail 006 (post-stamp 4-byte patch is the required design)
  is a forward-looking pointer, not an unexplored win — the projected
  impact even with that design is too small to justify the cross-subsystem
  refactor and bucket-format risk.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — extends fail 006 with the explicit post-stamp-patch
design recommended by its lesson; not previously written up as a concrete
hypothesis.

### Why It Failed

Even the maximal version of the optimization (full byte-reuse with 4-byte
sequence-number patch and a bucket-writer carve-out for pre-encoded
entries) saves only ~0.5–1.3ms per ledger on soroswap, well below the 3%
Medium severity floor. The encode/decode roundtrip is real but the per-entry
constants are too small; the dominant apply cost remains inside the Rust
host (`parallelApply` worker self-time, dominated by `host_function`
execution and budget metering), not the C++ bridge encoding. The cross-
subsystem refactor and bucket-format risk further reduce expected value.

### Lesson Learned

Quantify XDR encode/decode roundtrips by **byte volume per ledger** (not
just call count) before proposing byte-reuse pipelines. For soroswap-shaped
workloads, the per-entry payloads are small enough that even a full
byte-reuse pipeline cannot reach Medium severity unless it eliminates an
allocation-heavy phase wholesale. Future hypotheses in this area must show
either >50KB/ledger of saved encoding work or pair the byte-reuse with a
structural simplification (e.g., removing an entire intermediate
representation), not a 1:1 prefix patch.
