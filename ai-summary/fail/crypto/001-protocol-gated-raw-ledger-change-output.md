# H001: Protocol-Gated Raw Ledger-Change Output Pipeline

**Date**: 2026-05-21
**Subsystem**: crypto / Rust bridge / ledger-change XDR
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing redundant XDR encode/decode/re-encode work from successful Soroban ledger changes
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Successful Soroban invocation should commit exactly the `LedgerEntry` values returned by the host, validate the same footprint/resource limits, charge the same protocol-visible rent and serialization budget for the active protocol, and produce identical bucket-list bytes and metadata. For a next-protocol-gated optimization, p26 behavior should remain byte-for-byte and budget-for-budget unchanged, while protocol >26 may use an equivalent bulk/typed metering rule if the serialized output bytes are preserved.

## Mechanism

The current output path serializes each modified host entry to `encoded_new_value` in Rust, copies it through `RustBuf`, decodes it back to `LedgerEntry` in `InvokeHostFunctionOpFrame::recordStorageChanges`, and later writes the entry back through the C++ ledger/bucket machinery. This repeats XDR walking around a value whose canonical bytes already exist at the Rust output boundary. A protocol-gated raw ledger-change pipeline could carry `(encoded LedgerEntry bytes, precomputed LedgerKey/key size/entry size/rent metadata, footprint position)` through the bridge and commit using those bytes or a decoded-once typed value, avoiding the Rust encode -> C++ decode -> later C++ re-encode chain while preserving deterministic commit order.

## Trigger

Run the current soroswap apply-load case (`soroswap, TX=2000, T=8`) on the accepted trace from `ai-summary/CURRENT_STATE.md`. Every successful swap returns modified contract-data and TTL entries from `invoke_host_function`, causing `get_ledger_changes`, `extract_ledger_effects`, `recordStorageChanges`, and bucket output writes to process the same ledger-entry payloads.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:get_ledger_changes:248-336` — serializes keys and new RW entries into `LedgerEntryChange`.
- `src/rust/src/soroban_proto_any.rs:invoke_host_function:481-499` — extracts rent changes and modified ledger-entry buffers for the C++ bridge.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:recordStorageChanges:640-720` — decodes each `RustBuf` into `LedgerEntry`, recomputes the key, validates coverage, and upserts to the ledger.
- `src/bucket/BucketOutputIterator.cpp:put:80` and `util/XDRStream.h:writeOne/writeBytes` — later serialize committed entries for bucket-list output.

## Evidence

The current soroswap Tracy trace keeps these zones inside `applyLedger`: `write xdr` at `soroban-env-host/src/host/metered_xdr.rs:72` totals 168.017 ms / 202,955 calls inside apply, `recordStorageChanges` totals 98.487 ms / 6,776 calls, `writeOne` totals 126.162 ms inside apply, `writeBytes` totals 28.414 ms inside apply, and `BucketOutputIterator::put` totals 166.846 ms inside apply. These are not all independently removable, but together they describe a broad ledger-change serialization pipeline rather than a single micro-call-site; avoiding one complete encode/decode/re-encode lap has Medium headroom where prior isolated bridge or XDR micro-hypotheses did not.

## Anti-Evidence

Prior failures show that skipping metered XDR naively changes protocol-visible `ValSer`/`ValDeser` accounting and that C++-side decode alone is below threshold. This hypothesis is only viable if protocol-gated bulk/typed metering is part of the design and if the PoC proves that enough downstream bucket/ledger serialization work is actually bypassed rather than merely moved.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — broader than prior H010, but overlaps its failed FFI/decode surface
**Failed At**: reviewer

### Trace Summary

The host produces `LedgerEntryChange` records by metered-serializing modified read-write entries and by keeping rent-relevant encoded sizes, then `extract_ledger_effects` forwards those existing bytes as `RustBuf` values or builds TTL `LedgerEntry` bytes. C++ then must decode each returned buffer to a typed `LedgerEntry` in order to compute the `LedgerKey`, validate Soroban limits, match and cover the read-write footprint, update resource metrics, and upsert into the typed ledger state. Later bucket output is not a re-write of the same raw `LedgerEntry` bytes: `LedgerTxn::getAllEntries` extracts typed entries, `LiveBucket::convertToBucketEntry` wraps and sorts them as `BucketEntry` lifecycle records, and `BucketOutputIterator` writes framed bucket records while hashing and preserving bucket-list metadata.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:LedgerEntryChange:95-115` — bridge-facing ledger changes store `encoded_new_value` as `LedgerEntry` XDR and document that its length feeds rent size.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:get_ledger_changes:225-272` — old and new entries are metered-serialized; the new-entry buffer is reused for rent size and returned as `encoded_new_value`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:extract_rent_changes/entry_size_for_rent:329-386` — rent computation consumes the encoded-entry size, so the host-side serialization is not merely bridge packaging under current metering semantics.
- `src/rust/src/soroban_proto_any.rs:extract_ledger_effects:261-301` — modified contract entries are forwarded as the existing encoded bytes, while TTL changes synthesize and encode new `LedgerEntry` values.
- `src/rust/src/bridge.rs:RustBuf/InvokeHostFunctionOutput:17-55` — the bridge returns owned Rust byte vectors, not typed C++ `LedgerEntry` objects or raw bucket records.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:invokeHostFunction/doApply:557-584, 993-1015` — apply calls the Rust bridge, then records storage changes before events, refundable resources, and success finalization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:recordStorageChanges:640-766` — every modified buffer is decoded to `LedgerEntry`; the decoded value is required for key derivation, footprint matching, validation, resource accounting, upsert, creation counting, and deletion detection.
- `src/ledger/LedgerTxn.cpp:LedgerTxn::Impl::getAllEntries:1695-1735` — ledger close extracts typed `LedgerEntry` and `LedgerKey` vectors from the sealed ledger transaction state.
- `src/ledger/LedgerManagerImpl.cpp:3310-3367` — the typed vectors update in-memory Soroban state, module cache, and live bucket batches in parallel.
- `src/bucket/LiveBucket.cpp:convertToBucketEntry/fresh:390-528` — live bucket ingestion sorts references by ledger identity and materializes typed `BucketEntry` records before output.
- `src/bucket/LiveBucket.cpp:mergeInMemory:613-697` — level-0 merges combine old and new typed bucket entries, build an index, and then write the merged typed records.
- `src/bucket/BucketOutputIterator.cpp:put/getBucket:76-180` — output order, tombstone elision, buffering, and SHA-256 bucket hashing are tied to `BucketEntry` writes, not standalone `LedgerEntry` payload bytes.
- `src/util/XDRStream.h:XDROutputFileStream::writeOne/writeBytes:481-515, 408-448` — bucket files write framed XDR records and hash the exact bytes written.

### Why It Failed

The claimed removable encode/decode/re-encode lap is not fully redundant on the traced apply path. The Rust encode is currently the metered canonical output and rent-size source; the C++ decode is needed to update typed ledger state and validate the footprint; and the later bucket write serializes sorted `BucketEntry` lifecycle records after ledger-state extraction and merge logic, not the same raw `LedgerEntry` bytes returned by Rust. A raw-byte design would still have to decode to typed entries or add raw representations through LedgerTxn, in-memory Soroban state, bucket sorting, bucket hashing, and bucket indexes; that is a broad storage redesign rather than the localized bridge optimization described here. The only local, clearly recoverable portion collapses to the already-summarized H010 class of C++ decode/FFI savings, which is below this objective's Medium severity threshold.

### Lesson Learned

Do not size Soroban ledger-change serialization hypotheses by summing nested Tracy zones such as `BucketOutputIterator::put`, `writeOne`, and `writeBytes`, or by treating Rust `LedgerEntry` output bytes as directly reusable bucket bytes. Bucket output depends on typed lifecycle records, ordering, metadata, hashing, and merge semantics; viable Medium-tier work needs an isolated redesign of that typed bucket pipeline, not just raw bridge payload plumbing.
