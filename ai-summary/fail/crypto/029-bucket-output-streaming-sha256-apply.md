# H029: Bucket Output Iterator Streaming SHA256 on Apply-Path Level-0 Bucket Writes

**Date**: 2026-05-04
**Subsystem**: crypto
**Severity**: Low
**Impact**: apply-time reduction
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

When `closeLedger` calls `BucketManager::addLiveBatch` (apply-path
synchronous step), it builds a brand-new "level 0 curr" bucket file from
the just-applied `initEntries`/`liveEntries`/`deadEntries` for the ledger.
This goes through `BucketOutputIterator<LiveBucket>::put` then
`getBucket()`, which writes each entry via
`mOut.writeOne(*mBuf, &mHasher, &mBytesPut)` and finalizes a SHA256 over
the entire bucket file via `mHasher.finish()` at
`src/bucket/BucketOutputIterator.cpp:153,177,196`. The expected behavior
is that the SHA256 streaming work (one streaming `crypto_hash_sha256_*`
update per entry plus a final finalize) per ledger is small relative to
apply time and does not represent an exploitable optimization surface.

## Mechanism

The streaming SHA256 over the level-0 bucket runs synchronously inside
`addLiveBatch` (called from `LedgerManagerImpl::ledgerClosed` at
`src/ledger/LedgerManagerImpl.cpp:3356`), so it is on the soroswap apply
critical path. Soroswap writes thousands of entries per ledger, so the
hypothesis was that aggregate per-entry `SHA256_Update` calls plus the
final `mHasher.finish()` could be a meaningful slice of apply time and
that switching to a parallel/precomputed-incremental scheme could remove
it. Self-rejected: this work is bounded by Meta-Pattern 1 (the entire
in-apply SHA256 budget for soroswap is ~4.17 ms per ledger ≈ 0.67% of
apply), and the BucketOutputIterator share is only one of many callers
within that ceiling, so its individual slice is well under the 1% Low
floor and an order of magnitude below the 3% Medium floor.

## Trigger

Apply soroswap ledgers (TX=2000, T=8). Each `closeLedger` synchronously
constructs a new level-0 LiveBucket and a new HotArchive level-0 bucket
via `BucketOutputIterator`, both of which feed every output entry through
`mHasher.add(...)` and then call `mHasher.finish()`.

## Target Code

- `src/bucket/BucketOutputIterator.cpp:140-200` — `put`/`getBucket`
  streaming hash on every emitted entry plus final `mHasher.finish()`
- `src/bucket/BucketManager.cpp:1026-1070` — `addLiveBatch` /
  `addHotArchiveBatch` apply-path entry points
- `src/ledger/LedgerManagerImpl.cpp:3356` — `addLiveBatch` call from
  ledger close

## Evidence

- The path is reachable from `applyLedger`'s descendant
  `ledgerClosed`/`addLiveBatch`, so it is in scope (not a background
  merge).
- Soroswap writes a non-trivial number of entries per ledger, so the
  per-update SHA256 work scales with write volume.

## Anti-Evidence

- Meta-Pattern 1 caps total in-apply SHA256 work at ~4.17 ms / ledger
  (~0.67% of the 272 ms soroswap apply median). The bucket-output share
  is a fraction of that ceiling.
- `crypto_hash_sha256_update` is a tightly-vectorized libsodium
  primitive; per-byte cost on hot CPU is ~0.5–1 cycle, so even thousands
  of entries × hundreds of bytes hash in well under a millisecond.
- The non-Tracy SHA256 share is structurally bounded (Meta-Pattern 7
  confirms Tracy `add`-zone self-times are inflated by ZoneScoped
  overhead, not real work).

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — the BucketOutputIterator apply-path SHA256 streaming
hash is not the target of any prior failed hypothesis (H012/H023/H026
covered SHA256 class form / init-final / context pooling generally;
H020 covered LedgerHeader hash; H015 covered txResultSet bulk SHA256;
H003/H004 covered TTL key SHA256; this entry covers the bucket-file
hash specifically).

### Why It Failed

Below objective severity threshold. The total in-apply SHA256 budget
for soroswap is ~0.67% of apply time (Meta-Pattern 1). The
BucketOutputIterator streaming hash is only one of the SHA256 callers
inside that ceiling, so its share is structurally sub-1% and far below
the 3% Medium floor required by the optimize-soroswap objective.

### Lesson Learned

Apply-path bucket-output SHA256 is in scope (synchronous, not a
background merge) but is bounded by the Meta-Pattern 1 SHA256 budget
ceiling. Any hypothesis that targets a single SHA256 caller within the
in-apply budget is structurally below the 1% Low floor and cannot be
promoted at the hypothesis stage for this objective.
