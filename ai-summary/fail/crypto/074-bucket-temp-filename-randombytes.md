# H074: Bucket Temporary Filename Randomness Is Not a Medium Soroswap Apply Bottleneck

**Date**: 2026-05-24
**Subsystem**: crypto / bucket
**Severity**: Low
**Impact**: synchronous bucket-file setup micro-optimization below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When `closeLedger` writes live bucket output, temporary bucket filenames should be generated without adding measurable apply latency. Replacing cryptographic random filename suffixes with a deterministic per-process counter or cheaper nonce should preserve ledger output determinism, avoid filename collisions, and reduce measured `applyLedger` time only if `BucketBase::randomFileName` is a meaningful synchronous descendant of the apply window.

## Mechanism

`BucketBase::randomFileName` calls `randomBytes(8)`, hex-encodes the bytes with `binToHex`, constructs a `tmp-bucket-<hex>.xdr` path, and probes the filesystem with `std::ifstream` until it finds a free name. The candidate optimization would remove the libsodium RNG call and heap-allocating hex conversion from synchronous bucket creation. If this loop were hot in current soroswap apply, a per-process atomic counter combined with `O_EXCL`-style creation could make filename generation cheaper without changing bucket contents or hashes.

## Trigger

Run the soroswap apply-load benchmark and focus on blocking bucket output created from `applyLedger` bucket commits. The triggering path is any live bucket write that constructs a temporary output filename through `BucketBase::randomBucketName` / `randomIndexName`.

## Target Code

- `src/bucket/BucketBase.cpp:120-135` — `BucketBase::randomFileName` generates `tmp-bucket-` names via `binToHex(randomBytes(8))` and probes with `std::ifstream`.
- `src/crypto/Random.cpp:16-34` — `randomBytes` allocates a vector and calls `randombytes_buf`.
- `src/crypto/Hex.cpp:11-27` — `binToHex` allocates a vector and converts bytes to hex through libsodium.

## Evidence

The code path is real and filename generation is not consensus-visible: temporary filenames are local implementation details, while bucket file contents and bucket hashes remain unchanged. A local Tracy export from `/mnt/nvme2/tmp/tracy-test.tracy` showed `randomFileName` at `bucket/BucketBase.cpp:124` with 112.9 ms self-time, and the same trace showed the crypto helpers `randomBytes`/`binToHex` structurally inside the function. The exported soroswap profile summaries under `/mnt/nvme2/tmp/tracy*.csv` also contain `randomFileName` rows, confirming the path can appear in apply-load traces.

## Anti-Evidence

The current `ai-summary/CURRENT_STATE.md` soroswap trace path is not present on this machine, so the exact current apply-window overlap could not be re-exported. Existing available soroswap CSV exports show `randomFileName` at only about 1.1-1.9 ms total across the full run, far below the 3% Medium floor, and the large 112.9 ms `tracy-test.tracy` row appears to be a bucket-heavy diagnostic trace rather than the current soroswap baseline. Even full elimination of `randomBytes` and `binToHex` would leave filesystem probing and bucket creation work, so the removable crypto portion is only a fraction of an already sub-threshold row.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — temporary bucket filename randomness was not separately recorded in `ai-summary/fail/crypto/summary.md`

### Why It Failed

The candidate is below the optimize-soroswap severity threshold. Available soroswap exports put `BucketBase::randomFileName` around 1-2 ms for the whole run, and only the RNG plus hex-conversion slice of that row is crypto-removable. This cannot approach the roughly 6.3 ms per-ledger / 3% Medium requirement for the current 211 ms soroswap baseline.

### Lesson Learned

Crypto helpers embedded in bucket-local file naming can show up in traces, but temporary filename generation is a tiny synchronous surface on soroswap. Do not promote RNG/hex filename optimizations unless a current timestamp-filtered `applyLedger` export shows `randomFileName` at Medium-scale overlap.
