# H078: Contract Bytes-to-SHA256 Pipeline Is Below the Medium Floor

**Date**: 2026-05-25
**Subsystem**: crypto / rust
**Severity**: Low
**Impact**: Soroswap contract byte-construction plus SHA256 syscall optimization below objective threshold
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When soroswap contracts build byte preimages and hash them during `applyLedger`, the host should preserve exact guest-visible byte values, SHA256 results, metering charges, error behavior, and deterministic host-object allocation order. A viable optimization would replace the guest-level `serialize_to_bytes` + `bytes_append` + `compute_hash_sha256` chain with an equivalent fused path only if the apply-contained chain contributed at least Medium-tier wall-clock apply time.

## Mechanism

The soroswap trace contains apply-overlapping host syscall zones for `serialize_to_bytes`, `bytes_append`, and `compute_hash_sha256`. A tempting protocol-gated optimization would add a fused helper for common contract-ID/preimage construction so the host can serialize pieces once, append into a single scratch buffer, hash it, and return the same bytes/hash objects while preserving all `ValSer`, allocation, and SHA256 budget charges. The actual deviation from expected Medium impact is that these zones run inside `applySorobanStageClustersInParallel`; their aggregate worker self-time must be normalized by the 8 configured clusters, leaving a sub-threshold wall-clock surface.

## Trigger

Run the current accepted soroswap apply-load Tracy trace from `ai-summary/CURRENT_STATE.md` and timestamp-filter these zones against `applyLedger` windows:

- `serialize_to_bytes`
- `bytes_append`
- `compute_hash_sha256`
- the underlying `sha256` / `hash xdr` zones

The current trace shows apply-overlapping aggregate worker time around 176.9 ms for `serialize_to_bytes`, 158.1 ms for `bytes_append`, 101.0 ms for `compute_hash_sha256`, 29.0 ms for the Rust host `sha256`, and 48.5 ms for `hash xdr`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2698-2707` — `serialize_to_bytes` converts a `Val` to `ScVal`, writes XDR into a fresh `Vec<u8>`, and stores a new `ScBytes` host object.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3057-3075` — `bytes_append` allocates a combined `Vec`, copies both byte slices, and stores the result.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3119-3126` — `compute_hash_sha256` hashes a `BytesObject` and returns the digest as a new `ScBytes`.
- `src/rust/soroban/p26/soroban-env-host/src/crypto/mod.rs:410-428` — `sha256_hash_from_bytes_raw` charges `ComputeSha256Hash` and hashes the byte slice.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-100` — `metered_write_xdr` performs the metered XDR write used by serialization and hash-preimage construction.

## Evidence

The code path is real and apply-overlapping in the accepted diagnostic trace. The three guest-visible syscall zones together look large if summed as raw worker self-time, and the source shows a concrete sequence of allocation/copy/serialization/hash steps that a specialized host helper could theoretically collapse for the common soroswap byte-preimage pattern.

## Anti-Evidence

The aggregate worker-time total is not wall-clock apply impact. Dividing the optimistic 436 ms syscall subtotal by `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS = 8` gives roughly 54.5 ms over 71 ledgers, or about 0.77 ms per ledger. Even adding the underlying `sha256` and `hash xdr` rows and assuming impossible full elimination remains below the 3% Medium floor for the 207.6 ms non-Tracy soroswap baseline. Correctness also requires preserving budget charges and output host objects, so realistic removable work is only a fraction of the raw subtotal.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — prior records covered SHA256 syscall dispatch alone, host `get_contract_id` memoization, and typed bridge/XDR surfaces; this record covers the combined guest bytes-construction plus SHA256 syscall chain.

### Why It Failed

The candidate is below the optimize-soroswap Medium severity threshold after mandatory 8-way parallel-worker normalization. The chain is also not fully removable because byte serialization, host-object returns, and metering must remain guest-visible and deterministic.

### Lesson Learned

For in-host syscall sequences, do not sum aggregate worker self-time as wall-clock apply savings. Normalize by `NUM_CLUSTERS` first, then subtract the semantic work that must remain for guest-visible bytes, hashes, host objects, and budget charges.
