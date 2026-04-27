# H001: Stream Transaction Contents Hash Without Allocating XDR Opaque Buffers

**Date**: 2026-04-27
**Subsystem**: crypto, transactions, ledger apply
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by removing per-transaction XDR allocation/copying from transaction contents-hash computation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Computing a transaction contents hash during `closeLedger` should produce exactly the protocol-defined hash of `networkID || ENVELOPE_TYPE_TX || tx` (or the fee-bump equivalent) without changing the bytes being hashed, transaction ordering, signature semantics, metadata, or any observable ledger output. The hash should remain cached in `mContentsHash` and every caller should receive the same value as the existing `sha256(xdr::xdr_to_opaque(...))` implementation.

## Mechanism

`TransactionFrame::getContentsHash` currently materializes a temporary opaque byte vector with `xdr::xdr_to_opaque(...)` before hashing it with one-shot `sha256`. On the soroswap apply path, the current Tracy trace shows `getContentsHash` events inside `applyLedger` consuming 248,263,343 ns total over 204,725 in-scope calls, while `crypto/SHA.cpp:sha256` contributes 271,104,648 ns inside `applyLedger`. A variadic streaming XDR-SHA helper, or a specialized transaction-contents-hash helper in the crypto layer, could feed the same XDR words directly into `XDRSHA256` and avoid allocating/copying the serialized transaction preimage.

## Trigger

Run the current soroswap apply-load benchmark (`soroswap, TX=4000, T=8`) with Tracy enabled and apply a ledger containing many single-operation Soroban invoke-host-function transactions. The hot calls are reached through `TransactionFrame::commonPreApply`, `commonParallelPreApplyReadOnly`, `preParallelApply`, `apply`, and `LedgerManagerImpl::processResultAndMeta`, all of which call or propagate `getContentsHash()` during `applyLedger`.

## Target Code

- `src/transactions/TransactionFrame.cpp:133-154` - `TransactionFrame::getContentsHash` allocates an opaque XDR buffer for the contents preimage before hashing.
- `src/transactions/FeeBumpTransactionFrame.cpp:659-667` - fee-bump contents hashing uses the same allocate-then-hash pattern.
- `src/crypto/SHA.h:50-64` - `xdrSha256` already provides allocation-free XDR hashing for a single object; it could be generalized to hash the contents-hash preimage components in order.
- `src/crypto/XDRHasher.h:16-104` - streaming archiver already preserves XDR byte order and padding, so a helper built here should be deterministic.
- `src/ledger/LedgerManagerImpl.cpp:2733-2736` - result/meta generation reads each transaction contents hash while still in `applyLedger`.

## Evidence

The current accepted soroswap trace is `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`. `csvexport-release -e` reports `sha256,crypto/SHA.cpp,33` at 936,779,114 ns self-time overall, and timestamp overlap with `applyLedger` shows 123,759 in-scope `sha256` events totaling 276,789,698 ns, of which 271,104,648 ns comes from `crypto/SHA.cpp:33`. The same overlap check shows `getContentsHash` totaling 248,263,343 ns inside `applyLedger`. The source confirms that this contents hash still uses `sha256(xdr::xdr_to_opaque(...))`, unlike `getFullHash`, which already uses streaming `xdrSha256(mEnvelope)`.

## Anti-Evidence

OpenSSL one-shot `::SHA256` is fast and may outperform a naive streaming implementation that calls `SHA256_Update` for many small fields. The optimization must therefore avoid trading allocation overhead for excessive `SHA256::add` calls; a viable implementation should batch into the existing `XDRHasher` buffer or use a small stack/arena-backed preimage path and must be benchmarked repeatedly because only part of `sha256` time is from transaction contents hashing.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-27
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; the existing crypto fail record covers signature verification outside `applyLedger`, not transaction contents-hash serialization
**Failed At**: reviewer

### Trace Summary

`TransactionFrame::getContentsHash` and `FeeBumpTransactionFrame::getContentsHash` do use `sha256(xdr::xdr_to_opaque(...))` on the first uncached call, so the local mechanism exists. However, the soroswap close-ledger path receives transaction frames whose contents and full hashes are intentionally precomputed while preparing the tx set from wire XDR, before the measured apply path. The later `applyLedger` callers in fee processing, parallel pre-apply, transaction apply, and result/meta construction mainly read the cached `mContentsHash`, so streaming this contents preimage would optimize tx-set construction/validation rather than the objective's top-line apply-time metric.

### Code Paths Examined

- `src/transactions/TransactionFrame.cpp:133-154` — regular transaction contents hash allocates an opaque XDR buffer only when `mContentsHash` is zero; subsequent apply-path calls return the cached hash.
- `src/transactions/FeeBumpTransactionFrame.cpp:659-667` — fee-bump contents hash has the same cache-guarded allocate-then-hash pattern.
- `src/herder/TxSetFrame.cpp:1382-1434` — `TxSetXDRFrame::prepareForApply` builds the `ApplicableTxSetFrame` from wire XDR before ledger application.
- `src/herder/TxSetFrame.cpp:1724-1850,1923-1934` — generalized tx-set phase construction creates transaction frames and explicitly calls `tx->getContentsHash()` and `tx->getFullHash()` before sorting and before closeLedger applies the tx set.
- `src/herder/TxSetFrame.cpp:450-488,580-600` — legacy/sequential tx-set ingestion also precomputes contents and full hashes before insertion into the tx list.
- `src/ledger/LedgerManagerImpl.cpp:2813-2833,2871-2926,3028-3140` — apply setup obtains phases and later processes result/meta; these call sites use already prepared transaction frames.
- `src/transactions/ParallelApplyUtils.cpp:135-148,445-465` and `src/transactions/TransactionFrame.cpp:2146-2187,2251-2284` — parallel pre-apply calls `getContentsHash()` through wrapper paths, but after tx-set preparation has cached the value.
- `src/transactions/TransactionFrame.cpp:2752-2760` and `src/ledger/LedgerManagerImpl.cpp:2727-2736` — sequential apply and result/meta construction pass or record the cached contents hash.
- `src/crypto/SHA.h:50-64` and `src/crypto/XDRHasher.h:16-104` — streaming XDR hashing exists and would be a plausible correctness-preserving implementation for an off-path contents-hash optimization.
- `src/ledger/LedgerTypeUtils.cpp:31-37` and `src/ledger/LedgerManagerImpl.cpp:2478-2506` — frequent in-apply `sha256` events can also come from TTL-key hashing and Soroban PRNG sub-seeding, so aggregate `sha256` time cannot be attributed to transaction contents hashing without caller separation.

### Why It Failed

The optimization target is not on the measured soroswap `closeLedger` apply critical path in the way claimed. Transaction contents hashes are precomputed and cached during tx-set preparation, while the in-apply `getContentsHash()` calls mostly pay only a cache check and return-by-reference; eliminating the one-time `xdr_to_opaque` allocation would therefore not produce the required 3-10% apply-time reduction. This is below the objective severity threshold and effectively out of scope because the affected work is tx-set construction/validation rather than ledger apply.

### Lesson Learned

For cached transaction-frame helpers, distinguish accessor-zone time from first-computation time before assigning optimization impact. Crypto self-time inside `applyLedger` also needs caller attribution: in this path, `sha256` can be driven by TTL-key derivation and PRNG sub-seeds, not just transaction contents-hash computation.
