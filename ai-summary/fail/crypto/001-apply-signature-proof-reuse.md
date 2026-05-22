# H001: Protocol-Gated Apply Signature Proof Reuse

**Date**: 2026-05-21
**Subsystem**: crypto / transactions apply / signature checking
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by skipping redundant apply-window signature and contents-hash work after proving the same signer state
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Applying a Soroban transaction should accept or reject signatures exactly as it does today: the transaction contents hash, decorated signatures, source-account thresholds/signers, extra signers, operation source accounts, and `checkAllSignaturesUsed()` result must all match the ledger state used for application. A cached proof must be ignored unless it is tied to the same protocol version, contents hash, ledger sequence/state identity, source/op signer sets, thresholds, and extra-signers set; on any mismatch the code should fall back to the existing `SignatureChecker` path and produce identical `txBAD_AUTH`, `txBAD_AUTH_EXTRA`, and `opBAD_AUTH` results.

## Mechanism

The current close-ledger path constructs a fresh `SignatureChecker` during apply and replays the source and operation signature loops even though the benchmark already validated the same transaction envelopes before `applyLedger`. For Soroban invoke transactions, the expensive cryptographic result can be represented as a deterministic proof over the contents hash plus a digest of every signer set and threshold actually checked; apply can validate the signer-set digest against the loaded accounts and then reuse the precomputed weight/used-signature bitmap instead of calling `SignatureChecker::checkSignature` again. This differs from previously rejected verifySig micro-optimizations because it removes the broader apply-window signature pass, signer-vector construction, signature-loop bookkeeping, cache metrics locking, and contents-hash accessor traffic, not just a sub-operation inside `PubKeyUtils::verifySig`.

## Trigger

Run the current soroswap apply-load case from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). Each Soroban transaction enters `TransactionFrame::commonParallelPreApplyReadOnly` / `commonPreApply`, constructs a `SignatureChecker`, calls `commonValid`, then calls `processSignatures` or `processSignaturesReadOnly`; those paths call `checkAllTransactionSignatures`, `checkOperationSignatures`, `TransactionFrame::checkSignature`, and finally `SignatureChecker::checkSignature` for the same source-account credentials seen during tx-set validation.

## Target Code

- `src/transactions/TransactionFrame.cpp:1907-1944` — pre-apply validation constructs `SignatureChecker` from `getContentsHash()` and runs `commonValid` before apply.
- `src/transactions/TransactionFrame.cpp:2073-2143` — `commonPreApply` constructs a new apply-time checker, calls `commonValid`, then `processSignatures`.
- `src/transactions/TransactionFrame.cpp:2145-2247` — parallel Soroban read-only pre-apply repeats the same signature processing on worker snapshots.
- `src/transactions/TransactionFrame.cpp:499-598` — builds signer vectors and calls `SignatureChecker::checkSignature` for source, extra, and operation signatures.
- `src/transactions/SignatureChecker.cpp:23-144` — loops decorated signatures against signer buckets, calls `SignatureUtils::verify`, tracks used signatures, and updates cache metrics.
- `src/crypto/SecretKey.cpp:473` — `PubKeyUtils::verifySig`, the cryptographic cache/verify primitive reached by the apply-time signature pass.

## Evidence

The current soroswap diagnostic trace confirms these zones are inside `applyLedger`: `verifySig` totals **44.496 ms** / 82,981 calls, `checkAllTransactionSignatures` totals **35.646 ms** / 32,945 calls, `processSignatures` + `processSignaturesReadOnly` total **90.029 ms**, and `getContentsHash` totals **147.708 ms** / 164,725 calls within the 71 `applyLedger` windows. Individually, prior crypto micro-surfaces are below threshold; together, the repeated apply-window signature-validation envelope is about 318 ms of traced apply-contained work before counting signer-vector allocation and `SignatureChecker` metrics locking hidden in parent zones. A proof keyed by signer-state digest preserves determinism because every node either proves the same signer state and skips to the same boolean/used-signature result or falls back to the existing validation path.

## Anti-Evidence

Prior failures establish that optimizing only `verifySig`, BLAKE2 cache keys, contents-hash accessors, or source-account signature-weight caching is below threshold. This hypothesis is only viable if the proof covers the whole apply signature-validation envelope and if the PoC shows the affected zones are on the serial critical path rather than mostly parallel worker aggregate. It also needs strict invalidation for source/op accounts whose signer sets or thresholds differ from the prevalidated state; otherwise it would risk accepting stale signatures after earlier ledger changes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related signature/cache surfaces were previously rejected, but this exact whole-envelope proof mechanism was not recorded as an individual fail/success finding
**Failed At**: reviewer

### Trace Summary

`LedgerManagerImpl::applyLedger` prepares the tx set, charges fees/sequence numbers, then applies transactions; it does not consume any persisted signature proof from tx-set validation. In the parallel Soroban phase, `GlobalParallelApplyLedgerState::preParallelApplyAndCollectModifiedClassicEntries` calls `preParallelApplyReadOnly`, which reaches `TransactionFrame::commonParallelPreApplyReadOnly`, constructs a fresh `SignatureChecker`, runs `commonValid` for source/extra signers, then runs `processSignaturesReadOnly` for operation signatures and `checkAllSignaturesUsed()`. The repeated bookkeeping is real, but `PubKeyUtils::verifySig` already reuses the expensive cryptographic result through the sharded global verification cache, so apply-window rechecks are cache-hit signer/bitmap/account-state work rather than full Ed25519 verification.

### Code Paths Examined

- `src/ledger/LedgerManagerImpl.cpp:1462-1688` — `applyLedger` calls `prepareForApply`, `processFeesSeqNums`, and `applyTransactions`; no proof produced by tx-set validation is passed into apply.
- `src/ledger/LedgerManagerImpl.cpp:2784-3029` — parallel Soroban phases are bundled and sent through `applySorobanStages` after fee/sequence processing.
- `src/transactions/ParallelApplyUtils.cpp:134-148` and `src/transactions/ParallelApplyUtils.cpp:431-466` — read-only pre-apply executes across worker ranges, then buffered writes are committed; aggregate Tracy time in this region must be normalized by worker parallelism.
- `src/transactions/TransactionFrame.cpp:2145-2247` — `commonParallelPreApplyReadOnly` constructs `SignatureChecker`, calls `commonValid`, `processSignaturesReadOnly`, `checkOperationSignatures`, and `checkAllSignaturesUsed`.
- `src/transactions/TransactionFrame.cpp:1666-1774` and `src/transactions/TransactionFrame.cpp:573-598` — `commonValid` loads the source account and validates transaction signatures before returning `kMaybeValid`.
- `src/transactions/TransactionFrame.cpp:499-515` and `src/transactions/OperationFrame.cpp:217-260` — source/op signer vectors are rebuilt from loaded account state and passed to `SignatureChecker`.
- `src/transactions/SignatureChecker.cpp:23-144` — signer buckets are split, decorated signatures are matched, used-signature bits are recorded, and cache metrics are updated.
- `src/crypto/SecretKey.cpp:469-520` — `PubKeyUtils::verifySig` uses a sharded process-wide cache keyed by public key, signature, and message; earlier validation already primes the expensive verification result.
- `src/herder/TxSetFrame.cpp:2245-2257` and `src/herder/TxSetUtils.cpp:109-142` — tx-set validation can call `tx->checkValid`, but it only filters/validates and does not retain a signature proof for close-ledger apply.

### Why It Failed

The proposed proof would still need to load the same signer accounts and prove that every signer set, threshold, extra signer, protocol version, and contents hash matches the earlier validation state. Computing and checking that signer-state digest largely overlaps the existing small signer-vector/signature-loop work for the soroswap source-account path, while the expensive Ed25519 operation is already skipped by `verifySig` cache hits. The cited 318 ms is aggregate work over 71 ledgers and includes cache-hit `getContentsHash` accessor traffic plus read-only pre-apply worker time; with `T=8`, even an impossible full elimination of the cited aggregate surface would be far below the objective's 3-10% Medium threshold, and the realistic net after adding signer-state digest/proof plumbing is smaller. This is therefore below the optimize-soroswap severity threshold; Low/sub-1% findings are not accepted.

### Lesson Learned

For apply-path signature hypotheses, separate cryptographic verification from signer-state proof/bookkeeping and normalize worker aggregate zones by parallelism. Any future candidate must show a serial close-ledger caller outside the already-cached `verifySig` path and outside the previously documented sub-Medium signature-envelope ceiling.
