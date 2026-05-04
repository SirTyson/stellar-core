# H007: Precompute Soroban transaction PRNG sub-seeds outside worker apply

**Date**: 2026-05-04
**Subsystem**: transaction-ledger / ledger parallel Soroban apply
**Severity**: Low
**Impact**: Soroswap apply-time reduction by moving or caching per-transaction SHA-256 seed derivation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Each Soroban transaction should receive the same deterministic PRNG sub-seed derived from the ledger seed and transaction number. Computing that seed should not delay contract execution if it can be precomputed without changing deterministic ordering or observable transaction results.

## Mechanism

`LedgerManagerImpl::applyThread` computes `Hash txSubSeed = subSha256(sorobanBasePrngSeed, txBundle.getTxNum())` immediately before each transaction's `parallelApply`, and `InvokeHostFunctionApplyHelper::invokeHostFunction` then copies the 32-byte seed into a fresh `CxxBuf`. Precomputing sub-seeds during `TxBundle` construction or storing a fixed-size seed buffer in the bundle would remove repeated SHA context setup and vector allocation from worker apply.

## Trigger

Run the current soroswap benchmark and add narrow spans around `subSha256` in `LedgerManagerImpl::applyThread` and the `basePrngSeedBuf.data->assign` in `InvokeHostFunctionApplyHelper::invokeHostFunction`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2483-2511` — derives `txSubSeed` in the cluster worker loop for every transaction.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:570-584` — allocates a `std::vector<uint8_t>` and copies the 32-byte seed into `CxxBuf` for every host invocation.
- `src/transactions/ParallelApplyStage.h:74-114` — `TxBundle` could theoretically carry a precomputed fixed-size seed.

## Evidence

Timestamp filtering shows C++ `sha256` work inside `applyLedger` windows totaling **326,816,970 ns** and `add` work in `crypto/SHA.cpp` totaling **103,687,946 ns** in the current trace. The source confirms a per-transaction seed derivation in the apply worker and a per-invocation seed-buffer allocation before crossing the Rust bridge.

## Anti-Evidence

The SHA total includes other apply-window hash users, so the PRNG sub-seed subset is smaller than the aggregate. Even an unrealistically perfect removal of all in-window C++ SHA self-time normalizes to well under the 3% Medium threshold across eight parallel clusters and the full benchmark window. The vector copy is only 32 bytes per tx and is not visible as an isolated Tracy hotspot.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-04
**Failed At**: hypothesis
**Novelty**: PASS — not present in the active transaction-ledger failure summary

### Why It Failed

The seed derivation is real apply-path work, but its absolute size is too small. Moving it earlier or caching the 32-byte buffer would at best save a low-single-millisecond aggregate worker slice and far less on the critical path.

### Lesson Learned

Per-transaction hashes should be timestamp-filtered and then normalized by cluster parallelism before being treated as apply bottlenecks. Small deterministic precomputations are not Medium soroswap optimizations unless they remove a much larger repeated structure.
