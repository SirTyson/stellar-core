# H001: Stream TTL-Key Hashing Instead of Allocating XDR Buffers

**Date**: 2026-05-26
**Subsystem**: transactions / ledger
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction if the current C++ `sha256` hotspot is dominated by TTL-key derivation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Every TTL `LedgerKey` produced for a `CONTRACT_DATA` or `CONTRACT_CODE` key should have exactly the same `keyHash` as today. Soroban apply should preserve ledger output, BucketList contents, TTL bump semantics, archive/restore behavior, fees, refunds, result hashes, and determinism; only the physical hashing path should avoid allocating an intermediate XDR byte vector.

## Mechanism

`getTTLKey(LedgerKey const&)` currently computes `k.ttl().keyHash = sha256(xdr::xdr_to_opaque(e))`, which serializes the ledger key into a temporary buffer and then calls the one-shot SHA helper. The codebase already has `xdrSha256`, which streams XDR directly into an incremental SHA state without materializing the opaque vector. In the current soroswap trace, timestamp-filtered descendants of `applyLedger` contain 390,595 C++ `sha256` events at `crypto/SHA.cpp:33`, with 305,814,244 ns inside apply windows; replacing the TTL-key path with `xdrSha256(e)` should remove the temporary XDR allocation/copy and a large fraction of one-shot SHA wrapper overhead for the many TTL derivations in Soroban apply.

Unlike prior TTL-key memoization hypotheses, this does not add caches, lookup overhead, or rollback-invalidated state. It is a local implementation substitution that should be byte-equivalent and deterministic: `xdrSha256(e)` is documented as equivalent to `sha256(xdr_to_opaque(e))`.

## Trigger

Run the current soroswap apply-load trace with 2000 TX / T=8. The triggering workload repeatedly derives TTL keys while loading Soroban footprints, flushing read-only TTL bumps, recording storage changes, committing thread/global state, and finalizing in-memory/bucket state. Every live contract-data/code key that needs its TTL key currently takes the allocating one-shot path.

## Target Code

- `src/ledger/LedgerTypeUtils.cpp:30-37` — `getTTLKey(LedgerKey const&)`; replace `sha256(xdr::xdr_to_opaque(e))` with `xdrSha256(e)` or an equivalent streaming helper.
- `src/crypto/SHA.h:39-64` — existing `XDRSHA256` / `xdrSha256` helper that already avoids temporary XDR buffers.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:395-533` — `addReads` calls `getTTLKey` while preparing Soroban footprint entries.
- `src/transactions/ParallelApplyUtils.cpp:1003-1064` and `src/transactions/ParallelApplyUtils.cpp:1164-1190` — read-only TTL bump flushing and successful-tx commit paths derive TTL keys during parallel apply.

## Evidence

`ai-summary/CURRENT_STATE.md` records the active soroswap trace. A timestamp-filtered unwrap against `applyLedger` measured C++ `sha256` at `crypto/SHA.cpp:33` with 390,595 calls and 305,814,244 ns inside apply windows. Source inspection shows `getTTLKey` is a high-fanout apply helper and uses the allocating `sha256(xdr::xdr_to_opaque(e))` pattern even though the repository already provides `xdrSha256` specifically to avoid the temporary buffer.

The change is surgically testable: for representative `CONTRACT_DATA` and `CONTRACT_CODE` keys, assert that old and new `getTTLKey` hashes match bit-for-bit, then run the soroswap matrix to determine whether enough of the SHA hotspot was attributable to TTL-key derivation to clear the Medium threshold.

## Anti-Evidence

Prior TTL-key memoization probes found individual `getTTLKey` call sites below threshold after T=8 normalization, so this hypothesis depends on the current trace's large C++ `sha256` population being more concentrated in the allocating TTL helper than those earlier projections assumed. If the 305 ms C++ one-shot SHA total is mostly transaction hashing, setup, bucket hashing, or other non-TTL callers, this will fall below the objective floor. The PoC must isolate `getTTLKey` call counts or add temporary sub-zones before claiming a benchmark win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate/subset of `ai-summary/fail/transactions/summary.md` entries `009-memoize-getttlkey-across-apply-phase.md` and `002-footprint-apply-key-cache.md`
**Failed At**: reviewer

### Trace Summary

`closeLedger` reaches this helper through `LedgerManagerImpl::applyTransactions`, `applyParallelPhase`, `applySorobanStages`, `applySorobanStage`, and worker-side `applyThread`, which calls `TransactionFrame::parallelApply`, `OperationFrame::parallelApply`, and `InvokeHostFunctionOpFrame::doParallelApply`. The claimed allocation exists: `getTTLKey(LedgerKey const&)` builds a TTL key by hashing `xdr::xdr_to_opaque(e)`, while `xdrSha256` is documented and tested as byte-equivalent streaming XDR hashing. However, prior transaction reviews already surveyed the apply-path `getTTLKey` SHA256 class across cluster setup, `addReads`, `recordStorageChanges`, commit, and RO TTL bump sites and bounded even full memoization of those hashes at about 0.6% of apply time, below the objective's Medium floor. Streaming can only remove the temporary XDR buffer/copy portion of that already sub-threshold work, not the required XDR traversal or SHA digest itself.

### Code Paths Examined

- `src/ledger/LedgerTypeUtils.cpp:24-38` — `getTTLKey(LedgerEntry const&)` forwards to `getTTLKey(LedgerKey const&)`; the latter asserts `CONTRACT_CODE`/`CONTRACT_DATA` and sets `k.ttl().keyHash = sha256(xdr::xdr_to_opaque(e))`.
- `src/crypto/SHA.h:39-64` — `XDRSHA256` streams archived XDR bytes through `SHA256::add`; `xdrSha256(t)` avoids the opaque vector but still performs XDR archive traversal and SHA finalization.
- `src/crypto/test/CryptoTests.cpp:112-120` — existing test verifies `sha256(xdr::xdr_to_opaque(entry)) == xdrSha256(entry)` for generated ledger entries, supporting correctness of the substitution.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:386-533` — `addReads` derives a TTL key once per Soroban footprint key before loading/checking TTL and entry state.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-767` — `recordStorageChanges` may recompute TTL keys while matching TTL outputs to RW footprint keys and when deleting associated TTL entries.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1120-1184` — auto-restore path derives the TTL key before writing restored live/hot-archive TTL state.
- `src/transactions/ParallelApplyUtils.cpp:104-131,238-251,650-714,970-1038,1164-1250` — parallel apply derives TTL keys while building stage RW sets, building RO TTL sets, preloading read-only entries, collecting cluster entries, flushing RO TTL bumps, and committing successful transaction changes.
- `src/ledger/LedgerManagerImpl.cpp:2530-2670,2673-3030` — Soroban stages are applied with per-cluster worker threads and then committed back to the global state, so worker-side `getTTLKey` totals must be normalized by T=8 / cluster critical path rather than summed as serial apply time.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` and `src/transactions/TransactionFrame.cpp:2385-2454` — worker `applyThread` flushes RO TTL bumps, calls `TransactionFrame::parallelApply`, and commits successful transaction changes, covering the hot worker-side call sites in the hypothesis.
- `ai-summary/fail/transactions/summary.md:77-82,112,147` — prior records explicitly bound addReads micro-costs, recordStorageChanges `getTTLKey` work, all-site `getTTLKey` memoization, and footprint apply-key caching below Medium.

### Why It Failed

This is substantially covered by the prior getTTLKey/footprint-key failure records. The broadest prior version, memoizing `getTTLKey` across all apply call sites, was already estimated at about 0.6% of apply time even before lookup overhead; replacing the internal hash input path with `xdrSha256` is a strict subset because it preserves each call and removes only the temporary opaque allocation/copy. The cited 305 ms `sha256` total is an all-caller Tracy aggregate that includes transaction hashing, result hashing, bucket/hash work, and other non-TTL callers, and worker-side events cannot be treated as serial critical-path savings.

### Lesson Learned

Do not promote a single implementation variant under a helper after a broader all-call-site helper survey has already bounded the whole class below threshold. For TTL-key optimizations, first isolate `getTTLKey`-specific self time inside apply windows and divide worker totals by T=8; if eliminating the entire helper class is sub-Medium, replacing only `xdr_to_opaque` allocation with streaming XDR hashing cannot satisfy the optimize-soroswap objective.
