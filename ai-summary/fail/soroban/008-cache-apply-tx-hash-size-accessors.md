# H008: Cache apply-local transaction hash and size accessor results in `TxBundle`

**Date**: 2026-05-03
**Subsystem**: soroban / transactions
**Severity**: Low
**Impact**: Reduce repeated apply-path transaction-frame accessor overhead during soroswap parallel apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Parallel Soroban apply should use each transaction's full hash, contents hash, and serialized envelope size deterministically, producing the same PRNG sub-seeds, validation results, fee/resource checks, metadata, and ledger effects as the current code. If these values are cached in `TxBundle` when the apply bundle is constructed, all later uses during `applyLedger` should observe the same values returned by `TransactionFrame::getFullHash`, `TransactionFrame::getContentsHash`, and `TransactionFrame::getSize`.

## Mechanism

The current apply path keeps only a transaction pointer in `TxBundle`, so hot apply loops repeatedly call virtual/lazy accessors on `TransactionFrame`. The current Tracy trace reports in-apply overlap of about 69.0 ms for `getFullHash`, 147.7 ms for `getContentsHash`, and 28.8 ms for `getSize`; a small apply-local cache could avoid many repeated accessor calls, zero-hash checks, and `xdr_size` walks. This would deviate from the expected efficient behavior by recomputing or re-entering immutable transaction metadata many times after the transaction set has already been fixed.

## Trigger

Run the current soroswap apply-load benchmark from `ai-summary/CURRENT_STATE.md` (`soroswap, TX=2000, T=8`). The workload builds many `TxBundle`s and then repeatedly asks their `TransactionFrameBase` objects for hashes and sizes during pre-apply, parallel apply, meta/result construction, and fee/resource handling.

## Target Code

- `src/transactions/TransactionFrame.cpp:121-159` — lazy `getFullHash` and `getContentsHash` accessors still execute on every call even after the cached hash is initialized.
- `src/transactions/TransactionFrame.cpp:2827-2832` — `getSize` computes `xdr::xdr_size(mEnvelope)` on every call.
- `src/transactions/ParallelApplyStage.h:71-100` — `TxBundle` stores the transaction pointer and tx number but no immutable hash/size metadata.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520` — `applyThread` iterates `TxBundle`s in the Soroban apply critical path.

## Evidence

Using the current diagnostic trace `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`, timestamp overlap against `applyLedger` windows found `getFullHash` consuming 69,015,006 ns across 822,693 in-apply calls, `getContentsHash` consuming 147,708,026 ns across 164,725 in-apply calls, and `getSize` consuming 28,814,650 ns across 34,848 in-apply calls. The source confirms `TxBundle` does not hoist these immutable values, while `TransactionFrame::getSize` is not cached at all.

## Anti-Evidence

The already-cached hash accessors mostly avoid deep XDR hashing after the first call, so the visible self-time is dominated by accessor overhead, Tracy instrumentation, virtual dispatch, and cheap `isZero` checks. `getSize` is a real repeated XDR walk, but its total in-apply overlap is small. A `TxBundle` cache would also need API plumbing at every call site to avoid falling back to the existing accessors.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in retained soroban fail/success records

### Why It Failed

The complete upper bound is below the objective threshold. Even deleting all in-apply `getFullHash`, `getContentsHash`, and `getSize` time would save about 245.5 ms across 71 apply windows, or roughly 3.5 ms per ledger before subtracting replacement cache access and unavoidable first-computation costs. Against the current authoritative non-Tracy soroswap median of about 273 ms, that is roughly 1.3%, below the required Medium tier and mostly in the Tracy/instrumentation noise class.

### Lesson Learned

Repeated immutable transaction accessors can look large due to very high call counts, but the per-call cost is too small to matter at the current soroswap threshold. Future transaction-frame caching hypotheses should first compute an absolute per-ledger upper bound from apply-window overlap, not from full-trace counts.
