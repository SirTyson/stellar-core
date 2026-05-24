# H007: Cache `ApplicableTxSetFrame` from herder validation phase to skip `prepareForApply` rebuild inside `applyLedger`

**Date**: 2026-05-24
**Subsystem**: ledger / apply-thread entry path (TxSetXDRFrame → ApplicableTxSetFrame)
**Severity**: Low (claimed); actually below threshold
**Impact**: Skip the second `TxSetXDRFrame::prepareForApply` rebuild on the apply thread by carrying the already-validated `ApplicableTxSetFrame` from the herder validation/nomination pass into `LedgerCloseData`.
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`TxSetXDRFrame::prepareForApply` (`src/herder/TxSetFrame.cpp:1383`) is logically a
pure XDR-to-frame conversion: it validates the wire structure of a
`GeneralizedTransactionSet`, fans out `TransactionFrameBase::makeTransactionFromWire`
across `LEDGER_CLOSE_WORKER_THREADS` workers, precomputes `getContentsHash()` and
`getFullHash()` for every tx, and wraps the result in an `ApplicableTxSetFrame`.
On a healthy validator, the same `TxSetXDRFrame` has already been put through
`prepareForApply` during `HerderSCPDriver::cValidateValue`
(`src/herder/HerderSCPDriver.cpp:783` and `:1438`) for SCP validation. The apply
thread should be able to consume the cached `ApplicableTxSetFrame` instead of
rebuilding it from XDR, since the wire bytes, network ID, and previous-ledger
header are all identical to those used during validation.

## Mechanism

`LedgerCloseData` currently carries only `TxSetXDRFrameConstPtr` and the
canonical hash. When `LedgerManagerImpl::applyLedger`
(`src/ledger/LedgerManagerImpl.cpp:1581`) reaches the line
`auto applicableTxSet = txSet->prepareForApply(mApp, prevHeader);`, the whole
TxFrame creation + hash precomputation pipeline runs again. Tracy attributes
`prepareForApply` 115.8 ms of total time over 216 calls (`herder/TxSetFrame.cpp:1393`).
71 of those calls are the in-apply rebuilds (one per benchmark ledger); the
remaining 145 calls cover nomination and validation. If the herder cached the
validated `ApplicableTxSetFrame` keyed by `(TxSetXDRFrame.hash,
previousLedgerHash)` and exposed it through `LedgerCloseData::getTxSet`, the
apply thread could call `txSet->getCachedApplicableForLedger(prevHeader)` and
elide the rebuild entirely.

## Trigger

`scripts/run_apply_load_matrix.py` soroswap TX=2000 T=8. Each ledger applies a
TxSet that was previously prepared during the (test harness) validation pass,
yet `applyLedger` still rebuilds the `ApplicableTxSetFrame` from wire on the
apply thread.

## Target Code

- `src/herder/TxSetFrame.cpp:1383-1435` — `TxSetXDRFrame::prepareForApply`,
  serial entry that fans out parallel `makeTransactionFromWire`.
- `src/herder/TxSetFrame.cpp:1724-1900` — `TxSetPhaseFrame::makeFromWire` and
  the parallel `createTx` worker that does `XDRProvidesValidFee` +
  `getContentsHash()` + `getFullHash()` per tx.
- `src/ledger/LedgerManagerImpl.cpp:1581` —
  in-apply `txSet->prepareForApply(mApp, prevHeader)` call.
- `src/herder/HerderSCPDriver.cpp:783, :1438` — earlier `prepareForApply` calls
  during validation/nomination whose output is discarded.
- `src/ledger/LedgerCloseData.h` — wire object passed to the apply thread; would
  need a non-owning pointer/shared_ptr to the validated frame.

## Evidence

- Tracy total time for `prepareForApply` is 115.8 ms across 216 calls (1.13% of
  the 4475 ms `applyLedger` aggregate); the in-apply calls account for at most
  the per-ledger fraction (~0.53 ms/ledger on the median path with 8-way TxFrame
  parallelism).
- `prepareForApply` is pure CPU work on the wire bytes; nothing in its result
  depends on apply-thread mutations (it only reads `lclHeader` and `networkID`).
- The herder already runs the same code during SCP value validation, so the
  *first* call always succeeds and produces an equivalent frame to the second.
- The cache key would be the existing `TxSetXDRFrame::getContentsHash()` plus
  `previousLedgerHash`, both already available on both call sites without
  additional work.

## Anti-Evidence

- `prepareForApply` performs structural XDR validation that the apply thread
  must not skip on a freshly-received TxSet: catchup, ad-hoc applies, and
  startup paths reach `applyLedger` without a prior validation pass; a cache
  miss must fall through to the existing rebuild.
- The `ApplicableTxSetFrame` includes `TransactionFrameBasePtr`s whose lifetime
  must outlive both validation and apply; sharing the frame requires
  copying/refcounting the inner tx-frame vectors, which themselves carry the
  hot `mContentsHashCached`/`mFullHashCached` fields. Sharing across threads is
  safe only because those caches are populated synchronously by validation
  before apply begins.
- `BUILD_TESTS` apply-load templates also exercise `mApplicableTxSetOverride`
  (`TxSetFrame.cpp:1386`) which short-circuits `prepareForApply`. The benchmark
  may already partially deduplicate by that path on the SCP nomination side,
  reducing the addressable serial fraction further.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — no prior fail/hypothesis/reviewed/poc entry covers the
herder→apply ApplicableTxSetFrame handoff; closest entry (fail
`002-validated-txset-apply-certificate.md`) targeted skipping `commonValid`
checks, not the prepareForApply XDR rebuild itself.

### Why It Failed

Quantified ceiling is below the 3% Medium floor for this objective. Tracy
total for `prepareForApply` is 115.8 ms across 216 calls, of which the 71
in-apply calls amount to ~38 ms (≈0.85% of the 4475 ms aggregate `applyLedger`
window, or ~0.25% of the 218 ms apply-load median per ledger). Even with a
perfect zero-cost cache hit on every benchmark ledger, the saving is bounded
to roughly 535 µs/ledger — far below the 3% (≈6.5 ms) Medium threshold and
below the 1% Low floor. The cache handoff also introduces lifetime/threading
complexity (sharing `TransactionFrameBasePtr`s built on a validation thread
with the apply thread) without a way to clear the Medium floor.

### Lesson Learned

`prepareForApply` is a measurable but small slice of `applyLedger` (~0.85%);
its sub-millisecond per-ledger cost cannot be promoted to Medium even with a
perfect cache hit. Future apply-thread caching hypotheses targeting wire-to-frame
conversion paths must quantify the in-`applyLedger` fraction (filtered to the
71 in-apply calls, not the 216-call aggregate) before drafting, and must clear
the 3% Medium floor before promotion. Cross-thread frame sharing also incurs
lifetime overhead that competes with the small in-apply savings.
