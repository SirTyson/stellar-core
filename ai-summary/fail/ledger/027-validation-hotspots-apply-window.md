# H027: Apply-path signature validation aggregate hotspots

**Date**: 2026-05-24
**Subsystem**: ledger
**Severity**: Low
**Impact**: Apparent validation CPU hotspot in aggregate Tracy profile
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

If `commonValidPreSeqNum` and signature verification were a Medium-tier soroswap apply bottleneck, the majority of their Tracy time should occur inside measured `applyLedger` windows and removing redundant validation should recover at least 3% of soroswap apply time.

## Mechanism

The aggregate trace makes `commonValidPreSeqNum` and `verifySig` look dominant, but aggregate process totals mix TX-set construction and apply. Timeline filtering against `applyLedger` windows shows only a small in-scope fraction remains.

## Trigger

Run `csvexport-release -u` for `applyLedger`, `commonValidPreSeqNum`, and `verifySig`, then count target events whose start timestamp falls inside an `applyLedger` window.

## Target Code

- `src/transactions/TransactionFrame.cpp:1318-1355` — `commonValidPreSeqNum` validation zone.
- `src/crypto/SecretKey.cpp:473` — `verifySig` aggregate hotspot from transaction validation.
- `src/ledger/LedgerManagerImpl.cpp:2302-2441` — fee/sequence processing path that calls per-transaction validation during apply.

## Evidence

Aggregate self-time from the current soroswap trace reported `commonValidPreSeqNum` at 7.082 s and `verifySig` at 5.384 s, both high enough to attract attention. The apply flow does call validation while processing fees and sequence numbers.

## Anti-Evidence

Timeline filtering shows `commonValidPreSeqNum` has only 34,945 in-apply events totaling 58.150 ms, and `verifySig` has 86,981 in-apply events totaling 46.364 ms. Even ideal elimination is well below the 3% Medium floor once mandatory fee/state checks and existing signature-cache behavior are considered.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: DUPLICATE-ADJACENT — consistent with existing validation-hotspot failures, but rechecked against the current trace

### Why It Failed

The hot-looking validation zones are mostly outside measured `applyLedger`; the current in-apply fraction is too small for this objective.

### Lesson Learned

Always timeline-filter validation zones against `applyLedger` before estimating soroswap apply impact from aggregate Tracy totals.
