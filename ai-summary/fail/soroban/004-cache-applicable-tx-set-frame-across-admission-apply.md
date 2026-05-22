# H003: Cache ApplicableTxSetFrame Across prepareForApply Re-invocations

**Date**: 2026-05-22
**Subsystem**: soroban (apply-path orchestration)
**Severity**: Low
**Impact**: Per-ledger XDR deserialization at the head of `applyLedger`
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`prepareForApply` runs once at the top of `applyLedger` and reconstructs
an `ApplicableTxSetFrame` from the wire `TxSetXDRFrame` previously
nominated/admitted. In a benchmark like apply-load — where the same logical
tx set has already been fully constructed by the harness and where the wire
form is owned by the herder — the deserialization, frame construction, and
phase split inside `makeFromWire` is *redundant* work that the apply path
should be able to short-circuit when the herder retains an already-built
`ApplicableTxSetFrame` for the closed ledger.

## Mechanism

`TxSetXDRFrame::makeFromWire` shows Tracy self = 95ms / 144 calls = 660µs
per call, with exactly 2 calls per ledger (one per phase) inside the
benchmark's apply window — i.e. ~1.3ms per ledger purely in
deserialization, plus surrounding `prepareForApply` overhead pushing the
serial head of `applyLedger` to ~2ms/ledger. If `LedgerManagerImpl::applyLedger`
accepted an already-prepared `ApplicableTxSetFrame` (cached in the herder
or threaded through from the close-ledger boundary), this 2ms of
serial-critical-path work disappears from every ledger.

## Trigger

Any soroswap apply-load run with >0 Soroban txs per ledger. Every ledger
incurs the cost.

## Target Code

- `src/herder/TxSetFrame.cpp:makeFromWire` — 95ms self / 144 calls (Tracy)
- `src/ledger/LedgerManagerImpl.cpp:applyLedger:1484` then `prepareForApply` call
- `src/ledger/LedgerCloseData` (carrier of the wire tx set into apply)

## Evidence

- Tracy: 2 `makeFromWire` calls per ledger inside `applyLedger`.
- The benchmark already has the `ApplicableTxSetFrame` materialized at
  load-time; the wire round-trip is purely an artifact of the apply API.
- 2ms serial saving against a 230ms baseline = ~0.9% — *measurable* but
  below the Medium 3% threshold.

## Anti-Evidence

- The wire round-trip is intentional on the production path: the
  consensus value carries the wire-form XDR, and the herder reconstructs
  the applicable frame deterministically to defend against state drift.
  Bypassing this on the apply path would create a divergent code path
  guarded by "benchmark mode" — not acceptable for production code.
- An alternative ("cache the parsed frame in the herder and reuse during
  apply") changes ownership semantics of `LedgerCloseData` and is a
  cross-subsystem refactor far larger than the 2ms it would save.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — not in fail/hypothesis/reviewed/poc dirs.

### Why It Failed

The projected saving is ~0.9% of soroswap apply time — below the
objective's Medium ≥ 3% bar at the hypothesis stage, and below the Low
1% noise floor stated in the objective. Even if one accepted Low, the
required refactor (changing `LedgerCloseData` ownership of the parsed
applicable frame, or threading a cached frame from herder through
`applyLedger`'s entry point) is far from "trivially clean and low-risk"
and crosses the herder boundary — outside the scope of safe in-apply
optimization.

### Lesson Learned

The `prepareForApply` head of `applyLedger` is serial and small (~2ms)
but is already paying for an intentional consensus-defense
re-derivation. Any further reduction here requires either a
cross-subsystem ownership change (herder retains parsed frame) or a
"benchmark-only" bypass — both unacceptable. Future hypotheses should
treat the first ~2-3ms of `applyLedger` as fixed cost and target the
40+ms in `applySorobanStages` instead.
