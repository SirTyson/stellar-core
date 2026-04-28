# H010: Cache stateless commonValidPreSeqNum results on TransactionFrame

**Date**: 2026-04-28
**Subsystem**: transactions
**Severity**: Low
**Impact**: redundant per-tx validation work during apply
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The portions of `TransactionFrame::commonValidPreSeqNum` that depend only
on the immutable transaction envelope (envelope-type checks, extra-signers
malformed checks, `validateSorobanOpsConsistency`, `validateSorobanMemo`,
`checkSorobanResources` against immutable resource declarations, footprint
duplicate-key check) should be computed at most once per tx — ideally at
construction time — and reused across the multiple validation calls a tx
sees during a single ledger close.

## Mechanism

`commonValidPreSeqNum` is invoked during apply at three sites in
`TransactionFrame::apply` / `applySorobanRO` (lines 1940, 2121, 2185 of
`src/transactions/TransactionFrame.cpp`). Each call rebuilds a transient
`UnorderedSet<LedgerKey>` to dedupe the RO/RW footprint
(`TransactionFrame.cpp:1461-1489`), re-walks all extra-signers, re-checks
all envelope-type and protocol-version preconditions, and re-runs
`checkSorobanResources` against the same immutable resource declaration.
None of this work depends on ledger state — it is a pure function of the
immutable `TransactionEnvelope`. Caching the dedup result (or a single
"stateless validation passed" boolean) on the `TransactionFrame` would
make the second and third calls degenerate.

## Trigger

Soroswap invoke-host-function txs go through three apply-time validation
calls (commonValid wraps commonValidPreSeqNum): outer apply, inner
LedgerTxn validation, and Soroban readonly pre-apply. For 4000 tx/ledger
× 65 ledgers × 3 calls × ~30-key footprints, the dedup set is
constructed and populated ~23 M times.

## Target Code

- `src/transactions/TransactionFrame.cpp:1319-1490` — body of
  `commonValidPreSeqNum`, particularly the footprint-dedup
  `UnorderedSet<LedgerKey>` at lines 1461-1489.
- `src/transactions/TransactionFrame.cpp:1666-1750` — `commonValid`
  callers passing through to `commonValidPreSeqNum`.
- `src/transactions/TransactionFrame.cpp:1940,2121,2185` — three
  apply-path call sites.
- `src/transactions/TransactionFrame.h` — would need an
  `mStatelessValidationCached` member (and protocol-version-keyed
  cache, since the version check depends on ledger header).

## Evidence

- Tracy `commonValidPreSeqNum` self-time is 3.39 s in the soroswap
  trace, but most of that is from TX-set construction (out of scope).
  The apply-path portion is ~1.2-1.5 s estimated from per-call counts
  during apply windows.
- Footprint dedup allocates an `UnorderedSet` and inserts every
  `LedgerKey` (each requiring an XDR-walking `std::hash<LedgerKey>`).
  For ~30-key footprints, this is meaningful per-call CPU.
- The result is purely a function of the immutable envelope contents
  (after the protocol-version gating step succeeds), so caching is
  semantically sound.

## Anti-Evidence

- Apply-path savings ≈ 1.2-1.5 s CPU spread across 8 worker threads
  ≈ 150-180 ms wall ≈ 0.4-0.5 % of 38.7 s benchmark.
- The stateless-vs-stateful boundary inside `commonValidPreSeqNum` is
  genuinely subtle — protocol-version checks, the
  `validateResourceFee = chargeFee` gate (proto 23+), and the
  `chargeFee`-conditional `sorobanData.resourceFee > getFullFee()`
  check make a clean cache key non-trivial. Mistakes risk skipping a
  stateful check or caching a result against the wrong protocol
  version.
- A correct cache must also be invalidated/keyed by the
  `MutableTransactionResultBase` outcome since the function writes
  `txResult.setInnermostError(...)` on failure paths.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-28
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Below objective severity threshold. The dedup and stateless-precondition
work is real but unit cost is small (microseconds per call), and
projected wall-time savings (≈ 0.5 %) sit deep inside benchmark noise.
The risk of subtly skipping a stateful check (protocol-version drift,
chargeFee conditional, or txResult error-path semantics) is
disproportionate to the win.

### Lesson Learned

`commonValidPreSeqNum` is a deceptively attractive cache target because
of its high Tracy self-time, but most of that time accrues during
TX-set construction (out of scope for this objective). When evaluating
"validation called many times" optimizations against the apply
benchmark, restrict the per-call count to apply-path call sites only
and verify against `applyLedger`-descendant zone times before judging
impact. Multi-percent wins at the validation layer require attacking
the dominant per-call work (signature checking, footprint loading)
rather than precondition gating.
