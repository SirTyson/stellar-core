# H002: `addReads` always computes `xdr::xdr_size(lk)` per footprint key, but the value is only consumed on the non-soroban / pre-P23 metering path

**Date**: 2026-04-29
**Subsystem**: transaction-ledger (`InvokeHostFunctionOpFrame::addReads`)
**Severity**: Low (sub-Medium)
**Impact**: Apply-time reduction; trivial diff
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`addReads` should only compute `keySize` when it is actually consumed by
`meterDiskReadResource` (i.e. when the key is a classic entry, or when
running pre-P23). For protocol ≥ 23 the soroban footprint metering uses
in-memory state and `keySize` is dead.

## Mechanism

In `src/transactions/InvokeHostFunctionOpFrame.cpp:398`:
```cpp
uint32_t keySize = static_cast<uint32_t>(xdr::xdr_size(lk));
```
This is computed for every footprint key. The only consumer is at
line 522:
```cpp
if (!isSorobanEntry(lk) ||
    protocolVersionIsBefore(ledgerVersion,
                            PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION))
{
    if (!meterDiskReadResource(lk, keySize, entrySize)) ...
}
```
For soroswap (P23+, all-soroban footprints), `keySize` is computed
~40 000 times per measured ledger and discarded every time.

## Trigger

soroswap apply-load benchmark; trace `xdr::xdr_size<LedgerKey>` calls
inside `addReads`.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:398` — compute
  `keySize` lazily, gated on the same predicate as the metering branch.

## Evidence

- `xdr::xdr_size(LedgerKey)` walks the entire XDR structure — for
  CONTRACT_DATA keys this includes the SCVal — at ~100–200 ns per call.
- 4000 txs × ~10 keys = ~40 000 wasted calls per measured ledger
  ≈ **4–8 ms ≈ 0.6–1.3 %** of the 620 ms soroswap median.
- Trivial one-line refactor; no API surface change.

## Anti-Evidence

- Sub-Medium impact (~1 %); the objective explicitly rejects Low-tier
  hypotheses at the hypothesis stage.
- The optimization is below benchmark noise per the objective's
  SEVERITY_SCALE.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated

### Why It Failed

Projected impact is ~0.6–1.3 % of soroswap apply time, below the
objective's Medium threshold (3–10 %) and at the edge of benchmark
noise (objective rejects findings below 1 %). Per the optimize-soroswap
context, only Medium and High hypotheses are promoted to review.

### Lesson Learned

`xdr_size`/`xdr_to_opaque` per-call overhead on small XDR types
(`LedgerKey` is small) is genuinely cheap individually; even at high
call counts the cumulative cost is small relative to the per-tx
soroban host invocation budget. Only the full `xdr_to_opaque(LedgerEntry)`
serializations (~ μs each) reach Medium territory at soroswap call
counts.
