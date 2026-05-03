# H012: Hoist `getTTLKey(rwKeys[j])` out of `recordStorageChanges` inner loop

**Date**: 2026-05-03
**Subsystem**: ledger / Soroban host invocation post-processing
**Severity**: Low
**Impact**: 1–2% apply-time reduction (below Medium threshold)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`InvokeHostFunctionOpFrame::recordStorageChanges` should detect which read-write
footprint slot each modified output entry corresponds to in O(N) per output
entry, computing each rwKey's TTL key at most once per transaction. The TTL
key derivation is a pure function of the rwKey (see
`src/ledger/LedgerTypeUtils.cpp:31-38`: `xdr_to_opaque(e)` followed by
`sha256(...)`), so it does not need to be recomputed for every output entry
that happens to be a TTL.

## Mechanism

The inner loop at `src/transactions/InvokeHostFunctionOpFrame.cpp:672-695` is
O(rwKeys × out.modified_ledger_entries). When the current output entry `lk`
has type `TTL`, the `else if` branch evaluates
`getTTLKey(rwKeys[j])` (XDR-encode + SHA256) for every j the loop visits
before the early `break`. Each call costs ~1.4 µs (matching the trace's
average `sha256` self-time). Hoisting a precomputed
`std::array<LedgerKey, N>` (or small flat map) of `getTTLKey(rwKeys[j])`
above the outer loop replaces the O(N²) recomputation with O(N) work per tx.

## Trigger

Run `apply-load --mode soroswap-tps`. Every Soroban output entry stream
contains `(modified data, modified TTL)` pairs, so the `else if` branch fires
for every TTL output entry against every Soroban rwKey not yet matched.

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-741` —
  `recordStorageChanges` body, inner loop and `getTTLKey(rwKeys[j])` call.
- `src/ledger/LedgerTypeUtils.cpp:30-38` — `getTTLKey` impl
  (`xdr_to_opaque` + `sha256`).

## Evidence

- Trace `9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`:
  `recordStorageChanges` total 98 M ns / 6776 calls (~14 µs/tx).
- `sha256` self-time 647 M ns / 451 808 calls (~1.4 µs each).
- Soroswap typical RW footprint ≈ 5–8 Soroban entries; each invoke produces
  ~5–8 output entries with roughly half being TTLs.

## Anti-Evidence

- The inner loop early-breaks once both `matchedRwKey` and `relatedRwKey`
  are populated, so the average iteration count is well below `rwKeys.size()`.
- Quantification: per-tx upper bound ≈ (TTL outputs ≈ 5) × (Soroban rwKeys
  ≈ 5) × 1.4 µs = 35 µs / tx. Across 6776 txs this is ≈ 237 M ns ≈ **2.3 %
  of total trace**, and only a fraction of that is inside `applyLedger`'s
  worker portion. The realistic apply-time delta is ~1–2 %, below the
  Medium tier (3–10 %) accepted by this objective.
- The fail summary's meta-rule for TTL-key SHA256 (entry 011) explicitly
  warns that single-site TTL-key caches do not reach Medium floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — different call site than 011
  (`recordStorageChanges` rather than the addReads / GlobalParApply RO
  pre-load path), but the projected impact is below the objective's Medium
  severity floor.

### Why It Failed

The inner loop's worst-case O(N²) `getTTLKey` work is real but small in
absolute terms. With Soroswap's modest footprint sizes the projected savings
are 1–2 % of total trace, well below the Medium tier (3–10 % apply-time
reduction) required by `optimize-soroswap`. The fix would be a clean diff
but cannot meet the severity bar on its own.

### Lesson Learned

Per fail-summary entry 011, single-site optimizations of `getTTLKey` SHA256
cost cannot reach Medium. Future TTL-key-caching hypotheses must either
(a) consolidate the savings across all apply-path call sites by caching
the TTL key on a longer-lived structure (e.g. `TransactionFrame`'s parsed
footprint), AND (b) carry a quantified end-to-end delta that demonstrates
the consolidated savings exceed 3 % of `applyLedger`. Localized
loop-hoisting is too small alone.
