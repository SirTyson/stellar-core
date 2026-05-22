# H003: Hoist Per-Tx TTL-Key SHA256 Computation to Stage-Level Footprint Cache

**Date**: 2026-05-22
**Subsystem**: ledger, transactions
**Severity**: Medium
**Impact**: Apply-time CPU (SHA256 hashing of TTL keys)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

A `getTTLKey(LedgerKey)` computation is a SHA256 over the entry key's XDR
encoding. For a single Soroban transaction, the same RW footprint keys are
hashed via `getTTLKey` repeatedly across multiple apply-path call sites:
in `addReads` to build the RW liveness map, in `recordStorageChanges`
nested matching of host-output TTL entries to RW slots, in
`flushRoTTLBumpsInTxWriteFootprint`, in
`collectClusterFootprintEntriesFromGlobal`, and indirectly in
`getReadWriteKeysForStage`. The expected behavior is that the TTL key for
each footprint slot is computed **once per stage** (when the stage's RW
footprint union is built) and cached in the same `TxBundle` or
`ApplyStage`-level structure that already holds the footprint, so all
downstream consumers can look up the precomputed key by index instead of
re-hashing.

## Mechanism

The Soroban TTL-key derivation pattern (SHA256 of the wrapped XDR-encoded
`LedgerKey`) currently fires at multiple sites per (tx, RW-slot) pair
during a single apply. For soroswap (RW footprint typically 3–5 keys per
tx, with TTL companions for most of them), the redundant hashing adds up
to thousands of SHA256 invocations per ledger. A stage-level cache
populated once at footprint-build time would amortize the cost over
all downstream uses with zero correctness change.

## Trigger

Soroswap workload: 7467 txs / 71 ledgers ≈ 105 txs/ledger; ~3–5 RW
footprint keys per tx with ~2–3 TTL companions ≈ 300–500 TTL-key
SHA256s/ledger (across worker threads).

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:386` — `addReads` calls
  `getTTLKey` per RO/RW entry
- `src/transactions/InvokeHostFunctionOpFrame.cpp:641` — `recordStorageChanges`
  nested loop: for each host-output TTL entry, scans `rwKeys[]` computing
  `getTTLKey(rwKeys[j])` until match
- `src/transactions/ParallelApplyUtils.cpp:105` — `getReadWriteKeysForStage`
  builds stage RW union (the natural place to precompute TTL keys)
- `src/transactions/ParallelApplyUtils.cpp:1004` —
  `flushRoTTLBumpsInTxWriteFootprint`
- `src/transactions/ParallelApplyUtils.cpp:925` —
  `collectClusterFootprintEntriesFromGlobal`

## Evidence

- `getTTLKey` is SHA256-backed (per `crypto/SHA.h` and `LedgerHashUtils.h`
  usage in TTL key derivation).
- Tracy: `parallelApply` worker aggregate self-time ≈ 11.2s across 8
  workers ≈ 1.4s serial-equivalent per worker over the trace; any
  cumulative-µs reduction in hot per-entry paths inside that zone has
  whole-percent leverage on apply time.
- The lesson in fail 001 explicitly identified "Cache the SHA256 of TTL
  keys at footprint-construction time" as the correct design — and that
  hypothesis was **VIABLE at reviewer** but blocked at final review by an
  unrelated test flake, not by a design defect.

## Anti-Evidence

- Fail 001 (`cache-footprint-ttl-keys-on-transactionframe`) already explored
  this lineage at the **TransactionFrame** level and was marked NOT_VIABLE
  only because the PoC's full test suite did not complete cleanly on an
  independent run — i.e., the structural finding was accepted but the
  ledger-state regression was suspected. A re-proposal at the **stage** level
  rather than TransactionFrame level is structurally different (avoids
  per-TransactionFrame mutable state, places cache lifetime entirely inside
  a single `applySorobanStage` call) — but the underlying SHA256 reduction
  is the same and the test-flake risk remains.
- Quantified savings: SHA256 of a small XDR-encoded LedgerKey (~50–100B)
  on modern x86 is ~200–400ns. 500 redundant SHA256s/ledger ≈ 100–200µs/
  ledger, i.e. **0.04–0.09%** of the soroswap apply baseline (230ms).
  **Far below the 3% Medium threshold.**
- The previously-VIABLE reviewer assessment of fail 001 was likely based
  on cumulative SHA256 cost across **all** TTL-key consumers, but the
  Tracy zone for `getTTLKey`/SHA256 inside `applyLedger` descendants does
  not appear as a measurable self-time hotspot in the current trace —
  meaning the actual win is dwarfed by Rust host execution.
- Each redesign of TransactionFrame/ApplyStage state carries a high
  per-byte risk of subtle ledger-state divergence across nodes.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Failed At**: hypothesis
**Novelty**: PASS — re-proposal at the **ApplyStage / TxBundle** level rather
than the TransactionFrame level (a different lifetime and ownership shape
than fail 001); not previously written up as a distinct hypothesis.

### Why It Failed

Quantified SHA256 reduction is ~100–200µs/ledger (<0.1% of soroswap
baseline), below both the Medium severity floor (3%) and the Low severity
floor (1%) that this objective accepts at hypothesis stage. The fail 001
lineage was promoted to reviewer based on a qualitative "this is redundant
SHA256 work" argument; quantification at the byte/call level shows the
absolute win is in the same range as benchmark noise. Additionally, the
prior fail 001 PoC's inability to complete tests cleanly on independent
re-run flags TTL-key caching as a refactor with non-trivial ledger-state
risk, raising the bar for any re-proposal.

### Lesson Learned

When considering caching of a per-key hash, multiply
**(hash-compute-time) × (calls/ledger)** in absolute µs **before**
proposing the optimization. SHA256 of small XDR keys is ~200–400ns;
hundreds of calls/ledger is sub-1ms/ledger work — never reaching Medium
on a 230ms baseline. Footprint-derived hash caching should only be
proposed when the call count is in the thousands per ledger, not the
hundreds.
