# H013: addAnyContractsToModuleCache Iterates All Init/Live Entries On Critical Path

**Date**: 2026-05-03
**Subsystem**: transactions
**Severity**: Low
**Impact**: per-ledger serial scan inside finalizeLedgerTxnChanges
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`finalizeLedgerTxnChanges` runs serially under `mLedgerStateMutex` and is
on the apply critical path. It calls
`mApplyState.addAnyContractsToModuleCache(lh.ledgerVersion, initEntries)`
and `addAnyContractsToModuleCache(lh.ledgerVersion, liveEntries)`. These
should only touch the module cache when the batch contains a `CONTRACT_CODE`
entry (which is rare in steady-state soroswap traffic — no new contracts
are deployed mid-bench). For a typical soroswap ledger the function should
do effectively no work; the linear scan over thousands of `LedgerEntry`
values whose `data.type()` is `CONTRACT_DATA` / `TTL` / `ACCOUNT` /
`TRUSTLINE` is pure overhead on the critical path.

## Mechanism

The implementation
(`src/ledger/LedgerManagerImpl.cpp:3468-3496`) iterates the entire
`std::vector<LedgerEntry>` twice (init + live) checking
`e.data.type() == CONTRACT_CODE` per entry. For soroswap, every per-swap
ledger touches roughly 6 entries × 2000 swaps = ~12k ledger entries
scanned per close, none of which are `CONTRACT_CODE`. Each comparison is
cheap, but the iteration also pulls each `LedgerEntry` into cache solely
to read its discriminant. The `LedgerTxn::getAllEntries` call (just
above) already had to materialize these vectors in cache, so the marginal
overhead is mostly branch + discriminant load per entry.

## Trigger

Run `apply-load --mode soroswap-tps` and inspect the
`addAnyContractsToModuleCache` Tracy zone (or instrument it). Per-ledger
scan over ~12k entries × 2 (init + live) ≈ 24k discriminant reads × ~3 ns
≈ 72 µs/ledger. Across 71 ledgers ≈ 5 ms aggregate.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:3354-3357` — call sites inside `finalizeLedgerTxnChanges`.
- `src/ledger/LedgerManagerImpl.cpp:3468-3496` — `addAnyContractsToModuleCache` implementation.
- `src/ledger/LedgerTxn.cpp:1699` — `getAllEntries` returns the vectors.

## Evidence

The function is on the critical path between
`getAllEntries` (which seals the ltx) and `addLiveBatch` (which writes
buckets), inside `mLedgerStateMutex` in
`sealLedgerTxnAndStoreInBucketsAndDB`. There is no Tracy zone on the
function itself, but the parent `finalizeLedgerTxnChanges` zone shows
325 ms total / 71 ledgers ≈ 4.6 ms per ledger, of which a small portion
is this scan.

## Anti-Evidence (and reason for self-rejection)

The total addressable cost is well below the Medium severity floor:
- Even assuming the scan is the full ~5 ms aggregate (likely an
  overestimate; most of the 4.6 ms/ledger of `finalizeLedgerTxnChanges`
  is `addLiveBatch`, `resolveBackgroundEvictionScan`, and serializing
  state size), 5 ms / 5230 ms `applyLedger` ≈ **0.1%**.
- A flag like "ledger contains CONTRACT_CODE in delta" tracked during
  `LedgerTxn::commit` could short-circuit both calls, but the saved cost
  is sub-1% noise floor and does not justify the implementation +
  test surface.
- During contract-deployment ledgers the function does mandatory
  protocol-required wasm compilation; that path cannot be skipped.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-03
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated; complements prior
finalizeLedgerTxnChanges/bucket-write fail records (H004, etc.) which
focused on the bucket put loop, not the module-cache scan.

### Why It Failed

The addressable cost (≤ 0.1% of `applyLedger`) is well below the 1%
benchmark noise floor, far below the 3% Medium objective threshold. A
fix is structurally clean (track a "delta has CONTRACT_CODE" bit during
LedgerTxn commits and skip the scan if false) but the savings are
indistinguishable from noise.

### Lesson Learned

`finalizeLedgerTxnChanges` runs many small serial steps after `getAllEntries`
seals the ltx; when sizing per-step optimizations there, divide the parent
zone time across known sub-steps before assuming the scan in question
dominates. For soroswap, `addLiveBatch` and `resolveBackgroundEvictionScan`
account for nearly all of the 4.6 ms/ledger; module-cache iteration is a
rounding error and should not be repromoted unless a future workload
deploys contracts every ledger.
