# H003: Replace `std::map<AccountID, SequenceNumber> accToMaxSeq` with `unordered_map` in `processFeesSeqNums`

**Date**: 2026-05-24
**Subsystem**: transaction-ledger
**Severity**: Low
**Impact**: Apply-path serial fee-phase micro-optimization
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The merge-op tracking auxiliary structure in `processFeesSeqNums` should
use an O(1) hash map rather than an O(log n) red-black tree, since the
container's only purpose is per-account max-seq tracking which has no
ordering requirement.

## Mechanism

`LedgerManagerImpl::processFeesSeqNums`
(src/ledger/LedgerManagerImpl.cpp:2322) declares
`std::map<AccountID, SequenceNumber> accToMaxSeq;` and inserts/updates
it inside the per-tx loop (lines 2371-2377), but only for the path
`isV19OrLater && !tx->isSoroban()`. Each `emplace` and update incurs
red-black tree rotation + 3-way `AccountID` comparison (memcmp over
32 bytes). An `UnorderedMap<AccountID, SequenceNumber>` with hash on
the public key would replace tree rotation + 3-way compare with one
hash + one equality compare per operation.

## Trigger

Run a benchmark with a non-trivial classic-tx phase that has many
distinct source accounts; profile `processFeesSeqNums`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2322` — `std::map<AccountID,
  SequenceNumber> accToMaxSeq;` declaration.
- `src/ledger/LedgerManagerImpl.cpp:2369-2383` — emplace + max-update
  loop body, guarded by `isV19OrLater && !tx->isSoroban()`.

## Evidence

- `std::map` ops are O(log n) with per-node allocation and 3-way
  `AccountID` compare (memcmp over a 32-byte ed25519 public key).
- `unordered_map` ops are O(1) amortized with a single hash + equality.
- For a hypothetical 6000-classic-tx ledger with all distinct sources,
  `std::map` does ~6000 × log2(6000) ≈ 6000 × 13 ≈ 78000 node compares,
  versus 6000 hash + 6000 eq.

## Anti-Evidence

- The soroswap benchmark has Soroban-only ledgers; the guard
  `!tx->isSoroban()` skips the entire `accToMaxSeq` and `mergeOpInTx`
  path. Tracy confirms `processFeesSeqNums` ≈ 2.25 ms for soroswap and
  ≈ 4.2 ms for SAC — both Soroban-only — meaning `accToMaxSeq` is never
  exercised in either benchmark.
- The max-sac benchmark is also Soroban-only by construction (SAC
  invocations are Soroban transactions); SAC token transfers go through
  the soroban host, not classic ACCOUNT_MERGE.
- Even with a hypothetical 6000 classic-tx ledger, the absolute saving
  is sub-millisecond: red-black tree node ops are ~200 ns vs ~50 ns for
  unordered_map; saving ~150 ns × 6000 ≈ 900 µs/ledger ≈ 0.3% of a
  hypothetical 300 ms apply window — below the 3% Medium floor and the
  1% noise floor.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated. F008 covered batched
source-account loads in `processFeesSeqNums`, but no prior hypothesis
targeted the `accToMaxSeq` container choice.

### Why It Failed

The `accToMaxSeq`/`mergeOpInTx` code path is fully gated behind
`!tx->isSoroban()`. Both objective benchmarks (soroswap and max-sac)
are Soroban-only, so this code never executes during the measured
applyLedger window. The proposed optimization has exactly zero effect
on either benchmark. Even on a hypothetical classic-heavy ledger the
ceiling is sub-1% per Meta-Pattern #5.

### Lesson Learned

Always verify that a candidate code path actually runs during the
benchmark before proposing an optimization. The
`isV19OrLater && !tx->isSoroban()` guard in `processFeesSeqNums` makes
the `accToMaxSeq` work dead code for any Soroban-only workload — which
includes both objective benchmarks. Future hypotheses targeting
classic-only paths inside `processFeesSeqNums` or other apply-path
zones must first verify the path executes under soroswap / max-sac.
This is a special case of Meta-Pattern #7 (verify the code path is on
the apply-thread critical path during the benchmark before proposing
optimization).
