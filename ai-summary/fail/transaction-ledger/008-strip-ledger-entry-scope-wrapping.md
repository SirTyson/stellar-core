# H008: Eliminate LedgerEntryScope wrapping overhead in fetchSorobanReadOnlyEntries hot loop

**Date**: 2026-05-23
**Subsystem**: transaction-ledger
**Severity**: Low (sub-Medium)
**Impact**: Parallel-cluster worker overhead per RO entry load
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`fetchSorobanReadOnlyEntries`
(`src/transactions/ParallelApplyUtils.cpp:638-720`) is invoked once per
parallel cluster to bulk-load the read-only Soroban entries for all
transactions assigned to that cluster. For the soroswap workload (where
all Soroban data lives in `InMemorySorobanState`), the loop should
amount to: one in-memory hashmap lookup per RO key, plus inserting the
resulting `LedgerEntry` (or absent marker) into the thread-local map.
The per-entry overhead should be roughly the hashmap probe plus a small
constant-time wrap into the thread-local map structure.

## Mechanism

Every entry inserted into the thread-local map goes through
`scopeAdoptEntryOpt(std::make_optional(*res))` (and a sibling call for
TTL keys), which constructs a `ScopedLedgerEntryOpt<ThreadParApply>`
wrapping the entry along with an 8-byte `LedgerEntryScopeID`. The
ScopedLedgerEntryOpt wrapper exists for debugging — to catch ledger-
skew, thread-race, stale-read, and lost-write misuses (see
`src/ledger/LedgerEntryScope.h:13-38`). The hypothesis was that this
wrapping (plus the corresponding scope checks on subsequent
`scopeReadEntry` calls during tx apply) imposes a meaningful per-entry
overhead that could be removed via a build-flag controlled "release
mode" stripping of scope tracking, lowering hot-path cost in
`fetchSorobanReadOnlyEntries` and downstream `getLiveEntryOpt`
operations.

## Trigger

Soroswap apply-load matrix run with a build that conditionally compiles
`LedgerEntryScope` machinery down to a thin wrapper (or eliminates it
entirely behind `#ifdef BUILD_TESTS`-style guards). Measure apply time
delta against current p26 baseline.

## Target Code

- `src/transactions/ParallelApplyUtils.cpp:638-720`
  (`fetchSorobanReadOnlyEntries` loop)
- `src/transactions/ParallelApplyUtils.cpp:1311-1349`
  (`TxParallelApplyLedgerState::getLiveEntryOpt` /
  `updateEntryFromOpUpdates` — per-tx hot path that also adopts
  scoped entries)
- `src/ledger/LedgerEntryScope.cpp:432-446`
  (`LedgerEntryScope<S>::scopeAdoptEntryOpt`)
- `src/ledger/LedgerEntryScope.cpp:486-520`
  (`scopeAdoptEntryOptFromImpl` — scope transitions between
  GlobalParApply / ThreadParApply / TxParApply with active-scope check)

## Evidence

- `scopeAdoptEntryOpt` is invoked at 13 distinct sites in
  `ParallelApplyUtils.cpp` covering RO entry load, RW entry load, TTL
  entry load, op update commits, and global commits.
- For soroswap (~10 read-only keys per swap × 2000 tx × ~71 ledgers in
  the trace) the loop runs ≥ 1.4 M times across the trace.
- Each adoption does construct a `LedgerEntryScopeID` (a 64-bit struct)
  and copy or move the `std::optional<LedgerEntry>`.
- The scope class hierarchy (templated on `StaticLedgerEntryScope`,
  with `mActive` boolean, `scopeDeactivate()` guards, and
  `releaseAssert`-style runtime checks) was added in 2025 as a
  debug/safety net replacing some LedgerTxn checks.

## Anti-Evidence

- Reading `LedgerEntryScope.cpp:432-446` shows `scopeAdoptEntryOpt` is
  just `return ScopedLedgerEntryOpt(mScopeID, entry);` — copying an
  8-byte scope ID and forwarding the optional. The compiler should
  inline this to roughly the same cost as constructing the optional
  directly.
- The `scopeAdoptEntryOptFromImpl` variants do an `if (scope.mActive)
  throw` check (one boolean load + predictable branch) before moving
  the optional. This is one branch per adoption.
- The `ScopedLedgerEntryOpt` storage layout is `LedgerEntryScopeID`
  (8 bytes) + `std::optional<LedgerEntry>` (whatever LedgerEntry
  size is), so per-entry memory overhead is +8 bytes — negligible.
- Inlined cost estimate per adoption: ~5 ns (one branch + one move).
  Across 1.4 M adoptions in the trace: 7 M ns = 7 ms total over 71
  ledgers ÷ NUM_CLUSTERS=8 parallel ≈ 12 µs critical path per ledger.
  That's 0.005% of 218 ms — three orders of magnitude below the 1%
  noise floor.
- The scope checks are also part of the well-documented safety-net
  introduced for parallel-apply correctness. Removing them
  conditionally would require a build mode that runs without these
  checks, which adds maintenance burden and surface area for
  determinism bugs — exactly what Meta-Patterns warn against trading
  correctness for sub-noise wins.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated in fail/hypothesis/reviewed/poc

### Why It Failed

The `LedgerEntryScope` wrapping is already a near-trivial inlinable
copy (an 8-byte scope ID plus forwarding the optional value). Direct
sizing puts the total work at well under 0.01% of apply time even when
counting every adoption in the trace and ignoring 8-way cluster
parallelism. There is no meaningful apply-time win available, and the
optimization would degrade a deliberately-added safety net for
parallel-apply correctness.

### Lesson Learned

Templated wrapper types that look "expensive" by line-of-code count
often compile down to nothing once inlined. Before proposing
`#ifdef`-guarded removal of correctness instrumentation, size the
post-inlining cost directly from the implementation (here: a copy of an
8-byte struct + forwarded optional). When the inlined cost falls
below 100 ns per call and the call count is at most ~1.5 M / trace /
NUM_CLUSTERS, the entire scope-tracking subsystem cannot move
apply time more than ~10 µs / ledger — three orders of magnitude below
the 1% noise floor. Correctness instrumentation that compiles down to
trivial copies should not be removed for performance.
