# H003: Overlap Soroban RO Entry Preload with `processFeesSeqNums` and `prefetchTransactionData`

**Date**: 2026-05-20
**Subsystem**: ledger / parallel Soroban apply setup
**Severity**: Low
**Impact**: Apply-time reduction by hiding the read-only Soroban entry preload phase of `soroban_setup_glbl` behind the serial pre-apply phases (`prefetchTxSourceIds` → `processFeesSeqNums` → `prefetchTransactionData`).
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

The Soroban read-only entry preload block in
`GlobalParallelApplyLedgerState::collectModifiedClassicEntries`
(`src/transactions/ParallelApplyUtils.cpp:654-718`) walks every Soroban
read-only footprint key in the ledger, looks each one up in
`mInMemorySorobanState` (and a derived TTL key), and copies the entry into
`mGlobalEntryMap`. This block reads only from `mInMemorySorobanState` and
`mLCLSnapshot` — both immutable for the duration of `applyLedger`. Since this
preload does not depend on the `ltx` mutations performed by
`processFeesSeqNums`, the expected behavior is that it can be hoisted into a
`std::async` task launched before `prefetchTxSourceIds` and joined immediately
before `applySorobanStageClustersInParallel` begins. The observable apply
result and `mGlobalEntryMap` contents must be byte-identical, just produced
earlier on the wall clock.

## Mechanism

Today the ordering in `applyLedger` is strictly serial: `prefetchTxSourceIds`
(0.7 ms/ledger) → `processFeesSeqNums` (2.15 ms/ledger) → `applyTransactions`
→ `prefetchTransactionData` (1.65 ms/ledger) → `applyParallelPhase`. Only
after all of that does `GlobalParallelApplyLedgerState` construct, and its
constructor runs the RO Soroban preload as part of the ~24 ms
`soroban_setup_glbl` phase. The preload depends only on per-ledger
read-only data (`InMemorySorobanState`, `mLCLSnapshot`, the per-ledger tx
footprints, all available the moment the txset is known), so a background
task that builds the preload portion of `mGlobalEntryMap` in parallel with
fee/prefetch processing would shorten the serial critical path by up to the
sum of those pre-apply phases.

## Trigger

Run the soroswap apply-load benchmark (`TX=2000, T=8`) and inspect the
sequential window between `prefetchTxSourceIds` (start) and
`soroban_setup_glbl` (end). With overlap, `soroban_setup_glbl` should mostly
overlap the fee/prefetch phases, leaving only the classic-entry collection
and the join wait on the critical path.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:1659-1688` — `applyLedger` body sequencing
  `prefetchTxSourceIds` → `processFeesSeqNums` → `applyTransactions`.
- `src/ledger/LedgerManagerImpl.cpp:2823, 2858-2863, 2882-2884` — `applyTransactions`
  calling `prefetchTransactionData`, loading Soroban config, then
  `applyParallelPhase`.
- `src/transactions/ParallelApplyUtils.cpp:386-429, 654-718` —
  `GlobalParallelApplyLedgerState` constructor and the RO Soroban preload
  block that is the candidate to hoist into a background task.

## Evidence

- The RO Soroban preload reads only `mInMemorySorobanState` and `mLCLSnapshot`,
  both immutable during apply, so no synchronization is needed beyond a single
  `std::future::get` join before workers start.
- The pre-apply serial work (`prefetchTxSourceIds` + `processFeesSeqNums` +
  `prefetchTransactionData`) sums to ~4.5 ms per soroswap ledger in the
  current accepted Tracy trace; if fully hidden behind the preload, that is the
  upper bound on apply-time savings.
- `InMemorySorobanState` is already accessed concurrently by Soroban worker
  threads in the current architecture, so adding a single additional reader
  during the pre-apply window is consistent with existing thread-safety
  assumptions.

## Anti-Evidence

- The RO Soroban preload is **not** the dominant component of
  `soroban_setup_glbl`. For the soroswap workload it touches roughly the
  number of unique RO Soroban footprint keys (tens-to-low-hundreds, since
  thousands of swap txs all share the same 8 pair instances and a small set
  of SAC code/instance entries). Each lookup costs ~1 µs of `getTTLKey`
  SHA-256 plus a hash-table probe; the preload itself is on the order of
  1 ms per ledger, not the full ~24 ms of `soroban_setup_glbl`.
- The dominant `soroban_setup_glbl` cost is the V26 pre-parallel triage and
  duplicate footprint scans inside `preParallelApplyAndCollectModifiedClassicEntries`,
  which DO depend on the post-`processFeesSeqNums` ltx state and therefore
  cannot be hoisted. The reviewed `002-precompute-parallel-apply-footprint-index`
  already targets those duplicate scans.
- Even with a perfect overlap, the savings are bounded by
  `min(pre-apply serial time, preload time)` ≈ `min(4.5 ms, ~1 ms)` ≈ **1 ms
  per ledger**, well below the 3% Medium threshold (which would require
  ~8.2 ms on the 272 ms soroswap baseline).
- Prior parallelism wins on cluster state setup
  (`fail/ledger/001-parallelize-cluster-state-setup.md`) regressed real
  benchmarks despite structurally correct overlap, suggesting that adding
  background readers during pre-apply may itself cost cache/memory bandwidth
  that the apply critical path needs.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a fees-prefetch overlap
hypothesis (the prior cluster-state setup parallelism failure targeted
per-cluster state, not the global RO preload overlap with fees/prefetch).

### Why It Failed

The hypothesis is structurally sound (correctness, determinism, and
thread-safety constraints can all be satisfied), but the projected savings
are below the objective's Medium severity floor. The RO Soroban preload is
a small fraction of `soroban_setup_glbl`; the bulk of that 24 ms is the V26
pre-parallel triage and duplicate footprint scans that depend on
post-`processFeesSeqNums` ltx state and therefore cannot be hoisted into a
pre-fee background task. The maximum overlap window of ~4.5 ms is
additionally only partially fillable because the preload itself only does
~1 ms of work. Net projected savings are well under 3%, putting this in
Low territory; the objective explicitly does not accept Low hypotheses.

### Lesson Learned

`soroban_setup_glbl` is dominated by the V26 pre-parallel triage scan and
duplicate footprint walks, not by the RO Soroban preload block. Any hoist-
into-background scheme that tries to hide setup_glbl behind earlier phases
must either (a) target the larger V26 triage scan (blocked by its dependency
on `processFeesSeqNums` ltx mutations) or (b) accept that the available
overlap window is sub-Medium. Future hypotheses should quantify the specific
sub-zone they propose to overlap, not assume the entire `soroban_setup_glbl`
phase is hoistable.
