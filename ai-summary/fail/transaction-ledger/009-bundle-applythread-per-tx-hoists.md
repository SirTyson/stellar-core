# H009: Bundle Per-Tx Setup Hoists in `applyThread` Into Single Cluster-Local Pass

**Date**: 2026-05-26
**Subsystem**: transaction-ledger
**Severity**: Low (projected, even when combined)
**Impact**: per-tx setup overhead in Soroban worker loop
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`applyThread` (`src/ledger/LedgerManagerImpl.cpp:2484–2521`) executes a
per-tx loop that performs three near-constant pre-apply setup steps for
every transaction in a cluster:

1. `mApplyState.getMetrics().mTransactionApply.TimeScope()` (line 2497)
   — constructs a `medida::TimerContext` (RAII timer start).
2. `Hash txSubSeed = subSha256(sorobanBasePrngSeed, txBundle.getTxNum())`
   (line 2500) — SHA256 of a 36-byte concatenation, computed fresh for
   every tx.
3. `threadState->flushRoTTLBumpsInTxWriteFootprint(txBundle)` (line 2502)
   — iterates the tx's `readWrite` footprint, calling `getTTLKey(lk)`
   (a SHA256) per Soroban key, then probing `mRoTTLBumps`.

For ~250 Soroban txs per cluster on soroswap, each step runs 250 times
serially on the cluster's worker thread. The bundled hypothesis is:
hoist all three steps into a single pre-loop pass that (a) caches the
timer reference, (b) batch-precomputes all 250 sub-seeds in one pass
(possibly via a precomputed `Hash[]` array carried on the cluster), and
(c) precomputes all TTL keys for the cluster's footprints once at cluster
construction.

Expected wall savings on the cluster's critical path: SHA256 of small
constant inputs is ~500 ns each; for ~250 txs × (1 sub-seed + ~3 TTL
SHA256s) = ~1000 SHA256s per cluster = ~500 µs per cluster of redundant
hashing; plus medida `TimerContext` construction (~50 ns × 250 = ~12 µs)
and the `mRoTTLBumps` probes (~50 ns × 750 = ~37 µs). Aggregate
critical-path saving per cluster: ~550 µs.

## Mechanism

Each per-tx setup step is independently cheap but cumulatively visible.
A single hoisted precomputation pass (run either at cluster construction
time on the apply thread, or once at the start of `applyThread` before
the loop) could:

- compute all per-tx sub-seeds as `subSeeds[i] = subSha256(seed, i)` in
  one tight loop;
- precompute per-tx TTL keys as `Hash[][]` indexed by tx-in-cluster;
- cache `medida::TimerContext` factory (currently it's a member-access
  followed by `TimeScope()`; the saving is the per-call construction
  cost which is small).

The proposal explicitly bundles all three to clear the noise floor.

## Trigger

Run soroswap apply-load benchmark. The savings would manifest as
shorter per-cluster wall in Tracy `applySorobanStageClustersInParallel`.

## Target Code

- `src/ledger/LedgerManagerImpl.cpp:2484–2521` — `applyThread` per-tx loop.
- `src/transactions/ParallelApplyUtils.cpp:1004–1039` —
  `flushRoTTLBumpsInTxWriteFootprint` TTL-key precompute target.
- `src/transactions/ParallelApplyStage.h` — possibly extend `Cluster` or
  `TxBundle` to carry precomputed sub-seed and TTL-key vectors.

## Evidence

- Direct Tracy measurement (latest trace, 70 ledgers, 8 clusters):
  - `applyThread` body is ~270 ms aggregate worker time / 70 ledgers / 8
    clusters ≈ 0.48 ms/cluster/ledger of OTHER setup beyond
    `parallelApply` itself.
  - Cluster median size ~250 txs on soroswap.
- SHA256 cost: ~500 ns per call on amd64.
- medida `TimerContext` is a small RAII wrapper; per-construction ~50 ns.

## Anti-Evidence

- All three sub-targets are individually rejected as sub-threshold in
  prior fail records:
  - **TimerContext / `mTransactionApply`**: fail #003 (residual medida
    histograms, sub-1.2% per call site) and fail #016 (`mTransactionApply`
    sequential site at ~1.1%).
  - **Sub-seed precompute / per-tx SHA256**: fail #052
    (TTL-key memoization caps at ~1.5%) and fail #186 (cross-call cache
    aggregation caps at ~1%). Same SHA256-of-small-bytes ceiling.
  - **TTL-key precompute for `flushRoTTLBumpsInTxWriteFootprint`**: same
    ceiling as fail #052; `getTTLKey` is the same SHA256 cost.
- Meta-Pattern #5: bundling multiple individually sub-threshold C++
  apply-path micro-optimizations into one change does not push the
  combined saving past 3% Medium — the per-fix ceilings are physical
  (SHA256 cost is irreducible).
- Bundling cost: requires extending `Cluster` / `TxBundle` data members,
  threading precomputed vectors through `applyThread`, and ensuring the
  precompute pass itself runs off the critical path (it cannot, because
  cluster construction already runs on the apply thread serially before
  `applySorobanStageClustersInParallel` launches workers — see line 2548
  of `LedgerManagerImpl.cpp`). Moving precompute to the apply thread
  trades worker time for apply-thread time 1:1, with zero critical-path
  saving on the dominant slowest-cluster wait path.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-26
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail #003 / #052 / #180 / #186 in that
it explicitly bundles three otherwise-rejected micro-optimizations into a
single change. The bundling itself is novel, but the conclusion is the
same.

### Why It Failed

Direct sizing of the bundled saving:

- Per-cluster critical-path saving: ~550 µs (sum of three components, see
  Mechanism section).
- Per-ledger critical-path saving: max ≈ 550 µs (slowest cluster only —
  faster clusters' savings are absorbed by the `future.get()` wait floor
  set by the slowest cluster's wall, per fail #006 and Meta-Pattern 6).
- Relative to 207 ms soroswap median: ~0.27%.

This is below the 1% Low floor and an order of magnitude below the 3%
Medium floor.

Worse, the precompute pass for sub-seeds and TTL keys cannot meaningfully
run off the critical path: cluster construction in
`applyParallelPhase` is already on the apply thread serially before
worker launch, so moving precompute there shifts time from worker to
apply thread without changing the critical-path wall (apply-thread
work also gates `future.get()`'s parent zone). The only "saving" is the
SHA256 work cost itself, which is the irreducible 500-ns floor.

Meta-Pattern #5 directly forbids bundling sub-threshold C++ apply-path
micro-optimizations into a single hypothesis to clear the floor — and
this hypothesis is the textbook case.

### Lesson Learned

Bundling sub-threshold per-tx hoists in `applyThread` is governed by
two structural limits:
1. **Bundle ceiling = sum of individual ceilings**. Each sub-fix is
   already measured at sub-1%; their sum is bounded by the same
   irreducible work units (SHA256, atomic-counter ops, RAII timer
   construction).
2. **Precompute placement is constrained**: any precompute that must
   complete before workers launch runs on the apply thread, shifting
   not eliminating work on the critical path.

Future `applyThread`-targeted hypotheses must either eliminate
mandatory per-tx work entirely (e.g., remove the medida timer scope by
disabling the metric — protocol-visible behavior unchanged but blocked
by fail #003) or move work to a true non-critical-path location
(post-apply background thread). Hoists within the cluster's worker
loop into the cluster's precompute pass on the apply thread cannot help.
