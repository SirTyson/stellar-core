# 004: Cache Parallel-Apply Footprint LedgerKey Hashes

**Date**: 2026-04-28
**Severity**: Low
**Impact**: Apply-time reduction in the Soroban parallel apply path
**Subsystem**: soroban
**Final review by**: gpt-5.5, high

## Summary

The optimization is confirmed. It precomputes primed `ParallelApplyLedgerKey` values for each Soroban transaction footprint key and corresponding TTL key once per `TxBundle`, then reuses those cached keys through the parallel-apply ledger-access helpers instead of reconstructing lookup keys and recomputing hashes on every map probe.

Across three independent `scripts/run_apply_load_matrix.py --tracy` runs, soroswap median apply time improved from the accepted 620.996 ms baseline to 603.400 ms, 613.578 ms, and 596.381 ms. The average soroswap improvement was 2.66%, with max-sac also improving in all runs, so this clears the Low severity threshold.

## Root Cause

Parallel Soroban apply repeatedly probes maps keyed by `ParallelApplyLedgerKey` while starting from immutable footprint `LedgerKey` objects. The previous code constructed a fresh `ParallelApplyLedgerKey` for each lookup in `mTxEntryMap`, `mThreadEntryMap`, `mGlobalEntryMap`, RO TTL bump sets, and stage read-write sets, defeating the existing per-object hash cache and repeatedly deriving TTL keys.

## Reproduction

Run the apply-load matrix on the unoptimized baseline and optimized commit:

```sh
./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres
make -j30
env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j30 check
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
```

The inefficiency manifests during `closeLedger` for Soroban transactions with CONTRACT_DATA-heavy footprints, such as the soroswap benchmark. Every apply-stage setup, add-read, writeback, TTL flush, and successful-tx commit over those immutable keys can otherwise redo lookup-side hashing or TTL-key derivation.

## Affected Code

- `src/transactions/ParallelApplyStage.h:18-245` — `TxBundle` now owns cached footprint and TTL `ParallelApplyLedgerKey` values.
- `src/transactions/ParallelApplyUtils.cpp:104-1457` — parallel apply stage setup, thread-state preload, TTL bump flushing, tx/thread map probes, and successful-tx commit now use cached-key overloads where available.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:352-1475` — invoke-host add-read, writeback, erase, and autorestore paths route cached footprint and TTL keys through the parallel ledger-access helper.
- `src/ledger/LedgerManagerImpl.cpp:2504-2506` and transaction/operation frame headers — thread `TxBundle const&` through parallel apply so operation helpers can reach the cached keys.

## Optimization

- **Files modified**: `ParallelApplyStage.h`, `ParallelApplyUtils.{h,cpp}`, `InvokeHostFunctionOpFrame.{h,cpp}`, Soroban operation frame plumbing, transaction frame plumbing, and the mechanical test wrapper signature.
- **How to verify**:
  1. Build: `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres && make -j30`
  2. Run existing tests: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make -j30 check`
  3. Benchmark: `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy`

### Changes Made

`CachedTxFootprintKeys` precomputes `ParallelApplyLedgerKey` objects for read-only and read-write footprint keys and, for Soroban entries, their deterministic TTL keys. It primes `hash()` during `TxBundle` construction, before worker threads consume the bundle, avoiding mutable-hash races.

The parallel apply ledger-access interfaces gained `ParallelApplyLedgerKey const&` overloads while preserving `LedgerKey const&` fallbacks for synthesized or non-footprint keys. Hot paths now use cached keys in stage read-write sets, RO TTL sets, global/thread preload, invoke-host add-read/writeback, RO TTL flushing, and successful transaction commit.

### Benchmark Results

These numbers are from independent final-review runs using `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy`.

| Scenario | Baseline median ms | Optimized run 1 median ms | Optimized run 2 median ms | Optimized run 3 median ms | Average optimized median ms | Average improvement |
|----------|--------------------|---------------------------|---------------------------|---------------------------|-----------------------------|---------------------|
| soroswap, TX=4000, T=8 | 620.996218 | 603.400217 | 613.577685 | 596.381355 | 604.453086 | 2.66% |
| sac, TX=12000, T=8 | 709.638870 | 692.552348 | 668.856753 | 679.484763 | 680.297955 | 4.13% |

| Soroswap metric | Baseline | Best optimized run | Improvement |
|-----------------|----------|--------------------|-------------|
| median apply time | 620.996218 ms | 596.381355 ms | 3.96% |
| p95 apply time | 631.999204 ms | 615.479421 ms | 2.61% |
| p99 apply time | 641.865273 ms | 656.223990 ms | -2.24% |
| Errors | 0 | 0 | — |

Raw optimized benchmark output. Only the chosen best run's artifact directory is
retained after cleanup; earlier run directories were removed per the artifact
retention rule.

```text
Run 1: 729423c9f1a5-20260428-034840
sac,TX=12000,T=8: median=692.5523475000009ms, p95=826.2431193000072ms, p99=1034.150116329996ms
soroswap,TX=4000,T=8: median=603.400216500002ms, p95=711.4591699999934ms, p99=769.5354233200034ms

Run 2: 729423c9f1a5-20260428-040245
sac,TX=12000,T=8: median=668.8567534999984ms, p95=723.25062160001ms, p99=851.497942500007ms
soroswap,TX=4000,T=8: median=613.5776854999931ms, p95=624.0815708500011ms, p99=637.7503740399867ms

Run 3: 729423c9f1a5-20260428-041610 (chosen retained artifact)
sac,TX=12000,T=8: median=679.484763000004ms, p95=716.0496663000064ms, p99=863.0642700399967ms
soroswap,TX=4000,T=8: median=596.3813549999923ms, p95=615.4794212499918ms, p99=656.2239895100065ms
```

Tracy aggregate attribution on the accepted best run shows `getReadWriteKeysForStage` self-time dropped from 9.410 ms in the baseline soroswap trace to 2.837 ms in the optimized trace. The remaining gains are distributed across repeated parallel-apply map probe paths that no longer reconstruct lookup keys or TTL keys for footprint entries.

## Expected vs Actual Behavior

- **Expected**: Footprint and TTL key hashes should be computed once per transaction bundle and reused for every parallel-apply lookup over those immutable keys.
- **Actual**: The old code rebuilt lookup-side `ParallelApplyLedgerKey` objects from `LedgerKey const&` at every probe, discarding the cached hash after each call.

## Adversarial Review

1. Exercises claimed inefficiency: YES — the benchmark exercises stage setup, read materialization, host output writeback, TTL flushing, and successful-tx commit over Soroban footprints.
2. Realistic preconditions: YES — soroswap declares CONTRACT_DATA-heavy footprints and runs through the normal parallel Soroban `closeLedger` apply path.
3. Inefficiency vs by-design: INEFFICIENCY — no correctness property depends on recomputing deterministic hashes or TTL keys for immutable footprint entries; fallbacks remain for non-footprint keys.
4. Final severity: Low — soroswap median improved in all three optimized runs, averaging 2.66% versus the accepted baseline.
5. In scope: YES — all modified hot paths are descendants of `closeLedger` parallel Soroban apply.
6. Benchmark methodology: CORRECT — used the project apply-load matrix with Tracy and the locally built `./src/stellar-core` on the same host, comparing against `ai-summary/CURRENT_STATE.md`.
7. Alternative explanations: UNLIKELY — all three optimized runs improved soroswap median, max-sac also improved, and Tracy shows reduced self-time in a directly targeted stage-setup zone.
8. Novelty: NOVEL.

## Suggested Follow-Up

Investigate whether remaining `LedgerKey const&` fallback calls in restore/TTL-extension helpers can be routed through footprint-indexed cached keys without adding linear-scan overhead.
