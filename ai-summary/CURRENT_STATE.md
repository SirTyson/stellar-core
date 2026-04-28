# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted optimized baseline after confirming
`004-parallel-apply-ledgerkey-hash-recompute`.

## Commit

- SHA: `2133b4a98741b6b811a5cdcf74a38587220f90ca`
- Subject: `perf(soroban): cache parallel apply footprint keys`

## Timestamp

- Optimized benchmark runs: 2026-04-28T03:48:39Z through 2026-04-28T04:29:28Z
- Recorded: 2026-04-28T04:29:28Z

## Apply-time results (per-run, 3 runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `729423c9f1a5-20260428-034840` | sac, TX=12000, T=8 | 692.5523475000009 | 826.2431193000072 | 1034.150116329996 |
| 1 | `729423c9f1a5-20260428-034840` | soroswap, TX=4000, T=8 | 603.400216500002 | 711.4591699999934 | 769.5354233200034 |
| 2 | `729423c9f1a5-20260428-040245` | sac, TX=12000, T=8 | 668.8567534999984 | 723.25062160001 | 851.497942500007 |
| 2 | `729423c9f1a5-20260428-040245` | soroswap, TX=4000, T=8 | 613.5776854999931 | 624.0815708500011 | 637.7503740399867 |
| 3 | `729423c9f1a5-20260428-041610` | sac, TX=12000, T=8 | 679.484763000004 | 716.0496663000064 | 863.0642700399967 |
| 3 | `729423c9f1a5-20260428-041610` | soroswap, TX=4000, T=8 | 596.3813549999923 | 615.4794212499918 | 656.2239895100065 |

Headline metric for the next hypothesis round: **soroswap median apply
time = 596.381 ms** from the chosen best optimized run.

## Artifact paths

- Chosen run artifact directory:
  `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610`
- Tracy trace (sac):
  `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-01-sac-tx-12000-t-8.tracy`
- Tracy trace (soroswap):
  `/mnt/nvme2/apply-load/729423c9f1a5-20260428-041610/logs/729423c9f1a5-20260428-041610-02-soroswap-tx-4000-t-8.tracy`

The soroswap trace is the headline reference for future hypothesis-round
Tracy diffs.

## Build configuration

```sh
./configure --enable-ccache --enable-sdfprefs --enable-tracy \
            --enable-tracy-capture --disable-postgres
make -j30 ALL_SOROBAN_GIT_STATE_STAMPS=
env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' \
    make -j30 check ALL_SOROBAN_GIT_STATE_STAMPS=
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
```

The benchmark binary was built from the source tree that was subsequently
committed as `2133b4a98741b6b811a5cdcf74a38587220f90ca`.
