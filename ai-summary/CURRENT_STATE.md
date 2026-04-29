# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
switching authoritative apply-load measurements away from Tracy-enabled runs.

## Commit

- SHA: `8a1d4c2d0f5bad54b768f15740a3ca7f5e0f819e`
- Subject: `Restore smaller apply-load matrix counts`

## Timestamp

- Non-Tracy benchmark runs: 2026-04-28T23:33:11Z through 2026-04-28T23:53:33Z
- Diagnostic Tracy run: 2026-04-28T23:54:09Z through 2026-04-29T00:01:04Z
- Recorded: 2026-04-29T00:01:04Z

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `a645620fe528-20260428-233312` | sac, TX=6000, T=8 | 374.7747420000005 | 420.67973859999796 | 441.66502910999833 |
| 1 | `a645620fe528-20260428-233312` | soroswap, TX=2000, T=8 | 314.3531645000003 | 335.76203330000004 | 343.5404278100001 |
| 2 | `a645620fe528-20260428-234023` | sac, TX=6000, T=8 | 316.10224200000084 | 350.98036009999595 | 370.06274168000334 |
| 2 | `a645620fe528-20260428-234023` | soroswap, TX=2000, T=8 | 311.7416195000005 | 323.9066271000003 | 328.4619910800045 |
| 3 | `a645620fe528-20260428-234654` | sac, TX=6000, T=8 | 330.77135400000043 | 355.597785350002 | 375.3653804600006 |
| 3 | `a645620fe528-20260428-234654` | soroswap, TX=2000, T=8 | 309.7216619999999 | 323.5170060500009 | 326.42506947000055 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run.

## Diagnostic Tracy Run

The following run was executed only to capture traces. Its timing output is not
part of the authoritative baseline.

| run id | scenario | median_ms | p95_ms | p99_ms |
|--------|----------|-----------|--------|--------|
| `a645620fe528-20260428-235409` | sac, TX=6000, T=8 | 344.25222199999735 | 407.6281739000005 | 625.45597859 |
| `a645620fe528-20260428-235409` | soroswap, TX=2000, T=8 | 298.9327135000003 | 312.0726850999999 | 944.3160098099999 |

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/a645620fe528-20260428-233312`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/a645620fe528-20260428-234023`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/a645620fe528-20260428-234654`
- Diagnostic Tracy artifact directory:
  `/mnt/nvme2/apply-load/a645620fe528-20260428-235409`
- Diagnostic Tracy trace (sac):
  `/mnt/nvme2/apply-load/a645620fe528-20260428-235409/logs/a645620fe528-20260428-235409-01-sac-tx-6000-t-8.tracy`
- Diagnostic Tracy trace (soroswap):
  `/mnt/nvme2/apply-load/a645620fe528-20260428-235409/logs/a645620fe528-20260428-235409-02-soroswap-tx-2000-t-8.tracy`

The soroswap trace is the headline reference for future hypothesis-round Tracy
diffs.

## Build configuration

```sh
./configure --enable-ccache --enable-sdfprefs --enable-tracy \
            --enable-tracy-capture --disable-postgres
make -j $(nproc)
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
```

The first three benchmark commands are the authoritative non-Tracy baseline.
The final command is diagnostic-only and was run solely to capture Tracy traces.
