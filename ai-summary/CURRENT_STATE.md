# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming the validated `LedgerKey` storage-map lookup fast path.

## Commit

- SHA: `b196b62380c9c02bf10095707c04eb1074df4517`
- Subject: `perf(soroban-env): specialize storage map lookups`
- p26 submodule SHA: `1f86f3e5fa4bae1c529d3eb9520a639bbf872132`

## Timestamp

- Non-Tracy benchmark runs: 2026-04-29T01:09:22Z through 2026-04-29T01:23:11Z
- Diagnostic Tracy run: 2026-04-29T01:30:14Z
- Recorded: 2026-04-29T01:38:51Z

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `1695facd04c8-20260429-010922` | sac, TX=6000, T=8 | 335.604147 | 380.9146780499999 | 397.19659729000057 |
| 1 | `1695facd04c8-20260429-010922` | soroswap, TX=2000, T=8 | 313.2552390000019 | 318.90259645000066 | 325.0410912499998 |
| 2 | `1695facd04c8-20260429-011626` | sac, TX=6000, T=8 | 340.83282399999916 | 392.9254198499973 | 406.91980039999913 |
| 2 | `1695facd04c8-20260429-011626` | soroswap, TX=2000, T=8 | 297.3798060000008 | 305.59124730000076 | 319.14616032999714 |
| 3 | `1695facd04c8-20260429-012311` | sac, TX=6000, T=8 | 325.35075399999914 | 378.40040670000093 | 390.30781033999585 |
| 3 | `1695facd04c8-20260429-012311` | soroswap, TX=2000, T=8 | 304.8911174999994 | 315.1553698499934 | 323.8556112200008 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run.

## Diagnostic Tracy Run

The following run was executed only to capture traces. Its timing output is not
part of the authoritative baseline.

| run id | scenario | median_ms | p95_ms | p99_ms |
|--------|----------|-----------|--------|--------|
| `1695facd04c8-20260429-013014` | sac, TX=6000, T=8 | 316.6367880000016 | 343.19971699999945 | 632.98837132 |
| `1695facd04c8-20260429-013014` | soroswap, TX=2000, T=8 | 312.09119600000304 | 326.26665359999896 | 895.7621113799993 |

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/1695facd04c8-20260429-010922`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/1695facd04c8-20260429-011626`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/1695facd04c8-20260429-012311`
- Diagnostic Tracy artifact directory:
  `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014`
- Diagnostic Tracy trace (sac):
  `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-01-sac-tx-6000-t-8.tracy`
- Diagnostic Tracy trace (soroswap):
  `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`

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
