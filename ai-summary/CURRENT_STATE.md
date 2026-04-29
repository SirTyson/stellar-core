# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming the bulk-build host footprint and storage maps optimization
(transaction-ledger/001).

## Commit

- p26 submodule SHA: see the commit recorded with this update; the
  enforcing-mode `build_storage_footprint_from_xdr` and
  `build_storage_map_from_xdr_ledger_entries` paths now construct each
  `MeteredOrdMap` with a single `from_map` call after sorting+merging,
  rather than per-key `MeteredOrdMap::insert`.

## Timestamp

- Non-Tracy benchmark runs: 2026-04-29T18:04:10Z through 2026-04-29T18:17:17Z
- Diagnostic Tracy run: SKIPPED for this baseline update.
- Recorded: 2026-04-29

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `3259abf99f36-20260429-180410` | sac, TX=6000, T=8 | 323.572193 | 354.983247 | 388.081342 |
| 1 | `3259abf99f36-20260429-180410` | soroswap, TX=2000, T=8 | 306.252726 | 310.776013 | 313.924768 |
| 2 | `3259abf99f36-20260429-181048` | sac, TX=6000, T=8 | 313.851046 | 333.603606 | 356.475479 |
| 2 | `3259abf99f36-20260429-181048` | soroswap, TX=2000, T=8 | 294.393414 | 301.649963 | 316.209646 |
| 3 | `3259abf99f36-20260429-181717` | sac, TX=6000, T=8 | 319.460919 | 353.275286 | 373.037554 |
| 3 | `3259abf99f36-20260429-181717` | soroswap, TX=2000, T=8 | 299.912345 | 306.932627 | 313.700032 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run.

## Improvement vs Previous Baseline

Previous baseline (specialized storage map lookup fast path):
- soroswap median average: 305.175 ms
- sac median average: 333.929 ms

Current baseline (bulk build host storage maps):
- soroswap median average: 300.186 ms — 1.63% improvement
- sac median average: 318.961 ms — 4.48% improvement

## Diagnostic Tracy Run

Skipped for this baseline update. The previous Tracy reference traces from
`1695facd04c8-20260429-013014` remain valid for hypothesis-round attribution
work; see the prior CURRENT_STATE archived in
`ai-summary/success/soroban-env/002-specialize-storage-map-lookup-fast-path.md`
if specific paths are needed.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/3259abf99f36-20260429-180410`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/3259abf99f36-20260429-181048`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/3259abf99f36-20260429-181717`

## Build configuration

```sh
./configure --enable-ccache --enable-sdfprefs --enable-tracy \
            --enable-tracy-capture --disable-postgres
make -j $(nproc)
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
```

The three benchmark commands are the authoritative non-Tracy baseline. No
diagnostic Tracy run was captured for this baseline update.
