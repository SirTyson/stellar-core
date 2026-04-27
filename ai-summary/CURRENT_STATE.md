# CURRENT_STATE — Soroswap Optimization Baseline

This is the bootstrap baseline established before any optimization
hypothesis has been evaluated. It was produced by a single
`run_apply_load_matrix.py --tracy` invocation on the unmodified
`soroswap-perf` branch HEAD.

## Commit

- SHA: `51a6d449b595eaf69f1a8c9219ec699c45043309`
- Branch: `soroswap-perf`
- Subject: `Bump lib/tracy submodule to pick up tracy-capture segfault fixes`

(The two most recent commits — `ae7078058` untracking `SimpleTimer::mLock`
from Tracy and `51a6d449b` bumping the tracy submodule — exist solely
to make Tracy capture work on this workload. Neither touches
stellar-core hot-path timing, so the numbers below are valid as the
unoptimized baseline against which hypotheses are compared.)

## Timestamp

- Run timestamp: 2026-04-27T18:50:13Z
- Recorded: 2026-04-27T19:04:28Z

## Apply-time results (per-run, 1 run)

| scenario              | median_ms          | p95_ms             | p99_ms             |
|-----------------------|--------------------|--------------------|--------------------|
| sac, TX=12000, T=8    | 709.6388700000025  | 759.4978862000025  | 912.7892176300072  |
| soroswap, TX=4000, T=8| 620.9962180000002  | 631.9992041999922  | 641.8652729899914  |

Headline metric (per the final-review skill): **soroswap median apply
time = 620.996 ms**.

Only one run was performed because this is the very first bootstrap
baseline. Future hypothesis evaluations should run the matrix multiple
times (3 minimum, 5 preferred) for statistical confidence.

## Artifact paths

- Run artifact directory:
  `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013`
- Tracy trace (sac), full and valid (~436 MB, 48.7M+ zones):
  `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-01-sac-tx-12000-t-8.tracy`
- Tracy trace (soroswap), full and valid (~291 MB, 36.3M zones):
  `/mnt/nvme2/apply-load/14571316dcdf-20260427-185013/logs/14571316dcdf-20260427-185013-02-soroswap-tx-4000-t-8.tracy`

Both traces saved cleanly ("Saving trace... done!"). The soroswap
trace is the headline reference for hypothesis-round Tracy diffs
(use `scripts/DiffTracyCSV.py` per the analyzing-tracy-profiles skill).


## Build configuration

```
./configure --enable-ccache --enable-sdfprefs --enable-tracy \
            --enable-tracy-capture --disable-postgres
make -j30
# tracy-capture rebuilt:
( cd lib/tracy/capture/build/unix && make clean && make release \
    CC="ccache clang-20" CXX="ccache clang++-20 -std=c++20" \
    CXXFLAGS="-O3 -g1 -fno-omit-frame-pointer -stdlib=libc++ -pthread -DFMT_HEADER_ONLY=1 -DNO_PARALLEL_SORT=1" \
    CFLAGS="-O3 -g1 -fno-omit-frame-pointer" \
    TRACY_NO_ISA_EXTENSIONS=1 TRACY_NO_LTO=1 LEGACY=1 -j30 )
cp lib/tracy/capture/build/unix/capture-release tracy-capture
```

stellar-core binary: `./src/stellar-core` reporting `v26.0.0-165-g51a6d449b`.

