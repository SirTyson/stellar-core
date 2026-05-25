# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming sparse no-meta Soroban ledger-change extraction
(`ledger/001-sparse-no-meta-ledger-changes`), stacked on top of native Soroswap
pool raw instance storage, direct SAC balance reads for the native Soroswap pair
`swap` path, native Soroswap pair swap emulation, complete native Soroswap pool
getter emulation, protocol-gated host metering coalescing, cached old-entry XDR
size metadata, typed SAC balance storage fast path, and bulk-build host
footprint/storage-map optimizations.

## Commit

- p26 submodule SHA: `7aef8604bced962d79aaf06cab2f9e2c2c4e95d8`
  ("poc 001-sparse-no-meta-ledger-changes"), committed on the SirTyson fork at
  branch
  [`poc/001-sparse-no-meta-ledger-changes`](https://github.com/SirTyson/rs-soroban-env/tree/poc/001-sparse-no-meta-ledger-changes).
  The accepted p26 stack is recorded as real submodule commits, in order:
  - upstream `b351f88a` ("Bump version to 26.0.0", v26.0.0)
  - `2b026eca` "viable success 001-bulk-build-host-storage-maps"
  - `e6728024` "viable success 001-typed-sac-balance-storage-fast-path"
  - `ac6316c2` "viable poc 002-cache-old-entry-xdr-sizes"
  - `a417a963` "viable poc 002-cache-old-entry-xdr-sizes (revised positional metadata)"
  - `fa1226b3` "viable poc 001-protocol-gated-host-metering-coalescing"
  - `3a4015b9` "poc 001-complete-native-soroswap-pool-getters"
  - `06919b9a` "poc 001-complete-native-soroswap-pool-getters"
  - `03d78248` "poc 001-native-soroswap-pair-swap"
  - `e92dd6a5` "poc 001-direct-sac-balance-for-native-pair"
  - `fbbea0d9` "poc 001-direct-sac-balance-for-native-pair"
  - `9f262829` "poc 001-native-pool-raw-instance-storage"
  - `53acea39` "poc 001-native-pool-raw-instance-storage"
  - `bf6625f8` "poc 001-native-pool-raw-instance-storage"
  - `2ef5a839` "poc 001-sparse-no-meta-ledger-changes"
  - `f8efa2a7` "poc 001-sparse-no-meta-ledger-changes"
  - `7aef8604` "poc 001-sparse-no-meta-ledger-changes"
- Outer branch: `soroswap-perf` on the SirTyson stellar-core fork.
- Source/benchmark outer commit SHA on `soroswap-perf`:
  `1e61a61455cb1e69e0e68295b5180ca0bb7dd831`
  (`perf(ledger): sparse no-meta ledger changes`), recording the p26 gitlink at
  `7aef8604bced962d79aaf06cab2f9e2c2c4e95d8`.
- Reproduce this baseline from a clean checkout with:
  ```sh
  git fetch origin soroswap-perf
  git checkout 1e61a61455cb1e69e0e68295b5180ca0bb7dd831
  git submodule update --init --recursive src/rust/soroban/p26
  ```

## Timestamp

- Non-Tracy benchmark runs: 2026-05-25T00:58:11Z through 2026-05-25T01:10:26Z
- Diagnostic Tracy run: 2026-05-25T01:16:55Z
- Recorded: 2026-05-25

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `f5502210f4e4-20260525-005811` | sac, TX=6000, T=8 | 304.7717910 | 324.4614534 | 346.8156259 |
| 1 | `f5502210f4e4-20260525-005811` | soroswap, TX=2000, T=8 | 207.0457240 | 210.7548173 | 218.1700961 |
| 2 | `f5502210f4e4-20260525-010419` | sac, TX=6000, T=8 | 313.7902940 | 330.7629382 | 357.9009611 |
| 2 | `f5502210f4e4-20260525-010419` | soroswap, TX=2000, T=8 | 209.2724275 | 214.0044290 | 215.7058769 |
| 3 | `f5502210f4e4-20260525-011026` | sac, TX=6000, T=8 | 308.1304460 | 327.4401032 | 344.8353395 |
| 3 | `f5502210f4e4-20260525-011026` | soroswap, TX=2000, T=8 | 206.4515575 | 211.0340098 | 217.7408400 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run or an average-only
summary.

## Improvement vs Previous Baseline

Previous accepted baseline (native pool raw instance storage):
- soroswap median average: 211.443642 ms
- sac median average: 309.533176 ms

Current baseline (sparse no-meta ledger changes):
- soroswap median average: 207.589903 ms — **1.82% improvement**
- sac median average: 308.897510 ms — **0.21% improvement**

All three optimized soroswap medians (207.046 / 209.272 / 206.452 ms) are below
all three previous baseline soroswap medians (210.683 / 210.690 / 212.958 ms),
so the headline improvement is supported across every run. Max-sac median is
roughly neutral and slightly improved on average, so there is no adverse
soroswap-vs-max-sac tradeoff to justify.

## Diagnostic Tracy Run

- Run id: `f5502210f4e4-20260525-011655`
- Soroswap trace:
  `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`
- SAC trace:
  `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-01-sac-tx-6000-t-8.tracy`
- Tracy apply-time numbers from this run are **ignored for the verdict**; the
  headline metric is the three non-Tracy runs above.
- Diagnostic attribution: the source-level change removes unconsumed
  `LedgerEntryChange` output from the measured Soroban `InvokeHostFunction`
  apply flow. The p26 stellar-core bridge still performs the same metered key
  serialization for budget equivalence, but writes keys into a reused scratch
  buffer and drops no-op read-only changes before the bridge's rent/effects
  extractors iterate them. The change does not touch TX-set construction or lazy
  background bucket work.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/f5502210f4e4-20260525-005811`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/f5502210f4e4-20260525-010419`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011026`
- Tracy diagnostic run artifact directory:
  `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655`

## Build configuration

```sh
./configure --enable-ccache --enable-sdfprefs --enable-tracy \
            --enable-tracy-capture --disable-postgres \
            --enable-next-protocol-version-unsafe-for-production
make -j $(nproc)
env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py
PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy
```

The first three benchmark commands are the authoritative non-Tracy baseline.
The fourth benchmark command captured the diagnostic Tracy trace for
attribution; its apply-time numbers are not used for the verdict.

The `--enable-next-protocol-version-unsafe-for-production` flag is required for
this accepted state: the native Soroswap pool getter, pair swap, direct SAC
balance-read, and raw pool instance-storage optimizations are intentionally
gated behind a protocol number greater than released p26 so p26 ledgers retain
their exact Wasm execution and metering. The sparse no-meta ledger-change
optimization itself preserves p26 budget accounting by retaining equivalent
metered key serialization in the apply path.

## Worktree Build Note

This baseline was measured in a git worktree, which can expose a worktree
incompatibility in the `src/Makefile.am:267` rule introduced by upstream
PR #5187. If a future worktree build fails on a missing `git-state.txt`, apply
the worktree-local generated-Makefile fix used in prior runs or update the
upstream rule to resolve submodule gitdirs through `git rev-parse --git-path`.
