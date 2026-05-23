# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming direct SAC balance reads for the native Soroswap pair `swap` path
(`soroban-env/001-direct-sac-balance-for-native-pair`), stacked on top of native
Soroswap pair swap emulation, complete native Soroswap pool getter emulation,
protocol-gated host metering coalescing, cached old-entry XDR size metadata,
typed SAC balance storage fast path, and bulk-build host footprint/storage-map
optimizations.

## Commit

- p26 submodule SHA: `fbbea0d9cb33e94fbab331d3d4bf8e69f088f9d4`
  ("poc 001-direct-sac-balance-for-native-pair"), committed on the SirTyson fork
  at branch
  [`poc/001-direct-sac-balance-for-native-pair`](https://github.com/SirTyson/rs-soroban-env/tree/poc/001-direct-sac-balance-for-native-pair).
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
- Outer branch: `soroswap-perf` on the SirTyson stellar-core fork.
- Source/benchmark outer commit SHA on `soroswap-perf`:
  `04c9035453c68519e19c52006255f4ca0f40ca42`
  (`perf(soroban-env): read native pair SAC balances directly`), recording the
  p26 gitlink at `fbbea0d9cb33e94fbab331d3d4bf8e69f088f9d4`.
- Reproduce this baseline from a clean checkout with:
  ```sh
  git fetch origin soroswap-perf
  git checkout 04c9035453c68519e19c52006255f4ca0f40ca42
  git submodule update --init --recursive src/rust/soroban/p26
  ```

## Timestamp

- Non-Tracy benchmark runs: 2026-05-23T00:43:19Z through 2026-05-23T00:55:56Z
- Diagnostic Tracy run: 2026-05-23T01:02:30Z
- Recorded: 2026-05-23

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `62ee1ffb5d05-20260523-004319` | sac, TX=6000, T=8 | 316.314591 | 336.797731 | 352.292643 |
| 1 | `62ee1ffb5d05-20260523-004319` | soroswap, TX=2000, T=8 | 221.844987 | 225.673956 | 227.353551 |
| 2 | `62ee1ffb5d05-20260523-004934` | sac, TX=6000, T=8 | 316.279749 | 334.009878 | 342.990440 |
| 2 | `62ee1ffb5d05-20260523-004934` | soroswap, TX=2000, T=8 | 217.378587 | 221.208289 | 224.716387 |
| 3 | `62ee1ffb5d05-20260523-005556` | sac, TX=6000, T=8 | 311.369706 | 329.543232 | 341.252275 |
| 3 | `62ee1ffb5d05-20260523-005556` | soroswap, TX=2000, T=8 | 215.707167 | 219.655525 | 226.964780 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run or an average-only
summary.

## Improvement vs Previous Baseline

Previous accepted baseline (native Soroswap pair swap emulation):
- soroswap median average: 230.225027 ms
- sac median average: 310.805003 ms

Current baseline (direct SAC balance reads for native pair swap):
- soroswap median average: 218.310247 ms — **5.18% improvement**
- sac median average: 314.654682 ms — **1.24% regression**

All three optimized soroswap medians (221.845 / 217.379 / 215.707 ms) are below
all three previous baseline medians (223.447 / 240.603 / 226.626 ms), so the
headline improvement is supported across every run. Max-sac median regressed by
1.24% on average, which is below the 5% tradeoff limit and is dominated by the
5.18% soroswap win. Max-sac p95 and p99 improved relative to the previous
accepted baseline.

## Diagnostic Tracy Run

- Run id: `62ee1ffb5d05-20260523-010230`
- Soroswap trace:
  `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`
- SAC trace:
  `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-01-sac-tx-6000-t-8.tracy`
- Tracy apply-time numbers from this run are **ignored for the verdict**; the
  headline metric is the three non-Tracy runs above.
- Diagnostic attribution: the source-level change removes two read-only SAC
  `balance` subframes from each accepted native pair `swap` by directly reading
  the typed SAC contract balance after checking that the token instance is a
  Stellar Asset Contract. The direct path remains inside the measured
  `closeLedger` apply flow; it does not touch TX-set construction or lazy
  background bucket work.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-004319`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-004934`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-005556`
- Tracy diagnostic run artifact directory:
  `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230`

## Build configuration

```sh
./configure --enable-ccache --enable-sdfprefs --enable-tracy \
            --enable-tracy-capture --disable-postgres \
            --enable-next-protocol-version-unsafe-for-production
make -j30
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
this accepted state: the native Soroswap pool getter and pair swap emulation are
intentionally gated behind a protocol number greater than released p26 so p26
ledgers retain their exact Wasm execution and metering. The flag bumps
`Config::CURRENT_LEDGER_PROTOCOL_VERSION` from 26 to 27 and propagates the
`next` cargo feature into the p26 Soroban host crate, raising the host's
compiled `INTERFACE_VERSION.protocol` to 27 so the benchmark exercises the
optimized path automatically.

## Worktree Build Note

This baseline was measured in a git worktree, which can expose a worktree
incompatibility in the `src/Makefile.am:267` rule introduced by upstream
PR #5187. If a future worktree build fails on a missing `git-state.txt`, apply
the worktree-local generated-Makefile fix used in prior runs or update the
upstream rule to resolve submodule gitdirs through `git rev-parse --git-path`.
