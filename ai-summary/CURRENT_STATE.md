# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming native Soroswap pool raw instance storage
(`soroban/001-native-pool-raw-instance-storage`), stacked on top of direct SAC
balance reads for the native Soroswap pair `swap` path, native Soroswap pair swap
emulation, complete native Soroswap pool getter emulation, protocol-gated host
metering coalescing, cached old-entry XDR size metadata, typed SAC balance
storage fast path, and bulk-build host footprint/storage-map optimizations.

## Commit

- p26 submodule SHA: `bf6625f80504d9ccbd34ffe2fa5cc1761d5242fe`
  ("poc 001-native-pool-raw-instance-storage"), committed on the SirTyson fork
  at branch
  [`poc/001-native-pool-raw-instance-storage`](https://github.com/SirTyson/rs-soroban-env/tree/poc/001-native-pool-raw-instance-storage).
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
- Outer branch: `soroswap-perf` on the SirTyson stellar-core fork.
- Source/benchmark outer commit SHA on `soroswap-perf`:
  `8a53196ecf7a8d412d329d49c7c2dcbdd848df72`
  (`perf(soroban): optimize native pool raw instance storage`), recording the
  p26 gitlink at `bf6625f80504d9ccbd34ffe2fa5cc1761d5242fe`.
- Reproduce this baseline from a clean checkout with:
  ```sh
  git fetch origin soroswap-perf
  git checkout 8a53196ecf7a8d412d329d49c7c2dcbdd848df72
  git submodule update --init --recursive src/rust/soroban/p26
  ```

## Timestamp

- Non-Tracy benchmark runs: 2026-05-24T11:28:17Z through 2026-05-24T11:40:38Z
- Diagnostic Tracy run: 2026-05-24T11:47:04Z
- Recorded: 2026-05-24

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `8dd3f525748f-20260524-112817` | sac, TX=6000, T=8 | 318.3988075 | 336.1706546 | 360.1546387 |
| 1 | `8dd3f525748f-20260524-112817` | soroswap, TX=2000, T=8 | 210.6826550 | 214.8679175 | 217.6902260 |
| 2 | `8dd3f525748f-20260524-113424` | sac, TX=6000, T=8 | 304.7521720 | 322.2278743 | 330.6001261 |
| 2 | `8dd3f525748f-20260524-113424` | soroswap, TX=2000, T=8 | 210.6898800 | 214.4627854 | 223.1789672 |
| 3 | `8dd3f525748f-20260524-114038` | sac, TX=6000, T=8 | 305.4485480 | 325.0758114 | 352.7727210 |
| 3 | `8dd3f525748f-20260524-114038` | soroswap, TX=2000, T=8 | 212.9583905 | 216.8511416 | 219.6446553 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run or an average-only
summary.

## Improvement vs Previous Baseline

Previous accepted baseline (direct SAC balance reads for native pair swap):
- soroswap median average: 218.310247 ms
- sac median average: 314.654682 ms

Current baseline (native pool raw instance storage):
- soroswap median average: 211.443642 ms — **3.15% improvement**
- sac median average: 309.533176 ms — **1.63% improvement**

All three optimized soroswap medians (210.683 / 210.690 / 212.958 ms) are below
all three previous baseline medians (221.845 / 217.379 / 215.707 ms), so the
headline improvement is supported across every run. Max-sac median also improved
on average, so there is no soroswap-vs-max-sac tradeoff to justify.

## Diagnostic Tracy Run

- Run id: `8dd3f525748f-20260524-114704`
- Soroswap trace:
  `/mnt/nvme2/apply-load/8dd3f525748f-20260524-114704/logs/8dd3f525748f-20260524-114704-02-soroswap-tx-2000-t-8.tracy`
- SAC trace:
  `/mnt/nvme2/apply-load/8dd3f525748f-20260524-114704/logs/8dd3f525748f-20260524-114704-01-sac-tx-6000-t-8.tracy`
- Tracy apply-time numbers from this run are **ignored for the verdict**; the
  headline metric is the three non-Tracy runs above.
- Diagnostic attribution: the source-level change removes redundant native pool
  instance-storage representation work from the measured `closeLedger` apply
  flow. The protocol-27 allowlisted pool path reads fixed raw `ScMap` fields,
  keeps reserve values as `i128`, writes reserve updates by rebuilding the raw
  storage map directly, and avoids the extra full-instance clone when entering
  `Frame::NativeContract`. The change does not touch TX-set construction or lazy
  background bucket work.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/8dd3f525748f-20260524-112817`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/8dd3f525748f-20260524-113424`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/8dd3f525748f-20260524-114038`
- Tracy diagnostic run artifact directory:
  `/mnt/nvme2/apply-load/8dd3f525748f-20260524-114704`

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
balance-read, and raw pool instance-storage optimizations are intentionally gated
behind a protocol number greater than released p26 so p26 ledgers retain their
exact Wasm execution and metering. The flag bumps
`Config::CURRENT_LEDGER_PROTOCOL_VERSION` from 26 to 27 and propagates the
`next` cargo feature into the p26 Soroban host crate, raising the host's compiled
`INTERFACE_VERSION.protocol` to 27 so the benchmark exercises the optimized path
automatically.

## Worktree Build Note

This baseline was measured in a git worktree, which can expose a worktree
incompatibility in the `src/Makefile.am:267` rule introduced by upstream
PR #5187. If a future worktree build fails on a missing `git-state.txt`, apply
the worktree-local generated-Makefile fix used in prior runs or update the
upstream rule to resolve submodule gitdirs through `git rev-parse --git-path`.
