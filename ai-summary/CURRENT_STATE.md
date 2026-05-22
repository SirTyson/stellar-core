# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming complete native Soroswap pool getter emulation
(`soroban-env/001-complete-native-soroswap-pool-getters`), stacked on top of
the prior protocol-gated host metering coalescing, cached old-entry XDR size
metadata, typed SAC balance storage fast path, and bulk-build host
footprint/storage-map optimizations.

## Commit

- p26 submodule SHA: `06919b9ae9b593b06d5b4b908dfa2dbbb13fe49d`
  ("poc 001-complete-native-soroswap-pool-getters"), committed on the SirTyson
  fork at branch
  [`poc/001-complete-native-soroswap-pool-getters`](https://github.com/SirTyson/rs-soroban-env/tree/poc/001-complete-native-soroswap-pool-getters).
  The accepted p26 stack is recorded as real submodule commits, in order:
  - upstream `b351f88a` ("Bump version to 26.0.0", v26.0.0)
  - `2b026eca` "viable success 001-bulk-build-host-storage-maps"
  - `e6728024` "viable success 001-typed-sac-balance-storage-fast-path"
  - `ac6316c2` "viable poc 002-cache-old-entry-xdr-sizes"
  - `a417a963` "viable poc 002-cache-old-entry-xdr-sizes (revised positional metadata)"
  - `fa1226b3` "viable poc 001-protocol-gated-host-metering-coalescing"
  - `3a4015b9` "poc 001-complete-native-soroswap-pool-getters"
  - `06919b9a` "poc 001-complete-native-soroswap-pool-getters"
- Outer branch: `soroswap-perf` on the SirTyson stellar-core fork.
- Source/benchmark outer commit SHA on `soroswap-perf`:
  `35a1e59408796e266773a4b55db3e5c9d7049ce8`
  (`perf(soroban-env): enable native soroswap pool getters`), recording the p26
  gitlink at `06919b9ae9b593b06d5b4b908dfa2dbbb13fe49d`.
- Reproduce this baseline from a clean checkout with:
  ```sh
  git fetch origin soroswap-perf
  git checkout 35a1e59408796e266773a4b55db3e5c9d7049ce8
  git submodule update --init --recursive src/rust/soroban/p26
  ```

## Timestamp

- Non-Tracy benchmark runs: 2026-05-22T02:54:54Z through 2026-05-22T03:07:20Z
- Diagnostic Tracy run: 2026-05-22T03:13:43Z
- Recorded: 2026-05-22

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `2ff900fcd176-20260522-025454` | sac, TX=6000, T=8 | 302.746108 | 321.751289 | 326.874513 |
| 1 | `2ff900fcd176-20260522-025454` | soroswap, TX=2000, T=8 | 248.943592 | 253.098921 | 256.084719 |
| 2 | `2ff900fcd176-20260522-030109` | sac, TX=6000, T=8 | 306.976803 | 325.862619 | 330.021178 |
| 2 | `2ff900fcd176-20260522-030109` | soroswap, TX=2000, T=8 | 249.634999 | 254.180753 | 258.905346 |
| 3 | `2ff900fcd176-20260522-030720` | sac, TX=6000, T=8 | 301.951331 | 321.110183 | 335.943533 |
| 3 | `2ff900fcd176-20260522-030720` | soroswap, TX=2000, T=8 | 253.517163 | 258.063105 | 260.750227 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run or an average-only
summary.

## Improvement vs Previous Baseline

Previous accepted baseline (protocol-gated host metering coalescing):
- soroswap median average: 272.895607 ms
- sac median average: 306.542755 ms

Current baseline (complete native Soroswap pool getter emulation):
- soroswap median average: 250.698585 ms — **8.13% improvement**
- sac median average: 303.891414 ms — **0.86% improvement**

All three optimized soroswap medians (248.944 / 249.635 / 253.517 ms) are below
all three previous baseline medians (272.250 / 275.886 / 270.551 ms), so the
improvement is supported across every run. Max-sac improves slightly on average;
one run regressed by 2.14%, which is within the acceptable tradeoff envelope and
is dominated by the 8.13% soroswap win.

## Diagnostic Tracy Run

- Run id: `2ff900fcd176-20260522-031343`
- Soroswap trace:
  `/mnt/nvme2/apply-load/2ff900fcd176-20260522-031343/logs/2ff900fcd176-20260522-031343-02-soroswap-tx-2000-t-8.tracy`
- SAC trace:
  `/mnt/nvme2/apply-load/2ff900fcd176-20260522-031343/logs/2ff900fcd176-20260522-031343-01-sac-tx-6000-t-8.tracy`
- Tracy apply-time numbers from this run are **ignored for the verdict**; the
  headline metric is the three non-Tracy runs above.
- Diagnostic attribution: the optimized soroswap trace reported
  `Vm::instantiate_wasmi` 14,040 times and `Vm::instantiate_wasmi - instantiate`
  total time of 828.5 ms. The previous accepted trace cited for this hypothesis
  had 20,389 in-apply instantiation events, consistent with the source-level
  removal of the native-getter subset. The top-line non-Tracy apply-time result
  remains the source of truth.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/2ff900fcd176-20260522-025454`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/2ff900fcd176-20260522-030109`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/2ff900fcd176-20260522-030720`
- Tracy diagnostic run artifact directory:
  `/mnt/nvme2/apply-load/2ff900fcd176-20260522-031343`

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
this accepted state: the native Soroswap pool getter emulation is intentionally
gated behind a protocol number greater than released p26 so p26 ledgers retain
their exact Wasm execution and metering. The flag bumps
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
