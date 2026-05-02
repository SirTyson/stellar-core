# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming protocol-gated Soroban host metering coalescing
(`soroban/001-protocol-gated-host-metering-coalescing`), stacked on top of the
prior cached old-entry XDR size metadata, typed SAC balance storage fast path,
and bulk-build host footprint/storage-map optimizations.

## Commit

- p26 submodule SHA: `fa1226b3068605c5376efe56c6cf809ca225a036`
  ("viable poc 001-protocol-gated-host-metering-coalescing"),
  committed on the SirTyson fork at branch
  [`poc/001-protocol-gated-host-metering-coalescing`](https://github.com/SirTyson/rs-soroban-env/tree/poc/001-protocol-gated-host-metering-coalescing).
  The accepted p26 stack is recorded as real submodule commits, in order:
  - upstream `b351f88a` ("Bump version to 26.0.0", v26.0.0)
  - `2b026eca` "viable success 001-bulk-build-host-storage-maps"
  - `e6728024` "viable success 001-typed-sac-balance-storage-fast-path"
  - `ac6316c2` "viable poc 002-cache-old-entry-xdr-sizes"
  - `a417a963` "viable poc 002-cache-old-entry-xdr-sizes (revised positional metadata)"
  - `fa1226b3` "viable poc 001-protocol-gated-host-metering-coalescing"
- Outer branch: `soroswap-perf` on the SirTyson stellar-core fork.
- Source/benchmark outer commit SHA on `soroswap-perf`:
  `a0e763089aff250a6cb1395535253ba740ad6b39`
  (`viable poc 001-protocol-gated-host-metering-coalescing (iter 3)`),
  recording the p26 gitlink at
  `fa1226b3068605c5376efe56c6cf809ca225a036`.
- Reproduce this baseline from a clean checkout with:
  ```sh
  git fetch origin soroswap-perf
  git checkout a0e763089aff250a6cb1395535253ba740ad6b39
  git submodule update --init --recursive src/rust/soroban/p26
  ```

## Timestamp

- Non-Tracy benchmark runs: 2026-05-02T17:50:31Z through 2026-05-02T18:03:14Z
- Diagnostic Tracy run: 2026-05-02T18:09:44Z
- Recorded: 2026-05-02

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `9074352f02c4-20260502-175031` | sac, TX=6000, T=8 | 306.357371 | 323.520286 | 342.969893 |
| 1 | `9074352f02c4-20260502-175031` | soroswap, TX=2000, T=8 | 272.249541 | 277.125824 | 284.216066 |
| 2 | `9074352f02c4-20260502-175659` | sac, TX=6000, T=8 | 300.543791 | 318.326585 | 334.658452 |
| 2 | `9074352f02c4-20260502-175659` | soroswap, TX=2000, T=8 | 275.885919 | 280.428445 | 291.406201 |
| 3 | `9074352f02c4-20260502-180314` | sac, TX=6000, T=8 | 312.727103 | 332.254466 | 350.911892 |
| 3 | `9074352f02c4-20260502-180314` | soroswap, TX=2000, T=8 | 270.551362 | 274.494149 | 281.500531 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run or an average-only
summary.

## Improvement vs Previous Baseline

Previous accepted baseline (cached old-entry XDR sizes):
- soroswap median average: 278.740030 ms
- sac median average: 317.717361 ms

Current baseline (protocol-gated host metering coalescing):
- soroswap median average: 272.895607 ms — **2.10% improvement**
- sac median average: 306.542755 ms — **3.52% improvement**

All three optimized soroswap medians (272.250 / 275.886 / 270.551 ms) are below
the previous baseline's best run (278.120 ms), so the improvement is supported
across every run, not just the average. Max-sac also improves on average, so
there is no soroswap-vs-max-sac tradeoff concern.

## Diagnostic Tracy Run

- Run id: `9074352f02c4-20260502-180944`
- Soroswap trace:
  `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`
- SAC trace:
  `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-01-sac-tx-6000-t-8.tracy`
- Tracy apply-time numbers from this run are **ignored for the verdict**; the
  headline metric is the three non-Tracy runs above.
- Diagnostic attribution: the prior accepted soroswap trace reported
  `visit host object` self-time of 1,432,652,085 ns across 3,491,848 calls; the
  optimized diagnostic trace no longer reports that zone, matching the
  source-level next-protocol removal of the per-visit span and `VisitObject`
  charge. The top-line non-Tracy apply-time result remains the source of truth.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/9074352f02c4-20260502-175031`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/9074352f02c4-20260502-175659`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/9074352f02c4-20260502-180314`
- Tracy diagnostic run artifact directory:
  `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944`

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

The `--enable-next-protocol-version-unsafe-for-production` flag is required
starting with PoC 001 (protocol-gated host metering coalescing): the
optimization is intentionally gated behind a protocol number greater than the
released p26 so that p26 ledgers retain their exact metering. The flag bumps
`Config::CURRENT_LEDGER_PROTOCOL_VERSION` from 26 to 27 and propagates the
`next` cargo feature into the p26 Soroban host crate, raising the host's
compiled `INTERFACE_VERSION.protocol` to 27 so `Host::set_ledger_info` accepts
the new protocol and enables coalesced host metering. The apply-load benchmark
inherits `LEDGER_PROTOCOL_VERSION` from the configured build and therefore
exercises the optimized path automatically.

## Worktree Build Note

This baseline was measured in a git worktree, which can expose a worktree
incompatibility in the `src/Makefile.am:267` rule introduced by upstream
PR #5187. If a future worktree build fails on a missing `git-state.txt`, apply
the worktree-local generated-Makefile fix used in prior runs or update the
upstream rule to resolve submodule gitdirs through `git rev-parse --git-path`.
