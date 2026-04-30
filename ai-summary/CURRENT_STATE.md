# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming cached old-entry XDR size metadata for ledger-change rent accounting
(`ledger/002-cache-old-entry-xdr-sizes`), stacked on top of the prior typed SAC
balance storage fast path and bulk-build host footprint/storage-map
optimizations.

## Commit

- p26 submodule SHA: `a417a96314085a070bd7daf2cb29e85809f21ae3`
  ("viable poc 002-cache-old-entry-xdr-sizes (revised positional metadata)"),
  committed on the SirTyson fork at branch
  [`poc/002-cache-old-entry-xdr-sizes`](https://github.com/SirTyson/rs-soroban-env/tree/poc/002-cache-old-entry-xdr-sizes).
  The accepted p26 stack is recorded as real submodule commits, in order:
  - upstream `b351f88a` ("Bump version to 26.0.0", v26.0.0)
  - `2b026eca` "viable success 001-bulk-build-host-storage-maps"
  - `e6728024` "viable success 001-typed-sac-balance-storage-fast-path"
  - `ac6316c2` "viable poc 002-cache-old-entry-xdr-sizes"
  - `a417a963` "viable poc 002-cache-old-entry-xdr-sizes (revised positional metadata)"
- Outer branch: `soroswap-perf` on the SirTyson stellar-core fork.
- Source/benchmark outer commit SHA on `soroswap-perf`:
  `b5ade12b06e3e7172b738137ab0ff1c215cdd3f8`
  (`perf(ledger): cache old entry XDR sizes`), recording the p26 gitlink at
  `a417a96314085a070bd7daf2cb29e85809f21ae3`.
- Reproduce this baseline from a clean checkout with:
  ```sh
  git fetch origin soroswap-perf
  git checkout b5ade12b06e3e7172b738137ab0ff1c215cdd3f8
  git submodule update --init --recursive src/rust/soroban/p26
  ```

## Timestamp

- Non-Tracy benchmark runs: 2026-04-30T15:46:46Z through 2026-04-30T15:59:22Z
- Diagnostic Tracy run: 2026-04-30T16:06:27Z
- Recorded: 2026-04-30

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `1e0b14a6b879-20260430-154646` | sac, TX=6000, T=8 | 312.139381 | 331.111938 | 347.732977 |
| 1 | `1e0b14a6b879-20260430-154646` | soroswap, TX=2000, T=8 | 278.119725 | 284.411647 | 295.625918 |
| 2 | `1e0b14a6b879-20260430-155304` | sac, TX=6000, T=8 | 305.929053 | 325.707622 | 337.876517 |
| 2 | `1e0b14a6b879-20260430-155304` | soroswap, TX=2000, T=8 | 279.118436 | 288.663204 | 292.851181 |
| 3 | `1e0b14a6b879-20260430-155922` | sac, TX=6000, T=8 | 335.083649 | 386.183584 | 420.101186 |
| 3 | `1e0b14a6b879-20260430-155922` | soroswap, TX=2000, T=8 | 278.981930 | 284.718892 | 296.067910 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run or an average-only
summary.

## Improvement vs Previous Baseline

Previous accepted baseline (typed SAC balance storage fast path):
- soroswap median average: 288.722773 ms
- sac median average: 321.256127 ms

Current baseline (cached old-entry XDR sizes):
- soroswap median average: 278.740030 ms — **3.46% improvement**
- sac median average: 317.717361 ms — **1.10% improvement**

All three optimized soroswap medians (278.120 / 279.118 / 278.982 ms) are below
the previous baseline's best run (286.739 ms), so the improvement is supported
across every run, not just the average. Max-sac also improves on average; run 3
is slower than the previous SAC average, but the three-run SAC result is still a
net improvement and therefore satisfies the soroswap-vs-max-sac tradeoff rules.

## Diagnostic Tracy Run

- Run id: `1e0b14a6b879-20260430-160627`
- Soroswap trace:
  `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`
- SAC trace:
  `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-01-sac-tx-6000-t-8.tracy`
- Tracy apply-time numbers from this run are **ignored for the verdict**; the
  headline metric is the three non-Tracy runs above.
- Diagnostic attribution: aggregate soroswap `write xdr` work dropped from
  228,626,166 ns / 185,422 calls in the prior accepted baseline trace to
  147,686,586 ns / 152,631 calls in this optimized trace.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-154646`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-155304`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-155922`
- Tracy diagnostic run artifact directory:
  `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627`

## Build configuration

```sh
./configure --enable-ccache --enable-sdfprefs --enable-tracy \
            --enable-tracy-capture --disable-postgres
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

## Worktree Build Note

This baseline was measured in a git worktree, which can expose a worktree
incompatibility in the `src/Makefile.am:267` rule introduced by upstream
PR #5187. If a future worktree build fails on a missing `git-state.txt`, apply
the worktree-local generated-Makefile fix used in prior runs or update the
upstream rule to resolve submodule gitdirs through `git rev-parse --git-path`.
