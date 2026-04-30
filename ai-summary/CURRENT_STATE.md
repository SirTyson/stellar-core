# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming the typed SAC balance storage fast path
(transaction-ledger/001-typed-sac-balance-storage-fast-path), stacked on top
of the prior bulk-build host footprint and storage maps optimization
(transaction-ledger/001-bulk-build-host-storage-maps).

## Commit

- p26 submodule SHA: `e6728024aed9bb39cac3c2f247579bfac5b8bc79`
  ("viable success 001-typed-sac-balance-storage-fast-path"), committed on
  the SirTyson fork at branch
  [`poc/001-typed-sac-balance-storage-fast-path`](https://github.com/SirTyson/rs-soroban-env/tree/poc/001-typed-sac-balance-storage-fast-path).
  The baseline stack is recorded as real submodule commits, in order:
  - upstream `b351f88a` ("Bump version to 26.0.0", v26.0.0)
  - `2b026eca` "viable success 001-bulk-build-host-storage-maps"
  - `e6728024` "viable success 001-typed-sac-balance-storage-fast-path"
- Outer worktree branch: `poc/001-typed-sac-balance-storage-fast-path` on
  the SirTyson stellar-core fork. Outer commit recording the gitlink at
  `e6728024` is `fe9b7873e` "Bump p26 submodule to record bulk-build +
  typed-sac-balance success" (also present on `soroswap-perf` at the
  identical SHA chain `4e306108d` -> `fe9b7873e`).
- Reproduce baseline from a clean checkout with:
  ```sh
  git fetch origin soroswap-perf
  git checkout fe9b7873e
  git submodule update --init --recursive src/rust/soroban/p26
  ```
  After this, both the outer worktree and the p26 submodule worktree are
  clean and contain both accepted optimizations as committed code.

## Timestamp

- Non-Tracy benchmark runs: 2026-04-29T21:54:17Z through 2026-04-29T22:07:35Z
- Diagnostic Tracy run: 2026-04-29T22:21:59Z
- Recorded: 2026-04-29

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `ca0069935a7f-20260429-215417` | sac, TX=6000, T=8 | 333.099159 | 409.899619 | 415.473662 |
| 1 | `ca0069935a7f-20260429-215417` | soroswap, TX=2000, T=8 | 290.766289 | 320.513204 | 326.261744 |
| 2 | `ca0069935a7f-20260429-220101` | sac, TX=6000, T=8 | 314.378531 | 388.362011 | 400.919545 |
| 2 | `ca0069935a7f-20260429-220101` | soroswap, TX=2000, T=8 | 286.738946 | 309.253423 | 320.197842 |
| 3 | `ca0069935a7f-20260429-220735` | sac, TX=6000, T=8 | 316.290692 | 364.102294 | 383.006800 |
| 3 | `ca0069935a7f-20260429-220735` | soroswap, TX=2000, T=8 | 288.663084 | 294.675579 | 305.874426 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run.

## Improvement vs Previous Baseline

Previous baseline (bulk build host storage maps):
- soroswap median average: 300.186 ms
- sac median average: 318.961 ms

Current baseline (typed SAC balance storage fast path, stacked on bulk-build):
- soroswap median average: 288.723 ms — **3.82% improvement**
- sac median average: 321.256 ms — 0.72% regression (inside run-to-run noise;
  baseline 3-run sac spread was ~3%)

Tradeoff ratio (soroswap absolute win ÷ sac absolute loss): 11.463 / 2.295 = **4.99×**, well above the 2× rule-of-thumb. Max-sac regression is 0.72%, well under the 5% ceiling.

All three optimized soroswap medians (290.77 / 286.74 / 288.66 ms) are below
the previous baseline's best run (294.39 ms) — the improvement is supported
across every run, not just the average.

## Diagnostic Tracy Run

- Run id: `ca0069935a7f-20260429-222159`
- Soroswap trace: `/mnt/nvme2/apply-load/ca0069935a7f-20260429-222159/logs/ca0069935a7f-20260429-222159-02-soroswap-tx-2000-t-8.tracy`
- SAC trace: `/mnt/nvme2/apply-load/ca0069935a7f-20260429-222159/logs/ca0069935a7f-20260429-222159-01-sac-tx-6000-t-8.tracy`
- Tracy apply-time numbers from this run are **ignored for the verdict**;
  the headline metric is the average of the three non-Tracy runs above.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/ca0069935a7f-20260429-215417`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/ca0069935a7f-20260429-220101`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/ca0069935a7f-20260429-220735`
- Tracy diagnostic run artifact directory:
  `/mnt/nvme2/apply-load/ca0069935a7f-20260429-222159`

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
The fourth command captured the diagnostic Tracy trace for attribution; its
apply-time numbers are not used for the verdict.

## Worktree Build Note

This baseline was measured in a git worktree, which exposed a worktree
incompatibility in the `src/Makefile.am:267` rule introduced by upstream
PR #5187. A worktree-local fix in `src/Makefile` replaces the pattern rule's
hardcoded `$(top_srcdir)/.git/modules/...` prereq with per-protocol explicit
rules using `git rev-parse --git-path` to resolve the actual submodule
gitdir. The fix is local to the generated Makefile and does not affect the
optimization or the recorded numbers; an upstream patch to PR #5187 would
generalize this for all worktree-based builds.
