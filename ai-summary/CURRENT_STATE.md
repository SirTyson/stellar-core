# CURRENT_STATE — Soroswap Optimization Baseline

This is the accepted current baseline for the soroswap-performance arc after
confirming native Soroswap pair swap emulation
(`soroban-env/001-native-soroswap-pair-swap`), stacked on top of complete
native Soroswap pool getter emulation, protocol-gated host metering coalescing,
cached old-entry XDR size metadata, typed SAC balance storage fast path, and
bulk-build host footprint/storage-map optimizations.

## Commit

- p26 submodule SHA: `03d78248be2271e57e657150cf2e51e720264492`
  ("poc 001-native-soroswap-pair-swap"), committed on the SirTyson fork at
  branch
  [`poc/001-native-soroswap-pair-swap`](https://github.com/SirTyson/rs-soroban-env/tree/poc/001-native-soroswap-pair-swap).
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
- Outer branch: `soroswap-perf` on the SirTyson stellar-core fork.
- Source/benchmark outer commit SHA on `soroswap-perf`:
  `199622df4ac723ad2e2738c307ea5017a69500bb`
  (`perf(soroban-env): enable native soroswap pair swap`), recording the p26
  gitlink at `03d78248be2271e57e657150cf2e51e720264492`.
- Reproduce this baseline from a clean checkout with:
  ```sh
  git fetch origin soroswap-perf
  git checkout 199622df4ac723ad2e2738c307ea5017a69500bb
  git submodule update --init --recursive src/rust/soroban/p26
  ```

## Timestamp

- Non-Tracy benchmark runs: 2026-05-22T11:24:29Z through 2026-05-22T11:37:04Z
- Diagnostic Tracy run: 2026-05-22T11:43:38Z
- Recorded: 2026-05-22

## Apply-time results (authoritative non-Tracy runs)

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `183979915cef-20260522-112429` | sac, TX=6000, T=8 | 312.955341 | 365.764900 | 383.045421 |
| 1 | `183979915cef-20260522-112429` | soroswap, TX=2000, T=8 | 223.446927 | 229.685614 | 240.091432 |
| 2 | `183979915cef-20260522-113045` | sac, TX=6000, T=8 | 316.717310 | 367.398707 | 391.624597 |
| 2 | `183979915cef-20260522-113045` | soroswap, TX=2000, T=8 | 240.602642 | 248.197512 | 251.725105 |
| 3 | `183979915cef-20260522-113704` | sac, TX=6000, T=8 | 302.742357 | 330.107227 | 344.942766 |
| 3 | `183979915cef-20260522-113704` | soroswap, TX=2000, T=8 | 226.625512 | 231.080540 | 232.990802 |

Use all three non-Tracy runs above as the reference baseline for future
comparisons. Do not replace them with a single best run or an average-only
summary.

## Improvement vs Previous Baseline

Previous accepted baseline (complete native Soroswap pool getter emulation):
- soroswap median average: 250.698585 ms
- sac median average: 303.891414 ms

Current baseline (native Soroswap pair swap emulation):
- soroswap median average: 230.225027 ms — **8.17% improvement**
- sac median average: 310.805003 ms — **2.28% regression**

All three optimized soroswap medians (223.447 / 240.603 / 226.626 ms) are below
all three previous baseline medians (248.944 / 249.635 / 253.517 ms), so the
headline improvement is supported across every run. Max-sac median regressed by
2.28% on average, which is below the 5% tradeoff limit and is dominated by the
8.17% soroswap win. Max-sac p95/p99 values were noisier and regressed more than
the median; they are recorded above for future comparison.

## Diagnostic Tracy Run

- Run id: `183979915cef-20260522-114338`
- Soroswap trace:
  `/mnt/nvme2/apply-load/183979915cef-20260522-114338/logs/183979915cef-20260522-114338-02-soroswap-tx-2000-t-8.tracy`
- SAC trace:
  `/mnt/nvme2/apply-load/183979915cef-20260522-114338/logs/183979915cef-20260522-114338-01-sac-tx-6000-t-8.tracy`
- Tracy apply-time numbers from this run are **ignored for the verdict**; the
  headline metric is the three non-Tracy runs above.
- Diagnostic attribution: the source-level change removes the pair `swap` Wasm
  frame for exact hash/symbol/arity matches inside `call_contract_fn`, while
  preserving SAC `transfer` and `balance` subcalls through `call_n_internal`.
  The top-line non-Tracy apply-time result remains the source of truth.

## Artifact Paths

- Non-Tracy run 1 artifact directory:
  `/mnt/nvme2/apply-load/183979915cef-20260522-112429`
- Non-Tracy run 2 artifact directory:
  `/mnt/nvme2/apply-load/183979915cef-20260522-113045`
- Non-Tracy run 3 artifact directory:
  `/mnt/nvme2/apply-load/183979915cef-20260522-113704`
- Tracy diagnostic run artifact directory:
  `/mnt/nvme2/apply-load/183979915cef-20260522-114338`

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
