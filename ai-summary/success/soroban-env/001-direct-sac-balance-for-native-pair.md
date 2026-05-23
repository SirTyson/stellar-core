# 001: Direct SAC Balance Reads for Native Pair Swap

**Date**: 2026-05-23
**Severity**: Medium
**Impact**: Soroswap median apply time improved 5.18% on average across three non-Tracy apply-load runs
**Subsystem**: soroban-env
**Final review by**: gpt-5.5, high

## Summary

The p26 submodule now bypasses two read-only SAC `balance` subframes in the next-protocol native Soroswap pair `swap` path when the token is confirmed to be a Stellar Asset Contract and the owner is the pair contract. Independent final-review measurements showed soroswap median apply time dropping from 230.225 ms to 218.310 ms on average, a 5.18% improvement; max-sac median regressed 1.24%, within the accepted tradeoff envelope.

## Root Cause

The accepted native pair `swap` emulation still called `call_n_internal(..., "balance", ...)` twice after the output SAC transfer. For the benchmark's native pair shape, both tokens are SAC contracts and the balance owner is always the pair contract, so the read-only SAC frame, internal-call dispatch, argument/result conversion, and full instance clone used only to identify the executable were avoidable. The mandatory behavior is narrower: extend the SAC instance TTL, read the persistent `Balance(pair)` contract-data entry under the token contract id, extend that balance entry's TTL on hit, parse the typed `BalanceValue`, and return zero when the balance entry is missing.

## Reproduction

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` from a next-protocol build. In the soroswap scenario (`TX=2000,T=8`), every successful native pair `swap` now reaches the direct helper for the two post-transfer SAC balance reads; non-SAC tokens, non-contract owners, released p26 ledgers, and non-matching pair calls continue through the existing internal `balance` call path.

## Affected Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` — routes native pair SAC balance reads through the direct helper after confirming the token instance executable is `StellarAsset`.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs` — adds a peek-only executable-discriminant helper to avoid cloning full `ScContractInstance` storage when only SAC-vs-Wasm is needed.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs` — exposes a typed direct contract-owner SAC balance read that preserves balance TTL extension and missing-balance-as-zero behavior.

## Optimization

- **Files modified**: p26 submodule gitlink updated to `fbbea0d9cb33e94fbab331d3d4bf8e69f088f9d4`, on `github.com/SirTyson/rs-soroban-env` branch `poc/001-direct-sac-balance-for-native-pair`.
- **How to verify**:
  1. Build: `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production && make -j30`
  2. Run existing tests: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`
  3. Benchmark: `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times, then run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy` once for diagnostics only.

### Changes Made

`soroswap_pool_invoke_sac_balance` first converts the token address to a contract id and attempts a direct read. The direct path only proceeds for contract-owner addresses whose token instance ledger entry is a valid SAC instance; otherwise it returns `None` and the existing `call_n_internal(..., "balance", ...)` fallback runs unchanged. For confirmed SAC tokens, it extends the SAC instance TTL with the same constants used by SAC `balance`, builds the persistent `Balance(owner_contract)` key for the explicit token contract id, reads/parses `BalanceValue`, extends the balance entry TTL on hit, and returns `0` on a missing balance entry. The new executable check uses `Storage::get` and inspects `instance.executable` by reference, avoiding the full `ScContractInstance` metered clone.

### Benchmark Results

These numbers are from independent final-review runs using `scripts/run_apply_load_matrix.py` without `--tracy`. Smaller is better. The baseline is the prior accepted `ai-summary/CURRENT_STATE.md`.

| Scenario | Baseline medians (ms) | Optimized medians (ms) | Average delta |
|----------|------------------------|-------------------------|---------------|
| soroswap, TX=2000, T=8 | 223.446927 / 240.602642 / 226.625512 | 221.844987 / 217.378587 / 215.707167 | 5.18% faster |
| sac, TX=6000, T=8 | 312.955341 / 316.717310 / 302.742357 | 316.314591 / 316.279749 / 311.369706 | 1.24% slower |

| Run | Scenario | Baseline median | Baseline p95 | Baseline p99 | Optimized median | Optimized p95 | Optimized p99 |
|-----|----------|-----------------|--------------|--------------|------------------|---------------|---------------|
| 1 | sac, TX=6000, T=8 | 312.955341 | 365.764900 | 383.045421 | 316.314591 | 336.797731 | 352.292643 |
| 1 | soroswap, TX=2000, T=8 | 223.446927 | 229.685614 | 240.091432 | 221.844987 | 225.673956 | 227.353551 |
| 2 | sac, TX=6000, T=8 | 316.717310 | 367.398707 | 391.624597 | 316.279749 | 334.009878 | 342.990440 |
| 2 | soroswap, TX=2000, T=8 | 240.602642 | 248.197512 | 251.725105 | 217.378587 | 221.208289 | 224.716387 |
| 3 | sac, TX=6000, T=8 | 302.742357 | 330.107227 | 344.942766 | 311.369706 | 329.543232 | 341.252275 |
| 3 | soroswap, TX=2000, T=8 | 226.625512 | 231.080540 | 232.990802 | 215.707167 | 219.655525 | 226.964780 |

Diagnostic Tracy run, ignored for verdict timing:

- Artifact directory: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230`
- Soroswap trace: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`
- SAC trace: `/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-01-sac-tx-6000-t-8.tracy`

The soroswap win is consistent across all three non-Tracy runs, and all optimized soroswap medians are below all three accepted baseline medians. The max-sac median regression is 1.24%, below the 5% tradeoff threshold and dominated by the 5.18% soroswap median improvement. The diagnostic trace was captured for attribution only; the timing numbers from that run are not part of the comparison.

## Expected vs Actual Behavior

- **Expected**: The native pair `swap` path should observe the same SAC instance TTL extension, balance entry TTL extension, typed balance value, missing-balance-as-zero behavior, and error propagation as SAC `balance`, without pushing read-only SAC frames for the exact native SAC-token pair shape.
- **Actual before**: Every native pair `swap` still invoked SAC `balance` twice through `call_n_internal`, paying subframe, dispatch, conversion, and full instance-clone overhead for read-only balance observations.

## Adversarial Review

1. Exercises claimed inefficiency: YES — the changed helper is called for the two post-transfer balance reads inside the native pair `swap` apply path.
2. Realistic preconditions: YES — the apply-load soroswap workload uses SAC tokens and a contract-owner pair address for these reads.
3. Inefficiency vs by-design: INEFFICIENCY — released p26 behavior is preserved by the existing next-protocol native-pair gate; the direct helper preserves the SAC storage side effects needed by the optimized path.
4. Final severity: Medium — soroswap median apply time improved 5.18% on average, reproducibly across all three non-Tracy runs.
5. In scope: YES — the change affects contract execution during `closeLedger`, not TX-set construction or lazy background bucket work.
6. Benchmark methodology: CORRECT — three non-Tracy matrix runs were compared to the accepted `CURRENT_STATE.md`; the Tracy run was diagnostic only and used the local-build `PATH` prefix.
7. Alternative explanations: UNLIKELY — every optimized soroswap run beat every accepted baseline run, and the source-level change removes per-swap SAC balance subframes on the measured path.
8. Novelty: NOVEL — this builds on native pair `swap` emulation by specializing the remaining SAC balance reads rather than reworking the already-accepted pair dispatch.

## Suggested Follow-Up

If this optimization is prepared for upstream review, add focused host-level equivalence tests for present balance, missing balance, malformed balance value, footprint errors, and non-SAC fallback.
