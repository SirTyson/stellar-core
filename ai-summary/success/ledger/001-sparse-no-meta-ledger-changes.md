# 001: Sparse no-meta ledger changes

**Date**: 2026-05-25
**Severity**: Low
**Impact**: 1.82% average soroswap median apply-time reduction
**Subsystem**: ledger / Soroban host apply path
**Final review by**: gpt-5.5, high

## Summary

The p26 stellar-core apply bridge now uses an apply-only Soroban host result path that omits unused `encoded_key` buffers and drops no-op `LedgerEntryChange` records before Core extracts rent changes and modified ledger entries. The optimization preserves p26 budget accounting by still running the same metered key serialization into a reusable scratch buffer, while reducing unmetered allocation and filtering work in the no-meta apply path.

Independent non-Tracy apply-load runs measured soroswap median apply time improving from a 211.443642 ms baseline average to 207.589903 ms, a 1.82% Low-severity improvement. SAC median was roughly neutral/slightly better on average.

## Root Cause

`e2e_invoke::get_ledger_changes` built a dense `Vec<LedgerEntryChange>` containing every storage-map entry and retained an encoded `LedgerKey` buffer for each entry, even though the stellar-core apply bridge only consumes `encoded_new_value` and TTL-extension information. In no-ledger-close-meta apply-load runs, unchanged read-only footprint entries were pushed into the dense vector and then discarded by `extract_rent_changes` and `extract_ledger_effects`.

## Reproduction

Run the soroswap apply-load workload with transaction metadata disabled. Every successful `InvokeHostFunction` swap returns through `invoke_host_function_or_maybe_panic`, where the bridge computes rent changes and modified ledger-entry buffers from the host's ledger changes; no C++ consumer reads `LedgerEntryChange::encoded_key`.

## Affected Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:get_ledger_changes` — previously retained encoded keys and dense no-op change records for apply-only bridge output.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:invoke_host_function_for_apply` — new apply-only wrapper preserving metering while returning sparse bridge-relevant changes.
- `src/rust/src/soroban_proto_all.rs:p26::invoke_host_function_with_trace_hook_and_module_cache` — routes p26 enforcing-mode stellar-core invocations through the apply wrapper.

## Optimization

- **Files modified**:
  - `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` — added apply mode to reuse a scratch key buffer, preserve metered key serialization, and drop entries that produce neither modified ledger entries nor TTL-extension rent changes.
  - `src/rust/soroban/p26/soroban-env-host/src/test/e2e_tests.rs` — added dense-vs-apply regression coverage proving budget, result, events, and non-noop ledger changes remain equivalent while no-op entries are filtered.
  - `src/rust/src/soroban_proto_all.rs` — switched the p26 bridge wrapper to `invoke_host_function_for_apply`.
- **How to verify**:
  1. Build: `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production && make -j $(nproc)`
  2. Run existing tests: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`
  3. Benchmark: `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times without `--tracy`; then run one diagnostic `--tracy` pass.

### Changes Made

The dense recording/simulation path still returns one `LedgerEntryChange` per footprint entry with populated `encoded_key`. The stellar-core apply path uses `invoke_host_function_for_apply`, which still calls `metered_write_xdr` for every key but writes into a reused scratch buffer instead of retaining the bytes. After all metered per-entry work is complete, apply mode keeps only entries with `encoded_new_value.is_some()` or a TTL extension where `new_live_until_ledger > old_live_until_ledger`; these are exactly the entries consumed by `extract_ledger_effects` and `extract_rent_changes`.

### Benchmark Results

These numbers are from independent benchmark runs by the final reviewer using `scripts/run_apply_load_matrix.py`. The diagnostic Tracy run is not included in the comparison.

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| soroswap median average | 211.443642 ms | 207.589903 ms | 1.82% |
| soroswap p95 average | 215.393948 ms | 211.931085 ms | 1.61% |
| soroswap p99 average | 220.171283 ms | 217.205604 ms | 1.35% |
| SAC median average | 309.533176 ms | 308.897510 ms | 0.21% |

| run | scenario | baseline median_ms | optimized median_ms | optimized p95_ms | optimized p99_ms |
|-----|----------|--------------------|---------------------|------------------|------------------|
| 1 | sac, TX=6000, T=8 | 318.3988075 | 304.7717910 | 324.4614534 | 346.8156259 |
| 1 | soroswap, TX=2000, T=8 | 210.6826550 | 207.0457240 | 210.7548173 | 218.1700961 |
| 2 | sac, TX=6000, T=8 | 304.7521720 | 313.7902940 | 330.7629382 | 357.9009611 |
| 2 | soroswap, TX=2000, T=8 | 210.6898800 | 209.2724275 | 214.0044290 | 215.7058769 |
| 3 | sac, TX=6000, T=8 | 305.4485480 | 308.1304460 | 327.4401032 | 344.8353395 |
| 3 | soroswap, TX=2000, T=8 | 212.9583905 | 206.4515575 | 211.0340098 | 217.7408400 |

Optimized non-Tracy artifact directories:

- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-005811`
- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-010419`
- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011026`

Diagnostic Tracy artifact directory:

- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655`

Diagnostic trace:

- `/mnt/nvme2/apply-load/f5502210f4e4-20260525-011655/logs/f5502210f4e4-20260525-011655-02-soroswap-tx-2000-t-8.tracy`

## Expected vs Actual Behavior

- **Expected**: The apply bridge should return only the rent-relevant and modified ledger entries needed by Core, without retaining dense no-op change records or unused encoded keys.
- **Actual**: The old code retained every `encoded_key` and every no-op `LedgerEntryChange` until downstream bridge filters discarded them.

## Adversarial Review

1. Exercises claimed inefficiency: YES — the p26 bridge path calls the apply wrapper from successful `InvokeHostFunction` transactions during `closeLedger`.
2. Realistic preconditions: YES — apply-load disables transaction metadata and soroswap swaps carry read-only footprint entries that do not produce ledger effects.
3. Inefficiency vs by-design: INEFFICIENCY — dense `encoded_key` output remains for simulation/recording callers, while the apply path preserves metering and only drops data its consumers ignore.
4. Final severity: Low — soroswap median improved 1.82% on average across three non-Tracy runs, with all optimized soroswap medians below the accepted baseline medians.
5. In scope: YES — the change is under `InvokeHostFunction` execution in the measured `closeLedger` apply path.
6. Benchmark methodology: CORRECT — three non-Tracy project matrix runs used `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py`; the separate `--tracy` run was diagnostic only.
7. Alternative explanations: UNLIKELY — the soroswap improvement is present in all three optimized runs and SAC is not meaningfully regressed.
8. Novelty: NOVEL — this stacks on cached old-entry sizes but removes distinct retained key/no-op change output work.

## Risk and Determinism Notes

The optimization does not add parallelism or change execution ordering. The apply vector preserves the dense vector's relative order for all retained entries, and the regression test checks budget, result, events, and non-noop ledger changes against the dense path.

## Suggested Follow-Up

None.
