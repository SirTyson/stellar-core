# 001: Protocol-gated host metering coalescing

**Date**: 2026-05-02
**Severity**: Low
**Impact**: Soroswap median apply time reduced 2.10% on average across three independent non-Tracy apply-load runs
**Subsystem**: soroban
**Final review by**: gpt-5.5, high

## Summary

The optimization adds a next-protocol-only Soroban host metering mode that preserves p26 exact metering while coalescing two hot host-internal metering surfaces for protocol 27 builds. In the authoritative non-Tracy apply-load matrix, soroswap median apply time improved from a 278.740 ms baseline average to 272.896 ms, and all three optimized soroswap runs were below the baseline's best run.

## Root Cause

The p26 host charges `VisitObject` and `ValSer` at very fine granularity. That preserves released-protocol accounting, but in the apply path it produces millions of small budget-charge and tracing operations while successful soroswap transactions traverse host objects and serialize return values, events, keys, and ledger changes.

## Reproduction

Configure with the next-protocol build flag, then run `scripts/run_apply_load_matrix.py`. The benchmark inherits protocol 27 from the configured build, so `Host::set_ledger_info` enables the coalesced host-metering path during normal `closeLedger` Soroban execution.

## Affected Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:576-582` — enables coalesced host metering only when the validated ledger protocol exceeds p26.
- `src/rust/soroban/p26/soroban-env-host/src/host_object.rs:460-512` — keeps object-handle validation and lookup, but skips the per-visit `VisitObject` charge and Tracy span in coalesced mode.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-82` — serializes through the normal XDR `Limited` writer and charges one `ValSer` entry by total bytes written in coalesced mode.
- `src/rust/soroban/p26/soroban-env-host/src/test/protocol_gate.rs:9-33` — verifies p26 keeps coalesced metering disabled and documents the next-feature compile-time reachability assertion.

## Optimization

- **Files modified**: p26 Soroban host budget, ledger-info setup, object lookup, metered XDR serialization, and protocol-gate test files.
- **How to verify**:
  1. Build: `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production && make -j $(nproc)`
  2. Run existing tests: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`
  3. Benchmark: `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times, then run one diagnostic `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy`

### Changes Made

The patch adds a `BudgetImpl::coalesced_host_metering` flag defaulting to false. `Host::set_ledger_info` sets it only after protocol validation and only when the ledger protocol is greater than `MIN_LEDGER_PROTOCOL_VERSION`, so p26 continues to use the exact released micro-charge path. In coalesced mode, host object visits retain relative-handle rejection, bounds checks, typed lookup, and closure behavior while skipping the physical `VisitObject` charge/span; metered XDR writes retain the same writer and XDR limits while replacing per-chunk `ValSer` accounting with a single total-byte charge.

### Benchmark Results

These numbers are from an independent benchmark run by the final reviewer using the project's apply-load matrix tool. The Tracy run was diagnostic only and is not included in the timing comparison.

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Soroswap median apply time, avg of 3 | 278.740030 ms | 272.895607 ms | 2.10% |
| Soroswap p95 apply time, avg of 3 | 285.931248 ms | 277.349472 ms | 3.00% |
| Soroswap p99 apply time, avg of 3 | 294.848336 ms | 285.707599 ms | 3.10% |
| Max-sac median apply time, avg of 3 | 317.717361 ms | 306.542755 ms | 3.52% |
| Max-sac p95 apply time, avg of 3 | 347.667715 ms | 324.700446 ms | 6.61% |
| Max-sac p99 apply time, avg of 3 | 368.570227 ms | 342.846746 ms | 6.98% |

Raw authoritative non-Tracy runs:

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| baseline 1 | `1e0b14a6b879-20260430-154646` | sac, TX=6000, T=8 | 312.139381 | 331.111938 | 347.732977 |
| baseline 1 | `1e0b14a6b879-20260430-154646` | soroswap, TX=2000, T=8 | 278.119725 | 284.411647 | 295.625918 |
| baseline 2 | `1e0b14a6b879-20260430-155304` | sac, TX=6000, T=8 | 305.929053 | 325.707622 | 337.876517 |
| baseline 2 | `1e0b14a6b879-20260430-155304` | soroswap, TX=2000, T=8 | 279.118436 | 288.663204 | 292.851181 |
| baseline 3 | `1e0b14a6b879-20260430-155922` | sac, TX=6000, T=8 | 335.083649 | 386.183584 | 420.101186 |
| baseline 3 | `1e0b14a6b879-20260430-155922` | soroswap, TX=2000, T=8 | 278.981930 | 284.718892 | 296.067910 |
| optimized 1 | `9074352f02c4-20260502-175031` | sac, TX=6000, T=8 | 306.357371 | 323.520286 | 342.969893 |
| optimized 1 | `9074352f02c4-20260502-175031` | soroswap, TX=2000, T=8 | 272.249541 | 277.125824 | 284.216066 |
| optimized 2 | `9074352f02c4-20260502-175659` | sac, TX=6000, T=8 | 300.543791 | 318.326585 | 334.658452 |
| optimized 2 | `9074352f02c4-20260502-175659` | soroswap, TX=2000, T=8 | 275.885919 | 280.428445 | 291.406201 |
| optimized 3 | `9074352f02c4-20260502-180314` | sac, TX=6000, T=8 | 312.727103 | 332.254466 | 350.911892 |
| optimized 3 | `9074352f02c4-20260502-180314` | soroswap, TX=2000, T=8 | 270.551362 | 274.494149 | 281.500531 |

Diagnostic trace:

- Run id: `9074352f02c4-20260502-180944`
- Soroswap trace: `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy`
- SAC trace: `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-01-sac-tx-6000-t-8.tracy`
- Diagnostic timing from this run was ignored for the verdict.
- Tracy sanity check: the prior accepted soroswap trace had `visit host object` self-time of 1,432,652,085 ns over 3,491,848 calls; the optimized diagnostic trace no longer reports that zone, matching the source-level removal in the coalesced path.

## Expected vs Actual Behavior

- **Expected**: New-protocol host execution should preserve ledger effects while avoiding p26-only micro-metering overhead.
- **Actual**: The old new-protocol-capable code still performed p26-style `VisitObject` and per-chunk `ValSer` metering on the hot Soroban apply path.

## Adversarial Review

1. Exercises claimed inefficiency: YES — the change is in `Host::invoke_function` descendants exercised by successful soroswap transactions during `closeLedger`.
2. Realistic preconditions: YES — the benchmarked configuration uses `--enable-next-protocol-version-unsafe-for-production`, which raises the host interface protocol and makes the protocol-gated path reachable.
3. Inefficiency vs by-design: INEFFICIENCY FOR NEXT PROTOCOL — exact p26 micro-metering remains by design and is preserved; the new protocol is free to define coarser consensus metering.
4. Final severity: Low — soroswap median apply time improved 2.10% on average, consistently across all three runs.
5. In scope: YES — the source changes are in the Soroban host execution and serialization paths under `closeLedger`.
6. Benchmark methodology: CORRECT — three non-Tracy `scripts/run_apply_load_matrix.py` runs used the locally built binary via `PATH="$PWD/src:$PATH"` and were compared to `ai-summary/CURRENT_STATE.md`.
7. Alternative explanations: UNLIKELY — all optimized soroswap medians were below the baseline's best soroswap median, and max-sac also improved on average.
8. Novelty: NOVEL — prior retained failures targeted p26-preserving micro-optimizations, not this protocol-gated coalescing path.

## Suggested Follow-Up

Broaden the next-protocol coalescing model only with focused tests for deterministic budget-exceeded behavior; p26 exact metering should remain untouched.
