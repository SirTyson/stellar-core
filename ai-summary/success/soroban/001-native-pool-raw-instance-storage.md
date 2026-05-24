# 001: Native Soroswap Pool Raw Instance Storage

**Date**: 2026-05-24
**Severity**: Medium
**Impact**: 3.15% soroswap median apply-time reduction; SAC median improved 1.63%
**Subsystem**: soroban
**Final review by**: gpt-5.5, high

## Summary

The protocol-27 native Soroswap pool path now keeps fixed-schema instance-storage reads and reserve writes in raw `ScMap` / typed Rust values instead of materializing the generic host `InstanceStorageMap` for the allowlisted pool Wasm. Independent final-review apply-load runs showed all three optimized soroswap medians below the prior accepted baseline, with a 3.15% average soroswap median improvement and no SAC tradeoff.

## Root Cause

The accepted native pool getter/swap emulation avoided Wasm execution, but still paid generic instance-storage costs designed for arbitrary Wasm contracts: full `ScVal` to host `Val` conversion, address/i128 host-object materialization, `MeteredOrdMap` construction, fixed-key lookups, and reserve updates through generic map inserts. For the allowlisted Soroswap pool Wasm, the native path had already validated the storage schema, so these generic representation costs were redundant.

## Reproduction

Run the protocol-27 soroswap apply-load matrix. Each accepted native pool getter or `swap` call reaches the native path from `closeLedger`, validates the pool Wasm hash and fixed storage schema, and then reads keys 0/1/2/3/4/5 from pool instance storage. Before this change, those fixed-schema reads/writes still initialized and mutated the generic instance-storage map.

## Affected Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:794-857` — native pool dispatch moves the loaded `ScContractInstance` into `Frame::NativeContract` instead of metered-cloning the instance again.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:982-1110` — native fixed-key address and i128 readers decode raw `ScMap` values directly on native frames.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1230` — native swap uses raw token addresses for validation and only materializes address host objects for SAC subcalls.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1379-1456` — reserve updates build the final raw `ScMap` directly for keys 2 and 3.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:2001-2026` — frame-pop persistence stores updated native swap instance storage through `store_contract_instance`.

## Optimization

- **Files modified**: `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs` in the p26 submodule.
- **How to verify**:
  1. Build: `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres --enable-next-protocol-version-unsafe-for-production && make -j $(nproc)`
  2. Run existing tests: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`
  3. Benchmark: `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times, then `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy` once for diagnostics only.

### Changes Made

The native pool path now matches getters and swaps before pushing the native frame, then moves the already-loaded contract instance into that frame. Within the frame, fixed u32-key reads use raw `ScMap` helpers for token/factory addresses and reserves, swap reserve reads stay as `i128`, and reserve writes construct the updated `ScMap` directly. The path remains protocol-gated to post-p26 ledgers and still uses the existing TTL extension, SAC transfer/balance, event emission, rollback, and storage persistence flow.

### Benchmark Results

These numbers are from an independent final-review benchmark run using `stellar-rpc-blaster` through `scripts/run_apply_load_matrix.py`. The before numbers are the accepted non-Tracy baseline from `ai-summary/CURRENT_STATE.md`; the after numbers are the three optimized non-Tracy runs from this review.

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Soroswap median apply time | 221.844987 / 217.378587 / 215.707167 ms | 210.682655 / 210.689880 / 212.958390 ms | 3.15% average |
| Soroswap p95 apply time | 225.673956 / 221.208289 / 219.655525 ms | 214.867917 / 214.462785 / 216.851142 ms | Improved all runs |
| Soroswap p99 apply time | 227.353551 / 224.716387 / 226.964780 ms | 217.690226 / 223.178967 / 219.644655 ms | Improved all runs |
| SAC median apply time | 316.314591 / 316.279749 / 311.369706 ms | 318.398808 / 304.752172 / 305.448548 ms | 1.63% average |
| Errors | 0 | 0 | — |

Optimized non-Tracy run output:

```text
Run ID: 8dd3f525748f-20260524-112817
sac,TX=6000,T=8: median=318.39880750000157ms, p95=336.17065459999975ms, p99=360.1546386800003ms
soroswap,TX=2000,T=8: median=210.6826550000025ms, p95=214.86791749999966ms, p99=217.69022599000027ms

Run ID: 8dd3f525748f-20260524-113424
sac,TX=6000,T=8: median=304.7521719999986ms, p95=322.22787434999753ms, p99=330.6001261100002ms
soroswap,TX=2000,T=8: median=210.6898799999999ms, p95=214.46278544999967ms, p99=223.17896723000058ms

Run ID: 8dd3f525748f-20260524-114038
sac,TX=6000,T=8: median=305.44854799999666ms, p95=325.0758114000029ms, p99=352.77272096999644ms
soroswap,TX=2000,T=8: median=212.95839049999995ms, p95=216.85114159999785ms, p99=219.64465533999868ms
```

Diagnostic Tracy run, ignored for verdict timing:

```text
Run ID: 8dd3f525748f-20260524-114704
Soroswap trace: /mnt/nvme2/apply-load/8dd3f525748f-20260524-114704/logs/8dd3f525748f-20260524-114704-02-soroswap-tx-2000-t-8.tracy
SAC trace: /mnt/nvme2/apply-load/8dd3f525748f-20260524-114704/logs/8dd3f525748f-20260524-114704-01-sac-tx-6000-t-8.tracy
```

## Expected vs Actual Behavior

- **Expected**: The protocol-27 native pool path should preserve Soroswap pool getter/swap behavior while avoiding generic host storage representation work for a fixed, already-validated schema.
- **Actual before**: The native path still converted the pool instance `ScMap` into a generic `InstanceStorageMap`, allocated host objects for fixed storage values, and used `MeteredOrdMap` lookups/inserts.
- **Actual after**: The native path reads and writes fixed pool storage through raw `ScMap` helpers, only materializing host objects when values cross existing host/SAC/event interfaces.

## Adversarial Review

1. Exercises claimed inefficiency: YES — the change targets the native Soroswap pool frame path reached by protocol-27 `closeLedger` apply.
2. Realistic preconditions: YES — the benchmark uses the allowlisted Soroswap pool Wasm and fixed instance-storage schema exercised by the objective workload.
3. Inefficiency vs by-design: INEFFICIENCY — the generic map representation is necessary for arbitrary Wasm, but redundant after this narrow native path validates the schema.
4. Final severity: Medium — soroswap median apply time improved 3.15% on average across three non-Tracy runs.
5. In scope: YES — the win is in the Soroban contract apply path under `closeLedger`, not TX-set construction or lazy bucket merge work.
6. Benchmark methodology: CORRECT — final review used the required project matrix command three times without `--tracy`, then captured one diagnostic Tracy run whose timing was ignored.
7. Alternative explanations: UNLIKELY — all three optimized soroswap medians beat every accepted baseline soroswap median, and SAC also improved on average.
8. Novelty: NOVEL — this is a targeted extension of prior native pool emulation that removes raw instance-storage representation overhead.

## Risk and Determinism Notes

The change introduces no parallelism and preserves deterministic raw `ScMap` ordering by cloning existing entries and replacing only reserve keys 2 and 3. It is gated to protocol versions greater than p26, so released p26 behavior is unchanged. The main behavioral risk is native-path semantic drift from the Wasm pool contract; the implementation remains constrained by the existing hash/schema gate and existing native pool tests.

## Suggested Follow-Up

Investigate whether the remaining native pair/pool subcalls still materialize address or i128 host objects that can be delayed until an actual host interface boundary, but only if repeated non-Tracy matrix runs show a top-line soroswap gain.
