# 002: Specialize Storage Map Lookup Fast Path

**Date**: 2026-04-29
**Severity**: Low
**Impact**: 2.17% average soroswap median apply-time reduction, with p95/p99 also lower across the accepted three-run comparison
**Subsystem**: soroban-env
**Final review by**: gpt-5.5, high

## Summary

The optimization specializes `MeteredOrdMap<Rc<LedgerKey>, V, Budget>` lookups used by Soroban storage, footprint, TTL, and restored-key maps after their keys have already been validated as supported ledger-key variants. Independent non-Tracy apply-load measurements show the soroswap median apply time improving from 311.94 ms average to 305.18 ms average across three runs, so the original Medium claim is downgraded to Low.

## Root Cause

The hot storage map path used the fully generic fallible `MeteredOrdMap::find` loop for validated `LedgerKey` maps. Each binary-search probe paid physical overhead for a side-channel `Option<HostError>`, safe slice access, generic comparator dispatch, and repeated supported-key validation that was not part of protocol-visible metering after ingress validation had already succeeded.

## Reproduction

Soroswap apply executes many enforcing-storage reads, writes, footprint checks, TTL lookups, restored-key checks, and final ledger-change diff lookups during `closeLedger`. These operations repeatedly search `StorageMap`, `FootprintMap`, `TtlEntryMap`, and `RestoredKeySet`, all keyed by supported `LedgerKey` variants in the optimized call sites.

## Affected Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:86-217` — added validated `LedgerKey` lookup, contains, and insert helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:397-440` — split out `Budget::compare_validated_ledger_keys` while preserving public `Compare<LedgerKey>` validation.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154,252-363,505-789` — routed validated storage and footprint operations through the fast path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:142-164,177-319,720-1088` — routed footprint, storage, TTL, restored-key, snapshot, and ledger-change lookups through the fast path.

## Optimization

- **Files modified**:
  - `soroban-env-host/src/host/metered_map.rs` — specialized binary search for validated `LedgerKey` maps, preserving explicit access/search charges and comparison order.
  - `soroban-env-host/src/host/comparison.rs` — reusable validated-key comparator that keeps variant-specific metered comparisons.
  - `soroban-env-host/src/storage.rs` — uses the fast path after `check_supported_ledger_key_type` and related entry validation.
  - `soroban-env-host/src/e2e_invoke.rs` — uses the fast path for validated footprint/storage/TTL/restored-key construction and diffing.
- **How to verify**:
  1. Build: `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres && make -j $(nproc)`
  2. Run existing tests: `env NUM_PARTITIONS=30 make check`
  3. Benchmark: `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` three times, then `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy` once for diagnostic trace capture only.

### Changes Made

The change keeps the generic map implementation unchanged for arbitrary key/comparator pairs. It adds inherent methods for `MeteredOrdMap<Rc<LedgerKey>, V, Budget>` that perform the same pre-Rust-1.82 binary-search control flow, charge the same `map lookup` and access costs, and use the same variant-specific metered comparisons. The fast path is only used at call sites where the `LedgerKey` has been validated or derived from a supported `LedgerEntry`; restored footprint keys are explicitly validated before insertion.

### Benchmark Results

These numbers are from independent final-review runs using `scripts/run_apply_load_matrix.py` without `--tracy`. The diagnostic Tracy run was executed only to capture traces and is not included in the comparison.

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Soroswap median apply time, average of 3 runs | 311.938815 ms | 305.175388 ms | 2.17% |
| Soroswap p95 apply time, average of 3 runs | 327.728556 ms | 313.216405 ms | 4.43% |
| Soroswap p99 apply time, average of 3 runs | 332.809163 ms | 322.680954 ms | 3.04% |
| Max-sac median apply time, average of 3 runs | 340.549446 ms | 333.929242 ms | 1.94% |
| Errors | 0 | 0 | — |

Before measurements from prior accepted `ai-summary/CURRENT_STATE.md`:

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `a645620fe528-20260428-233312` | sac, TX=6000, T=8 | 374.7747420000005 | 420.67973859999796 | 441.66502910999833 |
| 1 | `a645620fe528-20260428-233312` | soroswap, TX=2000, T=8 | 314.3531645000003 | 335.76203330000004 | 343.5404278100001 |
| 2 | `a645620fe528-20260428-234023` | sac, TX=6000, T=8 | 316.10224200000084 | 350.98036009999595 | 370.06274168000334 |
| 2 | `a645620fe528-20260428-234023` | soroswap, TX=2000, T=8 | 311.7416195000005 | 323.9066271000003 | 328.4619910800045 |
| 3 | `a645620fe528-20260428-234654` | sac, TX=6000, T=8 | 330.77135400000043 | 355.597785350002 | 375.3653804600006 |
| 3 | `a645620fe528-20260428-234654` | soroswap, TX=2000, T=8 | 309.7216619999999 | 323.5170060500009 | 326.42506947000055 |

After measurements:

| run | run id | scenario | median_ms | p95_ms | p99_ms |
|-----|--------|----------|-----------|--------|--------|
| 1 | `1695facd04c8-20260429-010922` | sac, TX=6000, T=8 | 335.604147 | 380.9146780499999 | 397.19659729000057 |
| 1 | `1695facd04c8-20260429-010922` | soroswap, TX=2000, T=8 | 313.2552390000019 | 318.90259645000066 | 325.0410912499998 |
| 2 | `1695facd04c8-20260429-011626` | sac, TX=6000, T=8 | 340.83282399999916 | 392.9254198499973 | 406.91980039999913 |
| 2 | `1695facd04c8-20260429-011626` | soroswap, TX=2000, T=8 | 297.3798060000008 | 305.59124730000076 | 319.14616032999714 |
| 3 | `1695facd04c8-20260429-012311` | sac, TX=6000, T=8 | 325.35075399999914 | 378.40040670000093 | 390.30781033999585 |
| 3 | `1695facd04c8-20260429-012311` | soroswap, TX=2000, T=8 | 304.8911174999994 | 315.1553698499934 | 323.8556112200008 |

Diagnostic trace artifacts:

- `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-01-sac-tx-6000-t-8.tracy`
- `/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/1695facd04c8-20260429-013014-02-soroswap-tx-2000-t-8.tracy`

## Expected vs Actual Behavior

- **Expected**: validated Soroban storage maps should perform deterministic metered lookups without redoing generic fallible-search machinery that is unnecessary for supported `LedgerKey` variants.
- **Actual**: the old implementation used the generic fallible map lookup path for these hot storage maps, repeating unmetered validation and side-channel error handling on every search probe.

## Adversarial Review

1. Exercises claimed inefficiency: YES — the modified call sites are storage/footprint/TTL/restored-key lookups in the Soroban invoke and ledger-change paths under `closeLedger`.
2. Realistic preconditions: YES — soroswap performs many Soroban storage operations and final storage diff lookups in normal apply.
3. Inefficiency vs by-design: INEFFICIENCY — the public comparator still validates arbitrary inputs; only already-validated internal map paths skip repeated validation.
4. Final severity: Low — average soroswap median apply time improved 2.17%, below the original Medium threshold but above the Low threshold.
5. In scope: YES — the changed work is in Soroban host execution and ledger-change extraction under apply, not TX-set construction or background bucket merge work.
6. Benchmark methodology: CORRECT — three authoritative non-Tracy `run_apply_load_matrix.py` runs were compared to the accepted baseline; the Tracy run was diagnostic-only.
7. Alternative explanations: LOW RISK — the first optimized median run was close to the old baseline, but the three-run distribution and p95/p99 soroswap results shifted lower while max-sac median did not regress.
8. Novelty: NOVEL.

## Suggested Follow-Up

Investigate whether the same validated-key fast-path idea is beneficial in newer or future Soroban protocol trees after p26, but only if the benchmark continues to show a measurable apply-time signal.
