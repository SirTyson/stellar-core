# H002: Cache decoded input entry XDR sizes for ledger-change rent accounting

**Date**: 2026-04-30  
**Severity**: Medium  
**Impact**: 3.46% soroswap median apply-time reduction by avoiding redundant old-entry XDR serialization in successful Soroban host invocations  
**Subsystem**: ledger / Soroban host invocation output  
**Final review by**: gpt-5.5, high

## Summary

Confirmed. The p26 host now carries the canonical ingress `LedgerEntry` XDR size metadata from input decoding through ledger-change construction, so `old_entry_size_bytes_for_rent` can be computed without serializing the old entry again. Independent final-review measurements show soroswap median apply time improving from a 288.723 ms baseline average to 278.740 ms, a 3.46% reduction across three non-Tracy matrix runs.

## Root Cause

`build_storage_map_from_xdr_ledger_entries` decoded every input `LedgerEntry` from an already-encoded buffer but discarded that buffer length. Later, `get_ledger_changes` fetched each old entry from the initial snapshot and called `metered_write_xdr` into a temporary `Vec` only to recover the XDR length for rent-size accounting. This repeated serialization did not feed any returned bytes; it only supplied the old rent-size input.

## Reproduction

The inefficiency appears on successful Soroban invoke-host-function transactions with existing footprint entries. C++ supplies encoded ledger-entry buffers to the Rust host, Rust decodes them into enforcing storage, the host executes, and the post-invocation ledger-change path serializes old read-only and read-write entries again while building rent deltas. Soroswap exercises this path heavily because every swap invokes SAC/token contracts with multiple footprint entries.

## Affected Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:get_ledger_changes` — previously serialized old entries solely to compute `old_entry_size_bytes_for_rent`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:build_storage_map_from_xdr_ledger_entries` — now records the ingress XDR size and optional TTL metadata while decoding each input entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:invoke_host_function` — threads positional initial-entry metadata through enforcing-mode ledger-change construction.

## Optimization

- **Files modified**:
  - `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` — added `InitialEntryMetadata`, records input XDR sizes and TTL metadata, aligns metadata by storage-map position, and uses known-position lookups for the initial storage snapshot and footprint access type.
  - `src/rust/soroban/p26/soroban-env-host/src/test/e2e_tests.rs` — updated only recording-mode instruction-count expectations that decrease because the redundant `ValSer` work is no longer performed.
- **How to verify**:
  1. Build: `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres && make -j30`
  2. Run existing tests: `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`
  3. Benchmark: `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` run exactly three times without `--tracy`; run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py --tracy` only after the non-Tracy runs qualify.

### Changes Made

The change stores `xdr_size` and optional `TtlEntry` metadata while decoding input ledger entries. For enforcing storage, it converts the key-indexed metadata into a vector aligned with the fixed storage-map positions, so `get_ledger_changes` can read the initial entry, TTL key hash, and footprint access type by known position. When metadata is present, old rent size is computed as `entry_size_for_rent(old_entry, cached_xdr_size)`; when metadata is absent, the old fallback serialization remains.

This preserves encoded keys, encoded new read-write values, result XDR, events, TTL changes, and rent-size semantics. The budget delta is intentional for p26: the removed old-entry serialization no longer charges `ValSer`, and the test edits are limited to exact numeric recording-mode instruction baselines.

### Benchmark Results

These numbers are from independent final-review benchmark runs using `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py`. The baseline values are the previously accepted `ai-summary/CURRENT_STATE.md` state; the optimized values are the three non-Tracy runs from the promoted PoC source.

| run | baseline run id | baseline sac median_ms | baseline soroswap median_ms | optimized run id | optimized sac median_ms | optimized soroswap median_ms |
|-----|-----------------|------------------------|-----------------------------|------------------|-------------------------|------------------------------|
| 1 | `ca0069935a7f-20260429-215417` | 333.099159 | 290.766289 | `1e0b14a6b879-20260430-154646` | 312.139381 | 278.119725 |
| 2 | `ca0069935a7f-20260429-220101` | 314.378531 | 286.738946 | `1e0b14a6b879-20260430-155304` | 305.929053 | 279.118436 |
| 3 | `ca0069935a7f-20260429-220735` | 316.290692 | 288.663084 | `1e0b14a6b879-20260430-155922` | 335.083649 | 278.981930 |

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Soroswap median average | 288.722773 ms | 278.740030 ms | 3.46% |
| SAC median average | 321.256127 ms | 317.717361 ms | 1.10% |
| Soroswap run consistency | 286.739-290.766 ms | 278.120-279.118 ms | all optimized runs below baseline best |
| Errors | 0 | 0 | - |

Raw final-review benchmark excerpts:

```text
Run 1: sac median=312.139381ms p95=331.1119378ms p99=347.73297729ms
       soroswap median=278.119725ms p95=284.4116475ms p99=295.62591806ms
Run 2: sac median=305.929053ms p95=325.7076216ms p99=337.87651694ms
       soroswap median=279.1184355ms p95=288.663204ms p99=292.85118131ms
Run 3: sac median=335.083649ms p95=386.18358415ms p99=420.10118637ms
       soroswap median=278.981930ms p95=284.71889215ms p99=296.06790953ms
```

Diagnostic Tracy was captured in `/mnt/nvme2/apply-load/1e0b14a6b879-20260430-160627/logs/1e0b14a6b879-20260430-160627-02-soroswap-tx-2000-t-8.tracy`; that run's timing is ignored for the verdict. The diagnostic trace supports the attribution: aggregate `write xdr` work in the soroswap trace dropped from 228,626,166 ns / 185,422 calls in the prior baseline trace to 147,686,586 ns / 152,631 calls in the optimized trace.

## Expected vs Actual Behavior

- **Expected**: The host should compute old-entry rent sizes from the already-available ingress XDR length where possible, without producing throwaway serialized bytes.
- **Actual before**: The old path serialized each existing old entry again during ledger-change construction only to measure the temporary buffer length.

## Adversarial Review

1. Exercises claimed inefficiency: YES — the optimized path is `invoke_host_function` -> `get_ledger_changes`, inside the measured apply path for successful Soroban transactions.
2. Realistic preconditions: YES — soroswap invokes successful SAC/router transactions with multiple existing footprint entries per transaction.
3. Inefficiency vs by-design: INEFFICIENCY — the old serialization produced no returned bytes and only recovered size metadata already present at ingress; the fallback remains for callers without cached metadata.
4. Final severity: Medium — soroswap median apply time improved 3.46% on average across three non-Tracy matrix runs.
5. In scope: YES — the change is in Soroban ledger-change construction during `closeLedger` apply, not TX-set construction or background bucket work.
6. Benchmark methodology: CORRECT — full regression passed first, then three non-Tracy `scripts/run_apply_load_matrix.py` runs were executed with `PATH="$PWD/src:$PATH"`; Tracy was collected only afterward for attribution.
7. Alternative explanations: UNLIKELY — all three optimized soroswap runs are below the prior baseline's best run, and the diagnostic trace shows the targeted `write xdr` work and event count dropping.
8. Novelty: NOVEL — no prior success document covers cached old-entry XDR size metadata in p26 ledger-change construction.

## Risk and Determinism Notes

The change is deterministic and single-thread-local within host invocation output processing. It does not add parallelism, change ledger-entry ordering, or alter emitted ledger changes. The main semantic caveat is p26 budget accounting: successful recording-mode instruction counts decrease because redundant metered serialization is removed; existing tests were updated only for those exact numeric budget baselines.

## Suggested Follow-Up

Look for other post-invocation ledger-change fields that recompute metadata already available at C++/Rust ingress, but avoid adding side maps whose metered lookup cost offsets the saved serialization.
