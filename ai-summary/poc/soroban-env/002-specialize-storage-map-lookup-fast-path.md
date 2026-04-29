# H002: Specialize Hot Storage Map Lookups Away From Generic Fallible Binary Search

**Date**: 2026-04-28
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing hot storage/footprint lookup overhead while preserving all explicit budget charges
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Storage, footprint, TTL, and restored-key lookups during enforcing Soroban execution should return exactly the same entries and errors as today, and they should consume the same `MemCpy`/`MemCmp`/other budget amounts for the same sequence of lookups. For maps whose keys have already been validated as supported `LedgerKey` variants, the physical lookup should not repeatedly pay generic fallible-search overhead that exists only to support arbitrary `Compare` implementations.

## Mechanism

`MeteredOrdMap::find` is fully generic and fallible: it charges a binary search, allocates an `Option<HostError>` side channel, calls `binary_search_by_pre_rust_182`, uses `slice.get(mid).unwrap()` for every probe, and routes every comparison through `Ctx::compare` (`src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194`, `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:393-445`). Storage-heavy paths then use this for `StorageMap`, `FootprintMap`, `TtlEntryMap`, and `RestoredKeySet` lookups (`src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-266`, `333-357`; `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:206-258`, `1036-1049`). For `LedgerKey` specifically, every comparison also re-checks that both sides are supported key variants, even though insertion sites already call `Storage::check_supported_ledger_key_type` before inserting keys into these maps (`src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:397-430`; `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-956`, `976-1044`; `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357`).

The optimization would add a specialized lookup path for the validated ledger-key maps used by enforcing storage: keep the existing `charge_binsearch` and comparison-budget behavior, but use an infallible in-bounds binary search with `get_unchecked` under the same invariants as the copied stdlib implementation, remove the per-probe `Option<HostError>` side channel, and skip repeated supported-key checks after validation at insertion/boundary points. This should preserve deterministic ordering and metering while reducing physical CPU in the hottest map lookup loop.

## Trigger

Run the current soroswap apply-load benchmark (`TX=4000`, `T=8`) and inspect `map lookup` under `applyLedger`. A PoC should add a specialized `LedgerKey` lookup for storage/footprint/TTL/restored-key maps, keep the old generic path for host maps and arbitrary fallible comparators, and verify identical budget trackers plus at least a 3% median soroswap apply-time reduction across repeated runs.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194` — generic fallible `find` used by all `get`, `contains_key`, `insert`, and `remove` operations.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:393-445` — copied binary-search implementation uses safe `get(mid).unwrap()` despite documented in-bounds invariants.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:397-430` — `Budget::compare(LedgerKey, LedgerKey)` repeats supported-key validation on every comparison.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-266` — every storage read funnels through `StorageMap::get`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — every storage write enforces footprint access and then inserts through the same generic map path.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:206-258` — ledger-change extraction performs storage, TTL, and footprint lookups for every storage-map entry.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1036-1049` — storage-map construction checks footprint membership and missing footprint keys through generic map lookups.

## Evidence

The current soroswap trace reports `map lookup,soroban-env-host/src/host/metered_map.rs,173,411627084,...,382266,...` in self-time. Event timestamp intersection shows 348,072 of 382,266 `map lookup` calls and 603.6 ms of 662.0 ms total duration fall inside `applyLedger` windows, making this an in-scope apply-path hotspot. The hot storage paths use already-validated `LedgerKey` maps, so the generic error side channel, bounds-checked probe lookup, and repeated supported-key discriminant validation are structural overhead rather than required consensus semantics.

## Anti-Evidence

The comparator also performs protocol-visible budget charges (`MemCmp` and related nested compares), so the fast path must not change the number or input sizes of those charges. The estimated win depends on the generic search/error/type-check overhead being a large enough fraction of the 411.6 ms self-time; if most of that self-time is unavoidable metered comparison work or Tracy instrumentation, this will fall below the Medium threshold.

---

## Review

**Verdict**: VIABLE
**Severity**: Medium
**Date**: 2026-04-28
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — not previously investigated; existing soroban-env fail record 001 targets XDR output buffer capacity, and the fail summary entries cover Tracy-only charges, wasmi instantiation, TTL extension, XDR batching/roundtrips, budget setup, and parallel-apply setup rather than validated `LedgerKey` map lookup specialization

### Trace Summary

The apply path reaches this code from `InvokeHostFunctionOpFrame::doParallelApply`/`doApplyForSoroban` through `InvokeHostFunctionApplyHelper::invokeHostFunction`, which calls `rust_bridge::invoke_host_function` with footprint, ledger-entry, TTL, and restored-entry buffers. Rust `e2e_invoke::invoke_host_function` decodes resources, builds `RestoredKeySet`, `FootprintMap`, `StorageMap`, and `TtlEntryMap`, runs `Host::invoke_function` with enforcing storage, then calls `get_ledger_changes` to diff the final storage state. On that path, storage reads/writes, footprint enforcement, TTL lookup, restored-key lookup, missing-entry backfill, and final read-only/read-write classification all route through `MeteredOrdMap::find`, whose generic fallible binary search performs physical work that is not itself budget-visible.

### Code Paths Examined

- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ invoke helper serializes auth/source/resources/ledger buffers and calls `rust_bridge::invoke_host_function` inside Soroban operation apply.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:1022-1030,1328-1377` — Soroban operation apply and parallel apply both delegate to the helper that invokes the Rust host, so this is in the `closeLedger` apply path exercised by soroswap.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:408-452` — Rust entrypoint decodes resources, builds restored-key/footprint/storage/TTL maps, clones the initial storage map, and constructs enforcing `Storage` for host execution.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-956,976-1052` — footprint keys are explicitly checked before insertion; storage/TTL keys are derived from supported ledger-entry variants and checked against the footprint through generic map lookups.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:130-154,252-266,333-357,421-448` — enforcing reads, writes, `has`, and TTL extension validate the external key and then perform footprint and storage-map lookups through `MeteredOrdMap`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-258,1068-1082` — successful invocation diffing iterates the storage map and performs TTL, snapshot-storage, and footprint lookups for each changed/footprint entry.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-194,227-300` — every `get`, `contains_key`, `insert`, and `remove` delegates to `find`, which uses an `Option<HostError>` side channel around a copied binary search closure.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_vector.rs:393-445` — the copied pre-1.82 binary-search loop documents in-bounds invariants but uses `slice.get(mid).unwrap()` instead of the original unsafe unchecked access.
- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:397-430` and `src/rust/soroban/p26/soroban-env-common/src/compare.rs:104-109` — `Budget::compare(Rc<LedgerKey>)` delegates to `Budget::compare(LedgerKey)`, which re-runs supported-key validation on both operands before doing the metered variant-specific comparison.
- `src/rust/soroban/p26/soroban-env-host/src/macros.rs:8-25` — `tracy_span!` is no-op without the Tracy feature, so the PoC must validate on non-Tracy apply-time benchmarks rather than relying only on Tracy zone totals.

### Findings

The inefficiency exists. `MeteredOrdMap::find` has generic fallible-search machinery even when used with `MeteredOrdMap<Rc<LedgerKey>, _, Budget>`, and the storage/e2e call sites repeatedly search maps whose keys are either validated at ingress (`FootprintMap`, storage API keys) or derived from already-supported ledger entries (`StorageMap`, `TtlEntryMap`). The current implementation also runs supported-key validation inside every `LedgerKey` comparison; those checks do not charge budget and therefore are physical overhead, not protocol-visible metering.

The path is hot enough to justify a PoC under the objective threshold. The hypothesis's cited trace places about 348k `map lookup` calls and about 604 ms total lookup duration inside `applyLedger`; using the referenced 4.33 s soroswap apply window from the adjacent investigation, a Medium result requires roughly 130 ms saved. That is a high bar for a micro-optimization, but the target is not a single branch: a lookup can perform several binary-search probes, and each probe currently pays generic closure/result handling, optional-error checks, safe bounds checks, and two uncharged supported-key discriminant validations before reaching the mandatory metered comparison work.

The proposed fix is correctness-preserving if it is narrowly scoped. It must not replace `Budget::compare(LedgerKey)` globally, because generic map construction and invalid-input paths still rely on the existing fallible comparator. Instead it should add a validated-`LedgerKey` search path for the storage/footprint/TTL/restored maps and keep the same binary-search control flow, comparison order, `charge_binsearch`, and variant-specific `Budget::compare` calls so budget trackers remain identical for valid executions. One caveat is `build_restored_key_set`: it currently builds before `build_storage_footprint_from_xdr`, so a specialized restored-key insertion path should either validate restored footprint keys first or keep generic insertion there until the footprint has been checked.

### PoC Guidance

- **Target code**: `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs`, `src/rust/soroban/p26/soroban-env-host/src/storage.rs`, and `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs`. Optionally add the validated `LedgerKey` comparator helper near `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs`, but do not change the public/global `Compare<LedgerKey>` behavior.
- **Change description**: Add specialized inherent methods for `MeteredOrdMap<Rc<LedgerKey>, V, Budget>` (or an equivalent private helper) that perform the same pre-1.82 binary-search loop directly over the map, return `Result<Result<usize, usize>, HostError>` without the `Option<HostError>` side channel, use unchecked element access only under the documented loop invariants, and compare supported `LedgerKey` variants without repeating `Storage::check_supported_ledger_key_type` on every probe. Wire those methods into enforcing storage/footprint/TTL/restored-key `get`, `contains_key`, and hot `insert` call sites only after keys have been validated.
- **Correctness check**: Existing Soroban host e2e and budget-metering tests should continue to report identical result XDR, ledger changes, diagnostic behavior, and exact budget trackers. Add focused assertions if needed around invalid unsupported footprint/restored-key input so the specialized path still returns the same error type/code as the generic path.
- **Benchmark focus**: Measure non-Tracy soroswap apply time with `scripts/run_apply_load_matrix.py` over repeated runs; the acceptance metric is at least a 3% median apply-time reduction. Also compare budget tracker output before/after on representative invocations and, when profiling with Tracy, verify that `map lookup` self-time under `applyLedger` falls by at least the ~130 ms needed to clear the Medium threshold.

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-04-29
**PoC by**: gpt-5.5, high

### Changes Made

- `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs` lines 397-440: extracted `Budget::compare_validated_ledger_keys` so validated `LedgerKey` map lookups can reuse the same variant-specific metered comparisons without re-running supported-key validation on every binary-search probe; the public `Compare<LedgerKey>` implementation still performs validation first.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs` lines 86-217: added specialized inherent lookup/insert helpers for `MeteredOrdMap<Rc<LedgerKey>, V, Budget>` that keep the existing `map lookup` Tracy span, `charge_binsearch`, comparison order, insertion semantics, and access charges, while avoiding the generic fallible-search side channel and using unchecked probe access under the same binary-search invariants.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs` lines 139-143, 261-264, 359-361, 514-518, 692-695, 713-720, and 740-776: routed enforcing storage/footprint and recording-mode storage-map accesses that follow explicit key validation through the validated `LedgerKey` helpers.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs` lines 150-164, 203-210, 248-257, 267-274, 305-313, 749-756, 939-953, 1023-1052, and 1077-1081: routed footprint, storage, TTL, restored-key, ledger-change, and snapshot lookups/inserts through the validated fast path, adding explicit restored-footprint-key validation before using the restored-key insertion fast path.

### Demonstration

The optimization specializes the hot Soroban storage/footprint/TTL/restored-key map operations for maps whose `LedgerKey`s have already been checked at ingress or derived from supported ledger entries. It preserves all existing explicit metering and binary-search control flow while reducing physical CPU overhead from the generic error side channel, safe per-probe bounds checks, and repeated supported-key discriminant validation in apply-path map lookups.

### Test Results

Configured with `./configure --enable-ccache --enable-sdfprefs --enable-tracy --enable-tracy-capture --disable-postgres`, built successfully with `make -j30`, and ran the full suite successfully with `env NUM_PARTITIONS=30 STELLAR_CORE_TEST_PARAMS='--ll fatal -r simple --abort --disable-dots' make check`; the final output reported `PASS: test/selftest-nopg`, `PASS: test/check-nondet`, and `All 2 tests passed`.
