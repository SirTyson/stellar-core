# H001: Rc-backed enforcing storage side indexes

**Date**: 2026-05-23
**Subsystem**: soroban
**Severity**: Medium
**Impact**: reduce per-invocation host storage setup and indexed lookup overhead during soroswap apply
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

The enforcing-mode storage side indexes are physical acceleration structures: they should let the host map a footprint/storage `LedgerKey` to its sorted-vector position without changing metering or observable storage behavior. Building those indexes should reuse the already-owned `Rc<LedgerKey>` keys from `Footprint` and `StorageMap`, and lookup should still charge the same `MeteredOrdMap::charge_lookup` / `get_at_known_position` budget as the current indexed path.

## Mechanism

`Storage::with_enforcing_footprint_and_map` currently builds `HashMap<LedgerKey, usize>` indexes by deep-cloning every key from both maps even though the maps already own `Rc<LedgerKey>` keys. Soroswap invokes the host thousands of times per apply run with large, mostly repeated footprints, so these unmetered deep key copies and hashes add setup work before every `invoke_host_function`; using `HashMap<Rc<LedgerKey>, usize>` (or an equivalent borrowed-key/cached-hash index) should remove the repeated key materialization while preserving deterministic lookup order and the existing budget charges.

## Trigger

Run `scripts/run_apply_load_matrix.py --tracy` on the current soroswap baseline and inspect accepted Soroswap invocations. Each `invoke_host_function` builds enforcing storage with side indexes, then hot `storage get` calls use those indexes. A PoC should replace the cloned-key side indexes with Rc-backed indexes, preserve the same budget charge calls, and compare three non-Tracy soroswap runs against the current 215-222 ms median baseline.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:246-272` — `with_enforcing_footprint_and_map` deep-clones footprint and storage keys into `HashMap<LedgerKey, usize>`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:326-352` — `try_get_full_helper` uses the side index and then charges/reads through `get_at_known_position`.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:432-456` — write path uses the same side index for replacement.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:320-343` — indexed lookup already preserves the legacy budget profile.

## Evidence

The current Tracy trace shows the indexed storage path is inside `applyLedger`: `storage get` has 321,802 in-apply events / 672.085 ms aggregate, and `map lookup indexed` has 844,030 events / 441.213 ms aggregate. The index construction itself is not separately zoned, but it is structurally O(footprint) per host invocation and duplicates key ownership that already exists in `Footprint` and `StorageMap`.

## Anti-Evidence

Broad storage zones include mandatory budget charging, XDR decoding, and storage semantics that this change cannot remove. If the deep-clone portion of side-index construction is much smaller than the lookup body, the result may fall below the 3% Medium threshold; the PoC needs a dedicated timing zone around index construction or a non-Tracy benchmark win.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no exact prior Rc-backed side-index clone-removal file found; overlaps retained indexed/fused enforcing-storage failures
**Failed At**: reviewer

### Trace Summary

The Soroban apply path does construct enforcing storage for every host invocation: `InvokeHostFunctionOpFrame` crosses the Rust bridge, `soroban_proto_any::invoke_host_function_or_maybe_panic` creates the per-tx budget, and `e2e_invoke::invoke_host_function` builds the footprint and storage map before installing `Storage::with_enforcing_footprint_and_map`. However the current checked-out p26 storage code does not have enforcing side indexes at all. `Storage` only stores `footprint`, `mode`, and `map`; reads enforce the footprint and then call `StorageMap::get`, while writes call `StorageMap::insert`.

### Code Paths Examined

- `ai-summary/fail/soroban/summary.md:42` — retained prior failure for `002-index-host-storage-map-lookups.md`; indexed host storage-map lookup work changed metering and benchmarked as a regression.
- `ai-summary/fail/soroban/summary.md:93` — retained prior failure for `001-fused-enforcing-storage-map.md`; enforcing footprint/storage-map fusion was real but below Medium after parent/child zone overlap and parallel-worker normalization.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ apply serializes Soroban inputs and invokes the Rust host for each transaction.
- `src/rust/src/soroban_proto_any.rs:391-448` — Rust bridge constructs a per-invocation budget and delegates to the protocol-specific host invocation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:424-451` — host invocation builds `Footprint`, `StorageMap`, clones the initial storage map, and calls `Storage::with_enforcing_footprint_and_map`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:933-1052` — footprint and storage maps are built as `MeteredOrdMap<Rc<LedgerKey>, ...>` values; missing footprint keys are added to storage with `Rc::clone`, not through a side-index table.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:25-27` — `FootprintMap` and `StorageMap` already use `Rc<LedgerKey>` keys.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:178-183` — `Storage` has no `HashMap<LedgerKey, usize>` or side-index fields.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:230-239` — `with_enforcing_footprint_and_map` only stores the supplied footprint and map; it does not build any index or deep-clone keys.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `try_get_full_helper` performs footprint enforcement and calls `self.map.get`, not an indexed lookup.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:333-357` — writes enforce read-write access and replace `self.map` through `MeteredOrdMap::insert`; no side index is used or maintained.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-242` — current lookup is the metered binary-search `find`/`get` path.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:244-249` — the only positional accessor is `get_at_index`; there is no `get_at_known_position` or `map lookup indexed` path in this checkout.

### Why It Failed

The claimed inefficiency does not exist in the reviewed source. There is no enforcing-storage side-index construction in `Storage::with_enforcing_footprint_and_map`, no `HashMap<LedgerKey, usize>` deep clone to replace with `HashMap<Rc<LedgerKey>, usize>`, and no indexed read/write path for the proposed fix to optimize. The hypothesis appears to have been written against a stale or experimental branch that already added storage side indexes, not against the current p26 Soroban host source.

If reframed as "add an indexed enforcing-storage path", it would also run into retained prior failures: indexed/fused enforcing storage changes p26 metering unless exact budget behavior is replayed, and the previously investigated storage-map indexing/fusion family either regressed benchmarks or fell below the optimize-soroswap Medium threshold after correct parallel-worker normalization.

### Lesson Learned

Before proposing a refinement to an optimization layer, verify that the layer exists in the current checkout. The live p26 host still uses `MeteredOrdMap<Rc<LedgerKey>, ...>` binary searches for enforcing storage; storage-index ideas belong to the already-retained indexed/fused enforcing-storage failure family unless they provide new measured evidence and an exact metering plan.
