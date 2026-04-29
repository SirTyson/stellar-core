# H002: Avoid full `MeteredOrdMap` rebuilds for storage-map mutations

**Date**: 2026-04-29
**Subsystem**: crypto
**Severity**: Medium
**Impact**: Apply-time reduction on soroswap by replacing repeated O(n) ordered-map reconstruction in the host storage path with deterministic in-place or delta-based mutation
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

During a Soroban host invocation, reads and writes against the in-memory storage map should preserve deterministic key ordering and metered access semantics without rebuilding the entire ordered vector for every insert, replace, or remove. The final storage state and emitted ledger changes should be identical to the current `MeteredOrdMap` behavior for the same footprint and contract execution.

## Mechanism

`MeteredOrdMap::insert` and `MeteredOrdMap::remove` maintain immutable-style semantics by chaining cloned prefixes/suffixes and calling `from_exact_iter`, which collects a new `Vec`, charges deep clone, and revalidates ordering with adjacent comparisons. Soroswap performs many storage updates inside each contract invocation, so repeated mutations of the same small-to-medium ordered map pay O(n) clone/rebuild costs and repeated comparison/budget work. A storage-specific mutable map or overlay-delta path could keep the base sorted vector immutable, record deterministic replacements/removals in a small ordered delta, and materialize the final sorted map once at `host.try_finish()` / `get_ledger_changes`.

## Trigger

Run the current soroswap apply-load Tracy benchmark and inspect `new map` / storage-map zones under `applyLedger`. Unwrap-mode analysis found all 127,410 `new map` events inside `applyLedger`, with 403,159,898 ns total time and 228,409,843 ns self-time. The same trace shows 754,812 `map lookup` events totaling 1,321,580,918 ns inside `applyLedger`, indicating the storage/map path is hot enough that removing repeated rebuilds can plausibly reduce per-ledger apply time by more than 3%.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:117-160` — `MeteredOrdMap::from_exact_iter` collects a new vector, charges deep clone, and delegates to `from_map` for sorted-unique validation (`new map` Tracy zone).
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225` — `MeteredOrdMap::insert` rebuilds a whole ordered vector for replace and insert cases.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:254-287` — `MeteredOrdMap::remove` rebuilds a whole ordered vector for deletion.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:252-267` — `Storage::try_get_full_helper` funnels hot storage reads through the map layer.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-299` — `get_ledger_changes` later iterates the storage map to produce deterministic ledger changes, providing a natural point to merge a sorted base plus deterministic delta.

## Evidence

The current trace places this work squarely in the measured apply path: `new map` totals 403 ms inside 5.774 s of `applyLedger` time (~7.0%), while its self-time alone is ~4.0% of apply. The implementation makes the structural cost clear: each mutation allocates and clones a complete vector through `from_exact_iter`, even though the host storage map is scoped to one invocation and only needs deterministic final ordering when ledger changes are extracted. A storage-specific overlay could avoid repeated full-vector materialization while retaining binary-search reads against the base map plus a small sorted delta, capped within the existing single invocation and therefore independent of thread count or inter-node scheduling.

## Anti-Evidence

`MeteredOrdMap` is a general metered data structure used beyond storage; replacing it globally would risk changing budget, allocation, and ordering semantics. A viable PoC should specialize only the host storage-map mutation path or introduce an internal storage overlay, then prove that final iteration order and budget accounting remain deterministic. Some of the adjacent `map lookup` and `visit host object` cost is comparison and budget charging rather than rebuild cost, so the measurable win may be closer to the `new map` self-time floor than to the full storage-path total.
