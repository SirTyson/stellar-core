# H001: In-Place Value Mutation for Enforcing-Mode StorageMap Writes

**Date**: 2026-04-29
**Subsystem**: soroban / soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in host storage write path
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

In enforcing mode, the per-invocation `StorageMap` has a fixed key set
declared by the transaction footprint and validated up-front in
`build_storage_map_from_xdr_ledger_entries`. A host-function write
(`put_contract_data`, TTL extension) should locate the existing slot for the
key and replace the value cell in place — an O(log n) lookup plus O(1)
write — while still charging the same per-write budget items
(`charge_access`, `charge_binsearch`, key/value clone charges) and
preserving sorted iteration for `get_ledger_changes` and rollback.

## Mechanism

`MeteredOrdMap::insert`
(`src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225`)
is a persistent-data-structure update: even when the key already exists, it
reconstructs the whole sorted `Vec<(K, V)>` via `from_exact_iter` (line 209),
which `iter().take(replace_pos).cloned().chain(...).chain(skip(...).cloned())`
and then `Vec::collect` into a fresh allocation, charging
`charge_deep_clone` over the full map size. `Storage::put_opt_helper`
(`src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357`) calls
`self.map.insert(key, Some((entry, live)))` for every host write, so each
SAC `put_contract_data` triggers a full O(n) map rebuild even though the key
is guaranteed to already be present in enforcing mode (the footprint was
fully populated by `build_storage_map_from_xdr_ledger_entries`,
`e2e_invoke.rs:959-1052`).

For soroswap, every swap path issues several SAC balance writes that go
through this insert path, so the apply-time tax is `(footprint_size *
per-tx-writes * per-swap-writes)` shallow clones plus a metered allocator
charge per write. An enforcing-mode-only storage map that exposes
`replace_at(idx, V)` for the always-present key would keep the canonical
sorted vector and the same metering inputs but eliminate the O(n) Vec
rebuild on every write.

The fix is correctness-preserving because: (1) iteration order is
unchanged (vector is the same); (2) `Storage::with_enforcing_footprint_and_map`
clones the initial map for diffing in `get_ledger_changes`, so the original
state is preserved for rollback / change computation; and (3) the keys never
change in enforcing mode — only the value cell does — so `Rc<LedgerKey>`
identities remain stable.

## Trigger

Run the soroswap apply-load matrix
(`scripts/run_apply_load_matrix.py`, soroswap TX=2000, T=8). The PoC
should add an enforcing-mode `StorageMap` wrapper that retains the
canonical `Vec<(Rc<LedgerKey>, V)>` for iteration and rollback, but routes
`put_opt_helper` writes through an in-place value replacement when the
key already exists (the common case in enforcing mode). All metering
charges (`charge_access`, `charge_binsearch`, key/value clone charges)
must be preserved and validated against existing host storage and metering
tests; `get_ledger_changes` output, rollback semantics, and rent inputs
must remain bit-identical.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:196-225` —
  `MeteredOrdMap::insert` always rebuilds the entire `Vec<(K, V)>` via
  `from_exact_iter`, even on key replacement.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:144-166` —
  `from_exact_iter` allocates a new `Vec`, iterates and clones the source,
  then calls `charge_deep_clone` over the full size.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:332-357` —
  `Storage::put_opt_helper` is the enforcing-mode write entry point and
  calls `self.map.insert(...)` for every host write.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs:693-720` —
  enforcing read preparation lives next to the write path; both use the
  generic `MeteredOrdMap` with no in-place mutation.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:959-1052` —
  `build_storage_map_from_xdr_ledger_entries` populates the storage map
  with every footprint key (including `None` for missing rw entries),
  guaranteeing key presence at write time.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:44-199`
  — SAC `spend_balance` / `receive_balance` are the dominant soroswap
  callers of `put_contract_data`, each triggering the rebuild path.

## Evidence

The reference soroswap Tracy trace
(`/mnt/nvme2/apply-load/1695facd04c8-20260429-013014/logs/...02-soroswap-tx-2000-t-8.tracy`)
reports `new map,soroban-env-host/src/host/metered_map.rs,150` at
**228,409,843 ns self-time** across **110,705 calls** (mean 2,063 ns each).
This is `from_exact_iter`, the rebuild step every `MeteredOrdMap::insert`
goes through. The same trace shows `storage get` at 161 M ns / 176,910
calls and `extend_current_contract_instance_and_code_ttl` at 175 M ns /
13,301 calls — both write-adjacent. The path is an `applyLedger`
descendant via `applySorobanStageClustersInParallel` →
`InvokeHostFunctionOpFrame::doParallelApply` → `invoke_host_function` →
SAC `transfer` → `put_contract_data` → `Storage::put_opt_helper` →
`MeteredOrdMap::insert` → `from_exact_iter`.

Estimated apply-time impact: 228 ms (from `new map` self-time alone) is
~2.2% of the 10.2 s trace; combined with the secondary
`charge_deep_clone`/allocator-pressure savings (each rebuild charges the
budget across the full map and allocates a fresh `Vec`), and accounting
for the parallel-worker amortization, the wall-clock apply-time win on
the apply-thread critical path is plausibly in the 3–6% Medium range.

## Anti-Evidence

`MeteredOrdMap` is a generic structure shared with `FootprintMap`,
`HostMap` (guest-visible immutable maps), and the TTL/restored-keys maps;
the optimization must NOT change `HostMap` semantics, since guest code
relies on persistent (immutable) clone-on-write behavior. The fix should
be a storage-specific specialization (or an in-place variant exposed only
to `Storage::put_opt_helper`).

Budget metering must remain bit-identical: today, each `insert` charges
`charge_deep_clone` across the entire map. Replacing the rebuild with an
in-place write changes the metering input for that path, which changes
deterministic results unless the new path replicates the same charges
(e.g., still calls `charge_deep_clone` with the same input length even
though it doesn't actually clone). The PoC must preserve the exact
charge inputs to be consensus-safe.

The reviewed `H002: Add an Indexed Read Path for Enforcing Host Storage
Maps` (`ai-summary/reviewed/soroban/002-index-host-storage-map-lookups.md`)
covers the read side and the lookup-side of writes. It does NOT replace
the underlying `MeteredOrdMap::insert` rebuild — its PoC guidance routes
`put_opt_helper` lookups through the index but keeps the canonical map's
mutation strategy intact. This hypothesis is complementary, targeting the
distinct rebuild-on-insert cost.
