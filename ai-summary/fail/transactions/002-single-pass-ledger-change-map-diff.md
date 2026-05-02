# H002: Single-Pass Ledger-Change Diff over Sorted Host Storage Maps

**Date**: 2026-05-02
**Subsystem**: transactions
**Severity**: Medium
**Impact**: soroswap apply-time reduction by removing repeated post-invocation storage/footprint map searches
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

After each successful Soroban invocation, stellar-core should emit the exact same ledger changes, TTL changes, encoded keys/new values, rent-size inputs, and metered XDR/budget consumption that the current `get_ledger_changes` path emits. The extraction phase should compare final storage against the initial snapshot and footprint deterministically, but it should not repeatedly binary-search several sorted maps for every storage entry when those maps share the same ledger-key ordering.

## Mechanism

`get_ledger_changes` iterates `storage.map`, then performs separate ordered-map lookups for the TTL entry, the initial storage snapshot, the footprint access type, and restored-key membership. `StorageMapSnapshotSource::get` adds another `StorageMap::get` lookup for the same key. In enforcing mode, these maps are all built from the transaction footprint and ledger-entry vectors before invocation, so their key order is deterministic and can be traversed with a merge iterator or pre-annotated storage records. The actual behavior pays repeated binary-search/comparison costs in the apply path; a single-pass diff that carries access type, old entry/live-until, TTL hash, and restored status alongside each storage entry should preserve output while reducing post-invocation map churn.

## Trigger

Run the current soroswap apply-load scenario (`soroswap, TX=2000, T=8`) and inspect successful host invocations with multiple SAC balance keys in their footprint. The repeated lookup pattern is triggered for every successful invocation when `host.try_finish()` returns storage and `get_ledger_changes` materializes changes for all entries in `storage.map`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-291` — `get_ledger_changes` iterates `storage.map` and repeatedly queries TTL, snapshot, footprint, and restored-key maps.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:494-508` — successful invocations construct a `StorageMapSnapshotSource` and immediately call `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1082` — `StorageMapSnapshotSource::get` performs an additional ordered-map lookup into the initial storage map.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:168-190` — each map lookup performs a charged binary search and host key comparisons.

## Evidence

The current soroswap Tracy trace shows this work inside `applyLedger`: `map lookup`/`map lookup indexed` zones total 1,023,076,910 ns across 961,422 events inside the 70 apply windows, while `storage get` totals 453,518,609 ns and successful invocation output still performs `write xdr` for 152,109 events / 147,206,949 ns. The source loop in `get_ledger_changes` performs multiple lookups per storage entry after the host has already built the footprint and storage maps from sorted deterministic inputs. This makes the candidate a structural post-invocation optimization rather than a TX-set-construction artifact.

## Anti-Evidence

Some of the aggregate `map lookup` time comes from contract execution itself, not just `get_ledger_changes`, because the existing Tracy zones are at the generic map helper. A PoC must add finer attribution or compare before/after traces to prove the post-invocation diff accounts for a Medium-tier share. The change also must preserve exact budget charging for map scans/lookups and XDR serialization; if the physical searches are removed, equivalent consensus-visible charges may still need to be applied explicitly.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-02
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

The repeated lookup pattern exists: after a successful host invocation, `invoke_function` calls `host.try_finish()`, constructs a `StorageMapSnapshotSource`, and `get_ledger_changes` walks `storage.map` while separately probing the TTL map, initial storage map, footprint map, and restored-key set. Those lookups are on the Soroban parallel-apply worker path reached from `LedgerManagerImpl::applyThread` through `InvokeHostFunctionOpFrame::doParallelApply` and the Rust bridge. However, the cited 1.023s `map lookup` total is an aggregate across all worker threads and all generic map lookups inside the 70 apply windows, not an isolated serial cost of ledger-change diffing. With the active `soroswap, TX=2000, T=8` benchmark, even removing the entire aggregate `map lookup` total would convert to only about 128ms of critical-path wall time, roughly 2.5% of the cited 5.09s `applyLedger` windows, and the post-invocation diff is only a subset of that.

### Code Paths Examined

- `scripts/run_apply_load_matrix.py:120-124,417-423` — the active soroswap scenario runs `TX=2000` with `thread_count=8`, which is written to `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`.
- `src/simulation/ApplyLoad.cpp:2672-2682,3389-3393` — soroswap creates one token pair per configured cluster and round-robins swaps across pairs, so worker-path zone totals must be converted from aggregate parallel work to critical-path wall time.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520,2530-2574` — each stage launches one async worker per cluster, each worker calls `parallelApply` for its cluster, and the main apply path waits on the futures.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1378` — parallel invoke-host-function application dispatches each Soroban transaction to the Rust bridge from the worker path.
- `src/rust/src/soroban_invoke.rs:7-38` and `src/rust/src/soroban_proto_any.rs:429-488` — the bridge invokes the protocol-specific host, then reads budget counters and extracts rent and modified ledger effects from `ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:426-452,485-508` — enforcing storage and an initial storage snapshot are built, the host invocation runs, and successful results immediately call `get_ledger_changes`.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:183-291` — `get_ledger_changes` scans `storage.map`, writes encoded keys/values, looks up TTL entries, looks up the initial snapshot, looks up footprint access type, and optionally checks restored-key membership.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:1068-1082` — `StorageMapSnapshotSource::get` performs the additional initial-storage `StorageMap::get` lookup for each key.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_map.rs:63-83,168-190,227-242,294-314` — `get` and `contains_key` perform charged binary searches, while `iter` performs a charged scan; these charges and comparison calls contribute consensus-visible budget usage.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:16-24` and `src/rust/soroban/p26/soroban-env-host/src/host/comparison.rs:397-430` — XDR serialization and ledger-key comparison are metered, so a correctness-preserving physical fast path cannot simply delete the logical work without preserving budget effects.

### Why It Failed

The inefficiency exists but does not satisfy the optimize-soroswap Medium severity threshold. The hypothesis cites 1,023,076,910 ns of generic `map lookup` time across 70 apply windows, but in the configured soroswap workload that is parallel worker aggregate time over 8 clusters; the whole aggregate bounds to about 127,884,614 ns of critical-path wall time, or about 2.51% of the cited 5,092,107,609 ns `applyLedger` total. The actual recoverable amount is lower because many `map lookup` events occur during contract execution and storage access, not in `get_ledger_changes`, and because exact budget charging and XDR serialization must remain. Under the objective-specific rules, Low-tier or sub-3% findings are rejected even when the local optimization target is real.

### Lesson Learned

Post-invocation Soroban ledger-change extraction is a valid place to look for unnecessary ordered-map probes, but aggregate worker Tracy totals must be divided by the configured cluster parallelism and then narrowed to the specific loop being optimized. For this benchmark, a candidate must isolate a Medium-tier share after that conversion; broad `map lookup` totals alone are not enough.
